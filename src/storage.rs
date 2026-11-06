//! The storage trait and the default in-memory implementation.
//!
//! Provenance: `include/libtorrent/kademlia/dht_storage.hpp` and
//! `src/kademlia/dht_storage.cpp` of libtorrent RC_2_1 (commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Alden Torres, Arvid Norberg, Thomas Yuan, Steven Siloti, Andrei Kurushin,
//! Amir Abrams, Rosen Penev and contributors.
//!
//! [`DhtStorage`] is `dht_storage_interface`: everything a DHT node
//! remembers on behalf of the network, namely the peers announced for each
//! info-hash (BEP 5, with the BEP 33 scrape filters), the BEP 44 immutable
//! and mutable items, and the BEP 51 info-hash sample. The node only talks
//! to the trait, so a consumer can back it with a database.
//! [`DefaultStorage`] is `dht_default_storage`, the in-RAM implementation.
//!
//! # Time, randomness and settings
//!
//! libtorrent's storage reads the clock (`aux::time_now`), draws random
//! numbers (`aux::random`) and holds a *reference* to the live settings.
//! The sans-IO core has none of those globals, so [`DefaultStorage`] owns a
//! [`Clock`] and an [`Rng`] (inject a `ManualClock` and a `TestRng` for
//! deterministic tests, [`DefaultStorage::with_system`] otherwise), and the
//! owner pushes settings changes with [`DhtStorage::set_settings`].
//! [`DhtStorage::tick`] receives `now` explicitly, as PORTING.md specifies.
//!
//! # What is bounded
//!
//! A DHT node stores data for strangers, so every collection has a cap:
//! `max_torrents` torrents, `max_peers` peers per torrent, `max_dht_items`
//! items of each kind, at most 16 IPv6 peers per `/56` and info-hash, peer
//! names of at most 100 bytes. Hitting a cap drops (peers, torrents) or
//! evicts the least valuable entry (items) and never fails.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::bencode::{decode, Entry};
use crate::bloom_filter::{hash_address, BloomFilter};
use crate::net::write_endpoint;
use crate::node_id::{min_distance_exp, NodeId};
use crate::rng::{Rng, SystemRng};
use crate::settings::DhtSettings;
use crate::sha1_hash::Sha1Hash;
use crate::time::{Clock, SystemClock, Time};
use crate::types::{PublicKey, SequenceNumber, Signature};

/// How long a peer announce is valid before it is purged: 30 minutes is the
/// announce interval, and a peer survives one and a half of them
/// (`announce_interval * 3 / 2`). libtorrent has a TODO to make it a setting.
const PEER_LIFETIME: Duration = Duration::from_secs(30 * 60 * 3 / 2);

/// The shortest lifetime of a stored item when `item_lifetime` is set:
/// two hours, as BEP 44 recommends re-announcing hourly.
const MIN_ITEM_LIFETIME: Duration = Duration::from_secs(120 * 60);

/// Longest torrent name stored, in bytes (libtorrent `name.substr(0, 100)`;
/// the header comment of `announce_peer` says 50, the code says 100).
const MAX_NAME_LEN: usize = 100;

/// Max IPv6 peers per info-hash from one `/56`: the write token only proves
/// the announcer can receive at its address, and one host can receive on
/// every address of its prefix.
const MAX_PEERS_PER_PREFIX: usize = 16;

/// Upper bound of the BEP 51 `interval` field, in seconds.
const SAMPLE_INTERVAL_MAX: i32 = 21600;

/// Upper bound of the number of info-hashes in a BEP 51 sample.
const INFOHASHES_SAMPLE_COUNT_MAX: i32 = 20;

/// The counters a storage exposes (libtorrent `dht_storage_counters`).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::storage::StorageCounters;
/// assert_eq!(StorageCounters::default().peers, 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StorageCounters {
    /// Distinct torrents (info-hashes) with announced peers.
    pub torrents: i32,
    /// Announced peers across all torrents.
    pub peers: i32,
    /// Immutable items stored.
    pub immutable_data: i32,
    /// Mutable items stored.
    pub mutable_data: i32,
}

impl StorageCounters {
    /// Sets every counter to zero (libtorrent `dht_storage_counters::reset`).
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Everything a DHT node stores for the network (libtorrent
/// `dht_storage_interface`).
///
/// The trait is `Send` so a boxed storage can live in a node that is moved
/// across threads. Authentication of BEP 44 items is the caller's job: this
/// layer only stores what it is given.
pub trait DhtStorage: Send {
    /// Tells the storage the node IDs of every DHT instance in the process.
    /// Implementations keep them to decide which item to evict (the one
    /// farthest from every ID, discounted by popularity).
    fn update_node_ids(&mut self, ids: &[NodeId]);

    /// Fills `reply` with the peers tracked for `info_hash` and returns
    /// whether the torrent is *full*: `true` means the maximum number of
    /// peers is stored (or, for an unknown torrent, the maximum number of
    /// torrents), so the caller should only hand a write token to a
    /// requester that is already in the set.
    ///
    /// With `scrape` set the reply gets `BFpe` (downloaders) and `BFsd`
    /// (seeds), two 256-byte BEP 33 bloom filters; otherwise it gets
    /// `values`, a list of compact peers of the requester's address family,
    /// at most `max_peers_reply` of them (a quarter of that for IPv6), and
    /// without seeds when `noseed` is set. `n` holds the torrent name when
    /// one is known. An unknown torrent leaves `reply` untouched.
    ///
    /// # Panics
    ///
    /// Panics if `reply` is already a defined non-dictionary value.
    fn get_peers(
        &self,
        info_hash: &Sha1Hash,
        noseed: bool,
        scrape: bool,
        requester: IpAddr,
        reply: &mut Entry,
    ) -> bool;

    /// Stores a peer for `info_hash` (libtorrent `announce_peer`; the name
    /// is the torrent name from the announce, truncated by the default
    /// implementation to 100 bytes). Not networking: the node has
    /// already validated the token.
    fn announce_peer(&mut self, info_hash: &Sha1Hash, endpoint: SocketAddr, name: &str, seed: bool);

    /// Looks up an immutable item and writes its value to `item["v"]`.
    /// Returns whether it was found.
    fn get_immutable_item(&self, target: &Sha1Hash, item: &mut Entry) -> bool;

    /// Stores an immutable item (`buf` is the bencoded value) unless the
    /// target is already present, evicting the least important item when the
    /// table is full. `addr` is the announcer, counted for popularity.
    fn put_immutable_item(&mut self, target: &Sha1Hash, buf: &[u8], addr: IpAddr);

    /// The stored sequence number of a mutable item, if any.
    fn get_mutable_item_seq(&self, target: &Sha1Hash) -> Option<SequenceNumber>;

    /// Looks up a mutable item: always writes `item["seq"]`, and when
    /// `force_fill` is set or `0 <= seq < stored seq` also `v` (the decoded
    /// value), `sig` and `k`. Returns whether the item exists.
    fn get_mutable_item(
        &self,
        target: &Sha1Hash,
        seq: SequenceNumber,
        force_fill: bool,
        item: &mut Entry,
    ) -> bool;

    /// Stores a mutable item, or replaces the stored one when `seq` is newer
    /// (BEP 44 compare-and-swap is the caller's business). `addr` is the
    /// announcer, counted for popularity.
    #[allow(clippy::too_many_arguments)]
    fn put_mutable_item(
        &mut self,
        target: &Sha1Hash,
        buf: &[u8],
        sig: &Signature,
        seq: SequenceNumber,
        pk: &PublicKey,
        salt: &[u8],
        addr: IpAddr,
    );

    /// BEP 51: writes `interval`, `num` (torrents tracked) and `samples` (a
    /// string of 20-byte info-hashes) to `item` and returns the number of
    /// info-hashes in the sample. May refresh a cached sample lazily.
    fn get_infohashes_sample(&mut self, item: &mut Entry) -> usize;

    /// Periodic maintenance at time `now`: expire old peers and items.
    fn tick(&mut self, now: Time);

    /// The current counters.
    fn counters(&self) -> StorageCounters;

    /// Applies changed settings. libtorrent hands the storage a reference to
    /// the live settings; the owner of a `DhtStorage` calls this instead when
    /// they change. The default does nothing, for storages that ignore them.
    fn set_settings(&mut self, _settings: &DhtSettings) {}
}

/// One announced peer (libtorrent's private `peer_entry`).
#[derive(Debug, Clone, Copy)]
struct PeerEntry {
    /// When the peer announced, to purge stale peers.
    added: Time,
    addr: SocketAddr,
    seed: bool,
}

/// One tracked torrent (libtorrent's `torrent_entry`): the peers of each
/// family, each list kept sorted by endpoint.
#[derive(Debug, Default)]
struct TorrentEntry {
    name: String,
    peers4: Vec<PeerEntry>,
    peers6: Vec<PeerEntry>,
}

/// A stored item's shared bookkeeping (libtorrent `dht_immutable_item`).
#[derive(Debug)]
struct StoredItem {
    /// The bencoded value, as received.
    value: Box<[u8]>,
    /// The announcing IPs seen so far, to judge popularity when the table is
    /// full.
    ips: BloomFilter<128>,
    /// The last time anyone announced this item.
    last_seen: Time,
    /// The number of distinct IPs in `ips`.
    num_announcers: i32,
}

impl StoredItem {
    fn new(buf: &[u8]) -> Self {
        Self {
            value: buf.into(),
            ips: BloomFilter::new(),
            last_seen: Time::ZERO,
            num_announcers: 0,
        }
    }

    /// Records an announce from `addr` at `now` (libtorrent `touch_item`).
    fn touch(&mut self, addr: IpAddr, now: Time) {
        self.last_seen = now;
        let h = hash_address(addr);
        if !self.ips.find(&h) {
            self.ips.set(&h);
            self.num_announcers += 1;
        }
    }
}

/// A stored mutable item (libtorrent `dht_mutable_item`).
#[derive(Debug)]
struct MutableItem {
    base: StoredItem,
    sig: Signature,
    seq: SequenceNumber,
    key: PublicKey,
    /// Stored as libtorrent stores it; see [`DefaultStorage::mutable_item_salt`].
    salt: Vec<u8>,
}

/// The BEP 51 sample cache (libtorrent `infohashes_sample`).
#[derive(Debug, Default)]
struct InfohashesSample {
    samples: Vec<Sha1Hash>,
    created: Time,
}

/// `len >= limit` where `limit` is a (possibly nonsensical) `i32` setting.
fn at_capacity(len: usize, limit: i32) -> bool {
    i64::try_from(len).map_or(true, |l| l >= i64::from(limit))
}

/// A `usize` count as an `i32` counter, saturating.
fn as_i32(n: usize) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

/// The key of the table entry that is the best candidate for removal, i.e.
/// least important to keep (libtorrent `pick_least_important_item` with
/// `immutable_item_comparator`).
///
/// The score is `announcers / 5 - distance`, where distance is the
/// exponent of the XOR distance to the nearest of our node IDs: each extra
/// 5 announcers is worth one more bit of distance. The first entry with the
/// lowest score wins, as `std::min_element` does.
fn pick_least_important<T>(
    node_ids: &[NodeId],
    table: &BTreeMap<Sha1Hash, T>,
    announcers: impl Fn(&T) -> i32,
) -> Option<Sha1Hash> {
    table
        .iter()
        .min_by_key(|(k, v)| announcers(v) / 5 - min_distance_exp(k, node_ids))
        .map(|(k, _)| *k)
}

/// The in-RAM [`DhtStorage`] (libtorrent `dht_default_storage`).
///
/// Peers live in a map of sorted vectors, items in two ordered maps keyed by
/// target. It is fast and complete, but with a full table an eviction scans
/// every item, which is fine at the default 700.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::bencode::Entry;
/// use cloudllm_dht::settings::DhtSettings;
/// use cloudllm_dht::storage::{DefaultStorage, DhtStorage};
/// use cloudllm_dht::Sha1Hash;
///
/// let mut s = DefaultStorage::with_system(&DhtSettings::default());
/// let ih = Sha1Hash::of(b"a torrent");
/// s.announce_peer(&ih, "10.0.0.1:6881".parse().unwrap(), "name", false);
///
/// let mut reply = Entry::Undefined;
/// s.get_peers(&ih, false, false, "10.0.0.2".parse().unwrap(), &mut reply);
/// assert_eq!(reply.get("values").unwrap().as_list().unwrap().len(), 1);
/// assert_eq!(reply.get("n").unwrap().as_bytes(), Some(&b"name"[..]));
/// ```
pub struct DefaultStorage {
    settings: DhtSettings,
    counters: StorageCounters,
    node_ids: Vec<NodeId>,
    torrents: BTreeMap<Sha1Hash, TorrentEntry>,
    immutable: BTreeMap<Sha1Hash, StoredItem>,
    mutable: BTreeMap<Sha1Hash, MutableItem>,
    sample: InfohashesSample,
    clock: Box<dyn Clock + Send + Sync>,
    // `get_peers` is `&self` (as in libtorrent, where `aux::random` is a
    // global) but must draw randomness; the mutex is uncontended in
    // practice because the owning node is single threaded.
    rng: Mutex<Box<dyn Rng + Send>>,
}

impl std::fmt::Debug for DefaultStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultStorage")
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

impl DefaultStorage {
    /// A storage reading `clock` for announce and item times and drawing
    /// random peer selections from `rng`. Settings are copied; push updates
    /// with [`DhtStorage::set_settings`].
    #[must_use]
    pub fn new(
        settings: &DhtSettings,
        clock: Box<dyn Clock + Send + Sync>,
        rng: Box<dyn Rng + Send>,
    ) -> Self {
        Self {
            settings: settings.clone(),
            counters: StorageCounters::default(),
            node_ids: Vec::new(),
            torrents: BTreeMap::new(),
            immutable: BTreeMap::new(),
            mutable: BTreeMap::new(),
            sample: InfohashesSample::default(),
            clock,
            rng: Mutex::new(rng),
        }
    }

    /// A storage on the real monotonic clock and the OS random number
    /// generator (libtorrent's `dht_default_storage_constructor`).
    #[must_use]
    pub fn with_system(settings: &DhtSettings) -> Self {
        Self::new(settings, Box::new(SystemClock::new()), Box::new(SystemRng))
    }

    /// The salt a mutable item was first stored with, if the item exists.
    /// (libtorrent keeps the salt but never reads it back; it is exposed for
    /// persistent backends and diagnostics.)
    #[must_use]
    pub fn mutable_item_salt(&self, target: &Sha1Hash) -> Option<&[u8]> {
        self.mutable.get(target).map(|i| i.salt.as_slice())
    }

    fn rng(&self) -> std::sync::MutexGuard<'_, Box<dyn Rng + Send>> {
        self.rng.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The effective BEP 51 interval: the setting clamped to `0..=21600`.
    fn sample_interval(&self) -> i32 {
        self.settings
            .sample_infohashes_interval
            .clamp(0, SAMPLE_INTERVAL_MAX)
    }

    /// Rebuilds the cached info-hash sample unless it is fresh and complete
    /// (libtorrent `refresh_infohashes_sample`).
    fn refresh_infohashes_sample(&mut self) {
        let now = self.clock.now();
        let interval = self.sample_interval();
        let max_count = self
            .settings
            .max_infohashes_sample_count
            .clamp(0, INFOHASHES_SAMPLE_COUNT_MAX);
        let max_count = usize::try_from(max_count).unwrap_or(0);
        let count = max_count.min(self.torrents.len());
        let fresh = u64::try_from(interval)
            .ok()
            .filter(|i| *i > 0)
            .is_some_and(|i| self.sample.created + Duration::from_secs(i) > now);
        if fresh && self.sample.samples.len() >= max_count {
            return;
        }
        let rng = self.rng.get_mut().unwrap_or_else(PoisonError::into_inner);
        let mut samples = Vec::with_capacity(count);
        let mut to_pick = count;
        let mut candidates = u32::try_from(self.torrents.len()).unwrap_or(u32::MAX);
        for key in self.torrents.keys() {
            if to_pick == 0 {
                break;
            }
            // Pick with probability about <left to pick> / <left in the set>.
            // libtorrent draws from the *inclusive* range [0, candidates] and
            // keeps the key when the draw is <= to_pick, so the odds are
            // (to_pick + 1) / (candidates + 1): slightly biased towards
            // early keys, and certain once candidates == to_pick, which is
            // what guarantees `count` picks. Kept as is for fidelity.
            let draw = rng.random(candidates);
            candidates = candidates.saturating_sub(1);
            if usize::try_from(draw).map_or(true, |d| d > to_pick) {
                continue;
            }
            samples.push(*key);
            to_pick -= 1;
        }
        self.sample = InfohashesSample {
            samples,
            created: now,
        };
    }

    /// Drops announces older than [`PEER_LIFETIME`] from one peer list and
    /// returns how many went (libtorrent `purge_peers`).
    fn purge_peers(peers: &mut Vec<PeerEntry>, now: Time) -> usize {
        let before = peers.len();
        peers.retain(|p| p.added + PEER_LIFETIME >= now);
        // if we're using less than 1/4 of the capacity free up the excess
        if !peers.is_empty() && peers.capacity() / peers.len() >= 4 {
            peers.shrink_to_fit();
        }
        before - peers.len()
    }

    /// Removes the least important entry of a full item table.
    /// Returns `false` when there was nothing to evict.
    fn evict_one<T>(
        node_ids: &[NodeId],
        table: &mut BTreeMap<Sha1Hash, T>,
        announcers: impl Fn(&T) -> i32,
    ) -> bool {
        pick_least_important(node_ids, table, announcers)
            .and_then(|k| table.remove(&k))
            .is_some()
    }
}

/// The index range of the run of IPv6 peers sharing the `/56` of `prefix`
/// around `pos` in the sorted list `peers`.
///
/// `peers` is sorted by address, so the entries of one prefix are
/// contiguous and surround the insertion point (libtorrent `prefix_run`).
fn prefix_run(peers: &[PeerEntry], pos: usize, prefix: &[u8; 16]) -> std::ops::Range<usize> {
    let same = |p: &PeerEntry| match p.addr.ip() {
        IpAddr::V6(a) => a.octets()[..7] == prefix[..7],
        IpAddr::V4(_) => false,
    };
    let first = peers[..pos]
        .iter()
        .rposition(|p| !same(p))
        .map_or(0, |i| i + 1);
    let last = pos + peers[pos..].iter().take_while(|p| same(p)).count();
    first..last
}

/// Truncates a torrent name to [`MAX_NAME_LEN`] bytes on a character
/// boundary (libtorrent cuts bytes; a `&str` cannot be cut mid-character).
fn truncate_name(name: &str) -> &str {
    let mut end = name.len().min(MAX_NAME_LEN);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    &name[..end]
}

impl DhtStorage for DefaultStorage {
    fn update_node_ids(&mut self, ids: &[NodeId]) {
        self.node_ids = ids.to_vec();
    }

    fn get_peers(
        &self,
        info_hash: &Sha1Hash,
        noseed: bool,
        scrape: bool,
        requester: IpAddr,
        reply: &mut Entry,
    ) -> bool {
        let Some(v) = self.torrents.get(info_hash) else {
            return at_capacity(self.torrents.len(), self.settings.max_torrents);
        };
        let peersv = if requester.is_ipv4() {
            &v.peers4
        } else {
            &v.peers6
        };
        if !v.name.is_empty() {
            reply.set("n", v.name.as_str());
        }
        if scrape {
            let (mut downloaders, mut seeds) =
                (BloomFilter::<256>::new(), BloomFilter::<256>::new());
            for p in peersv {
                let filter = if p.seed { &mut seeds } else { &mut downloaders };
                filter.set(&hash_address(p.addr.ip()));
            }
            reply.set("BFpe", downloaders.as_bytes().as_slice());
            reply.set("BFsd", seeds.as_bytes().as_slice());
        } else {
            reply.set(
                "values",
                Entry::List(self.pick_peers(peersv, noseed, requester)),
            );
        }
        if !at_capacity(peersv.len(), self.settings.max_peers) {
            return false;
        }
        // We're at the max peers stored for this torrent: only send a write
        // token if the requester is already in the set. Only the IP is
        // compared, because the peer may announce a different port than the
        // one it sends DHT messages from.
        let i = peersv.partition_point(|p| p.addr.ip() < requester);
        peersv.get(i).map(|p| p.addr.ip()) != Some(requester)
    }

    fn announce_peer(
        &mut self,
        info_hash: &Sha1Hash,
        endpoint: SocketAddr,
        name: &str,
        seed: bool,
    ) {
        let now = self.clock.now();
        if !self.torrents.contains_key(info_hash) {
            if at_capacity(self.torrents.len(), self.settings.max_torrents) {
                // we're at capacity, drop the announce
                return;
            }
            self.counters.torrents += 1;
        }
        let max_peers = self.settings.max_peers;
        let v = self.torrents.entry(*info_hash).or_default();
        // the peer announces a torrent name, and we don't have one yet
        if !name.is_empty() && v.name.is_empty() {
            v.name = truncate_name(name).to_owned();
        }
        let peersv = if endpoint.is_ipv4() {
            &mut v.peers4
        } else {
            &mut v.peers6
        };
        let peer = PeerEntry {
            added: now,
            addr: endpoint,
            seed,
        };
        let i = peersv.partition_point(|p| p.addr < endpoint);
        if peersv.get(i).is_some_and(|p| p.addr == endpoint) {
            peersv[i] = peer;
            return;
        }
        if let IpAddr::V6(a) = endpoint.ip() {
            let run = prefix_run(peersv, i, &a.octets());
            if run.len() >= MAX_PEERS_PER_PREFIX {
                // Replace rather than drop, so a peer in a contested prefix
                // can still get in. The list doesn't grow, so `max_peers`
                // does not apply. The new entry belongs within the run, so
                // sorting the run restores the order.
                let oldest = run.start
                    + peersv[run.clone()]
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, p)| p.added)
                        .map_or(0, |(k, _)| k);
                peersv[oldest] = peer;
                peersv[run].sort_unstable_by_key(|p| p.addr);
                return;
            }
        }
        if at_capacity(peersv.len(), max_peers) {
            // we're at capacity, drop the announce
            return;
        }
        peersv.insert(i, peer);
        self.counters.peers += 1;
    }

    fn get_immutable_item(&self, target: &Sha1Hash, item: &mut Entry) -> bool {
        let Some(i) = self.immutable.get(target) else {
            return false;
        };
        item.set("v", decode_value(&i.value));
        true
    }

    fn put_immutable_item(&mut self, target: &Sha1Hash, buf: &[u8], addr: IpAddr) {
        let now = self.clock.now();
        if !self.immutable.contains_key(target) {
            // make sure we don't add too many items
            if at_capacity(self.immutable.len(), self.settings.max_dht_items)
                && Self::evict_one(&self.node_ids, &mut self.immutable, |i| i.num_announcers)
            {
                self.counters.immutable_data -= 1;
            }
            if at_capacity(self.immutable.len(), self.settings.max_dht_items) {
                return; // a cap of zero (or less) stores nothing
            }
            self.immutable.insert(*target, StoredItem::new(buf));
            self.counters.immutable_data += 1;
        }
        if let Some(i) = self.immutable.get_mut(target) {
            i.touch(addr, now);
        }
    }

    fn get_mutable_item_seq(&self, target: &Sha1Hash) -> Option<SequenceNumber> {
        self.mutable.get(target).map(|i| i.seq)
    }

    fn get_mutable_item(
        &self,
        target: &Sha1Hash,
        seq: SequenceNumber,
        force_fill: bool,
        item: &mut Entry,
    ) -> bool {
        let Some(f) = self.mutable.get(target) else {
            return false;
        };
        item.set("seq", Entry::Int(f.seq.0));
        if force_fill || (SequenceNumber(0) <= seq && seq < f.seq) {
            item.set("v", decode_value(&f.base.value));
            item.set("sig", f.sig.0.as_slice());
            item.set("k", f.key.0.as_slice());
        }
        true
    }

    fn put_mutable_item(
        &mut self,
        target: &Sha1Hash,
        buf: &[u8],
        sig: &Signature,
        seq: SequenceNumber,
        pk: &PublicKey,
        salt: &[u8],
        addr: IpAddr,
    ) {
        let now = self.clock.now();
        match self.mutable.get_mut(target) {
            Some(item) => {
                // we already have an item in this slot: only a newer
                // sequence number replaces it
                if item.seq < seq {
                    item.base.value = buf.into();
                    item.seq = seq;
                    item.sig = *sig;
                }
            }
            None => {
                // no item in this slot: make sure we don't add too many
                if at_capacity(self.mutable.len(), self.settings.max_dht_items)
                    && Self::evict_one(&self.node_ids, &mut self.mutable, |i| i.base.num_announcers)
                {
                    self.counters.mutable_data -= 1;
                }
                if at_capacity(self.mutable.len(), self.settings.max_dht_items) {
                    return; // a cap of zero (or less) stores nothing
                }
                self.mutable.insert(
                    *target,
                    MutableItem {
                        base: StoredItem::new(buf),
                        sig: *sig,
                        seq,
                        key: *pk,
                        salt: salt.to_vec(),
                    },
                );
                self.counters.mutable_data += 1;
            }
        }
        if let Some(i) = self.mutable.get_mut(target) {
            i.base.touch(addr, now);
        }
    }

    fn get_infohashes_sample(&mut self, item: &mut Entry) -> usize {
        item.set("interval", Entry::Int(i64::from(self.sample_interval())));
        item.set("num", Entry::Int(i64::from(as_i32(self.torrents.len()))));
        self.refresh_infohashes_sample();
        let samples: Vec<u8> = self.sample.samples.iter().flat_map(|h| h.0).collect();
        item.set("samples", samples);
        self.sample.samples.len()
    }

    fn tick(&mut self, now: Time) {
        // look through all peers and see if any have timed out
        let mut purged = 0usize;
        self.torrents.retain(|_, t| {
            purged += Self::purge_peers(&mut t.peers4, now);
            purged += Self::purge_peers(&mut t.peers6, now);
            let keep = !t.peers4.is_empty() || !t.peers6.is_empty();
            if !keep {
                self.counters.torrents -= 1;
            }
            keep
        });
        self.counters.peers -= as_i32(purged);

        if self.settings.item_lifetime == 0 {
            return;
        }
        let configured =
            Duration::from_secs(u64::try_from(self.settings.item_lifetime).unwrap_or(0));
        let lifetime = configured.max(MIN_ITEM_LIFETIME);
        let before = (self.immutable.len(), self.mutable.len());
        self.immutable.retain(|_, i| i.last_seen + lifetime > now);
        self.mutable
            .retain(|_, i| i.base.last_seen + lifetime > now);
        self.counters.immutable_data -= as_i32(before.0 - self.immutable.len());
        self.counters.mutable_data -= as_i32(before.1 - self.mutable.len());
    }

    fn counters(&self) -> StorageCounters {
        self.counters
    }

    fn set_settings(&mut self, settings: &DhtSettings) {
        self.settings = settings.clone();
    }
}

impl DefaultStorage {
    /// Picks the `values` of a `get_peers` reply: a random subset of up to
    /// `max_peers_reply` peers (a quarter of that for IPv6, whose compact
    /// form is three times longer), skipping seeds when `noseed` is set.
    fn pick_peers(&self, peersv: &[PeerEntry], noseed: bool, requester: IpAddr) -> Vec<Entry> {
        let mut to_pick = usize::try_from(self.settings.max_peers_reply).unwrap_or(0);
        // if these are IPv6 peers their addresses are 4x the size of IPv4,
        // so reduce the max peers 4 fold to compensate
        if !peersv.is_empty() && requester.is_ipv6() {
            to_pick /= 4;
        }
        let skip = |p: &PeerEntry| noseed && p.seed;
        let mut candidates = peersv.iter().filter(|p| !skip(p)).count();
        to_pick = to_pick.min(candidates);
        let mut picked = Vec::with_capacity(to_pick);
        let mut rng = self.rng();
        for p in peersv {
            if to_pick == 0 {
                break;
            }
            // if the node asking for peers is a seed, skip seeds
            if skip(p) {
                continue;
            }
            // Pick this peer with probability <left to pick> / <left in the
            // set>, with libtorrent's inclusive draw (see
            // `refresh_infohashes_sample`).
            let draw = rng.random(u32::try_from(candidates).unwrap_or(u32::MAX));
            candidates -= 1;
            if usize::try_from(draw).map_or(true, |d| d > to_pick) {
                continue;
            }
            let mut compact = Vec::with_capacity(18);
            write_endpoint(&p.addr, &mut compact);
            picked.push(Entry::Str(compact));
            to_pick -= 1;
        }
        picked
    }
}

/// Decodes a stored bencoded value (libtorrent `bdecode` into an `entry`);
/// a value that no longer decodes yields `Undefined`, as an invalid
/// `bdecode_node` converts to an undefined `entry`.
fn decode_value(raw: &[u8]) -> Entry {
    decode(raw)
        .map(|n| Entry::from_node(&n))
        .unwrap_or_default()
}
