//! Tests for `storage`: every `TEST_CASE` of libtorrent
//! `test/test_dht_storage.cpp` and the two storage cases of
//! `simulation/test_dht_storage.cpp` (RC_2_1,
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), plus coverage of the
//! behaviours they leave out.
//!
//! The simulation cases drive the storage with a simulated clock; here a
//! `ManualClock` plays that role and `tick` receives its reading.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use cloudllm_dht::bencode::Entry;
use cloudllm_dht::bloom_filter::{hash_address, BloomFilter};
use cloudllm_dht::node_id::min_distance_exp;
use cloudllm_dht::rng::{Rng, TestRng};
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::storage::{DefaultStorage, DhtStorage, StorageCounters};
use cloudllm_dht::testing::{addr4, ep, rand_v4, to_hash};
use cloudllm_dht::time::{Clock, ManualClock};
use cloudllm_dht::types::{PublicKey, SequenceNumber, Signature};
use cloudllm_dht::Sha1Hash;

/// `test_settings()` of the C++ file: two torrents, two items, a two hour
/// item lifetime.
fn test_settings() -> DhtSettings {
    DhtSettings {
        max_torrents: 2,
        max_dht_items: 2,
        item_lifetime: 120 * 60,
        ..DhtSettings::default()
    }
}

/// `create_default_dht_storage()`: a storage with the one node ID
/// `...0200`, on a manual clock the test keeps a handle to.
fn create_default_dht_storage(settings: &DhtSettings) -> (DefaultStorage, ManualClock) {
    let clock = ManualClock::new();
    let mut s = DefaultStorage::new(
        settings,
        Box::new(clock.clone()),
        Box::new(TestRng::new(0x5702a6e)),
    );
    s.update_node_ids(&[to_hash("0000000000000000000000000000000000000200")]);
    (s, clock)
}

fn n(last: &str) -> Sha1Hash {
    to_hash(&format!("5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee4{last}"))
}

fn v4_any() -> IpAddr {
    addr4("0.0.0.0")
}

fn values(reply: &Entry) -> &[Entry] {
    reply.get("values").and_then(Entry::as_list).unwrap_or(&[])
}

fn peers_of(s: &DefaultStorage, ih: &Sha1Hash, requester: IpAddr) -> Entry {
    let mut e = Entry::Undefined;
    s.get_peers(ih, false, false, requester, &mut e);
    e
}

/// Port of `TEST_CASE(announce_peer)`.
#[test]
fn test_announce_peer() {
    let (mut s, _) = create_default_dht_storage(&test_settings());
    let (n1, n2, n3) = (n("01"), n("02"), n("03"));

    // an unknown torrent leaves the reply untouched (the C++ test's
    // `peers["n"]` access creates empty entries; here they are absent)
    let peers = peers_of(&s, &n1, v4_any());
    assert!(peers.get("n").is_none());
    assert!(values(&peers).is_empty());

    s.announce_peer(&n1, ep("124.31.75.21", 1), "torrent_name", false);
    let peers = peers_of(&s, &n1, v4_any());
    assert_eq!(
        peers.get("n").unwrap().as_bytes(),
        Some(&b"torrent_name"[..])
    );
    assert_eq!(values(&peers).len(), 1);

    s.announce_peer(&n2, ep("124.31.75.22", 1), "torrent_name1", false);
    s.announce_peer(&n2, ep("124.31.75.23", 1), "torrent_name1", false);
    // the table holds two torrents: this announce is dropped
    s.announce_peer(&n3, ep("124.31.75.24", 1), "torrent_name2", false);
    let peers = peers_of(&s, &n3, v4_any());
    assert!(peers.get("values").is_none());
}

/// Port of `TEST_CASE(dual_stack)`: a requester only gets peers of its own
/// address family.
#[test]
fn test_dual_stack() {
    let (mut s, _) = create_default_dht_storage(&test_settings());
    let n1 = n("01");
    for p in [
        "124.31.75.21",
        "124.31.75.22",
        "124.31.75.23",
        "2000::1",
        "2000::2",
    ] {
        s.announce_peer(&n1, ep(p, 1), "torrent_name", false);
    }
    assert_eq!(values(&peers_of(&s, &n1, v4_any())).len(), 3);
    assert_eq!(values(&peers_of(&s, &n1, "::".parse().unwrap())).len(), 2);
}

/// Port of `TEST_CASE(put_items)`: the item table holds two entries; the
/// least important is evicted for a newcomer.
#[test]
fn test_put_items() {
    let (mut s, _) = create_default_dht_storage(&test_settings());
    let (n1, n2, n3, n4) = (n("01"), n("02"), n("03"), n("04"));
    let mut item = Entry::Undefined;
    assert!(!s.get_immutable_item(&n4, &mut item));
    s.put_immutable_item(&n4, b"123", addr4("124.31.75.21"));
    assert!(s.get_immutable_item(&n4, &mut item));
    s.put_immutable_item(&n1, b"123", addr4("124.31.75.21"));
    s.put_immutable_item(&n2, b"123", addr4("124.31.75.21"));
    s.put_immutable_item(&n3, b"123", addr4("124.31.75.21"));
    let mut item = Entry::Undefined;
    assert!(!s.get_immutable_item(&n1, &mut item));

    let mut item = Entry::Undefined;
    assert!(!s.get_mutable_item(&n4, SequenceNumber(0), false, &mut item));
    s.put_mutable_item(
        &n4,
        b"123",
        &Signature::default(),
        SequenceNumber(1),
        &PublicKey::default(),
        b"salt",
        addr4("124.31.75.21"),
    );
    assert!(s.get_mutable_item(&n4, SequenceNumber(0), false, &mut item));
}

/// Port of `TEST_CASE(counters)`.
#[test]
fn test_counters() {
    let (mut s, _) = create_default_dht_storage(&test_settings());
    let (n1, n2, n3, n4) = (n("01"), n("02"), n("03"), n("04"));
    assert_eq!(s.counters().peers, 0);
    assert_eq!(s.counters().torrents, 0);
    s.announce_peer(&n1, ep("124.31.75.21", 1), "torrent_name", false);
    assert_eq!(s.counters().peers, 1);
    assert_eq!(s.counters().torrents, 1);
    s.announce_peer(&n2, ep("124.31.75.22", 1), "torrent_name1", false);
    s.announce_peer(&n2, ep("124.31.75.23", 1), "torrent_name1", false);
    s.announce_peer(&n3, ep("124.31.75.24", 1), "torrent_name2", false);
    assert_eq!(s.counters().peers, 3);
    assert_eq!(s.counters().torrents, 2);

    s.put_immutable_item(&n4, b"123", addr4("124.31.75.21"));
    assert_eq!(s.counters().immutable_data, 1);
    s.put_immutable_item(&n1, b"123", addr4("124.31.75.21"));
    s.put_immutable_item(&n2, b"123", addr4("124.31.75.21"));
    s.put_immutable_item(&n3, b"123", addr4("124.31.75.21"));
    assert_eq!(s.counters().immutable_data, 2);
    s.put_mutable_item(
        &n4,
        b"123",
        &Signature::default(),
        SequenceNumber(1),
        &PublicKey::default(),
        b"salt",
        addr4("124.31.75.21"),
    );
    assert_eq!(s.counters().mutable_data, 1);
}

/// A storage built by "a custom constructor" that delegates to the default
/// one; the stand-in for the C++ tests' `dht_custom_storage_constructor`.
struct CustomStorage {
    inner: DefaultStorage,
}

impl CustomStorage {
    fn construct(settings: &DhtSettings, invoked: &mut bool) -> Box<dyn DhtStorage> {
        *invoked = true;
        Box::new(Self {
            inner: DefaultStorage::with_system(settings),
        })
    }
}

impl DhtStorage for CustomStorage {
    fn update_node_ids(&mut self, ids: &[Sha1Hash]) {
        self.inner.update_node_ids(ids);
    }
    fn get_peers(
        &self,
        ih: &Sha1Hash,
        noseed: bool,
        scrape: bool,
        r: IpAddr,
        reply: &mut Entry,
    ) -> bool {
        self.inner.get_peers(ih, noseed, scrape, r, reply)
    }
    fn announce_peer(&mut self, ih: &Sha1Hash, ep: SocketAddr, name: &str, seed: bool) {
        self.inner.announce_peer(ih, ep, name, seed);
    }
    fn get_immutable_item(&self, t: &Sha1Hash, item: &mut Entry) -> bool {
        self.inner.get_immutable_item(t, item)
    }
    fn put_immutable_item(&mut self, t: &Sha1Hash, buf: &[u8], addr: IpAddr) {
        self.inner.put_immutable_item(t, buf, addr);
    }
    fn get_mutable_item_seq(&self, t: &Sha1Hash) -> Option<SequenceNumber> {
        self.inner.get_mutable_item_seq(t)
    }
    fn get_mutable_item(
        &self,
        t: &Sha1Hash,
        seq: SequenceNumber,
        ff: bool,
        item: &mut Entry,
    ) -> bool {
        self.inner.get_mutable_item(t, seq, ff, item)
    }
    fn put_mutable_item(
        &mut self,
        t: &Sha1Hash,
        buf: &[u8],
        sig: &Signature,
        seq: SequenceNumber,
        pk: &PublicKey,
        salt: &[u8],
        addr: IpAddr,
    ) {
        self.inner
            .put_mutable_item(t, buf, sig, seq, pk, salt, addr);
    }
    fn get_infohashes_sample(&mut self, item: &mut Entry) -> usize {
        self.inner.get_infohashes_sample(item)
    }
    fn tick(&mut self, now: cloudllm_dht::time::Time) {
        self.inner.tick(now);
    }
    fn counters(&self) -> StorageCounters {
        self.inner.counters()
    }
}

/// Port of `TEST_CASE(set_custom)` and `TEST_CASE(default_set_custom)` at the
/// level this crate can express them: a consumer-supplied storage is used
/// through `Box<dyn DhtStorage>`, is only constructed when asked for, and
/// behaves like the default one. (Swapping it into a running DHT session is
/// the node's business and is covered by WP4's `tests/dht_node.rs`.)
#[test]
fn test_set_custom_storage_is_usable_as_trait_object() {
    let mut invoked = false;
    assert!(!invoked, "nothing constructs a storage on its own");
    let mut s = CustomStorage::construct(&test_settings(), &mut invoked);
    assert!(invoked);
    s.update_node_ids(&[Sha1Hash::MIN]);
    s.announce_peer(&n("01"), ep("1.2.3.4", 5), "x", true);
    assert_eq!(s.counters().peers, 1);
    let mut reply = Entry::Undefined;
    assert!(!s.get_peers(&n("01"), false, false, v4_any(), &mut reply));
    assert_eq!(values(&reply).len(), 1);
}

/// Port of `TEST_CASE(peer_limit)`: the peers of one torrent never exceed
/// `max_peers`.
#[test]
fn test_peer_limit() {
    let settings = DhtSettings {
        max_peers: 42,
        ..test_settings()
    };
    let (mut s, _) = create_default_dht_storage(&settings);
    let mut rng = TestRng::new(2);
    for _ in 0..200 {
        let port = u16::try_from(rng.random(0xffff)).unwrap();
        let addr = SocketAddr::new(rand_v4(&mut rng), port);
        s.announce_peer(&n("01"), addr, "torrent_name", false);
        assert!(s.counters().peers <= 42);
    }
    assert_eq!(s.counters().peers, 42);
}

const PEERS_PER_PREFIX: usize = 16;

/// `v6_peer()` of the C++ file: an address in the `/56` selected by
/// `prefix`, all within `2001:db8::/48`.
fn v6_peer(prefix: usize, host: usize) -> SocketAddr {
    ep(&format!("2001:db8:0:{prefix:02x}00::{:x}", host + 1), 6881)
}

/// `stored_v6_peers()`: what an IPv6 requester gets back.
fn stored_v6_peers(s: &DefaultStorage, ih: &Sha1Hash) -> Vec<SocketAddr> {
    let reply = peers_of(s, ih, "::".parse().unwrap());
    values(&reply)
        .iter()
        .map(|e| {
            let b = e.as_bytes().unwrap();
            assert_eq!(b.len(), 18);
            cloudllm_dht::net::read_endpoint(cloudllm_dht::net::Protocol::V6, b).unwrap()
        })
        .collect()
}

/// Port of `TEST_CASE(peer_prefix_limit)`: at most 16 peers per `/56`; the
/// oldest entries of a full prefix are replaced, the adjacent prefix counts
/// separately, and refreshing a stored endpoint evicts nothing.
#[test]
fn test_peer_prefix_limit() {
    // IPv6 replies are sized at a quarter of this, make sure we see all
    let settings = DhtSettings {
        max_peers_reply: 4000,
        ..test_settings()
    };
    let (mut s, clock) = create_default_dht_storage(&settings);
    let n1 = n("01");
    for i in 0..2 * PEERS_PER_PREFIX {
        // `added` must differ for "oldest" to mean something
        clock.advance(Duration::from_millis(1));
        s.announce_peer(&n1, v6_peer(0, i), "", false);
        assert!(usize::try_from(s.counters().peers).unwrap() <= PEERS_PER_PREFIX);
    }
    assert_eq!(
        usize::try_from(s.counters().peers).unwrap(),
        PEERS_PER_PREFIX
    );

    // the oldest entries were replaced, the newest survive
    let stored = stored_v6_peers(&s, &n1);
    assert_eq!(stored.len(), PEERS_PER_PREFIX);
    for i in 0..2 * PEERS_PER_PREFIX {
        assert_eq!(
            stored.contains(&v6_peer(0, i)),
            i >= PEERS_PER_PREFIX,
            "peer {i}"
        );
    }

    // the adjacent /56 is counted separately
    for i in 0..PEERS_PER_PREFIX {
        clock.advance(Duration::from_millis(1));
        s.announce_peer(&n1, v6_peer(1, i), "", false);
    }
    assert_eq!(
        usize::try_from(s.counters().peers).unwrap(),
        2 * PEERS_PER_PREFIX
    );

    // refreshing a stored endpoint of a full prefix evicts nothing
    s.announce_peer(&n1, v6_peer(0, PEERS_PER_PREFIX), "", false);
    assert_eq!(
        usize::try_from(s.counters().peers).unwrap(),
        2 * PEERS_PER_PREFIX
    );
    let stored = stored_v6_peers(&s, &n1);
    assert_eq!(stored.len(), 2 * PEERS_PER_PREFIX);
    for i in PEERS_PER_PREFIX..2 * PEERS_PER_PREFIX {
        assert!(stored.contains(&v6_peer(0, i)));
    }
}

/// Port of `TEST_CASE(peer_prefix_limit_full)`: a full prefix keeps
/// replacing its oldest entry even once the torrent is at `max_peers`,
/// since the list does not grow.
#[test]
fn test_peer_prefix_limit_full() {
    let settings = DhtSettings {
        max_peers_reply: 4000,
        max_peers: i32::try_from(PEERS_PER_PREFIX + 4).unwrap(),
        ..test_settings()
    };
    let (mut s, clock) = create_default_dht_storage(&settings);
    let n1 = n("01");
    let announce = |s: &mut DefaultStorage, p: SocketAddr| {
        clock.advance(Duration::from_millis(1));
        s.announce_peer(&n1, p, "", false);
    };
    for i in 0..2 * PEERS_PER_PREFIX {
        announce(&mut s, v6_peer(0, i));
    }
    assert_eq!(
        usize::try_from(s.counters().peers).unwrap(),
        PEERS_PER_PREFIX
    );

    // the flooded prefix left room for other prefixes
    for i in 0..10 {
        announce(&mut s, v6_peer(1, i));
    }
    assert_eq!(
        usize::try_from(s.counters().peers).unwrap(),
        PEERS_PER_PREFIX + 4
    );
    announce(&mut s, v6_peer(2, 0));
    assert_eq!(
        usize::try_from(s.counters().peers).unwrap(),
        PEERS_PER_PREFIX + 4
    );
    announce(&mut s, v6_peer(0, 2 * PEERS_PER_PREFIX));
    assert_eq!(
        usize::try_from(s.counters().peers).unwrap(),
        PEERS_PER_PREFIX + 4
    );

    let stored = stored_v6_peers(&s, &n1);
    assert_eq!(stored.len(), PEERS_PER_PREFIX + 4);
    assert!(stored.contains(&v6_peer(0, 2 * PEERS_PER_PREFIX)));
    assert!(!stored.contains(&v6_peer(0, PEERS_PER_PREFIX)));
    assert!(!stored.contains(&v6_peer(2, 0)));
}

/// Port of `TEST_CASE(torrent_limit)`.
#[test]
fn test_torrent_limit() {
    let settings = DhtSettings {
        max_torrents: 42,
        ..test_settings()
    };
    let (mut s, _) = create_default_dht_storage(&settings);
    let mut rng = TestRng::new(3);
    for _ in 0..200 {
        let port = u16::try_from(rng.random(0xffff)).unwrap();
        s.announce_peer(
            &rng.random_hash(),
            SocketAddr::new(rand_v4(&mut rng), port),
            "",
            false,
        );
        assert!(s.counters().torrents <= 42);
    }
    assert_eq!(s.counters().torrents, 42);
}

/// Port of `TEST_CASE(immutable_item_limit)`.
#[test]
fn test_immutable_item_limit() {
    let settings = DhtSettings {
        max_dht_items: 42,
        ..test_settings()
    };
    let (mut s, _) = create_default_dht_storage(&settings);
    let mut rng = TestRng::new(4);
    for _ in 0..200 {
        s.put_immutable_item(&rng.random_hash(), b"123", rand_v4(&mut rng));
        assert!(s.counters().immutable_data <= 42);
    }
    assert_eq!(s.counters().immutable_data, 42);
}

/// Port of `TEST_CASE(mutable_item_limit)`.
#[test]
fn test_mutable_item_limit() {
    let settings = DhtSettings {
        max_dht_items: 42,
        ..test_settings()
    };
    let (mut s, _) = create_default_dht_storage(&settings);
    let mut rng = TestRng::new(5);
    for _ in 0..200 {
        s.put_mutable_item(
            &rng.random_hash(),
            b"123",
            &Signature::default(),
            SequenceNumber(1),
            &PublicKey::default(),
            b"salt",
            rand_v4(&mut rng),
        );
        assert!(s.counters().mutable_data <= 42);
    }
    assert_eq!(s.counters().mutable_data, 42);
}

/// Port of `TEST_CASE(get_peers_dist)`: two replies of 100 from 1000 peers
/// are reasonably disjoint, and `noseed` still fills the reply when half the
/// peers are seeds.
#[test]
fn test_get_peers_dist() {
    let settings = DhtSettings {
        max_peers: 2000,
        max_peers_reply: 100,
        ..test_settings()
    };
    let (mut s, _) = create_default_dht_storage(&settings);
    let n1 = n("01");
    let ip = rand_v4(&mut TestRng::new(6));
    for i in 0..1000u16 {
        s.announce_peer(&n1, SocketAddr::new(ip, i), "torrent_name", false);
    }
    let mut seen = BTreeSet::new();
    let mut duplicates = 0;
    for _ in 0..2 {
        let reply = peers_of(&s, &n1, v4_any());
        assert_eq!(values(&reply).len(), 100);
        for p in values(&reply) {
            let b = p.as_bytes().unwrap();
            let port = u16::from_be_bytes([b[4], b[5]]);
            if !seen.insert(port) {
                duplicates += 1;
            }
        }
    }
    assert!(duplicates < 20, "duplicate peers found: {duplicates}");

    for i in 1000..2000u16 {
        s.announce_peer(&n1, SocketAddr::new(ip, i), "torrent_name", true);
    }
    let mut reply = Entry::Undefined;
    s.get_peers(&n1, true, false, v4_any(), &mut reply);
    assert_eq!(values(&reply).len(), 100);
    // and every one of them is a non-seed (ports below 1000)
    assert!(values(&reply)
        .iter()
        .all(|p| u16::from_be_bytes([p.as_bytes().unwrap()[4], p.as_bytes().unwrap()[5]]) < 1000));
}

/// Port of `TEST_CASE(update_node_ids)`: eviction prefers to keep the item
/// closest to the node IDs the storage was told about.
#[test]
fn test_update_node_ids() {
    let mut s = DefaultStorage::new(
        &test_settings(),
        Box::new(ManualClock::new()),
        Box::new(TestRng::new(7)),
    );
    let node_ids = [
        to_hash("0000000000000000000000000000000000000200"),
        to_hash("0000000000000000000000000000000000000400"),
        to_hash("0000000000000000000000000000000000000800"),
    ];
    s.update_node_ids(&node_ids);
    let h1 = to_hash("0000000000000000000000000000000000010200");
    let h2 = to_hash("0000000000000000000000000000000100000400");
    let h3 = to_hash("0000000000000000000000010000000000000800");
    assert_eq!(min_distance_exp(&h1, &node_ids), 16);
    assert_eq!(min_distance_exp(&h2, &node_ids), 32);
    assert_eq!(min_distance_exp(&h3, &node_ids), 64);

    // all items have one announcer, so the score is the distance alone
    let ip = addr4("124.31.75.21");
    s.put_immutable_item(&h1, b"123", ip);
    assert_eq!(s.counters().immutable_data, 1);
    s.put_immutable_item(&h2, b"123", ip);
    assert_eq!(s.counters().immutable_data, 2);
    // h2 (distance 32) is less important than h1 (16) and makes room for h3
    s.put_immutable_item(&h3, b"123", ip);
    assert_eq!(s.counters().immutable_data, 2);
    let mut item = Entry::Undefined;
    assert!(s.get_immutable_item(&h1, &mut item));
    assert!(!s.get_immutable_item(&h2, &mut Entry::Undefined));
    assert!(s.get_immutable_item(&h3, &mut Entry::Undefined));
}

/// Port of `TEST_CASE(infohashes_sample)`: the sample respects the count
/// limit; raising the limit through new settings yields everything.
#[test]
fn test_infohashes_sample() {
    let mut settings = DhtSettings {
        max_torrents: 5,
        sample_infohashes_interval: 10,
        max_infohashes_sample_count: 2,
        ..test_settings()
    };
    let (mut s, _) = create_default_dht_storage(&settings);
    let hashes = [n("01"), n("02"), n("03"), n("04")];
    for (i, h) in hashes.iter().enumerate() {
        s.announce_peer(
            h,
            ep(&format!("124.31.75.{}", 21 + i), 1),
            "torrent_name",
            false,
        );
    }
    let mut item = Entry::Undefined;
    assert_eq!(s.get_infohashes_sample(&mut item), 2);
    assert_eq!(item.get("interval").unwrap().as_int(), Some(10));
    assert_eq!(item.get("num").unwrap().as_int(), Some(4));
    assert_eq!(
        item.get("samples").unwrap().as_bytes().unwrap().len(),
        2 * 20
    );

    // get all of them (the C++ test mutates the live settings; here the
    // owner pushes the change)
    settings.max_infohashes_sample_count = 5;
    s.set_settings(&settings);
    let mut item = Entry::Undefined;
    assert_eq!(s.get_infohashes_sample(&mut item), 4);
    assert_eq!(item.get("num").unwrap().as_int(), Some(4));
    let samples = item.get("samples").unwrap().as_bytes().unwrap();
    assert_eq!(samples.len(), 4 * 20);
    for h in &hashes {
        assert!(samples.chunks(20).any(|c| c == h.0), "{h} missing");
    }
}

/// Port of `TEST_CASE(infohashes_sample_dist)`: with the interval at 0 every
/// call refreshes, and a thousand single-hash samples cover many torrents.
#[test]
fn test_infohashes_sample_dist() {
    let settings = DhtSettings {
        max_torrents: 1000,
        sample_infohashes_interval: 0,
        max_infohashes_sample_count: 1,
        ..test_settings()
    };
    let (mut s, _) = create_default_dht_storage(&settings);
    let mut rng = TestRng::new(8);
    for i in 0..1000u16 {
        s.announce_peer(
            &rng.random_hash(),
            SocketAddr::new(rand_v4(&mut rng), i),
            "torrent_name",
            false,
        );
    }
    let mut set = BTreeSet::new();
    for _ in 0..1000 {
        let mut item = Entry::Undefined;
        assert_eq!(s.get_infohashes_sample(&mut item), 1);
        assert_eq!(item.get("interval").unwrap().as_int(), Some(0));
        assert_eq!(item.get("num").unwrap().as_int(), Some(1000));
        let samples = item.get("samples").unwrap().as_bytes().unwrap();
        assert_eq!(samples.len(), 20);
        set.insert(Sha1Hash::from_slice(samples).unwrap());
    }
    assert!(set.len() > 500, "infohashes set size: {}", set.len());
}

/// Port of simulation `dht_storage_counters`: peers expire after 45
/// minutes, items after the two hour lifetime, torrents with their last
/// peer. The three checks happen at 30 minutes, then 80 minutes later, then
/// an hour later, on one continuing timeline like the simulation's.
#[test]
fn test_dht_storage_counters_expiry() {
    let (mut s, clock) = create_default_dht_storage(&test_settings());
    let (n1, n2, n3, n4) = (n("01"), n("02"), n("03"), n("04"));
    let ip = addr4("124.31.75.21");
    s.announce_peer(&n1, ep("124.31.75.21", 1), "torrent_name", false);
    s.announce_peer(&n2, ep("124.31.75.22", 1), "torrent_name1", false);
    s.announce_peer(&n2, ep("124.31.75.23", 1), "torrent_name1", false);
    s.announce_peer(&n3, ep("124.31.75.24", 1), "torrent_name2", false);
    for h in [&n4, &n1, &n2, &n3] {
        s.put_immutable_item(h, b"123", ip);
    }
    s.put_mutable_item(
        &n4,
        b"123",
        &Signature::default(),
        SequenceNumber(1),
        &PublicKey::default(),
        b"salt",
        ip,
    );
    let expect = |s: &DefaultStorage, peers, torrents, immutable, mutable| {
        assert_eq!(
            s.counters(),
            StorageCounters {
                torrents,
                peers,
                immutable_data: immutable,
                mutable_data: mutable
            }
        );
    };

    // 30 minutes: torrents and peers are still alive
    clock.advance(Duration::from_secs(30 * 60));
    s.tick(clock.now());
    expect(&s, 3, 2, 2, 1);
    // 110 minutes: peers (45 min) are gone, items (120 min) are not
    clock.advance(Duration::from_secs(80 * 60));
    s.tick(clock.now());
    expect(&s, 0, 0, 2, 1);
    // 170 minutes: everything is gone
    clock.advance(Duration::from_secs(60 * 60));
    s.tick(clock.now());
    expect(&s, 0, 0, 0, 0);
}

/// Port of simulation `dht_storage_infohashes_sample`: once the torrents
/// have expired the sample is empty.
#[test]
fn test_dht_storage_infohashes_sample_after_expiry() {
    let settings = DhtSettings {
        max_torrents: 5,
        sample_infohashes_interval: 30,
        max_infohashes_sample_count: 2,
        ..test_settings()
    };
    let (mut s, clock) = create_default_dht_storage(&settings);
    for (i, h) in [n("01"), n("02"), n("03"), n("04")].iter().enumerate() {
        s.announce_peer(
            h,
            ep(&format!("124.31.75.{}", 21 + i), 1),
            "torrent_name",
            false,
        );
    }
    assert_eq!(s.get_infohashes_sample(&mut Entry::Undefined), 2);
    clock.advance(Duration::from_secs(3600)); // expiration of torrents
    s.tick(clock.now());
    assert_eq!(s.get_infohashes_sample(&mut Entry::Undefined), 0);
}

/// A cached sample is reused inside the interval while it is complete, and
/// rebuilt after it (libtorrent `refresh_infohashes_sample`).
#[test]
fn test_infohashes_sample_cache_and_refresh() {
    let settings = DhtSettings {
        max_torrents: 100,
        sample_infohashes_interval: 30,
        max_infohashes_sample_count: 1,
        ..test_settings()
    };
    let (mut s, clock) = create_default_dht_storage(&settings);
    let mut rng = TestRng::new(9);
    for i in 0..50u16 {
        s.announce_peer(
            &rng.random_hash(),
            SocketAddr::new(rand_v4(&mut rng), i),
            "",
            false,
        );
    }
    let sample = |s: &mut DefaultStorage| {
        let mut e = Entry::Undefined;
        s.get_infohashes_sample(&mut e);
        e.get("samples").unwrap().as_bytes().unwrap().to_vec()
    };
    clock.advance(Duration::from_secs(100));
    let first = sample(&mut s);
    assert_eq!(first.len(), 20);
    clock.advance(Duration::from_secs(29));
    assert_eq!(sample(&mut s), first, "cached inside the interval");
    // after the interval a new draw happens; over several tries it changes
    let mut changed = false;
    for _ in 0..20 {
        clock.advance(Duration::from_secs(31));
        changed |= sample(&mut s) != first;
    }
    assert!(changed);
}

/// BEP 51 interval is clamped to `0..=21600` in the reply.
#[test]
fn test_infohashes_sample_interval_is_clamped() {
    let mut settings = test_settings();
    settings.sample_infohashes_interval = 1_000_000;
    let (mut s, _) = create_default_dht_storage(&settings);
    let mut e = Entry::Undefined;
    s.get_infohashes_sample(&mut e);
    assert_eq!(e.get("interval").unwrap().as_int(), Some(21600));
    settings.sample_infohashes_interval = -5;
    s.set_settings(&settings);
    let mut e = Entry::Undefined;
    s.get_infohashes_sample(&mut e);
    assert_eq!(e.get("interval").unwrap().as_int(), Some(0));
}

/// A peer expires 45 minutes after its announce (one and a half announce
/// intervals): present at exactly 45 minutes, gone a moment later; a
/// re-announce refreshes it.
#[test]
fn test_peer_expiry_boundary_and_refresh() {
    let (mut s, clock) = create_default_dht_storage(&test_settings());
    let n1 = n("01");
    s.announce_peer(&n1, ep("1.2.3.4", 1), "", false);
    clock.advance(Duration::from_secs(45 * 60));
    s.tick(clock.now());
    assert_eq!(s.counters().peers, 1);
    clock.advance(Duration::from_millis(1));
    s.tick(clock.now());
    assert_eq!(s.counters().peers, 0);
    assert_eq!(s.counters().torrents, 0);

    s.announce_peer(&n1, ep("1.2.3.4", 1), "", false);
    clock.advance(Duration::from_secs(40 * 60));
    s.announce_peer(&n1, ep("1.2.3.4", 1), "", true); // refresh (and seed flag)
    assert_eq!(s.counters().peers, 1);
    clock.advance(Duration::from_secs(40 * 60));
    s.tick(clock.now());
    assert_eq!(s.counters().peers, 1);
}

/// Item expiry honours a minimum lifetime of two hours even when the setting
/// is shorter, and `item_lifetime = 0` means items never expire.
#[test]
fn test_item_lifetime_floor_and_zero() {
    let mut settings = test_settings();
    settings.item_lifetime = 60; // below the 120 minute floor
    let (mut s, clock) = create_default_dht_storage(&settings);
    s.put_immutable_item(&n("01"), b"i1e", addr4("1.1.1.1"));
    clock.advance(Duration::from_secs(119 * 60));
    s.tick(clock.now());
    assert_eq!(s.counters().immutable_data, 1);
    clock.advance(Duration::from_secs(2 * 60));
    s.tick(clock.now());
    assert_eq!(s.counters().immutable_data, 0);

    settings.item_lifetime = 0;
    let (mut s, clock) = create_default_dht_storage(&settings);
    s.put_immutable_item(&n("01"), b"i1e", addr4("1.1.1.1"));
    clock.advance(Duration::from_secs(365 * 24 * 3600));
    s.tick(clock.now());
    assert_eq!(s.counters().immutable_data, 1);
}

/// Announcing an item again refreshes its `last_seen`, delaying expiry.
#[test]
fn test_item_reannounce_extends_lifetime() {
    let (mut s, clock) = create_default_dht_storage(&test_settings());
    let t = n("01");
    s.put_immutable_item(&t, b"i1e", addr4("1.1.1.1"));
    clock.advance(Duration::from_secs(100 * 60));
    s.put_immutable_item(&t, b"i1e", addr4("1.1.1.1"));
    clock.advance(Duration::from_secs(100 * 60));
    s.tick(clock.now());
    assert_eq!(s.counters().immutable_data, 1);
    clock.advance(Duration::from_secs(21 * 60));
    s.tick(clock.now());
    assert_eq!(s.counters().immutable_data, 0);
}

/// A scrape reply carries two 256-byte bloom filters holding the hashed peer
/// addresses, split into downloaders (`BFpe`) and seeds (`BFsd`), and no
/// `values` (BEP 33).
#[test]
fn test_scrape_reply_has_bloom_filters() {
    let (mut s, _) = create_default_dht_storage(&test_settings());
    let n1 = n("01");
    s.announce_peer(&n1, ep("1.2.3.4", 1), "", false);
    s.announce_peer(&n1, ep("5.6.7.8", 1), "", true);
    s.announce_peer(&n1, ep("2000::1", 1), "", true); // other family: absent
    let mut reply = Entry::Undefined;
    s.get_peers(&n1, false, true, v4_any(), &mut reply);
    assert!(reply.get("values").is_none());
    let bf = |k: &str| {
        BloomFilter::<256>::from_bytes(reply.get(k).unwrap().as_bytes().unwrap()).unwrap()
    };
    let (downloaders, seeds) = (bf("BFpe"), bf("BFsd"));
    assert!(downloaders.find(&hash_address(addr4("1.2.3.4"))));
    assert!(!downloaders.find(&hash_address(addr4("5.6.7.8"))));
    assert!(seeds.find(&hash_address(addr4("5.6.7.8"))));
    assert!(!seeds.find(&hash_address("2000::1".parse().unwrap())));
    assert!((seeds.size() - 1.0).abs() < 0.1);
}

/// `noseed` drops seeds from the reply, and the name is only taken from the
/// first announce that has one and cut to 100 bytes.
#[test]
fn test_noseed_and_name_handling() {
    let (mut s, _) = create_default_dht_storage(&test_settings());
    let n1 = n("01");
    s.announce_peer(&n1, ep("1.1.1.1", 1), "", true);
    s.announce_peer(&n1, ep("2.2.2.2", 1), &"x".repeat(150), false);
    s.announce_peer(&n1, ep("3.3.3.3", 1), "second name", false);
    let mut reply = Entry::Undefined;
    s.get_peers(&n1, true, false, v4_any(), &mut reply);
    assert_eq!(values(&reply).len(), 2);
    assert!(!values(&reply)
        .iter()
        .any(|p| p.as_bytes().unwrap()[..4] == [1, 1, 1, 1]));
    assert_eq!(
        reply.get("n").unwrap().as_bytes().unwrap(),
        "x".repeat(100).as_bytes()
    );
    // multi-byte names are cut on a character boundary
    let mut s2 = create_default_dht_storage(&test_settings()).0;
    s2.announce_peer(&n1, ep("1.1.1.1", 1), &"\u{e9}".repeat(60), false);
    let mut reply = Entry::Undefined;
    s2.get_peers(&n1, false, false, v4_any(), &mut reply);
    assert_eq!(reply.get("n").unwrap().as_bytes().unwrap().len(), 100);
}

/// IPv6 replies carry a quarter of `max_peers_reply` (their compact form is
/// 18 bytes, three times the IPv4 one, plus overhead).
#[test]
fn test_ipv6_reply_is_a_quarter_of_max_peers_reply() {
    let settings = DhtSettings {
        max_peers_reply: 8,
        max_peers: 100,
        ..test_settings()
    };
    let (mut s, _) = create_default_dht_storage(&settings);
    let n1 = n("01");
    for i in 0..20u16 {
        s.announce_peer(&n1, ep(&format!("2000:{i:x}::1"), 1), "", false);
        s.announce_peer(&n1, ep(&format!("10.0.0.{i}"), 1), "", false);
    }
    assert_eq!(values(&peers_of(&s, &n1, "::1".parse().unwrap())).len(), 2);
    assert_eq!(values(&peers_of(&s, &n1, v4_any())).len(), 8);
}

/// `get_peers` returns `true` ("full: only tokens for known requesters") when
/// the torrent has `max_peers` peers and the requester is not among them, or
/// for an unknown torrent when the torrent table is full.
#[test]
fn test_get_peers_reports_full_torrents() {
    let settings = DhtSettings {
        max_peers: 3,
        max_torrents: 1,
        ..test_settings()
    };
    let (mut s, _) = create_default_dht_storage(&settings);
    let (n1, n2) = (n("01"), n("02"));
    let mut e = Entry::Undefined;
    assert!(
        !s.get_peers(&n2, false, false, v4_any(), &mut e),
        "table not full yet"
    );
    for i in 1..=3 {
        s.announce_peer(&n1, ep(&format!("10.0.0.{i}"), 1000 + i), "", false);
    }
    // an unknown torrent while the table is full
    assert!(s.get_peers(&n2, false, false, v4_any(), &mut Entry::Undefined));
    // full torrent: a stranger gets no token, a known IP (any port) does
    assert!(s.get_peers(&n1, false, false, addr4("10.0.0.9"), &mut Entry::Undefined));
    assert!(!s.get_peers(&n1, false, false, addr4("10.0.0.2"), &mut Entry::Undefined));
    assert!(!s.get_peers(&n1, false, false, addr4("10.0.0.3"), &mut Entry::Undefined));
    // below the cap nobody is refused
    let (mut s, _) = create_default_dht_storage(&DhtSettings {
        max_peers: 4,
        ..settings
    });
    for i in 1..=3 {
        s.announce_peer(&n1, ep(&format!("10.0.0.{i}"), 1), "", false);
    }
    assert!(!s.get_peers(&n1, false, false, addr4("10.0.0.9"), &mut Entry::Undefined));
}

/// An announce of an endpoint already stored replaces the entry (keeping the
/// count) and updates the seed flag; the same IP on another port is a new peer.
#[test]
fn test_reannounce_replaces_entry() {
    let (mut s, _) = create_default_dht_storage(&test_settings());
    let n1 = n("01");
    s.announce_peer(&n1, ep("1.2.3.4", 80), "", false);
    s.announce_peer(&n1, ep("1.2.3.4", 80), "", true);
    assert_eq!(s.counters().peers, 1);
    let mut reply = Entry::Undefined;
    s.get_peers(&n1, true, false, v4_any(), &mut reply);
    assert!(values(&reply).is_empty(), "now a seed");
    s.announce_peer(&n1, ep("1.2.3.4", 81), "", false);
    assert_eq!(s.counters().peers, 2);
}

/// Immutable items round-trip their decoded value under `v`; announcing the
/// same target again keeps the value and does not double count.
#[test]
fn test_immutable_roundtrip_and_idempotence() {
    let (mut s, _) = create_default_dht_storage(&test_settings());
    let t = n("01");
    s.put_immutable_item(&t, b"12:Hello World!", addr4("1.1.1.1"));
    s.put_immutable_item(&t, b"3:xyz", addr4("2.2.2.2"));
    assert_eq!(s.counters().immutable_data, 1);
    let mut item = Entry::Undefined;
    assert!(s.get_immutable_item(&t, &mut item));
    assert_eq!(
        item.get("v").unwrap().as_bytes(),
        Some(&b"Hello World!"[..])
    );
}

/// Mutable item semantics: `seq` always reported; value, signature and key
/// only when `force_fill` or `0 <= seq < stored`; only a strictly newer
/// sequence number replaces the value; the salt is kept from the first put.
#[test]
fn test_mutable_item_semantics() {
    let (mut s, _) = create_default_dht_storage(&test_settings());
    let t = n("01");
    let (sig1, sig2) = (Signature([1; 64]), Signature([2; 64]));
    let pk = PublicKey([9; 32]);
    let put = |s: &mut DefaultStorage, v: &[u8], sig: &Signature, seq: i64, salt: &[u8]| {
        s.put_mutable_item(&t, v, sig, SequenceNumber(seq), &pk, salt, addr4("1.1.1.1"));
    };
    assert_eq!(s.get_mutable_item_seq(&t), None);
    put(&mut s, b"i1e", &sig1, 5, b"salt");
    assert_eq!(s.get_mutable_item_seq(&t), Some(SequenceNumber(5)));
    assert_eq!(s.mutable_item_salt(&t), Some(&b"salt"[..]));

    let get = |s: &DefaultStorage, seq: i64, force: bool| {
        let mut e = Entry::Undefined;
        assert!(s.get_mutable_item(&t, SequenceNumber(seq), force, &mut e));
        e
    };
    // requester is up to date: only the seq
    let e = get(&s, 5, false);
    assert_eq!(e.get("seq").unwrap().as_int(), Some(5));
    assert!(e.get("v").is_none() && e.get("sig").is_none() && e.get("k").is_none());
    // a negative seq means "no seq known": nothing unless forced
    assert!(get(&s, -1, false).get("v").is_none());
    let e = get(&s, -1, true);
    assert_eq!(e.get("v").unwrap().as_int(), Some(1));
    assert_eq!(e.get("sig").unwrap().as_bytes(), Some(&[1u8; 64][..]));
    assert_eq!(e.get("k").unwrap().as_bytes(), Some(&[9u8; 32][..]));
    // requester is behind
    assert!(get(&s, 4, false).get("v").is_some());
    assert!(get(&s, 0, false).get("v").is_some());

    // an older or equal seq does not replace; a newer one does
    put(&mut s, b"i2e", &sig2, 5, b"other");
    put(&mut s, b"i2e", &sig2, 4, b"other");
    assert_eq!(get(&s, 0, true).get("v").unwrap().as_int(), Some(1));
    put(&mut s, b"i3e", &sig2, 6, b"other");
    let e = get(&s, 0, true);
    assert_eq!(e.get("v").unwrap().as_int(), Some(3));
    assert_eq!(e.get("sig").unwrap().as_bytes(), Some(&[2u8; 64][..]));
    assert_eq!(s.counters().mutable_data, 1);
    assert_eq!(s.mutable_item_salt(&t), Some(&b"salt"[..]));
}

/// Popular items survive eviction: five more announcers are worth one more
/// bit of distance, so an item with ten announcers beats a closer one with
/// one.
#[test]
fn test_eviction_weighs_popularity() {
    let settings = DhtSettings {
        max_dht_items: 2,
        ..test_settings()
    };
    let (mut s, _) = create_default_dht_storage(&settings);
    let near = to_hash("0000000000000000000000000000000000000300"); // distance exp 8
    let far = to_hash("0000000000000000000000000000000000100200"); // distance exp 20
    let newcomer = to_hash("0000000000000000000000000000000000000100"); // exp 9
    s.put_immutable_item(&near, b"i1e", addr4("1.0.0.1"));
    s.put_immutable_item(&far, b"i1e", addr4("1.0.0.1"));
    // 79 more distinct announcers lift `far` by about 15 bits (79 / 5), so
    // its score is about 15 - 20 = -5 against `near`'s 0 - 8 = -8: the
    // closer but unpopular item is the better candidate for removal
    for i in 2..=80u8 {
        s.put_immutable_item(&far, b"i1e", addr4(&format!("1.0.0.{i}")));
    }
    s.put_immutable_item(&newcomer, b"i1e", addr4("9.9.9.9"));
    assert!(
        !s.get_immutable_item(&near, &mut Entry::Undefined),
        "near, unpopular: evicted"
    );
    assert!(
        s.get_immutable_item(&far, &mut Entry::Undefined),
        "far but popular: kept"
    );
}

/// A cap of zero stores nothing (libtorrent would erase from an empty table,
/// undefined behaviour) and never panics.
#[test]
fn test_zero_capacity_stores_nothing() {
    let settings = DhtSettings {
        max_dht_items: 0,
        max_torrents: 0,
        max_peers: 0,
        ..test_settings()
    };
    let (mut s, _) = create_default_dht_storage(&settings);
    s.put_immutable_item(&n("01"), b"i1e", addr4("1.1.1.1"));
    s.put_mutable_item(
        &n("01"),
        b"i1e",
        &Signature::default(),
        SequenceNumber(1),
        &PublicKey::default(),
        b"",
        addr4("1.1.1.1"),
    );
    s.announce_peer(&n("01"), ep("1.1.1.1", 1), "", false);
    assert_eq!(s.counters(), StorageCounters::default());
    assert!(s.get_peers(&n("01"), false, false, v4_any(), &mut Entry::Undefined));
}

/// With `max_peers` reached the torrent entry created by a refused announce
/// stays (as in libtorrent) until `tick` removes the peerless torrent, and
/// the torrent counter is consistent afterwards.
#[test]
fn test_torrent_without_peers_is_collected_by_tick() {
    let settings = DhtSettings {
        max_peers: 0,
        ..test_settings()
    };
    let (mut s, clock) = create_default_dht_storage(&settings);
    s.announce_peer(&n("01"), ep("1.1.1.1", 1), "", false);
    assert_eq!(s.counters().torrents, 1);
    assert_eq!(s.counters().peers, 0);
    clock.advance(Duration::from_secs(1));
    s.tick(clock.now());
    assert_eq!(s.counters().torrents, 0);
}

/// `StorageCounters::reset` zeroes everything.
#[test]
fn test_counters_reset() {
    let mut c = StorageCounters {
        torrents: 1,
        peers: 2,
        immutable_data: 3,
        mutable_data: 4,
    };
    c.reset();
    assert_eq!(c, StorageCounters::default());
}
