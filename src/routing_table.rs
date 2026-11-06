//! The Kademlia routing table with replacement buckets, extended buckets and
//! IP restriction.
//!
//! Provenance: `include/libtorrent/kademlia/routing_table.hpp` and
//! `src/kademlia/routing_table.cpp` of libtorrent RC_2_1 (commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg, Steven Siloti, Thomas Yuan, Alden Torres, Andrei Kurushin,
//! Angel Leon and Pavel Pimenov.
//!
//! # How the table is organised
//!
//! The table is a list of buckets. Bucket `i` holds the nodes whose ID
//! shares exactly `i` leading bits with ours (`159 - distance_exp`); the
//! last bucket additionally holds everything closer, and is *split* when it
//! overflows. Each bucket is a [`Bucket`]: `live_nodes` that we have pinged
//! at least once, and `replacements`, a cache of candidates that did not fit
//! (or were only heard about) and that take over when a live node fails.
//!
//! The differences from the paper, all inherited from libtorrent:
//!
//! * Nodes are not marked stale; each carries a count of consecutive
//!   failures. A full bucket replaces the node that failed the most, if any
//!   failed at all.
//! * With [`DhtSettings::extended_routing_table`] the first four buckets are
//!   16, 8, 4 and 2 times larger ([`RoutingTable::bucket_limit`]), to get
//!   close to a target in fewer round trips.
//! * Nodes with a lower RTT are preferred, and so are *verified* nodes
//!   (BEP 42: the ID matches the node's IP). Inside a full bucket the nodes
//!   are spread over `bucket_size` prefix "slots" ([`classify_prefix`]) so a
//!   lookup has a good first hop in every sub-branch.
//! * With [`DhtSettings::restrict_routing_ips`] the whole table holds at
//!   most one node per IP address and one per /24 (/64 for IPv6) per bucket,
//!   against Sybil and routing-table-poisoning attacks.
//!
//! # Differences from libtorrent
//!
//! * The table owns a *copy* of the [`DhtSettings`] (libtorrent keeps a
//!   reference to the live `session_settings`). Call
//!   [`RoutingTable::set_settings`] when they change.
//! * Time is passed in (`now`) wherever libtorrent calls `aux::time_now()`.
//! * `dht_observer`'s IP filter is a closure installed with
//!   [`RoutingTable::set_ip_filter`]; its presence stands for
//!   `settings_pack::apply_filter_to_dht`.
//! * [`RoutingTable::find_node`] takes `&self`; libtorrent's creates the
//!   first (empty) bucket as a side effect when the table is empty, here an
//!   empty table simply returns no nodes. [`RoutingTable::num_active_buckets`]
//!   of a table that was only queried is therefore `0`, not `1`.
//! * [`RoutingTable::depth`] of an empty table is `0`, not `-1`, and the
//!   cached depth never goes negative. libtorrent's `routing_table::depth()`
//!   stores `-1` for an empty table and then returns it forever, even after
//!   nodes arrive, because the early-return for negative values never
//!   recomputes; `node::tick` calls `depth()` before the first node is
//!   added, so a node would re-bootstrap itself every ten minutes for good.
//!   Regression test: `test_depth_recovers_after_empty_table`.
//! * The `dht_logger` messages are not ported; the decisions they report are
//!   visible through the return values and [`RoutingTable::write_state`].

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::ops::BitOr;
use std::sync::atomic::{AtomicI32, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Duration;

use crate::net::Protocol;
use crate::node_entry::NodeEntry;
use crate::node_id::{distance_exp, verify_id, NodeId};
use crate::settings::DhtSettings;
use crate::time::Time;

/// The largest number of buckets a table may grow to before splitting stops
/// being retried (libtorrent's "sanity check" in `add_node`).
///
/// In the wild tables are 26 or 27 deep; deeper means a bug or an attacker
/// spoofing node IDs.
const MAX_SPLIT_DEPTH: usize = 50;

/// How long after its last query a node counts as "recently queried" when a
/// possibly malicious bucket is scheduled for re-pinging.
const REPING_AFTER: Duration = Duration::from_secs(5 * 60);

/// The `bucket_limit` multipliers of the first four buckets when the
/// extended routing table is on (libtorrent `size_exceptions`).
const SIZE_EXCEPTIONS: [usize; 4] = [16, 8, 4, 2];

/// An IP filter installed with [`RoutingTable::set_ip_filter`]; returns
/// `true` when the address is *blocked* (libtorrent `ip_filter::access ==
/// blocked`).
pub type IpFilter = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

/// A multiset of the IP addresses present in a routing table (libtorrent
/// `dht::ip_set`).
///
/// It is a multiset because, with
/// [`DhtSettings::restrict_routing_ips`] off, several entries (different
/// ports) may share an address. IPv4 and IPv6 addresses are kept apart, as
/// in libtorrent, so an IPv4-mapped IPv6 address is not the same element as
/// the IPv4 address it maps.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::routing_table::IpSet;
///
/// let mut s = IpSet::default();
/// let a = "1.2.3.4".parse().unwrap();
/// s.insert(a);
/// s.insert(a);
/// assert_eq!(s.len(), 2);
/// s.erase(a);
/// assert!(s.exists(a));
/// s.erase(a);
/// assert!(!s.exists(a));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpSet {
    counts: HashMap<IpAddr, u32>,
    len: usize,
}

impl IpSet {
    /// Adds one occurrence of `addr` (libtorrent `ip_set::insert`).
    pub fn insert(&mut self, addr: IpAddr) {
        *self.counts.entry(addr).or_insert(0) += 1;
        self.len += 1;
    }

    /// `true` if at least one occurrence of `addr` is present
    /// (libtorrent `exists`).
    #[must_use]
    pub fn exists(&self, addr: IpAddr) -> bool {
        self.counts.contains_key(&addr)
    }

    /// Removes one occurrence of `addr` (libtorrent `erase`). Returns whether
    /// there was one; libtorrent asserts that there is.
    pub fn erase(&mut self, addr: IpAddr) -> bool {
        let Some(count) = self.counts.get_mut(&addr) else {
            return false;
        };
        *count -= 1;
        if *count == 0 {
            self.counts.remove(&addr);
        }
        self.len -= 1;
        true
    }

    /// Removes everything (libtorrent `clear`).
    pub fn clear(&mut self) {
        self.counts.clear();
        self.len = 0;
    }

    /// The total number of occurrences, counting duplicates (libtorrent
    /// `size`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` when the set holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// One routing table bucket (libtorrent `routing_table_node`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bucket {
    /// Nodes that have answered us at least once; all `pinged()`.
    pub live_nodes: Vec<NodeEntry>,
    /// Candidates waiting for a live slot: unconfirmed nodes, and confirmed
    /// ones that did not fit.
    pub replacements: Vec<NodeEntry>,
}

/// The outcome of trying to insert a node (libtorrent
/// `routing_table::add_node_status_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddNodeStatus {
    /// The node was rejected (wrong family, blocked, duplicate IP, ...).
    FailedToAdd,
    /// The node was inserted, refreshed or replaced another one.
    NodeAdded,
    /// The last bucket is full and splitting it may make room.
    NeedBucketSplit,
}

/// Options for [`RoutingTable::find_node`] (libtorrent
/// `find_nodes_flags_t`).
///
/// A flag set as a newtype over `u8`; combine with `|`.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::routing_table::FindNodeOptions;
///
/// let o = FindNodeOptions::NONE | FindNodeOptions::INCLUDE_FAILED;
/// assert!(o.contains(FindNodeOptions::INCLUDE_FAILED));
/// assert!(!FindNodeOptions::NONE.contains(FindNodeOptions::INCLUDE_FAILED));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct FindNodeOptions(pub u8);

impl FindNodeOptions {
    /// No options: only confirmed nodes (`timeout_count == 0`) are returned.
    pub const NONE: Self = Self(0);
    /// Also return nodes that have failed, and nodes we never pinged
    /// (libtorrent `routing_table::include_failed`).
    pub const INCLUDE_FAILED: Self = Self(1);

    /// `true` if every flag of `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for FindNodeOptions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// The population of one bucket, as reported in the `dht_routing_bucket`
/// alert (libtorrent `dht_routing_bucket`, minus the deprecated
/// `last_active`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketStatus {
    /// Live nodes in the bucket.
    pub num_nodes: usize,
    /// Nodes in the bucket's replacement cache.
    pub num_replacements: usize,
}

/// Why [`RoutingTable::try_new`] rejected its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RoutingTableError {
    /// The bucket size must be a power of two, at least 1 (libtorrent
    /// asserts `((bucket_size - 1) & bucket_size) == 0`): the prefix-slot
    /// classification splits a byte of the node ID into `bucket_size` slots.
    #[error("bucket size {0} is not a power of two")]
    InvalidBucketSize(usize),
}

/// A broken routing table invariant, found by
/// [`RoutingTable::check_invariants`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvariantError {
    /// A live node was never pinged (libtorrent asserts `j.pinged()`).
    #[error("live node {id} in bucket {bucket} was never pinged")]
    LiveNodeNotPinged {
        /// The bucket index.
        bucket: usize,
        /// The offending node.
        id: NodeId,
    },
    /// The IP set does not match the addresses stored in the buckets.
    #[error("the IP set differs from the addresses stored in the buckets")]
    IpSetMismatch,
    /// A node sits in a bucket its ID does not belong to.
    #[error("node {id} is in bucket {bucket} but belongs in bucket {expected}")]
    WrongBucket {
        /// Where it is.
        bucket: usize,
        /// Where it should be.
        expected: usize,
        /// The offending node.
        id: NodeId,
    },
    /// A node with our own ID is in the table.
    #[error("the table contains an entry with our own node ID")]
    ContainsOwnId,
    /// A node of the other address family is in the table.
    #[error("node {id} in bucket {bucket} is not of the table's address family")]
    ForeignFamily {
        /// The bucket index.
        bucket: usize,
        /// The offending node.
        id: NodeId,
    },
    /// The last bucket is empty (it should have been pruned).
    #[error("the last bucket is empty")]
    EmptyLastBucket,
}

/// Where a node lives inside the table.
#[derive(Debug, Clone, Copy)]
struct Location {
    bucket: usize,
    replacement: bool,
    index: usize,
}

/// `true` if two IPs are "too close" to be both admitted: the same /24 for
/// IPv4, the same /64 for IPv6 (libtorrent `compare_ip_cidr`).
///
/// Addresses of different families are never close (libtorrent asserts that
/// the families match).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::routing_table::compare_ip_cidr;
///
/// let a = "10.255.255.0".parse().unwrap();
/// let b = "10.255.255.255".parse().unwrap();
/// assert!(compare_ip_cidr(a, b));
/// assert!(!compare_ip_cidr(a, "11.0.0.0".parse().unwrap()));
/// ```
#[must_use]
pub fn compare_ip_cidr(lhs: IpAddr, rhs: IpAddr) -> bool {
    match (lhs, rhs) {
        (IpAddr::V4(l), IpAddr::V4(r)) => (u32::from(l) ^ u32::from(r)) <= 0xff,
        (IpAddr::V6(l), IpAddr::V6(r)) => l.octets()[..8] == r.octets()[..8],
        _ => false,
    }
}

/// `true` when at least two thirds of the bucket's nodes are verified (BEP
/// 42), or when it is empty (libtorrent `mostly_verified_nodes`).
///
/// A bucket that has nodes but not a single verified one is never "mostly
/// verified". Used to refuse splitting a bucket full of unverifiable nodes.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::node_entry::NodeEntry;
/// use cloudllm_dht::routing_table::mostly_verified_nodes;
///
/// assert!(mostly_verified_nodes(&[]));
/// let mut n = NodeEntry::unknown_id("1.2.3.4:5".parse().unwrap());
/// assert!(!mostly_verified_nodes(&[n]));
/// n.verified = true;
/// assert!(mostly_verified_nodes(&[n]));
/// ```
#[must_use]
pub fn mostly_verified_nodes(bucket: &[NodeEntry]) -> bool {
    let num_verified = bucket.iter().filter(|e| e.verified).count();
    if num_verified == 0 && !bucket.is_empty() {
        return false;
    }
    num_verified >= bucket.len() * 2 / 3
}

/// The prefix "slot" of `nid` inside a bucket: the `log2(bucket_size)` bits
/// of the ID that follow the bits the bucket already fixes (libtorrent
/// `classify_prefix`).
///
/// Bucket `bucket_idx` fixes its first `bucket_idx` bits, and the bit after
/// them too unless it is the `last_bucket` (which has not split yet and so
/// still holds both sides). The next `log2(bucket_size)` bits are the slot,
/// in `0..bucket_size`. The routing table keeps one node per slot so that a
/// lookup has a good first hop into every sub-branch.
///
/// `bucket_size` is expected to be a power of two up to 256; any other value
/// is treated as the power of two at or below it (`0` as `1`), where
/// libtorrent only asserts. Bits beyond the end of the ID read as zero.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::routing_table::classify_prefix;
/// use cloudllm_dht::testing::to_hash;
///
/// let id = to_hash("acdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdc");
/// // 0xac = 1010 1100: the last bucket looks at the top three bits.
/// assert_eq!(classify_prefix(0, true, 8, &id), 0b101);
/// // a split bucket skips the first one: bits 010.
/// assert_eq!(classify_prefix(0, false, 8, &id), 0b010);
/// ```
#[must_use]
pub fn classify_prefix(
    bucket_idx: usize,
    last_bucket: bool,
    bucket_size: usize,
    nid: &NodeId,
) -> u8 {
    let bits = bucket_size.max(1).ilog2().min(8);
    if bits == 0 {
        return 0;
    }
    let shift = bucket_idx + usize::from(!last_bucket);
    let (byte, bit) = (shift / 8, shift % 8);
    let at = |i: usize| nid.0.get(i).copied().unwrap_or(0);
    // The first byte of `nid << shift`.
    let first = if bit == 0 {
        at(byte)
    } else {
        (at(byte) << bit) | (at(byte + 1) >> (8 - bit))
    };
    first >> (8 - bits)
}

/// `true` if the new node `id` and every node in `b` have the same value in
/// bit `bucket_index` of the node ID, i.e. splitting the bucket on that bit
/// would not separate any of them (libtorrent `all_in_same_bucket`).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::routing_table::all_in_same_bucket;
/// use cloudllm_dht::node_entry::NodeEntry;
/// use cloudllm_dht::testing::to_hash;
///
/// let ep = "1.2.3.4:5".parse().unwrap();
/// let mut n = NodeEntry::unknown_id(ep);
/// n.id = to_hash("0000000000000000000000000000000000000000");
/// let id = to_hash("8000000000000000000000000000000000000000");
/// assert!(!all_in_same_bucket(&[n], &id, 0));
/// assert!(all_in_same_bucket(&[], &id, 0));
/// ```
#[must_use]
pub fn all_in_same_bucket(b: &[NodeEntry], id: &NodeId, bucket_index: usize) -> bool {
    let (byte_offset, bit_offset) = (bucket_index / 8, bucket_index % 8);
    let mask = 0x80u8 >> bit_offset;
    let bit = |h: &NodeId| h.0.get(byte_offset).is_some_and(|v| v & mask != 0);
    let first = bit(id);
    b.iter().all(|e| bit(&e.id) == first)
}

/// The index of the first element that no other element is greater than,
/// like C++ `std::max_element` (Rust's `Iterator::max_by` returns the last).
fn first_max_index(len: usize, mut less: impl FnMut(usize, usize) -> bool) -> Option<usize> {
    (0..len).fold(None, |best, i| match best {
        Some(b) if !less(b, i) => Some(b),
        _ => Some(i),
    })
}

/// Replaces one node of the full bucket `b` with `e` if a good victim
/// exists (libtorrent `replace_node_impl`).
///
/// In order of preference the victim is:
///
/// 1. the node with the most consecutive failures, if any failed at all;
/// 2. the worst node (verified status, then RTT) sharing `e`'s prefix slot
///    ([`classify_prefix`]), but only if `e` is better than it;
/// 3. if `e`'s slot is empty, the worst node among those whose slots hold
///    more than one node.
///
/// Returns [`AddNodeStatus::NodeAdded`] after replacing (keeping `ips` in
/// step) and [`AddNodeStatus::NeedBucketSplit`] when no victim was found; it
/// never returns `FailedToAdd`. Ties are broken towards the first candidate
/// in bucket order, like `std::max_element`. An empty `b` finds no victim.
#[must_use]
pub fn replace_node_impl(
    e: &NodeEntry,
    b: &mut [NodeEntry],
    ips: &mut IpSet,
    bucket_index: usize,
    bucket_size_limit: usize,
    last_bucket: bool,
) -> AddNodeStatus {
    let Some(stale) = first_max_index(b.len(), |l, r| b[l].fail_count() < b[r].fail_count()) else {
        return AddNodeStatus::NeedBucketSplit;
    };
    let victim = if b[stale].fail_count() > 0 {
        Some(stale)
    } else {
        pick_victim_by_prefix(e, b, bucket_index, bucket_size_limit, last_bucket)
    };
    let Some(j) = victim else {
        return AddNodeStatus::NeedBucketSplit;
    };
    ips.erase(b[j].addr());
    b[j] = *e;
    ips.insert(e.addr());
    AddNodeStatus::NodeAdded
}

/// Steps 2 and 3 of [`replace_node_impl`]: the victim among healthy nodes,
/// chosen to keep the prefix slots spread out.
fn pick_victim_by_prefix(
    e: &NodeEntry,
    b: &[NodeEntry],
    bucket_index: usize,
    bucket_size_limit: usize,
    last_bucket: bool,
) -> Option<usize> {
    let slot = |n: &NodeEntry| classify_prefix(bucket_index, last_bucket, bucket_size_limit, &n.id);
    let to_add = slot(e);
    let slots: Vec<u8> = b.iter().map(slot).collect();
    // "worst" is the maximum under `is_better_than`, as in libtorrent.
    let worst_of = |candidates: &[usize]| {
        first_max_index(candidates.len(), |l, r| {
            b[candidates[l]].is_better_than(&b[candidates[r]])
        })
        .map(|i| candidates[i])
    };

    if slots.contains(&to_add) {
        let same: Vec<usize> = (0..b.len()).filter(|&i| slots[i] == to_add).collect();
        // Replace only if `e` beats the worst node in its slot.
        return worst_of(&same).filter(|&j| e.is_better_than(&b[j]));
    }
    // No node in `e`'s slot: it is wanted. Take the worst among the nodes of
    // crowded slots, visiting slots in ascending order.
    let mut counts = [0u16; 256];
    slots.iter().for_each(|&s| counts[usize::from(s)] += 1);
    let mut crowded: Vec<usize> = (0..b.len())
        .filter(|&i| counts[usize::from(slots[i])] > 1)
        .collect();
    crowded.sort_by_key(|&i| slots[i]);
    worst_of(&crowded)
}

/// Whether to accept a node ID given the address it came from: with
/// `enforce_node_id` the ID must be BEP 42 valid for the address.
fn verify_node_address(settings: &DhtSettings, id: &NodeId, addr: IpAddr) -> bool {
    !settings.enforce_node_id || verify_id(id, addr)
}

fn same_endpoint(a: &SocketAddr, b: &SocketAddr) -> bool {
    a.ip() == b.ip() && a.port() == b.port()
}

/// The Kademlia routing table of one DHT node (libtorrent
/// `dht::routing_table`).
///
/// One table serves one address family ([`Protocol`]); a dual-stack node has
/// two. See the [module documentation](self) for the structure and the
/// differences from libtorrent.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::net::Protocol;
/// use cloudllm_dht::routing_table::{FindNodeOptions, RoutingTable};
/// use cloudllm_dht::settings::DhtSettings;
/// use cloudllm_dht::time::Time;
/// use cloudllm_dht::testing::to_hash;
///
/// let ours = to_hash("3123456789abcdef01232456789abcdef0123456");
/// let mut table = RoutingTable::new(ours, Protocol::V4, 8, &DhtSettings::default());
///
/// let theirs = to_hash("e123456789abcdef01232456789abcdef0123456");
/// let ep = "4.4.4.4:6881".parse().unwrap();
/// assert!(table.node_seen(theirs, ep, 30, Time::ZERO));
///
/// let (nodes, replacements, confirmed) = table.size();
/// assert_eq!((nodes, replacements, confirmed), (1, 0, 1));
/// let closest = table.find_node(&theirs, FindNodeOptions::NONE, 8);
/// assert_eq!(closest[0].id, theirs);
/// ```
pub struct RoutingTable {
    /// Bucket 0 is farthest from our ID; the last bucket is the one that
    /// splits.
    buckets: Vec<Bucket>,
    id: NodeId,
    protocol: Protocol,
    /// The last seen depth. libtorrent keeps it `mutable` and updates it from
    /// the `const` `depth()`; an atomic keeps this type `Sync`.
    depth: AtomicI32,
    /// Endpoints that are used in searches but never added to the table.
    router_nodes: BTreeSet<SocketAddr>,
    /// Every address in the table, for the one-node-per-IP rule.
    ips: IpSet,
    settings: DhtSettings,
    ip_filter: Option<IpFilter>,
    /// `k` in the paper.
    bucket_size: usize,
}

impl Clone for RoutingTable {
    fn clone(&self) -> Self {
        Self {
            buckets: self.buckets.clone(),
            id: self.id,
            protocol: self.protocol,
            depth: AtomicI32::new(self.depth.load(AtomicOrdering::Relaxed)),
            router_nodes: self.router_nodes.clone(),
            ips: self.ips.clone(),
            settings: self.settings.clone(),
            ip_filter: self.ip_filter.clone(),
            bucket_size: self.bucket_size,
        }
    }
}

impl fmt::Debug for RoutingTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutingTable")
            .field("id", &self.id)
            .field("protocol", &self.protocol)
            .field("bucket_size", &self.bucket_size)
            .field("buckets", &self.buckets)
            .field("router_nodes", &self.router_nodes)
            .field("ip_filter", &self.ip_filter.as_ref().map(|_| "<filter>"))
            .finish_non_exhaustive()
    }
}

impl RoutingTable {
    /// Creates an empty table (libtorrent `routing_table::routing_table`).
    ///
    /// `bucket_size` is `k`, libtorrent uses 8. `settings` is copied; see
    /// [`RoutingTable::set_settings`].
    ///
    /// # Panics
    ///
    /// Panics if `bucket_size` is not a power of two; use
    /// [`RoutingTable::try_new`] to handle configuration errors.
    #[must_use]
    pub fn new(id: NodeId, protocol: Protocol, bucket_size: usize, settings: &DhtSettings) -> Self {
        Self::try_new(id, protocol, bucket_size, settings)
            .expect("the routing table bucket size must be a power of two")
    }

    /// Like [`RoutingTable::new`] but reports a bad bucket size as an error.
    ///
    /// # Errors
    ///
    /// [`RoutingTableError::InvalidBucketSize`] unless `bucket_size` is a
    /// power of two.
    pub fn try_new(
        id: NodeId,
        protocol: Protocol,
        bucket_size: usize,
        settings: &DhtSettings,
    ) -> Result<Self, RoutingTableError> {
        if !bucket_size.is_power_of_two() {
            return Err(RoutingTableError::InvalidBucketSize(bucket_size));
        }
        Ok(Self {
            buckets: Vec::with_capacity(30),
            id,
            protocol,
            depth: AtomicI32::new(0),
            router_nodes: BTreeSet::new(),
            ips: IpSet::default(),
            settings: settings.clone(),
            ip_filter: None,
            bucket_size,
        })
    }

    /// Our own node ID (libtorrent `id()`).
    #[must_use]
    pub fn id(&self) -> NodeId {
        self.id
    }

    /// The address family this table serves.
    #[must_use]
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// The settings the table consults.
    #[must_use]
    pub fn settings(&self) -> &DhtSettings {
        &self.settings
    }

    /// Replaces the settings (libtorrent's table reads the live
    /// `session_settings`, so changes apply immediately there).
    ///
    /// Existing entries are not re-validated: turning
    /// `restrict_routing_ips` on does not evict duplicates already present.
    pub fn set_settings(&mut self, settings: &DhtSettings) {
        self.settings = settings.clone();
    }

    /// Installs (or removes) an IP filter consulted for every node added
    /// (libtorrent `dht_observer::get_dht_ip_filter` together with
    /// `apply_filter_to_dht`). Router nodes are exempt, as in libtorrent.
    ///
    /// The filter returns `true` for a blocked address.
    pub fn set_ip_filter(&mut self, filter: Option<IpFilter>) {
        self.ip_filter = filter;
    }

    /// `k`, the nominal bucket size (libtorrent `bucket_size()`).
    #[must_use]
    pub fn bucket_size(&self) -> usize {
        self.bucket_size
    }

    /// The buckets, farthest from our ID first (libtorrent `buckets()`).
    #[must_use]
    pub fn buckets(&self) -> &[Bucket] {
        &self.buckets
    }

    /// The number of live nodes in `bucket`; a bucket index past the end
    /// means the last bucket, and an empty table has no nodes (libtorrent
    /// `bucket_size(int)`, renamed because [`RoutingTable::bucket_size`] is
    /// `k`).
    #[must_use]
    pub fn bucket_len(&self, bucket: usize) -> usize {
        self.buckets
            .get(bucket.min(self.buckets.len().saturating_sub(1)))
            .map_or(0, |b| b.live_nodes.len())
    }

    /// The number of buckets (libtorrent `num_active_buckets`).
    #[must_use]
    pub fn num_active_buckets(&self) -> usize {
        self.buckets.len()
    }

    /// How many live nodes `bucket` may hold (libtorrent `bucket_limit`):
    /// `bucket_size`, times 16, 8, 4 and 2 for the first four buckets when
    /// [`DhtSettings::extended_routing_table`] is on.
    #[must_use]
    pub fn bucket_limit(&self, bucket: usize) -> usize {
        if !self.settings.extended_routing_table {
            return self.bucket_size;
        }
        SIZE_EXCEPTIONS
            .get(bucket)
            .map_or(self.bucket_size, |m| self.bucket_size * m)
    }

    /// `true` if `bucket` has its maximum of live nodes *and* a full
    /// replacement cache (libtorrent `is_full`); `false` for a bucket that
    /// does not exist.
    #[must_use]
    pub fn is_full(&self, bucket: usize) -> bool {
        self.buckets.get(bucket).is_some_and(|b| {
            b.live_nodes.len() >= self.bucket_limit(bucket)
                && b.replacements.len() >= self.bucket_size
        })
    }

    /// `true` if `addr` is of this table's address family (libtorrent
    /// `native_address`).
    #[must_use]
    pub fn native_address(&self, addr: &IpAddr) -> bool {
        Protocol::of(addr) == self.protocol
    }

    /// `true` if `ep` is of this table's address family (libtorrent
    /// `native_endpoint`).
    #[must_use]
    pub fn native_endpoint(&self, ep: &SocketAddr) -> bool {
        self.native_address(&ep.ip())
    }

    /// Registers an endpoint that searches use but the table never stores
    /// (libtorrent `add_router_node`).
    pub fn add_router_node(&mut self, router: SocketAddr) {
        self.router_nodes.insert(router);
    }

    /// The router nodes, in endpoint order (libtorrent `begin()/end()`).
    pub fn router_nodes(&self) -> impl Iterator<Item = &SocketAddr> {
        self.router_nodes.iter()
    }

    /// The live nodes of every bucket, farthest bucket first.
    pub fn live_nodes(&self) -> impl Iterator<Item = &NodeEntry> {
        self.buckets.iter().flat_map(|b| b.live_nodes.iter())
    }

    /// The replacement-cache nodes of every bucket.
    pub fn replacement_nodes(&self) -> impl Iterator<Item = &NodeEntry> {
        self.buckets.iter().flat_map(|b| b.replacements.iter())
    }

    /// Calls `live_cb` for every live node and `replacements_cb` for every
    /// replacement node, bucket by bucket, live nodes first (libtorrent
    /// `for_each_node(live_cb, replacements_cb)`).
    ///
    /// Pass `|_| {}` for a half you do not need.
    pub fn for_each_node(
        &self,
        mut live_cb: impl FnMut(&NodeEntry),
        mut replacements_cb: impl FnMut(&NodeEntry),
    ) {
        for b in &self.buckets {
            b.live_nodes.iter().for_each(&mut live_cb);
            b.replacements.iter().for_each(&mut replacements_cb);
        }
    }

    /// Calls `f` for every live and replacement node, per bucket live nodes
    /// first (libtorrent's one-argument `for_each_node`).
    pub fn for_each_entry(&self, mut f: impl FnMut(&NodeEntry)) {
        for b in &self.buckets {
            b.live_nodes.iter().chain(&b.replacements).for_each(&mut f);
        }
    }

    /// `(live nodes, replacement nodes, confirmed live nodes)` (libtorrent
    /// `size()`); confirmed means pinged and answered since.
    #[must_use]
    pub fn size(&self) -> (usize, usize, usize) {
        self.buckets.iter().fold((0, 0, 0), |(n, r, c), b| {
            (
                n + b.live_nodes.len(),
                r + b.replacements.len(),
                c + b.live_nodes.iter().filter(|e| e.confirmed()).count(),
            )
        })
    }

    /// An estimate of the number of nodes in the whole DHT (libtorrent
    /// `num_global_nodes`), extrapolated from how many leading buckets are
    /// full. Saturates at `u64::MAX` for absurdly deep tables.
    #[must_use]
    pub fn num_global_nodes(&self) -> u64 {
        let mut deepest_bucket = 0u32;
        let mut deepest_size = 0usize;
        for b in &self.buckets {
            deepest_size = b.live_nodes.len();
            if deepest_size < self.bucket_size {
                break;
            }
            deepest_bucket += 1;
        }
        if deepest_bucket == 0 {
            return 1 + deepest_size as u64;
        }
        let scale = 1u128 << deepest_bucket.min(100);
        let estimate = if deepest_size < self.bucket_size / 2 {
            scale * self.bucket_size as u128
        } else {
            2 * scale * deepest_size as u128
        };
        u64::try_from(estimate).unwrap_or(u64::MAX)
    }

    /// The number of bits down the table that we have (about) full buckets
    /// (libtorrent `depth`).
    ///
    /// The result depends on the previous call: the cached depth is walked
    /// deeper while the next bucket is at least half full, and shallower
    /// while the previous bucket is less than half full. `0` for an empty
    /// table (libtorrent returns `-1`, see the module docs).
    #[must_use]
    pub fn depth(&self) -> usize {
        let Some(last) = self.buckets.len().checked_sub(1) else {
            self.depth.store(0, AtomicOrdering::Relaxed);
            return 0;
        };
        let half = self.bucket_size / 2;
        let live = |i: usize| self.buckets[i].live_nodes.len();
        let mut d = usize::try_from(self.depth.load(AtomicOrdering::Relaxed))
            .unwrap_or(0)
            .min(last);
        while d < last && live(d + 1) >= half {
            d += 1;
        }
        while d > 0 && live(d - 1) < half {
            d -= 1;
        }
        self.depth.store(
            i32::try_from(d).unwrap_or(i32::MAX),
            AtomicOrdering::Relaxed,
        );
        d
    }

    /// Per-bucket populations for the `dht_routing_bucket` alert (libtorrent
    /// `status(std::vector<dht_routing_bucket>&)` without its accumulation
    /// quirk; see [`RoutingTable::status_into`]).
    #[must_use]
    pub fn status(&self) -> Vec<BucketStatus> {
        self.buckets
            .iter()
            .map(|b| BucketStatus {
                num_nodes: b.live_nodes.len(),
                num_replacements: b.replacements.len(),
            })
            .collect()
    }

    /// libtorrent's `status(std::vector<dht_routing_bucket>&)` exactly: `s`
    /// is only overwritten if this table has at least as many buckets as
    /// `s` already holds, so with several tables (multi-homed) the deepest
    /// one is reported.
    pub fn status_into(&self, s: &mut Vec<BucketStatus>) {
        if s.len() > self.buckets.len() {
            return;
        }
        *s = self.status();
    }

    // ---------------------------------------------------------------
    // finding nodes
    // ---------------------------------------------------------------

    /// The bucket a node ID belongs to; the table must not be empty.
    fn bucket_index_for(&self, id: &NodeId) -> usize {
        let exp = usize::try_from(distance_exp(&self.id, id)).unwrap_or(0);
        159usize.saturating_sub(exp).min(self.buckets.len() - 1)
    }

    /// Like `bucket_index_for` but creates the first bucket when the table
    /// is empty (libtorrent `find_bucket`).
    fn find_bucket(&mut self, id: &NodeId) -> usize {
        if self.buckets.is_empty() {
            self.buckets.push(Bucket::default());
        }
        self.bucket_index_for(id)
    }

    /// Locates the node with exactly this endpoint, replacements of a bucket
    /// before its live nodes (libtorrent `find_node(udp::endpoint)`).
    fn locate(&self, ep: &SocketAddr) -> Option<Location> {
        self.buckets.iter().enumerate().find_map(|(bucket, b)| {
            let find = |v: &[NodeEntry], replacement| {
                v.iter()
                    .position(|n| same_endpoint(&n.endpoint, ep))
                    .map(|index| Location {
                        bucket,
                        replacement,
                        index,
                    })
            };
            find(&b.replacements, true).or_else(|| find(&b.live_nodes, false))
        })
    }

    fn entry(&self, loc: Location) -> &NodeEntry {
        let b = &self.buckets[loc.bucket];
        if loc.replacement {
            &b.replacements[loc.index]
        } else {
            &b.live_nodes[loc.index]
        }
    }

    fn entry_mut(&mut self, loc: Location) -> &mut NodeEntry {
        let b = &mut self.buckets[loc.bucket];
        if loc.replacement {
            &mut b.replacements[loc.index]
        } else {
            &mut b.live_nodes[loc.index]
        }
    }

    /// Removes the node at `loc` and its IP (libtorrent `remove_node`).
    fn remove_at(&mut self, loc: Location) {
        let b = &mut self.buckets[loc.bucket];
        let removed = if loc.replacement {
            b.replacements.remove(loc.index)
        } else {
            b.live_nodes.remove(loc.index)
        };
        self.ips.erase(removed.addr());
    }

    /// Returns up to `count` nodes closest to `target` (libtorrent
    /// `find_node`); `count == 0` means `bucket_size`.
    ///
    /// Only confirmed nodes are returned unless
    /// [`FindNodeOptions::INCLUDE_FAILED`] is given. The search starts in the
    /// bucket the target falls into, continues to the closer buckets, and
    /// finally to the farther ones. When more than `count` candidates are
    /// found in the last bucket visited, the closest are selected, but the
    /// result is **not sorted**: only its membership is specified.
    ///
    /// # Examples
    ///
    /// ```
    /// use cloudllm_dht::net::Protocol;
    /// use cloudllm_dht::routing_table::{FindNodeOptions, RoutingTable};
    /// use cloudllm_dht::settings::DhtSettings;
    /// use cloudllm_dht::testing::to_hash;
    ///
    /// let table = RoutingTable::new(to_hash("0000000000000000000000000000000000000000"), Protocol::V4, 8, &DhtSettings::default());
    /// assert!(table.find_node(&to_hash("ffffffffffffffffffffffffffffffffffffffff"), FindNodeOptions::NONE, 0).is_empty());
    /// ```
    #[must_use]
    pub fn find_node(
        &self,
        target: &NodeId,
        options: FindNodeOptions,
        count: usize,
    ) -> Vec<NodeEntry> {
        let count = if count == 0 { self.bucket_size } else { count };
        if self.buckets.is_empty() {
            return Vec::new();
        }
        let first = self.bucket_index_for(target);
        let mut found = Vec::with_capacity(self.bucket_limit(first));
        // First the target's bucket and the (closer) ones after it, then the
        // (farther) ones before it.
        let order = (first..self.buckets.len()).chain((0..first).rev());
        for j in order {
            let unsorted_start = found.len();
            let bucket = &self.buckets[j].live_nodes;
            if options.contains(FindNodeOptions::INCLUDE_FAILED) {
                found.extend_from_slice(bucket);
            } else {
                found.extend(bucket.iter().filter(|n| n.confirmed()).copied());
            }
            if select_closest(&mut found, count, unsorted_start, target) {
                break;
            }
        }
        found
    }

    /// Picks the node that should be pinged next to keep the table fresh
    /// (libtorrent `next_refresh`) and stamps it as queried at `now`, so the
    /// next call picks a different one.
    ///
    /// The candidate is the never-queried live node closest to us, else the
    /// live node queried longest ago; in the last bucket and in any bucket
    /// with room it may also be an unpinged replacement that was never
    /// queried, which might be promoted if it answers. Returns the (updated)
    /// entry and the index of its bucket. `None` when the table is empty.
    ///
    /// [`Time::ZERO`] is "never queried", so drive the table with a clock
    /// that starts after zero.
    pub fn next_refresh(&mut self, now: Time) -> Option<(NodeEntry, usize)> {
        let location = self.refresh_candidate()?;
        let entry = self.entry_mut(location);
        entry.last_queried = now;
        Some((*entry, location.bucket))
    }

    fn refresh_candidate(&self) -> Option<Location> {
        let last = self.buckets.len().checked_sub(1)?;
        let mut best: Option<Location> = None;
        // Closest buckets first: a bias towards pinging nodes near us.
        for bucket in (0..=last).rev() {
            let b = &self.buckets[bucket];
            for (index, n) in b.live_nodes.iter().enumerate() {
                if n.id == self.id {
                    continue;
                }
                let loc = Location {
                    bucket,
                    replacement: false,
                    index,
                };
                if n.last_queried == Time::ZERO {
                    return Some(loc);
                }
                if best.is_none_or(|c| n.last_queried < self.entry(c).last_queried) {
                    best = Some(loc);
                }
            }
            // The bucket is not full or can still split: look for an unpinged
            // replacement that could be promoted if it answers.
            if bucket == last || b.live_nodes.len() < self.bucket_limit(bucket) {
                let fresh = b
                    .replacements
                    .iter()
                    .position(|e| !e.pinged() && e.last_queried == Time::ZERO);
                if let Some(index) = fresh {
                    return Some(Location {
                        bucket,
                        replacement: true,
                        index,
                    });
                }
            }
        }
        best
    }

    // ---------------------------------------------------------------
    // adding and removing nodes
    // ---------------------------------------------------------------

    /// Records a sign of life from a node: inserts it, or refreshes its
    /// entry (libtorrent `node_seen`). The node counts as pinged, and its
    /// `rtt` is folded into the average.
    ///
    /// With `enforce_node_id` the ID must match the endpoint's IP (BEP 42).
    /// Returns `true` if the node is now in the table (live or replacement).
    ///
    /// # Examples
    ///
    /// ```
    /// use cloudllm_dht::net::Protocol;
    /// use cloudllm_dht::routing_table::RoutingTable;
    /// use cloudllm_dht::settings::DhtSettings;
    /// use cloudllm_dht::time::Time;
    /// use cloudllm_dht::testing::to_hash;
    ///
    /// let mut t = RoutingTable::new(to_hash("0000000000000000000000000000000000000000"), Protocol::V4, 8, &DhtSettings::default());
    /// let id = to_hash("8000000000000000000000000000000000000001");
    /// assert!(t.node_seen(id, "4.4.4.4:1".parse().unwrap(), 10, Time::ZERO));
    /// // The table never stores our own ID.
    /// assert!(!t.node_seen(t.id(), "5.5.5.5:1".parse().unwrap(), 10, Time::ZERO));
    /// ```
    pub fn node_seen(&mut self, id: NodeId, ep: SocketAddr, rtt: u16, now: Time) -> bool {
        verify_node_address(&self.settings, &id, ep.ip())
            && self.add_node(NodeEntry::new_at(id, ep, rtt, true, now), now)
    }

    /// Records that we heard of a node from a third party, without having
    /// talked to it: it may be spoofed, so it goes to the replacement cache
    /// unless it is already known (libtorrent `heard_about`).
    pub fn heard_about(&mut self, id: NodeId, ep: SocketAddr, now: Time) {
        if verify_node_address(&self.settings, &id, ep.ip()) {
            let _ = self.add_node(NodeEntry::new_at(id, ep, 0xffff, false, now), now);
        }
    }

    /// Notes that a request to this node timed out (libtorrent
    /// `node_failed`).
    ///
    /// A node with a replacement waiting is replaced at once; one without is
    /// dropped after `max_fail_count` consecutive failures, or immediately if
    /// it never answered. A mismatched endpoint (another node claiming the
    /// ID) and our own ID are ignored.
    pub fn node_failed(&mut self, id: &NodeId, ep: SocketAddr) {
        if *id == self.id {
            return;
        }
        let i = self.find_bucket(id);
        let max_fail = i64::from(self.settings.max_fail_count);
        let b = &mut self.buckets[i];
        let Some(j) = b.live_nodes.iter().position(|n| n.id == *id) else {
            if let Some(n) = b
                .replacements
                .iter_mut()
                .find(|n| n.id == *id && same_endpoint(&n.endpoint, &ep))
            {
                n.timed_out();
            }
            return;
        };
        if !same_endpoint(&b.live_nodes[j].endpoint, &ep) {
            return;
        }
        if b.replacements.is_empty() {
            let n = &mut b.live_nodes[j];
            n.timed_out();
            if i64::from(n.fail_count()) >= max_fail || !n.pinged() {
                let addr = n.addr();
                b.live_nodes.remove(j);
                self.ips.erase(addr);
            }
            return;
        }
        let removed = b.live_nodes.remove(j);
        self.ips.erase(removed.addr());
        self.fill_from_replacements(i);
        self.prune_empty_bucket();
    }

    /// Inserts a node, splitting the last bucket as often as needed
    /// (libtorrent `add_node`). Returns `true` if the node ended up in the
    /// table.
    ///
    /// The rules, in order: wrong address family, blocked by the IP filter,
    /// or a router node: rejected. The same endpoint with the same ID just
    /// refreshes the entry; the same endpoint with another ID is a sign of
    /// an attack and evicts the old entry (see
    /// [`DhtSettings::restrict_routing_ips`]). Our own ID is rejected. Then
    /// the bucket logic: insert if there is room, else maybe split, replace a
    /// worse node ([`replace_node_impl`]), or cache in the replacement
    /// bucket.
    pub fn add_node(&mut self, e: NodeEntry, now: Time) -> bool {
        loop {
            match self.add_node_impl(e, now) {
                AddNodeStatus::FailedToAdd => return false,
                AddNodeStatus::NodeAdded => return true,
                AddNodeStatus::NeedBucketSplit => {}
            }
            self.split_bucket();
            if self.buckets.len() > MAX_SPLIT_DEPTH {
                // A sanity limit: real tables are 26 or 27 deep. A deeper one
                // means a bug or somebody spoofing node IDs.
                return self.add_node_impl(e, now) == AddNodeStatus::NodeAdded;
            }
            // Keep splitting while the new last bucket is still over-full.
            if self.last_bucket_overfull() {
                continue;
            }
            let status = self.add_node_impl(e, now);
            // If nothing, not even `e`, ended up in the new bucket, drop it.
            if self.buckets.last().is_some_and(|b| b.live_nodes.is_empty()) {
                self.buckets.pop();
            }
            match status {
                AddNodeStatus::FailedToAdd => return false,
                AddNodeStatus::NodeAdded => return true,
                AddNodeStatus::NeedBucketSplit => {}
            }
        }
    }

    fn last_bucket_overfull(&self) -> bool {
        self.buckets
            .last()
            .is_some_and(|b| b.live_nodes.len() > self.bucket_limit(self.buckets.len() - 1))
    }

    /// One attempt at inserting `e` (libtorrent `add_node_impl`).
    ///
    /// Takes `e` by value because a node found in the replacement bucket is
    /// promoted with its stored fields.
    fn add_node_impl(&mut self, mut e: NodeEntry, now: Time) -> AddNodeStatus {
        use AddNodeStatus::{FailedToAdd, NodeAdded};
        if !self.native_endpoint(&e.endpoint)
            || self.ip_filter.as_ref().is_some_and(|f| f(e.addr()))
            || self.router_nodes.contains(&e.endpoint)
        {
            return FailedToAdd;
        }
        if self.ips.exists(e.addr()) {
            if let Some(status) = self.handle_known_ip(&e, now) {
                return status;
            }
        }
        if e.id == self.id {
            return FailedToAdd;
        }

        let i = self.find_bucket(&e.id);
        let limit = self.bucket_limit(i);

        if let Some(status) = self.refresh_existing_id(i, &e) {
            return status;
        }
        if let Some(promoted) = self.take_from_replacements(i, &e) {
            match promoted {
                Some(entry) => e = entry,
                None => return FailedToAdd,
            }
        }
        if self.settings.restrict_routing_ips && self.too_close_to_existing(i, &e) {
            return FailedToAdd;
        }

        // If there is room in the live bucket, insert.
        let live = &mut self.buckets[i].live_nodes;
        if e.pinged() && live.len() < limit {
            if live.is_empty() {
                live.reserve(limit);
            }
            live.push(e);
            self.ips.insert(e.addr());
            return NodeAdded;
        }

        let last_bucket = i + 1 == self.buckets.len();
        if self.can_split(i, &e) {
            return AddNodeStatus::NeedBucketSplit;
        }
        if e.confirmed() {
            let b = &mut self.buckets[i];
            let ret =
                replace_node_impl(&e, &mut b.live_nodes, &mut self.ips, i, limit, last_bucket);
            if ret != AddNodeStatus::NeedBucketSplit {
                return ret;
            }
        }
        self.insert_replacement(i, e, last_bucket)
    }

    /// The part of `add_node_impl` for a node whose IP address is already in
    /// the table. `Some` ends the insertion, `None` lets it continue.
    fn handle_known_ip(&mut self, e: &NodeEntry, now: Time) -> Option<AddNodeStatus> {
        use AddNodeStatus::{FailedToAdd, NodeAdded};
        let restrict = self.settings.restrict_routing_ips;
        // There may be a node with the same IP but another port: `ips` only
        // holds addresses, this lookup is for the full endpoint.
        let Some(loc) = self.locate(&e.endpoint) else {
            return restrict.then_some(FailedToAdd);
        };
        let existing_id = self.entry(loc).id;
        if existing_id == e.id {
            // The same node: reset its failures and take the new RTT.
            let existing = self.entry_mut(loc);
            existing.timeout_count = 0;
            if e.pinged() {
                existing.update_rtt(e.rtt);
                existing.last_queried = e.last_queried;
            }
            // A replacement may now be eligible for promotion.
            self.fill_from_replacements(loc.bucket);
            self.prune_empty_bucket();
            return Some(NodeAdded);
        }
        if existing_id == NodeId::MIN {
            // The old entry's ID was unknown: replace it with the real one.
            self.remove_at(loc);
            return None;
        }
        if !e.pinged() {
            // An unconfirmed claim on a known endpoint with a new ID looks
            // like a poisoning attack: never replace the existing entry.
            return restrict.then_some(FailedToAdd);
        }
        // Same endpoint, new ID, and we heard from it: possibly malicious,
        // so evict the old entry and have the rest of the bucket re-pinged.
        self.remove_at(loc);
        self.fill_from_replacements(loc.bucket);
        for n in &mut self.buckets[loc.bucket].live_nodes {
            if n.last_queried + REPING_AFTER < now {
                n.last_queried = Time::ZERO;
            }
        }
        self.prune_empty_bucket();
        Some(FailedToAdd)
    }

    /// If `e`'s ID is already a live node of bucket `i`: ignore a different
    /// endpoint claiming it, otherwise refresh. `None` if it is not there.
    fn refresh_existing_id(&mut self, i: usize, e: &NodeEntry) -> Option<AddNodeStatus> {
        let n = self.buckets[i]
            .live_nodes
            .iter_mut()
            .find(|n| n.id == e.id)?;
        if !same_endpoint(&n.endpoint, &e.endpoint) {
            // A new IP claims this node ID: ignore it.
            return Some(AddNodeStatus::FailedToAdd);
        }
        n.timeout_count = 0;
        n.update_rtt(e.rtt);
        Some(AddNodeStatus::NodeAdded)
    }

    /// If `e`'s ID is in bucket `i`'s replacement cache, pulls it out (it may
    /// win a live slot now that its RTT is updated). Outer `None`: not
    /// there; `Some(None)`: a different endpoint claims the ID, reject;
    /// `Some(Some(entry))`: the cached entry to insert instead of `e`.
    fn take_from_replacements(&mut self, i: usize, e: &NodeEntry) -> Option<Option<NodeEntry>> {
        let rb = &mut self.buckets[i].replacements;
        let j = rb.iter().position(|n| n.id == e.id)?;
        if !same_endpoint(&rb[j].endpoint, &e.endpoint) {
            return Some(None);
        }
        rb[j].timeout_count = 0;
        rb[j].update_rtt(e.rtt);
        let promoted = rb.remove(j);
        self.ips.erase(promoted.addr());
        Some(Some(promoted))
    }

    /// `true` if bucket `i` already has a node in the same /24 (/64) as `e`.
    fn too_close_to_existing(&self, i: usize, e: &NodeEntry) -> bool {
        let b = &self.buckets[i];
        b.live_nodes
            .iter()
            .chain(&b.replacements)
            .any(|a| compare_ip_cidr(a.addr(), e.addr()))
    }

    /// Whether the last bucket may be split to make room for `e`: it must be
    /// the last bucket, `e` confirmed (and, with `prefer_verified_node_ids`,
    /// verified in a mostly verified bucket), the bucket before it must not
    /// be nearly empty, and splitting must actually separate something.
    fn can_split(&self, i: usize, e: &NodeEntry) -> bool {
        let live = &self.buckets[i].live_nodes;
        i + 1 == self.buckets.len()
            && self.buckets.len() < 159
            && (!self.settings.prefer_verified_node_ids
                || (e.verified && mostly_verified_nodes(live)))
            && e.confirmed()
            && (i == 0 || self.buckets[i - 1].live_nodes.len() > 1)
            && !all_in_same_bucket(live, &e.id, i)
    }

    /// Puts `e` in bucket `i`'s replacement cache, making room if needed
    /// (the tail of libtorrent's `add_node_impl`).
    fn insert_replacement(&mut self, i: usize, e: NodeEntry, last_bucket: bool) -> AddNodeStatus {
        use AddNodeStatus::{FailedToAdd, NodeAdded};
        let bucket_size = self.bucket_size;
        let rb = &mut self.buckets[i].replacements;
        if let Some(j) = rb.iter().position(|n| n.id == e.id) {
            // Already cached; if the endpoint matches it is the same node,
            // make sure it is marked as pinged.
            if same_endpoint(&rb[j].endpoint, &e.endpoint) {
                rb[j].set_pinged();
            }
            return NodeAdded;
        }
        if rb.len() >= bucket_size {
            // Full: drop the oldest entry that was never pinged (less reliable
            // than `e`), else try to replace a worse one.
            let Some(j) = rb.iter().position(|n| !n.pinged()) else {
                let ret = replace_node_impl(&e, rb, &mut self.ips, i, bucket_size, last_bucket);
                return if ret == NodeAdded {
                    NodeAdded
                } else {
                    FailedToAdd
                };
            };
            let dropped = rb.remove(j);
            self.ips.erase(dropped.addr());
        }
        if rb.is_empty() {
            rb.reserve(bucket_size);
        }
        rb.push(e);
        self.ips.insert(e.addr());
        NodeAdded
    }

    /// Fills bucket `bi` from its replacement cache, best RTT and verified
    /// nodes first, only taking pinged nodes (libtorrent
    /// `fill_from_replacements`).
    fn fill_from_replacements(&mut self, bi: usize) {
        let limit = self.bucket_limit(bi);
        let Bucket {
            live_nodes: b,
            replacements: rb,
        } = &mut self.buckets[bi];
        if b.len() >= limit {
            return;
        }
        rb.sort_by(NodeEntry::quality_cmp);
        while b.len() < limit {
            let Some(j) = rb.iter().position(NodeEntry::pinged) else {
                break;
            };
            b.push(rb.remove(j));
        }
    }

    /// Removes the last bucket if it holds nothing (libtorrent
    /// `prune_empty_bucket`).
    fn prune_empty_bucket(&mut self) {
        if self
            .buckets
            .last()
            .is_some_and(|b| b.live_nodes.is_empty() && b.replacements.is_empty())
        {
            self.buckets.pop();
        }
    }

    /// Splits the last bucket by adding a new one after it and moving the
    /// nodes that are closer to us into it (libtorrent `split_bucket`).
    fn split_bucket(&mut self) {
        let bucket_index = self.buckets.len() - 1;
        let limit = self.bucket_limit(bucket_index);
        let new_limit = self.bucket_limit(bucket_index + 1);
        let threshold = 159 - i32::try_from(bucket_index).unwrap_or(159);
        // Nodes with `distance_exp >= threshold` stay; the rest move.
        let own = self.id;
        let stays = |id: &NodeId| distance_exp(&own, id) >= threshold;

        let old = std::mem::take(&mut self.buckets[bucket_index]);
        let (mut b, moved): (Vec<_>, Vec<_>) =
            old.live_nodes.into_iter().partition(|n| stays(&n.id));
        let mut new_bucket = Bucket {
            live_nodes: moved,
            replacements: Vec::new(),
        };
        let mut rb = old.replacements;

        if b.len() > limit {
            // TODO in libtorrent: move the lowest priority nodes instead.
            rb.extend_from_slice(&b[limit..]);
            b.truncate(limit);
        }

        // Split the replacements too. If the live bucket has room again, the
        // pinged ones that stay are promoted.
        let mut kept = Vec::with_capacity(rb.len());
        for n in rb {
            if stays(&n.id) {
                if !n.pinged() || b.len() >= limit {
                    kept.push(n);
                } else {
                    b.push(n);
                }
            } else if n.pinged() && new_bucket.live_nodes.len() < new_limit {
                new_bucket.live_nodes.push(n);
            } else {
                new_bucket.replacements.push(n);
            }
        }
        self.buckets[bucket_index] = Bucket {
            live_nodes: b,
            replacements: kept,
        };
        self.buckets.push(new_bucket);
    }

    /// Changes our node ID, re-inserting every node under the new ID
    /// (libtorrent `update_node_id`). Can be expensive, and drops nodes that
    /// no longer fit, or that the restrictions reject.
    ///
    /// Live nodes are re-added first, then the replacements.
    pub fn set_id(&mut self, id: NodeId, now: Time) {
        self.id = id;
        self.ips.clear();
        let old = std::mem::take(&mut self.buckets);
        for n in old.iter().flat_map(|b| &b.live_nodes) {
            let _ = self.add_node(*n, now);
        }
        for n in old.iter().flat_map(|b| &b.replacements) {
            let _ = self.add_node(*n, now);
        }
    }

    // ---------------------------------------------------------------
    // diagnostics
    // ---------------------------------------------------------------

    /// Verifies the structural invariants of the table (libtorrent's
    /// `check_invariant`, extended): every live node was pinged, the IP set
    /// matches the stored nodes, every node is in the bucket its ID belongs
    /// to, no node has our ID or the wrong family, and the last bucket is not
    /// empty.
    ///
    /// Meant for tests and fuzzing; `O(n)`.
    ///
    /// # Errors
    ///
    /// The first [`InvariantError`] found.
    pub fn check_invariants(&self) -> Result<(), InvariantError> {
        let mut all_ips = IpSet::default();
        for (bucket, b) in self.buckets.iter().enumerate() {
            if let Some(n) = b.live_nodes.iter().find(|n| !n.pinged()) {
                return Err(InvariantError::LiveNodeNotPinged { bucket, id: n.id });
            }
            for n in b.live_nodes.iter().chain(&b.replacements) {
                if n.id == self.id {
                    return Err(InvariantError::ContainsOwnId);
                }
                if !self.native_endpoint(&n.endpoint) {
                    return Err(InvariantError::ForeignFamily { bucket, id: n.id });
                }
                let expected = self.bucket_index_for(&n.id);
                if expected != bucket {
                    return Err(InvariantError::WrongBucket {
                        bucket,
                        expected,
                        id: n.id,
                    });
                }
                all_ips.insert(n.addr());
            }
        }
        if all_ips != self.ips {
            return Err(InvariantError::IpSetMismatch);
        }
        match self.buckets.last() {
            Some(b) if b.live_nodes.is_empty() && b.replacements.is_empty() => {
                Err(InvariantError::EmptyLastBucket)
            }
            _ => Ok(()),
        }
    }

    /// Writes a human-readable dump of the table: per-bucket populations,
    /// every node with its prefix slot, RTT, failures and distance, and the
    /// prefix-slot spread per bucket (the `print_state` helper of
    /// libtorrent's `test_dht.cpp`). `now` is used for the "last queried"
    /// column.
    ///
    /// # Errors
    ///
    /// Only those of `out`.
    pub fn write_state(&self, out: &mut dyn fmt::Write, now: Time) -> fmt::Result {
        writeln!(out, "kademlia routing table state")?;
        writeln!(out, "bucket_size: {}", self.bucket_size)?;
        writeln!(out, "global node count: {}", self.num_global_nodes())?;
        writeln!(out, "node_id: {}\n", self.id)?;
        writeln!(out, "number of nodes per bucket:")?;
        for (idx, b) in self.buckets.iter().enumerate() {
            let live = "#".repeat(b.live_nodes.len());
            let repl = "-".repeat(b.replacements.len());
            writeln!(out, "{idx:>2}: {live}{repl}")?;
        }
        write!(out, "\nnodes:")?;
        for (idx, b) in self.buckets.iter().enumerate() {
            self.write_bucket_nodes(out, idx, b, now)?;
        }
        writeln!(out, "\nnode spread per bucket:")?;
        for (idx, b) in self.buckets.iter().enumerate() {
            self.write_spread(out, idx, b)?;
        }
        Ok(())
    }

    fn write_bucket_nodes(
        &self,
        out: &mut dyn fmt::Write,
        idx: usize,
        b: &Bucket,
        now: Time,
    ) -> fmt::Result {
        write!(
            out,
            "\n=== BUCKET == {idx} == {}|{} ==== \n",
            b.live_nodes.len(),
            b.replacements.len()
        )?;
        let limit = self.bucket_limit(idx);
        let last = idx + 1 == self.buckets.len();
        let mut nodes = b.live_nodes.clone();
        nodes.sort_by_key(|n| n.id);
        for n in &nodes {
            let prefix = classify_prefix(idx, last, limit, &n.id);
            write!(out, " prefix: {prefix:>2x} id: {}", n.id)?;
            if n.rtt == 0xffff {
                write!(out, " rtt:     ")?;
            } else {
                write!(out, " rtt: {:>4}", n.rtt)?;
            }
            write!(
                out,
                " fail: {:>3} ping: {} dist: {}",
                n.fail_count(),
                u8::from(n.pinged()),
                distance_exp(&self.id, &n.id)
            )?;
            if n.last_queried == Time::ZERO {
                write!(out, " query:    ")?;
            } else {
                write!(out, " query: {:>3}", (now - n.last_queried).as_secs())?;
            }
            write!(out, " ip: {}", n.endpoint)?;
        }
        Ok(())
    }

    fn write_spread(&self, out: &mut dyn fmt::Write, idx: usize, b: &Bucket) -> fmt::Result {
        let limit = self.bucket_limit(idx);
        let last = idx + 1 == self.buckets.len();
        let mut occupied = [false; 256];
        for n in &b.live_nodes {
            occupied[usize::from(classify_prefix(idx, last, limit, &n.id))] = true;
        }
        let row: String = occupied
            .iter()
            .take(limit)
            .map(|&o| if o { 'X' } else { ' ' })
            .collect();
        writeln!(out, "{idx:>2}: [{row}]")
    }

    /// [`RoutingTable::write_state`] into a `String`.
    #[must_use]
    pub fn print_state(&self, now: Time) -> String {
        let mut s = String::new();
        self.write_state(&mut s, now)
            .expect("writing to a String cannot fail");
        s
    }
}

/// After appending a bucket to `found`: returns `true` when `found` holds
/// `count` nodes or more, trimming it to the `count` closest to `target`.
///
/// Nodes before `unsorted_start` come from buckets closer to the target than
/// any later bucket, so only the tail is partitioned (libtorrent's
/// `std::nth_element` over `[unsorted_start, end)`).
fn select_closest(
    found: &mut Vec<NodeEntry>,
    count: usize,
    unsorted_start: usize,
    target: &NodeId,
) -> bool {
    match found.len().cmp(&count) {
        Ordering::Less => false,
        Ordering::Equal => true,
        Ordering::Greater => {
            let by_distance =
                |a: &NodeEntry, b: &NodeEntry| (a.id ^ *target).cmp(&(b.id ^ *target));
            found[unsorted_start..].select_nth_unstable_by(count - unsorted_start, by_distance);
            found.truncate(count);
            true
        }
    }
}
