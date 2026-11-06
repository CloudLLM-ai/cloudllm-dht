//! DHT configuration with libtorrent's defaults, and its persistence.
//!
//! Provenance: `include/libtorrent/kademlia/dht_settings.hpp` and
//! `src/kademlia/dht_settings.cpp` of libtorrent RC_2_1 (commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg and Alden Torres.

use crate::bencode::{Entry, Node, NodeKind};

/// Every DHT tunable (libtorrent `dht::settings`, which extends the
/// deprecated `dht_settings` with `prefer_verified_node_ids`).
///
/// [`DhtSettings::default`] gives libtorrent's defaults. Integer fields are
/// `i32` like the C++ `int`s so a state file written by either
/// implementation reads back the same.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::settings::DhtSettings;
///
/// let s = DhtSettings::default();
/// assert_eq!(s.search_branching, 5);
/// assert!(s.extended_routing_table);
/// assert!(!s.read_only);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtSettings {
    /// Max peers in a `get_peers` response. Default 100.
    pub max_peers_reply: i32,
    /// Concurrent requests per lookup ("alpha" in the Kademlia paper).
    /// Default 5.
    pub search_branching: i32,
    /// Failed contacts before a node is dropped from the routing table even
    /// with no replacement ready. Default 20.
    pub max_fail_count: i32,
    /// Max torrents (info-hashes) tracked; a memory bound against hostile
    /// nodes. Default 2000.
    pub max_torrents: i32,
    /// Max BEP 44 items stored. Default 700.
    pub max_dht_items: i32,
    /// Max peers stored per torrent. Default 500.
    pub max_peers: i32,
    /// Max torrents in a search reply. Default 20.
    pub max_torrent_search_reply: i32,
    /// Restrict routing-table entries to one per IP, and one per /24 (/64
    /// for IPv6) per bucket, against node-ID spoofing. Default `true`.
    pub restrict_routing_ips: bool,
    /// Keep lookups from adding nodes with very close CIDR distance.
    /// Default `true`.
    pub restrict_search_ips: bool,
    /// Make the first buckets hold 128, 64, 32 and 16 nodes instead of 8.
    /// Default `true`.
    pub extended_routing_table: bool,
    /// Keep `search_branching` requests outstanding to the closest nodes at
    /// all times rather than treating it as a hard cap. Default `true`.
    pub aggressive_lookups: bool,
    /// Perform lookups that leak less about the searcher at a higher cost.
    /// Default `false`.
    pub privacy_lookups: bool,
    /// Ignore nodes whose ID does not match their IP (BEP 42), answering
    /// them with an "invalid node ID" error. Default `false`.
    pub enforce_node_id: bool,
    /// Ignore packets from address ranges that should carry no DHT traffic.
    /// Default `true`.
    pub ignore_dark_internet: bool,
    /// Seconds a node is blocked after exceeding the rate limit.
    /// Default 300.
    pub block_timeout: i32,
    /// Packets per second (averaged over 10 s) before a node is blocked.
    /// Default 5.
    pub block_ratelimit: i32,
    /// BEP 43: do not answer queries and mark outgoing queries `ro`.
    /// Default `false`.
    pub read_only: bool,
    /// Seconds before stored items expire; `0` means never. Default 0.
    pub item_lifetime: i32,
    /// Average bytes per second the node may send in responses. Default
    /// 8000.
    pub upload_rate_limit: i32,
    /// BEP 51: seconds between recomputing the info-hash sample, 0 to
    /// 21600. Default 21600.
    pub sample_infohashes_interval: i32,
    /// BEP 51: max info-hashes in a sample. Default 20.
    pub max_infohashes_sample_count: i32,
    /// Prefer BEP 42-valid node IDs in the routing table. Default `true`.
    pub prefer_verified_node_ids: bool,
}

impl Default for DhtSettings {
    fn default() -> Self {
        Self {
            max_peers_reply: 100,
            search_branching: 5,
            max_fail_count: 20,
            max_torrents: 2000,
            max_dht_items: 700,
            max_peers: 500,
            max_torrent_search_reply: 20,
            restrict_routing_ips: true,
            restrict_search_ips: true,
            extended_routing_table: true,
            aggressive_lookups: true,
            privacy_lookups: false,
            enforce_node_id: false,
            ignore_dark_internet: true,
            block_timeout: 5 * 60,
            block_ratelimit: 5,
            read_only: false,
            item_lifetime: 0,
            upload_rate_limit: 8000,
            sample_infohashes_interval: 21600,
            max_infohashes_sample_count: 20,
            prefer_verified_node_ids: true,
        }
    }
}

/// Reads settings from a bencoded dictionary (libtorrent
/// `read_dht_settings`). Missing keys keep their defaults; a non-dictionary
/// yields the defaults. Integers outside `i32` are ignored.
///
/// Only the keys libtorrent persists are read: `upload_rate_limit`, the two
/// BEP 51 fields and `prefer_verified_node_ids` are runtime-only there.
#[must_use]
pub fn read_dht_settings(e: &Node<'_>) -> DhtSettings {
    let mut s = DhtSettings::default();
    if e.kind() != NodeKind::Dict {
        return s;
    }
    let int = |key: &str| e.dict_find_int(key.as_bytes()).map(Node::int_value);
    let num = |key: &str, slot: &mut i32| {
        if let Some(v) = int(key).and_then(|v| i32::try_from(v).ok()) {
            *slot = v;
        }
    };
    let flag = |key: &str, slot: &mut bool| {
        if let Some(v) = int(key) {
            *slot = v != 0;
        }
    };
    num("max_peers_reply", &mut s.max_peers_reply);
    num("search_branching", &mut s.search_branching);
    num("max_fail_count", &mut s.max_fail_count);
    num("max_torrents", &mut s.max_torrents);
    num("max_dht_items", &mut s.max_dht_items);
    num("max_peers", &mut s.max_peers);
    num("max_torrent_search_reply", &mut s.max_torrent_search_reply);
    flag("restrict_routing_ips", &mut s.restrict_routing_ips);
    flag("restrict_search_ips", &mut s.restrict_search_ips);
    flag("extended_routing_table", &mut s.extended_routing_table);
    flag("aggressive_lookups", &mut s.aggressive_lookups);
    flag("privacy_lookups", &mut s.privacy_lookups);
    flag("enforce_node_id", &mut s.enforce_node_id);
    flag("ignore_dark_internet", &mut s.ignore_dark_internet);
    num("block_timeout", &mut s.block_timeout);
    num("block_ratelimit", &mut s.block_ratelimit);
    flag("read_only", &mut s.read_only);
    num("item_lifetime", &mut s.item_lifetime);
    s
}

/// Serialises the persisted subset of the settings (libtorrent
/// `save_dht_settings`).
#[must_use]
pub fn save_dht_settings(s: &DhtSettings) -> Entry {
    let mut e = Entry::dict();
    e.set("max_peers_reply", s.max_peers_reply)
        .set("search_branching", s.search_branching)
        .set("max_fail_count", s.max_fail_count)
        .set("max_torrents", s.max_torrents)
        .set("max_dht_items", s.max_dht_items)
        .set("max_peers", s.max_peers)
        .set("max_torrent_search_reply", s.max_torrent_search_reply)
        .set("restrict_routing_ips", s.restrict_routing_ips)
        .set("restrict_search_ips", s.restrict_search_ips)
        .set("extended_routing_table", s.extended_routing_table)
        .set("aggressive_lookups", s.aggressive_lookups)
        .set("privacy_lookups", s.privacy_lookups)
        .set("enforce_node_id", s.enforce_node_id)
        .set("ignore_dark_internet", s.ignore_dark_internet)
        .set("block_timeout", s.block_timeout)
        .set("block_ratelimit", s.block_ratelimit)
        .set("read_only", s.read_only)
        .set("item_lifetime", s.item_lifetime);
    e
}
