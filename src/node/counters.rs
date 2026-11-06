//! Per-node message counters.
//!
//! Provenance: the `counters::dht_*` statistics libtorrent's `node` and
//! `dht_tracker` increment (`include/libtorrent/performance_counters.hpp`
//! names, RC_2_1 commit `86d573f2631b0162d3cca5e257217eaf530fdcba`),
//! BSD-3-Clause, Copyright Arvid Norberg and contributors.
//!
//! libtorrent shares one global `counters` object between the session and
//! the DHT. Here every [`crate::node::Node`] owns a plain value and the
//! tracker sums them, so nothing is shared and no atomics are needed.

/// Counts of the messages one node handled, in libtorrent's names.
///
/// All counters only ever increase. `*_in` counts valid queries answered,
/// `invalid_*` counts queries rejected with a DHT error, `*_out` counts
/// requests the node itself sent.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::node::counters::NodeCounters;
///
/// let mut a = NodeCounters::default();
/// a.ping_in += 1;
/// let mut b = NodeCounters::default();
/// b.ping_in += 2;
/// a.add(&b);
/// assert_eq!(a.ping_in, 3);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeCounters {
    /// `counters::dht_ping_in`.
    pub ping_in: u64,
    /// `counters::dht_find_node_in`.
    pub find_node_in: u64,
    /// `counters::dht_get_peers_in`.
    pub get_peers_in: u64,
    /// `counters::dht_announce_peer_in`.
    pub announce_peer_in: u64,
    /// `counters::dht_put_in`.
    pub put_in: u64,
    /// `counters::dht_get_in`.
    pub get_in: u64,
    /// `counters::dht_sample_infohashes_in`.
    pub sample_infohashes_in: u64,
    /// `counters::dht_invalid_get_peers`.
    pub invalid_get_peers: u64,
    /// `counters::dht_invalid_find_node`.
    pub invalid_find_node: u64,
    /// `counters::dht_invalid_announce`.
    pub invalid_announce: u64,
    /// `counters::dht_invalid_put`.
    pub invalid_put: u64,
    /// `counters::dht_invalid_get`.
    pub invalid_get: u64,
    /// `counters::dht_invalid_sample_infohashes`.
    pub invalid_sample_infohashes: u64,
    /// `counters::dht_messages_in_dropped`: queries dropped because the
    /// send quota was exhausted (the tracker adds its own drops).
    pub messages_in_dropped: u64,
    /// `counters::dht_ping_out`.
    pub ping_out: u64,
    /// `counters::dht_get_peers_out`.
    pub get_peers_out: u64,
    /// `counters::dht_announce_peer_out`.
    pub announce_peer_out: u64,
    /// `counters::dht_sample_infohashes_out`.
    pub sample_infohashes_out: u64,
}

impl NodeCounters {
    /// Adds every counter of `other` to `self` (saturating): how the
    /// tracker totals its nodes.
    pub fn add(&mut self, other: &Self) {
        macro_rules! sum { ($($f:ident),*) => { $( self.$f = self.$f.saturating_add(other.$f); )* } }
        sum!(
            ping_in,
            find_node_in,
            get_peers_in,
            announce_peer_in,
            put_in,
            get_in,
            sample_infohashes_in,
            invalid_get_peers,
            invalid_find_node,
            invalid_announce,
            invalid_put,
            invalid_get,
            invalid_sample_infohashes,
            messages_in_dropped,
            ping_out,
            get_peers_out,
            announce_peer_out,
            sample_infohashes_out
        );
    }
}
