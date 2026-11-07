//! The event (alert) stream: how results leave the sans-IO core.
//!
//! Ports the callbacks libtorrent hands to `node::get_peers`,
//! `node::get_item`, `node::put_item`, `node::sample_infohashes`,
//! `node::direct_request` and `node::bootstrap`, and the notifications of
//! `dht_observer` in `include/libtorrent/kademlia/dht_observer.hpp`
//! (libtorrent RC_2_1, commit `86d573f2631b0162d3cca5e257217eaf530fdcba`,
//! BSD-3-Clause, Copyright Arvid Norberg and contributors).
//!
//! libtorrent returns results through `std::function` callbacks captured
//! when a traversal is created. A sans-IO core cannot call back into a
//! caller that is borrowing it, so traversals push an [`Event`] onto the
//! `Vec<Event>` the owner passes in (`NodeCtx::events`) and the owner drains
//! it after each call.
//!
//! **Ownership.** The traversal family (work package 2) defines the
//! variants it produces; the node and tracker (work package 4) extend this
//! enum with their own. The enum is `#[non_exhaustive]` so adding variants is
//! not a breaking change for downstream matchers.

use std::net::SocketAddr;
use std::time::Duration;

use crate::bencode::Entry;
use crate::item::Item;
use crate::node_id::NodeId;

/// Something a lookup or request produced, for the owner of the node to act
/// on or ignore.
///
/// Every variant that answers a request carries the `target` (or `token`)
/// the request was started with, so a caller running several lookups can
/// tell the answers apart.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// A `get_peers` response carried peers (the `data_callback` of
    /// libtorrent's `get_peers` traversal). Fired once per responding node
    /// that returned a `values` list, possibly many times per lookup, and
    /// also for late responses that arrive after the lookup finished.
    GetPeersReply {
        /// The info-hash being looked up.
        target: NodeId,
        /// Peers the node returned (the `values` list, either the mainline
        /// compact form or the uTorrent/libtorrent list form).
        peers: Vec<SocketAddr>,
    },
    /// A bootstrap traversal finished (the `done_callback` passed to
    /// `node::bootstrap`).
    BootstrapDone,
    /// A result of a tracker-level operation, tagged with the operation it
    /// answers. `result` is the aggregated [`Event::GetItemDone`] (a mutable
    /// get may produce several, the last one authoritative) or
    /// [`Event::PutDone`] across all of the tracker's nodes. Unlike the
    /// per-node events inside the traversals this is what a `Dht` owner
    /// sees, so two concurrent operations on the same target never mix.
    Operation {
        /// The operation.
        op: OpId,
        /// Its result.
        result: Box<Event>,
    },
    /// The operation will produce no result because the tracker shut down
    /// or a socket was removed while it was running.
    OperationCancelled {
        /// The operation.
        op: OpId,
    },
    /// A remote node asked us for peers (libtorrent
    /// `dht_observer::get_peers`).
    IncomingGetPeers {
        /// The info-hash asked for.
        info_hash: NodeId,
        /// The requester.
        from: SocketAddr,
    },
    /// A remote node announced itself with a valid write token (libtorrent
    /// `dht_observer::announce`; fired before the token is checked, as in
    /// libtorrent).
    IncomingAnnounce {
        /// The announced info-hash.
        info_hash: NodeId,
        /// The announcer's address.
        from: std::net::IpAddr,
        /// The port it announced (or its source port with `implied_port`).
        port: u16,
    },
    /// A remote node told us our external address (the `ip` key of a
    /// message that arrived on the node's own socket; libtorrent
    /// `dht_observer::set_external_address`). Vote on it, then call
    /// `Dht::set_external_address` once confident.
    ExternalAddress {
        /// The address the remote claims to see us at.
        addr: std::net::IpAddr,
        /// The remote node's address.
        source: std::net::IpAddr,
    },
    /// The `get_peers` query was about to go out to `to` (libtorrent
    /// `dht_observer::outgoing_get_peers`). `sent_target` differs from
    /// `target` for privacy (obfuscated) lookups, where only the leading
    /// bits of the real target are sent.
    OutgoingGetPeers {
        /// The real info-hash.
        target: NodeId,
        /// What actually goes on the wire.
        sent_target: NodeId,
        /// Destination of the query.
        to: SocketAddr,
    },
    /// A BEP 51 `sample_infohashes` answer (libtorrent
    /// `sample_infohashes::data_callback`).
    SampleInfohashes {
        /// The node that answered.
        from: SocketAddr,
        /// That node's ID, from its response.
        nid: NodeId,
        /// How long the node asks us to wait before sampling it again.
        interval: Duration,
        /// How many info-hashes the node has in total.
        num: u32,
        /// A sample of its info-hashes.
        samples: Vec<NodeId>,
        /// Nodes it suggests we sample next (its `nodes`/`nodes6`).
        nodes: Vec<(NodeId, SocketAddr)>,
    },
    /// A BEP 44 lookup produced an item (the data callback of libtorrent's
    /// `get_item`). For an immutable item it fires once, when the item is
    /// found (`authoritative` is `true`). For a mutable item it fires
    /// whenever a higher sequence number turns up (`authoritative` is
    /// `false`: a better one may still arrive) and once more when the lookup
    /// completes (`authoritative` is `true`, and `item` is empty if nobody
    /// had it).
    GetItemDone {
        /// What was looked up: the SHA-1 of the value, or of key and salt.
        target: NodeId,
        /// The best item found so far.
        item: Item,
        /// `true` once the lookup is complete.
        authoritative: bool,
    },
    /// A BEP 44 put finished (the `put_callback` of libtorrent's
    /// `put_data`).
    PutDone {
        /// The target the item is stored under.
        target: NodeId,
        /// The item that was written.
        item: Item,
        /// How many nodes acknowledged the write.
        responses: usize,
    },
    /// The answer to a direct request (libtorrent
    /// `direct_traversal::message_callback`). `reply` is `None` when the
    /// request timed out, where libtorrent passes an empty message.
    DirectResponse {
        /// The correlation token given to `direct_request`.
        token: u64,
        /// The responding node's address.
        from: SocketAddr,
        /// The response dictionary as received, or `None` on timeout.
        reply: Option<Entry>,
    },
}

/// Identifies one operation started on a `Dht` (a BEP 44 get or put). Ids
/// are unique within a tracker and never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpId(pub u64);

impl Event {
    /// The operation this event belongs to, if the tracker tagged it
    /// ([`Event::Operation`] or [`Event::OperationCancelled`]).
    #[must_use]
    pub fn op(&self) -> Option<OpId> {
        match self {
            Self::Operation { op, .. } | Self::OperationCancelled { op } => Some(*op),
            _ => None,
        }
    }
}
