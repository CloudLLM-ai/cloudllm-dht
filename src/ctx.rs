//! The borrowed context a traversal gets while handling one event.
//!
//! This is the single seam between the traversal family and the node: the
//! node builds a [`NodeCtx`] for each call it makes into the traversals
//! (an incoming datagram, a timer tick, a new lookup) and every traversal
//! callback receives it. There is no libtorrent counterpart; it replaces
//! the `node&` reference every `traversal_algorithm` keeps
//! (`m_node.m_table`, `m_node.m_rpc`, `m_node.settings()`,
//! `m_node.observer()`, `aux::time_now()`, `aux::random()`), as described in
//! `docs/ARCHITECTURE.md` (libtorrent RC_2_1, commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`, BSD-3-Clause).
//!
//! # Why the RPC operations are methods here
//!
//! libtorrent's `rpc_manager::invoke` needs the socket, the settings and the
//! random source in addition to its own transaction table. With the manager
//! borrowed *out of* the context (`ctx.rpc.invoke(ctx, ..)`) Rust would see
//! two mutable borrows of one object, so the operations that need both live
//! on [`NodeCtx`] (`invoke`, `rpc_incoming`, `rpc_tick`, `rpc_unreachable`,
//! in [`crate::rpc_manager`]) and [`RpcManager`] holds only the state.

use std::net::{IpAddr, SocketAddr};

use crate::events::Event;
use crate::net::Protocol;
use crate::node_id::{IdSecret, NodeId};
use crate::rng::Rng;
use crate::rpc_manager::RpcManager;
use crate::settings::DhtSettings;
use crate::time::Time;
use crate::transport::Transport;
use crate::traversal::Traversal;

/// What the traversal family needs from the routing table.
///
/// libtorrent traversals reach `m_node.m_table` directly. A trait keeps the
/// traversals independent of the table's representation (and testable
/// against a small fake); `RoutingTable` implements it. Every method is the
/// port of the `routing_table` member of the same name.
pub trait TableOps {
    /// The bucket size `k` (libtorrent `bucket_size()`), 8 by default. Also
    /// the number of results a lookup aims for.
    fn bucket_size(&self) -> usize;

    /// A node was mentioned by another node: it may exist, so the table may
    /// want to ping it (libtorrent `heard_about`).
    fn heard_about(&mut self, id: NodeId, ep: SocketAddr, now: Time);

    /// A request to this node failed (libtorrent `node_failed`).
    fn node_failed(&mut self, id: NodeId, ep: SocketAddr);

    /// The node answered one of our requests, so it is not spoofing
    /// (libtorrent `node_seen`). `rtt` is the round-trip time in
    /// milliseconds. Returns `true` if the table wants a refresh.
    fn node_seen(&mut self, id: NodeId, ep: SocketAddr, rtt: u16, now: Time) -> bool;

    /// The `k` nodes closest to `target`, failed nodes included (libtorrent
    /// `find_node(target, routing_table::include_failed)`), nearest first.
    fn closest_including_failed(&self, target: &NodeId) -> Vec<(NodeId, SocketAddr)>;

    /// The configured router (bootstrap) endpoints (libtorrent iterates
    /// `m_table.begin()..end()` in `add_router_entries`).
    fn router_nodes(&self) -> Vec<SocketAddr>;
}

/// Decides whether an address is blocked by the embedder's IP filter
/// (libtorrent `ip_filter::access(addr) == blocked`).
pub type IpFilter<'a> = &'a dyn Fn(IpAddr) -> bool;

/// Everything a traversal may touch while handling one event.
///
/// Built by the node for each call; nothing in it outlives the call. See
/// the module documentation for why the RPC operations are methods of this
/// type.
pub struct NodeCtx<'a> {
    /// The current time (`aux::time_now()`).
    pub now: Time,
    /// This node's current ID (`node::nid()`).
    pub id: NodeId,
    /// The address family this node serves.
    pub protocol: Protocol,
    /// Behavioural settings.
    pub settings: &'a DhtSettings,
    /// The routing table.
    pub table: &'a mut dyn TableOps,
    /// The transaction table and observer arena.
    pub rpc: &'a mut RpcManager,
    /// Where requests are sent.
    pub transport: &'a mut dyn Transport,
    /// The random source (`aux::random()`).
    pub rng: &'a mut dyn Rng,
    /// Results flow out through this queue.
    pub events: &'a mut Vec<Event>,
    /// The per-node secret behind `make_id_secret` / `generate_secret_id`.
    pub id_secret: IdSecret,
    ip_filter: Option<IpFilter<'a>>,
    followups: Vec<Box<dyn Traversal>>,
    pings: Vec<SocketAddr>,
}

impl<'a> NodeCtx<'a> {
    /// Builds a context. The optional IP filter is added with
    /// [`NodeCtx::with_ip_filter`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        now: Time,
        id: NodeId,
        protocol: Protocol,
        settings: &'a DhtSettings,
        table: &'a mut dyn TableOps,
        rpc: &'a mut RpcManager,
        transport: &'a mut dyn Transport,
        rng: &'a mut dyn Rng,
        events: &'a mut Vec<Event>,
        id_secret: IdSecret,
    ) -> Self {
        Self {
            now,
            id,
            protocol,
            settings,
            table,
            rpc,
            transport,
            rng,
            events,
            id_secret,
            ip_filter: None,
            followups: Vec::new(),
            pings: Vec::new(),
        }
    }

    /// Installs the embedder's IP filter. Without one nothing is filtered
    /// (libtorrent: no `dht_observer`, or `apply_filter_to_dht` off).
    #[must_use]
    pub fn with_ip_filter(mut self, blocked: IpFilter<'a>) -> Self {
        self.ip_filter = Some(blocked);
        self
    }

    /// `true` if `addr` is blocked by the IP filter (libtorrent
    /// `traversal_algorithm::filtered`).
    #[must_use]
    pub fn filtered(&self, addr: SocketAddr) -> bool {
        self.ip_filter.is_some_and(|blocked| blocked(addr.ip()))
    }

    /// `true` if `addr` belongs to this node's address family (libtorrent
    /// `node::native_address`).
    #[must_use]
    pub fn native_address(&self, addr: IpAddr) -> bool {
        Protocol::of(&addr) == self.protocol
    }

    /// Issues a fresh traversal id.
    pub fn new_traversal_id(&mut self) -> crate::observer::TraversalId {
        self.rpc.next_traversal_id()
    }

    /// Queues a traversal to be started by the owner of the traversal arena
    /// after the current callback returns (an obfuscated lookup spawning its
    /// plain follow-up, a `get` spawning the `put`).
    pub fn spawn(&mut self, t: Box<dyn Traversal>) {
        self.followups.push(t);
    }

    pub(crate) fn take_followups(&mut self) -> Vec<Box<dyn Traversal>> {
        std::mem::take(&mut self.followups)
    }

    /// Asks the node to ping `ep` and add it to the routing table if it
    /// answers (libtorrent `node::add_node`, called from
    /// `bootstrap::done`). The node drains these with
    /// [`NodeCtx::take_pings`] after calling into the traversals.
    pub fn request_ping(&mut self, ep: SocketAddr) {
        self.pings.push(ep);
    }

    /// Endpoints queued by [`NodeCtx::request_ping`] since the last call.
    pub fn take_pings(&mut self) -> Vec<SocketAddr> {
        std::mem::take(&mut self.pings)
    }
}
