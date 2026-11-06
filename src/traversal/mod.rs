//! The traversal family: iterative lookups over the routing table, and the
//! arena that runs them.
//!
//! Ports the `traversal_algorithm` class hierarchy of libtorrent RC_2_1
//! (`src/kademlia/traversal_algorithm.cpp`, `find_data.cpp`, `get_peers.cpp`,
//! `get_item.cpp`, `put_data.cpp`, `sample_infohashes.cpp`, `refresh.cpp`
//! and `include/libtorrent/kademlia/direct_request.hpp`; commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`, BSD-3-Clause, Copyright Arvid
//! Norberg, Steven Siloti, Alden Torres).
//!
//! # Running traversals
//!
//! A [`Traversal`] is one lookup. The node keeps its live traversals in a
//! [`Traversals`] arena and routes every event to it: a response goes to
//! [`Traversals::incoming`], a timer tick to [`Traversals::tick`], an ICMP
//! unreachable to [`Traversals::unreachable`], and a new lookup is started
//! with [`Traversals::spawn`]. Each call takes the [`NodeCtx`] the node
//! builds for it and leaves its results in `ctx.events`.
//!
//! libtorrent keeps a traversal alive with `shared_ptr` while any of its
//! requests is outstanding (even after the lookup finished, a late reply is
//! still delivered). The arena reproduces that: a finished traversal is
//! dropped when its last observer is freed.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use crate::bencode::Node;
use crate::ctx::NodeCtx;
use crate::node_id::NodeId;
use crate::observer::{ObserverFlags, ObserverId, ObserverKind, TraversalId};
use crate::rpc_manager::Incoming;

pub mod algorithm;
pub mod direct_request;
pub mod find_data;
pub mod get_item;
pub mod get_peers;
pub mod put_data;
pub mod refresh;
pub mod sample_infohashes;

pub use algorithm::Algorithm;

/// One lookup or request: the virtual interface of `traversal_algorithm`
/// and of the observers it creates.
///
/// Implementors embed an [`Algorithm`] and expose it through
/// [`Traversal::algo`]. The provided methods are the base-class behaviour;
/// override the ones the C++ subclass overrides.
///
/// The *observer* half (libtorrent's `observer::reply`, `timeout`,
/// `short_timeout`) is part of this trait because an observer's behaviour
/// is determined by the lookup that made it.
pub trait Traversal: Send {
    /// A short name for diagnostics (`name()`).
    fn name(&self) -> &'static str;

    /// The shared lookup state.
    fn algo(&self) -> &Algorithm;

    /// The shared lookup state, mutably.
    fn algo_mut(&mut self) -> &mut Algorithm;

    /// What kind of observer this lookup creates for a new candidate
    /// (libtorrent `new_observer`).
    fn new_observer(&self) -> ObserverKind {
        ObserverKind::Null
    }

    /// Begins the lookup (libtorrent `start`).
    fn start(&mut self, ctx: &mut NodeCtx<'_>) {
        algorithm::base_start(self, ctx);
    }

    /// Sends the request for one candidate; `true` if it went out
    /// (libtorrent `invoke`). The default sends nothing.
    fn invoke(&mut self, _ctx: &mut NodeCtx<'_>, _obs: ObserverId) -> bool {
        false
    }

    /// The lookup is finished (libtorrent `done`). Overrides do their
    /// completion work, then call [`algorithm::base_done`].
    fn done(&mut self, ctx: &mut NodeCtx<'_>) {
        algorithm::base_done(self, ctx);
    }

    /// `true` once [`Traversal::done`] ran.
    fn is_done(&self) -> bool {
        self.algo().is_done()
    }

    /// The node behind `obs` sent a valid response envelope (libtorrent
    /// `observer::reply`). `msg` is the whole message; `from` its source.
    /// The default is `null_observer`: just mark the request done.
    fn on_reply(
        &mut self,
        ctx: &mut NodeCtx<'_>,
        obs: ObserverId,
        from: SocketAddr,
        msg: &Node<'_>,
    ) {
        let _ = (from, msg);
        if let Some(o) = ctx.rpc.observers.get_mut(obs) {
            o.flags |= ObserverFlags::DONE;
        }
    }

    /// The request failed: timed out, was answered with an error, or the
    /// response was malformed (libtorrent `observer::timeout`).
    fn on_timeout(&mut self, ctx: &mut NodeCtx<'_>, obs: ObserverId) {
        algorithm::observer_timeout(self, ctx, obs);
    }

    /// The request has been outstanding for the short timeout
    /// (libtorrent `observer::short_timeout`).
    fn on_short_timeout(&mut self, ctx: &mut NodeCtx<'_>, obs: ObserverId) {
        algorithm::observer_short_timeout(self, ctx, obs);
    }
}

/// A snapshot of one running lookup (libtorrent `traversal_algorithm::status`
/// filling a `dht_lookup`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupStatus {
    /// Which lookup.
    pub id: TraversalId,
    /// Its `name()`.
    pub kind: &'static str,
    /// The target.
    pub target: NodeId,
    /// Requests that timed out.
    pub timeouts: i32,
    /// Responses received.
    pub responses: i32,
    /// Requests in flight.
    pub outstanding_requests: i32,
    /// Current branch factor.
    pub branch_factor: i32,
    /// Candidates not asked yet.
    pub nodes_left: usize,
    /// In-flight requests that already passed the short timeout.
    pub first_timeout: usize,
    /// Seconds since the most recent request was sent, `None` if none.
    pub last_sent: Option<u64>,
}

/// The arena of running traversals (the node's `m_running_requests`).
///
/// See the [module documentation](self) for how the node drives it.
#[derive(Default)]
pub struct Traversals {
    live: BTreeMap<TraversalId, Box<dyn Traversal>>,
}

impl std::fmt::Debug for Traversals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Traversals")
            .field("live", &self.live.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Traversals {
    /// An empty arena.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of traversals still alive (running, or finished but with
    /// requests in flight).
    #[must_use]
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// `true` if no traversal is alive.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    /// Looks a traversal up by id.
    #[must_use]
    pub fn get(&self, id: TraversalId) -> Option<&dyn Traversal> {
        self.live.get(&id).map(|t| &**t)
    }

    /// Starts a traversal and keeps it until it is finished and its last
    /// request is gone. Traversals the start-up spawns in turn (a `get`
    /// handing its nodes to a `put`) are started too.
    pub fn spawn(&mut self, ctx: &mut NodeCtx<'_>, t: Box<dyn Traversal>) -> TraversalId {
        let id = t.algo().id();
        let mut touched = vec![id];
        self.start_one(ctx, t);
        self.start_followups(ctx, &mut touched);
        self.reap(ctx, &touched);
        id
    }

    fn start_one(&mut self, ctx: &mut NodeCtx<'_>, mut t: Box<dyn Traversal>) {
        let id = t.algo().id();
        t.start(ctx);
        self.live.insert(id, t);
    }

    /// Runs `f` on the traversal `id` with the traversal taken out of the
    /// arena, so `f` can have the context and the traversal at once.
    fn with<R>(&mut self, id: TraversalId, f: impl FnOnce(&mut dyn Traversal) -> R) -> Option<R> {
        let mut t = self.live.remove(&id)?;
        let r = f(&mut *t);
        self.live.insert(id, t);
        Some(r)
    }

    /// Starts the traversals other traversals queued, recursively.
    fn start_followups(&mut self, ctx: &mut NodeCtx<'_>, touched: &mut Vec<TraversalId>) {
        loop {
            let queued = ctx.take_followups();
            if queued.is_empty() {
                return;
            }
            for t in queued {
                touched.push(t.algo().id());
                self.start_one(ctx, t);
            }
        }
    }

    /// Drops the traversals among `touched` and those that just lost their
    /// last observer: with no observer left (an observer is held by the
    /// result list until the lookup is done, and by its request until the
    /// answer or the timeout) nothing can reach them any more. This is the
    /// moment libtorrent's `shared_ptr<traversal_algorithm>` count hits zero.
    fn reap(&mut self, ctx: &mut NodeCtx<'_>, touched: &[TraversalId]) {
        let idle = ctx.rpc.observers.take_idle();
        for id in idle.iter().chain(touched) {
            if ctx.rpc.observers.live_for(*id) == 0 {
                self.live.remove(id);
            }
        }
    }

    /// The common tail of every event: start what was queued, drop what is
    /// finished.
    fn settle(&mut self, ctx: &mut NodeCtx<'_>, mut touched: Vec<TraversalId>) {
        self.start_followups(ctx, &mut touched);
        self.reap(ctx, &touched);
    }

    /// Handles a datagram with `y` of `r` or `e`: matches it to its
    /// request, lets the request's lookup process it, then reports the
    /// sender to the routing table (libtorrent `rpc_manager::incoming`).
    ///
    /// Returns `Some(id)` when the table asked for a refresh of the node
    /// `id` (`node_seen` returned `true`).
    pub fn incoming(
        &mut self,
        ctx: &mut NodeCtx<'_>,
        from: SocketAddr,
        msg: &Node<'_>,
    ) -> Option<NodeId> {
        let mut touched = Vec::new();
        let refresh = match ctx.rpc_incoming(from, msg) {
            Incoming::Ignored => None,
            Incoming::Failed(obs) => {
                touched.extend(self.dispatch_timeout(ctx, obs));
                ctx.rpc.observers.release(obs);
                None
            }
            Incoming::Reply { observer, id, rtt } => {
                touched.extend(self.dispatch_reply(ctx, observer, from, msg));
                ctx.rpc.observers.release(observer);
                let now = ctx.now;
                ctx.table.node_seen(id, from, rtt, now).then_some(id)
            }
        };
        self.settle(ctx, touched);
        refresh
    }

    /// Times out requests (libtorrent `rpc_manager::tick`); returns when to
    /// call again.
    pub fn tick(&mut self, ctx: &mut NodeCtx<'_>) -> Duration {
        let out = ctx.rpc_tick();
        let mut touched = Vec::new();
        for obs in out.timeouts {
            touched.extend(self.dispatch_timeout(ctx, obs));
            ctx.rpc.observers.release(obs);
        }
        for obs in out.short_timeouts {
            touched.extend(self.dispatch_short_timeout(ctx, obs));
        }
        self.settle(ctx, touched);
        out.next
    }

    /// An ICMP port-unreachable arrived from `ep`.
    pub fn unreachable(&mut self, ctx: &mut NodeCtx<'_>, ep: SocketAddr) {
        let mut touched = Vec::new();
        if let Some(obs) = ctx.rpc_unreachable(ep) {
            touched.extend(self.dispatch_timeout(ctx, obs));
            ctx.rpc.observers.release(obs);
        }
        self.settle(ctx, touched);
    }

    /// A snapshot of every lookup that was started and still exists, ordered
    /// by id (the `requests` of libtorrent's `dht_status`; like there, a
    /// finished lookup stays listed while requests that refer to it are
    /// still in flight).
    #[must_use]
    pub fn status(&self, ctx: &NodeCtx<'_>) -> Vec<LookupStatus> {
        self.live
            .values()
            .filter(|t| t.algo().is_initialized())
            .map(|t| status_of(&**t, ctx))
            .collect()
    }

    fn dispatch_reply(
        &mut self,
        ctx: &mut NodeCtx<'_>,
        obs: ObserverId,
        from: SocketAddr,
        msg: &Node<'_>,
    ) -> Option<TraversalId> {
        let tid = ctx.rpc.observers.get(obs)?.traversal;
        match tid {
            Some(tid) => {
                self.with(tid, |t| t.on_reply(ctx, obs, from, msg));
            }
            None => detached::reply(ctx, obs, msg),
        }
        tid
    }

    fn dispatch_timeout(&mut self, ctx: &mut NodeCtx<'_>, obs: ObserverId) -> Option<TraversalId> {
        let tid = ctx.rpc.observers.get(obs)?.traversal;
        match tid {
            Some(tid) => {
                self.with(tid, |t| t.on_timeout(ctx, obs));
            }
            None => detached::timeout(ctx, obs),
        }
        tid
    }

    fn dispatch_short_timeout(
        &mut self,
        ctx: &mut NodeCtx<'_>,
        obs: ObserverId,
    ) -> Option<TraversalId> {
        let tid = ctx.rpc.observers.get(obs)?.traversal;
        match tid {
            Some(tid) => {
                self.with(tid, |t| t.on_short_timeout(ctx, obs));
            }
            None => detached::short_timeout(ctx, obs),
        }
        tid
    }
}

fn status_of(t: &dyn Traversal, ctx: &NodeCtx<'_>) -> LookupStatus {
    let a = t.algo();
    let mut s = LookupStatus {
        id: a.id(),
        kind: t.name(),
        target: *a.target(),
        timeouts: a.num_timeouts(),
        responses: a.num_responses(),
        outstanding_requests: a.invoke_count(),
        branch_factor: a.branch_factor(),
        nodes_left: 0,
        first_timeout: 0,
        last_sent: None,
    };
    for oid in a.results() {
        let Some(o) = ctx.rpc.observers.get(*oid) else {
            continue;
        };
        if o.flags.contains(ObserverFlags::QUERIED) {
            let age = (ctx.now - o.sent).as_secs();
            s.last_sent = Some(s.last_sent.map_or(age, |l| l.min(age)));
            if o.has_short_timeout() {
                s.first_timeout += 1;
            }
        } else {
            s.nodes_left += 1;
        }
    }
    s
}

/// Observers without a traversal: the ping and the `announce_peer`.
///
/// libtorrent gives these a dummy `traversal_algorithm` with no results, so
/// `observer::timeout` degenerates to telling the routing table.
mod detached {
    use crate::bencode::Node;
    use crate::ctx::NodeCtx;
    use crate::observer::{ObserverFlags, ObserverId, ObserverKind};

    use super::algorithm::look_for_nodes;

    /// `ping_observer::reply` and `announce_observer::reply`.
    pub(super) fn reply(ctx: &mut NodeCtx<'_>, obs: ObserverId, msg: &Node<'_>) {
        let Some(o) = ctx.rpc.observers.get_mut(obs) else {
            return;
        };
        o.flags |= ObserverFlags::DONE;
        if o.kind != ObserverKind::Ping {
            return;
        }
        let Some(r) = msg.dict_find_dict(b"r") else {
            return;
        };
        let now = ctx.now;
        for n in look_for_nodes(ctx.protocol, r) {
            ctx.table.heard_about(n.id, n.ep, now);
        }
    }

    /// `observer::timeout` with an empty dummy algorithm: mark done, tell
    /// the table.
    pub(super) fn timeout(ctx: &mut NodeCtx<'_>, obs: ObserverId) {
        let Some(o) = ctx.rpc.observers.get_mut(obs) else {
            return;
        };
        if o.flags.contains(ObserverFlags::DONE) {
            return;
        }
        o.flags |= ObserverFlags::DONE;
        node_failed(ctx, obs);
    }

    /// `observer::short_timeout` with an empty dummy algorithm: tell the
    /// table once and remember it. (libtorrent forgets to set the flag, so
    /// it reports every tick; fixed here, see PORTING.md.)
    pub(super) fn short_timeout(ctx: &mut NodeCtx<'_>, obs: ObserverId) {
        match ctx.rpc.observers.get_mut(obs) {
            Some(o) if !o.has_short_timeout() => o.flags |= ObserverFlags::SHORT_TIMEOUT,
            _ => return,
        }
        node_failed(ctx, obs);
    }

    fn node_failed(ctx: &mut NodeCtx<'_>, obs: ObserverId) {
        let Some(o) = ctx.rpc.observers.get(obs) else {
            return;
        };
        if !o.flags.contains(ObserverFlags::NO_ID) {
            let (id, ep) = (o.id, o.target);
            ctx.table.node_failed(id, ep);
        }
    }
}
