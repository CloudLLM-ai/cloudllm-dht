//! A request to one known node, answered through an event.
//!
//! Ports `include/libtorrent/kademlia/direct_request.hpp` and
//! `node::direct_request` (libtorrent RC_2_1, commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`, BSD-3-Clause, Copyright Arvid
//! Norberg).
//!
//! libtorrent exposes this to plugins (`session::dht_direct_request`): the
//! caller supplies an arbitrary query, it is sent to an endpoint chosen by
//! the caller, and the response arrives as a `dht_direct_response_alert`
//! carrying the caller's user data. Here the user data is a `u64`
//! correlation token and the alert is [`Event::DirectResponse`], whose
//! `reply` is `None` when the request timed out (libtorrent delivers an
//! empty message then).
//!
//! Like [`sample_infohashes`](super::sample_infohashes) this is "not really a
//! traversal": one observer, no result list.

use std::net::SocketAddr;

use crate::bencode::{Entry, Node};
use crate::ctx::NodeCtx;
use crate::events::Event;
use crate::node_id::NodeId;
use crate::observer::{Observer, ObserverFlags, ObserverId, ObserverKind};

use super::algorithm::{base_done, Algorithm};
use super::Traversal;

/// A single request to a chosen node (libtorrent `direct_traversal`).
#[derive(Debug)]
pub struct DirectTraversal {
    algo: Algorithm,
    ep: SocketAddr,
    request: Option<Entry>,
    token: u64,
    /// Cleared once the answer was delivered (libtorrent nulls `m_cb`).
    pending: bool,
}

impl DirectTraversal {
    /// A request `e` (at least `q`, plus whatever `a` the query needs) for
    /// `ep`. The RPC manager adds `y`, `t` and our `id`.
    #[must_use]
    pub fn new(ctx: &mut NodeCtx<'_>, ep: SocketAddr, e: Entry, token: u64) -> Self {
        Self {
            algo: Algorithm::new(ctx.new_traversal_id(), NodeId::MIN),
            ep,
            request: Some(e),
            token,
            pending: true,
        }
    }

    /// `direct_traversal::invoke_cb`: delivers the answer once and finishes.
    fn invoke_cb(&mut self, ctx: &mut NodeCtx<'_>, from: SocketAddr, reply: Option<Entry>) {
        if self.pending {
            self.pending = false;
            ctx.events.push(Event::DirectResponse {
                token: self.token,
                from,
                reply,
            });
            base_done(self, ctx);
        }
    }
}

/// `node::direct_request`: the traversal to hand to
/// [`Traversals::spawn`](super::Traversals::spawn), which sends the request.
#[must_use]
pub fn direct_request(
    ctx: &mut NodeCtx<'_>,
    ep: SocketAddr,
    e: Entry,
    token: u64,
) -> Box<dyn Traversal> {
    Box::new(DirectTraversal::new(ctx, ep, e, token))
}

impl Traversal for DirectTraversal {
    fn name(&self) -> &'static str {
        "direct_traversal"
    }

    fn algo(&self) -> &Algorithm {
        &self.algo
    }

    fn algo_mut(&mut self) -> &mut Algorithm {
        &mut self.algo
    }

    fn start(&mut self, ctx: &mut NodeCtx<'_>) {
        let Some(e) = self.request.take() else {
            return;
        };
        let mut o = Observer::new(
            ObserverKind::Direct,
            Some(self.algo.id()),
            NodeId::MIN,
            self.ep,
            ctx.now,
        );
        o.flags |= ObserverFlags::QUERIED;
        let obs = ctx.rpc.observers.insert(o);
        ctx.invoke(e, self.ep, obs);
        ctx.rpc.observers.release(obs);
    }

    /// `direct_observer::reply`: whatever came back, valid or not, is the
    /// answer.
    fn on_reply(
        &mut self,
        ctx: &mut NodeCtx<'_>,
        obs: ObserverId,
        from: SocketAddr,
        msg: &Node<'_>,
    ) {
        if let Some(o) = ctx.rpc.observers.get_mut(obs) {
            o.flags |= ObserverFlags::DONE;
        }
        self.invoke_cb(ctx, from, Some(Entry::from_node(msg)));
    }

    /// `direct_observer::timeout`: the answer is "nothing". Unlike the
    /// default timeout this does not tell the routing table the node failed.
    fn on_timeout(&mut self, ctx: &mut NodeCtx<'_>, obs: ObserverId) {
        let Some(o) = ctx.rpc.observers.get_mut(obs) else {
            return;
        };
        if o.flags.contains(ObserverFlags::DONE) {
            return;
        }
        o.flags |= ObserverFlags::DONE;
        let ep = o.target;
        self.invoke_cb(ctx, ep, None);
    }
}
