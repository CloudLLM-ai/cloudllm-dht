//! BEP 51: sampling the info-hashes a node knows.
//!
//! Ports `include/libtorrent/kademlia/sample_infohashes.hpp`,
//! `src/kademlia/sample_infohashes.cpp` and `node::sample_infohashes`
//! (libtorrent RC_2_1, commit `86d573f2631b0162d3cca5e257217eaf530fdcba`,
//! BSD-3-Clause, Copyright Arvid Norberg and Alden Torres).
//!
//! Despite living among the traversals this is "not an actual traversal"
//! (libtorrent's own comment): it sends one `sample_infohashes` request to
//! one node and reports what comes back as an
//! [`Event::SampleInfohashes`]. The result list stays empty, so nothing is
//! iterated; the traversal object only owns the observer's behaviour.
//!
//! The response must carry a 20-byte `id`, an `interval` of 0 to 21600
//! seconds, a non-negative `num` that fits an `i32`, and a `samples` string
//! whose length is a multiple of 20; otherwise the request counts as failed.
//! A node's `nodes` (or `nodes6`) are passed on, but, unlike in a lookup,
//! not followed.

use std::net::SocketAddr;
use std::time::Duration;

use crate::bencode::{Entry, Node};
use crate::ctx::NodeCtx;
use crate::events::Event;
use crate::node_id::NodeId;
use crate::observer::{Observer, ObserverFlags, ObserverId, ObserverKind};
use crate::sha1_hash::HASH_LEN;

use super::algorithm::{look_for_nodes, observer_timeout, Algorithm};
use super::Traversal;

/// The largest `interval` a node may ask for: six hours (the literal 21600
/// in `sample_infohashes_observer::reply`, which carries a TODO to name it).
pub const MAX_INTERVAL_SECS: i64 = 21600;

/// A single BEP 51 request (libtorrent `sample_infohashes`).
#[derive(Debug)]
pub struct SampleInfohashes {
    algo: Algorithm,
    ep: SocketAddr,
    sample_target: NodeId,
    /// Cleared once the answer was delivered (libtorrent nulls
    /// `m_data_callback`).
    pending: bool,
}

impl SampleInfohashes {
    /// A request for `ep` asking for a sample near `target` (the `target`
    /// argument of the query, not a lookup target).
    #[must_use]
    pub fn new(ctx: &mut NodeCtx<'_>, ep: SocketAddr, target: NodeId) -> Self {
        Self {
            algo: Algorithm::new(ctx.new_traversal_id(), NodeId::MIN),
            ep,
            sample_target: target,
            pending: true,
        }
    }

    /// `sample_infohashes::got_samples`: delivers the answer once.
    fn got_samples(&mut self, ctx: &mut NodeCtx<'_>, ev: Event) {
        if self.pending {
            self.pending = false;
            ctx.events.push(ev);
            super::algorithm::base_done(self, ctx);
        }
    }
}

/// `node::sample_infohashes`: the traversal to hand to
/// [`Traversals::spawn`](super::Traversals::spawn), which sends the request.
#[must_use]
pub fn sample_infohashes(
    ctx: &mut NodeCtx<'_>,
    ep: SocketAddr,
    target: NodeId,
) -> Box<dyn Traversal> {
    Box::new(SampleInfohashes::new(ctx, ep, target))
}

impl Traversal for SampleInfohashes {
    fn name(&self) -> &'static str {
        "sample_infohashes"
    }

    fn algo(&self) -> &Algorithm {
        &self.algo
    }

    fn algo_mut(&mut self) -> &mut Algorithm {
        &mut self.algo
    }

    /// Sends the request. The observer is not part of the result list; the
    /// transaction table holds it until the answer or the timeout.
    fn start(&mut self, ctx: &mut NodeCtx<'_>) {
        let mut o = Observer::new(
            ObserverKind::SampleInfohashes,
            Some(self.algo.id()),
            NodeId::MIN,
            self.ep,
            ctx.now,
        );
        o.flags |= ObserverFlags::QUERIED;
        let obs = ctx.rpc.observers.insert(o);
        let mut a = Entry::dict();
        a.set("target", self.sample_target.0.to_vec());
        let mut e = Entry::dict();
        e.set("q", "sample_infohashes").set("a", a);
        ctx.invoke(e, self.ep, obs);
        ctx.rpc.observers.release(obs);
    }

    fn on_reply(
        &mut self,
        ctx: &mut NodeCtx<'_>,
        obs: ObserverId,
        from: SocketAddr,
        msg: &Node<'_>,
    ) {
        let Some(r) = msg.dict_find_dict(b"r") else {
            observer_timeout(self, ctx, obs);
            return;
        };
        let nodes: Vec<(NodeId, SocketAddr)> = look_for_nodes(ctx.protocol, r)
            .map(|n| (n.id, n.ep))
            .collect();
        let Some(nid) = r
            .dict_find_string(b"id")
            .and_then(|n| NodeId::from_slice(n.string_value()))
        else {
            observer_timeout(self, ctx, obs);
            return;
        };
        let interval = r.dict_find_int_value(b"interval", -1);
        if !(0..=MAX_INTERVAL_SECS).contains(&interval) {
            observer_timeout(self, ctx, obs);
            return;
        }
        let num = r.dict_find_int_value(b"num", -1);
        let Some(num) = u32::try_from(num)
            .ok()
            .filter(|n| i32::try_from(*n).is_ok())
        else {
            observer_timeout(self, ctx, obs);
            return;
        };
        match r
            .dict_find_string(b"samples")
            .map(Node::string_value)
            .filter(|s| s.len() % HASH_LEN == 0)
        {
            Some(samples) => {
                let samples: Vec<NodeId> = samples
                    .as_chunks::<HASH_LEN>()
                    .0
                    .iter()
                    .map(|c| NodeId::from(*c))
                    .collect();
                let interval = Duration::from_secs(
                    u64::try_from(interval).expect("range checked to be non-negative"),
                );
                self.got_samples(
                    ctx,
                    Event::SampleInfohashes {
                        from,
                        nid,
                        interval,
                        num,
                        samples,
                        nodes,
                    },
                );
            }
            None => observer_timeout(self, ctx, obs),
        }
        // We deliberately do not run the base `traversal_observer::reply`:
        // the nodes are reported, not followed. Marking the request done is
        // what keeps `observer::abort` and `timeout` quiet afterwards.
        if let Some(o) = ctx.rpc.observers.get_mut(obs) {
            o.flags |= ObserverFlags::DONE;
        }
    }
}
