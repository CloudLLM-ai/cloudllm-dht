//! The write phase of BEP 44: `put` an item to the nodes a `get` found.
//!
//! Ports `include/libtorrent/kademlia/put_data.hpp`,
//! `src/kademlia/put_data.cpp` and the `put_item` entry points of
//! `src/kademlia/node.cpp` (libtorrent RC_2_1, commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`, BSD-3-Clause, Copyright Arvid
//! Norberg and Alden Torres).
//!
//! # A put is two traversals
//!
//! 1. a [`GetItem`] looks the item's target up,
//!    which yields the `k` closest nodes and the write token each gave;
//! 2. a [`PutData`] then sends them the `put`. It is *not* a lookup: its
//!    result list is those nodes, in that order, and it just invokes them
//!    (up to the branch factor at a time), counting the responses.
//!
//! The first hands its nodes to the second through
//! [`NodesCallback::Put`]; the second
//! reports [`Event::PutDone`] with the number of nodes that acknowledged.
//!
//! For a *mutable* put the first traversal also gets to look at the
//! authoritative item (the highest sequence number among the answers) and
//! the caller decides what to store: that is the data callback of
//! [`put_mutable`], which may replace the item wholesale (typically signing
//! a new value with `seq + 1`, which is how BEP 44's compare-and-swap is
//! done).

use std::net::SocketAddr;

use crate::bencode::{Entry, Node};
use crate::ctx::NodeCtx;
use crate::events::Event;
use crate::item::Item;
use crate::node_id::NodeId;
use crate::observer::{Observer, ObserverId, ObserverKind};
use crate::types::PublicKey;

use super::algorithm::{add_requests, base_done, init, Algorithm};
use super::find_data::{NodeToken, NodesCallback};
use super::get_item::{GetItem, Report};
use super::Traversal;

/// The `put` phase (libtorrent `put_data`).
#[derive(Debug)]
pub struct PutData {
    algo: Algorithm,
    data: Item,
    done: bool,
}

impl PutData {
    /// A put with no data and no targets yet; give it both before starting
    /// it.
    #[must_use]
    pub fn new(ctx: &mut NodeCtx<'_>) -> Self {
        Self {
            algo: Algorithm::new(ctx.new_traversal_id(), NodeId::MIN),
            data: Item::new(),
            done: false,
        }
    }

    /// Sets the item to store (libtorrent `set_data`).
    pub fn set_data(&mut self, data: Item) {
        self.data = data;
    }

    /// The item that will be stored.
    #[must_use]
    pub fn data(&self) -> &Item {
        &self.data
    }

    /// Sets the nodes to write to, with the token each gave (libtorrent
    /// `set_targets`): they become the result list as given, unsorted.
    pub fn set_targets(&mut self, ctx: &mut NodeCtx<'_>, targets: &[NodeToken]) {
        for t in targets {
            let o = Observer::new(
                ObserverKind::Put {
                    token: t.token.clone(),
                },
                Some(self.algo.id()),
                t.id,
                t.ep,
                ctx.now,
            );
            let oid = ctx.rpc.observers.insert(o);
            self.algo.push_unsorted(oid);
        }
    }

    fn put_request(&self, token: &[u8]) -> Entry {
        let mut a = Entry::dict();
        a.set("v", self.data.value().clone())
            .set("token", token.to_vec());
        if self.data.is_mutable() {
            a.set("k", self.data.pk().0.to_vec())
                .set("seq", Entry::Int(self.data.seq().0))
                .set("sig", self.data.sig().0.to_vec());
            if !self.data.salt().is_empty() {
                a.set("salt", self.data.salt().to_vec());
            }
        }
        let mut e = Entry::dict();
        e.set("q", "put").set("a", a);
        e
    }
}

impl Traversal for PutData {
    fn name(&self) -> &'static str {
        "put_data"
    }

    fn algo(&self) -> &Algorithm {
        &self.algo
    }

    fn algo_mut(&mut self) -> &mut Algorithm {
        &mut self.algo
    }

    /// Starts writing. Unlike a lookup this never adds router nodes: they
    /// must not be sent puts.
    fn start(&mut self, ctx: &mut NodeCtx<'_>) {
        init(self, ctx);
        if add_requests(self, ctx) {
            self.done(ctx);
        }
    }

    fn invoke(&mut self, ctx: &mut NodeCtx<'_>, obs: ObserverId) -> bool {
        if self.done {
            return false;
        }
        let Some((ep, token)) = ctx.rpc.observers.get(obs).and_then(|o| match &o.kind {
            ObserverKind::Put { token } => Some((o.target, token.clone())),
            _ => None,
        }) else {
            return false;
        };
        let e = self.put_request(&token);
        ctx.invoke(e, ep, obs)
    }

    /// Reports how many nodes stored the item, then finishes.
    fn done(&mut self, ctx: &mut NodeCtx<'_>) {
        self.done = true;
        ctx.events.push(Event::PutDone {
            target: self.data.target(),
            item: self.data.clone(),
            responses: usize::try_from(self.algo.num_responses()).unwrap_or(0),
        });
        base_done(self, ctx);
    }

    /// `put_data_observer::reply`: any valid response counts as stored.
    fn on_reply(
        &mut self,
        ctx: &mut NodeCtx<'_>,
        obs: ObserverId,
        _from: SocketAddr,
        _msg: &Node<'_>,
    ) {
        super::algorithm::observer_done(self, ctx, obs);
    }
}

/// `node::put_item` for an immutable item: look `target` up (the caller
/// computed it with
/// [`immutable_item_target_id`](crate::item::immutable_item_target_id)),
/// then write `data` to the closest nodes. Completes with
/// [`Event::PutDone`].
#[must_use]
pub fn put_immutable(ctx: &mut NodeCtx<'_>, target: NodeId, data: Entry) -> Box<dyn Traversal> {
    let mut put = PutData::new(ctx);
    put.set_data(Item::immutable(data));
    Box::new(GetItem::new_immutable(
        ctx,
        target,
        Report::Silent,
        NodesCallback::Put(Box::new(put)),
    ))
}

/// The callback of a mutable put: called once, with the authoritative item
/// found by the lookup (empty if nobody had one), and expected to leave in
/// it the item to store. Replacing it wholesale (as libtorrent's test does,
/// `i = g_put_item`) is allowed.
pub type DataCallback = Box<dyn FnMut(&mut Item) + Send>;

/// `node::put_item` for a mutable item: look the item up, call `data_cb`
/// with what the network holds, then write the item it leaves behind.
#[must_use]
pub fn put_mutable(
    ctx: &mut NodeCtx<'_>,
    pk: PublicKey,
    salt: &[u8],
    data_cb: DataCallback,
) -> Box<dyn Traversal> {
    let put = PutData::new(ctx);
    Box::new(GetItem::new_mutable(
        ctx,
        pk,
        salt,
        Report::PrepareMutablePut(data_cb),
        NodesCallback::Put(Box::new(put)),
    ))
}
