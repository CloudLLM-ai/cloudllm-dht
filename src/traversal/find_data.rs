//! The lookups that end by collecting write tokens: `find_data`.
//!
//! Ports `include/libtorrent/kademlia/find_data.hpp` and
//! `src/kademlia/find_data.cpp` (libtorrent RC_2_1, commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`, BSD-3-Clause, Copyright Arvid
//! Norberg and Alden Torres).
//!
//! `find_data` is the base of `get_peers`, `get_item` and `bootstrap`: it
//! asks the closest nodes for data and remembers the *write token* each node
//! hands out, so that when the lookup completes the `k` closest nodes that
//! answered, with their tokens, can be given to whatever comes next
//! (`announce_peer`, `put`). That "whatever comes next" is
//! libtorrent's `nodes_callback`; here it is the [`NodesCallback`] enum.
//!
//! Because derived lookups embed a [`FindDataCore`] and share its logic, the
//! logic is exposed as functions over [`HasFindData`], the way
//! [`algorithm`](super::algorithm) exposes the base algorithm.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use crate::announce_flags::AnnounceFlags;
use crate::bencode::{Entry, Node};
use crate::ctx::NodeCtx;
use crate::events::Event;
use crate::node_id::NodeId;
use crate::observer::{ObserverFlags, ObserverId, ObserverKind};

use super::algorithm::{
    add_entry, base_done, base_start, observer_done, observer_timeout, traversal_observer_reply,
    Algorithm,
};
use super::Traversal;

/// A node that answered, with the write token it gave us (one element of
/// the vector libtorrent passes to a `nodes_callback`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeToken {
    /// The node's ID.
    pub id: NodeId,
    /// Where it lives.
    pub ep: SocketAddr,
    /// The token to present in the follow-up write.
    pub token: Vec<u8>,
}

/// Parameters of the `announce_peer` that follows a `get_peers` lookup
/// (libtorrent `announce_fun`'s bound arguments).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnounceArgs {
    /// The torrent.
    pub info_hash: NodeId,
    /// The port to announce; already resolved (not 0).
    pub listen_port: u16,
    /// Seed, implied port and SSL flags.
    pub flags: AnnounceFlags,
}

/// What happens with the closest nodes and their tokens when a `find_data`
/// family lookup completes (libtorrent `find_data::nodes_callback`).
#[derive(Debug, Default)]
pub enum NodesCallback {
    /// Nothing (an empty `std::function`).
    #[default]
    None,
    /// Tell the owner the bootstrap finished ([`Event::BootstrapDone`]).
    Bootstrap,
    /// Send `announce_peer` to each node (`node.cpp` `announce_fun`).
    Announce(AnnounceArgs),
}

/// The state `find_data` adds to the base algorithm.
#[derive(Debug, Default)]
pub struct FindDataCore {
    write_tokens: BTreeMap<NodeId, Vec<u8>>,
    done: bool,
    /// What to do on completion. Public so a lookup that hands its job to a
    /// successor (the obfuscated `get_peers`) can take it.
    pub next: NodesCallback,
}

impl FindDataCore {
    /// A core that will run `next` on completion.
    #[must_use]
    pub fn new(next: NodesCallback) -> Self {
        Self {
            write_tokens: BTreeMap::new(),
            done: false,
            next,
        }
    }

    /// Remembers the token node `id` gave (libtorrent `got_write_token`).
    pub fn got_write_token(&mut self, id: NodeId, token: Vec<u8>) {
        self.write_tokens.insert(id, token);
    }

    /// `true` once `find_data::done` ran; lookups that send requests stop
    /// sending then (libtorrent's `find_data::m_done`).
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.done
    }
}

/// A lookup built on `find_data`: it embeds a [`FindDataCore`].
pub trait HasFindData: Traversal {
    /// The `find_data` state.
    fn fd(&self) -> &FindDataCore;
    /// The `find_data` state, mutably.
    fn fd_mut(&mut self) -> &mut FindDataCore;
}

/// `find_data::start`: with no seed nodes, take the closest `k` from the
/// routing table (failed ones included), then run the base start.
pub fn start<T: HasFindData + ?Sized>(t: &mut T, ctx: &mut NodeCtx<'_>) {
    // if the user didn't add seed-nodes manually, grab k (bucket size)
    // nodes from the routing table
    if t.algo().results().is_empty() {
        let target = *t.algo().target();
        for (id, ep) in ctx.table.closest_including_failed(&target) {
            add_entry(t, ctx, id, ep, ObserverFlags::INITIAL);
        }
    }
    base_start(t, ctx);
}

/// The nodes that answered, nearest first, with their tokens; at most `k`.
fn collect_results<T: HasFindData + ?Sized>(t: &T, ctx: &NodeCtx<'_>) -> Vec<NodeToken> {
    let k = ctx.table.bucket_size();
    t.algo()
        .results()
        .iter()
        .filter_map(|oid| ctx.rpc.observers.get(*oid))
        .filter(|o| o.flags.contains(ObserverFlags::ALIVE))
        .filter_map(|o| {
            let token = t.fd().write_tokens.get(&o.id)?;
            Some(NodeToken {
                id: o.id,
                ep: o.target,
                token: token.clone(),
            })
        })
        .take(k)
        .collect()
}

/// `find_data::done`: hands the closest answering nodes and their tokens to
/// the lookup's [`NodesCallback`], then runs the base completion.
pub fn done<T: HasFindData + ?Sized>(t: &mut T, ctx: &mut NodeCtx<'_>) {
    t.fd_mut().done = true;
    let results = collect_results(t, ctx);
    match std::mem::take(&mut t.fd_mut().next) {
        NodesCallback::None => {}
        NodesCallback::Bootstrap => ctx.events.push(Event::BootstrapDone),
        NodesCallback::Announce(args) => announce_peer(ctx, &args, &results),
    }
    base_done(t, ctx);
}

/// Sends `announce_peer` to each node (libtorrent `announce_fun` in
/// `node.cpp`). The requests belong to no traversal.
fn announce_peer(ctx: &mut NodeCtx<'_>, args: &AnnounceArgs, nodes: &[NodeToken]) {
    for n in nodes {
        let mut e = Entry::dict();
        e.set("q", "announce_peer");
        let mut a = Entry::dict();
        a.set("info_hash", args.info_hash.0.to_vec())
            .set("port", Entry::Int(i64::from(args.listen_port)))
            .set("token", n.token.clone())
            .set(
                "seed",
                Entry::Int(i64::from(args.flags.contains(AnnounceFlags::SEED))),
            );
        if args.flags.contains(AnnounceFlags::IMPLIED_PORT) {
            a.set("implied_port", Entry::Int(1));
        }
        e.set("a", a);
        ctx.invoke_detached(ObserverKind::Announce, n.id, n.ep, e);
    }
}

/// `find_data_observer::reply`: remembers the write token, follows the nodes
/// the response lists, adopts the node's ID, and marks the request done.
///
/// A missing `r` dictionary or a bad `id` counts as a timeout.
pub fn observer_reply<T: HasFindData + ?Sized>(
    t: &mut T,
    ctx: &mut NodeCtx<'_>,
    oid: ObserverId,
    msg: &Node<'_>,
) {
    let Some(r) = msg.dict_find_dict(b"r") else {
        observer_timeout(t, ctx, oid);
        return;
    };
    let Some(id) = r
        .dict_find_string(b"id")
        .and_then(|n| NodeId::from_slice(n.string_value()))
    else {
        observer_timeout(t, ctx, oid);
        return;
    };
    if let Some(token) = r.dict_find_string(b"token") {
        t.fd_mut()
            .got_write_token(id, token.string_value().to_vec());
    }
    traversal_observer_reply(t, ctx, oid, msg);
    observer_done(t, ctx, oid);
}

/// A bare `find_data` lookup (libtorrent `find_data`).
///
/// libtorrent never instantiates it (only its subclasses), and it sends no
/// request of its own, so every candidate fails at once. It is ported for
/// completeness and for tests of the shared machinery.
#[derive(Debug)]
pub struct FindData {
    algo: Algorithm,
    fd: FindDataCore,
}

impl FindData {
    /// A lookup for `target` that runs `next` on completion.
    #[must_use]
    pub fn new(ctx: &mut NodeCtx<'_>, target: NodeId, next: NodesCallback) -> Self {
        Self {
            algo: Algorithm::new(ctx.new_traversal_id(), target),
            fd: FindDataCore::new(next),
        }
    }
}

impl HasFindData for FindData {
    fn fd(&self) -> &FindDataCore {
        &self.fd
    }

    fn fd_mut(&mut self) -> &mut FindDataCore {
        &mut self.fd
    }
}

impl Traversal for FindData {
    fn name(&self) -> &'static str {
        "find_data"
    }

    fn algo(&self) -> &Algorithm {
        &self.algo
    }

    fn algo_mut(&mut self) -> &mut Algorithm {
        &mut self.algo
    }

    fn new_observer(&self) -> ObserverKind {
        ObserverKind::FindData
    }

    fn start(&mut self, ctx: &mut NodeCtx<'_>) {
        start(self, ctx);
    }

    fn done(&mut self, ctx: &mut NodeCtx<'_>) {
        done(self, ctx);
    }

    fn on_reply(
        &mut self,
        ctx: &mut NodeCtx<'_>,
        obs: ObserverId,
        _from: SocketAddr,
        msg: &Node<'_>,
    ) {
        observer_reply(self, ctx, obs, msg);
    }
}
