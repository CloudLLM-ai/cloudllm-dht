//! Bootstrap: join the network, or refresh our corner of it, by looking up
//! an ID close to our own.
//!
//! Ports `include/libtorrent/kademlia/refresh.hpp`,
//! `src/kademlia/refresh.cpp` (class `bootstrap`) and `node::bootstrap` /
//! the self-refresh in `node::tick` (libtorrent RC_2_1, commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`, BSD-3-Clause, Copyright Arvid
//! Norberg and Alden Torres).
//!
//! A bootstrap is a `get_peers` lookup ([`Flavour::Bootstrap`]) for our own
//! node ID with its last bytes randomised (`make_id_secret`), so that the
//! lookup walks towards us and fills the routing table buckets near us
//! without being mistaken for a real info-hash. Requests to the seed nodes
//! carry `bs = 1`. When it completes, the nodes it learned about but never
//! asked are pinged ([`NodeCtx::request_ping`]), so the table adds those
//! that answer.

use std::net::SocketAddr;

use crate::ctx::NodeCtx;
use crate::node_id::NodeId;
use crate::observer::ObserverFlags;

use super::algorithm::add_entry;
use super::find_data::NodesCallback;
use super::get_peers::{Flavour, GetPeers};
use super::Traversal;

/// `node::bootstrap`: a lookup seeded with `nodes` (from saved state or the
/// settings), minus those the IP filter blocks. With no seeds it uses the
/// routing table's closest nodes, and the router nodes if that is too few.
///
/// `notify` makes completion produce [`Event::BootstrapDone`]; libtorrent's
/// self-refresh passes a no-op callback, which is `notify == false`.
///
/// The caller spawns the result with
/// [`Traversals::spawn`](super::Traversals::spawn).
///
/// [`Event::BootstrapDone`]: crate::events::Event::BootstrapDone
#[must_use]
pub fn bootstrap(ctx: &mut NodeCtx<'_>, nodes: &[SocketAddr], notify: bool) -> Box<dyn Traversal> {
    let mut target = ctx.id;
    let secret = ctx.id_secret;
    secret.make_id_secret(&mut target, &mut *ctx.rng);
    let next = if notify {
        NodesCallback::Bootstrap
    } else {
        NodesCallback::None
    };
    let mut t = GetPeers::new(ctx, Flavour::Bootstrap, target, false, false, next);
    for n in nodes {
        // these come from persisted state (or the configuration), so,
        // unlike nodes discovered by a lookup, they have not been filtered
        if ctx.filtered(*n) {
            continue;
        }
        add_entry(&mut t, ctx, NodeId::MIN, *n, ObserverFlags::INITIAL);
    }
    Box::new(t)
}

/// The periodic self-refresh of `node::tick`: a bootstrap with no seeds and
/// no completion event. The node runs it every ten minutes while its
/// routing table is shallow.
#[must_use]
pub fn refresh(ctx: &mut NodeCtx<'_>) -> Box<dyn Traversal> {
    bootstrap(ctx, &[], false)
}
