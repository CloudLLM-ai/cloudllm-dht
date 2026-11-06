//! `get_peers` lookups: plain, obfuscated (privacy), and the observer that
//! reads peers out of responses.
//!
//! Ports `include/libtorrent/kademlia/get_peers.hpp` and
//! `src/kademlia/get_peers.cpp`, and the construction of these lookups in
//! `node::get_peers` and `node::announce` (libtorrent RC_2_1, commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`, BSD-3-Clause, Copyright Arvid
//! Norberg, Steven Siloti and Alden Torres).
//!
//! # The three flavours
//!
//! libtorrent has three classes here, each a subclass of the previous:
//!
//! * `get_peers`: asks each node for `info_hash`;
//! * `obfuscated_get_peers`: a *two phase* lookup for privacy. Phase one
//!   asks each node about an info-hash whose bits past the shared prefix
//!   (plus 3) are random, which is just enough for the node to answer with
//!   closer nodes, without telling it which torrent is wanted. When it ends,
//!   it starts phase two, a plain `get_peers` seeded with up to 16 live nodes
//!   from phase one, which carries the callbacks;
//! * `bootstrap` (in [`refresh`](super::refresh)): a `get_peers` for a
//!   made-up target near our own ID.
//!
//! They differ only in a few virtual members, so one struct, [`GetPeers`],
//! carries a [`Flavour`] that selects them.
//!
//! # What a response may contain
//!
//! Peers arrive in `values`: either one string of packed 6-byte IPv4
//! endpoints (the mainline form, only from an IPv4 sender) or a list with
//! one string per peer (the uTorrent/libtorrent form, also used for IPv6).
//! Each response with a `values` list produces an [`Event::GetPeersReply`].

use std::net::SocketAddr;

use crate::announce_flags::AnnounceFlags;
use crate::bencode::{Entry, Node, NodeKind};
use crate::ctx::NodeCtx;
use crate::events::Event;
use crate::net::{read_endpoint, read_endpoint_list, Protocol};
use crate::node_id::{generate_prefix_mask, generate_random_id, NodeId};
use crate::observer::{ObserverFlags, ObserverId, ObserverKind};

use super::algorithm::{
    add_entry, observer_done, observer_timeout, traversal_observer_reply, Algorithm,
};
use super::find_data::{self, AnnounceArgs, FindDataCore, HasFindData, NodesCallback};
use super::Traversal;

/// Which of libtorrent's `get_peers` classes a [`GetPeers`] stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// `get_peers`.
    Plain,
    /// `obfuscated_get_peers`, phase one (`m_obfuscated` true). When it
    /// completes it spawns a [`Flavour::Plain`] lookup.
    Obfuscated,
    /// `bootstrap`: see [`super::refresh`].
    Bootstrap,
}

/// A `get_peers` lookup (libtorrent `get_peers`, `obfuscated_get_peers`
/// and, through [`Flavour::Bootstrap`], `bootstrap`).
#[derive(Debug)]
pub struct GetPeers {
    algo: Algorithm,
    fd: FindDataCore,
    noseeds: bool,
    /// Whether to report peers (libtorrent: a `data_callback` was given).
    report_peers: bool,
    flavour: Flavour,
}

impl GetPeers {
    /// Creates the lookup but does not start it.
    ///
    /// `noseeds` asks nodes to leave seeds out of their answer (BEP 5
    /// `noseed`); `report_peers` says whether peers found go to
    /// `ctx.events`; `next` runs on completion.
    #[must_use]
    pub fn new(
        ctx: &mut NodeCtx<'_>,
        flavour: Flavour,
        target: NodeId,
        noseeds: bool,
        report_peers: bool,
        next: NodesCallback,
    ) -> Self {
        Self {
            algo: Algorithm::new(ctx.new_traversal_id(), target),
            fd: FindDataCore::new(next),
            noseeds,
            report_peers,
            flavour,
        }
    }

    /// Which flavour this lookup is.
    #[must_use]
    pub fn flavour(&self) -> Flavour {
        self.flavour
    }

    /// `get_peers::got_peers`: reports peers found (if anybody listens).
    fn got_peers(&self, ctx: &mut NodeCtx<'_>, peers: Vec<SocketAddr>) {
        if self.report_peers {
            ctx.events.push(Event::GetPeersReply {
                target: *self.algo.target(),
                peers,
            });
        }
    }

    /// `get_peers::invoke`: the plain query.
    fn invoke_plain(&mut self, ctx: &mut NodeCtx<'_>, obs: ObserverId) -> bool {
        if self.fd.is_done() {
            return false;
        }
        let Some(ep) = ctx.rpc.observers.get(obs).map(|o| o.target) else {
            return false;
        };
        let target = *self.algo.target();
        let mut a = Entry::dict();
        a.set("info_hash", target.0.to_vec());
        if self.noseeds {
            a.set("noseed", Entry::Int(1));
        }
        let mut e = Entry::dict();
        e.set("q", "get_peers").set("a", a);
        ctx.events.push(Event::OutgoingGetPeers {
            target,
            sent_target: target,
            to: ep,
        });
        ctx.invoke(e, ep, obs)
    }

    /// `obfuscated_get_peers::invoke`: asks about a target that agrees with
    /// the real one only up to three bits past the prefix we share with the
    /// node, so the node can answer with closer nodes but cannot tell which
    /// torrent is wanted.
    fn invoke_obfuscated(&mut self, ctx: &mut NodeCtx<'_>, obs: ObserverId) -> bool {
        let Some((id, ep)) = ctx.rpc.observers.get(obs).map(|o| (o.id, o.target)) else {
            return false;
        };
        let target = *self.algo.target();
        let obfuscated = obfuscate(&target, &id, generate_random_id(&mut *ctx.rng));
        let mut a = Entry::dict();
        a.set("info_hash", obfuscated.0.to_vec());
        let mut e = Entry::dict();
        e.set("q", "get_peers").set("a", a);
        ctx.events.push(Event::OutgoingGetPeers {
            target,
            sent_target: obfuscated,
            to: ep,
        });
        ctx.invoke(e, ep, obs)
    }

    /// `bootstrap::invoke`: a `get_peers` for a made-up ID near our own.
    ///
    /// The ID is taken from the node *now*, not from the target stored at
    /// creation, in case our ID changes during the bootstrap. A request to
    /// a seed (initial) node carries `bs = 1`, telling a router node that
    /// this is a bootstrap and not collateral traffic.
    fn invoke_bootstrap(&mut self, ctx: &mut NodeCtx<'_>, obs: ObserverId) -> bool {
        let Some((ep, initial)) = ctx
            .rpc
            .observers
            .get(obs)
            .map(|o| (o.target, o.flags.contains(ObserverFlags::INITIAL)))
        else {
            return false;
        };
        let mut target = ctx.id;
        let secret = ctx.id_secret;
        secret.make_id_secret(&mut target, &mut *ctx.rng);
        let mut a = Entry::dict();
        a.set("info_hash", target.0.to_vec());
        if initial {
            a.set("bs", Entry::Int(1));
        }
        let mut e = Entry::dict();
        e.set("q", "get_peers").set("a", a);
        ctx.invoke(e, ep, obs)
    }

    /// `obfuscated_get_peers::done`: phase one is over; start the plain
    /// lookup, seeded with up to 16 live nodes whose IDs we learned, and
    /// give it the callbacks.
    fn spawn_phase_two(&mut self, ctx: &mut NodeCtx<'_>) {
        let mut next = GetPeers::new(
            ctx,
            Flavour::Plain,
            *self.algo.target(),
            self.noseeds,
            self.report_peers,
            std::mem::take(&mut self.fd.next),
        );
        // the successor reports peers now; this lookup must not
        self.report_peers = false;
        let seeds: Vec<(NodeId, SocketAddr)> = self
            .algo
            .results()
            .iter()
            .filter_map(|oid| ctx.rpc.observers.get(*oid))
            // only nodes whose ID we know and that we know are alive
            .filter(|o| !o.flags.contains(ObserverFlags::NO_ID))
            .filter(|o| o.flags.contains(ObserverFlags::ALIVE))
            .map(|o| (o.id, o.target))
            .take(16)
            .collect();
        for (id, ep) in seeds {
            add_entry(&mut next, ctx, id, ep, ObserverFlags::INITIAL);
        }
        ctx.spawn(Box::new(next));
    }
}

/// The ID sent in an obfuscated query: `target` for the first
/// `shared + 3` bits, `random` after that, where `shared` is the number of
/// leading bits `node` and `target` have in common.
///
/// libtorrent computes `shared` as `160 - distance_exp(node, target)`, which
/// is one too many (`distance_exp` is `159 - leading_zeros`), so it reveals
/// four bits past the prefix although its comment says three. This port
/// reveals three. Other nodes only ever see the result as a random-looking
/// ID, so this is interoperable; see `docs/PORTING.md`.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::traversal::get_peers::obfuscate;
/// use cloudllm_dht::Sha1Hash;
///
/// let target = Sha1Hash([0xff; 20]);
/// let node = Sha1Hash([0xff; 20]); // shares everything: nothing hidden
/// let random = Sha1Hash([0x00; 20]);
/// assert_eq!(obfuscate(&target, &node, random), target);
///
/// let far = Sha1Hash([0x00; 20]); // shares no bits: 3 are revealed
/// assert_eq!(obfuscate(&target, &far, random).0[0], 0b1110_0000);
/// ```
#[must_use]
pub fn obfuscate(target: &NodeId, node: &NodeId, random: NodeId) -> NodeId {
    let shared_prefix = (*node ^ *target).leading_zeros() as usize;
    let mask = generate_prefix_mask(shared_prefix + 3);
    let mut out = [0u8; 20];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (random.0[i] & !mask.0[i]) | (target.0[i] & mask.0[i]);
    }
    NodeId::from(out)
}

/// Reads the `values` of a `get_peers` response (the `get_peers_observer`
/// parsing): one packed string of IPv4 endpoints from an IPv4 sender, else
/// a list of per-peer strings. Malformed entries are skipped.
fn read_values(values: &Node<'_>, from: SocketAddr) -> Vec<SocketAddr> {
    if values.list_len() == 1 && from.is_ipv4() {
        if let Some(first) = values.list_at(0).filter(|f| f.kind() == NodeKind::Str) {
            // assume it's the mainline format
            return first
                .string_value()
                .as_chunks::<{ Protocol::V4.endpoint_len() }>()
                .0
                .iter()
                .filter_map(|c| read_endpoint(Protocol::V4, c))
                .collect();
        }
    }
    // assume it's the uTorrent/libtorrent format
    read_endpoint_list(values)
}

impl HasFindData for GetPeers {
    fn fd(&self) -> &FindDataCore {
        &self.fd
    }

    fn fd_mut(&mut self) -> &mut FindDataCore {
        &mut self.fd
    }
}

impl Traversal for GetPeers {
    fn name(&self) -> &'static str {
        match self.flavour {
            Flavour::Plain => "get_peers",
            Flavour::Obfuscated => "get_peers [obfuscated]",
            Flavour::Bootstrap => "bootstrap",
        }
    }

    fn algo(&self) -> &Algorithm {
        &self.algo
    }

    fn algo_mut(&mut self) -> &mut Algorithm {
        &mut self.algo
    }

    fn new_observer(&self) -> ObserverKind {
        match self.flavour {
            Flavour::Obfuscated => ObserverKind::ObfuscatedGetPeers,
            Flavour::Plain | Flavour::Bootstrap => ObserverKind::GetPeers,
        }
    }

    fn start(&mut self, ctx: &mut NodeCtx<'_>) {
        find_data::start(self, ctx);
    }

    fn invoke(&mut self, ctx: &mut NodeCtx<'_>, obs: ObserverId) -> bool {
        match self.flavour {
            Flavour::Plain => self.invoke_plain(ctx, obs),
            Flavour::Obfuscated => self.invoke_obfuscated(ctx, obs),
            Flavour::Bootstrap => self.invoke_bootstrap(ctx, obs),
        }
    }

    fn done(&mut self, ctx: &mut NodeCtx<'_>) {
        match self.flavour {
            Flavour::Plain => {}
            Flavour::Obfuscated => self.spawn_phase_two(ctx),
            // `bootstrap::done`: ping the nodes we never got to ask, so
            // the table learns about them if they answer
            Flavour::Bootstrap => {
                let untried: Vec<SocketAddr> = self
                    .algo
                    .results()
                    .iter()
                    .filter_map(|oid| ctx.rpc.observers.get(*oid))
                    .filter(|o| !o.flags.contains(ObserverFlags::QUERIED))
                    .map(|o| o.target)
                    .collect();
                for ep in untried {
                    ctx.request_ping(ep);
                }
            }
        }
        find_data::done(self, ctx);
    }

    fn on_reply(
        &mut self,
        ctx: &mut NodeCtx<'_>,
        obs: ObserverId,
        from: SocketAddr,
        msg: &Node<'_>,
    ) {
        let kind = ctx.rpc.observers.get(obs).map(|o| o.kind.clone());
        match kind {
            Some(ObserverKind::ObfuscatedGetPeers) => self.reply_obfuscated(ctx, obs, msg),
            Some(ObserverKind::GetPeers) => self.reply_get_peers(ctx, obs, from, msg),
            _ => {}
        }
    }
}

impl GetPeers {
    /// `get_peers_observer::reply`.
    fn reply_get_peers(
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
        // look for peers
        if let Some(values) = r.dict_find_list(b"values") {
            let peers = read_values(values, from);
            self.got_peers(ctx, peers);
        }
        find_data::observer_reply(self, ctx, obs, msg);
    }

    /// `obfuscated_get_peers_observer::reply`: only nodes matter, there are
    /// no peers or tokens in an answer to an obfuscated query.
    fn reply_obfuscated(&mut self, ctx: &mut NodeCtx<'_>, obs: ObserverId, msg: &Node<'_>) {
        let Some(r) = msg.dict_find_dict(b"r") else {
            observer_timeout(self, ctx, obs);
            return;
        };
        if r.dict_find_string(b"id")
            .and_then(|n| NodeId::from_slice(n.string_value()))
            .is_none()
        {
            observer_timeout(self, ctx, obs);
            return;
        }
        traversal_observer_reply(self, ctx, obs, msg);
        observer_done(self, ctx, obs);
    }
}

/// A plain `get_peers` lookup for `info_hash` that reports peers as events
/// (libtorrent `node::get_peers` with a data callback and no nodes
/// callback). Follows `privacy_lookups`: an obfuscated lookup when set.
///
/// `flags.SEED` becomes the `noseed` argument: a seed has no use for other
/// seeds. The caller spawns the result with
/// [`Traversals::spawn`](super::Traversals::spawn).
#[must_use]
pub fn get_peers(
    ctx: &mut NodeCtx<'_>,
    info_hash: NodeId,
    flags: AnnounceFlags,
) -> Box<dyn Traversal> {
    lookup(ctx, info_hash, flags, NodesCallback::None)
}

/// `node::announce`: a `get_peers` lookup whose closest nodes get an
/// `announce_peer` when it completes. `listen_port` must already be
/// resolved (libtorrent asks the observer for the real port when given 0).
#[must_use]
pub fn announce(
    ctx: &mut NodeCtx<'_>,
    info_hash: NodeId,
    listen_port: u16,
    flags: AnnounceFlags,
) -> Box<dyn Traversal> {
    let args = AnnounceArgs {
        info_hash,
        listen_port,
        flags,
    };
    lookup(ctx, info_hash, flags, NodesCallback::Announce(args))
}

fn lookup(
    ctx: &mut NodeCtx<'_>,
    info_hash: NodeId,
    flags: AnnounceFlags,
    next: NodesCallback,
) -> Box<dyn Traversal> {
    // search for nodes with ids close to the info-hash, or with peers for it
    let noseeds = flags.contains(AnnounceFlags::SEED);
    let flavour = if ctx.settings.privacy_lookups {
        Flavour::Obfuscated
    } else {
        Flavour::Plain
    };
    Box::new(GetPeers::new(ctx, flavour, info_hash, noseeds, true, next))
}
