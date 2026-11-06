//! The RPC manager: transaction ids, matching responses to requests, and
//! timeouts.
//!
//! Ports `include/libtorrent/kademlia/rpc_manager.hpp` and
//! `src/kademlia/rpc_manager.cpp` (libtorrent RC_2_1, commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`, BSD-3-Clause, Copyright
//! Arvid Norberg, Steven Siloti, Thomas Yuan, Alden Torres).
//!
//! # How a request lives
//!
//! 1. A traversal builds the query [`Entry`] (`q` and its arguments) and
//!    calls [`NodeCtx::invoke`]: the manager adds `y`, `a.id`, a random
//!    two-byte transaction id `t` (and `ro` for a read-only node, `a.want`
//!    for a cross-family query), sends it, and remembers the observer under
//!    that id.
//! 2. A datagram with `y` of `r` or `e` goes to [`NodeCtx::rpc_incoming`],
//!    which finds the observer by transaction id *and source endpoint*
//!    (a reply from the right id but the wrong port is ignored, libtorrent
//!    test `rpc_reply_ignores_wrong_port`), validates the envelope and
//!    reports what to do.
//! 3. [`NodeCtx::rpc_tick`] times requests out: a *short* timeout after one
//!    second (the traversal may start another request), a full timeout
//!    after fifteen.
//!
//! The manager only reports; it never calls back into traversals, which
//! live elsewhere (see [`crate::traversal::Traversals`]). The reply,
//! timeout and short-timeout dispatch that libtorrent does inside
//! `rpc_manager` is done there, from the ids returned here.
//!
//! # Differences from libtorrent
//!
//! * `rpc_manager::incoming` also calls `routing_table::node_seen`; here the
//!   caller does, after the observer has handled the reply, which is the
//!   order libtorrent runs them in. See [`Incoming::Reply`].
//! * Log lines (`m_log->log(...)`) are not ported.
//! * `~rpc_manager`'s abort of every outstanding observer is not ported:
//!   dropping the node drops the arena.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use crate::bencode::{Entry, Node};
use crate::ctx::NodeCtx;
use crate::node_id::{verify_id, NodeId};
use crate::observer::{Observer, ObserverFlags, ObserverId, ObserverKind, Observers, TraversalId};

/// A request with no answer after this long gets its short-timeout
/// treatment (libtorrent `short_timeout` in `rpc_manager::tick`).
pub const SHORT_TIMEOUT: Duration = Duration::from_secs(1);
/// A request with no answer after this long has failed (libtorrent
/// `timeout` in `rpc_manager::tick`).
pub const TIMEOUT: Duration = Duration::from_secs(15);
/// `tick` never asks to be called back sooner than this.
pub const MIN_TICK: Duration = Duration::from_millis(200);

/// The transaction table and the observer arena of one node (libtorrent
/// `rpc_manager`, minus the operations that need the node's socket, settings
/// and random source; those are methods of [`NodeCtx`]).
#[derive(Debug)]
pub struct RpcManager {
    our_id: NodeId,
    /// The observers, shared between the transaction table and the
    /// traversals' result lists.
    pub observers: Observers,
    /// `(transaction id, sequence)` to observer. The sequence number makes
    /// colliding 16-bit ids distinct keys while keeping iteration
    /// deterministic (libtorrent uses an `unordered_multimap`).
    transactions: BTreeMap<(u16, u64), ObserverId>,
    next_sequence: u64,
    next_traversal: u64,
}

/// What an incoming response or error turned out to be
/// ([`NodeCtx::rpc_incoming`]).
///
/// In every variant that carries an [`ObserverId`] the transaction's
/// reference to the observer passes to the caller, who must
/// [`Observers::release`] it once the observer has been told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// Not a response to anything we asked: no transaction id, an unknown
    /// one, or the right id from the wrong endpoint. libtorrent drops these
    /// silently, because answering would allow amplification attacks.
    Ignored,
    /// It matched a request but is an error, or the response is malformed
    /// (no `r` dictionary, no 20-byte `id`, or an ID that fails BEP 42 while
    /// `enforce_node_id` is set). The observer must be told it timed out
    /// (`observer::timeout()`).
    Failed(ObserverId),
    /// A good response. The observer must handle it
    /// (`observer::reply(msg)`); then the caller reports
    /// `table.node_seen(id, from, rtt, now)`, which tells it whether the
    /// table wants a refresh.
    Reply {
        /// The observer the response answers.
        observer: ObserverId,
        /// The responding node's ID (`r.id`).
        id: NodeId,
        /// Milliseconds between sending the request and now, saturated to
        /// what a routing-table entry can store.
        rtt: u16,
    },
}

/// The outcome of [`NodeCtx::rpc_tick`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickOutcome {
    /// When to call `tick` again (libtorrent's return value).
    pub next: Duration,
    /// Observers whose request timed out. Each must get `timeout()`, and
    /// then its transaction reference released (as for [`Incoming`]).
    pub timeouts: Vec<ObserverId>,
    /// Observers that passed the short timeout and have not been told yet.
    /// Each must get `short_timeout()`; they stay in the transaction table.
    pub short_timeouts: Vec<ObserverId>,
}

impl RpcManager {
    /// An empty manager for a node with ID `our_id` (libtorrent
    /// `rpc_manager` constructor; the settings, table, socket and logger it
    /// stores arrive through [`NodeCtx`] here).
    #[must_use]
    pub fn new(our_id: NodeId) -> Self {
        Self {
            our_id,
            observers: Observers::default(),
            transactions: BTreeMap::new(),
            next_sequence: 0,
            next_traversal: 1,
        }
    }

    /// Records the node's new ID; later queries carry it (libtorrent
    /// `update_node_id`).
    pub fn update_node_id(&mut self, id: NodeId) {
        self.our_id = id;
    }

    /// The ID put in `a.id`.
    #[must_use]
    pub fn our_id(&self) -> NodeId {
        self.our_id
    }

    /// Adds `id` (our node ID) to a request's or response's argument
    /// dictionary (libtorrent `add_our_id`).
    pub fn add_our_id(&self, args: &mut Entry) {
        args.set("id", self.our_id.0.to_vec());
    }

    /// Number of live observers (libtorrent `num_allocated_observers`).
    #[must_use]
    pub fn num_allocated_observers(&self) -> usize {
        self.observers.len()
    }

    /// Number of requests awaiting an answer.
    #[must_use]
    pub fn num_transactions(&self) -> usize {
        self.transactions.len()
    }

    /// Issues a traversal id. Ids come from here because observers, which
    /// refer to their traversal by id, are created before the traversal is
    /// registered (libtorrent's `node::search_id`).
    pub fn next_traversal_id(&mut self) -> TraversalId {
        let id = TraversalId(self.next_traversal);
        self.next_traversal += 1;
        id
    }

    /// Removes the first outstanding request to `ep` (libtorrent
    /// `unreachable`: an ICMP port-unreachable arrived) and returns its
    /// observer, whose transaction reference passes to the caller; the
    /// observer must get `timeout()`. libtorrent stops after the first
    /// match, so does this.
    pub fn take_unreachable(&mut self, ep: SocketAddr) -> Option<ObserverId> {
        let key = self.transactions.iter().find_map(|(k, o)| {
            self.observers
                .get(*o)
                .filter(|obs| obs.target == ep)
                .map(|_| *k)
        })?;
        self.transactions.remove(&key)
    }

    fn take_matching(&mut self, tid: u16, from: SocketAddr) -> Option<ObserverId> {
        let key = self
            .transactions
            .range((tid, 0)..=(tid, u64::MAX))
            .find(|(_, o)| {
                self.observers
                    .get(**o)
                    .is_some_and(|obs| obs.target == from)
            })
            .map(|(k, _)| *k)?;
        self.transactions.remove(&key)
    }
}

/// The `a` dictionary of a request, created if absent.
fn args_mut(e: &mut Entry) -> &mut Entry {
    if matches!(e, Entry::Undefined) {
        *e = Entry::dict();
    }
    match e {
        Entry::Dict(map) => map.entry(b"a".to_vec()).or_insert_with(Entry::dict),
        other => panic!("a query must be a dictionary, got {other:?}"),
    }
}

impl NodeCtx<'_> {
    /// Sends the query `e` to `target` and, if it went out, tracks `obs`
    /// until a response or a timeout (libtorrent `rpc_manager::invoke`).
    ///
    /// Adds `y = "q"`, `a.id`, a random transaction id `t`, `ro = 1` for a
    /// read-only node, and `a.want = [family]` when `target` is not of this
    /// node's address family. Sets the observer's target and refreshes its
    /// send time. Returns whether the transport accepted the packet; on
    /// `false` nothing is tracked and the observer keeps only the
    /// references it had.
    ///
    /// The observer must already carry [`ObserverFlags::QUERIED`].
    ///
    /// # Panics
    ///
    /// Panics if `e` is defined but not a dictionary, or if `obs` is not a
    /// live observer; both are programming errors in the caller.
    pub fn invoke(&mut self, mut e: Entry, target: SocketAddr, obs: ObserverId) -> bool {
        e.set("y", "q");
        let native = self.native_address(target.ip());
        let want = self.protocol.want_key();
        {
            let args = args_mut(&mut e);
            self.rpc.add_our_id(args);
            if !native {
                args.set("want", Entry::List(vec![Entry::from(want)]));
            }
        }
        let tid = u16::try_from(self.rng.random(0xffff)).expect("random(0xffff) fits in a u16");
        e.set("t", tid.to_be_bytes().to_vec());
        // BEP 43: a read-only node marks every query it sends.
        if self.settings.read_only {
            e.set("ro", Entry::Int(1));
        }

        let now = self.now;
        let o = self
            .rpc
            .observers
            .get_mut(obs)
            .expect("invoke needs a live observer");
        debug_assert!(o.flags.contains(ObserverFlags::QUERIED));
        o.target = target;
        o.sent = now;

        if !self.transport.send_packet(&e, target) {
            return false;
        }
        self.rpc.observers.acquire(obs);
        let seq = self.rpc.next_sequence;
        self.rpc.next_sequence += 1;
        self.rpc.transactions.insert((tid, seq), obs);
        true
    }

    /// Creates a detached observer (one with no traversal: a ping or an
    /// `announce_peer`), marks it queried and sends `e` with it, as
    /// `node::send_single_refresh` and `announce_fun` do in libtorrent.
    ///
    /// `id` is the node's ID, or [`NodeId::MIN`] (all zero) if unknown.
    /// Returns whether the packet was sent.
    pub fn invoke_detached(
        &mut self,
        kind: ObserverKind,
        id: NodeId,
        target: SocketAddr,
        e: Entry,
    ) -> bool {
        let mut o = Observer::new(kind, None, id, target, self.now);
        o.flags |= ObserverFlags::QUERIED;
        let obs = self.rpc.observers.insert(o);
        let sent = self.invoke(e, target, obs);
        self.rpc.observers.release(obs);
        sent
    }

    /// Matches a response (`y` of `r`) or error (`y` of `e`) to the request
    /// it answers and validates its envelope (libtorrent
    /// `rpc_manager::incoming` up to, but excluding, `observer::reply` and
    /// `node_seen`). See [`Incoming`] for what the caller does with the
    /// result.
    pub fn rpc_incoming(&mut self, from: SocketAddr, msg: &Node<'_>) -> Incoming {
        let t = msg.dict_find_string_value(b"t", b"");
        if t.is_empty() {
            return Incoming::Ignored;
        }
        // Anything but two bytes cannot be ours; 0xffff is as good a
        // wrong id as any, libtorrent maps it the same way.
        let tid = <[u8; 2]>::try_from(t).map_or(0xffff, u16::from_be_bytes);
        let Some(obs) = self.rpc.take_matching(tid, from) else {
            // Not necessarily misbehaviour: after a restart the node has
            // forgotten its requests. Do not answer (amplification).
            return Incoming::Ignored;
        };
        if msg.dict_find_string_value(b"y", b"") == b"e" {
            return Incoming::Failed(obs);
        }
        let Some(r) = msg.dict_find_dict(b"r") else {
            return Incoming::Failed(obs);
        };
        let Some(nid) = r
            .dict_find_string(b"id")
            .and_then(|n| NodeId::from_slice(n.string_value()))
        else {
            return Incoming::Failed(obs);
        };
        if self.settings.enforce_node_id && !verify_id(&nid, from.ip()) {
            return Incoming::Failed(obs);
        }
        let sent = self.rpc.observers.get(obs).map_or(self.now, |o| o.sent);
        let ms = (self.now - sent).as_millis();
        // 0xffff means "unknown" in a routing-table entry, so stop below it.
        let rtt = u16::try_from(ms.min(0xfffe)).expect("clamped to a u16");
        Incoming::Reply {
            observer: obs,
            id: nid,
            rtt,
        }
    }

    /// Finds the requests that have timed out or passed the short timeout
    /// (libtorrent `rpc_manager::tick`). Requests already marked done are
    /// dropped silently. The caller tells the observers; see
    /// [`TickOutcome`].
    pub fn rpc_tick(&mut self) -> TickOutcome {
        let mut out = TickOutcome {
            next: SHORT_TIMEOUT,
            timeouts: Vec::new(),
            short_timeouts: Vec::new(),
        };
        if self.rpc.transactions.is_empty() {
            return out;
        }
        let now = self.now;
        let mut erase = Vec::new();
        for (key, oid) in &self.rpc.transactions {
            let Some(o) = self.rpc.observers.get(*oid) else {
                erase.push((*key, false));
                continue;
            };
            if o.flags.contains(ObserverFlags::DONE) {
                // a cancelled request
                erase.push((*key, true));
                continue;
            }
            let diff = now - o.sent;
            if diff >= TIMEOUT {
                erase.push((*key, false));
                out.timeouts.push(*oid);
                continue;
            }
            // do not report a short timeout twice
            if diff >= SHORT_TIMEOUT && !o.has_short_timeout() {
                out.short_timeouts.push(*oid);
                continue;
            }
            out.next = out.next.min(TIMEOUT - diff);
        }
        for (key, release) in erase {
            if let Some(oid) = self.rpc.transactions.remove(&key) {
                if release {
                    self.rpc.observers.release(oid);
                }
            }
        }
        out.next = out.next.max(MIN_TICK);
        out
    }

    /// An ICMP port-unreachable arrived for `ep` (libtorrent
    /// `rpc_manager::unreachable`): see [`RpcManager::take_unreachable`].
    pub fn rpc_unreachable(&mut self, ep: SocketAddr) -> Option<ObserverId> {
        self.rpc.take_unreachable(ep)
    }
}
