//! The base of every lookup: the sorted result list, the branch factor and
//! the done conditions.
//!
//! Ports `include/libtorrent/kademlia/traversal_algorithm.hpp` and
//! `src/kademlia/traversal_algorithm.cpp` (libtorrent RC_2_1, commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`, BSD-3-Clause, Copyright Arvid
//! Norberg, Steven Siloti, Alden Torres).
//!
//! # Structure
//!
//! C++ `traversal_algorithm` is a base class whose virtual members
//! (`start`, `done`, `invoke`, `new_observer`) the concrete lookups
//! override and whose non-virtual members call back into those overrides.
//! Here the state is the [`Algorithm`] struct embedded in each lookup, the
//! virtual members are methods of the [`Traversal`] trait, and the
//! non-virtual members are the free functions of this module, generic over
//! `T: Traversal + ?Sized` so they can call the overrides ([`add_requests`]
//! calls `invoke`, [`failed`] and [`finished`] call `done`). An override
//! that wants the base behaviour calls the matching function here
//! (`done` overrides end in [`base_done`], like C++ ends in
//! `traversal_algorithm::done()`).
//!
//! # The result list
//!
//! `results` holds the candidate nodes, as observers in the
//! [`Observers`](crate::observer::Observers) arena. The first `sorted`
//! entries are ordered by XOR distance to the target, closest first. The
//! tail holds nodes whose IDs were unknown when added (bootstrap nodes);
//! they stay in insertion order until their ID is learned
//! ([`set_id`]). The list never grows past 100 entries.
//!
//! # Branching and timeouts
//!
//! At most `branch_factor` requests are outstanding (with
//! `aggressive_lookups`, at the top of the list; otherwise anywhere). A
//! request that passes the short timeout raises the branch factor by one so
//! another node can be asked while the slow one keeps its chance to answer;
//! when that request finishes either way, the branch factor is restored.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

use crate::bencode::Node;
use crate::ctx::NodeCtx;
use crate::net::{read_node_endpoint, NodeEndpoint, Protocol};
use crate::node_id::{compare_ref, generate_random_id, NodeId};
use crate::observer::{Observer, ObserverFlags, ObserverId, ObserverKind, TraversalId};

use super::Traversal;

/// Results beyond this many are dropped (the literal 100 in
/// `traversal_algorithm::add_entry`).
pub const MAX_RESULTS: usize = 100;

/// The state `traversal_algorithm` keeps, shared by every lookup.
///
/// Fields are private; lookups use the accessors and the functions of this
/// module. Tests read the result list through [`Algorithm::results`].
#[derive(Debug)]
pub struct Algorithm {
    id: TraversalId,
    target: NodeId,
    results: Vec<ObserverId>,
    sorted_results: usize,
    invoke_count: i32,
    branch_factor: i32,
    responses: i32,
    timeouts: i32,
    done: bool,
    abort: bool,
    initialized: bool,
    peer4_prefixes: BTreeSet<u32>,
    peer6_prefixes: BTreeSet<u64>,
}

impl Algorithm {
    /// A new, empty lookup state for `target` (libtorrent
    /// `traversal_algorithm(node, target)`). The default branch factor of 3
    /// is replaced by the setting when the lookup starts.
    #[must_use]
    pub fn new(id: TraversalId, target: NodeId) -> Self {
        Self {
            id,
            target,
            results: Vec::new(),
            sorted_results: 0,
            invoke_count: 0,
            branch_factor: 3,
            responses: 0,
            timeouts: 0,
            done: false,
            abort: false,
            initialized: false,
            peer4_prefixes: BTreeSet::new(),
            peer6_prefixes: BTreeSet::new(),
        }
    }

    /// This lookup's id.
    #[must_use]
    pub fn id(&self) -> TraversalId {
        self.id
    }

    /// What the lookup searches for (`target()`).
    #[must_use]
    pub fn target(&self) -> &NodeId {
        &self.target
    }

    /// The candidate list, closest known nodes first, then nodes of unknown
    /// ID in insertion order.
    #[must_use]
    pub fn results(&self) -> &[ObserverId] {
        &self.results
    }

    /// How many leading entries of [`Algorithm::results`] are sorted by
    /// distance (`num_sorted_results`).
    #[must_use]
    pub fn num_sorted_results(&self) -> usize {
        self.sorted_results
    }

    /// Outstanding requests (`invoke_count`).
    #[must_use]
    pub fn invoke_count(&self) -> i32 {
        self.invoke_count
    }

    /// Current concurrency limit (`branch_factor`).
    #[must_use]
    pub fn branch_factor(&self) -> i32 {
        self.branch_factor
    }

    /// Responses received so far (`num_responses`).
    #[must_use]
    pub fn num_responses(&self) -> i32 {
        self.responses
    }

    /// Requests that timed out or failed (`num_timeouts`).
    #[must_use]
    pub fn num_timeouts(&self) -> i32 {
        self.timeouts
    }

    /// `true` once the lookup finished ([`base_done`] ran); no more results
    /// are accepted.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// `true` once the lookup was started with the base `start` (libtorrent
    /// `init()` registers it as a running request). Lookups that are a
    /// single request ([`SampleInfohashes`](super::sample_infohashes::SampleInfohashes),
    /// [`DirectTraversal`](super::direct_request::DirectTraversal)) never are.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Appends an observer to the end of the result list without sorting it
    /// (libtorrent's `m_results.push_back` in `put_data::set_targets`, where
    /// the nodes are already the chosen targets). The list takes over the
    /// caller's reference to the observer.
    pub fn push_unsorted(&mut self, oid: ObserverId) {
        self.results.push(oid);
    }

    /// Stops issuing new requests; the ones in flight still complete
    /// (`traversal_algorithm::abort`).
    pub fn abort(&mut self) {
        self.abort = true;
    }
}

fn obs<'c>(ctx: &'c NodeCtx<'_>, id: ObserverId) -> &'c Observer {
    ctx.rpc
        .observers
        .get(id)
        .expect("the result list holds a reference to each of its observers")
}

fn obs_mut<'c>(ctx: &'c mut NodeCtx<'_>, id: ObserverId) -> &'c mut Observer {
    ctx.rpc
        .observers
        .get_mut(id)
        .expect("the result list holds a reference to each of its observers")
}

/// Adds a node to the candidate list (libtorrent `add_entry`).
///
/// A node with an all-zero `id` has an unknown ID: it gets a random
/// placeholder, [`ObserverFlags::NO_ID`], and goes to the unsorted tail.
/// Otherwise it is inserted in distance order unless a node with that ID is
/// already listed, or (with `restrict_search_ips`, and unless `flags`
/// contains [`ObserverFlags::INITIAL`]) another node from the same /24 (/64
/// for IPv6) is already listed. Does nothing once the lookup is done.
/// Keeps the list to [`MAX_RESULTS`], cancelling the requests of the
/// entries it drops.
pub fn add_entry<T: Traversal + ?Sized>(
    t: &mut T,
    ctx: &mut NodeCtx<'_>,
    id: NodeId,
    addr: SocketAddr,
    flags: ObserverFlags,
) {
    if t.algo().done {
        return;
    }
    let mut ob = Observer::new(t.new_observer(), Some(t.algo().id), id, addr, ctx.now);
    ob.flags |= flags;
    if id == NodeId::MIN {
        ob.id = generate_random_id(&mut *ctx.rng);
        ob.flags |= ObserverFlags::NO_ID;
        let oid = ctx.rpc.observers.insert(ob);
        t.algo_mut().results.push(oid);
    } else if !insert_sorted(t, ctx, ob, flags) {
        return;
    }
    trim_results(t, ctx);
}

/// Inserts `ob` among the sorted prefix. Returns `false` if the node was
/// rejected for sharing a prefix with a node already in the search.
fn insert_sorted<T: Traversal + ?Sized>(
    t: &mut T,
    ctx: &mut NodeCtx<'_>,
    ob: Observer,
    flags: ObserverFlags,
) -> bool {
    let id = ob.id;
    let addr = ob.target;
    let a = t.algo();
    let target = a.target;
    let pos = a.results[..a.sorted_results]
        .partition_point(|r| compare_ref(&obs(ctx, *r).id, &id, &target));
    if pos < a.sorted_results && obs(ctx, a.results[pos]).id == id {
        // already listed
        return true;
    }
    // The restriction does not apply to nodes from our own routing table
    // or the caller's seed list.
    if ctx.settings.restrict_search_ips
        && !flags.contains(ObserverFlags::INITIAL)
        && !t.algo_mut().claim_prefix(addr.ip())
    {
        // A node with a nearly identical address but a different ID:
        // probably an attack. Ignore it.
        return false;
    }
    let oid = ctx.rpc.observers.insert(ob);
    let a = t.algo_mut();
    a.results.insert(pos, oid);
    a.sorted_results += 1;
    true
}

impl Algorithm {
    /// Records the /24 (IPv4) or /64 (IPv6) prefix of `ip`; `false` if a
    /// node of that prefix is already in the search.
    fn claim_prefix(&mut self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => self.peer4_prefixes.insert(u32::from(a) & 0xffff_ff00),
            IpAddr::V6(a) => {
                let o = a.octets();
                let prefix = u64::from_be_bytes([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]);
                self.peer6_prefixes.insert(prefix)
            }
        }
    }
}

/// Cuts the list to [`MAX_RESULTS`]. A request still in flight to a dropped
/// node is cancelled (flagged done, its slot given back) so it cannot call
/// into the lookup later.
fn trim_results<T: Traversal + ?Sized>(t: &mut T, ctx: &mut NodeCtx<'_>) {
    if t.algo().results.len() <= MAX_RESULTS {
        return;
    }
    let dropped = t.algo_mut().results.split_off(MAX_RESULTS);
    for oid in dropped {
        let f = obs(ctx, oid).flags;
        let in_flight = f & (ObserverFlags::QUERIED | ObserverFlags::FAILED | ObserverFlags::ALIVE)
            == ObserverFlags::QUERIED;
        if in_flight {
            obs_mut(ctx, oid).flags |= ObserverFlags::DONE;
            let a = t.algo_mut();
            debug_assert!(a.invoke_count > 0);
            a.invoke_count -= 1;
            if f.contains(ObserverFlags::SHORT_TIMEOUT) {
                debug_assert!(a.branch_factor > 0);
                a.branch_factor -= 1;
            }
        }
        ctx.rpc.observers.release(oid);
    }
    let a = t.algo_mut();
    a.sorted_results = a.sorted_results.min(MAX_RESULTS);
}

/// Changes an observer's node ID and moves it to its sorted place
/// (libtorrent `observer::set_id` and `resort_result`).
pub fn set_id<T: Traversal + ?Sized>(
    t: &mut T,
    ctx: &mut NodeCtx<'_>,
    oid: ObserverId,
    id: NodeId,
) {
    let o = obs_mut(ctx, oid);
    if o.id == id {
        return;
    }
    o.id = id;
    resort_result(t, ctx, oid);
}

/// Removes `oid` from the result list and re-inserts it in distance order
/// (libtorrent `resort_result`). Does nothing if it is not in the list.
pub fn resort_result<T: Traversal + ?Sized>(t: &mut T, ctx: &mut NodeCtx<'_>, oid: ObserverId) {
    let a = t.algo_mut();
    let Some(from) = a.results.iter().position(|r| *r == oid) else {
        return;
    };
    if from < a.sorted_results {
        a.sorted_results -= 1;
    }
    a.results.remove(from);
    let a = t.algo();
    let id = obs(ctx, oid).id;
    let target = a.target;
    let pos = a.results[..a.sorted_results]
        .partition_point(|r| compare_ref(&obs(ctx, *r).id, &id, &target));
    let a = t.algo_mut();
    a.results.insert(pos, oid);
    a.sorted_results += 1;
}

/// Learns of a node from another node's response: tells the routing table
/// and adds it to the search (libtorrent `traverse`).
pub fn traverse<T: Traversal + ?Sized>(
    t: &mut T,
    ctx: &mut NodeCtx<'_>,
    id: NodeId,
    addr: SocketAddr,
) {
    if t.algo().done || ctx.filtered(addr) {
        return;
    }
    // let the routing table know this node may exist
    let now = ctx.now;
    ctx.table.heard_about(id, addr, now);
    add_entry(t, ctx, id, addr, ObserverFlags::EMPTY);
}

/// Seeds the list with the configured router nodes, for when the table
/// gave too few (libtorrent `add_router_entries`). Routers are trusted
/// bootstrap points, so the IP filter does not apply to them.
pub fn add_router_entries<T: Traversal + ?Sized>(t: &mut T, ctx: &mut NodeCtx<'_>) {
    for ep in ctx.table.router_nodes() {
        add_entry(t, ctx, NodeId::MIN, ep, ObserverFlags::INITIAL);
    }
}

/// Begins the lookup (libtorrent `traversal_algorithm::start`): falls back
/// to the routers when there are fewer than three candidates, takes the
/// branch factor from the settings, and sends the first requests.
pub fn base_start<T: Traversal + ?Sized>(t: &mut T, ctx: &mut NodeCtx<'_>) {
    if t.algo().results.len() < 3 {
        add_router_entries(t, ctx);
    }
    init(t, ctx);
    if add_requests(t, ctx) {
        t.done(ctx);
    }
}

/// Takes the branch factor from the settings (libtorrent `init`).
pub fn init<T: Traversal + ?Sized>(t: &mut T, ctx: &NodeCtx<'_>) {
    let a = t.algo_mut();
    a.branch_factor = ctx.settings.search_branching;
    a.initialized = true;
}

/// Sends requests until the branch factor is met or the lookup has what it
/// came for. Returns `true` if the lookup is finished (libtorrent
/// `add_requests`).
///
/// A lookup is finished when `k` nodes have answered and nothing is left in
/// flight at the top of the list, or when nothing is in flight at all (even
/// if fewer than `k` answered, there is nobody left to ask).
pub fn add_requests<T: Traversal + ?Sized>(t: &mut T, ctx: &mut NodeCtx<'_>) -> bool {
    if t.algo().done {
        return true;
    }
    let mut results_target = i32::try_from(ctx.table.bucket_size()).unwrap_or(i32::MAX);
    // requests in flight among the top of the list; invoke_count also
    // counts old ones waiting on nodes far behind the current point
    let mut outstanding = 0;
    let aggressive = ctx.settings.aggressive_lookups;
    let mut i = 0;
    while i < t.algo().results.len() && results_target > 0 {
        let a = t.algo();
        let below_limit = if aggressive {
            outstanding < a.branch_factor
        } else {
            a.invoke_count < a.branch_factor
        };
        if !below_limit {
            break;
        }
        let oid = a.results[i];
        i += 1;
        let f = obs(ctx, oid).flags;
        if f.contains(ObserverFlags::ALIVE) {
            debug_assert!(f.contains(ObserverFlags::QUERIED));
            results_target -= 1;
            continue;
        }
        if f.contains(ObserverFlags::QUERIED) {
            // queried, not alive: in flight unless it failed
            if !f.contains(ObserverFlags::FAILED) {
                outstanding += 1;
            }
            continue;
        }
        // shutting down: issue no more requests
        if t.algo().abort {
            continue;
        }
        obs_mut(ctx, oid).flags |= ObserverFlags::QUERIED;
        if t.invoke(ctx, oid) {
            t.algo_mut().invoke_count += 1;
            outstanding += 1;
        } else {
            obs_mut(ctx, oid).flags |= ObserverFlags::FAILED;
        }
    }
    (results_target == 0 && outstanding == 0) || t.algo().invoke_count == 0
}

/// The base completion (libtorrent `traversal_algorithm::done`): marks the
/// lookup done, cancels what is still in flight and empties the result list.
pub fn base_done<T: Traversal + ?Sized>(t: &mut T, ctx: &mut NodeCtx<'_>) {
    debug_assert!(!t.algo().done, "done() must run once");
    t.algo_mut().done = true;
    let results = std::mem::take(&mut t.algo_mut().results);
    for oid in results {
        let f = obs(ctx, oid).flags;
        let outstanding_short = f
            & (ObserverFlags::QUERIED
                | ObserverFlags::ALIVE
                | ObserverFlags::DONE
                | ObserverFlags::FAILED
                | ObserverFlags::SHORT_TIMEOUT)
            == ObserverFlags::QUERIED | ObserverFlags::SHORT_TIMEOUT;
        if outstanding_short {
            let a = t.algo_mut();
            debug_assert!(a.branch_factor > 0);
            a.branch_factor -= 1;
        }
        if f & (ObserverFlags::QUERIED | ObserverFlags::FAILED) == ObserverFlags::QUERIED {
            // Flag in-flight requests done so that a late reply or timeout
            // does not call back into a finished lookup.
            obs_mut(ctx, oid).flags |= ObserverFlags::DONE;
        }
        ctx.rpc.observers.release(oid);
    }
    let a = t.algo_mut();
    a.sorted_results = 0;
    a.invoke_count = 0;
}

/// A request got its response: restores a raised branch factor, counts the
/// response, and keeps the lookup going (libtorrent `finished`).
pub fn finished<T: Traversal + ?Sized>(t: &mut T, ctx: &mut NodeCtx<'_>, oid: ObserverId) {
    let o = obs_mut(ctx, oid);
    let had_short_timeout = o.flags.contains(ObserverFlags::SHORT_TIMEOUT);
    debug_assert!(
        o.flags & (ObserverFlags::QUERIED | ObserverFlags::ALIVE | ObserverFlags::FAILED)
            == ObserverFlags::QUERIED
    );
    o.flags |= ObserverFlags::ALIVE;
    let a = t.algo_mut();
    // We raised the branch factor when the short timeout fired; give it back.
    if had_short_timeout {
        debug_assert!(a.branch_factor > 0);
        a.branch_factor -= 1;
    }
    a.responses += 1;
    debug_assert!(a.invoke_count > 0);
    a.invoke_count -= 1;
    if add_requests(t, ctx) {
        t.done(ctx);
    }
}

/// A request failed, or (`short`) has not been answered for a while
/// (libtorrent `failed`).
///
/// Always tells the routing table about the failure, unless the node's ID is
/// our own placeholder. A short timeout opens a slot (branch factor + 1) but
/// keeps the request alive; a full failure counts it as a timeout, frees
/// its slot and restores the branch factor if a short timeout had raised it.
pub fn failed<T: Traversal + ?Sized>(
    t: &mut T,
    ctx: &mut NodeCtx<'_>,
    oid: ObserverId,
    short: bool,
) {
    let (id, ep, f) = {
        let o = obs(ctx, oid);
        (o.id, o.target, o.flags)
    };
    // Do not report IDs we made up ourselves.
    if !f.contains(ObserverFlags::NO_ID) {
        ctx.table.node_failed(id, ep);
    }
    if t.algo().results.is_empty() {
        // An observer that is not in a result list (a sample or direct
        // request, or one cancelled by a finished lookup) still has to
        // remember its short timeout, or `rpc_manager::tick` reports it
        // again every second. libtorrent returns here without setting the
        // flag (traversal_algorithm.cpp, `failed`): see PORTING.md.
        if short {
            obs_mut(ctx, oid).flags |= ObserverFlags::SHORT_TIMEOUT;
        }
        return;
    }
    debug_assert!(f.contains(ObserverFlags::QUERIED));
    let mut restore_branch_factor = false;
    if short {
        // Probably no response is coming, but keep the handler in case one
        // does, and open the slot by raising the branch factor.
        let a = t.algo_mut();
        if !f.contains(ObserverFlags::SHORT_TIMEOUT) && a.branch_factor < i32::from(i8::MAX) {
            a.branch_factor += 1;
            obs_mut(ctx, oid).flags |= ObserverFlags::SHORT_TIMEOUT;
        }
    } else {
        obs_mut(ctx, oid).flags |= ObserverFlags::FAILED;
        restore_branch_factor = f.contains(ObserverFlags::SHORT_TIMEOUT);
        let a = t.algo_mut();
        a.timeouts += 1;
        debug_assert!(a.invoke_count > 0);
        a.invoke_count -= 1;
    }
    if restore_branch_factor {
        let a = t.algo_mut();
        debug_assert!(a.branch_factor > 1);
        a.branch_factor = (a.branch_factor - 1).max(1);
    }
    if add_requests(t, ctx) {
        t.done(ctx);
    }
}

/// `observer::timeout()`: the request failed. Does nothing if it is
/// already done.
pub fn observer_timeout<T: Traversal + ?Sized>(t: &mut T, ctx: &mut NodeCtx<'_>, oid: ObserverId) {
    let o = obs_mut(ctx, oid);
    if o.flags.contains(ObserverFlags::DONE) {
        return;
    }
    o.flags |= ObserverFlags::DONE;
    failed(t, ctx, oid, false);
}

/// `observer::abort()`: the node is shutting down. Marks the request done,
/// stops its lookup from issuing more requests and counts the request as
/// failed. Does nothing if it is already done.
pub fn observer_abort<T: Traversal + ?Sized>(t: &mut T, ctx: &mut NodeCtx<'_>, oid: ObserverId) {
    let o = obs_mut(ctx, oid);
    if o.flags.contains(ObserverFlags::DONE) {
        return;
    }
    o.flags |= ObserverFlags::DONE;
    t.algo_mut().abort();
    failed(t, ctx, oid, false);
}

/// `observer::short_timeout()`: no answer after the short timeout. Does
/// nothing if one was already reported.
pub fn observer_short_timeout<T: Traversal + ?Sized>(
    t: &mut T,
    ctx: &mut NodeCtx<'_>,
    oid: ObserverId,
) {
    if obs(ctx, oid).has_short_timeout() {
        return;
    }
    failed(t, ctx, oid, true);
}

/// `observer::done()`: the request got a full answer. Does nothing if it is
/// already done.
pub fn observer_done<T: Traversal + ?Sized>(t: &mut T, ctx: &mut NodeCtx<'_>, oid: ObserverId) {
    let o = obs_mut(ctx, oid);
    if o.flags.contains(ObserverFlags::DONE) {
        return;
    }
    o.flags |= ObserverFlags::DONE;
    finished(t, ctx, oid);
}

/// The compact nodes under `nodes` (or `nodes6`) in a response dictionary
/// (libtorrent `look_for_nodes`). Trailing bytes that do not make a whole
/// node are ignored, as is a missing or non-string entry.
///
/// Borrows only the response, so callers can feed the nodes straight into
/// [`traverse`] without collecting them first.
pub fn look_for_nodes<'a>(
    protocol: Protocol,
    r: &Node<'a>,
) -> impl Iterator<Item = NodeEndpoint> + 'a {
    r.dict_find_string(protocol.nodes_key().as_bytes())
        .map(Node::string_value)
        .unwrap_or_default()
        .chunks_exact(protocol.node_len())
        .filter_map(move |c| read_node_endpoint(protocol, c))
}

/// `traversal_observer::reply`: reads `nodes`/`nodes6` from the response and
/// keeps traversing, then adopts the node's ID.
///
/// An absent `r` dictionary or an `id` that is not 20 bytes counts as a
/// timeout. Note the order: the nodes are used *before* the ID is checked,
/// as in libtorrent.
pub fn traversal_observer_reply<T: Traversal + ?Sized>(
    t: &mut T,
    ctx: &mut NodeCtx<'_>,
    oid: ObserverId,
    msg: &Node<'_>,
) {
    let Some(r) = msg.dict_find_dict(b"r") else {
        observer_timeout(t, ctx, oid);
        return;
    };
    for n in look_for_nodes(ctx.protocol, r) {
        traverse(t, ctx, n.id, n.ep);
    }
    let Some(id) = r
        .dict_find_string(b"id")
        .and_then(|n| NodeId::from_slice(n.string_value()))
    else {
        observer_timeout(t, ctx, oid);
        return;
    };
    // we may not have known the ID when we sent the request (a bootstrap node)
    set_id(t, ctx, oid, id);
}

/// A lookup with no behaviour of its own: libtorrent's bare
/// `traversal_algorithm`, whose observers are `null_observer`s.
///
/// libtorrent uses it as a dummy owner in tests and for fire-and-forget
/// requests; here it exists mainly for the same tests
/// (`unsorted_traversal_results`).
#[derive(Debug)]
pub struct Plain {
    algo: Algorithm,
}

impl Plain {
    /// A plain traversal for `target`.
    #[must_use]
    pub fn new(ctx: &mut NodeCtx<'_>, target: NodeId) -> Self {
        Self {
            algo: Algorithm::new(ctx.new_traversal_id(), target),
        }
    }
}

impl Traversal for Plain {
    fn name(&self) -> &'static str {
        "traversal_algorithm"
    }

    fn algo(&self) -> &Algorithm {
        &self.algo
    }

    fn algo_mut(&mut self) -> &mut Algorithm {
        &mut self.algo
    }

    fn new_observer(&self) -> ObserverKind {
        ObserverKind::Null
    }
}
