//! The DHT node: one routing table, one address family, the query handlers
//! and the glue to the traversals.
//!
//! Ports libtorrent RC_2_1 `include/libtorrent/kademlia/node.hpp` and
//! `src/kademlia/node.cpp` (commit `86d573f2631b0162d3cca5e257217eaf530fdcba`,
//! BSD-3-Clause, Copyright Arvid Norberg and contributors).
//!
//! # What a [`Node`] is
//!
//! A node serves one address family (libtorrent creates one `node` per
//! listen socket): it owns the routing table ([`crate::routing_table`]), the
//! transaction table ([`crate::rpc_manager`]), the arena of running lookups
//! ([`crate::traversal`]) and the write-token secrets
//! ([`tokens::WriteTokens`]). It never reads a clock, never draws random
//! numbers on its own and never touches a socket: every call receives a
//! [`NodeEnv`] carrying the time, the [`Transport`], the [`Rng`], the shared
//! storage and the queue of [`Event`]s, which is the sans-IO seam described
//! in `docs/ARCHITECTURE.md`.
//!
//! # Driving a node
//!
//! 1. Feed every datagram to [`Node::incoming`] (the tracker does the
//!    cheap pre-filtering and the decode; see [`crate::tracker`]).
//! 2. Call [`Node::connection_timeout`] when the delay it returned last time
//!    has elapsed (request timeouts, storage expiry) and [`Node::tick`]
//!    every five seconds (routing-table refresh).
//! 3. Call [`Node::new_write_key`] every five minutes.
//! 4. Drain `env.events` after every call.
//!
//! # Submodules
//!
//! * [`query`]: building the answer to an incoming query.
//! * [`tokens`]: write tokens.
//! * [`counters`]: message counters.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::announce_flags::AnnounceFlags;
use crate::bencode::Entry;
use crate::ctx::{IpFilter, NodeCtx};
use crate::events::Event;
use crate::msg::Msg;
use crate::net::Protocol;
use crate::node::counters::NodeCounters;
use crate::node::query::{handle_query, ForeignTables, QueryEnv, RequestHook};
use crate::node::tokens::WriteTokens;
use crate::node_id::{
    distance_exp, generate_id, generate_prefix_mask, generate_random_id, verify_id, IdSecret,
    NodeId,
};
use crate::observer::ObserverKind;
use crate::rng::Rng;
use crate::routing_table::{BucketStatus, RoutingTable};
use crate::settings::DhtSettings;
use crate::storage::DhtStorage;
use crate::time::Time;
use crate::transport::Transport;
use crate::traversal::direct_request::direct_request;
use crate::traversal::get_item::{get_immutable, get_mutable};
use crate::traversal::get_peers::{announce, get_peers};
use crate::traversal::put_data::{put_immutable, put_mutable, DataCallback};
use crate::traversal::refresh::{bootstrap, refresh};
use crate::traversal::sample_infohashes::sample_infohashes;
use crate::traversal::{LookupStatus, Traversals};
use crate::types::PublicKey;

pub mod counters;
pub mod query;
pub mod tokens;

/// How often a node refreshes its own ID neighbourhood when its table is
/// shallow (the `minutes(10)` in `node::tick`).
pub const SELF_REFRESH_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// A table shallower than this many buckets is expanded by bootstrapping
/// towards our own ID (the `m_table.depth() < 4` in `node::tick`).
pub const MIN_TABLE_DEPTH: usize = 4;

/// How often the node ticks its storage (the `minutes(2)` in
/// `node::connection_timeout`).
pub const STORAGE_TICK_INTERVAL: Duration = Duration::from_secs(2 * 60);

/// What a call into a [`Node`] may use besides the node itself: everything
/// the node needs from the outside world, borrowed for the duration of one
/// call.
///
/// libtorrent keeps most of these as members (`m_sock_man`, `m_observer`,
/// `m_storage`, `m_counters`, the clock, the RNG); making them arguments is
/// what keeps the node deterministic.
pub struct NodeEnv<'a> {
    /// The current time.
    pub now: Time,
    /// Where datagrams go, and the upload quota (libtorrent `socket_manager`).
    pub transport: &'a mut dyn Transport,
    /// The random source.
    pub rng: &'a mut dyn Rng,
    /// BEP 5/33/44/51 storage. Nodes of one tracker share it.
    pub storage: &'a mut dyn DhtStorage,
    /// Notifications and lookup results for the owner.
    pub events: &'a mut Vec<Event>,
    /// The other family's tables, for BEP 32 `want`.
    pub foreign: &'a dyn ForeignTables,
    /// The optional `on_dht_request` hook.
    pub hook: Option<&'a mut RequestHook<'a>>,
    /// The embedder's IP filter: returns `true` for blocked addresses.
    /// When present it is applied to nodes the node is told to add and to
    /// the candidates of every lookup (libtorrent `apply_filter_to_dht`).
    pub ip_filter: Option<IpFilter<'a>>,
}

/// A snapshot of a node for diagnostics (libtorrent `dht_status`).
#[derive(Debug, Clone, PartialEq)]
pub struct DhtStatus {
    /// The node's current ID.
    pub our_id: NodeId,
    /// The address family served.
    pub protocol: Protocol,
    /// The population of every bucket (`dht_routing_bucket` data).
    pub table: Vec<BucketStatus>,
    /// The running lookups (`dht_lookup` data).
    pub requests: Vec<LookupStatus>,
}

/// One Kademlia node (libtorrent `dht::node`).
///
/// See the [module documentation](self) for how to drive it.
pub struct Node {
    id: NodeId,
    protocol: Protocol,
    settings: DhtSettings,
    table: RoutingTable,
    rpc: crate::rpc_manager::RpcManager,
    traversals: Traversals,
    tokens: WriteTokens,
    id_secret: IdSecret,
    counters: NodeCounters,
    /// Last time storage was ticked (`m_last_tracker_tick`).
    last_storage_tick: Time,
    /// Last bootstrap or refresh of our own ID (`m_last_self_refresh`).
    last_self_refresh: Time,
}

/// Chooses the ID a new node starts with (libtorrent
/// `calculate_node_id`).
///
/// Without a known external address the stored ID is kept (or a random one
/// is made): deriving an ID from `0.0.0.0` would be worse than random. With
/// one, a stored ID is kept only if it is a valid BEP 42 ID for it.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::node::calculate_node_id;
/// use cloudllm_dht::node_id::verify_id;
/// use cloudllm_dht::rng::TestRng;
/// use cloudllm_dht::Sha1Hash;
///
/// let mut rng = TestRng::new(1);
/// let ip = "124.31.75.21".parse().unwrap();
/// let id = calculate_node_id(Sha1Hash::MIN, Some(ip), &mut rng);
/// assert!(verify_id(&id, ip));
/// // a valid stored ID survives
/// assert_eq!(calculate_node_id(id, Some(ip), &mut rng), id);
/// ```
#[must_use]
pub fn calculate_node_id(nid: NodeId, external: Option<IpAddr>, rng: &mut dyn Rng) -> NodeId {
    let unset = nid == NodeId::MIN;
    match external.filter(|ip| !ip.is_unspecified()) {
        None if unset => generate_random_id(rng),
        None => nid,
        Some(ip) if unset || !verify_id(&nid, ip) => generate_id(ip, rng),
        Some(_) => nid,
    }
}

impl Node {
    /// Creates a node of address family `protocol` (libtorrent `node`
    /// constructor).
    ///
    /// `nid` is the ID restored from saved state ([`NodeId::MIN`] for
    /// none) and `external` the externally visible address if known; see
    /// [`calculate_node_id`]. The bucket size is 8 like libtorrent's.
    #[must_use]
    pub fn new(
        protocol: Protocol,
        settings: DhtSettings,
        nid: NodeId,
        external: Option<IpAddr>,
        rng: &mut dyn Rng,
    ) -> Self {
        let id = calculate_node_id(nid, external, rng);
        Self {
            id,
            protocol,
            table: RoutingTable::new(id, protocol, 8, &settings),
            rpc: crate::rpc_manager::RpcManager::new(id),
            traversals: Traversals::new(),
            tokens: WriteTokens::new(rng),
            id_secret: IdSecret::new(rng),
            counters: NodeCounters::default(),
            settings,
            last_storage_tick: Time::ZERO,
            last_self_refresh: Time::ZERO,
        }
    }

    /// This node's ID (`node::nid`).
    #[must_use]
    pub fn nid(&self) -> NodeId {
        self.id
    }

    /// The address family served (`node::protocol`).
    #[must_use]
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// The settings in force.
    #[must_use]
    pub fn settings(&self) -> &DhtSettings {
        &self.settings
    }

    /// Replaces the settings (libtorrent re-reads its session settings on
    /// every use; here the owner pushes them).
    pub fn set_settings(&mut self, settings: DhtSettings) {
        self.table.set_settings(&settings);
        self.settings = settings;
    }

    /// The routing table (libtorrent `m_table`).
    #[must_use]
    pub fn table(&self) -> &RoutingTable {
        &self.table
    }

    /// The routing table, mutably, for tests and for seeding it from saved
    /// state.
    pub fn table_mut(&mut self) -> &mut RoutingTable {
        &mut self.table
    }

    /// The transaction table (libtorrent `m_rpc`).
    #[must_use]
    pub fn rpc(&self) -> &crate::rpc_manager::RpcManager {
        &self.rpc
    }

    /// The write-token secrets, so a test can mint or check tokens.
    #[must_use]
    pub fn tokens(&self) -> &WriteTokens {
        &self.tokens
    }

    /// Message counters.
    #[must_use]
    pub fn counters(&self) -> &NodeCounters {
        &self.counters
    }

    /// `(nodes, replacements, confirmed)` in the table (`node::size`).
    #[must_use]
    pub fn size(&self) -> (usize, usize, usize) {
        self.table.size()
    }

    /// The estimated number of nodes in the whole DHT
    /// (`node::num_global_nodes`).
    #[must_use]
    pub fn num_global_nodes(&self) -> u64 {
        self.table.num_global_nodes()
    }

    /// Number of live lookups, including finished ones that still have
    /// requests in flight.
    #[must_use]
    pub fn num_lookups(&self) -> usize {
        self.traversals.len()
    }

    /// `true` if `addr` belongs to this node's family (`native_address`).
    #[must_use]
    pub fn native_address(&self, addr: IpAddr) -> bool {
        Protocol::of(&addr) == self.protocol
    }

    /// The search branching factor (`node::branch_factor`).
    #[must_use]
    pub fn branch_factor(&self) -> i32 {
        self.settings.search_branching
    }

    /// Builds the [`NodeCtx`] the traversals need and runs `f` with it and
    /// the arena, then performs the pings the traversals queued.
    fn with_ctx<R>(
        &mut self,
        env: &mut NodeEnv<'_>,
        f: impl FnOnce(&mut NodeCtx<'_>, &mut Traversals) -> R,
    ) -> R {
        let Self {
            id,
            protocol,
            settings,
            table,
            rpc,
            traversals,
            id_secret,
            ..
        } = self;
        let mut ctx = NodeCtx::new(
            env.now,
            *id,
            *protocol,
            settings,
            table,
            rpc,
            &mut *env.transport,
            &mut *env.rng,
            &mut *env.events,
            *id_secret,
        );
        if let Some(filter) = env.ip_filter {
            ctx = ctx.with_ip_filter(filter);
        }
        let result = f(&mut ctx, traversals);
        let pings = ctx.take_pings();
        drop(ctx);
        for ep in pings {
            self.add_node(env, ep);
        }
        result
    }

    /// Re-derives the ID from the externally visible address if the
    /// current one is not valid for it (libtorrent `node::update_node_id`).
    ///
    /// Returns `true` when the ID changed (the owner then tells the storage
    /// via `update_node_ids`). The table is rebuilt around the new ID and
    /// outgoing queries carry it.
    pub fn update_node_id(&mut self, env: &mut NodeEnv<'_>, external: IpAddr) -> bool {
        if verify_id(&self.id, external) {
            return false;
        }
        self.id = generate_id(external, &mut *env.rng);
        self.table.set_id(self.id, env.now);
        self.rpc.update_node_id(self.id);
        true
    }

    /// Generates a new write-token secret and demotes the old one
    /// (`node::new_write_key`). The tracker calls this every five minutes.
    pub fn new_write_key(&mut self, rng: &mut dyn Rng) {
        self.tokens.rotate(rng);
    }

    /// Handles one decoded datagram (libtorrent `node::incoming`).
    ///
    /// `own_socket` says whether the datagram arrived on the socket this
    /// node is bound to: a tracker offers every datagram to every node.
    /// Responses and errors are matched against outstanding requests by any
    /// node; queries are answered only by the node that owns the socket,
    /// and only when it is not read-only (BEP 43) and the transport has
    /// upload quota left. A message without a one-byte `y` is dropped
    /// silently so the node cannot be used as an amplifier.
    pub fn incoming(&mut self, env: &mut NodeEnv<'_>, m: &Msg<'_, '_>, own_socket: bool) {
        let Some(y) = m
            .message
            .dict_find_string(b"y")
            .filter(|n| n.string_length() == 1)
        else {
            return;
        };
        if own_socket {
            report_external_address(env, m);
        }
        match y.string_value()[0] {
            b'r' | b'e' => self.incoming_reply(env, m),
            b'q' if !self.settings.read_only && own_socket => self.incoming_query(env, m),
            _ => {}
        }
    }

    fn incoming_reply(&mut self, env: &mut NodeEnv<'_>, m: &Msg<'_, '_>) {
        self.with_ctx(env, |ctx, traversals| {
            traversals.incoming(ctx, m.addr, m.message);
        });
    }

    fn incoming_query(&mut self, env: &mut NodeEnv<'_>, m: &Msg<'_, '_>) {
        if !env.transport.has_quota() {
            self.counters.messages_in_dropped += 1;
            return;
        }
        let response: Entry = {
            let mut qenv = QueryEnv {
                now: env.now,
                settings: &self.settings,
                id: self.id,
                protocol: self.protocol,
                table: &mut self.table,
                storage: &mut *env.storage,
                tokens: &self.tokens,
                foreign: env.foreign,
                counters: &mut self.counters,
                events: &mut *env.events,
                hook: env
                    .hook
                    .as_deref_mut()
                    .map(|h| -> &mut RequestHook<'_> { h }),
            };
            handle_query(&mut qenv, m)
        };
        env.transport.send_packet(&response, m.addr);
    }

    /// Tells the node an ICMP port-unreachable arrived from `ep`
    /// (`node::unreachable`): the first request to it fails at once.
    pub fn unreachable(&mut self, env: &mut NodeEnv<'_>, ep: SocketAddr) {
        self.with_ctx(env, |ctx, traversals| traversals.unreachable(ctx, ep));
    }

    /// Times out requests and ticks the storage when due (libtorrent
    /// `node::connection_timeout`). Returns when to call it again.
    pub fn connection_timeout(&mut self, env: &mut NodeEnv<'_>) -> Duration {
        let next = self.with_ctx(env, |ctx, traversals| traversals.tick(ctx));
        if env.now - STORAGE_TICK_INTERVAL < self.last_storage_tick {
            return next;
        }
        self.last_storage_tick = env.now;
        env.storage.tick(env.now);
        next
    }

    /// Housekeeping every few seconds (libtorrent `node::tick`): re-bootstrap
    /// towards our own ID when the table is shallow, otherwise refresh the
    /// stalest bucket by pinging one of its nodes.
    pub fn tick(&mut self, env: &mut NodeEnv<'_>) {
        if self.last_self_refresh + SELF_REFRESH_INTERVAL < env.now
            && self.table.depth() < MIN_TABLE_DEPTH
        {
            self.refresh_self(env);
            return;
        }
        let Some((ne, _)) = self.table.next_refresh(env.now) else {
            return;
        };
        // `ne.id == self.id` cannot happen: the table never stores our ID.
        if ne.id == self.id {
            return;
        }
        let bucket = usize::try_from(159 - distance_exp(&self.id, &ne.id)).unwrap_or(0);
        self.send_single_refresh(env, ne.endpoint, bucket, ne.id);
    }

    /// A bootstrap towards a secret ID near ours, to expand the buckets
    /// close to us (the body of the first branch of `node::tick`).
    fn refresh_self(&mut self, env: &mut NodeEnv<'_>) {
        self.last_self_refresh = env.now;
        self.start_refresh(env);
    }

    /// Sends one `ping` or `get_peers` to `ep` to learn about nodes in
    /// `bucket` and to verify `id` (libtorrent `node::send_single_refresh`).
    ///
    /// A target is made inside the bucket: our ID's prefix up to the bucket
    /// and random bits after. If the bucket is already full only a `ping` is
    /// sent; otherwise a `get_peers` for the target, since the reply carries
    /// nodes either way and a peer search is the cheapest query that does.
    pub fn send_single_refresh(
        &mut self,
        env: &mut NodeEnv<'_>,
        ep: SocketAddr,
        bucket: usize,
        id: NodeId,
    ) {
        let mask = generate_prefix_mask(bucket + 1);
        let random = self.id_secret.generate_secret_id(&mut *env.rng);
        let mut target = NodeId::MIN;
        for i in 0..target.0.len() {
            target.0[i] = (random.0[i] & !mask.0[i]) | (self.id.0[i] & mask.0[i]);
        }
        let full = self.table.is_full(bucket);
        let mut e = Entry::dict();
        if full {
            e.set("q", "ping");
            self.counters.ping_out += 1;
        } else {
            e.set("q", "get_peers");
            let mut args = Entry::dict();
            args.set("info_hash", target.0);
            e.set("a", args);
            self.counters.get_peers_out += 1;
        }
        self.with_ctx(env, |ctx, _| {
            ctx.invoke_detached(ObserverKind::Ping, id, ep, e);
        });
    }

    fn start_refresh(&mut self, env: &mut NodeEnv<'_>) {
        self.with_ctx(env, |ctx, traversals| {
            let t = refresh(ctx);
            traversals.spawn(ctx, t);
        });
    }

    /// Joins the network (libtorrent `node::bootstrap`): a lookup for an ID
    /// near ours, seeded with `nodes` (saved state, configuration) minus
    /// those the IP filter blocks, falling back to the table's closest
    /// nodes and the router nodes when `nodes` is empty. `notify` makes its
    /// completion produce [`Event::BootstrapDone`].
    pub fn bootstrap(&mut self, env: &mut NodeEnv<'_>, nodes: &[SocketAddr], notify: bool) {
        self.last_self_refresh = env.now;
        self.with_ctx(env, |ctx, traversals| {
            let t = bootstrap(ctx, nodes, notify);
            traversals.spawn(ctx, t);
        });
    }

    /// Starts a `get_peers` lookup whose peers arrive as
    /// [`Event::GetPeersReply`] (libtorrent `node::get_peers` without a
    /// nodes callback).
    pub fn get_peers(&mut self, env: &mut NodeEnv<'_>, info_hash: NodeId, flags: AnnounceFlags) {
        self.with_ctx(env, |ctx, traversals| {
            let t = get_peers(ctx, info_hash, flags);
            traversals.spawn(ctx, t);
        });
    }

    /// Looks up `info_hash` and announces `listen_port` to the closest
    /// nodes that gave a write token (libtorrent `node::announce`). The
    /// caller resolves a port of 0 (libtorrent asks its observer).
    pub fn announce(
        &mut self,
        env: &mut NodeEnv<'_>,
        info_hash: NodeId,
        listen_port: u16,
        flags: AnnounceFlags,
    ) {
        self.with_ctx(env, |ctx, traversals| {
            let t = announce(ctx, info_hash, listen_port, flags);
            traversals.spawn(ctx, t);
        });
    }

    /// Looks an immutable item up by `target` (SHA-1 of its bencoded
    /// value); the result is an [`Event::GetItemDone`] (libtorrent
    /// `node::get_item(sha1_hash)`).
    pub fn get_immutable(&mut self, env: &mut NodeEnv<'_>, target: NodeId) {
        self.with_ctx(env, |ctx, traversals| {
            let t = get_immutable(ctx, target);
            traversals.spawn(ctx, t);
        });
    }

    /// Looks a mutable item up by key and salt; better versions arrive as
    /// non-authoritative [`Event::GetItemDone`]s and the final one as an
    /// authoritative one (libtorrent `node::get_item(public_key, salt)`).
    pub fn get_mutable(&mut self, env: &mut NodeEnv<'_>, pk: PublicKey, salt: &[u8]) {
        self.with_ctx(env, |ctx, traversals| {
            let t = get_mutable(ctx, pk, salt);
            traversals.spawn(ctx, t);
        });
    }

    /// Stores an immutable item: a lookup for `target` followed by a `put`
    /// to the closest nodes, ending in [`Event::PutDone`] (libtorrent
    /// `node::put_item(sha1_hash, entry)`).
    pub fn put_immutable(&mut self, env: &mut NodeEnv<'_>, target: NodeId, data: Entry) {
        self.with_ctx(env, |ctx, traversals| {
            let t = put_immutable(ctx, target, data);
            traversals.spawn(ctx, t);
        });
    }

    /// Stores a mutable item: looks it up, lets `data_cb` produce the item
    /// to store from what the network holds (sign it with `seq + 1` for a
    /// compare-and-swap), then writes it (libtorrent
    /// `node::put_item(public_key, salt, ..)`).
    pub fn put_mutable(
        &mut self,
        env: &mut NodeEnv<'_>,
        pk: PublicKey,
        salt: &[u8],
        data_cb: DataCallback,
    ) {
        self.with_ctx(env, |ctx, traversals| {
            let t = put_mutable(ctx, pk, salt, data_cb);
            traversals.spawn(ctx, t);
        });
    }

    /// Sends a BEP 51 `sample_infohashes` to `ep`; the answer is an
    /// [`Event::SampleInfohashes`] (libtorrent `node::sample_infohashes`).
    pub fn sample_infohashes(&mut self, env: &mut NodeEnv<'_>, ep: SocketAddr, target: NodeId) {
        self.counters.sample_infohashes_out += 1;
        self.with_ctx(env, |ctx, traversals| {
            let t = sample_infohashes(ctx, ep, target);
            traversals.spawn(ctx, t);
        });
    }

    /// Sends an arbitrary request to `ep`; the answer, or `None` on
    /// timeout, is an [`Event::DirectResponse`] carrying `token` (libtorrent
    /// `node::direct_request`).
    pub fn direct_request(
        &mut self,
        env: &mut NodeEnv<'_>,
        ep: SocketAddr,
        request: Entry,
        token: u64,
    ) {
        self.with_ctx(env, |ctx, traversals| {
            let t = direct_request(ctx, ep, request, token);
            traversals.spawn(ctx, t);
        });
    }

    /// Aborts every outstanding request and refuses new ones (libtorrent
    /// `~rpc_manager`); call once before dropping the node.
    pub fn shutdown(&mut self, env: &mut NodeEnv<'_>) {
        self.with_ctx(env, |ctx, traversals| traversals.shutdown(ctx));
    }

    /// Pings `ep` and adds it to the routing table if it answers
    /// (libtorrent `node::add_node`). Nodes of the other family and
    /// filtered addresses are ignored.
    pub fn add_node(&mut self, env: &mut NodeEnv<'_>, ep: SocketAddr) {
        if !self.native_address(ep.ip()) {
            return;
        }
        if env.ip_filter.is_some_and(|blocked| blocked(ep.ip())) {
            return;
        }
        let bucket = self.table.num_active_buckets();
        self.send_single_refresh(env, ep, bucket, NodeId::MIN);
    }

    /// Adds a router (bootstrap) node (`node::add_router_node`). Routers
    /// are contacted by lookups but never enter the table.
    pub fn add_router_node(&mut self, router: SocketAddr) {
        self.table.add_router_node(router);
    }

    /// A snapshot of the table and the running lookups (`node::status`).
    #[must_use]
    pub fn status(&mut self, env: &mut NodeEnv<'_>) -> DhtStatus {
        let table = self.table.status();
        let requests = self.with_ctx(env, |ctx, traversals| traversals.status(ctx));
        DhtStatus {
            our_id: self.id,
            protocol: self.protocol,
            table,
            requests,
        }
    }
}

/// Surfaces the external address a remote node claims to see us at (the
/// `ip` key of every DHT message) as an [`Event::ExternalAddress`], so the
/// owner can vote on it and eventually rebuild the node ID. Only datagrams
/// that arrived on this node's own socket count.
fn report_external_address(env: &mut NodeEnv<'_>, m: &Msg<'_, '_>) {
    let Some(ip) = m.message.dict_find_string(b"ip") else {
        return;
    };
    let bytes = ip.string_value();
    let addr = if bytes.len() >= 16 {
        <[u8; 16]>::try_from(&bytes[..16]).ok().map(IpAddr::from)
    } else if bytes.len() >= 4 {
        <[u8; 4]>::try_from(&bytes[..4]).ok().map(IpAddr::from)
    } else {
        None
    };
    if let Some(addr) = addr {
        env.events.push(Event::ExternalAddress {
            addr,
            source: m.addr.ip(),
        });
    }
}
