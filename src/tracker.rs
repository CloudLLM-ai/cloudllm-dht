//! The owner of one node per address family: sockets, timers, the upload
//! quota, flood protection and the public API.
//!
//! Ports libtorrent RC_2_1 `include/libtorrent/kademlia/dht_tracker.hpp` and
//! `src/kademlia/dht_tracker.cpp` (commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`, BSD-3-Clause, Copyright Arvid
//! Norberg and contributors).
//!
//! # What [`Dht`] is
//!
//! [`Dht`] is the sans-IO unit a consumer embeds: it owns one
//! [`Node`] per registered socket (usually one IPv4 and one IPv6), the
//! storage the nodes share, the DoS blocker and the send quota, and it
//! speaks to the outside world only through values:
//!
//! * datagrams in: [`Dht::incoming_packet`];
//! * datagrams out: [`Dht::poll_transmit`];
//! * time in: every method that needs it takes `now`; [`Dht::next_timeout`]
//!   says when to call [`Dht::poll`] next;
//! * results out: [`Dht::poll_event`].
//!
//! The tokio driver in [`crate::driver`] is a hundred lines around exactly
//! these calls; so is the in-memory network the simulation tests use.
//!
//! # Differences from libtorrent
//!
//! * libtorrent's tracker is driven by asio deadline timers and a `send_fun`
//!   callback; here the owner drives timers via [`Dht::poll`] and collects
//!   datagrams from a queue.
//! * `listen_socket_handle` is [`SocketId`], an opaque number the owner
//!   chooses the meaning of.
//! * The `dht_observer` hooks are [`Event`]s plus [`Dht::set_ip_filter`] and
//!   [`Dht::set_request_hook`].
//! * `dht_tracker::state()` puts IPv6 nodes in `DhtState::nodes6`; libtorrent
//!   puts every node in `nodes` and its serialiser splits them again.
//! * Every outgoing message carries a `v` client tag; libtorrent's is
//!   `LT` plus its version, ours is [`CLIENT_VERSION`].

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::announce_flags::AnnounceFlags;
use crate::bencode::{decode_with_limits, Entry, NodeKind};
use crate::dht_state::DhtState;
use crate::dos_blocker::DosBlocker;
use crate::events::Event;
use crate::msg::Msg;
use crate::net::Protocol;
use crate::node::counters::NodeCounters;
use crate::node::query::{ForeignTables, RequestHook};
use crate::node::{DhtStatus, Node, NodeEnv};
use crate::node_entry::NodeEntry;
use crate::node_id::NodeId;
use crate::rng::{Rng, SystemRng};
use crate::routing_table::{FindNodeOptions, RoutingTable};
use crate::settings::DhtSettings;
use crate::storage::{DefaultStorage, DhtStorage};
use crate::time::Time;
use crate::transport::Transport;

pub mod prefilter;
pub mod quota;

use prefilter::{is_dark_internet, plausible_dht_datagram};
use quota::SendQuota;

/// How often the write-token secrets rotate (`key_refresh` in
/// `dht_tracker.cpp`).
pub const KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// How often every node's housekeeping tick runs (`refresh_timeout`).
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Delay before a node's first connection timeout after start.
pub const FIRST_CONNECTION_TIMEOUT: Duration = Duration::from_secs(1);

/// The `v` value stamped on every outgoing message: two letters naming this
/// library and two bytes of version (`0.1`). libtorrent stamps `LT` and its
/// own version the same way (BEP 5 leaves `v` to the client).
pub const CLIENT_VERSION: [u8; 4] = [b'C', b'D', 0, 1];

/// Bencode depth limit for incoming datagrams (the `10` passed to `bdecode`
/// in `incoming_packet`).
pub const DECODE_DEPTH_LIMIT: usize = 10;

/// Token limit for incoming datagrams (the `500` passed to `bdecode`).
pub const DECODE_TOKEN_LIMIT: i64 = 500;

/// Identifies one UDP socket the embedder has bound and registered with
/// [`Dht::add_socket`] (libtorrent `listen_socket_handle`). The tracker never
/// interprets the number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketId(pub u32);

/// A datagram the embedder must send (what libtorrent's `send_fun_t`
/// receives).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// The socket to send it from.
    pub socket: SocketId,
    /// The destination.
    pub to: SocketAddr,
    /// The bencoded message.
    pub payload: Vec<u8>,
}

/// What went wrong sending to or receiving from an endpoint, as reported by
/// the embedder to [`Dht::socket_error`] (libtorrent `incoming_error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketErrorKind {
    /// ICMP port unreachable / `ECONNREFUSED`: nobody listens there.
    ConnectionRefused,
    /// `ECONNRESET`.
    ConnectionReset,
    /// `ECONNABORTED`.
    ConnectionAborted,
    /// Anything else; ignored.
    Other,
}

impl SocketErrorKind {
    /// `true` for the errors that mean the peer is unreachable, which make
    /// libtorrent fail the first outstanding request to that endpoint.
    #[must_use]
    pub fn is_unreachable(self) -> bool {
        !matches!(self, Self::Other)
    }
}

/// Traffic counters of the tracker (the `counters::dht_*` that
/// `dht_tracker.cpp` increments; per-node counters are
/// [`NodeCounters`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrackerCounters {
    /// `dht_bytes_in`.
    pub bytes_in: u64,
    /// `dht_bytes_out`.
    pub bytes_out: u64,
    /// `dht_messages_in`.
    pub messages_in: u64,
    /// `dht_messages_out`.
    pub messages_out: u64,
    /// `dht_messages_in_dropped`: dropped by the dark-internet filter, the
    /// IP filter, the DoS blocker or because they did not parse.
    pub messages_in_dropped: u64,
    /// `dht_messages_out_dropped`: no socket for the destination's family.
    pub messages_out_dropped: u64,
}

/// A registered socket.
#[derive(Debug, Clone, Copy)]
struct SocketInfo {
    id: SocketId,
    local: SocketAddr,
    protocol: Protocol,
}

/// One node of the tracker with its timer (libtorrent `tracker_node`).
struct Slot {
    socket: SocketId,
    local: SocketAddr,
    /// `None` only while the node is taken out for a call.
    node: Option<Node>,
    /// When the node's connection timeout is next due.
    next_timeout: Option<Time>,
}

/// The tracker's view of the nodes, for BEP 32 `want` lists.
struct Siblings<'a>(&'a [Slot]);

impl ForeignTables for Siblings<'_> {
    fn find_nodes(&self, family: Protocol, target: &NodeId) -> Option<Vec<NodeEntry>> {
        self.0
            .iter()
            .filter_map(|s| s.node.as_ref())
            .find(|n| n.protocol() == family)
            .map(|n| n.table().find_node(target, FindNodeOptions::NONE, 0))
    }
}

/// The [`Transport`] the nodes of a tracker send through: it stamps the
/// client version, charges the quota and queues the datagram on the socket
/// of the destination's family.
struct TrackerTransport<'a> {
    now: Time,
    limit: i32,
    quota: &'a mut SendQuota,
    outbox: &'a mut VecDeque<Datagram>,
    sockets: &'a [SocketInfo],
    own: SocketId,
    counters: &'a mut TrackerCounters,
}

impl Transport for TrackerTransport<'_> {
    fn has_quota(&mut self) -> bool {
        self.quota.has_quota(self.now, self.limit)
    }

    fn send_packet(&mut self, msg: &Entry, dst: SocketAddr) -> bool {
        let mut e = msg.clone();
        e.set("v", CLIENT_VERSION.to_vec());
        let payload = e.encode();
        // The quota is charged even if the packet is then dropped for lack
        // of a socket, as in libtorrent; it only blocks *incoming* queries.
        self.quota.charge(payload.len());

        let wanted = Protocol::of(&dst.ip());
        // The node's own socket if it is of the destination's family, else
        // any socket of that family: a v6 node bootstrapping from a v4
        // router, say.
        let socket = self
            .sockets
            .iter()
            .find(|s| s.id == self.own && s.protocol == wanted)
            .or_else(|| self.sockets.iter().find(|s| s.protocol == wanted));
        let Some(socket) = socket else {
            self.counters.messages_out_dropped += 1;
            return false;
        };
        self.counters.bytes_out += payload.len() as u64;
        self.counters.messages_out += 1;
        self.outbox.push_back(Datagram {
            socket: socket.id,
            to: dst,
            payload,
        });
        true
    }
}

/// An embedder-supplied predicate: `true` for addresses to ignore.
pub type IpFilterFn = dyn Fn(IpAddr) -> bool + Send + Sync;

/// A user hook that may answer queries itself; see
/// [`crate::node::query::RequestHook`].
pub type RequestHookFn = dyn FnMut(&str, &Msg<'_, '_>, &mut Entry) -> bool + Send;

/// Collects the parts of a [`Dht`] before it is built.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::settings::DhtSettings;
/// use cloudllm_dht::tracker::Dht;
///
/// let dht = Dht::builder(DhtSettings::default()).build();
/// assert_eq!(dht.sockets().count(), 0);
/// ```
pub struct DhtBuilder {
    settings: DhtSettings,
    state: DhtState,
    storage: Option<Box<dyn DhtStorage>>,
    rng: Option<Box<dyn Rng + Send>>,
}

impl DhtBuilder {
    /// Saved state (node IDs and bootstrap nodes) to start from; see
    /// [`Dht::state`].
    #[must_use]
    pub fn state(mut self, state: DhtState) -> Self {
        self.state = state;
        self
    }

    /// The BEP 5/44/51 storage the nodes share; defaults to
    /// [`DefaultStorage`] on the system clock.
    #[must_use]
    pub fn storage(mut self, storage: Box<dyn DhtStorage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// The random source; defaults to the operating system's. Pass a
    /// seeded [`crate::rng::TestRng`] for deterministic runs.
    #[must_use]
    pub fn rng(mut self, rng: Box<dyn Rng + Send>) -> Self {
        self.rng = Some(rng);
        self
    }

    /// Builds the tracker (libtorrent `dht_tracker` constructor). It is
    /// not running until [`Dht::start`].
    #[must_use]
    pub fn build(self) -> Dht {
        let storage = self
            .storage
            .unwrap_or_else(|| Box::new(DefaultStorage::with_system(&self.settings)));
        let mut blocker = DosBlocker::new();
        blocker.set_block_timer(self.settings.block_timeout);
        blocker.set_rate_limit(self.settings.block_ratelimit);
        Dht {
            quota: SendQuota::new(self.settings.upload_rate_limit, Time::ZERO),
            settings: self.settings,
            storage,
            state: Some(self.state),
            sockets: Vec::new(),
            nodes: Vec::new(),
            blocker,
            outbox: VecDeque::new(),
            events: VecDeque::new(),
            scratch: Vec::new(),
            rng: self.rng.unwrap_or_else(|| Box::new(SystemRng)),
            running: false,
            next_key_refresh: None,
            next_refresh: None,
            ip_filter: None,
            hook: None,
            counters: TrackerCounters::default(),
            next_socket: 0,
        }
    }
}

/// The sans-IO DHT: one node per registered socket plus everything they
/// share (libtorrent `dht_tracker`). See the [module documentation](self).
///
/// # Examples
///
/// A single IPv4 node answering a ping, without any I/O:
///
/// ```
/// use cloudllm_dht::bencode::Entry;
/// use cloudllm_dht::rng::TestRng;
/// use cloudllm_dht::settings::DhtSettings;
/// use cloudllm_dht::time::Time;
/// use cloudllm_dht::tracker::Dht;
/// use std::time::Duration;
///
/// let now = Time::ZERO + Duration::from_secs(100);
/// let mut dht = Dht::builder(DhtSettings::default())
///     .rng(Box::new(TestRng::new(1)))
///     .build();
/// let socket = dht.add_socket("10.0.0.2:6881".parse().unwrap(), None, now);
/// dht.start(now);
///
/// let mut ping = Entry::dict();
/// let mut args = Entry::dict();
/// args.set("id", [7u8; 20]);
/// ping.set("y", "q").set("q", "ping").set("t", "aa").set("a", args);
/// assert!(dht.incoming_packet(socket, "10.0.0.9:5555".parse().unwrap(), &ping.encode(), now));
///
/// let reply = dht.poll_transmit().expect("a pong");
/// assert_eq!(reply.to, "10.0.0.9:5555".parse().unwrap());
/// ```
pub struct Dht {
    settings: DhtSettings,
    storage: Box<dyn DhtStorage>,
    /// Saved state, consumed by [`Dht::start`] ("to be used only once").
    state: Option<DhtState>,
    sockets: Vec<SocketInfo>,
    nodes: Vec<Slot>,
    blocker: DosBlocker,
    quota: SendQuota,
    outbox: VecDeque<Datagram>,
    events: VecDeque<Event>,
    /// Events of the call in progress, moved to `events` afterwards.
    scratch: Vec<Event>,
    rng: Box<dyn Rng + Send>,
    running: bool,
    next_key_refresh: Option<Time>,
    next_refresh: Option<Time>,
    ip_filter: Option<Box<IpFilterFn>>,
    hook: Option<Box<RequestHookFn>>,
    counters: TrackerCounters,
    next_socket: u32,
}

impl Dht {
    /// A builder with the given settings.
    #[must_use]
    pub fn builder(settings: DhtSettings) -> DhtBuilder {
        DhtBuilder {
            settings,
            state: DhtState::default(),
            storage: None,
            rng: None,
        }
    }

    /// The settings in force.
    #[must_use]
    pub fn settings(&self) -> &DhtSettings {
        &self.settings
    }

    /// Replaces the settings and pushes them to the nodes, the storage and
    /// the DoS blocker (libtorrent re-reads its session settings on every
    /// use; `refresh_timeout` copies the blocker's).
    pub fn set_settings(&mut self, settings: DhtSettings) {
        for slot in &mut self.nodes {
            if let Some(n) = slot.node.as_mut() {
                n.set_settings(settings.clone());
            }
        }
        self.storage.set_settings(&settings);
        self.blocker.set_block_timer(settings.block_timeout);
        self.blocker.set_rate_limit(settings.block_ratelimit);
        self.settings = settings;
    }

    /// Installs the IP filter: `blocked(ip)` returns `true` for addresses
    /// whose datagrams are dropped and which are never added to a table or
    /// contacted by a lookup (libtorrent `apply_filter_to_dht` with the
    /// session's `ip_filter`).
    pub fn set_ip_filter(&mut self, blocked: Option<Box<IpFilterFn>>) {
        self.ip_filter = blocked;
    }

    /// Installs a hook that sees every query before the built-in handler
    /// and may answer it (libtorrent `dht_observer::on_dht_request`).
    pub fn set_request_hook(&mut self, hook: Option<Box<RequestHookFn>>) {
        self.hook = hook;
    }

    /// The registered sockets, in registration order.
    pub fn sockets(&self) -> impl Iterator<Item = (SocketId, SocketAddr)> + '_ {
        self.sockets.iter().map(|s| (s.id, s.local))
    }

    /// `true` between [`Dht::start`] and [`Dht::stop`].
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Traffic counters.
    #[must_use]
    pub fn counters(&self) -> &TrackerCounters {
        &self.counters
    }

    /// The sum of every node's message counters.
    #[must_use]
    pub fn node_counters(&self) -> NodeCounters {
        let mut total = NodeCounters::default();
        for n in self.nodes.iter().filter_map(|s| s.node.as_ref()) {
            total.add(n.counters());
        }
        total
    }

    /// The node serving `socket`, for inspection.
    #[must_use]
    pub fn node(&self, socket: SocketId) -> Option<&Node> {
        self.nodes
            .iter()
            .find(|s| s.socket == socket)
            .and_then(|s| s.node.as_ref())
    }

    /// The node serving `socket`, mutably: for tests and for seeding a
    /// table from outside state (libtorrent's simulations reach into
    /// `node::m_table` the same way).
    pub fn node_mut(&mut self, socket: SocketId) -> Option<&mut Node> {
        self.nodes
            .iter_mut()
            .find(|s| s.socket == socket)
            .and_then(|s| s.node.as_mut())
    }

    /// The shared storage, for inspection.
    #[must_use]
    pub fn storage(&self) -> &dyn DhtStorage {
        &*self.storage
    }

    // ------------------------------------------------------------------
    // sockets and nodes
    // ------------------------------------------------------------------

    /// Registers a socket and creates its node (libtorrent
    /// `dht_tracker::new_socket`).
    ///
    /// `local` is the bound address (its family decides the node's);
    /// `external` the externally visible address if known, which seeds the
    /// BEP 42 node ID. A node ID saved for `local`'s address in the state
    /// is reused when valid. If the tracker is running the node starts
    /// right away, bootstrapping from the routing-table seeds only.
    pub fn add_socket(
        &mut self,
        local: SocketAddr,
        external: Option<IpAddr>,
        now: Time,
    ) -> SocketId {
        let id = SocketId(self.next_socket);
        self.next_socket += 1;
        let protocol = Protocol::of(&local.ip());
        let stored = self
            .state
            .as_ref()
            .and_then(|s| s.nids.iter().find(|(ip, _)| *ip == local.ip()))
            .map_or(NodeId::MIN, |(_, nid)| *nid);
        let node = Node::new(
            protocol,
            self.settings.clone(),
            stored,
            external,
            &mut *self.rng,
        );
        self.sockets.push(SocketInfo {
            id,
            local,
            protocol,
        });
        self.nodes.push(Slot {
            socket: id,
            local,
            node: Some(node),
            next_timeout: None,
        });
        self.update_storage_node_ids();
        if self.running {
            let idx = self.nodes.len() - 1;
            self.nodes[idx].next_timeout = Some(now + FIRST_CONNECTION_TIMEOUT);
            self.with_node(idx, now, |node, env| node.bootstrap(env, &[], true));
        }
        id
    }

    /// Removes a socket and its node (libtorrent `delete_socket`).
    pub fn remove_socket(&mut self, socket: SocketId) {
        self.sockets.retain(|s| s.id != socket);
        self.nodes.retain(|s| s.socket != socket);
        self.update_storage_node_ids();
    }

    /// Re-derives the node ID of `socket`'s node from a newly learned
    /// external address (libtorrent `update_node_id`); the usual trigger
    /// is [`Event::ExternalAddress`] after the embedder's vote.
    pub fn set_external_address(&mut self, socket: SocketId, external: IpAddr, now: Time) {
        let Some(idx) = self.nodes.iter().position(|s| s.socket == socket) else {
            return;
        };
        self.with_node(idx, now, |node, env| node.update_node_id(env, external));
        self.update_storage_node_ids();
    }

    fn update_storage_node_ids(&mut self) {
        let ids: Vec<NodeId> = self
            .nodes
            .iter()
            .filter_map(|s| s.node.as_ref())
            .map(Node::nid)
            .collect();
        self.storage.update_node_ids(&ids);
    }

    /// Runs `f` on node `idx` with an environment built from the tracker's
    /// shared parts, then moves the events it produced to the queue.
    fn with_node<R>(
        &mut self,
        idx: usize,
        now: Time,
        f: impl FnOnce(&mut Node, &mut NodeEnv<'_>) -> R,
    ) -> Option<R> {
        let Self {
            settings,
            storage,
            sockets,
            nodes,
            quota,
            outbox,
            events,
            scratch,
            rng,
            ip_filter,
            hook,
            counters,
            ..
        } = self;
        let mut node = nodes.get_mut(idx)?.node.take()?;
        let own = nodes[idx].socket;
        let result = {
            let siblings = Siblings(nodes);
            let mut transport = TrackerTransport {
                now,
                limit: settings.upload_rate_limit,
                quota,
                outbox,
                sockets,
                own,
                counters,
            };
            let hook_ref = hook.as_deref_mut().map(|h| -> &mut RequestHook<'_> { h });
            let mut env = NodeEnv {
                now,
                transport: &mut transport,
                rng: &mut **rng,
                storage: &mut **storage,
                events: scratch,
                foreign: &siblings,
                hook: hook_ref,
                ip_filter: ip_filter
                    .as_deref()
                    .map(|f| -> &dyn Fn(IpAddr) -> bool { f }),
            };
            f(&mut node, &mut env)
        };
        nodes[idx].node = Some(node);
        events.extend(scratch.drain(..));
        Some(result)
    }

    // ------------------------------------------------------------------
    // lifecycle and timers
    // ------------------------------------------------------------------

    /// Starts the tracker (libtorrent `dht_tracker::start`): schedules the
    /// timers and bootstraps every node from the saved state's nodes (a v6
    /// node tries its own family's nodes first), then discards the state.
    /// Each node's bootstrap completion produces an
    /// [`Event::BootstrapDone`].
    pub fn start(&mut self, now: Time) {
        self.running = true;
        self.next_key_refresh = Some(now + KEY_REFRESH_INTERVAL);
        self.next_refresh = Some(now + REFRESH_INTERVAL);
        // libtorrent refreshes the key immediately on start
        let state = self.state.take().unwrap_or_default();
        for idx in 0..self.nodes.len() {
            self.nodes[idx].next_timeout = Some(now + FIRST_CONNECTION_TIMEOUT);
            let seeds = match self.sockets.get(idx).map(|s| s.protocol) {
                Some(Protocol::V6) => [state.nodes6.as_slice(), state.nodes.as_slice()].concat(),
                _ => [state.nodes.as_slice(), state.nodes6.as_slice()].concat(),
            };
            self.with_node(idx, now, |node, env| node.bootstrap(env, &seeds, true));
        }
    }

    /// Stops the timers (libtorrent `dht_tracker::stop`). Datagrams that
    /// arrive afterwards are still handled; queued output stays queued.
    pub fn stop(&mut self) {
        self.running = false;
        self.next_key_refresh = None;
        self.next_refresh = None;
        for slot in &mut self.nodes {
            slot.next_timeout = None;
        }
    }

    /// When [`Dht::poll`] next has work: the earliest of the key refresh,
    /// the housekeeping tick and every node's connection timeout. `None`
    /// while stopped.
    #[must_use]
    pub fn next_timeout(&self) -> Option<Time> {
        self.nodes
            .iter()
            .filter_map(|s| s.next_timeout)
            .chain(self.next_key_refresh)
            .chain(self.next_refresh)
            .min()
    }

    /// Runs every timer that is due at `now` (libtorrent's
    /// `connection_timeout`, `refresh_timeout` and `refresh_key`
    /// handlers): request timeouts and storage expiry, the five-second node
    /// tick, the five-minute write-key rotation.
    pub fn poll(&mut self, now: Time) {
        if !self.running {
            return;
        }
        if self.next_key_refresh.is_some_and(|t| t <= now) {
            self.next_key_refresh = Some(now + KEY_REFRESH_INTERVAL);
            for slot in &mut self.nodes {
                if let Some(n) = slot.node.as_mut() {
                    n.new_write_key(&mut *self.rng);
                }
            }
        }
        for idx in 0..self.nodes.len() {
            if self.nodes[idx].next_timeout.is_some_and(|t| t <= now) {
                let d = self
                    .with_node(idx, now, |node, env| node.connection_timeout(env))
                    .unwrap_or(FIRST_CONNECTION_TIMEOUT);
                self.nodes[idx].next_timeout = Some(now + d);
            }
        }
        if self.next_refresh.is_some_and(|t| t <= now) {
            self.next_refresh = Some(now + REFRESH_INTERVAL);
            for idx in 0..self.nodes.len() {
                self.with_node(idx, now, |node, env| node.tick(env));
            }
            // periodically update the DOS blocker's settings
            self.blocker.set_block_timer(self.settings.block_timeout);
            self.blocker.set_rate_limit(self.settings.block_ratelimit);
        }
    }

    // ------------------------------------------------------------------
    // datagrams
    // ------------------------------------------------------------------

    /// Handles a datagram that arrived on `socket` from `from` (libtorrent
    /// `dht_tracker::incoming_packet`).
    ///
    /// Returns `false` when the datagram does not look like a DHT message
    /// (so the embedder may offer it to another protocol sharing the
    /// socket, as libtorrent does with uTP and the tracker protocols) and
    /// `true` when it was consumed, even if dropped on purpose.
    ///
    /// The order is libtorrent's: shape (longer than 20 bytes, `d` ... `e`),
    /// dark-internet filter, IP filter, DoS blocker, bencode parse with
    /// depth 10 and 500 tokens, then every node sees the message and the
    /// one owning `socket` answers queries.
    pub fn incoming_packet(
        &mut self,
        socket: SocketId,
        from: SocketAddr,
        buf: &[u8],
        now: Time,
    ) -> bool {
        if !plausible_dht_datagram(buf) {
            return false;
        }
        self.counters.bytes_in += buf.len() as u64;
        self.counters.messages_in += 1;

        if self.settings.ignore_dark_internet && is_dark_internet(from.ip()) {
            self.counters.messages_in_dropped += 1;
            return true;
        }
        if self
            .ip_filter
            .as_deref()
            .is_some_and(|blocked| blocked(from.ip()))
        {
            self.counters.messages_in_dropped += 1;
            return true;
        }
        if !self.blocker.incoming(from.ip(), now) {
            self.counters.messages_in_dropped += 1;
            return true;
        }
        let Ok(message) = decode_with_limits(buf, DECODE_DEPTH_LIMIT, DECODE_TOKEN_LIMIT) else {
            self.counters.messages_in_dropped += 1;
            return false;
        };
        if message.kind() != NodeKind::Dict {
            // it's not a good idea to send a response to an invalid message
            self.counters.messages_in_dropped += 1;
            return false;
        }
        let m = Msg {
            message: &message,
            addr: from,
        };
        for idx in 0..self.nodes.len() {
            let own = self.nodes[idx].socket == socket;
            self.with_node(idx, now, |node, env| node.incoming(env, &m, own));
        }
        true
    }

    /// Takes the next datagram to send, oldest first.
    pub fn poll_transmit(&mut self) -> Option<Datagram> {
        self.outbox.pop_front()
    }

    /// Takes the next event, oldest first.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Takes every queued event.
    pub fn drain_events(&mut self) -> Vec<Event> {
        self.events.drain(..).collect()
    }

    /// Reports a socket error for `ep` (libtorrent `incoming_error`): an
    /// unreachable endpoint fails its first outstanding request in every
    /// node.
    pub fn socket_error(&mut self, kind: SocketErrorKind, ep: SocketAddr, now: Time) {
        if !kind.is_unreachable() {
            return;
        }
        for idx in 0..self.nodes.len() {
            self.with_node(idx, now, |node, env| node.unreachable(env, ep));
        }
    }

    // ------------------------------------------------------------------
    // operations
    // ------------------------------------------------------------------

    /// Adds a router (bootstrap) node to every table (libtorrent
    /// `add_router_node`). Routers are queried by lookups but never kept.
    pub fn add_router_node(&mut self, router: SocketAddr) {
        for slot in &mut self.nodes {
            if let Some(n) = slot.node.as_mut() {
                n.add_router_node(router);
            }
        }
    }

    /// Pings `ep` from every node of its family and adds it to the table if
    /// it answers (libtorrent `add_node`).
    pub fn add_node(&mut self, ep: SocketAddr, now: Time) {
        for idx in 0..self.nodes.len() {
            self.with_node(idx, now, |node, env| node.add_node(env, ep));
        }
    }

    /// Starts a `get_peers` lookup on every node; peers arrive as
    /// [`Event::GetPeersReply`] (libtorrent `dht_tracker::get_peers`).
    pub fn get_peers(&mut self, info_hash: NodeId, now: Time) {
        for idx in 0..self.nodes.len() {
            self.with_node(idx, now, |node, env| {
                node.get_peers(env, info_hash, AnnounceFlags::EMPTY);
            });
        }
    }

    /// Looks `info_hash` up and announces `listen_port` to the closest
    /// nodes on every node (libtorrent `dht_tracker::announce`). A
    /// `listen_port` of 0 announces each socket's own port, which is what
    /// libtorrent obtains from its observer.
    pub fn announce(
        &mut self,
        info_hash: NodeId,
        listen_port: u16,
        flags: AnnounceFlags,
        now: Time,
    ) {
        for idx in 0..self.nodes.len() {
            let port = if listen_port == 0 {
                self.nodes[idx].local.port()
            } else {
                listen_port
            };
            self.with_node(idx, now, |node, env| {
                node.announce(env, info_hash, port, flags)
            });
        }
    }

    // ------------------------------------------------------------------
    // state and status
    // ------------------------------------------------------------------

    /// The state to persist (libtorrent `dht_tracker::state`): every node's
    /// ID keyed by its *local* address (the external one is unknown after a
    /// restart behind a NAT) and the endpoints in its routing table.
    #[must_use]
    pub fn state(&self) -> DhtState {
        let mut state = DhtState::default();
        for slot in &self.nodes {
            let Some(node) = slot.node.as_ref() else {
                continue;
            };
            state.nids.push((slot.local.ip(), node.nid()));
            node.table().for_each_entry(|e| match e.endpoint {
                SocketAddr::V4(_) => state.nodes.push(e.endpoint),
                SocketAddr::V6(_) => state.nodes6.push(e.endpoint),
            });
        }
        state
    }

    /// The live routing-table entries of the node whose ID is `nid`
    /// (libtorrent `live_nodes`).
    #[must_use]
    pub fn live_nodes(&self, nid: &NodeId) -> Vec<(NodeId, SocketAddr)> {
        self.nodes
            .iter()
            .filter_map(|s| s.node.as_ref())
            .find(|n| n.nid() == *nid)
            .map(|n| {
                let table: &RoutingTable = n.table();
                let mut out = Vec::new();
                table.for_each_node(|e| out.push((e.id, e.endpoint)), |_| {});
                out
            })
            .unwrap_or_default()
    }

    /// A snapshot of every node (libtorrent `dht_status`).
    pub fn status(&mut self, now: Time) -> Vec<(SocketId, DhtStatus)> {
        let mut out = Vec::new();
        for idx in 0..self.nodes.len() {
            let socket = self.nodes[idx].socket;
            if let Some(s) = self.with_node(idx, now, |node, env| node.status(env)) {
                out.push((socket, s));
            }
        }
        out
    }
}
