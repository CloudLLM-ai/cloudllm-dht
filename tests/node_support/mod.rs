//! A node under test: what libtorrent's `dht_test_setup` and
//! `send_dht_request` wire together for `test_dht.cpp` (libtorrent RC_2_1,
//! commit `86d573f2631b0162d3cca5e257217eaf530fdcba`).
//!
//! [`Fixture`] owns one [`Node`], a [`MockSocket`], a storage, an event
//! queue, a seeded RNG and a hand-moved clock. [`Fixture::request`] builds a
//! query exactly as `send_dht_request` does, pushes it through the node's
//! `incoming` and hands back the response packet the node sent.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;

use cloudllm_dht::bencode::{decode, Node as BNode};
use cloudllm_dht::events::Event;
use cloudllm_dht::msg::Msg;
use cloudllm_dht::net::Protocol;
use cloudllm_dht::node::query::{ForeignTables, NoForeignTables, RequestHook};
use cloudllm_dht::node::{Node, NodeEnv};
use cloudllm_dht::node_entry::NodeEntry;
use cloudllm_dht::node_id::NodeId;
use cloudllm_dht::rng::TestRng;
use cloudllm_dht::routing_table::{FindNodeOptions, RoutingTable};
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::storage::{DefaultStorage, DhtStorage};
use cloudllm_dht::testing::{build_query, Encoded, MockSocket, MsgArgs};
use cloudllm_dht::time::{Clock, ManualClock, Time};
use cloudllm_dht::Sha1Hash;

/// The settings `test_dht.cpp::test_settings()` uses.
pub fn test_settings() -> DhtSettings {
    DhtSettings {
        max_torrents: 4,
        max_dht_items: 4,
        enforce_node_id: false,
        ..DhtSettings::default()
    }
}

/// A request hook as the fixture stores it.
pub type TestHook = dyn FnMut(&str, &Msg<'_, '_>, &mut cloudllm_dht::bencode::Entry) -> bool;

/// One node plus everything it needs (libtorrent `dht_test_setup`).
pub struct Fixture {
    /// The node under test.
    pub node: Node,
    /// Records every packet the node sends.
    pub sock: MockSocket,
    /// The shared storage.
    pub storage: Box<dyn DhtStorage>,
    /// Events the node produced and the test has not drained.
    pub events: Vec<Event>,
    /// The random source (seeded).
    pub rng: TestRng,
    /// The simulated time; shared with the storage.
    pub clock: ManualClock,
    /// The default sender of [`Fixture::request`].
    pub source: SocketAddr,
    /// Blocks addresses (libtorrent's `ip_filter` with `apply_filter_to_dht`).
    pub ip_filter: Option<std::sync::Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync>>,
    /// Called for every query, may take over the response.
    pub hook: Option<Box<TestHook>>,
}

impl Fixture {
    /// A node of the family of `source` with the test settings.
    pub fn new(source: SocketAddr) -> Self {
        Self::with_settings(source, test_settings())
    }

    /// A node of the family of `source` with explicit settings.
    pub fn with_settings(source: SocketAddr, settings: DhtSettings) -> Self {
        let mut rng = TestRng::new(0x5eed);
        let protocol = Protocol::of(&source.ip());
        let clock = ManualClock::new();
        clock.advance(Duration::from_secs(1000));
        let storage: Box<dyn DhtStorage> = Box::new(DefaultStorage::new(
            &settings,
            Box::new(clock.clone()),
            Box::new(TestRng::new(0x570)),
        ));
        let node = Node::new(protocol, settings, Sha1Hash::MIN, None, &mut rng);
        Self {
            node,
            sock: MockSocket::new(),
            storage,
            events: Vec::new(),
            rng,
            clock,
            source,
            hook: None,
            ip_filter: None,
        }
    }

    /// Installs a filter on the node's table and on lookups, like the
    /// tracker does.
    pub fn set_ip_filter(
        &mut self,
        blocked: Option<std::sync::Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync>>,
    ) {
        self.node.table_mut().set_ip_filter(blocked.clone());
        self.ip_filter = blocked;
    }

    /// Runs `f` with the node and an environment built from the fixture.
    pub fn with_env<R>(&mut self, f: impl FnOnce(&mut Node, &mut NodeEnv<'_>) -> R) -> R {
        self.with_env_foreign(&NoForeignTables, f)
    }

    /// [`Fixture::with_env`] with the other family's tables available.
    pub fn with_env_foreign<R>(
        &mut self,
        foreign: &dyn ForeignTables,
        f: impl FnOnce(&mut Node, &mut NodeEnv<'_>) -> R,
    ) -> R {
        let Self {
            node,
            sock,
            storage,
            events,
            rng,
            clock,
            hook,
            ip_filter,
            ..
        } = self;
        let hook_ref: Option<&mut RequestHook<'_>> = match hook {
            Some(h) => Some(&mut **h),
            None => None,
        };
        let mut env = NodeEnv {
            now: clock.now(),
            transport: sock,
            rng,
            storage: &mut **storage,
            events,
            foreign,
            hook: hook_ref,
            ip_filter: ip_filter
                .as_deref()
                .map(|f| -> &dyn Fn(std::net::IpAddr) -> bool { f }),
        };
        f(node, &mut env)
    }

    /// Delivers an already-decoded datagram to the node as if it arrived
    /// on its socket.
    pub fn deliver(&mut self, from: SocketAddr, bytes: &[u8]) {
        self.deliver_on(from, bytes, true, &NoForeignTables);
    }

    /// [`Fixture::deliver`] with control over whether the datagram arrived
    /// on the node's own socket and over the foreign tables.
    pub fn deliver_on(
        &mut self,
        from: SocketAddr,
        bytes: &[u8],
        own_socket: bool,
        foreign: &dyn ForeignTables,
    ) {
        let decoded: BNode<'_> = decode(bytes).expect("test datagram must decode");
        let m = Msg {
            message: &decoded,
            addr: from,
        };
        self.with_env_foreign(foreign, |node, env| node.incoming(env, &m, own_socket));
    }

    /// `send_dht_request`: sends query `q` with `args` from `from` (random
    /// node ID unless `args` has one) and returns the node's response, or
    /// `None` if it sent nothing to `from`.
    pub fn request_from(&mut self, q: &str, from: SocketAddr, args: &MsgArgs) -> Option<Encoded> {
        self.request_foreign(q, from, args, &NoForeignTables)
    }

    /// [`Fixture::request_from`] with the other family's tables available.
    pub fn request_foreign(
        &mut self,
        q: &str,
        from: SocketAddr,
        args: &MsgArgs,
        foreign: &dyn ForeignTables,
    ) -> Option<Encoded> {
        let entry = build_query(q, args, "10", &mut self.rng);
        self.deliver_on(from, &entry.encode(), true, foreign);
        self.sock.take_packet(from).map(|e| Encoded::from_entry(&e))
    }

    /// [`Fixture::request_from`] from the fixture's default source.
    pub fn request(&mut self, q: &str, args: &MsgArgs) -> Option<Encoded> {
        self.request_from(q, self.source, args)
    }

    /// The current simulated time.
    pub fn now(&self) -> Time {
        self.clock.now()
    }

    /// Removes and returns the events queued so far.
    pub fn drain_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }
}

/// A read-only view of another node's table as [`ForeignTables`]
/// (libtorrent's `get_foreign_node` lambda in `dht_dual_stack`).
pub struct TableView<'a>(pub &'a RoutingTable);

impl ForeignTables for TableView<'_> {
    fn find_nodes(&self, family: Protocol, target: &NodeId) -> Option<Vec<NodeEntry>> {
        (self.0.protocol() == family).then(|| self.0.find_node(target, FindNodeOptions::NONE, 0))
    }
}
