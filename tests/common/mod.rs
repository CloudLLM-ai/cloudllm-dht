//! A miniature node for the traversal and RPC tests: everything libtorrent's
//! `dht_test_setup` wires together (routing table, rpc manager, socket,
//! settings), minus the query handlers, which belong to the node (work
//! package 4).
//!
//! `FakeTable` stands in for the real routing table behind
//! [`TableOps`]; it records what the traversals told it so tests can assert
//! on it.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;

use cloudllm_dht::bencode::{Entry, Node};
use cloudllm_dht::ctx::{NodeCtx, TableOps};
use cloudllm_dht::events::Event;
use cloudllm_dht::net::Protocol;
use cloudllm_dht::node_id::{distance, IdSecret, NodeId};
use cloudllm_dht::rng::TestRng;
use cloudllm_dht::rpc_manager::RpcManager;
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::testing::{build_response, Encoded, MockSocket, MsgArgs};
use cloudllm_dht::time::Time;
use cloudllm_dht::traversal::Traversals;
use cloudllm_dht::Sha1Hash;

/// A routing table that remembers what it was told.
#[derive(Debug, Default)]
pub struct FakeTable {
    /// Known nodes (`add_node`), in insertion order.
    pub nodes: Vec<(NodeId, SocketAddr)>,
    /// Router endpoints.
    pub routers: Vec<SocketAddr>,
    /// Every `heard_about`.
    pub heard: Vec<(NodeId, SocketAddr)>,
    /// Every `node_failed`.
    pub failed: Vec<(NodeId, SocketAddr)>,
    /// Every `node_seen`: id, endpoint, rtt.
    pub seen: Vec<(NodeId, SocketAddr, u16)>,
    /// What `node_seen` answers (the "needs refresh" flag).
    pub refresh_on_seen: bool,
    /// Bucket size `k`.
    pub k: usize,
}

impl FakeTable {
    /// An empty table with `k = 8`.
    pub fn new() -> Self {
        Self {
            k: 8,
            ..Self::default()
        }
    }

    /// Adds a node to the table (`routing_table::add_node`).
    pub fn add_node(&mut self, id: NodeId, ep: SocketAddr) {
        self.nodes.push((id, ep));
    }
}

impl TableOps for FakeTable {
    fn bucket_size(&self) -> usize {
        self.k
    }

    fn heard_about(&mut self, id: NodeId, ep: SocketAddr, _now: Time) {
        self.heard.push((id, ep));
    }

    fn node_failed(&mut self, id: NodeId, ep: SocketAddr) {
        self.failed.push((id, ep));
    }

    fn node_seen(&mut self, id: NodeId, ep: SocketAddr, rtt: u16, _now: Time) -> bool {
        self.seen.push((id, ep, rtt));
        self.refresh_on_seen
    }

    fn closest_including_failed(&self, target: &NodeId) -> Vec<(NodeId, SocketAddr)> {
        let mut v = self.nodes.clone();
        v.sort_by_key(|(id, _)| distance(id, target));
        v.truncate(self.k);
        v
    }

    fn router_nodes(&self) -> Vec<SocketAddr> {
        self.routers.clone()
    }
}

/// Everything a node owns that the traversals touch, with helpers that
/// build the [`NodeCtx`] and feed datagrams in.
pub struct World {
    pub settings: DhtSettings,
    pub table: FakeTable,
    pub rpc: RpcManager,
    pub sock: MockSocket,
    pub rng: TestRng,
    pub events: Vec<Event>,
    pub traversals: Traversals,
    pub now: Time,
    pub id: NodeId,
    pub protocol: Protocol,
    pub secret: IdSecret,
    /// Endpoints the traversals asked the node to ping (`NodeCtx::take_pings`),
    /// collected after every call.
    pub pings: Vec<SocketAddr>,
}

impl World {
    /// A node with the given ID serving `protocol`.
    pub fn new(id: NodeId, protocol: Protocol) -> Self {
        Self {
            settings: DhtSettings::default(),
            table: FakeTable::new(),
            rpc: RpcManager::new(id),
            sock: MockSocket::new(),
            rng: TestRng::new(0x5eed),
            events: Vec::new(),
            traversals: Traversals::new(),
            now: Time::ZERO,
            id,
            protocol,
            secret: IdSecret::from_value(0x1234_5678),
            pings: Vec::new(),
        }
    }

    /// A node whose ID is all `0x11` bytes, serving IPv4.
    pub fn v4() -> Self {
        Self::new(Sha1Hash([0x11; 20]), Protocol::V4)
    }

    /// A node whose ID is all `0x11` bytes, serving IPv6.
    pub fn v6() -> Self {
        Self::new(Sha1Hash([0x11; 20]), Protocol::V6)
    }

    /// Runs `f` with a context and the traversal arena.
    pub fn run<R>(&mut self, f: impl FnOnce(&mut NodeCtx<'_>, &mut Traversals) -> R) -> R {
        let mut ctx = NodeCtx::new(
            self.now,
            self.id,
            self.protocol,
            &self.settings,
            &mut self.table,
            &mut self.rpc,
            &mut self.sock,
            &mut self.rng,
            &mut self.events,
            self.secret,
        );
        let r = f(&mut ctx, &mut self.traversals);
        self.pings.extend(ctx.take_pings());
        r
    }

    /// Like [`World::run`], with an IP filter installed.
    pub fn run_with_filter<R>(
        &mut self,
        blocked: &dyn Fn(std::net::IpAddr) -> bool,
        f: impl FnOnce(&mut NodeCtx<'_>, &mut Traversals) -> R,
    ) -> R {
        let mut ctx = NodeCtx::new(
            self.now,
            self.id,
            self.protocol,
            &self.settings,
            &mut self.table,
            &mut self.rpc,
            &mut self.sock,
            &mut self.rng,
            &mut self.events,
            self.secret,
        )
        .with_ip_filter(blocked);
        let r = f(&mut ctx, &mut self.traversals);
        self.pings.extend(ctx.take_pings());
        r
    }

    /// Delivers a response or error datagram (`node.incoming`).
    pub fn incoming(&mut self, from: SocketAddr, e: &Entry) -> Option<NodeId> {
        let enc = Encoded::from_entry(e);
        let n = enc.node();
        self.incoming_node(from, &n)
    }

    /// Delivers an already decoded datagram.
    pub fn incoming_node(&mut self, from: SocketAddr, n: &Node<'_>) -> Option<NodeId> {
        self.run(|ctx, trs| trs.incoming(ctx, from, n))
    }

    /// Answers `request` (a packet the node sent) from `from`, like
    /// `send_dht_response`; a random `id` is added when `args` has none.
    pub fn respond(&mut self, request: &Entry, from: SocketAddr, args: &MsgArgs) -> Option<NodeId> {
        let t = request
            .get("t")
            .and_then(Entry::as_bytes)
            .expect("a request has a transaction id")
            .to_vec();
        let resp = build_response(&t, args, &mut self.rng);
        self.incoming(from, &resp)
    }

    /// Moves the clock forward.
    pub fn advance(&mut self, d: Duration) {
        self.now = self.now + d;
    }

    /// Calls `Traversals::tick`.
    pub fn tick(&mut self) -> Duration {
        self.run(|ctx, trs| trs.tick(ctx))
    }

    /// Removes and returns the first packet sent to `ep`.
    pub fn take_packet(&mut self, ep: SocketAddr) -> Option<Entry> {
        self.sock.take_packet(ep)
    }

    /// Takes the queued events.
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }
}
