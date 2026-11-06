# Porting plan and status

Source of truth: libtorrent `RC_2_1`, commit
`86d573f2631b0162d3cca5e257217eaf530fdcba` (2026-11-05), BSD-3-Clause. Every
module's rustdoc repeats the file(s) it ports. Architecture and rationale:
[ARCHITECTURE.md](ARCHITECTURE.md). Status values: `done` (implemented,
documented, tested), `todo`, `n/a` (no Rust counterpart, with the reason).

## Ground rules for porters

* Read `skills/rust-engineer.md` first; also `rust-concurrency-patterns.md`,
  `rust-fuzzing.md`, `rust-criterion-benchmarking.md`,
  `rust-performance-reviewer.md` as relevant.
* Every public item is documented to manual grade: what it does, why, the
  invariants, failure modes, and the libtorrent function it corresponds to.
* Tests live in `tests/` (never `#[cfg(test)]` in `src/`). Port libtorrent's
  test cases faithfully under snake_case names, each with a doc comment
  naming the original `TEST_CASE`. Any bug found gets a regression test.
* Use `cloudllm_dht::testing` (the `mock_socket`/`msg_args` port) so tests
  read like `test_dht.cpp`; extend it in a *new* file if you need more, so
  work packages do not conflict in `src/testing.rs`.
* Everything untrusted-input-facing gets a fuzz target (WP2: reply parsing
  of every traversal; WP3: `dht_state` loader, item verification, storage op
  sequences; WP4: whole-node `incoming` datagram fuzz and an op-sequence
  fuzzer driving `Node` against `MockSocket`). Commit corpora; crashes become
  named regression tests.
* Run `make ci` and (for fuzz changes) `make fuzz-build fuzz-replay` before
  every push. Commit granularly to `master`; no branches.
* Module declarations for every work package are **already in `lib.rs`**
  as placeholder files, so packages never edit `lib.rs`. Replace the
  placeholder with the implementation. Add dependencies to `Cargo.toml` only
  in your own commit and keep MSRV 1.88 (`make msrv`).

## Work packages

| WP | Scope | Owns (files) | Depends on |
|----|-------|--------------|------------|
| foundation | bencode, node IDs/BEP 42, net encodings, settings, message model, `Transport`/`Clock`/`Rng`, test harness | done, see below | - |
| **WP1** | routing table with replacement buckets, node entries | `node_entry.rs`, `routing_table.rs`, `tests/{routing_table,node_entry}.rs` | foundation only |
| **WP2** | rpc manager, observers, every traversal | `observer.rs`, `rpc_manager.rs`, `traversal/*`, `ctx.rs`, `tests/{rpc_manager,traversal}.rs` | WP1 interface (a fake works until it lands) |
| **WP3** | storage, BEP 44 items, ed25519, DoS blocker, state, bloom filter | `storage.rs`, `item.rs`, `ed25519.rs`, `dos_blocker.rs`, `dht_state.rs`, `bloom_filter.rs`, `announce_flags.rs`, tests | foundation only |
| **WP4** | node (query handlers), tracker, events, tokio driver, integration and simulation tests | `node.rs`, `tracker.rs`, `events.rs`, `driver.rs`, `tests/{dht_node,dht_tracker,sim_dht}.rs` | WP1-3 interfaces; may start against the stubs below |

### Interfaces between packages

These signatures are the contract. A package may add methods but must not
change these without telling the others. Types in `code` are Rust; "ports"
names the libtorrent member.

**WP1 -> WP2, WP4: `RoutingTable` and `NodeEntry`** (landed; the code is the
reference, this is the summary. Changes from the first sketch are marked
*changed*.)

```rust
pub struct NodeEntry {            // node_entry
    pub last_queried: Time /* ZERO = never */, pub id: NodeId, pub endpoint: SocketAddr,
    pub rtt: u16 /* RTT_UNKNOWN = 0xffff */, pub timeout_count: u8 /* NEVER_PINGED = 0xff */,
    pub verified: bool,
}
impl NodeEntry {
    pub fn new(id: NodeId, ep: SocketAddr, rtt: u16, pinged: bool) -> Self; // last_queried = ZERO
    /// changed (new): like `new`, but a pinged entry gets last_queried = now (libtorrent reads the clock here)
    pub fn new_at(id: NodeId, ep: SocketAddr, rtt: u16, pinged: bool, now: Time) -> Self;
    pub fn unknown_id(ep: SocketAddr) -> Self;               // node_entry(ep)
    pub fn pinged(&self) -> bool; pub fn confirmed(&self) -> bool; pub fn fail_count(&self) -> u32;
    pub fn set_pinged(&mut self); pub fn timed_out(&mut self); pub fn reset_fail_count(&mut self);
    pub fn update_rtt(&mut self, rtt: u16);
    pub fn ep(&self) -> SocketAddr; pub fn addr(&self) -> IpAddr; pub fn port(&self) -> u16;
    /// changed: not `Ord` (libtorrent's operator< looks at (verified, rtt) only, so it is not
    /// consistent with Eq); `a.is_better_than(&b)` is `a < b`, `quality_cmp` the three-way form.
    pub fn is_better_than(&self, other: &Self) -> bool;
}

pub struct RoutingTable { /* ... */ }
impl RoutingTable {
    pub fn new(id: NodeId, protocol: Protocol, bucket_size: usize, settings: &DhtSettings) -> Self; // panics unless bucket_size is a power of two
    pub fn try_new(..same..) -> Result<Self, RoutingTableError>;
    pub fn id(&self) -> NodeId;            pub fn protocol(&self) -> Protocol;
    /// changed: takes `now` (re-adds every node, and add_node needs the clock)
    pub fn set_id(&mut self, id: NodeId, now: Time);          // update_node_id
    /// changed (new): the table keeps a COPY of the settings (libtorrent keeps a reference to the live
    /// session_settings). Node must call this whenever settings change.
    pub fn set_settings(&mut self, s: &DhtSettings);
    /// changed (new): `dht_observer::get_dht_ip_filter` + `apply_filter_to_dht`; closure returns true = blocked.
    pub fn set_ip_filter(&mut self, f: Option<IpFilter>);
    pub fn node_seen(&mut self, id: NodeId, ep: SocketAddr, rtt: u16, now: Time) -> bool;
    pub fn add_node(&mut self, e: NodeEntry, now: Time) -> bool;
    pub fn heard_about(&mut self, id: NodeId, ep: SocketAddr, now: Time);
    pub fn node_failed(&mut self, id: &NodeId, ep: SocketAddr);       // changed: id by reference
    pub fn add_router_node(&mut self, ep: SocketAddr); pub fn router_nodes(&self) -> impl Iterator<Item = &SocketAddr>;
    /// count == 0 means bucket_size. Result is NOT sorted (libtorrent only selects the closest of the last bucket).
    pub fn find_node(&self, target: &NodeId, opts: FindNodeOptions, count: usize) -> Vec<NodeEntry>;
    /// libtorrent's next_refresh() returns a pointer; here the stamped entry and its bucket index.
    /// Tick with a clock that starts after Time::ZERO (ZERO means "never queried").
    pub fn next_refresh(&mut self, now: Time) -> Option<(NodeEntry, usize)>;
    pub fn size(&self) -> (usize, usize, usize);   // (nodes, replacements, confirmed)
    pub fn depth(&self) -> usize;                  // 0 for an empty table (libtorrent: -1, and stuck there; see below)
    pub fn bucket_size(&self) -> usize;            // k;  the per-bucket count is `bucket_len(i)` (changed: renamed)
    pub fn bucket_limit(&self, bucket: usize) -> usize; pub fn is_full(&self, bucket: usize) -> bool;
    pub fn num_active_buckets(&self) -> usize;     pub fn buckets(&self) -> &[Bucket];
    pub fn num_global_nodes(&self) -> u64;
    pub fn for_each_node(&self, live: impl FnMut(&NodeEntry), replacements: impl FnMut(&NodeEntry));
    pub fn for_each_entry(&self, f: impl FnMut(&NodeEntry));   // libtorrent's one-callback for_each_node
    pub fn live_nodes(&self) -> impl Iterator<Item = &NodeEntry>; pub fn replacement_nodes(&self) -> ...;
    pub fn status(&self) -> Vec<BucketStatus>;     // dht_routing_bucket alert data; status_into() is libtorrent's exact accumulating form
    pub fn native_address / native_endpoint(..);
    pub fn check_invariants(&self) -> Result<(), InvariantError>;  // tests and fuzzing
    pub fn print_state(&self, now: Time) -> String; pub fn write_state(&self, out: &mut dyn fmt::Write, now: Time) -> fmt::Result;
}
// libtorrent has no increment_out_message / increment_message_count at this commit: not ported.
pub fn classify_prefix(bucket_idx: usize, last_bucket: bool, bucket_size: usize, nid: &NodeId) -> u8;
pub fn mostly_verified_nodes(bucket: &[NodeEntry]) -> bool;
pub fn compare_ip_cidr(lhs: IpAddr, rhs: IpAddr) -> bool;
pub fn all_in_same_bucket(b: &[NodeEntry], id: &NodeId, bucket_index: usize) -> bool;
pub fn replace_node_impl(e: &NodeEntry, b: &mut [NodeEntry], ips: &mut IpSet, bucket_index: usize,
                         bucket_size_limit: usize, last_bucket: bool) -> AddNodeStatus;
```

A libtorrent bug found while porting: `routing_table::depth()` stores `-1` in its
cached `m_depth` when called on an empty table and then returns it forever
(the early return for negative values never recomputes), even after nodes
arrive. `node::tick` calls `depth()` before the first node exists, so the
"rebootstrap while depth < 4" check is permanently true and the node re-runs
its self-bootstrap every ten minutes. Fixed here (the cache never goes
negative); regression test `test_depth_recovers_after_empty_table`.

A second libtorrent bug (found by the `routing_table_ops` fuzzer): after
splitting the last bucket, `routing_table::add_node` erases the new bucket
"if none of the nodes ended up in it" but only checks `live_nodes`; a new
bucket holding only replacements is erased with them and their addresses
stay in `m_ips` forever (with the default `dht_restrict_routing_ips` such an
IP can then never be added again). Fixed here by also requiring the
replacement cache to be empty; regression test
`test_split_does_not_drop_a_new_bucket_holding_only_replacements`.

**WP2 -> WP4: the traversal family and `NodeCtx`** (revised by WP2: the
first sketch did not survive the borrow checker, see "why" below)

```rust
/// What a traversal may touch while handling an event; built by Node per call.
pub struct NodeCtx<'a> {
    pub now: Time, pub id: NodeId, pub protocol: Protocol,
    pub settings: &'a DhtSettings,
    pub table: &'a mut dyn TableOps,                // WP1's RoutingTable implements it (impl lives in ctx.rs)
    pub rpc: &'a mut RpcManager,                    // transaction table + observer arena
    pub transport: &'a mut dyn Transport,
    pub rng: &'a mut dyn Rng,
    pub events: &'a mut Vec<Event>,                 // events.rs
    pub id_secret: IdSecret,                        // make_id_secret for the bootstrap target
    /* private: ip filter, follow-up traversal queue, ping queue */
}
impl NodeCtx<'_> {
    pub fn new(now, id, protocol, settings, table, rpc, transport, rng, events, id_secret) -> NodeCtx;
    pub fn with_ip_filter(self, blocked: &dyn Fn(IpAddr) -> bool) -> NodeCtx; // apply_filter_to_dht
    // rpc_manager operations (methods here because `ctx.rpc.invoke(ctx, ..)` would borrow twice):
    pub fn invoke(&mut self, e: Entry, target: SocketAddr, obs: ObserverId) -> bool;
    pub fn invoke_detached(&mut self, kind: ObserverKind /*Ping|Announce*/, id: NodeId, target: SocketAddr, e: Entry) -> bool;
    pub fn rpc_incoming(&mut self, from: SocketAddr, msg: &Node<'_>) -> Incoming; // Ignored | Failed(obs) | Reply{observer,id,rtt}
    pub fn rpc_tick(&mut self) -> TickOutcome;      // low level; Traversals::tick wraps it
    pub fn rpc_unreachable(&mut self, ep: SocketAddr) -> Option<ObserverId>;
    pub fn take_pings(&mut self) -> Vec<SocketAddr>; // bootstrap::done's node.add_node(ep); node pings each
}
pub trait TableOps {                                // the methods traversals call on routing_table
    fn bucket_size(&self) -> usize;
    fn heard_about(&mut self, id: NodeId, ep: SocketAddr, now: Time);
    fn node_failed(&mut self, id: NodeId, ep: SocketAddr);
    fn node_seen(&mut self, id: NodeId, ep: SocketAddr, rtt: u16, now: Time) -> bool;
    fn closest_including_failed(&self, target: &NodeId) -> Vec<(NodeId, SocketAddr)>;
    fn router_nodes(&self) -> Vec<SocketAddr>;
}
pub struct RpcManager { .. }   // RpcManager::new(our_id), update_node_id, add_our_id, num_allocated_observers, our_id
pub struct TraversalId(pub u64);
pub trait Traversal: Send { /* name, algo, new_observer, start, invoke, done, on_reply, on_timeout, on_short_timeout */ }
/// The arena the node owns; routes every event to the right traversal.
pub struct Traversals { .. }
impl Traversals {
    pub fn new() -> Self;
    pub fn spawn(&mut self, ctx: &mut NodeCtx<'_>, t: Box<dyn Traversal>) -> TraversalId;
    /// Handles y=r / y=e: rpc match, observer.reply/timeout, then table.node_seen.
    /// Some(id) = node_seen asked for a refresh of that node.
    pub fn incoming(&mut self, ctx: &mut NodeCtx<'_>, from: SocketAddr, msg: &Node<'_>) -> Option<NodeId>;
    pub fn tick(&mut self, ctx: &mut NodeCtx<'_>) -> Duration;      // rpc timeouts; delay to next tick
    pub fn unreachable(&mut self, ctx: &mut NodeCtx<'_>, ep: SocketAddr);
    pub fn status(&self, ctx: &NodeCtx<'_>) -> Vec<LookupStatus>;
}
// Constructors Node (WP4) calls (each returns a Box<dyn Traversal> for `Traversals::spawn`):
//   bootstrap, get_peers/announce, get_item_*, put_item_*, sample_infohashes, direct_request  (module docs list exact signatures)
// Results flow back as Events pushed on ctx.events, never as callbacks.
```

Why: `ctx.rpc.invoke(ctx, ..)` borrows `ctx` twice, so the rpc operations that
need the socket, settings and rng are methods of `NodeCtx`; `RpcManager` is
the state. The table is a trait object so traversals do not depend on the
routing table's layout (and can be fuzzed against a fake). Observers live in
an arena inside `RpcManager` (reference counted, like libtorrent's
`shared_ptr<observer>`); a traversal is dropped when it is done and its last
observer is freed.

**WP3 -> WP2, WP4: `DhtStorage`, `Item`, `DhtState`, `AnnounceFlags`**

```rust
bitflags-free newtype: pub struct AnnounceFlags(u8) { SEED, IMPLIED_PORT, SSL_TORRENT }   // announce_flags.hpp
pub trait DhtStorage {                                           // dht_storage_interface
    fn update_node_ids(&mut self, ids: &[NodeId]);
    /// Fills `reply` ("values"/"values6"/"BFsd"/"BFpe" for scrape) -> any peers found.
    fn get_peers(&self, info_hash: &Sha1Hash, noseed: bool, scrape: bool, requester: IpAddr, reply: &mut Entry) -> bool;
    fn announce_peer(&mut self, info_hash: &Sha1Hash, endpoint: SocketAddr, name: &str, seed: bool);
    fn get_immutable_item(&self, target: &Sha1Hash, item: &mut Entry) -> bool;
    fn put_immutable_item(&mut self, target: &Sha1Hash, buf: &[u8], addr: IpAddr);
    fn get_mutable_item_seq(&self, target: &Sha1Hash) -> Option<SequenceNumber>;
    fn get_mutable_item(&self, target: &Sha1Hash, seq: SequenceNumber, force_fill: bool, item: &mut Entry) -> bool;
    fn put_mutable_item(&mut self, target: &Sha1Hash, buf: &[u8], sig: &Signature, seq: SequenceNumber,
                        pk: &PublicKey, salt: &[u8], addr: IpAddr);
    fn get_infohashes_sample(&mut self, item: &mut Entry) -> usize;
    fn tick(&mut self, now: Time);                              // expiry
    fn counters(&self) -> StorageCounters;
}
pub struct DefaultStorage { .. }  impl DefaultStorage { pub fn new(settings: &DhtSettings, rng: ..) -> Self }
pub struct Item { .. }            // item.hpp: immutable/mutable, value, salt, pk, sig, seq
pub fn item_target_id(salt: &[u8], pk: &PublicKey) -> Sha1Hash;           // item_target_id
pub fn verify_mutable_item(v: &[u8], salt: &[u8], seq: SequenceNumber, pk: &PublicKey, sig: &Signature) -> bool;
pub fn sign_mutable_item(v: &[u8], salt: &[u8], seq: SequenceNumber, pk: &PublicKey, sk: &SecretKey) -> Signature;
pub struct DosBlocker { .. }   impl { pub fn new() -> Self; pub fn incoming(&mut self, addr: IpAddr, now: Time, ban: bool..) -> bool; }
pub struct DhtState { pub nids: Vec<(IpAddr, NodeId)>, pub nodes: Vec<SocketAddr>, pub nodes6: Vec<SocketAddr> }
pub fn read_dht_state(e: &Node<'_>) -> DhtState;  pub fn save_dht_state(s: &DhtState) -> Entry;
```

**WP4 owns `Event` and the public `Dht` API** (`events.rs`, `tracker.rs`).
WP2 pushes results as events: `Event::GetPeersReply { target, peers }`,
`Event::GetItemDone { target, item, authoritative }`, `Event::PutDone { target, responses }`,
`Event::SampleInfohashes { from, interval, num, samples, nodes }`,
`Event::DirectResponse { token, reply }`,
`Event::BootstrapDone`; WP4 may add variants but not rename these. Until WP4
lands `events.rs`, WP2 defines a minimal `Event` in `events.rs` itself
(the file is theirs to start; WP4 extends it).

**Dependency order for parallel work.** WP1 and WP3 depend only on the
foundation and can finish independently. WP2 needs `RoutingTable` only
through the methods above: until WP1 lands it may use a 40-line fake
implementing the same method set in `tests/`. WP4 can write `Node`
against the interfaces and the `MockSocket` while WP1-3 finish, then
integrate; the final wiring and the `test_dht.cpp` node-level cases are
WP4's.


## Source files

| libtorrent | Rust | WP | status | notes |
|---|---|---|---|---|
| `include/libtorrent/kademlia/node_id.hpp + src/kademlia/node_id.cpp` | `src/node_id.rs, src/sha1_hash.rs` | foundation | done |  |
| `src/kademlia/msg.cpp + msg.hpp` | `src/msg.rs` | foundation | done | `verify_message`, message model (`Query`, `MessageType`, `Want`, `ErrorCode`) |
| `include/libtorrent/kademlia/io.hpp + socket_io.hpp` | `src/net.rs` | foundation | done | compact endpoints/nodes, `is_local` |
| `include/libtorrent/kademlia/types.hpp` | `src/types.rs` | foundation | done | `PublicKey`, `SecretKey`, `Signature`, `SequenceNumber` |
| `src/kademlia/dht_settings.cpp + dht_settings.hpp` | `src/settings.rs` | foundation | done | `DhtSettings`, `read_dht_settings`, `save_dht_settings` |
| `src/bdecode.cpp, src/entry.cpp, bencode.hpp (not in kademlia/)` | `src/bencode/` | foundation | done | decoder, encoder |
| `socket_manager (node.hpp)` | `src/transport.rs` | foundation | done | `Transport` |
| `aux::time_now, aux::random` | `src/time.rs, src/rng.rs` | foundation | done | `Time`, `Clock`, `Rng` |
| `test/test_dht.cpp helpers (mock_socket, msg_args, ...)` | `src/testing.rs` | foundation | done | harness |
| `include/libtorrent/kademlia/node_entry.hpp + src/kademlia/node_entry.cpp` | `src/node_entry.rs` | WP1 | done | `NodeEntry`; `new_at` takes the clock, `is_better_than` replaces `operator<` |
| `include/libtorrent/kademlia/routing_table.hpp + src/kademlia/routing_table.cpp` | `src/routing_table.rs` | WP1 | done | replacement buckets, extended table, IP restriction (`compare_ip_cidr`), `classify_prefix`, `mostly_verified_nodes`, refresh scheduling |
| `include/libtorrent/kademlia/observer.hpp` | `src/observer.rs` | WP2 | done | request record in the rpc manager arena |
| `include/libtorrent/kademlia/rpc_manager.hpp + src/kademlia/rpc_manager.cpp` | `src/rpc_manager.rs` | WP2 | done | transaction table, timeouts, `unreachable` |
| `include/libtorrent/kademlia/traversal_algorithm.hpp + .cpp` | `src/traversal/algorithm.rs` | WP2 | done |  |
| `include/libtorrent/kademlia/find_data.hpp + .cpp` | `src/traversal/find_data.rs` | WP2 | todo |  |
| `include/libtorrent/kademlia/get_peers.hpp + .cpp` | `src/traversal/get_peers.rs` | WP2 | todo | incl. BEP 33 scrape reply parsing |
| `include/libtorrent/kademlia/get_item.hpp + .cpp` | `src/traversal/get_item.rs` | WP2 | todo | BEP 44 get |
| `include/libtorrent/kademlia/put_data.hpp + .cpp` | `src/traversal/put_data.rs` | WP2 | todo | BEP 44 put, announce_peer |
| `include/libtorrent/kademlia/sample_infohashes.hpp + .cpp` | `src/traversal/sample_infohashes.rs` | WP2 | todo | BEP 51 |
| `include/libtorrent/kademlia/direct_request.hpp` | `src/traversal/direct_request.rs` | WP2 | todo |  |
| `include/libtorrent/kademlia/refresh.hpp + src/kademlia/refresh.cpp (refresh, bootstrap)` | `src/traversal/refresh.rs` | WP2 | todo | moved from WP1: a traversal subclass |
| `include/libtorrent/kademlia/dht_storage.hpp + src/kademlia/dht_storage.cpp` | `src/storage.rs` | WP3 | todo | `DhtStorage` trait + `DefaultStorage`, BEP 33 bloom filters, token-less |
| `include/libtorrent/bloom_filter.hpp (not in kademlia/)` | `src/bloom_filter.rs` | WP3 | todo | BEP 33 scrape |
| `include/libtorrent/kademlia/item.hpp + src/kademlia/item.cpp` | `src/item.rs` | WP3 | todo | BEP 44 `Item`, signing payload, `verify_mutable_item` |
| `include/libtorrent/kademlia/ed25519.hpp + src/kademlia/ed25519.cpp` | `src/ed25519.rs` | WP3 | todo | thin layer over ed25519-dalek, see ARCHITECTURE.md section 3 |
| `include/libtorrent/kademlia/dos_blocker.hpp + src/kademlia/dos_blocker.cpp` | `src/dos_blocker.rs` | WP3 | todo |  |
| `include/libtorrent/kademlia/dht_state.hpp + src/kademlia/dht_state.cpp` | `src/dht_state.rs` | WP3 | todo | `DhtState`, `read_dht_state`, `save_dht_state`, `extract_node_ids` |
| `include/libtorrent/kademlia/announce_flags.hpp` | `src/announce_flags.rs` | WP3 | todo | tiny; shared with WP2/WP4 so it lands first |
| `include/libtorrent/kademlia/node.hpp + src/kademlia/node.cpp` | `src/node.rs` | WP4 | todo | query handlers, token generation, `incoming`, `tick` |
| `include/libtorrent/kademlia/dht_tracker.hpp + src/kademlia/dht_tracker.cpp` | `src/tracker.rs` | WP4 | todo | multi-node (v4/v6) owner, timers, rate limiter |
| `include/libtorrent/kademlia/dht_observer.hpp` | `src/events.rs` | WP4 | todo | alerts as an `Event` stream |
| `(new) tokio UDP driver` | `src/driver.rs (feature `tokio-driver`)` | WP4 | todo | not in libtorrent: asio is its driver |

## Test cases: `test/test_dht.cpp`

| TEST_CASE | Rust test file | WP / status |
|---|---|---|
| `ping` | `tests/dht_node.rs` | WP4 |
| `invalid_message` | `tests/dht_node.rs` | WP4 |
| `node_id_testing` | `tests/node_id.rs` | done |
| `get_peers_announce` | `tests/dht_node.rs` | WP4 |
| `scrape_v4` | `tests/dht_node.rs` | WP4 |
| `scrape_v6` | `tests/dht_node.rs` | WP4 |
| `id_enforcement_v4` | `tests/dht_node.rs` | WP4 |
| `id_enforcement_v6` | `tests/dht_node.rs` | WP4 |
| `bloom_filter` | `tests/bloom_filter.rs` | WP3 |
| `put_v4` | `tests/dht_node.rs` | WP4 |
| `put_v6` | `tests/dht_node.rs` | WP4 |
| `routing_table_v4` | `tests/routing_table.rs` | done |
| `routing_table_v6` | `tests/routing_table.rs` | done |
| `bootstrap_v4` | `tests/traversal.rs` | WP2 |
| `bootstrap_v6` | `tests/traversal.rs` | WP2 |
| `bootstrap_want_v4` | `tests/traversal.rs` | WP2 |
| `bootstrap_want_v6` | `tests/traversal.rs` | WP2 |
| `short_nodes_v4` | `tests/traversal.rs` | WP2 |
| `short_nodes_v6` | `tests/traversal.rs` | WP2 |
| `get_peers_v4` | `tests/traversal.rs` | WP2 |
| `get_peers_v6` | `tests/traversal.rs` | WP2 |
| `mutable_get_v4` | `tests/traversal.rs` | WP2 |
| `mutable_get_salt_v4` | `tests/traversal.rs` | WP2 |
| `mutable_get_v6` | `tests/traversal.rs` | WP2 |
| `mutable_get_salt_v6` | `tests/traversal.rs` | WP2 |
| `immutable_get` | `tests/traversal.rs` | WP2 |
| `immutable_put` | `tests/traversal.rs` | WP2 |
| `mutable_put` | `tests/traversal.rs` | WP2 |
| `traversal_done` | `tests/traversal.rs` | WP2 |
| `dht_dual_stack` | `tests/dht_node.rs` | WP4 |
| `multi_home` | `tests/dht_node.rs` | WP4 |
| `signing_test1` | `tests/item.rs` | WP3 |
| `signing_test2` | `tests/item.rs` | WP3 |
| `signing_test3` | `tests/item.rs` | WP3 |
| `signing_oversized_salt` | `tests/item.rs` | WP3 |
| `verify_message` | `tests/msg.rs` | done |
| `routing_table_uniform` | `tests/routing_table.rs` | done |
| `routing_table_balance` | `tests/routing_table.rs` | done |
| `routing_table_extended` | `tests/routing_table.rs` | done |
| `routing_table_set_id` | `tests/routing_table.rs` | done |
| `routing_table_for_each` | `tests/routing_table.rs` | done |
| `node_set_id` | `tests/dht_node.rs` | WP4 |
| `read_only_node` | `tests/dht_node.rs` | WP4 |
| `rpc_reply_ignores_wrong_port` | `tests/rpc_manager.rs` | WP2 done |
| `invalid_error_msg` | `tests/rpc_manager.rs` | WP2 done |
| `unsorted_traversal_results` | `tests/traversal.rs` | WP2 done |
| `rpc_invalid_error_msg` | `tests/rpc_manager.rs` | WP2 done |
| `node_id_bucket_distribution` | `tests/node_id.rs` | done |
| `node_id_min_distance_exp` | `tests/node_id.rs` | done |
| `dht_verify_node_address` | `tests/routing_table.rs` | done |
| `dht_ip_filter` | `tests/dht_node.rs` | WP4 |
| `dht_tracker_ip_filter` | `tests/dht_tracker.rs` | WP4 |
| `dht_node_add_node_ip_filter` | `tests/dht_node.rs` | WP4 |
| `generate_prefix_mask` | `tests/node_id.rs` | done |
| `distance_exp` | `tests/node_id.rs` | done |
| `compare_ip_cidr` | `tests/routing_table.rs` | done |
| `dht_state` | `tests/dht_state.rs` | WP3 |
| `sample_infohashes` | `tests/traversal.rs` | WP2 |
| `node_entry_comparison` | `tests/node_entry.rs` | done |
| `mostly_verified_nodes` | `tests/routing_table.rs` | done |
| `classify_prefix` | `tests/routing_table.rs` | done |
| `replace_node_impl` | `tests/routing_table.rs` | done |
| `all_in_same_bucket` | `tests/routing_table.rs` | done |
| `rate_limit_non_positive` | `tests/dht_tracker.rs` | WP4 |
| `rate_limit_int_max` | `tests/dht_tracker.rs` | WP4 |
| `rate_limit_large_delta` | `tests/dht_tracker.rs` | WP4 |
| `rate_limit_accrue_limit` | `tests/dht_tracker.rs` | WP4 |
| `dht` | `-` | n/a |

## Test cases: `test/test_dht_storage.cpp`

| TEST_CASE | Rust test file | WP / status |
|---|---|---|
| `announce_peer` | `tests/storage.rs` | WP3 |
| `dual_stack` | `tests/storage.rs` | WP3 |
| `put_items` | `tests/storage.rs` | WP3 |
| `counters` | `tests/storage.rs` | WP3 |
| `set_custom` | `tests/storage.rs` | WP3 |
| `default_set_custom` | `tests/storage.rs` | WP3 |
| `peer_limit` | `tests/storage.rs` | WP3 |
| `peer_prefix_limit` | `tests/storage.rs` | WP3 |
| `peer_prefix_limit_full` | `tests/storage.rs` | WP3 |
| `torrent_limit` | `tests/storage.rs` | WP3 |
| `immutable_item_limit` | `tests/storage.rs` | WP3 |
| `mutable_item_limit` | `tests/storage.rs` | WP3 |
| `get_peers_dist` | `tests/storage.rs` | WP3 |
| `update_node_ids` | `tests/storage.rs` | WP3 |
| `infohashes_sample` | `tests/storage.rs` | WP3 |
| `infohashes_sample_dist` | `tests/storage.rs` | WP3 |
| `dummy` | `-` | n/a |

## Test cases: `test/test_direct_dht.cpp`

| TEST_CASE | Rust test file | WP / status |
|---|---|---|
| `direct_dht_request` | `tests/traversal.rs` | WP2 |

## Test cases: `test/test_dos_blocker.cpp`

| TEST_CASE | Rust test file | WP / status |
|---|---|---|
| `dos_blocker` | `tests/dos_blocker.rs` | WP3 |

## Test cases: `test/test_ed25519.cpp`

| TEST_CASE | Rust test file | WP / status |
|---|---|---|
| `ed25519_test_vec1` | `tests/ed25519.rs` | WP3 |
| `create_seed` | `tests/ed25519.rs` | WP3 |
| `add_scalar` | `tests/ed25519.rs` | WP3 |
| `key_exchange` | `tests/ed25519.rs` | WP3 |
| `empty` | `-` | n/a |

## Test cases: `test/test_bdecode.cpp`

| TEST_CASE | Rust test file | WP / status |
|---|---|---|
| `integer` | `tests/bdecode.rs` | done |
| `construct_string` | `tests/bdecode.rs` | done |
| `construct_string_literal` | `tests/bdecode.rs` | done |
| `construct_string_view` | `tests/bdecode.rs` | done |
| `construct_integer` | `tests/bdecode.rs` | done |
| `string` | `tests/bdecode.rs` | done |
| `string_prefix1` | `tests/bdecode.rs` | done |
| `list` | `tests/bdecode.rs` | done |
| `dict` | `tests/bdecode.rs` | done |
| `dict_key_novalue` | `tests/bdecode.rs` | done |
| `dict_nonstring_key` | `tests/bdecode.rs` | done |
| `dict_null_key` | `tests/bdecode.rs` | done |
| `dict_unordered_keys` | `tests/bdecode.rs` | done |
| `dict_duplicate_key` | `tests/bdecode.rs` | done |
| `premature_e` | `tests/bdecode.rs` | done |
| `negative_length_prefix` | `tests/bdecode.rs` | done |
| `overflow_length_prefix` | `tests/bdecode.rs` | done |
| `close_overflow_length_prefix` | `tests/bdecode.rs` | done |
| `overflow_length_prefix2` | `tests/bdecode.rs` | done |
| `leading_zero_length_prefix` | `tests/bdecode.rs` | done |
| `nodigit_int` | `tests/bdecode.rs` | done |
| `minus_int` | `tests/bdecode.rs` | done |
| `interior_minus_int` | `tests/bdecode.rs` | done |
| `int_overflow` | `tests/bdecode.rs` | done |
| `int_overflow2` | `tests/bdecode.rs` | done |
| `int_truncated` | `tests/bdecode.rs` | done |
| `int_leading_zero` | `tests/bdecode.rs` | done |
| `bdecode_error` | `tests/bdecode.rs` | done |
| `64bit_int` | `tests/bdecode.rs` | done |
| `64bit_int_negative` | `tests/bdecode.rs` | done |
| `int_invalid_digit` | `tests/bdecode.rs` | done |
| `invalid_encoding` | `tests/bdecode.rs` | done |
| `depth_limit` | `tests/bdecode.rs` | done |
| `item_limit` | `tests/bdecode.rs` | done |
| `unexpected_eof` | `tests/bdecode.rs` | done |
| `unexpected_eof2` | `tests/bdecode.rs` | done |
| `expected_string` | `tests/bdecode.rs` | done |
| `unexpected_eof_dict_key` | `tests/bdecode.rs` | done |
| `unexpected_eof_dict_key2` | `tests/bdecode.rs` | done |
| `expected_string_dict_key2` | `tests/bdecode.rs` | done |
| `unexpected_eof_int` | `tests/bdecode.rs` | done |
| `unexpected_eof_int2` | `tests/bdecode.rs` | done |
| `expected_colon_dict` | `tests/bdecode.rs` | done |
| `empty_string` | `tests/bdecode.rs` | done |
| `partial_string` | `tests/bdecode.rs` | done |
| `list_ints` | `tests/bdecode.rs` | done |
| `dict_ints` | `tests/bdecode.rs` | done |
| `dict_at` | `tests/bdecode.rs` | done |
| `string_ptr` | `tests/bdecode.rs` | done |
| `exceed_buf_limit` | `tests/bdecode.rs` | done |
| `parse_int` | `tests/bdecode.rs` | done |
| `invalid_digit` | `tests/bdecode.rs` | done |
| `parse_int_overflow` | `tests/bdecode.rs` | done |
| `parse_length_overflow` | `tests/bdecode.rs` | done |
| `expected_colon_string` | `tests/bdecode.rs` | done |
| `dict_find_funs` | `tests/bdecode.rs` | done |
| `list_at_funs` | `tests/bdecode.rs` | done |
| `list_at_reverse` | `tests/bdecode.rs` | done |
| `dict_find_funs2` | `tests/bdecode.rs` | done |
| `print_entry` | `tests/bdecode.rs` | done |
| `print_entry2` | `tests/bdecode.rs` | done |
| `swap` | `-` | n/a (C++ memory management) |
| `swap_root` | `-` | n/a (C++ memory management) |
| `swap_disjoint` | `-` | n/a (C++ memory management) |
| `swap_root_disjoint` | `-` | n/a (C++ memory management) |
| `clear` | `-` | n/a (C++ memory management) |
| `copy_root` | `-` | n/a (C++ memory management) |
| `non_owning_refs` | `-` | n/a (C++ memory management) |
| `partial_parse` | `tests/bdecode.rs` | done |
| `partial_parse2` | `tests/bdecode.rs` | done |
| `partial_parse3` | `tests/bdecode.rs` | done |
| `partial_parse4` | `tests/bdecode.rs` | done |
| `partial_parse_string` | `tests/bdecode.rs` | done |
| `switch_buffer` | `-` | n/a (C++ memory management) |
| `long_string_99999999` | `tests/bdecode.rs` | done |
| `long_string_100000000` | `tests/bdecode.rs` | done |
| `data_offset` | `tests/bdecode.rs` | done |
| `string_offset` | `tests/bdecode.rs` | done |
| `dict_at_node` | `tests/bdecode.rs` | done |

All `done` rows for `test_bdecode.cpp` and the node-ID/`verify_message` rows of `test_dht.cpp` are ported under snake_case names prefixed `test_`; `test/dht_server.*` (a scripted DHT server used by `test_dht.cpp`/session tests) is replaced by `testing::MockSocket` plus the simulation harness WP4 builds for `tests/sim_dht.rs`.


## Simulation tests (`simulation/`)

libtorrent drives these through `libsimulator`. Here they are deterministic multi-node tests over an in-memory network built from `ManualClock`, `TestRng` and a `Transport` that routes datagrams between `Node`s (WP4: `tests/sim_dht.rs`, helper in `tests/common/`).

| file | test | Rust | WP |
|---|---|---|---|
| `simulation/test_dht.cpp` | `dht_bootstrap` | `tests/sim_dht.rs` | WP4 |
| `simulation/test_dht.cpp` | `dht_dual_stack_get_peers` | `tests/sim_dht.rs` | WP4 |
| `simulation/test_dht.cpp` | `dht_dual_stack_immutable_item` | `tests/sim_dht.rs` | WP4 |
| `simulation/test_dht.cpp` | `dht_dual_stack_mutable_item` | `tests/sim_dht.rs` | WP4 |
| `simulation/test_dht_rate_limit.cpp` | `dht_rate_limit` | `tests/sim_dht.rs` | WP4 |
| `simulation/test_dht_rate_limit.cpp` | `dht_delete_socket` | `tests/sim_dht.rs` | WP4 |
| `simulation/test_dht_bootstrap.cpp` | `dht_bootstrap` | `tests/sim_dht.rs` | WP4 |
| `simulation/test_dht_storage.cpp` | `dht_storage_counters` | `tests/storage.rs` | WP3 |
| `simulation/test_dht_storage.cpp` | `dht_storage_infohashes_sample` | `tests/storage.rs` | WP3 |

## Fuzzers (`fuzzers/src/`)

libtorrent ships `dht_node.cpp`, `bdecode_node.cpp`, `bdecode_entry.cpp`, `dht_*_reply.cpp`, `dht_put_item_request.cpp`. Mapped to `fuzz/fuzz_targets/`: `bdecode` (done), `message_parse` (done), and for the packages: `node_incoming` (`dht_node.cpp`, WP4), `traversal_replies` (the `dht_*_reply.cpp` family, WP2), `item_verify` (WP3), `state_load` (WP3), `storage_ops` (WP3), `routing_table_ops` (WP1, done).

