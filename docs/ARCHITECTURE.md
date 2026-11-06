# cloudllm_dht architecture

`cloudllm_dht` is a Rust port of libtorrent RC_2_1's Kademlia DHT
(`src/kademlia`, `include/libtorrent/kademlia`) as a standalone crate. This
document records the decisions that shape every module and why. The
work-package split and the per-file status are in [PORTING.md](PORTING.md).

## 1. Sans-IO core, thin driver

**Decision.** The node, routing table, RPC manager, traversals, storage and
DoS blocker are deterministic state machines. They never read a clock, never
draw randomness, and never touch a socket on their own. Everything they need
is passed in:

| Need                 | libtorrent                         | Here                                   |
|----------------------|------------------------------------|----------------------------------------|
| incoming datagram    | `node::incoming(sock, msg)`        | `Node::incoming(&mut self, ctx, from: SocketAddr, datagram: &[u8], now: Time)` |
| time                 | `aux::time_now()` / `clock_type`   | a `now: Time` argument; [`Clock`] for drivers |
| randomness           | `aux::random()`                    | `&mut dyn Rng` ([`SystemRng`], [`TestRng`]) |
| outgoing datagram    | `socket_manager::send_packet`      | `&mut dyn Transport` (`has_quota`, `send_packet(&Entry, SocketAddr)`) |
| timers               | `deadline_timer` in `dht_tracker`  | `Node::next_timeout(&self) -> Option<Time>` and `Node::tick(now)` |
| observer / alerts    | `dht_observer`                     | an `Event` queue the caller drains     |

**Why.**

* `test_dht.cpp` is written against `mock_socket` and a hand-driven node;
  with a sans-IO core those tests port almost line for line (see
  `testing::MockSocket`, `MsgArgs`, `build_query`).
* Determinism: with a seeded `TestRng` and a `ManualClock`, a lookup across
  hundreds of simulated nodes is reproducible, which is what libtorrent's
  `simulation/` tests rely on a network simulator for.
* Fuzzing: a state machine that takes bytes in and returns bytes out is
  directly fuzzable (`fuzz/fuzz_targets/`), with no sockets in the loop.
* One implementation serves tokio, async-std, a mio loop, or an embedded
  event loop; the crate does not pick a runtime. The tokio driver is a
  feature (`tokio-driver`), about a hundred lines.

**The cycle problem.** libtorrent's `node`, `rpc_manager`, `observer` and
`traversal_algorithm` hold raw pointers to one another (an observer points
at its traversal, a traversal at the node, the node at the rpc manager).
Rust ownership forbids that, so the port uses *ids and an arena*:

* `Node` owns `RpcManager` (the transaction table), the `RoutingTable`, and
  a `slab` of live traversals addressed by `TraversalId`.
* An in-flight request is an `Observer` record `{ traversal: TraversalId,
  target: NodeEndpoint, sent: Time, flags, .. }` stored in the rpc manager
  under its transaction id.
* A reply, error or timeout is dispatched by looking up the observer, taking
  its traversal out of the slab, and calling
  `traversal.on_reply(&mut ctx, observer, msg)`; the traversal receives a
  short-lived `NodeCtx` borrowing the table, the rpc manager, the transport,
  the rng and the settings. Nothing is `Rc<RefCell<..>>`.

`NodeCtx` is the single seam between the traversal family (WP2) and the node
(WP4); its fields are fixed in PORTING.md.

## 2. Storage behind a trait

`dht_storage_interface` becomes `trait DhtStorage` (`storage.rs`), with the
default in-memory implementation `DefaultStorage` (libtorrent
`dht_default_storage`). A consumer who wants disk or a database for BEP 44
items implements the trait; the node only sees the trait object. The trait
is the interface between WP3 (owner) and WP2/WP4 (users); see PORTING.md.

## 3. Crypto

| Use                     | Crate                 | Notes |
|-------------------------|-----------------------|-------|
| BEP 44 signatures       | `ed25519-dalek` 2.x   | `default-features = false`, `hazmat` for the expanded key (below) |
| SHA-1 (IDs, tokens, targets) | `sha1` 0.10       | libtorrent's `hasher` |
| BEP 42 CRC32C           | `crc32c` 0.6          | hardware-accelerated; matches the BEP 42 vectors (tested) |
| Randomness              | `getrandom` 0.3       | only inside `SystemRng` |

**The Ed25519 key format.** libtorrent's `secret_key` is *64 bytes*: the
SHA-512 expansion of a 32-byte seed with the scalar half clamped, not the
seed. `ed25519_create_keypair(seed)` produces `(public_key, secret_key)`;
`ed25519_sign(msg, pk, sk)` signs with the expanded key directly. In
`ed25519-dalek` 2.x the equivalent is `hazmat::ExpandedSecretKey`
(`from_bytes(&[u8; 64])`) with `hazmat::raw_sign::<Sha512>(&esk, msg, &vk)`;
verification is the ordinary `VerifyingKey::verify`. So:

* `SecretKey` (64 bytes) stays the wire/state-compatible type; it converts to
  `ExpandedSecretKey` for signing and its public half is derivable.
* A seed-based constructor (`create_keypair(seed: [u8; 32])`) expands with
  SHA-512 and clamps exactly like libtorrent's `ed25519_create_keypair`, so
  both implementations produce identical keys from the same seed. WP3 tests
  it against `test_ed25519.cpp` (`ed25519_test_vec1` and the fixed key pair
  in `test_dht.cpp::get_test_keypair`, already exposed as
  `testing::test_keypair()`).
* Verification strictness: libtorrent's verify is the reference
  (non-strict) algorithm. WP3 must check that `verify` (not `verify_strict`)
  accepts everything libtorrent accepts, and add a regression test for any
  divergence found against the BEP 44 test vectors.

## 4. Message handling

Datagrams are decoded zero-copy into `bencode::Node` (borrowing the buffer),
validated by declarative `msg::KeyDesc` tables via `verify_message` (port of
`verify_message_impl`, same error strings), and answered with
`bencode::Entry` values. BEP 44 signs the *raw bytes* of the `v` value, so
`Node::data_section` returns exact source slices; nothing re-encodes what it
verifies.

## 5. Public API sketch (consumer view)

```rust
// Construction. Settings and state are plain values.
let settings = DhtSettings::default();
let state    = DhtState::load(&bytes)?;           // or DhtState::default()
let mut dht  = Dht::builder(settings)
    .state(state)
    .storage(Box::new(DefaultStorage::new(&settings)))   // or your own
    .build();

// tokio driver (feature `tokio-driver`)
let handle = DhtHandle::bind("0.0.0.0:6881".parse()?, dht).await?;

handle.bootstrap(["router.bittorrent.com:6881"]).await?;

// BEP 5
let peers: PeerStream = handle.get_peers(info_hash);      // Stream<Item = Vec<SocketAddr>>
handle.announce(info_hash, listen_port, AnnounceFlags::SEED).await?;

// BEP 44
let target = handle.put_immutable(Entry::from("hello")).await?;
let item   = handle.get_immutable(target).await?;
handle.put_mutable(&secret_key, salt, |current| next_value).await?;   // CAS via seq
let item   = handle.get_mutable(public_key, salt).await?;

// BEP 51
let sample = handle.sample_infohashes(node_endpoint, target).await?;

// BEP 33
let scrape = handle.scrape(info_hash).await?;            // seeds/downloaders estimate

// Observability: a stream of Event (alerts) the owner can ignore or log.
let mut events = handle.events();                        // incoming/outgoing queries,
                                                         // routing bucket changes, errors
// Persistence
let bytes = handle.save_state().await?.encode();         // node IDs + routing nodes
```

Without tokio the same operations are methods on `Dht` taking `now` and
returning the datagrams to send; see `Node` in PORTING.md WP4.

## 6. Engineering rules (from `skills/`)

`#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`; every item documented
with the libtorrent function it corresponds to; tests only in `tests/`
(porting libtorrent's cases under snake_case names with a comment naming the
`TEST_CASE`); every parser/loader of untrusted input has a cargo-fuzz target
with a committed corpus; every crash becomes a named regression test;
`make ci` is the gate and is run before each push.
