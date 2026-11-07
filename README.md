# cloudllm_dht

The BitTorrent Mainline DHT as a **sans-IO Rust library**, ported from
[libtorrent](https://github.com/arvidn/libtorrent)'s Kademlia implementation
(branch `RC_2_1`).

Target feature set (everything libtorrent RC_2_1 implements): BEP 5 (DHT),
BEP 32 (IPv6), BEP 33 (scrape, bloom filters), BEP 42 (node ID security),
BEP 43 (read-only nodes), BEP 44 (immutable and mutable items, salt, CAS),
BEP 51 (`sample_infohashes`), the routing table with replacement buckets,
RPC timeouts, traversal algorithms, the DoS blocker, rate limits, state
persistence and settings.

The node, routing table, RPC manager, traversals and storage are
deterministic state machines driven by `(datagram, endpoint, now)`, with an
injectable clock and RNG; a thin tokio UDP driver sits on top behind the
`tokio-driver` feature. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Using it

With the `tokio-driver` feature the whole DHT is one async handle:

```rust,ignore
use cloudllm_dht::driver::DhtHandle;
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::bencode::Entry;
use std::time::Duration;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let dht = DhtHandle::bind(&["0.0.0.0:6881".parse().unwrap()], DhtSettings::default()).await?;
    dht.bootstrap(&["router.bittorrent.com:6881", "dht.libtorrent.org:25401"]).await?;

    // BEP 5: who has this torrent?
    let ih = cloudllm_dht::Sha1Hash::from_hex("08ada5a7a6183aae1e09d831df6748d566095a10").unwrap();
    let peers = dht.lookup_peers(ih, Duration::from_secs(10)).await;
    println!("{} peers", peers.len());

    // BEP 44: store and fetch an immutable item
    let (target, acks) = dht.put_immutable(Entry::from("hello")).await.unwrap();
    println!("stored under {target} on {acks} nodes: {:?}", dht.get_immutable(target).await);

    // keep the routing table across restarts
    let saved = dht.save_state().await.unwrap().encode();
    std::fs::write("dht.state", saved)?;
    Ok(())
}
```

`DhtHandle` also offers `announce`, `get_mutable`/`put_mutable` (BEP 44 with
salt and compare-and-swap through the data callback), `sample_infohashes`
(BEP 51), `direct_request`, and `events()` for a stream of everything the
node notices. To use another runtime, or none, drive `tracker::Dht` yourself:
feed it `incoming_packet(socket, from, bytes, now)`, send what
`poll_transmit()` yields, call `poll(now)` when `next_timeout()` says so,
read `poll_event()`. `tests/sim_dht.rs` runs thousands of nodes this way in
memory, deterministically.

`cargo test --release --features tokio-driver --test live -- --ignored
--nocapture` checks interoperability against the real Mainline DHT.

**Status:** under construction. [docs/PORTING.md](docs/PORTING.md) maps every
libtorrent source file and test case to its Rust module and says what is done.

## Engineering

The crate follows the house standards in [skills/](skills/): `make ci`
(fmt, check, clippy `-D warnings`, tests, rustdoc `-D warnings`),
`make msrv` (Rust 1.88), `make fuzz-build` / `make fuzz-replay` / `make fuzz
TARGET=...` (nightly, cargo-fuzz). No `unsafe`. Every public item is
documented; tests live in `tests/` and port libtorrent's test cases under
snake_case names with a comment naming the original `TEST_CASE`.

## License and attribution

BSD-3-Clause. This crate is a derivative work of libtorrent
(Copyright (c) 2003-2022 Arvid Norberg and contributors, BSD-3-Clause);
libtorrent's copyright notice is retained in [LICENSE](LICENSE) next to
"Copyright (c) 2026 CloudLLM-ai contributors". See [NOTICE](NOTICE). The
C++ source is not vendored: this is a fresh Rust implementation following
the same algorithms, with per-module provenance (libtorrent file and commit
`86d573f2631b0162d3cca5e257217eaf530fdcba`) in each module's rustdoc.
