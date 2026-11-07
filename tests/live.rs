//! Opt-in interoperability checks against the real Mainline DHT.
//!
//! These tests are `#[ignore]`d: they need the Internet and take a while.
//! Run them by hand with
//!
//! ```text
//! cargo test --release --features tokio-driver --test live -- --ignored --nocapture
//! ```
//!
//! They bind an ephemeral UDP port on all interfaces and talk to the public
//! routers. Nothing is asserted about other people's nodes beyond "the
//! DHT answers": a router being down is a failure of the environment, not
//! of this crate, so read the output.

#![cfg(feature = "tokio-driver")]

use std::sync::Arc;
use std::time::Duration;

use cloudllm_dht::bencode::Entry;
use cloudllm_dht::driver::DhtHandle;
use cloudllm_dht::ed25519::{create_keypair, create_seed};
use cloudllm_dht::item::Item;
use cloudllm_dht::rng::SystemRng;
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::types::SequenceNumber;
use cloudllm_dht::Sha1Hash;

/// The public bootstrap nodes.
const ROUTERS: [&str; 4] = [
    "router.bittorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "router.utorrent.com:6881",
    "dht.libtorrent.org:25401",
];

/// The info-hash of the Sintel test torrent, which has had peers for years.
const WELL_KNOWN: &str = "08ada5a7a6183aae1e09d831df6748d566095a10";

async fn joined() -> DhtHandle {
    let dht = DhtHandle::bind(&["0.0.0.0:0".parse().unwrap()], DhtSettings::default())
        .await
        .expect("bind");
    tokio::time::timeout(Duration::from_secs(60), dht.bootstrap(&ROUTERS))
        .await
        .expect("bootstrap finished in time")
        .expect("at least one router resolved");
    dht
}

/// Bootstraps and finds peers for a well-known info-hash (BEP 5).
#[tokio::test]
#[ignore = "needs the Internet"]
async fn live_bootstrap_and_get_peers() {
    let dht = joined().await;
    let st = dht.save_state().await.expect("state");
    println!(
        "routing table endpoints after bootstrap: {}",
        st.nodes.len()
    );
    assert!(!st.nodes.is_empty(), "the routing table stayed empty");
    let ih = Sha1Hash::from_hex(WELL_KNOWN).expect("hex");
    let peers = dht.lookup_peers(ih, Duration::from_secs(30)).await;
    println!("found {} peers, e.g. {:?}", peers.len(), peers.first());
    assert!(!peers.is_empty(), "no peers for {WELL_KNOWN}");
}

/// Stores an immutable and a mutable item (BEP 44) and reads both back.
/// Only some nodes implement BEP 44, so the put may reach few nodes.
#[tokio::test]
#[ignore = "needs the Internet"]
async fn live_bep44_roundtrip() {
    let dht = joined().await;

    let v = Entry::from(format!("cloudllm_dht live test {}", std::process::id()));
    let (target, acks) = dht.put_immutable(v.clone()).await.expect("put finished");
    println!("immutable put {target} acknowledged by {acks} nodes");
    assert!(acks > 0, "no node accepted the immutable put");
    assert_eq!(dht.get_immutable(target).await, Some(v));

    let (pk, sk) = create_keypair(&create_seed(&mut SystemRng));
    let salt = b"cloudllm_dht";
    let cb = Arc::new(move |i: &mut Item| {
        let seq = SequenceNumber(i.seq().0 + 1);
        *i = Item::signed(Entry::from("live mutable"), salt, seq, &pk, &sk).expect("small item");
    });
    let acks = dht.put_mutable(pk, salt, cb).await.expect("put finished");
    println!("mutable put acknowledged by {acks} nodes");
    assert!(acks > 0, "no node accepted the mutable put");
    let item = dht.get_mutable(pk, salt).await.expect("item found");
    assert_eq!(item.value(), &Entry::from("live mutable"));
}
