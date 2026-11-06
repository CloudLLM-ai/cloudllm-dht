//! Tests of the tokio driver over real loopback UDP sockets (ephemeral
//! ports only). Not a libtorrent port: nothing here touches the Internet.

#![cfg(feature = "tokio-driver")]

use std::sync::Arc;
use std::time::Duration;

use cloudllm_dht::announce_flags::AnnounceFlags;
use cloudllm_dht::bencode::Entry;
use cloudllm_dht::driver::DhtHandle;
use cloudllm_dht::ed25519::create_keypair;
use cloudllm_dht::item::Item;
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::types::SequenceNumber;
use cloudllm_dht::Sha1Hash;

fn settings() -> DhtSettings {
    DhtSettings {
        restrict_routing_ips: false,
        ..DhtSettings::default()
    }
}

async fn node() -> DhtHandle {
    DhtHandle::bind(&["127.0.0.1:0".parse().unwrap()], settings())
        .await
        .expect("bind loopback")
}

/// Three nodes on loopback: the others bootstrap from the first.
async fn swarm() -> Vec<DhtHandle> {
    let a = node().await;
    let seed = a.local_addrs()[0];
    let mut all = vec![a];
    for _ in 0..2 {
        let n = node().await;
        tokio::time::timeout(Duration::from_secs(20), n.bootstrap_endpoints(vec![seed]))
            .await
            .expect("bootstrap finishes");
        all.push(n);
    }
    all
}

/// An immutable item put through one node can be fetched through another.
#[tokio::test]
async fn test_driver_immutable_roundtrip() {
    let nodes = swarm().await;
    let v = Entry::from("loopback value");
    let (target, acks) = nodes[1].put_immutable(v.clone()).await.expect("put done");
    assert!(acks >= 1, "acknowledged by {acks}");
    let got = nodes[2].get_immutable(target).await;
    assert_eq!(got, Some(v));
}

/// A mutable item round-trips and a newer sequence number replaces it.
#[tokio::test]
async fn test_driver_mutable_roundtrip() {
    let nodes = swarm().await;
    let (pk, sk) = create_keypair(&[7u8; 32]);
    for (seq, text) in [(1i64, "first"), (2, "second")] {
        let cb = Arc::new(move |i: &mut Item| {
            *i = Item::signed(Entry::from(text), b"s", SequenceNumber(seq), &pk, &sk)
                .expect("small item");
        });
        let acks = nodes[1].put_mutable(pk, b"s", cb).await.expect("put done");
        assert!(acks >= 1);
    }
    let item = nodes[2].get_mutable(pk, b"s").await.expect("found");
    assert_eq!(item.value(), &Entry::from("second"));
    assert_eq!(item.seq(), SequenceNumber(2));
}

/// Announce then look up: the announcing node's port comes back.
#[tokio::test]
async fn test_driver_announce_and_get_peers() {
    let nodes = swarm().await;
    let ih = Sha1Hash([9; 20]);
    nodes[1].announce(ih, 4242, AnnounceFlags::EMPTY);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let peers = nodes[2].lookup_peers(ih, Duration::from_secs(2)).await;
    assert!(peers.iter().any(|p| p.port() == 4242), "peers: {peers:?}");
}

/// State can be saved, and a direct request gets an answer.
#[tokio::test]
async fn test_driver_state_and_direct_request() {
    let nodes = swarm().await;
    let st = nodes[1].save_state().await.expect("state");
    assert_eq!(st.nids.len(), 1);
    assert!(!st.nodes.is_empty());
    let mut ping = Entry::dict();
    ping.set("q", "ping");
    let r = nodes[1]
        .direct_request(nodes[0].local_addrs()[0], ping)
        .await
        .expect("answered");
    assert_eq!(r.get("y"), Some(&Entry::from("r")));
}
