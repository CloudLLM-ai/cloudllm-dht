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
    let found = nodes[1].announce(ih, 4242, AnnounceFlags::EMPTY).await;
    assert!(found.is_some(), "the announce completed");
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

/// Two concurrent gets of one immutable target, and two concurrent puts of
/// one mutable slot, each get their own answer through the handle.
#[tokio::test]
async fn test_driver_concurrent_same_target_operations() {
    let nodes = swarm().await;
    let v = Entry::from("concurrent value");
    let (target, _) = nodes[1].put_immutable(v.clone()).await.expect("put");
    let (a, b) = tokio::join!(
        nodes[2].get_immutable(target),
        nodes[2].get_immutable(target)
    );
    assert_eq!(a, Some(v.clone()));
    assert_eq!(b, Some(v));

    let (pk, sk) = create_keypair(&[9u8; 32]);
    let cb = |text: &'static str| {
        Arc::new(move |i: &mut Item| {
            let seq = SequenceNumber(i.seq().0.max(0) + 1);
            *i = Item::signed(Entry::from(text), b"c", seq, &pk, &sk).expect("small item");
        })
    };
    let (p1, p2) = tokio::join!(
        nodes[1].put_mutable(pk, b"c", cb("first")),
        nodes[1].put_mutable(pk, b"c", cb("second"))
    );
    assert!(p1.is_some_and(|n| n >= 1) && p2.is_some_and(|n| n >= 1));
    let (m1, m2) = tokio::join!(
        nodes[2].get_mutable(pk, b"c"),
        nodes[2].get_mutable(pk, b"c")
    );
    let (m1, m2) = (m1.expect("found"), m2.expect("found"));
    assert_eq!(m1.seq(), SequenceNumber(2));
    assert_eq!(m2.value(), &Entry::from("second"));
}

/// Shutting the handle down resolves requests that cannot complete to
/// `None` instead of hanging.
#[tokio::test]
async fn test_driver_shutdown_resolves_pending_requests() {
    let nodes = swarm().await;
    let h = nodes[1].clone();
    let pending = tokio::spawn(async move { h.get_immutable(Sha1Hash([4; 20])).await });
    tokio::time::sleep(Duration::from_millis(5)).await;
    nodes[1].shutdown();
    let r = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .expect("resolved after shutdown")
        .expect("task ok");
    assert_eq!(r, None);
}

/// `lookup_peers` returns as soon as the lookup has finished, well before
/// its timeout, and the peer stream ends by itself.
#[tokio::test]
async fn test_driver_lookup_completes_before_timeout() {
    let nodes = swarm().await;
    let ih = Sha1Hash([5; 20]);
    let started = std::time::Instant::now();
    let _ = nodes[2].lookup_peers(ih, Duration::from_secs(60)).await;
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "took {:?}",
        started.elapsed()
    );
    let mut stream = nodes[2].get_peers(ih);
    let closed = tokio::time::timeout(Duration::from_secs(30), async {
        while stream.recv().await.is_some() {}
    })
    .await;
    assert!(closed.is_ok(), "the stream ended with the lookup");
}

/// Sampling and direct requests complete; a request to a silent endpoint
/// resolves to `None`.
#[tokio::test]
async fn test_driver_sample_and_direct_complete() {
    let nodes = swarm().await;
    let s = nodes[1]
        .sample_infohashes(nodes[0].local_addrs()[0], Sha1Hash([1; 20]))
        .await;
    assert!(s.is_some(), "a sample came back");
    let mut ping = Entry::dict();
    ping.set("q", "ping");
    let silent: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let r = tokio::time::timeout(
        Duration::from_secs(30),
        nodes[1].direct_request(silent, ping),
    )
    .await
    .expect("resolved");
    assert_eq!(r, None);
}
