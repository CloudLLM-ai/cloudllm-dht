//! Tests for the `testing` harness, `time` and `rng`: the helpers porters
//! rely on must themselves be trustworthy. The harness mirrors the helpers
//! of libtorrent `test/test_dht.cpp` (RC_2_1,
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`).

use std::collections::BTreeSet;
use std::time::Duration;

use cloudllm_dht::bencode::{decode, Entry};
use cloudllm_dht::rng::{Rng, SystemRng, TestRng};
use cloudllm_dht::testing::{
    add_and_replace, build_query, build_response, ep, rand_v4, rand_v6, test_keypair, to_hash,
    write_peers, Encoded, MockSocket, MsgArgs,
};
use cloudllm_dht::time::{Clock, ManualClock, SystemClock, Time};
use cloudllm_dht::transport::Transport;
use cloudllm_dht::types::{PublicKey, SecretKey, SequenceNumber};

/// The mock socket records packets per destination and `take_packet`
/// removes the first for that endpoint (libtorrent `find_packet` + erase).
#[test]
fn test_mock_socket_records_and_takes_packets() {
    let mut s = MockSocket::new();
    let a = ep("1.2.3.4", 1);
    let b = ep("5.6.7.8", 2);
    assert!(s.has_quota());
    assert!(s.send_packet(&Entry::Int(1), a));
    assert!(s.send_packet(&Entry::Int(2), b));
    assert!(s.send_packet(&Entry::Int(3), a));
    assert_eq!(s.find_packet(b), Some(1));
    assert_eq!(s.take_packet(a), Some(Entry::Int(1)));
    assert_eq!(s.take_packet(a), Some(Entry::Int(3)));
    assert_eq!(s.take_packet(a), None);
    s.out_of_quota = true;
    assert!(!s.has_quota());
    s.clear();
    assert!(s.sent.is_empty());
}

/// `build_query` produces what `send_dht_request` sends, and inserts a
/// random `id` only when the arguments have none.
#[test]
fn test_build_query_inserts_id_only_when_missing() {
    let mut rng = TestRng::new(1);
    let q = build_query("get_peers", &MsgArgs::new().port(5), "10", &mut rng);
    let enc = Encoded::from_entry(&q);
    let n = enc.node();
    assert_eq!(n.dict_find_string_value(b"q", b""), b"get_peers");
    assert_eq!(n.dict_find_string_value(b"t", b""), b"10");
    assert_eq!(n.dict_find_string_value(b"y", b""), b"q");
    let a = n.dict_find_dict(b"a").unwrap();
    assert_eq!(a.dict_find_int_value(b"port", 0), 5);
    assert_eq!(a.dict_find_string(b"id").unwrap().string_length(), 20);

    let fixed = to_hash("0102030405060708090a0b0c0d0e0f1011121314");
    let q = build_query("ping", &MsgArgs::new().nid(&fixed), "aa", &mut rng);
    assert_eq!(
        q.get("a").unwrap().get("id").unwrap().as_bytes(),
        Some(&fixed.0[..])
    );
}

/// `build_response` echoes the transaction id.
#[test]
fn test_build_response() {
    let mut rng = TestRng::new(2);
    let r = build_response(b"tx", &MsgArgs::new().token(b"tok"), &mut rng);
    let enc = Encoded::from_entry(&r);
    let n = enc.node();
    assert_eq!(n.dict_find_string_value(b"y", b""), b"r");
    assert_eq!(n.dict_find_string_value(b"t", b""), b"tx");
    assert_eq!(
        n.dict_find_dict(b"r")
            .unwrap()
            .dict_find_string_value(b"token", b""),
        b"tok"
    );
}

/// Every `MsgArgs` setter writes the key libtorrent's setter writes.
#[test]
fn test_msg_args_setters() {
    let h = to_hash("0102030405060708090a0b0c0d0e0f1011121314");
    let (pk, _) = test_keypair();
    let peers: BTreeSet<_> = [ep("1.2.3.4", 5)].into_iter().collect();
    let a = MsgArgs::new()
        .info_hash(&h)
        .name("n")
        .token(b"t")
        .port(1)
        .target(&h)
        .value(Entry::from("v"))
        .scrape(true)
        .seed(false)
        .key(&pk)
        .seq(SequenceNumber(3))
        .cas(SequenceNumber(2))
        .salt(b"")
        .want("n4")
        .want("n6")
        .nodes(b"")
        .nodes6(b"xx")
        .peers(&peers)
        .interval(7)
        .num(8)
        .samples(&[h, h])
        .a;
    for k in [
        "info_hash",
        "n",
        "token",
        "port",
        "target",
        "v",
        "scrape",
        "seed",
        "k",
        "seq",
        "cas",
        "want",
        "nodes6",
        "values",
        "interval",
        "num",
        "samples",
    ] {
        assert!(a.get(k).is_some(), "missing {k}");
    }
    assert!(a.get("salt").is_none(), "empty salt is skipped");
    assert!(a.get("nodes").is_none(), "empty nodes is skipped");
    assert_eq!(a.get("want").unwrap().as_list().unwrap().len(), 2);
    assert_eq!(a.get("scrape").unwrap().as_int(), Some(1));
    assert_eq!(a.get("samples").unwrap().as_bytes().unwrap().len(), 40);
}

/// The fixed BEP 44 test key pair has the right shape.
#[test]
fn test_keypair_lengths() {
    let (pk, sk) = test_keypair();
    assert_eq!(pk.as_bytes().len(), PublicKey::LEN);
    assert_eq!(sk.as_bytes().len(), SecretKey::LEN);
    assert_eq!(format!("{sk:?}"), "SecretKey(<redacted>)");
    assert_eq!(pk.0[0], 0x77);
}

/// `add_and_replace` carries across bytes and wraps at 2^160.
#[test]
fn test_add_and_replace() {
    let mut d = to_hash("00000000000000000000000000000000000000ff");
    add_and_replace(&mut d, &to_hash("0000000000000000000000000000000000000001"));
    assert_eq!(d, to_hash("0000000000000000000000000000000000000100"));
    let mut m = to_hash("ffffffffffffffffffffffffffffffffffffffff");
    add_and_replace(&mut m, &to_hash("0000000000000000000000000000000000000001"));
    assert_eq!(m, to_hash("0000000000000000000000000000000000000000"));
}

/// `write_peers` emits one compact string per peer.
#[test]
fn test_write_peers() {
    let peers: BTreeSet<_> = [ep("1.2.3.4", 1), ep("2001:db8::1", 2)]
        .into_iter()
        .collect();
    let e = write_peers(&peers);
    let lens: Vec<_> = e
        .as_list()
        .unwrap()
        .iter()
        .map(|p| p.as_bytes().unwrap().len())
        .collect();
    assert_eq!(lens, [6, 18]);
}

/// Random addresses are never local, so BEP 42 verification applies.
#[test]
fn test_rand_addresses_are_public() {
    let mut rng = TestRng::new(8);
    for _ in 0..1000 {
        assert!(!cloudllm_dht::net::is_local(rand_v4(&mut rng)));
        assert!(rand_v6(&mut rng).is_ipv6());
    }
}

/// `TestRng` is reproducible; `random(max)` is inclusive and in range;
/// `SystemRng` produces varying output.
#[test]
fn test_rng() {
    let (mut a, mut b) = (TestRng::new(99), TestRng::new(99));
    let xs: Vec<_> = (0..16).map(|_| a.next_u32()).collect();
    let ys: Vec<_> = (0..16).map(|_| b.next_u32()).collect();
    assert_eq!(xs, ys);
    let mut r = TestRng::new(1);
    let mut seen = [false; 8];
    for _ in 0..1000 {
        let v = r.random(7);
        assert!(v <= 7);
        seen[v as usize] = true;
    }
    assert!(seen.iter().all(|s| *s), "random(7) reaches 0..=7");
    assert_eq!(r.random(0), 0);
    let _ = r.random(u32::MAX);
    let mut s = SystemRng;
    assert_ne!(s.random_hash(), s.random_hash());
    let mut odd = [0u8; 13];
    r.fill_bytes(&mut odd);
    assert!(odd.iter().any(|b| *b != 0));
}

/// `ManualClock` moves only when advanced and clones share a timeline;
/// `Time` arithmetic saturates.
#[test]
fn test_clock_and_time() {
    let c = ManualClock::new();
    let c2 = c.clone();
    assert_eq!(c.now(), Time::ZERO);
    c.advance(Duration::from_secs(3));
    assert_eq!(c2.now().as_duration(), Duration::from_secs(3));
    let t = c.now() + Duration::from_secs(2);
    assert_eq!(t - c.now(), Duration::from_secs(2));
    assert_eq!(c.now() - t, Duration::ZERO);
    assert_eq!(Time::ZERO - Duration::from_secs(1), Time::ZERO);
    let real = SystemClock::new();
    assert!(real.now() <= real.now() + Duration::from_secs(1));
    assert!(SystemClock::default().now() < Time::from_duration(Duration::from_secs(60)));
}

/// `Encoded` hands out a node whose raw bytes are the entry's encoding.
#[test]
fn test_encoded_roundtrip() {
    let mut e = Entry::dict();
    e.set("a", 1);
    let enc = Encoded::from_entry(&e);
    assert_eq!(enc.bytes(), b"d1:ai1ee");
    assert_eq!(decode(enc.bytes()).unwrap().data_section(), enc.bytes());
}
