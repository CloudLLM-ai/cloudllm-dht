//! Fuzzes the whole receive path of a node: `Dht::incoming_packet` with
//! arbitrary bytes from arbitrary endpoints (the pre-filter, the DoS
//! blocker, the bounded decode and the query handlers on top of real
//! routing table and storage), the port of libtorrent's `dht_node.cpp`
//! fuzzer.
//!
//! Input layout: the first byte picks the sender (a handful of IPv4
//! addresses, so the DoS blocker and the routing table both see repeats),
//! the rest is the datagram. Datagrams are also offered in a second shape
//! that is a valid query with fuzzed `a`-dictionary bytes spliced in.
//!
//! Invariants: no panic; every datagram the node sends decodes, has `y` of
//! `q`, `r` or `e` and carries `t` (the queries we send ourselves have it
//! too); a response to a query echoes its `t`; an error response carries
//! `e` as `[int, string]`; the routing table passes its own invariant
//! check afterwards.
#![no_main]

use std::net::SocketAddr;
use std::time::Duration;

use cloudllm_dht::bencode::{decode, NodeKind};
use cloudllm_dht::rng::TestRng;
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::time::Time;
use cloudllm_dht::tracker::Dht;
use libfuzzer_sys::fuzz_target;

fn check_outgoing(payload: &[u8], query_t: Option<&[u8]>) {
    let m = decode(payload).expect("everything the node sends decodes");
    assert_eq!(m.kind(), NodeKind::Dict);
    let y = m.dict_find_string_value(b"y", b"");
    assert!(matches!(y, b"q" | b"r" | b"e"), "bad y {y:?}");
    assert!(m.dict_find_string(b"t").is_some(), "missing t");
    if y == b"e" {
        let e = m.dict_find_list(b"e").expect("an error has e");
        assert_eq!(e.list_len(), 2);
        assert!(e.list_at(0).is_some_and(|n| n.kind() == NodeKind::Int));
        assert!(e.list_at(1).is_some_and(|n| n.kind() == NodeKind::Str));
    }
    if y != b"q" {
        if let Some(t) = query_t {
            assert_eq!(m.dict_find_string_value(b"t", b""), t);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&who, body)) = data.split_first() else { return };
    let mut now = Time::ZERO + Duration::from_secs(1000);
    let settings = DhtSettings {
        enforce_node_id: who & 0x80 != 0,
        ..DhtSettings::default()
    };
    let mut dht = Dht::builder(settings)
        .rng(Box::new(TestRng::new(u64::from(who))))
        .build();
    let local: SocketAddr = "93.184.216.34:6881".parse().unwrap();
    let sock = dht.add_socket(local, Some(local.ip()), now);
    let from: SocketAddr = format!("198.51.100.{}:{}", who & 7, 1000 + u16::from(who)).parse().unwrap();

    let query_t = decode(body)
        .ok()
        .map(|m| m.dict_find_string_value(b"t", b"").to_vec());

    for _ in 0..2 {
        dht.incoming_packet(sock, from, body, now);
        now = now + Duration::from_millis(200);
        dht.poll(now);
        while let Some(d) = dht.poll_transmit() {
            check_outgoing(&d.payload, query_t.as_deref());
        }
    }
    // a valid query shell around the fuzzed bytes as the argument values
    let mut shell = b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaa9:info_hash20:".to_vec();
    shell.extend(body.iter().chain([0u8; 20].iter()).take(20));
    shell.extend_from_slice(b"e1:q9:get_peers1:t2:zz1:y1:qe");
    dht.incoming_packet(sock, from, &shell, now);
    while let Some(d) = dht.poll_transmit() {
        check_outgoing(&d.payload, Some(b"zz"));
    }
    if let Some(node) = dht.node(sock) {
        node.table().check_invariants().expect("routing table invariants");
    }
});
