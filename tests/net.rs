//! Tests for `net`: compact endpoint and node encodings (BEP 5, BEP 32) and
//! the local-address classification used by BEP 42 verification.
//! Behaviour follows libtorrent `socket_io.hpp`, `io.hpp` and
//! `ip_helpers.cpp` (RC_2_1, `86d573f2631b0162d3cca5e257217eaf530fdcba`).

use std::collections::BTreeSet;

use cloudllm_dht::bencode::decode;
use cloudllm_dht::net::{
    is_link_local, is_local, read_endpoint, read_endpoint_list, read_node_endpoint, read_nodes,
    write_endpoint, write_nodes, write_nodes_entry, NodeEndpoint, Protocol,
};
use cloudllm_dht::testing::{addr4, addr6, ep, to_hash, write_peers};

/// IPv4 and IPv6 endpoints roundtrip through the compact form.
#[test]
fn test_endpoint_roundtrip() {
    for e in [
        ep("1.2.3.4", 6881),
        ep("255.0.0.1", 1),
        ep("2001:db8::1", 65535),
    ] {
        let mut b = Vec::new();
        write_endpoint(&e, &mut b);
        let p = Protocol::of(&e.ip());
        assert_eq!(b.len(), p.endpoint_len());
        assert_eq!(read_endpoint(p, &b), Some(e));
    }
}

/// The port is big-endian.
#[test]
fn test_endpoint_port_is_big_endian() {
    let mut b = Vec::new();
    write_endpoint(&ep("1.2.3.4", 0x1ae1), &mut b);
    assert_eq!(b, [1, 2, 3, 4, 0x1a, 0xe1]);
}

/// Truncated input is rejected, not read out of bounds.
#[test]
fn test_read_endpoint_truncated() {
    assert_eq!(read_endpoint(Protocol::V4, &[1, 2, 3, 4, 5]), None);
    assert_eq!(read_endpoint(Protocol::V6, &[0; 17]), None);
    assert_eq!(read_endpoint(Protocol::V4, &[]), None);
}

/// Family constants match BEP 5 and BEP 32.
#[test]
fn test_protocol_constants() {
    assert_eq!(Protocol::V4.node_len(), 26);
    assert_eq!(Protocol::V6.node_len(), 38);
    assert_eq!(Protocol::V4.nodes_key(), "nodes");
    assert_eq!(Protocol::V6.nodes_key(), "nodes6");
    assert_eq!(Protocol::V4.want_key(), "n4");
    assert_eq!(Protocol::V6.want_key(), "n6");
}

/// Packed nodes roundtrip for both families.
#[test]
fn test_nodes_roundtrip() {
    for (proto, a, b) in [
        (Protocol::V4, ep("1.2.3.4", 1), ep("5.6.7.8", 2)),
        (Protocol::V6, ep("2001:db8::1", 3), ep("2001:db8::2", 4)),
    ] {
        let id1 = to_hash("0102030405060708090a0b0c0d0e0f1011121314");
        let id2 = to_hash("ffffffffffffffffffffffffffffffffffffffff");
        let packed = write_nodes([(&id1, &a), (&id2, &b)]);
        assert_eq!(packed.len(), 2 * proto.node_len());
        assert_eq!(
            read_nodes(proto, &packed),
            vec![
                NodeEndpoint { id: id1, ep: a },
                NodeEndpoint { id: id2, ep: b }
            ]
        );
        assert_eq!(
            write_nodes_entry([(&id1, &a)]).as_bytes().unwrap().len(),
            proto.node_len()
        );
    }
}

/// A trailing partial node is ignored.
#[test]
fn test_read_nodes_ignores_trailing_bytes() {
    let id = to_hash("0102030405060708090a0b0c0d0e0f1011121314");
    let mut packed = write_nodes([(&id, &ep("1.2.3.4", 1))]);
    packed.extend_from_slice(&[0xaa; 10]);
    assert_eq!(read_nodes(Protocol::V4, &packed).len(), 1);
    assert_eq!(read_node_endpoint(Protocol::V4, &packed[..25]), None);
}

/// `read_endpoint_list` takes 6- and 18-byte strings, skips other lengths,
/// and stops at a non-string like libtorrent.
#[test]
fn test_read_endpoint_list() {
    let peers: BTreeSet<_> = [ep("1.2.3.4", 1), ep("2001:db8::1", 2)]
        .into_iter()
        .collect();
    let enc = write_peers(&peers).encode();
    let n = decode(&enc).unwrap();
    let got: BTreeSet<_> = read_endpoint_list(&n).into_iter().collect();
    assert_eq!(got, peers);

    let mixed = decode(b"l6:\x01\x02\x03\x04\x00\x011:xi5e6:\x05\x06\x07\x08\x00\x02e").unwrap();
    assert_eq!(read_endpoint_list(&mixed), vec![ep("1.2.3.4", 1)]);
    assert!(read_endpoint_list(&decode(b"i1e").unwrap()).is_empty());
}

/// `is_local` follows libtorrent's ranges.
#[test]
fn test_is_local() {
    for a in [
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "169.254.1.1",
        "127.0.0.1",
    ] {
        assert!(is_local(addr4(a)), "{a}");
    }
    for a in ["172.15.0.1", "172.32.0.1", "8.8.8.8", "192.169.0.1"] {
        assert!(!is_local(addr4(a)), "{a}");
    }
    for a in [
        "::1", "fe80::1", "fec0::1", "fc00::1", "fd12::1", "ff02::1", "ff05::1",
    ] {
        assert!(is_local(addr6(a)), "{a}");
    }
    for a in ["2001:db8::1", "2a00::1", "ff0e::1"] {
        assert!(!is_local(addr6(a)), "{a}");
    }
}

/// `is_link_local` is narrower than `is_local`.
#[test]
fn test_is_link_local() {
    assert!(is_link_local(addr4("169.254.3.4")));
    assert!(!is_link_local(addr4("10.0.0.1")));
    assert!(is_link_local(addr6("fe80::1")));
    assert!(!is_link_local(addr6("fc00::1")));
}
