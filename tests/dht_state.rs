//! Tests for `dht_state`: `TEST_CASE(dht_state)` of libtorrent
//! `test/test_dht.cpp` (RC_2_1, `86d573f2631b0162d3cca5e257217eaf530fdcba`)
//! and the loader's tolerance of hostile or old-format input.

use cloudllm_dht::bencode::{decode, Entry};
use cloudllm_dht::dht_state::{extract_node_ids, read_dht_state, save_dht_state, DhtState};
use cloudllm_dht::testing::{ep, to_hash};

fn load(bytes: &[u8]) -> DhtState {
    read_dht_state(&decode(bytes).unwrap())
}

/// Port of `TEST_CASE(dht_state)`: save, bencode, decode and read back
/// (IPv4 as in the original), and an empty document reads as empty. The
/// original comments out its IPv6 half because it needed a host with IPv6;
/// nothing here touches a socket, so it is exercised too.
#[test]
fn test_dht_state() {
    let mut s = DhtState::default();
    s.nids.push((
        "1.1.1.1".parse().unwrap(),
        to_hash("0000000000000000000000000000000000000001"),
    ));
    s.nodes.push(ep("1.1.1.1", 1));
    s.nodes.push(ep("2.2.2.2", 2));
    let bytes = save_dht_state(&s).encode();
    let s1 = load(&bytes);
    assert_eq!(s1.nids, s.nids);
    assert_eq!(s1.nodes, s.nodes);
    assert!(s1.nodes6.is_empty());

    let empty = read_dht_state(&decode(b"de").unwrap());
    assert!(empty.nids.is_empty() && empty.nodes.is_empty() && empty.nodes6.is_empty());
}

/// The IPv6 half the C++ test leaves commented out.
#[test]
fn test_dht_state_roundtrips_ipv6() {
    let mut s = DhtState::default();
    s.nids.push((
        "1::1".parse().unwrap(),
        to_hash("0000000000000000000000000000000000000002"),
    ));
    s.nids.push((
        "1.2.3.4".parse().unwrap(),
        to_hash("ff00000000000000000000000000000000000003"),
    ));
    s.nodes6.push(ep("1::1", 3));
    s.nodes6.push(ep("2::2", 4));
    s.nodes.push(ep("9.9.9.9", 65535));
    assert_eq!(load(&s.encode()), s);
    assert_eq!(DhtState::load(&s.encode()).unwrap(), s);
}

/// The wire layout is fixed: `node-id` is always written (empty list when
/// there are none), `nodes`/`nodes6` only when non-empty, and an entry is the
/// 20-byte id followed by the raw address.
#[test]
fn test_save_layout_matches_libtorrent() {
    assert_eq!(
        save_dht_state(&DhtState::default()).encode(),
        b"d7:node-idlee".to_vec()
    );
    let mut s = DhtState::default();
    s.nids.push((
        "1.2.3.4".parse().unwrap(),
        to_hash("0000000000000000000000000000000000000001"),
    ));
    s.nodes.push(ep("5.6.7.8", 0x1ae1));
    let e = save_dht_state(&s);
    // keys are sorted: "node-id" < "nodes"
    let mut want = b"d7:node-idl24:".to_vec();
    want.extend_from_slice(&to_hash("0000000000000000000000000000000000000001").0);
    want.extend_from_slice(&[1, 2, 3, 4]);
    want.extend_from_slice(b"e5:nodesl6:");
    want.extend_from_slice(&[5, 6, 7, 8, 0x1a, 0xe1]);
    want.extend_from_slice(b"ee");
    assert_eq!(e.encode(), want);
}

/// Old-style state holds the id as a single 20-byte string; it is read as
/// an id with the unspecified IPv4 address. A list value of the right type
/// takes the other path; a 20-byte string wins over everything else.
#[test]
fn test_extract_node_ids_old_style() {
    let doc = b"d7:node-id20:aaaaaaaaaaaaaaaaaaaae";
    let n = decode(doc).unwrap();
    let ids = extract_node_ids(&n, "node-id");
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].0.to_string(), "0.0.0.0");
    assert_eq!(ids[0].1 .0, [b'a'; 20]);
    // wrong length string is not an old-style id and not a list
    assert!(extract_node_ids(
        &decode(b"d7:node-id19:aaaaaaaaaaaaaaaaaaae").unwrap(),
        "node-id"
    )
    .is_empty());
}

/// The loader skips what it cannot use, entry by entry: strings shorter than
/// 20 bytes, lengths other than 24 and 36, non-string elements.
#[test]
fn test_extract_node_ids_skips_malformed_entries() {
    let id = [7u8; 20];
    let mut doc = b"d7:node-idl".to_vec();
    let mut push = |bytes: &[u8]| {
        doc.extend_from_slice(format!("{}:", bytes.len()).as_bytes());
        doc.extend_from_slice(bytes);
    };
    push(&id[..19]); // too short
    push(&[id.as_slice(), &[1, 2, 3]].concat()); // 23
    push(&[id.as_slice(), &[1, 2, 3, 4]].concat()); // 24: v4
    push(&[id.as_slice(), &[0; 5]].concat()); // 25
    push(&[id.as_slice(), &[0xab; 16]].concat()); // 36: v6
    push(&[id.as_slice(), &[0; 15]].concat()); // 35
    doc.extend_from_slice(b"i5e"); // not a string
    doc.extend_from_slice(b"e");
    doc.extend_from_slice(b"e");
    let ids = extract_node_ids(&decode(&doc).unwrap(), "node-id");
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0].0.to_string(), "1.2.3.4");
    assert_eq!(
        ids[1].0,
        "abab:abab:abab:abab:abab:abab:abab:abab"
            .parse::<std::net::IpAddr>()
            .unwrap()
    );
}

/// Anything that is not a dictionary reads as the empty state; so do keys of
/// the wrong type. None of it panics.
#[test]
fn test_read_dht_state_tolerates_wrong_shapes() {
    for doc in [
        &b"le"[..],
        b"i5e",
        b"3:abc",
        b"d7:node-idi1e5:nodesi2e6:nodes63:abce",
        b"d5:nodesd1:a1:bee",
    ] {
        assert_eq!(
            load(doc),
            DhtState::default(),
            "{}",
            String::from_utf8_lossy(doc)
        );
    }
    assert!(DhtState::load(b"d5:nodes").is_err());
    assert!(DhtState::load(b"").is_err());
}

/// `nodes` entries other than 6 or 18 bytes are skipped and a non-string
/// entry ends the list (libtorrent `read_endpoint_list`), keeping what was
/// read so far.
#[test]
fn test_read_dht_state_endpoint_list_edge_cases() {
    let mut doc = b"d5:nodesl6:".to_vec();
    doc.extend_from_slice(&[1, 2, 3, 4, 0, 80]);
    doc.extend_from_slice(b"5:abcde"); // 5 bytes: skipped
    doc.extend_from_slice(b"6:");
    doc.extend_from_slice(&[5, 6, 7, 8, 1, 0]);
    doc.extend_from_slice(b"i1e"); // stops here
    doc.extend_from_slice(b"6:");
    doc.extend_from_slice(&[9, 9, 9, 9, 0, 1]);
    doc.extend_from_slice(b"ee");
    let s = load(&doc);
    assert_eq!(s.nodes, vec![ep("1.2.3.4", 80), ep("5.6.7.8", 256)]);
}

/// `clear` returns to the default state.
#[test]
fn test_clear_resets_everything() {
    let mut s = DhtState::default();
    s.nodes.push(ep("1.2.3.4", 1));
    s.nodes6.push(ep("1::1", 1));
    s.nids.push((
        "1.1.1.1".parse().unwrap(),
        to_hash("0000000000000000000000000000000000000001"),
    ));
    s.clear();
    assert_eq!(s, DhtState::default());
    assert_eq!(Entry::dict().encode(), b"de".to_vec());
}
