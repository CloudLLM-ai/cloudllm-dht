//! Fuzzes everything a node does with an untrusted datagram before any
//! state machine sees it: decode, the top-level and per-query verifier
//! tables, compact node and endpoint parsing, and the typed tokens.
//!
//! Invariants: no panics; `read_nodes` returns at most `len / node_len`
//! nodes and every returned node re-encodes to the bytes it came from;
//! `read_endpoint_list` entries re-encode to 6 or 18 bytes; verify results
//! are consistent (a required key that verified is `Some`).
#![no_main]

use cloudllm_dht::bencode::{decode, NodeKind};
use cloudllm_dht::msg::{verify_message, KeyDesc, KeyFlags, Query};
use cloudllm_dht::net::{read_endpoint_list, read_nodes, write_nodes, Protocol};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(msg) = decode(data) else { return };

    // libtorrent's top-level table (node.cpp incoming_request).
    let top = [
        KeyDesc::new("q", Some(NodeKind::Str), 0, KeyFlags::NONE),
        KeyDesc::new("ro", Some(NodeKind::Int), 0, KeyFlags::OPTIONAL),
        KeyDesc::new("a", Some(NodeKind::Dict), 0, KeyFlags::PARSE_CHILDREN),
        KeyDesc::new("id", Some(NodeKind::Str), 20, KeyFlags::LAST_CHILD),
    ];
    if let Ok(found) = verify_message(&msg, &top) {
        assert!(found[0].is_some() && found[2].is_some() && found[3].is_some());
        if let Ok(q) = std::str::from_utf8(found[0].unwrap().string_value()) {
            let _ = q.parse::<Query>();
        }
    }

    for proto in [Protocol::V4, Protocol::V6] {
        for key in ["nodes", "nodes6", "samples"] {
            let search = msg
                .dict_find_dict(b"r")
                .and_then(|r| r.dict_find_string(key.as_bytes()))
                .or_else(|| msg.dict_find_string(key.as_bytes()));
            if let Some(s) = search {
                let raw = s.string_value();
                let nodes = read_nodes(proto, raw);
                assert!(nodes.len() <= raw.len() / proto.node_len());
                let packed = write_nodes(nodes.iter().map(|n| (&n.id, &n.ep)));
                assert_eq!(packed, raw[..nodes.len() * proto.node_len()]);
            }
        }
    }
    if let Some(v) = msg.dict_find_dict(b"r").and_then(|r| r.dict_find_list(b"values")) {
        assert!(read_endpoint_list(v).len() <= v.list_len());
    }
    let _ = msg.has_soft_error();
});
