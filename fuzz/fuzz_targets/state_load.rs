//! Fuzzes the DHT state loader: the bencoded blob a node saved on a previous
//! run (or a hostile file dropped in its place).
//!
//! Invariants: loading never panics and never returns more nodes than the
//! document has list elements; what was read survives a save/load round trip
//! unchanged (the loader normalizes, so `load(save(load(x))) == load(x)`).
#![no_main]

use cloudllm_dht::bencode::decode;
use cloudllm_dht::dht_state::{extract_node_ids, read_dht_state, save_dht_state, DhtState};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(node) = decode(data) else { return };
    let state = read_dht_state(&node);

    let list_len = |key: &[u8]| node.dict_find_list(key).map_or(0, |l| l.list_len());
    assert!(state.nodes.len() <= list_len(b"nodes"));
    assert!(state.nodes6.len() <= list_len(b"nodes6"));
    assert!(state.nids.len() <= list_len(b"node-id").max(1));
    assert_eq!(state.nids, extract_node_ids(&node, "node-id"));

    let bytes = save_dht_state(&state).encode();
    let again = DhtState::load(&bytes).expect("saved state is valid bencode");
    assert_eq!(again, state);
    assert_eq!(again.encode(), bytes, "encoding is canonical");
});
