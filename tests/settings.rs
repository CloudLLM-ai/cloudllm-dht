//! Tests for `settings`: libtorrent's defaults and the persisted subset
//! (`read_dht_settings` / `save_dht_settings`, RC_2_1,
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`).

use cloudllm_dht::bencode::decode;
use cloudllm_dht::settings::{read_dht_settings, save_dht_settings, DhtSettings};

/// The defaults are exactly libtorrent's.
#[test]
fn test_defaults_match_libtorrent() {
    let s = DhtSettings::default();
    assert_eq!(s.max_peers_reply, 100);
    assert_eq!(s.search_branching, 5);
    assert_eq!(s.max_fail_count, 20);
    assert_eq!(s.max_torrents, 2000);
    assert_eq!(s.max_dht_items, 700);
    assert_eq!(s.max_peers, 500);
    assert_eq!(s.max_torrent_search_reply, 20);
    assert!(s.restrict_routing_ips && s.restrict_search_ips);
    assert!(s.extended_routing_table && s.aggressive_lookups);
    assert!(!s.privacy_lookups && !s.enforce_node_id && !s.read_only);
    assert!(s.ignore_dark_internet);
    assert_eq!(s.block_timeout, 300);
    assert_eq!(s.block_ratelimit, 5);
    assert_eq!(s.item_lifetime, 0);
    assert_eq!(s.upload_rate_limit, 8000);
    assert_eq!(s.sample_infohashes_interval, 21600);
    assert_eq!(s.max_infohashes_sample_count, 20);
    assert!(s.prefer_verified_node_ids);
}

/// Saved settings read back identically (the persisted subset; the
/// runtime-only fields keep their defaults).
#[test]
fn test_settings_roundtrip() {
    let s = DhtSettings {
        max_peers_reply: 7,
        search_branching: 9,
        restrict_routing_ips: false,
        read_only: true,
        item_lifetime: 3600,
        block_timeout: 1,
        ..DhtSettings::default()
    };
    let bytes = save_dht_settings(&s).encode();
    assert_eq!(read_dht_settings(&decode(&bytes).unwrap()), s);
}

/// Missing keys keep defaults; a non-dictionary gives all defaults;
/// out-of-range integers are ignored.
#[test]
fn test_read_settings_lenient() {
    let n = decode(b"d9:max_peersi5ee").unwrap();
    assert_eq!(read_dht_settings(&n).max_peers, 5);
    assert_eq!(
        read_dht_settings(&decode(b"i3e").unwrap()),
        DhtSettings::default()
    );
    let n = decode(b"d9:max_peersi99999999999ee").unwrap();
    assert_eq!(read_dht_settings(&n).max_peers, 500);
}
