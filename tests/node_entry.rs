//! Tests for `node_entry`, ported from `node_entry_comparison` in
//! libtorrent `test/test_dht.cpp` (RC_2_1,
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg and contributors, plus the behaviour of `node_entry.cpp`.

use std::net::SocketAddr;
use std::time::Duration;

use cloudllm_dht::node_entry::{NodeEntry, NEVER_PINGED, RTT_UNKNOWN};
use cloudllm_dht::node_id::generate_id_impl;
use cloudllm_dht::rng::TestRng;
use cloudllm_dht::time::Time;
use cloudllm_dht::Sha1Hash;

fn ep() -> SocketAddr {
    "4.4.4.4:6881".parse().unwrap()
}

/// libtorrent's `fake_node(verified, rtt)`.
fn fake_node(verified: bool, rtt: u16) -> NodeEntry {
    let mut e = NodeEntry::unknown_id(ep());
    e.verified = verified;
    e.rtt = rtt;
    e
}

/// TEST_CASE `node_entry_comparison`: being verified always trumps RTT in the
/// sort order; at equal verification a lower RTT is better.
#[test]
fn test_node_entry_comparison() {
    // being verified or not always trumps RTT in sort order
    assert!(fake_node(true, 10).is_better_than(&fake_node(false, 5)));
    assert!(fake_node(true, 5).is_better_than(&fake_node(false, 10)));
    assert!(!fake_node(false, 10).is_better_than(&fake_node(true, 5)));
    assert!(!fake_node(false, 5).is_better_than(&fake_node(true, 10)));

    // if both are verified, lower RTT is better
    assert!(fake_node(true, 5).is_better_than(&fake_node(true, 10)));
    assert!(!fake_node(true, 10).is_better_than(&fake_node(true, 5)));

    // if neither are verified, lower RTT is better
    assert!(fake_node(false, 5).is_better_than(&fake_node(false, 10)));
    assert!(!fake_node(false, 10).is_better_than(&fake_node(false, 5)));
}

/// Equal quality is "not better" in both directions (a strict order, like
/// libtorrent's `operator<`).
#[test]
fn test_node_entry_comparison_is_strict() {
    let a = fake_node(true, 7);
    let b = fake_node(true, 7);
    assert!(!a.is_better_than(&b));
    assert!(!b.is_better_than(&a));
}

/// The constructor with a known ID: `pinged` selects `timeout_count` 0 or
/// 0xff, `verified` comes from BEP 42, `last_queried` starts at "never".
#[test]
fn test_new_pinged_and_unpinged() {
    let id = Sha1Hash::MAX;
    let unpinged = NodeEntry::new(id, ep(), RTT_UNKNOWN, false);
    assert_eq!(unpinged.timeout_count, NEVER_PINGED);
    assert!(!unpinged.pinged());
    assert!(!unpinged.confirmed());
    assert_eq!(unpinged.fail_count(), 0);
    assert_eq!(unpinged.last_queried, Time::ZERO);

    let pinged = NodeEntry::new(id, ep(), 33, true);
    assert_eq!(pinged.timeout_count, 0);
    assert!(pinged.pinged() && pinged.confirmed());
    assert_eq!(pinged.rtt, 33);
}

/// `verified` is computed with `verify_id` at construction.
#[test]
fn test_new_computes_verified_from_bep42() {
    let ip = "124.31.75.21".parse().unwrap();
    let good = generate_id_impl(ip, 1, &mut TestRng::new(1));
    let e = NodeEntry::new(good, SocketAddr::new(ip, 6881), 10, true);
    assert!(e.verified);
    let mut bad = good;
    bad.0[0] ^= 0xff;
    assert!(!NodeEntry::new(bad, SocketAddr::new(ip, 6881), 10, true).verified);
}

/// `new_at` stamps a pinged entry with `now`, an unpinged one with "never".
#[test]
fn test_new_at_stamps_only_pinged_entries() {
    let now = Time::ZERO + Duration::from_secs(100);
    assert_eq!(
        NodeEntry::new_at(Sha1Hash::MAX, ep(), 1, true, now).last_queried,
        now
    );
    assert_eq!(
        NodeEntry::new_at(Sha1Hash::MAX, ep(), 1, false, now).last_queried,
        Time::ZERO
    );
}

/// `node_entry(ep)`: zero ID, unknown RTT, never pinged, unverified.
#[test]
fn test_unknown_id_defaults() {
    let e = NodeEntry::unknown_id(ep());
    assert_eq!(e.id, Sha1Hash::MIN);
    assert_eq!(e.rtt, RTT_UNKNOWN);
    assert_eq!(e.timeout_count, NEVER_PINGED);
    assert!(!e.verified);
    assert_eq!((e.addr(), e.port(), e.ep()), (ep().ip(), 6881, ep()));
}

/// `update_rtt`: first sample taken as is, later ones blended 2/3 + 1/3, an
/// "unknown" sample ignored.
#[test]
fn test_update_rtt_blends_samples() {
    let mut e = NodeEntry::unknown_id(ep());
    e.update_rtt(0xffff);
    assert_eq!(e.rtt, RTT_UNKNOWN);
    e.update_rtt(300);
    assert_eq!(e.rtt, 300);
    e.update_rtt(30);
    assert_eq!(e.rtt, 300 * 2 / 3 + 30 / 3);
    e.update_rtt(0xffff);
    assert_eq!(e.rtt, 210);
}

/// Regression: the blend is done in wider arithmetic; with a large old RTT
/// `old * 2` overflows `u16`.
#[test]
fn test_update_rtt_does_not_overflow_u16() {
    let mut e = NodeEntry::unknown_id(ep());
    e.rtt = 0xfffe;
    e.update_rtt(0xfffe);
    // 0xfffe * 2 / 3 + 0xfffe / 3, truncating twice
    assert_eq!(e.rtt, 0xfffd);
    e.update_rtt(0);
    assert_eq!(u32::from(e.rtt), 0xfffd_u32 * 2 / 3);
}

/// `timed_out`, `fail_count`, `reset_fail_count`, `set_pinged` on a pinged
/// and a never-pinged entry.
#[test]
fn test_failure_bookkeeping() {
    let mut e = NodeEntry::new(Sha1Hash::MAX, ep(), 10, true);
    e.timed_out();
    e.timed_out();
    assert_eq!(e.fail_count(), 2);
    assert!(!e.confirmed());
    e.reset_fail_count();
    assert_eq!(e.fail_count(), 0);
    assert!(e.confirmed());

    let mut u = NodeEntry::new(Sha1Hash::MAX, ep(), 10, false);
    u.timed_out();
    u.reset_fail_count();
    assert_eq!(
        u.timeout_count, NEVER_PINGED,
        "unpinged entries ignore both"
    );
    u.set_pinged();
    assert_eq!(u.timeout_count, 0);
    u.timed_out();
    u.set_pinged();
    assert_eq!(
        u.timeout_count, 1,
        "set_pinged does not reset a pinged entry"
    );
}

/// `timed_out` saturates at 0xfe so a pinged node never becomes "never
/// pinged" (0xff).
#[test]
fn test_timed_out_saturates_below_never_pinged() {
    let mut e = NodeEntry::new(Sha1Hash::MAX, ep(), 10, true);
    for _ in 0..1000 {
        e.timed_out();
    }
    assert_eq!(e.timeout_count, 0xfe);
    assert!(e.pinged());
}
