//! Tests for `dos_blocker`: `TEST_CASE(dos_blocker)` of libtorrent
//! `test/test_dos_blocker.cpp` (RC_2_1, `86d573f2631b0162d3cca5e257217eaf530fdcba`)
//! and the behaviours around the window, ban and eviction logic.

use std::net::IpAddr;
use std::time::Duration;

use cloudllm_dht::dos_blocker::{DosBlocker, DosDecision, NUM_BAN_NODES};
use cloudllm_dht::rng::TestRng;
use cloudllm_dht::testing::rand_v4;
use cloudllm_dht::time::Time;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn after(ms: u64) -> Time {
    Time::ZERO + Duration::from_millis(ms)
}

/// Port of `TEST_CASE(dos_blocker)`: a spammer interleaved with a thousand
/// random one-shot senders; every random sender passes and the spammer is
/// blocked at the end.
#[test]
fn test_dos_blocker() {
    let mut rng = TestRng::new(1);
    let mut b = DosBlocker::new();
    let spammer = ip("10.10.10.10");
    let mut now = Time::ZERO + Duration::from_secs(1000);
    for _ in 0..1000 {
        b.incoming(spammer, now);
        now = now + Duration::from_millis(1);
        assert!(b.incoming(rand_v4(&mut rng), now));
        now = now + Duration::from_millis(1);
    }
    now = now + Duration::from_millis(1);
    assert!(!b.incoming(spammer, now));
}

/// The 50th packet inside 10 seconds (rate 5 x 10) is the first refused, and
/// it is reported as the ban; later ones are plain blocks.
#[test]
fn test_ban_starts_at_rate_limit_times_ten() {
    let mut b = DosBlocker::new();
    let a = ip("1.2.3.4");
    let mut ds = Vec::new();
    for i in 0..60 {
        ds.push(b.incoming_decision(a, after(i)));
    }
    assert!(ds[..49].iter().all(|d| *d == DosDecision::Allow));
    match ds[49] {
        DosDecision::Ban { count, window_ms } => {
            assert_eq!(count, 50);
            // libtorrent prints (now - limit) + 10 s: limit was 10 s after
            // the first packet at t=0, now is t=49 ms
            assert_eq!(window_ms, 49 - 10_000 + 10_000);
        }
        other => panic!("expected a ban, got {other:?}"),
    }
    assert!(ds[50..].iter().all(|d| *d == DosDecision::Block));
}

/// A sender slower than the rate is never blocked: its counter restarts
/// whenever 10 s have passed (here 1 packet per second, indefinitely).
#[test]
fn test_slow_sender_is_never_blocked() {
    let mut b = DosBlocker::new();
    let a = ip("1.2.3.4");
    for s in 0..2000 {
        assert!(b.incoming(a, Time::ZERO + Duration::from_secs(s)));
    }
}

/// Reaching the threshold only blocks when it happens inside the window:
/// 50 packets spread over 50 s pass, the counter is reset at the 10 s edge.
#[test]
fn test_threshold_outside_window_resets_counter() {
    let mut b = DosBlocker::new();
    let a = ip("1.2.3.4");
    // 49 packets in the first second, then one more 11 s later
    for i in 0..49 {
        assert!(b.incoming(a, after(i)));
    }
    assert!(b.incoming(a, Time::ZERO + Duration::from_secs(11)));
    // the window restarted: 48 more packets still pass
    for i in 0..48 {
        assert!(b.incoming(
            a,
            Time::ZERO + Duration::from_secs(11) + Duration::from_millis(i + 1)
        ));
    }
}

/// A ban lasts exactly the block timeout from the packet that caused it, no
/// matter how much the sender keeps sending; afterwards it starts afresh.
/// (The source comment says "until it's silent for 5 minutes", but the code
/// does not extend the ban, and neither does this port.)
#[test]
fn test_ban_expires_after_block_timeout() {
    let mut b = DosBlocker::new();
    b.set_block_timer(60);
    let a = ip("1.2.3.4");
    for i in 0..50 {
        b.incoming(a, after(i)); // banned at t = 49 ms
    }
    let ban_start = after(49);
    assert!(!b.incoming(a, ban_start + Duration::from_secs(30)));
    assert!(!b.incoming(a, ban_start + Duration::from_secs(59)));
    assert!(b.incoming(a, ban_start + Duration::from_secs(60)));
    // and it is a fresh window, not an immediate re-ban
    assert!(b.incoming(
        a,
        ban_start + Duration::from_secs(60) + Duration::from_millis(1)
    ));
}

/// `set_rate_limit` scales the threshold; values below 1 become 1 and
/// `set_block_timer` clamps likewise, as in libtorrent.
#[test]
fn test_setters_clamp_and_scale() {
    let mut b = DosBlocker::new();
    b.set_rate_limit(1);
    let a = ip("1.2.3.4");
    let passed = (0..30).filter(|i| b.incoming(a, after(*i))).count();
    assert_eq!(passed, 9, "threshold 1 * 10 packets: the 10th is refused");

    let mut b = DosBlocker::new();
    b.set_rate_limit(-7);
    b.set_block_timer(0);
    let passed = (0..30).filter(|i| b.incoming(a, after(*i))).count();
    assert_eq!(passed, 9, "negative rate limit behaves as 1");
    // a 1 s block ends after 1 s
    assert!(b.incoming(a, after(1000 + 10)));

    let mut b = DosBlocker::new();
    b.set_rate_limit(i32::MAX); // threshold saturates instead of overflowing
    assert!((0..1000).all(|i| b.incoming(a, after(i))));
}

/// The table holds 20 senders; a new one evicts the entry with the lowest
/// count, so a heavy sender survives a flood of one-shot addresses and a
/// quiet one is forgotten.
#[test]
fn test_eviction_prefers_low_count() {
    let mut b = DosBlocker::new();
    let heavy = ip("10.0.0.1");
    for i in 0..30 {
        b.incoming(heavy, after(i));
    }
    for n in 0..(NUM_BAN_NODES * 5) {
        let fresh: IpAddr = format!("20.0.{}.{}", n / 250, n % 250).parse().unwrap();
        assert!(b.incoming(fresh, after(100 + n as u64)));
    }
    // heavy still has its count of 30: 19 more packets reach 49, the 50th bans
    let passed = (0..30)
        .filter(|i| b.incoming(heavy, after(1000 + i)))
        .count();
    assert_eq!(passed, 19);
}

/// IPv4 and IPv6 addresses are distinct keys, and the "empty slot" marker
/// (`0.0.0.0`) behaves like any other address (a libtorrent quirk kept on
/// purpose): its first packet matches an empty slot and is counted.
#[test]
fn test_distinct_families_and_unspecified_address() {
    let mut b = DosBlocker::new();
    let v4 = ip("1.2.3.4");
    let v6 = ip("::ffff:1.2.3.4");
    for i in 0..49 {
        assert!(b.incoming(v4, after(i)));
    }
    assert!(b.incoming(v6, after(50)), "v6 has its own counter");
    assert!(!b.incoming(v4, after(51)));
    assert!(b.incoming(ip("0.0.0.0"), after(52)));
}
