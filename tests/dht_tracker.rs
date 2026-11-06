//! Tests for `dht_tracker`: the send quota and the datagram pre-filter
//! (libtorrent RC_2_1 `src/kademlia/dht_tracker.cpp`; the quota is covered
//! upstream by `simulation/test_dht_rate_limit.cpp`).

use std::time::Duration;

use cloudllm_dht::testing::addr4;
use cloudllm_dht::time::Time;
use cloudllm_dht::tracker::prefilter::{is_dark_internet, plausible_dht_datagram};
use cloudllm_dht::tracker::quota::SendQuota;

fn t(ms: u64) -> Time {
    Time::ZERO + Duration::from_millis(ms)
}

/// A fresh quota holds one second of budget and charging past zero blocks
/// the next incoming query.
#[test]
fn test_quota_starts_with_one_second_and_blocks_when_spent() {
    let mut q = SendQuota::new(1000, t(0));
    assert_eq!(q.remaining(), 1000);
    assert!(q.has_quota(t(0), 1000));
    q.charge(1500);
    assert_eq!(q.remaining(), -500);
    assert!(!q.has_quota(t(0), 1000));
}

/// The quota accrues proportionally to the elapsed time.
#[test]
fn test_quota_accrues_with_time() {
    let mut q = SendQuota::new(1000, t(0));
    q.charge(1000);
    assert!(!q.has_quota(t(0), 1000));
    // 100 ms at 1000 B/s is 100 bytes.
    assert!(q.has_quota(t(100), 1000));
    assert_eq!(q.remaining(), 100);
}

/// The bucket never holds more than three seconds of budget.
#[test]
fn test_quota_burst_capped_at_three_seconds() {
    let mut q = SendQuota::new(1000, t(0));
    assert!(q.has_quota(t(2500), 1000));
    assert_eq!(q.remaining(), 3000);
    // a long idle gap refills, but only to the cap
    assert!(q.has_quota(t(60_000), 1000));
    assert_eq!(q.remaining(), 3000);
}

/// A limit of zero or less means "send nothing".
#[test]
fn test_quota_zero_limit_never_allows() {
    let mut q = SendQuota::new(0, t(0));
    assert!(!q.has_quota(t(10_000), 0));
    assert!(!q.has_quota(t(20_000), -5));
    assert_eq!(q.remaining(), 0);
}

/// A huge limit and a huge gap must not overflow (libtorrent guards the
/// 32-bit product with the `max / limit` microsecond test).
#[test]
fn test_quota_huge_limit_does_not_overflow() {
    let mut q = SendQuota::new(i32::MAX, t(0));
    assert!(q.has_quota(t(1), i32::MAX));
    assert!(q.remaining() <= i64::from(i32::MAX));
    q.charge(usize::MAX);
    assert!(q.remaining() < 0);
    assert!(q.has_quota(t(100), i32::MAX));
}

/// Only plausibly shaped datagrams are handed to the parser.
#[test]
fn test_prefilter_shape() {
    assert!(plausible_dht_datagram(
        b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:t2:aa1:y1:qe"
    ));
    assert!(!plausible_dht_datagram(b""));
    assert!(!plausible_dht_datagram(b"d"));
    // exactly 20 bytes: rejected (libtorrent `buf_size <= 20`)
    assert!(!plausible_dht_datagram(&b"de".repeat(10)[..20]));
    let mut ok = vec![b'd'];
    ok.extend_from_slice(&[b'x'; 19]);
    ok.push(b'e');
    assert_eq!(ok.len(), 21);
    assert!(plausible_dht_datagram(&ok));
    *ok.last_mut().unwrap() = b'x';
    assert!(!plausible_dht_datagram(&ok));
}

/// The dark-internet list matches libtorrent's `class_a` array.
#[test]
fn test_prefilter_dark_internet() {
    for first in [
        3u8, 6, 7, 9, 11, 19, 21, 22, 25, 26, 28, 29, 30, 33, 34, 48, 56,
    ] {
        assert!(is_dark_internet(addr4(&format!("{first}.1.1.1"))));
    }
    for first in [1u8, 2, 4, 8, 10, 12, 100, 200] {
        assert!(!is_dark_internet(addr4(&format!("{first}.1.1.1"))));
    }
}
