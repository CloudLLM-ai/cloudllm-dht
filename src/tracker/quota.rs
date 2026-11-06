//! The send quota: the upload rate limit that gates responses.
//!
//! Provenance: `dht_tracker::has_quota` and the `m_send_quota` /
//! `m_last_tick` members of `src/kademlia/dht_tracker.cpp` (libtorrent
//! RC_2_1, commit `86d573f2631b0162d3cca5e257217eaf530fdcba`),
//! BSD-3-Clause, Copyright Arvid Norberg and contributors.
//!
//! # Why a quota
//!
//! A DHT node answers queries from the whole internet, so it is a
//! reflection amplifier unless its response traffic is bounded. The quota
//! is a token bucket measured in bytes: it accrues `limit` bytes per second
//! up to a three-second burst, every packet the node sends is charged
//! against it, and incoming queries are dropped while it is empty. As in
//! libtorrent an outgoing packet is never refused for lack of quota (the
//! node's own lookups must make progress); the debt just blocks the next
//! incoming query.

use std::time::Duration;

use crate::time::Time;

/// The burst allowance, in seconds' worth of `limit`.
const BURST_SECONDS: i64 = 3;

/// A byte-denominated token bucket (libtorrent `m_send_quota` plus
/// `m_last_tick`).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::time::Time;
/// use cloudllm_dht::tracker::quota::SendQuota;
/// use std::time::Duration;
///
/// let t0 = Time::ZERO + Duration::from_secs(100);
/// // 4000 bytes per second, starts with one second of quota.
/// let mut q = SendQuota::new(4000, t0);
/// assert!(q.has_quota(t0, 4000));
/// q.charge(4000);
/// assert!(!q.has_quota(t0, 4000));
/// // Half a second later 2000 bytes have accrued.
/// assert!(q.has_quota(t0 + Duration::from_millis(500), 4000));
/// ```
#[derive(Debug, Clone)]
pub struct SendQuota {
    /// Bytes that may still be sent; negative when in debt.
    quota: i64,
    /// The previous call to [`SendQuota::has_quota`].
    last_tick: Time,
}

impl SendQuota {
    /// A quota that starts with one second of budget (`m_send_quota`
    /// is initialised to the limit) at time `now`.
    #[must_use]
    pub fn new(limit: i32, now: Time) -> Self {
        Self {
            quota: i64::from(limit),
            last_tick: now,
        }
    }

    /// The bytes left (negative when in debt): for status output and tests.
    #[must_use]
    pub fn remaining(&self) -> i64 {
        self.quota
    }

    /// Accrues the quota earned since the last call and reports whether any
    /// is left (libtorrent `dht_tracker::has_quota`). `limit` is the
    /// `upload_rate_limit` setting in bytes per second; a limit of zero or
    /// less means "send nothing" and always returns `false`.
    pub fn has_quota(&mut self, now: Time, limit: i32) -> bool {
        let delta = now - self.last_tick;
        self.last_tick = now;

        let limit = i64::from(limit);
        if limit <= 0 {
            self.quota = 0;
            return false;
        }
        let max_accrue = (BURST_SECONDS * limit).min(i64::from(i32::MAX));

        // A long gap refills the bucket without computing the product,
        // which also keeps `limit * micros` from overflowing in libtorrent's
        // 32-bit arithmetic.
        if delta >= Duration::from_secs(BURST_SECONDS.unsigned_abs())
            || delta.as_micros()
                >= u128::from(i32::MAX.unsigned_abs()) / u128::from(limit.unsigned_abs())
        {
            self.quota = max_accrue;
            return true;
        }
        let add = limit * i64::try_from(delta.as_micros()).unwrap_or(i64::MAX) / 1_000_000;
        if max_accrue - self.quota < add {
            self.quota = max_accrue;
            return true;
        }
        self.quota += add;
        self.quota > 0
    }

    /// Charges `bytes` for a packet that was sent (libtorrent
    /// `m_send_quota -= m_send_buf.size()` in `send_packet`). May drive the
    /// quota negative; that is intended.
    pub fn charge(&mut self, bytes: usize) {
        self.quota = self
            .quota
            .saturating_sub(i64::try_from(bytes).unwrap_or(i64::MAX));
    }
}
