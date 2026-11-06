//! Per-address rate limiting and banning of abusive nodes.
//!
//! Provenance: `include/libtorrent/kademlia/dos_blocker.hpp` and
//! `src/kademlia/dos_blocker.cpp` of libtorrent RC_2_1 (commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg, Alden Torres and contributors.
//!
//! The blocker keeps a table of the [`NUM_BAN_NODES`] busiest recent
//! senders. A sender that delivers `rate_limit * 10` packets inside a
//! 10 second window (an average of `rate_limit` packets per second) is
//! ignored until it has been silent for the block timeout; a sender that
//! stays under the rate has its counter reset every 10 seconds. The table
//! is deliberately tiny and fixed-size: an attacker spraying addresses
//! cannot grow it, only evict the quietest entries.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::time::Time;

/// The number of senders tracked at once (`dos_blocker::num_ban_nodes`).
pub const NUM_BAN_NODES: usize = 20;

/// The measuring window and the counter-reset period: ten seconds.
const WINDOW: Duration = Duration::from_secs(10);

/// What [`DosBlocker::incoming_decision`] decided about a packet.
///
/// libtorrent logs the transition into a ban from inside `incoming`
/// (`BANNING PEER`); here the caller gets it as data so it can log or raise
/// an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DosDecision {
    /// Let the packet through.
    Allow,
    /// Drop the packet: the sender is banned or over its rate.
    Block,
    /// Drop the packet, and this is the packet that tipped the sender into a
    /// ban for the block timeout. Carries what libtorrent logs.
    Ban {
        /// The sender's packet count in the window (the ban threshold).
        count: i32,
        /// Milliseconds libtorrent prints as `time`: `(now - window_end) + 10 s`.
        window_ms: i64,
    },
}

/// One tracked sender (libtorrent's private `node_ban_entry`).
#[derive(Debug, Clone, Copy)]
struct BanEntry {
    src: IpAddr,
    /// End of the 10 s window, or the end of the ban once banned.
    limit: Time,
    count: i32,
}

impl BanEntry {
    /// An unused slot: `address()` (IPv4 `0.0.0.0`), count 0, `min_time()`.
    const EMPTY: Self = Self {
        src: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        limit: Time::ZERO,
        count: 0,
    };
}

/// Tracks abusive senders and tells the node which packets to drop
/// (libtorrent `dht::dos_blocker`).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::dos_blocker::DosBlocker;
/// use cloudllm_dht::time::Time;
/// use std::time::Duration;
///
/// let mut b = DosBlocker::new(); // 5 packets/s, 5 minute block
/// let spammer = "10.10.10.10".parse().unwrap();
/// let mut now = Time::ZERO;
/// let mut passed = 0;
/// for _ in 0..100 {
///     if b.incoming(spammer, now) { passed += 1; }
///     now = now + Duration::from_millis(1);
/// }
/// assert_eq!(passed, 49); // the 50th packet within 10 s trips the ban
/// ```
#[derive(Debug, Clone)]
pub struct DosBlocker {
    /// Packets per second, averaged over 10 s, before a sender is blocked.
    message_rate_limit: i32,
    /// Seconds a sender stays blocked.
    block_timeout: i32,
    nodes: [BanEntry; NUM_BAN_NODES],
}

impl Default for DosBlocker {
    fn default() -> Self {
        Self::new()
    }
}

impl DosBlocker {
    /// A blocker with libtorrent's defaults: 5 packets per second, blocked
    /// for 5 minutes (`dht_block_ratelimit`, `dht_block_timeout`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_rate_limit: 5,
            block_timeout: 5 * 60,
            nodes: [BanEntry::EMPTY; NUM_BAN_NODES],
        }
    }

    /// Sets the allowed packets per second; values below 1 become 1
    /// (libtorrent `set_rate_limit`).
    pub fn set_rate_limit(&mut self, limit: i32) {
        self.message_rate_limit = limit.max(1);
    }

    /// Sets the block duration in seconds; values below 1 become 1
    /// (libtorrent `set_block_timer`).
    pub fn set_block_timer(&mut self, seconds: i32) {
        self.block_timeout = seconds.max(1);
    }

    /// The packet count that trips a ban: `rate_limit * 10`, saturating
    /// (libtorrent's `int` product overflows for huge limits).
    fn ban_threshold(&self) -> i32 {
        self.message_rate_limit.saturating_mul(10)
    }

    /// The tracked entry for `addr`, if any, else the slot to recycle: the
    /// one with the lowest count, ties broken by the earliest `limit`
    /// (libtorrent's scan in `dos_blocker::incoming`).
    fn find_or_pick(&self, addr: IpAddr) -> Result<usize, usize> {
        let mut min = 0;
        for (i, e) in self.nodes.iter().enumerate() {
            if e.src == addr {
                return Ok(i);
            }
            let m = &self.nodes[min];
            if e.count < m.count || (e.count == m.count && e.limit < m.limit) {
                min = i;
            }
        }
        Err(min)
    }

    /// Called for every incoming packet; `true` lets it through, `false`
    /// drops it (libtorrent `dos_blocker::incoming`, without the logger).
    ///
    /// Use [`DosBlocker::incoming_decision`] to learn when a ban starts.
    pub fn incoming(&mut self, addr: IpAddr, now: Time) -> bool {
        self.incoming_decision(addr, now) == DosDecision::Allow
    }

    /// [`DosBlocker::incoming`] with the reason for a refusal.
    ///
    /// # Examples
    ///
    /// ```
    /// use cloudllm_dht::dos_blocker::{DosBlocker, DosDecision};
    /// use cloudllm_dht::time::Time;
    ///
    /// let mut b = DosBlocker::new();
    /// let ip = "1.2.3.4".parse().unwrap();
    /// let decisions: Vec<_> = (0..51).map(|_| b.incoming_decision(ip, Time::ZERO)).collect();
    /// assert_eq!(decisions[48], DosDecision::Allow);
    /// assert!(matches!(decisions[49], DosDecision::Ban { count: 50, .. }));
    /// assert_eq!(decisions[50], DosDecision::Block);
    /// ```
    pub fn incoming_decision(&mut self, addr: IpAddr, now: Time) -> DosDecision {
        let threshold = self.ban_threshold();
        let slot = match self.find_or_pick(addr) {
            Ok(i) => i,
            Err(i) => {
                // a sender we do not know: take over the least busy slot
                self.nodes[i] = BanEntry {
                    src: addr,
                    limit: now + WINDOW,
                    count: 1,
                };
                return DosDecision::Allow;
            }
        };
        let block_timeout = Duration::from_secs(u64::from(self.block_timeout.unsigned_abs()));
        let e = &mut self.nodes[slot];
        e.count = e.count.saturating_add(1);
        if e.count < threshold {
            return DosDecision::Allow;
        }
        if now < e.limit {
            // too many packets in under 10 s: ignore this sender until it
            // has been silent for the block timeout
            let newly_banned = e.count == threshold;
            let window_ms = signed_millis(now, e.limit) + 10_000;
            let count = e.count;
            if newly_banned {
                e.limit = now + block_timeout;
                return DosDecision::Ban { count, window_ms };
            }
            return DosDecision::Block;
        }
        // the packets took longer than 10 s to arrive: restart the window
        e.count = 0;
        e.limit = now + WINDOW;
        DosDecision::Allow
    }
}

/// `a - b` in whole milliseconds, negative when `a` is earlier.
fn signed_millis(a: Time, b: Time) -> i64 {
    let ms = |d: Duration| i64::try_from(d.as_millis()).unwrap_or(i64::MAX);
    if a >= b {
        ms(a - b)
    } else {
        -ms(b - a)
    }
}
