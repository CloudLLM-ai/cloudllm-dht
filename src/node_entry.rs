//! A routing table entry: node ID, endpoint, RTT, fail count, verified flag.
//!
//! Provenance: `include/libtorrent/kademlia/node_entry.hpp` and
//! `src/kademlia/node_entry.cpp` of libtorrent RC_2_1 (commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg, Steven Siloti and Alden Torres.
//!
//! A [`NodeEntry`] is what the [`crate::routing_table::RoutingTable`] stores
//! for every contact, and what a lookup is handed back when it asks for the
//! nodes closest to a target.
//!
//! # Differences from libtorrent
//!
//! * The sans-IO core never reads a clock, so the constructor that stamps
//!   `last_queried` with "now" takes that time as an argument
//!   ([`NodeEntry::new_at`]). [`NodeEntry::new`] leaves `last_queried` at
//!   [`Time::ZERO`] (libtorrent's `min_time()`, "never").
//! * libtorrent's `operator<` ("is this node a better routing table
//!   resident") is [`NodeEntry::is_better_than`], not an `Ord` impl: it
//!   compares only `(verified, rtt)`, so two distinct entries can be
//!   "equal", which `Ord` (consistent with `Eq`) must not allow.
//! * `first_seen`, which libtorrent keeps only for log messages, is not
//!   stored.

use std::cmp::Ordering;
use std::net::{IpAddr, SocketAddr};

use crate::node_id::{verify_id, NodeId};
use crate::time::Time;

/// The `rtt` of a node whose round-trip time is not known (libtorrent
/// `0xffff`).
pub const RTT_UNKNOWN: u16 = 0xffff;

/// The `timeout_count` of a node we have never pinged (libtorrent `0xff`).
pub const NEVER_PINGED: u8 = 0xff;

/// A node known to the routing table (libtorrent `dht::node_entry`).
///
/// `timeout_count` doubles as the "have we heard from it" flag:
/// [`NEVER_PINGED`] means we have never exchanged a verified message with it
/// (it was only *heard about*, so it may be a spoofed or poisoned contact),
/// `0` means its last request was answered, and `1..` is the number of
/// requests in a row that timed out. Only entries with `timeout_count == 0`
/// are [confirmed](NodeEntry::confirmed) and eligible to be handed to other
/// nodes in `find_node` responses.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::node_entry::NodeEntry;
/// use cloudllm_dht::Sha1Hash;
///
/// let ep = "4.4.4.4:6881".parse().unwrap();
/// let heard = NodeEntry::new(Sha1Hash::MAX, ep, 0xffff, false);
/// assert!(!heard.pinged());
/// assert!(!heard.confirmed());
///
/// let seen = NodeEntry::new(Sha1Hash::MAX, ep, 40, true);
/// assert!(seen.pinged() && seen.confirmed());
/// assert_eq!(seen.rtt, 40);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeEntry {
    /// The time we last queried this node (libtorrent `last_queried`);
    /// [`Time::ZERO`] means never. The routing table's refresh scheduling
    /// ([`RoutingTable::next_refresh`](crate::routing_table::RoutingTable::next_refresh))
    /// picks the entry with the oldest value.
    pub last_queried: Time,
    /// The node's ID; all zeros for [`NodeEntry::unknown_id`].
    pub id: NodeId,
    /// Where the node answers (libtorrent `aux::union_endpoint`).
    pub endpoint: SocketAddr,
    /// The smoothed round-trip time in milliseconds, [`RTT_UNKNOWN`] when
    /// not measured yet.
    pub rtt: u16,
    /// Consecutive failed requests, or [`NEVER_PINGED`]. See the type docs.
    pub timeout_count: u8,
    /// `true` when `id` is a valid BEP 42 ID for `endpoint`'s address
    /// (libtorrent computes this once in the constructor with `verify_id`).
    pub verified: bool,
}

impl NodeEntry {
    /// An entry for a node with a known ID (libtorrent
    /// `node_entry(id, ep, roundtriptime, pinged)`).
    ///
    /// `pinged` says whether we have actually exchanged a verified message
    /// with the node: it sets `timeout_count` to `0` instead of
    /// [`NEVER_PINGED`]. `verified` is computed from `id` and the address
    /// with [`verify_id`]. `last_queried` is [`Time::ZERO`]; use
    /// [`NodeEntry::new_at`] to stamp a pinged entry with the current time as
    /// libtorrent does.
    #[must_use]
    pub fn new(id: NodeId, ep: SocketAddr, rtt: u16, pinged: bool) -> Self {
        Self {
            last_queried: Time::ZERO,
            id,
            endpoint: ep,
            rtt,
            timeout_count: if pinged { 0 } else { NEVER_PINGED },
            verified: verify_id(&id, ep.ip()),
        }
    }

    /// Like [`NodeEntry::new`], but a pinged entry's `last_queried` is `now`
    /// (libtorrent's constructor evaluates `aux::time_now()` for it).
    ///
    /// This is what `node_seen` uses for a node that just answered, so the
    /// refresh scheduler does not immediately re-query it.
    #[must_use]
    pub fn new_at(id: NodeId, ep: SocketAddr, rtt: u16, pinged: bool, now: Time) -> Self {
        Self {
            last_queried: if pinged { now } else { Time::ZERO },
            ..Self::new(id, ep, rtt, pinged)
        }
    }

    /// An entry for an endpoint whose node ID is not known yet (libtorrent
    /// `explicit node_entry(udp::endpoint const&)`).
    ///
    /// The ID is all zeros, `rtt` unknown, never pinged, not verified. A
    /// traversal uses these for router/bootstrap nodes; the routing table
    /// replaces such an entry when the real ID arrives.
    #[must_use]
    pub fn unknown_id(ep: SocketAddr) -> Self {
        Self {
            last_queried: Time::ZERO,
            id: NodeId::MIN,
            endpoint: ep,
            rtt: RTT_UNKNOWN,
            timeout_count: NEVER_PINGED,
            verified: false,
        }
    }

    /// Folds a new round-trip sample into the average (libtorrent
    /// `update_rtt`).
    ///
    /// A sample of [`RTT_UNKNOWN`] is ignored. The first real sample is
    /// taken as is; after that the average is `old * 2/3 + sample / 3`, in
    /// integer arithmetic exactly like libtorrent.
    ///
    /// # Examples
    ///
    /// ```
    /// use cloudllm_dht::node_entry::NodeEntry;
    ///
    /// let mut e = NodeEntry::unknown_id("1.2.3.4:5".parse().unwrap());
    /// e.update_rtt(90);
    /// assert_eq!(e.rtt, 90);
    /// e.update_rtt(30);
    /// assert_eq!(e.rtt, 90 * 2 / 3 + 30 / 3);
    /// e.update_rtt(0xffff);
    /// assert_eq!(e.rtt, 70);
    /// ```
    pub fn update_rtt(&mut self, rtt: u16) {
        if rtt == RTT_UNKNOWN {
            return;
        }
        self.rtt = if self.rtt == RTT_UNKNOWN {
            rtt
        } else {
            // libtorrent does this in `int`; with both operands below 0xffff
            // the result is below 0xffff too.
            u16::try_from(u32::from(self.rtt) * 2 / 3 + u32::from(rtt) / 3)
                .expect("a 2/3 + 1/3 blend of two u16 values fits in u16")
        };
    }

    /// `true` once we have exchanged a message with the node, i.e.
    /// `timeout_count != 0xff` (libtorrent `pinged`).
    #[must_use]
    pub fn pinged(&self) -> bool {
        self.timeout_count != NEVER_PINGED
    }

    /// Marks a never-pinged entry as pinged with zero failures (libtorrent
    /// `set_pinged`); a no-op for one that already was.
    pub fn set_pinged(&mut self) {
        if self.timeout_count == NEVER_PINGED {
            self.timeout_count = 0;
        }
    }

    /// Records one more timed-out request (libtorrent `timed_out`). Does
    /// nothing for a never-pinged entry, and saturates below `0xff` so a
    /// pinged node can never be mistaken for a never-pinged one.
    pub fn timed_out(&mut self) {
        if self.pinged() && self.timeout_count < 0xfe {
            self.timeout_count += 1;
        }
    }

    /// The number of consecutive failures; `0` for a never-pinged entry
    /// (libtorrent `fail_count`).
    #[must_use]
    pub fn fail_count(&self) -> u32 {
        if self.pinged() {
            u32::from(self.timeout_count)
        } else {
            0
        }
    }

    /// Forgives past failures (libtorrent `reset_fail_count`); a no-op for a
    /// never-pinged entry.
    pub fn reset_fail_count(&mut self) {
        if self.pinged() {
            self.timeout_count = 0;
        }
    }

    /// `true` when the node answered its last request, `timeout_count == 0`
    /// (libtorrent `confirmed`).
    #[must_use]
    pub fn confirmed(&self) -> bool {
        self.timeout_count == 0
    }

    /// The endpoint (libtorrent `ep()`).
    #[must_use]
    pub fn ep(&self) -> SocketAddr {
        self.endpoint
    }

    /// The IP address (libtorrent `addr()`).
    #[must_use]
    pub fn addr(&self) -> IpAddr {
        self.endpoint.ip()
    }

    /// The UDP port (libtorrent `port()`).
    #[must_use]
    pub fn port(&self) -> u16 {
        self.endpoint.port()
    }

    /// The sort key of libtorrent's `operator<`: verified nodes first
    /// (`false < true` after negation), then lower RTT.
    #[must_use]
    pub fn quality_key(&self) -> (bool, u16) {
        (!self.verified, self.rtt)
    }

    /// Compares two entries by how good a routing table resident they are;
    /// `Less` is better (libtorrent `operator<` as a three-way compare).
    ///
    /// Being verified always trumps RTT; among nodes with the same verified
    /// status the lower RTT wins.
    #[must_use]
    pub fn quality_cmp(&self, other: &Self) -> Ordering {
        self.quality_key().cmp(&other.quality_key())
    }

    /// `true` if `self` is strictly better than `other` (libtorrent
    /// `self < other`).
    ///
    /// # Examples
    ///
    /// ```
    /// use cloudllm_dht::node_entry::NodeEntry;
    /// use cloudllm_dht::Sha1Hash;
    ///
    /// let ep = "4.4.4.4:6881".parse().unwrap();
    /// let mut fast = NodeEntry::new(Sha1Hash::MAX, ep, 5, true);
    /// let mut slow = fast;
    /// fast.verified = false;
    /// slow.verified = true;
    /// slow.rtt = 500;
    /// // verified beats a lower RTT
    /// assert!(slow.is_better_than(&fast));
    /// assert!(!fast.is_better_than(&slow));
    /// ```
    #[must_use]
    pub fn is_better_than(&self, other: &Self) -> bool {
        self.quality_cmp(other) == Ordering::Less
    }
}
