//! Cheap checks on a raw datagram before any node sees it.
//!
//! Provenance: the first half of `dht_tracker::incoming_packet` in
//! `src/kademlia/dht_tracker.cpp` (libtorrent RC_2_1, commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg and contributors.
//!
//! The order matters and matches libtorrent: shape, then the dark-internet
//! filter, then (in the tracker) the IP filter and the DoS blocker, then
//! the bencode parse. Everything cheaper than parsing runs first so a flood
//! of garbage costs one branch per packet.

use std::net::IpAddr;

/// A datagram shorter than or equal to this cannot hold a DHT message
/// (libtorrent: `buf_size <= 20`).
pub const MIN_DATAGRAM: usize = 21;

/// The IPv4 class-A first octets that are not available to the public, so a
/// message from them is suspicious (`class_a` in `incoming_packet`).
pub const DARK_INTERNET_FIRST_OCTETS: [u8; 17] = [
    3, 6, 7, 9, 11, 19, 21, 22, 25, 26, 28, 29, 30, 33, 34, 48, 56,
];

/// `true` when `buf` can possibly be a bencoded dictionary of useful size:
/// longer than 20 bytes, starting with `d` and ending with `e`
/// (libtorrent returns `false` for anything else, without counting it).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::tracker::prefilter::plausible_dht_datagram;
/// assert!(plausible_dht_datagram(b"d1:y1:q1:q4:ping1:t2:aa1:ai1ee"));
/// assert!(!plausible_dht_datagram(b"d1:ae"));
/// assert!(!plausible_dht_datagram(b"x1:y1:q1:q4:ping1:t2:aa1:ai1ee"));
/// ```
#[must_use]
pub fn plausible_dht_datagram(buf: &[u8]) -> bool {
    buf.len() >= MIN_DATAGRAM && buf.first() == Some(&b'd') && buf.last() == Some(&b'e')
}

/// `true` when `ip` is an IPv4 address in one of the unallocated class-A
/// networks (`dht_ignore_dark_internet`). IPv6 never is.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::tracker::prefilter::is_dark_internet;
/// assert!(is_dark_internet("3.1.2.3".parse().unwrap()));
/// assert!(!is_dark_internet("8.8.8.8".parse().unwrap()));
/// assert!(!is_dark_internet("2001:db8::1".parse().unwrap()));
/// ```
#[must_use]
pub fn is_dark_internet(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => DARK_INTERNET_FIRST_OCTETS.contains(&v4.octets()[0]),
        IpAddr::V6(_) => false,
    }
}
