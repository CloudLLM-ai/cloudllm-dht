//! Test harness mirroring the helpers at the top of libtorrent's
//! `test/test_dht.cpp`, so that test cases port nearly line for line.
//!
//! Provenance: `test/test_dht.cpp` (the `mock_socket`, `msg_args`,
//! `send_dht_request`, `send_dht_response`, `node_from_entry`,
//! `write_peers`, `add_and_replace`, `addr4`/`addr6`/`rand_v4`/`rand_v6`
//! helpers and `get_test_keypair`) of libtorrent RC_2_1 (commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg and contributors.
//!
//! This module is public (not `#[cfg(test)]`) so the integration tests in
//! `tests/`, the fuzz targets and downstream crates' own tests can use it.
//! It is deterministic: nothing here touches the network or the clock.
//!
//! # How the C++ helpers map
//!
//! | C++                              | Rust                                   |
//! |----------------------------------|----------------------------------------|
//! | `mock_socket`, `g_sent_packets`  | [`MockSocket`] (per instance, no global) |
//! | `find_packet(ep)`                | [`MockSocket::take_packet`]            |
//! | `node_from_entry`, `lazy_from_entry` | [`Encoded::from_entry`] then [`Encoded::node`] |
//! | `msg_args`                       | [`MsgArgs`]                            |
//! | `send_dht_request` (build half)  | [`build_query`]                        |
//! | `send_dht_response` (build half) | [`build_response`]                     |
//! | `write_peers`                    | [`write_peers`]                        |
//! | `addr4("1.2.3.4")`               | [`addr4`]                              |
//! | `to_hash("ab..")`                | [`to_hash`]                            |
//! | `generate_next()`                | [`Rng::random_hash`]                   |

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::bencode::{decode, Entry, Node};
use crate::net::write_endpoint;
use crate::rng::Rng;
use crate::sha1_hash::Sha1Hash;
use crate::transport::Transport;
use crate::types::{PublicKey, SecretKey, SequenceNumber, Signature};

/// A [`Transport`] that records every packet instead of sending it
/// (libtorrent `mock_socket`).
///
/// Unlike the C++ version the record is per instance rather than a global
/// (`g_sent_packets`, which the original flags with a TODO), so tests are
/// independent.
#[derive(Debug, Default)]
pub struct MockSocket {
    /// Every packet sent so far, oldest first.
    pub sent: Vec<(SocketAddr, Entry)>,
    /// What [`Transport::has_quota`] returns; `true` unless a test turns
    /// the upload budget off.
    pub out_of_quota: bool,
}

impl MockSocket {
    /// An empty socket with unlimited quota.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Index of the first packet sent to `ep` (libtorrent `find_packet`).
    #[must_use]
    pub fn find_packet(&self, ep: SocketAddr) -> Option<usize> {
        self.sent.iter().position(|(to, _)| *to == ep)
    }

    /// Removes and returns the first packet sent to `ep`; this is what
    /// `send_dht_request` does with the response.
    pub fn take_packet(&mut self, ep: SocketAddr) -> Option<Entry> {
        self.find_packet(ep).map(|i| self.sent.remove(i).1)
    }

    /// Forgets all recorded packets (libtorrent `g_sent_packets.clear()`).
    pub fn clear(&mut self) {
        self.sent.clear();
    }
}

impl Transport for MockSocket {
    fn has_quota(&mut self) -> bool {
        !self.out_of_quota
    }

    fn send_packet(&mut self, msg: &Entry, dst: SocketAddr) -> bool {
        self.sent.push((dst, msg.clone()));
        true
    }
}

/// An [`Entry`] bencoded into an owned buffer, so tests can hold a decoded
/// [`Node`] without a self-referential struct (libtorrent
/// `lazy_from_entry` / `node_from_entry`).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::bencode::Entry;
/// use cloudllm_dht::testing::Encoded;
///
/// let mut e = Entry::dict();
/// e.set("y", "r");
/// let enc = Encoded::from_entry(&e);
/// assert_eq!(enc.node().dict_find_string_value(b"y", b""), b"r");
/// ```
#[derive(Debug, Clone)]
pub struct Encoded {
    buf: Vec<u8>,
}

impl Encoded {
    /// Bencodes `e`.
    #[must_use]
    pub fn from_entry(e: &Entry) -> Self {
        Self { buf: e.encode() }
    }

    /// The wire bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Decodes the buffer.
    ///
    /// # Panics
    ///
    /// Panics if the entry does not decode, which fails the calling test
    /// (libtorrent `TEST_CHECK(ret == 0)`).
    #[must_use]
    pub fn node(&self) -> Node<'_> {
        decode(&self.buf).expect("an encoded entry must decode")
    }
}

/// Builder for the `a`/`r` argument dictionary of a test message
/// (libtorrent `msg_args`).
///
/// Every setter returns `self`, so calls chain like the C++ ones:
/// `MsgArgs::new().token("tok").port(6881)`.
#[derive(Debug, Clone)]
pub struct MsgArgs {
    /// The dictionary being built.
    pub a: Entry,
}

impl Default for MsgArgs {
    fn default() -> Self {
        Self { a: Entry::dict() }
    }
}

impl MsgArgs {
    /// An empty argument dictionary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with(mut self, key: &str, v: impl Into<Entry>) -> Self {
        self.a.set(key, v);
        self
    }

    /// `info_hash` (20 raw bytes).
    #[must_use]
    pub fn info_hash(self, h: &Sha1Hash) -> Self {
        self.with("info_hash", h.0)
    }

    /// `n` (the torrent name of a BEP 33 search).
    #[must_use]
    pub fn name(self, n: &str) -> Self {
        self.with("n", n)
    }

    /// `token`.
    #[must_use]
    pub fn token(self, t: &[u8]) -> Self {
        self.with("token", t)
    }

    /// `port`.
    #[must_use]
    pub fn port(self, p: i64) -> Self {
        self.with("port", Entry::Int(p))
    }

    /// `target`.
    #[must_use]
    pub fn target(self, t: &Sha1Hash) -> Self {
        self.with("target", t.0)
    }

    /// `v` (a BEP 44 value).
    #[must_use]
    pub fn value(self, v: Entry) -> Self {
        self.with("v", v)
    }

    /// `scrape` as 0/1.
    #[must_use]
    pub fn scrape(self, s: bool) -> Self {
        self.with("scrape", s)
    }

    /// `seed` as 0/1.
    #[must_use]
    pub fn seed(self, s: bool) -> Self {
        self.with("seed", s)
    }

    /// `k` (BEP 44 public key).
    #[must_use]
    pub fn key(self, k: &PublicKey) -> Self {
        self.with("k", k.0)
    }

    /// `sig` (BEP 44 signature).
    #[must_use]
    pub fn sig(self, s: &Signature) -> Self {
        self.with("sig", s.0)
    }

    /// `seq` (BEP 44 sequence number).
    #[must_use]
    pub fn seq(self, s: SequenceNumber) -> Self {
        self.with("seq", Entry::Int(s.0))
    }

    /// `cas` (BEP 44 compare-and-swap).
    #[must_use]
    pub fn cas(self, c: SequenceNumber) -> Self {
        self.with("cas", Entry::Int(c.0))
    }

    /// `id`.
    #[must_use]
    pub fn nid(self, n: &Sha1Hash) -> Self {
        self.with("id", n.0)
    }

    /// `salt`, left out when empty like libtorrent's setter.
    #[must_use]
    pub fn salt(self, s: &[u8]) -> Self {
        if s.is_empty() {
            self
        } else {
            self.with("salt", s)
        }
    }

    /// Appends `w` to the `want` list.
    #[must_use]
    pub fn want(mut self, w: &str) -> Self {
        let mut list = match self.a.get("want") {
            Some(Entry::List(l)) => l.clone(),
            _ => Vec::new(),
        };
        list.push(Entry::from(w));
        self.a.set("want", Entry::List(list));
        self
    }

    /// `nodes` from a pre-packed string, skipped when empty.
    #[must_use]
    pub fn nodes(self, packed: &[u8]) -> Self {
        if packed.is_empty() {
            self
        } else {
            self.with("nodes", packed)
        }
    }

    /// `nodes6` from a pre-packed string, skipped when empty.
    #[must_use]
    pub fn nodes6(self, packed: &[u8]) -> Self {
        if packed.is_empty() {
            self
        } else {
            self.with("nodes6", packed)
        }
    }

    /// `values`: compact peers, skipped when empty.
    #[must_use]
    pub fn peers(self, peers: &BTreeSet<SocketAddr>) -> Self {
        if peers.is_empty() {
            self
        } else {
            self.with("values", write_peers(peers))
        }
    }

    /// `interval` in seconds (BEP 51).
    #[must_use]
    pub fn interval(self, secs: i64) -> Self {
        self.with("interval", Entry::Int(secs))
    }

    /// `num` (BEP 51).
    #[must_use]
    pub fn num(self, n: i64) -> Self {
        self.with("num", Entry::Int(n))
    }

    /// `samples`: concatenated 20-byte hashes (BEP 51).
    #[must_use]
    pub fn samples(self, samples: &[Sha1Hash]) -> Self {
        let bytes: Vec<u8> = samples.iter().flat_map(|h| h.0).collect();
        self.with("samples", bytes)
    }
}

/// Builds a query datagram the way `send_dht_request` does:
/// `{"q": msg, "t": t, "y": "q", "a": args}` with a random `id` inserted
/// only when `args` did not set one.
#[must_use]
pub fn build_query(msg: &str, args: &MsgArgs, t: &str, rng: &mut dyn Rng) -> Entry {
    let mut a = args.a.clone();
    if a.get("id").is_none() {
        a.set("id", rng.random_hash().0);
    }
    let mut e = Entry::dict();
    e.set("q", msg).set("t", t).set("y", "q").set("a", a);
    e
}

/// Builds a response datagram the way `send_dht_response` does:
/// `{"y": "r", "t": t, "r": args}` with a random `id` when `args` has none.
#[must_use]
pub fn build_response(t: &[u8], args: &MsgArgs, rng: &mut dyn Rng) -> Entry {
    let mut r = args.a.clone();
    if r.get("id").is_none() {
        r.set("id", rng.random_hash().0);
    }
    let mut e = Entry::dict();
    e.set("y", "r").set("t", t).set("r", r);
    e
}

/// Packs peers as a list of compact endpoint strings (libtorrent
/// `write_peers`, the `values` of a `get_peers` response).
#[must_use]
pub fn write_peers(peers: &BTreeSet<SocketAddr>) -> Entry {
    Entry::List(
        peers
            .iter()
            .map(|p| {
                let mut b = Vec::with_capacity(18);
                write_endpoint(p, &mut b);
                Entry::Str(b)
            })
            .collect(),
    )
}

/// Parses an IPv4 address, panicking on bad test input (libtorrent
/// `addr4`).
///
/// # Panics
///
/// Panics if `s` is not an IPv4 address.
#[must_use]
pub fn addr4(s: &str) -> IpAddr {
    IpAddr::V4(s.parse::<Ipv4Addr>().expect("valid IPv4 literal"))
}

/// Parses an IPv6 address, panicking on bad test input (libtorrent
/// `addr6`).
///
/// # Panics
///
/// Panics if `s` is not an IPv6 address.
#[must_use]
pub fn addr6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().expect("valid IPv6 literal"))
}

/// An endpoint from an address literal and a port (libtorrent
/// `udp::endpoint(addr4(..), port)`).
///
/// # Panics
///
/// Panics if `ip` is not an IP literal.
#[must_use]
pub fn ep(ip: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip.parse().expect("valid IP literal"), port)
}

/// A random public-looking IPv4 address (libtorrent `rand_v4`): the first
/// octet is never 0, 10, 127 or in the multicast and reserved range, so
/// BEP 42 verification applies to it.
#[must_use]
pub fn rand_v4(rng: &mut dyn Rng) -> IpAddr {
    loop {
        let b = rng.next_u32().to_be_bytes();
        let ip = Ipv4Addr::from(b);
        if !(crate::net::is_local(IpAddr::V4(ip)) || b[0] == 0 || b[0] >= 224) {
            return IpAddr::V4(ip);
        }
    }
}

/// A random global-unicast-looking IPv6 address (libtorrent `rand_v6`),
/// inside `2000::/3`.
#[must_use]
pub fn rand_v6(rng: &mut dyn Rng) -> IpAddr {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    b[0] = 0x20 | (b[0] & 0x1f);
    IpAddr::V6(Ipv6Addr::from(b))
}

/// Parses a hash from hex, panicking on bad test input (libtorrent
/// `to_hash`).
///
/// # Panics
///
/// Panics if `s` is not 40 hex digits.
#[must_use]
pub fn to_hash(s: &str) -> Sha1Hash {
    Sha1Hash::from_hex(s).expect("valid 40-digit hex literal")
}

/// Adds `add` to `dst` as 160-bit big-endian integers, wrapping on
/// overflow (libtorrent `add_and_replace`).
pub fn add_and_replace(dst: &mut Sha1Hash, add: &Sha1Hash) {
    let mut carry = 0u16;
    for k in (0..20).rev() {
        let sum = u16::from(dst.0[k]) + u16::from(add.0[k]) + carry;
        dst.0[k] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
}

/// The fixed BEP 44 test key pair of `test_dht.cpp` (`get_test_keypair`):
/// a public key and its 64-byte expanded secret key.
///
/// # Panics
///
/// Never in practice: the literals are valid hex of the right length.
#[must_use]
pub fn test_keypair() -> (PublicKey, SecretKey) {
    let pk = hex("77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548");
    let sk = hex(concat!(
        "e06d3183d14159228433ed599221b80bd0a5ce8352e4bdf0262f76786ef1c74d",
        "b7e7a9fea2c0eb269d61e3b38e450a22e754941ac78479d6c54e1faf6037881d"
    ));
    (
        PublicKey::from_slice(&pk).expect("32-byte public key"),
        SecretKey::from_slice(&sk).expect("64-byte secret key"),
    )
}

/// Decodes a hex string of any even length.
///
/// # Panics
///
/// Panics on an odd length or a non-hex digit.
#[must_use]
pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() & 1 == 0, "odd-length hex");
    s.as_bytes()
        .chunks(2)
        .map(|p| {
            let digits = std::str::from_utf8(p).expect("ascii hex");
            u8::from_str_radix(digits, 16).expect("hex digit")
        })
        .collect()
}
