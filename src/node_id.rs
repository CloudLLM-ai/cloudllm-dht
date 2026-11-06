//! Node IDs: the XOR metric, BEP 42 ID generation and verification, and the
//! "secret" IDs a node uses to recognise its own lookups.
//!
//! Provenance: `src/kademlia/node_id.cpp` and
//! `include/libtorrent/kademlia/node_id.hpp` of libtorrent RC_2_1 (commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg, Alden Torres and Steven Siloti.
//!
//! # BEP 42
//!
//! A node's ID is derived from its external IP so an attacker cannot pick
//! an ID next to a victim's: the first 21 bits are the CRC32C of the masked
//! IP combined with a 3-bit random value `r`, and the last byte stores
//! `r`. [`generate_id_impl`] builds such an ID and [`verify_id`] checks one;
//! local addresses are exempt from verification because their "external"
//! IP is meaningless to the sender.

use std::net::IpAddr;

use sha1::{Digest, Sha1};

use crate::net::is_local;
use crate::rng::Rng;
use crate::sha1_hash::Sha1Hash;

/// A node's 160-bit ID; the same type as an info-hash (libtorrent
/// `using node_id = sha1_hash`).
pub type NodeId = Sha1Hash;

/// The Kademlia XOR distance between two IDs (libtorrent `distance`).
#[must_use]
pub fn distance(n1: &NodeId, n2: &NodeId) -> NodeId {
    *n1 ^ *n2
}

/// `true` if `n1` is strictly closer to `reference` than `n2`
/// (libtorrent `compare_ref`).
#[must_use]
pub fn compare_ref(n1: &NodeId, n2: &NodeId, reference: &NodeId) -> bool {
    (*n1 ^ *reference) < (*n2 ^ *reference)
}

/// The bucket exponent of the distance: `n` such that
/// `2^n <= distance < 2^(n+1)`, i.e. `159 - leading_zeros` clamped at `0`
/// (libtorrent `distance_exp`).
///
/// libtorrent notes that "159 - clz" is slightly odd (160 would be
/// natural) but all other code is tuned to it, so it is preserved.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::node_id::distance_exp;
/// use cloudllm_dht::Sha1Hash;
///
/// let a = Sha1Hash::MAX;
/// assert_eq!(distance_exp(&a, &Sha1Hash::MIN), 159);
/// assert_eq!(distance_exp(&a, &a), 0);
/// ```
#[must_use]
pub fn distance_exp(n1: &NodeId, n2: &NodeId) -> i32 {
    let clz = i32::try_from(distance(n1, n2).leading_zeros()).expect("at most 160");
    (159 - clz).max(0)
}

/// The smallest [`distance_exp`] from `n1` to any of `ids`; `160` when
/// `ids` is empty (libtorrent asserts non-empty and starts from `160`).
#[must_use]
pub fn min_distance_exp(n1: &NodeId, ids: &[NodeId]) -> i32 {
    ids.iter()
        .map(|id| distance_exp(n1, id))
        .fold(160, i32::min)
}

/// Builds a BEP 42 ID for `ip` with the 3-bit-significant random value `r`
/// (libtorrent `generate_id_impl`).
///
/// The ID is `crc32c(masked ip | r << 29)` in its first 21 bits, random in
/// the rest, and ends in the byte `r`. For IPv4 the mask is
/// `03.0f.3f.ff`, for IPv6 the first eight bytes are masked with
/// `01.03.07.0f.1f.3f.7f.ff`.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::node_id::{generate_id_impl, verify_id};
/// use cloudllm_dht::rng::TestRng;
///
/// let ip = "124.31.75.21".parse().unwrap();
/// let id = generate_id_impl(ip, 1, &mut TestRng::new(1));
/// assert_eq!(&id.0[..2], &[0x5f, 0xbf]); // BEP 42 test vector
/// assert!(verify_id(&id, ip));
/// ```
#[must_use]
pub fn generate_id_impl(ip: IpAddr, r: u32, rng: &mut dyn Rng) -> NodeId {
    const V4_MASK: [u8; 4] = [0x03, 0x0f, 0x3f, 0xff];
    const V6_MASK: [u8; 8] = [0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff];
    let mut octets: Vec<u8> = match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets()[..8].to_vec(),
    };
    let mask: &[u8] = if ip.is_ipv4() { &V4_MASK } else { &V6_MASK };
    octets.iter_mut().zip(mask).for_each(|(o, m)| *o &= m);
    octets[0] |= ((r & 0x7) << 5) as u8;
    let c = crc32c::crc32c(&octets);

    let mut id = [0u8; 20];
    id[0] = (c >> 24) as u8;
    id[1] = (c >> 16) as u8;
    id[2] = (((c >> 8) & 0xf8) as u8) | (rng.random(0x7) as u8);
    rng.fill_bytes(&mut id[3..19]);
    id[19] = (r & 0xff) as u8;
    Sha1Hash(id)
}

/// Generates a BEP 42 ID for the node's external address (libtorrent
/// `generate_id`).
#[must_use]
pub fn generate_id(external_ip: IpAddr, rng: &mut dyn Rng) -> NodeId {
    let r = rng.next_u32();
    generate_id_impl(external_ip, r, rng)
}

/// Checks that `nid` is a valid BEP 42 ID for a node reachable at
/// `source_ip` (libtorrent `verify_id`).
///
/// Local and private addresses always verify: their public address is
/// unknown to the sender, so a mismatch proves nothing.
#[must_use]
pub fn verify_id(nid: &NodeId, source_ip: IpAddr) -> bool {
    if is_local(source_ip) {
        return true;
    }
    // `rng` is unused for the bits compared below; any source will do.
    let h = generate_id_impl(
        source_ip,
        u32::from(nid[19]),
        &mut crate::rng::TestRng::new(0),
    );
    nid[0] == h[0] && nid[1] == h[1] && (nid[2] & 0xf8) == (h[2] & 0xf8)
}

/// A uniformly random ID: the SHA-1 of 20 random bytes (libtorrent
/// `generate_random_id`).
#[must_use]
pub fn generate_random_id(rng: &mut dyn Rng) -> NodeId {
    let mut r = [0u8; 20];
    rng.fill_bytes(&mut r);
    Sha1Hash::of(&r)
}

/// libtorrent keeps one process-wide secret in a static; here it is a value
/// the caller owns, so two nodes (or two tests) cannot interfere.
///
/// A "secret ID" carries 4 random bytes and a 4-byte keyed digest of them
/// in its tail, which lets the node later tell an ID it made (for example
/// for a privacy lookup) from a foreign one without remembering it.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::node_id::IdSecret;
/// use cloudllm_dht::rng::TestRng;
///
/// let mut rng = TestRng::new(9);
/// let secret = IdSecret::new(&mut rng);
/// let mut id = secret.generate_secret_id(&mut rng);
/// assert!(secret.verify_secret_id(&id));
/// id.0[19] ^= 0x55;
/// assert!(!secret.verify_secret_id(&id));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdSecret(u32);

impl IdSecret {
    /// Draws a non-zero secret (libtorrent `random(0xfffffffe) + 1`).
    #[must_use]
    pub fn new(rng: &mut dyn Rng) -> Self {
        Self(rng.random(0xffff_fffe) + 1)
    }

    /// A secret with a fixed value, for tests.
    #[must_use]
    pub fn from_value(v: u32) -> Self {
        Self(v)
    }

    fn signature(self, rand: [u8; 4]) -> [u8; 4] {
        let mut h = Sha1::new();
        h.update(self.0.to_le_bytes());
        h.update(rand);
        let digest = h.finalize();
        [digest[0], digest[1], digest[2], digest[3]]
    }

    /// Stamps `id`'s last 8 bytes with a random value and its signature
    /// (libtorrent `make_id_secret`).
    pub fn make_id_secret(self, id: &mut NodeId, rng: &mut dyn Rng) {
        let rand = rng.next_u32().to_le_bytes();
        id.0[12..16].copy_from_slice(&rand);
        id.0[16..20].copy_from_slice(&self.signature(rand));
    }

    /// A random ID that [`IdSecret::verify_secret_id`] accepts (libtorrent
    /// `generate_secret_id`).
    #[must_use]
    pub fn generate_secret_id(self, rng: &mut dyn Rng) -> NodeId {
        let mut id = generate_random_id(rng);
        self.make_id_secret(&mut id, rng);
        id
    }

    /// `true` if `id` was stamped with this secret (libtorrent
    /// `verify_secret_id`; the C++ returns `false` while its static secret
    /// is still unset, which cannot happen here).
    #[must_use]
    pub fn verify_secret_id(self, id: &NodeId) -> bool {
        let rand = [id[12], id[13], id[14], id[15]];
        id.0[16..20] == self.signature(rand)
    }
}

/// `true` if the first bits of `nid`, after shifting left by `offset` bits,
/// satisfy `(first_byte & mask) == prefix` (libtorrent `matching_prefix`).
#[must_use]
pub fn matching_prefix(nid: &NodeId, mask: u8, prefix: u8, offset: usize) -> bool {
    (nid.shl(offset)[0] & mask) == prefix
}

/// An ID whose first `bits` bits are one and the rest zero; `bits` above
/// 160 is clamped (libtorrent `generate_prefix_mask`).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::node_id::generate_prefix_mask;
/// assert_eq!(
///     generate_prefix_mask(11).to_string(),
///     "ffe0000000000000000000000000000000000000"
/// );
/// ```
#[must_use]
pub fn generate_prefix_mask(bits: usize) -> NodeId {
    let bits = bits.min(160);
    let mut mask = [0u8; 20];
    for (i, m) in mask.iter_mut().enumerate() {
        let start = i * 8;
        *m = match bits.saturating_sub(start) {
            0 => 0,
            n if n >= 8 => 0xff,
            n => 0xffu8 << (8 - n),
        };
    }
    Sha1Hash(mask)
}
