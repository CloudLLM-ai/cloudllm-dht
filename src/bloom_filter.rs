//! The BEP 33 bloom filter used for scrape.
//!
//! Provenance: `include/libtorrent/aux_/bloom_filter.hpp` and
//! `src/bloom_filter.cpp` of libtorrent RC_2_1 (commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg and contributors. (In libtorrent the header is under
//! `aux_/`, not `kademlia/`; the work-package table calls it
//! `bloom_filter.hpp`.)
//!
//! BEP 33 specifies a 2048-bit (256-byte) filter with two hash functions:
//! the SHA-1 of an IP address supplies the bit indices. The filter is
//! generic over its byte length `N` because libtorrent also uses a
//! 128-byte one to count the announcers of a stored BEP 44 item.

use std::net::IpAddr;

use crate::sha1_hash::{Sha1Hash, HASH_LEN};

/// The SHA-1 of an address's raw bytes (4 for IPv4, 16 for IPv6): the key
/// under which a peer address enters a [`BloomFilter`] (libtorrent
/// `aux::hash_address` in `src/socket_io.cpp`).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::bloom_filter::hash_address;
/// use cloudllm_dht::Sha1Hash;
///
/// let ip = "192.0.2.1".parse().unwrap();
/// assert_eq!(hash_address(ip), Sha1Hash::of(&[192, 0, 2, 1]));
/// ```
#[must_use]
pub fn hash_address(ip: IpAddr) -> Sha1Hash {
    match ip {
        IpAddr::V4(a) => Sha1Hash::of(&a.octets()),
        IpAddr::V6(a) => Sha1Hash::of(&a.octets()),
    }
}

/// Number of zero bits in `bits` (libtorrent `aux::count_zero_bits`).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::bloom_filter::count_zero_bits;
/// assert_eq!(count_zero_bits(&[0x00, 0xff, 0x0f]), 12);
/// ```
#[must_use]
pub fn count_zero_bits(bits: &[u8]) -> usize {
    bits.iter().map(|b| b.count_zeros() as usize).sum()
}

/// A bloom filter of `N` bytes with libtorrent's two-index scheme
/// (`aux::bloom_filter<N>`).
///
/// The bit indices of a key are `k[0] | k[1] << 8` and `k[2] | k[3] << 8`,
/// each taken modulo `N * 8`; the key is the SHA-1 of the item (for scrape,
/// of the peer's IP address bytes), so both indices are well distributed.
/// BEP 33 requires exactly this layout so the filters interoperate.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::bloom_filter::BloomFilter;
/// use cloudllm_dht::Sha1Hash;
///
/// let mut f = BloomFilter::<256>::new();
/// let k = Sha1Hash::of(b"1.2.3.4");
/// assert!(!f.find(&k));
/// f.set(&k);
/// assert!(f.find(&k));
/// assert!((f.size() - 1.0).abs() < 0.1); // one item sets two bits
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct BloomFilter<const N: usize> {
    bits: [u8; N],
}

impl<const N: usize> std::fmt::Debug for BloomFilter<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BloomFilter<{N}>(~{} items)", self.size())
    }
}

impl<const N: usize> Default for BloomFilter<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> BloomFilter<N> {
    const NBITS: u32 = {
        assert!(N > 0 && N * 8 <= u32::MAX as usize, "bad bloom filter size");
        (N * 8) as u32
    };

    /// An empty filter (libtorrent's default constructor, `clear()`).
    #[must_use]
    pub const fn new() -> Self {
        Self { bits: [0; N] }
    }

    /// Builds a filter from its wire form (libtorrent `from_string`).
    /// `None` unless `bytes` is exactly `N` long; libtorrent's `memcpy`
    /// trusts the caller, here a wrong length is a typed rejection.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        <[u8; N]>::try_from(bytes).ok().map(|bits| Self { bits })
    }

    /// The wire form: the raw bits (libtorrent `to_string`).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bits
    }

    /// Clears every bit (libtorrent `clear`).
    pub fn clear(&mut self) {
        self.bits = [0; N];
    }

    fn indices(k: &Sha1Hash) -> (usize, usize) {
        let [a, b, c, d, ..] = k.0;
        let idx1 = (u32::from(a) | (u32::from(b) << 8)) % Self::NBITS;
        let idx2 = (u32::from(c) | (u32::from(d) << 8)) % Self::NBITS;
        (idx1 as usize, idx2 as usize)
    }

    /// Whether `k` may have been added: no false negatives, and false
    /// positives with the filter's usual probability (libtorrent `find`).
    #[must_use]
    pub fn find(&self, k: &Sha1Hash) -> bool {
        let (i1, i2) = Self::indices(k);
        self.bits[i1 / 8] & (1 << (i1 & 7)) != 0 && self.bits[i2 / 8] & (1 << (i2 & 7)) != 0
    }

    /// Adds `k` (libtorrent `set`).
    pub fn set(&mut self, k: &Sha1Hash) {
        let (i1, i2) = Self::indices(k);
        self.bits[i1 / 8] |= 1 << (i1 & 7);
        self.bits[i2 / 8] |= 1 << (i2 & 7);
    }

    /// The BEP 33 estimate of the number of distinct items added:
    /// `ln(c / m) / (2 ln(1 - 1/m))` with `m = 8N` bits and `c` zero bits,
    /// `c` capped *above* at `m - 1`. An empty filter therefore estimates
    /// exactly `0.5` items, not `0`; a completely full one (`c == 0`) has no
    /// finite estimate and gives positive infinity, as in libtorrent's
    /// `size()` (which also computes in `f32`).
    #[must_use]
    pub fn size(&self) -> f32 {
        let m = Self::NBITS as usize;
        let c = count_zero_bits(&self.bits).min(m - 1);
        let (c, m) = (c as f32, m as f32);
        (c / m).ln() / (2.0 * (1.0 - 1.0 / m).ln())
    }
}

/// Compile-time check that a [`Sha1Hash`] always has the four bytes the
/// index computation reads.
const _: () = assert!(HASH_LEN >= 4);
