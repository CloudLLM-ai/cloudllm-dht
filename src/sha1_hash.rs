//! The 160-bit hash used for both node IDs and info-hashes.
//!
//! Provenance: `include/libtorrent/sha1_hash.hpp` (`digest32<160>`) and
//! `include/libtorrent/kademlia/node_id.hpp` (`using node_id = sha1_hash`) of
//! libtorrent RC_2_1 (commit `86d573f2631b0162d3cca5e257217eaf530fdcba`),
//! BSD-3-Clause, Copyright Arvid Norberg and contributors.

use std::fmt;
use std::ops::{BitXor, Index};
use std::str::FromStr;

use sha1::{Digest, Sha1};

/// Number of bytes in a [`Sha1Hash`].
pub const HASH_LEN: usize = 20;

/// A 160-bit value, ordered like `memcmp` (big-endian, byte by byte).
///
/// libtorrent uses one type, `sha1_hash`, for node IDs, info-hashes and BEP
/// 44 targets; [`crate::node_id::NodeId`] is an alias for it here too. The
/// derived `Ord` is the numeric order of the 160-bit big-endian integer,
/// which is what Kademlia's XOR metric comparisons need.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::Sha1Hash;
///
/// let a: Sha1Hash = "0000000000000000000000000000000000000002".parse().unwrap();
/// let b: Sha1Hash = "0000000000000000000000000000000000000004".parse().unwrap();
/// assert!(a < b);
/// assert_eq!((a ^ b).leading_zeros(), 157);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Sha1Hash(pub [u8; HASH_LEN]);

/// The input to [`Sha1Hash::from_hex`] was not 40 hexadecimal digits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected 40 hexadecimal digits, got {0:?}")]
pub struct ParseHashError(pub String);

impl Sha1Hash {
    /// All zero bits (libtorrent `sha1_hash::min()`).
    pub const MIN: Self = Self([0; HASH_LEN]);
    /// All one bits (libtorrent `sha1_hash::max()`).
    pub const MAX: Self = Self([0xff; HASH_LEN]);

    /// The SHA-1 digest of `data` (libtorrent `hasher(data).final()`).
    #[must_use]
    pub fn of(data: &[u8]) -> Self {
        Self(Sha1::digest(data).into())
    }

    /// Builds a hash from exactly 20 bytes; `None` for any other length.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; HASH_LEN]>::try_from(bytes).ok().map(Self)
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Parses 40 hex digits (either case).
    ///
    /// # Errors
    ///
    /// [`ParseHashError`] when the length is not 40 or a digit is invalid.
    pub fn from_hex(s: &str) -> Result<Self, ParseHashError> {
        let err = || ParseHashError(s.to_owned());
        if s.len() != HASH_LEN * 2 || !s.is_ascii() {
            return Err(err());
        }
        let mut out = [0u8; HASH_LEN];
        for (byte, pair) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
            let digits = std::str::from_utf8(pair).map_err(|_| err())?;
            *byte = u8::from_str_radix(digits, 16).map_err(|_| err())?;
        }
        Ok(Self(out))
    }

    /// Number of leading zero bits, `160` for the zero hash (libtorrent
    /// `count_leading_zeroes`).
    #[must_use]
    pub fn leading_zeros(&self) -> u32 {
        let mut n = 0;
        for b in self.0 {
            n += b.leading_zeros();
            if b != 0 {
                break;
            }
        }
        n
    }

    /// Shifts the whole value left by `bits` (libtorrent `operator<<=`),
    /// filling with zeros; shifting by 160 or more gives zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use cloudllm_dht::Sha1Hash;
    /// let h = Sha1Hash::from_hex("00ff000000000000000000000000000000000001").unwrap();
    /// assert_eq!(h.shl(4).to_string(), "0ff0000000000000000000000000000000000010");
    /// ```
    #[must_use]
    pub fn shl(&self, bits: usize) -> Self {
        let mut out = [0u8; HASH_LEN];
        let (bytes, rem) = (bits / 8, bits % 8);
        for (i, o) in out.iter_mut().enumerate() {
            let hi = self.0.get(i + bytes).copied().unwrap_or(0);
            let lo = self.0.get(i + bytes + 1).copied().unwrap_or(0);
            *o = if rem == 0 {
                hi
            } else {
                (hi << rem) | (lo >> (8 - rem))
            };
        }
        Self(out)
    }

    /// Lowercase hexadecimal, the form libtorrent prints.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for Sha1Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for Sha1Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha1Hash({self})")
    }
}

impl FromStr for Sha1Hash {
    type Err = ParseHashError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl BitXor for Sha1Hash {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        let mut out = self.0;
        out.iter_mut().zip(rhs.0).for_each(|(a, b)| *a ^= b);
        Self(out)
    }
}

impl Index<usize> for Sha1Hash {
    type Output = u8;
    fn index(&self, i: usize) -> &u8 {
        &self.0[i]
    }
}

impl AsRef<[u8]> for Sha1Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; HASH_LEN]> for Sha1Hash {
    fn from(b: [u8; HASH_LEN]) -> Self {
        Self(b)
    }
}
