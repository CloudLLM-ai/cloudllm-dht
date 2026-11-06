//! BEP 44 key, signature and sequence-number types.
//!
//! Provenance: `include/libtorrent/kademlia/types.hpp` of libtorrent RC_2_1
//! (commit `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause,
//! Copyright Arvid Norberg and Alden Torres.
//!
//! The C++ `public_key`, `secret_key` and `signature` are bare byte arrays;
//! here each is a distinct newtype so a signature cannot be passed where a
//! key is expected. `secret_key` is libtorrent's 64-byte *expanded* Ed25519
//! secret (the SHA-512 expansion of the seed, clamped), not a 32-byte seed;
//! see `docs/ARCHITECTURE.md` for how it maps onto `ed25519-dalek`.

use std::fmt;

macro_rules! byte_newtype {
    ($(#[$m:meta])* $name:ident, $len:expr) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            /// Length in bytes.
            pub const LEN: usize = $len;

            /// Builds the value from exactly `LEN` bytes; `None` otherwise.
            #[must_use]
            pub fn from_slice(b: &[u8]) -> Option<Self> {
                <[u8; $len]>::try_from(b).ok().map(Self)
            }

            /// The raw bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self { Self([0; $len]) }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] { &self.0 }
        }
    };
}

byte_newtype!(
    /// A 32-byte Ed25519 public key (libtorrent `dht::public_key`).
    PublicKey, 32
);
byte_newtype!(
    /// A 64-byte Ed25519 signature (libtorrent `dht::signature`).
    Signature, 64
);
byte_newtype!(
    /// A 64-byte expanded Ed25519 secret key (libtorrent `dht::secret_key`).
    ///
    /// Its `Debug` output is redacted so keys do not leak into logs.
    SecretKey, 64
);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str(")")
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signature(")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str(")")
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// A BEP 44 mutable-item sequence number (libtorrent `sequence_number`).
///
/// Newtype over `i64`, ordered numerically; storing the sequence number of
/// an item as the wire integer keeps `seq` comparisons and CAS checks in one
/// place.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::types::SequenceNumber;
///
/// let s = SequenceNumber(4);
/// assert!(s.next() > s);
/// assert_eq!(s.next().prev(), s);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SequenceNumber(pub i64);

impl SequenceNumber {
    /// The following sequence number (saturating).
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// The preceding sequence number (saturating).
    #[must_use]
    pub fn prev(self) -> Self {
        Self(self.0.saturating_sub(1))
    }
}
