//! Flags of an `announce_peer`: seed, implied port, SSL.
//!
//! Provenance: `include/libtorrent/kademlia/announce_flags.hpp` of
//! libtorrent RC_2_1 (commit `86d573f2631b0162d3cca5e257217eaf530fdcba`),
//! BSD-3-Clause, Copyright Arvid Norberg and contributors.
//!
//! libtorrent models these as `flags::bitfield_flag<std::uint8_t, ...>`
//! constants in the `announce` namespace (`announce::seed`,
//! `announce::implied_port`, `announce::ssl_torrent`). [`AnnounceFlags`] is
//! the same thing as a tiny hand-written newtype (no `bitflags` dependency),
//! with the same bit positions so a value round-trips with a libtorrent
//! `announce_flags_t`.

use std::ops::{BitAnd, BitOr, BitOrAssign, Not};

/// A set of announce flags (libtorrent `dht::announce_flags_t`).
///
/// Combine flags with `|`, test with [`AnnounceFlags::contains`].
///
/// # Examples
///
/// ```
/// use cloudllm_dht::announce_flags::AnnounceFlags;
///
/// let f = AnnounceFlags::SEED | AnnounceFlags::IMPLIED_PORT;
/// assert!(f.contains(AnnounceFlags::SEED));
/// assert!(!f.contains(AnnounceFlags::SSL_TORRENT));
/// assert_eq!(f.bits(), 0b011);
/// assert_eq!(AnnounceFlags::default(), AnnounceFlags::EMPTY);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AnnounceFlags(u8);

impl AnnounceFlags {
    /// No flag set.
    pub const EMPTY: Self = Self(0);

    /// Announce to the DHT as a seed (libtorrent `announce::seed`, bit 0).
    pub const SEED: Self = Self(1 << 0);

    /// Announce with the BEP 5 `implied_port` flag set: tells the network to
    /// use the source UDP port of the announce as the listen port rather than
    /// the one in the message, which can help traverse NATs when using uTP
    /// (libtorrent `announce::implied_port`, bit 1).
    pub const IMPLIED_PORT: Self = Self(1 << 1);

    /// The announced port is the SSL listen socket's port (libtorrent
    /// `announce::ssl_torrent`, bit 2).
    pub const SSL_TORRENT: Self = Self(1 << 2);

    /// Builds a flag set from raw bits, keeping unknown bits (as the C++
    /// `bitfield_flag` does, so values from a newer libtorrent survive a
    /// round trip).
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// The raw bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// `true` when no flag is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// `true` when every flag of `other` is also set in `self` (an empty
    /// `other` is always contained).
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// `self` with the flags of `other` added (the const form of `|`).
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// `self` with the flags of `other` removed.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl BitOr for AnnounceFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl BitOrAssign for AnnounceFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = self.union(rhs);
    }
}

impl BitAnd for AnnounceFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl Not for AnnounceFlags {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}
