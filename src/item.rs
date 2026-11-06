//! BEP 44 items: targets, signing payloads and verification.
//!
//! Provenance: `include/libtorrent/kademlia/item.hpp` and
//! `src/kademlia/item.cpp` of libtorrent RC_2_1 (commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg, Steven Siloti, Alden Torres and contributors.
//!
//! BEP 44 stores two kinds of items in the DHT. An *immutable* item is
//! addressed by the SHA-1 of its bencoded value. A *mutable* item is
//! addressed by the SHA-1 of its owner's public key and an optional salt,
//! carries a sequence number, and is authenticated by an Ed25519 signature
//! over a canonical byte string (the "signing payload") built from the salt,
//! the sequence number and the **raw bytes** of the bencoded value `v`.
//! Signing and verifying therefore operate on bytes, never on re-encoded
//! structures, which is why verification takes `&[u8]`.
//!
//! # Differences from the C++ code
//!
//! * libtorrent builds the payload in a fixed 1200-byte stack buffer and
//!   silently truncates anything longer (`canonical_string`); its own
//!   comment and `TEST_CASE(signing_oversized_salt)` document a bug fix for
//!   an overrun there, but verification of a truncated payload is still
//!   possible for an over-long `v`. Here [`signing_payload`] never
//!   truncates, [`sign_mutable_item`] signs the full payload, and
//!   [`verify_mutable_item`] returns `false` for a salt over 64 bytes (as
//!   libtorrent does) *and* for a payload over 1200 bytes (libtorrent would
//!   verify the truncated prefix). Both bounds are unreachable for valid
//!   BEP 44 traffic (`v` is at most 1000 bytes, the salt at most 64).
//! * `item::assign(entry, ..)` bencodes into a 1000-byte `std::array` with
//!   no bounds check in release builds; [`Item::signed`] rejects an encoding
//!   over 1000 bytes with [`ItemError::ValueTooLarge`].

use std::io::Write as _;

use sha1::{Digest, Sha1};

use crate::bencode::{Entry, Node};
use crate::ed25519;
use crate::sha1_hash::Sha1Hash;
use crate::types::{PublicKey, SecretKey, SequenceNumber, Signature};

/// BEP 44's cap on the bencoded value `v` of an item, in bytes.
pub const MAX_VALUE_SIZE: usize = 1000;

/// BEP 44's cap on a mutable item's salt, in bytes.
pub const MAX_SALT_SIZE: usize = 64;

/// The size of libtorrent's signing-payload buffer; a payload longer than
/// this is rejected by [`verify_mutable_item`].
pub const MAX_PAYLOAD_SIZE: usize = 1200;

/// Why an [`Item`] could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ItemError {
    /// The bencoded value is longer than [`MAX_VALUE_SIZE`].
    #[error("item value is {len} bytes, the BEP 44 limit is 1000")]
    ValueTooLarge {
        /// The encoded size.
        len: usize,
    },
    /// The salt is longer than [`MAX_SALT_SIZE`].
    #[error("item salt is {len} bytes, the BEP 44 limit is 64")]
    SaltTooLarge {
        /// The salt size.
        len: usize,
    },
    /// The signature does not verify for the value, salt and sequence number.
    #[error("item signature does not verify")]
    BadSignature,
}

/// The target (DHT key) of an immutable item: the SHA-1 of its bencoded
/// value (libtorrent `item_target_id(span v)`).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::item::immutable_item_target_id;
///
/// // BEP 44 / libtorrent test vector 3.
/// assert_eq!(
///     immutable_item_target_id(b"12:Hello World!").to_string(),
///     "e5f96f6f38320f0f33959cb4d3d656452117aadb"
/// );
/// ```
#[must_use]
pub fn immutable_item_target_id(v: &[u8]) -> Sha1Hash {
    Sha1Hash::of(v)
}

/// The target of a mutable item: the SHA-1 of the public key followed by the
/// salt (libtorrent `item_target_id(salt, pk)`). An empty salt hashes the key
/// alone.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::item::item_target_id;
/// use cloudllm_dht::testing::test_keypair;
///
/// let (pk, _) = test_keypair();
/// assert_eq!(
///     item_target_id(b"", &pk).to_string(),
///     "4a533d47ec9c7d95b1ad75f576cffc641853b750"
/// );
/// assert_eq!(
///     item_target_id(b"foobar", &pk).to_string(),
///     "411eba73b6f087ca51a3795d9c8c938d365e32c1"
/// );
/// ```
#[must_use]
pub fn item_target_id(salt: &[u8], pk: &PublicKey) -> Sha1Hash {
    let mut h = Sha1::new();
    h.update(pk.0);
    h.update(salt);
    Sha1Hash(h.finalize().into())
}

/// Builds the byte string a mutable item's signature covers (libtorrent's
/// internal `canonical_string`): `4:salt<len>:<salt>` when the salt is not
/// empty, then `3:seqi<seq>e1:v` and the raw bytes of `v`.
///
/// `v` must already be valid bencoding; this function does not check.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::item::signing_payload;
/// use cloudllm_dht::types::SequenceNumber;
///
/// assert_eq!(
///     signing_payload(b"12:Hello World!", b"foobar", SequenceNumber(1)),
///     b"4:salt6:foobar3:seqi1e1:v12:Hello World!".to_vec()
/// );
/// assert_eq!(
///     signing_payload(b"i3e", b"", SequenceNumber(-2)),
///     b"3:seqi-2e1:vi3e".to_vec()
/// );
/// ```
#[must_use]
pub fn signing_payload(v: &[u8], salt: &[u8], seq: SequenceNumber) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() + salt.len() + 64);
    // writing to a Vec cannot fail
    if !salt.is_empty() {
        let _ = write!(out, "4:salt{}:", salt.len());
        out.extend_from_slice(salt);
    }
    let _ = write!(out, "3:seqi{}e1:v", seq.0);
    out.extend_from_slice(v);
    out
}

/// Checks a mutable item's signature (libtorrent `verify_mutable_item`).
///
/// Returns `false` for a salt over [`MAX_SALT_SIZE`] bytes, for a signing
/// payload over [`MAX_PAYLOAD_SIZE`] bytes, and for any signature that does
/// not verify. This is the authentication boundary for everything a remote
/// node can `put`; it never panics on any input.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::item::{sign_mutable_item, verify_mutable_item};
/// use cloudllm_dht::testing::test_keypair;
/// use cloudllm_dht::types::SequenceNumber;
///
/// let (pk, sk) = test_keypair();
/// let seq = SequenceNumber(1);
/// let sig = sign_mutable_item(b"12:Hello World!", b"", seq, &pk, &sk);
/// assert!(verify_mutable_item(b"12:Hello World!", b"", seq, &pk, &sig));
/// assert!(!verify_mutable_item(b"12:Hello World?", b"", seq, &pk, &sig));
/// assert!(!verify_mutable_item(b"12:Hello World!", b"", seq.next(), &pk, &sig));
/// ```
#[must_use]
pub fn verify_mutable_item(
    v: &[u8],
    salt: &[u8],
    seq: SequenceNumber,
    pk: &PublicKey,
    sig: &Signature,
) -> bool {
    // The BEP 44 salt is capped at 64 bytes: a larger one can never be part
    // of a valid item.
    if salt.len() > MAX_SALT_SIZE {
        return false;
    }
    let payload = signing_payload(v, salt, seq);
    if payload.len() > MAX_PAYLOAD_SIZE {
        return false;
    }
    ed25519::verify(sig, &payload, pk)
}

/// Signs a mutable item (libtorrent `sign_mutable_item`): the Ed25519
/// signature over [`signing_payload`]. `pk` must be the public key matching
/// `sk`.
///
/// Unlike libtorrent this never truncates: an oversized salt or value
/// produces a signature [`verify_mutable_item`] will reject, not one over a
/// silently shortened payload.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::item::sign_mutable_item;
/// use cloudllm_dht::testing::test_keypair;
/// use cloudllm_dht::types::SequenceNumber;
///
/// let (pk, sk) = test_keypair();
/// let sig = sign_mutable_item(b"12:Hello World!", b"", SequenceNumber(1), &pk, &sk);
/// assert_eq!(&sig.0[..4], &[0x30, 0x5a, 0xc8, 0xae]);
/// ```
#[must_use]
pub fn sign_mutable_item(
    v: &[u8],
    salt: &[u8],
    seq: SequenceNumber,
    pk: &PublicKey,
    sk: &SecretKey,
) -> Signature {
    ed25519::sign(&signing_payload(v, salt, seq), pk, sk)
}

/// A BEP 44 item: an immutable value, or a mutable one with its key, salt,
/// sequence number and signature (libtorrent `dht::item`).
///
/// An item is *empty* until given a value ([`Item::is_empty`], libtorrent
/// `empty()`, true when the value is `undefined_t`). Construction goes
/// through the constructors below; the accessors then expose the parts the
/// storage and the lookups need.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::bencode::Entry;
/// use cloudllm_dht::item::Item;
/// use cloudllm_dht::testing::test_keypair;
/// use cloudllm_dht::types::SequenceNumber;
///
/// let (pk, sk) = test_keypair();
/// let item = Item::signed(Entry::from("Hello World!"), b"salt", SequenceNumber(7), &pk, &sk)
///     .unwrap();
/// assert!(item.is_mutable());
/// assert_eq!(item.seq(), SequenceNumber(7));
/// assert_eq!(item.salt(), b"salt");
///
/// let plain = Item::immutable(Entry::Int(1));
/// assert!(!plain.is_mutable());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Item {
    value: Entry,
    salt: Vec<u8>,
    pk: PublicKey,
    sig: Signature,
    seq: SequenceNumber,
    mutable: bool,
}

impl Item {
    /// An empty item (libtorrent's default constructor).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty *mutable* item bound to `pk` and `salt`, to be filled by a
    /// lookup result (libtorrent `item(public_key const&, span salt)`).
    #[must_use]
    pub fn for_key(pk: PublicKey, salt: &[u8]) -> Self {
        Self {
            salt: salt.to_vec(),
            pk,
            mutable: true,
            ..Self::default()
        }
    }

    /// An immutable item holding `v` (libtorrent `item(entry)`).
    #[must_use]
    pub fn immutable(v: Entry) -> Self {
        Self {
            value: v,
            ..Self::default()
        }
    }

    /// An immutable item copied from a decoded value (libtorrent
    /// `item(bdecode_node const&)`).
    #[must_use]
    pub fn immutable_from_node(v: &Node<'_>) -> Self {
        Self::immutable(Entry::from_node(v))
    }

    /// A mutable item signed here with `sk` over the bencoding of `v`
    /// (libtorrent `item(entry, salt, seq, pk, sk)`).
    ///
    /// # Errors
    ///
    /// [`ItemError::ValueTooLarge`] when the bencoding of `v` exceeds
    /// [`MAX_VALUE_SIZE`] and [`ItemError::SaltTooLarge`] when the salt
    /// exceeds [`MAX_SALT_SIZE`]; either would produce an item no node
    /// accepts.
    pub fn signed(
        v: Entry,
        salt: &[u8],
        seq: SequenceNumber,
        pk: &PublicKey,
        sk: &SecretKey,
    ) -> Result<Self, ItemError> {
        let encoded = v.encode();
        if encoded.len() > MAX_VALUE_SIZE {
            return Err(ItemError::ValueTooLarge { len: encoded.len() });
        }
        if salt.len() > MAX_SALT_SIZE {
            return Err(ItemError::SaltTooLarge { len: salt.len() });
        }
        let sig = sign_mutable_item(&encoded, salt, seq, pk, sk);
        Ok(Self::from_signed_entry(v, salt, seq, pk, &sig))
    }

    /// A mutable item from a value, key, salt, sequence number and signature
    /// that the caller has *already authenticated* (libtorrent
    /// `assign(entry, salt, seq, pk, sig)`, which does not verify). Use
    /// [`Item::from_signed_node`] for untrusted input.
    #[must_use]
    pub fn from_signed_entry(
        v: Entry,
        salt: &[u8],
        seq: SequenceNumber,
        pk: &PublicKey,
        sig: &Signature,
    ) -> Self {
        Self {
            value: v,
            salt: salt.to_vec(),
            pk: *pk,
            sig: *sig,
            seq,
            mutable: true,
        }
    }

    /// A mutable item from a decoded `v`, verifying its signature over the
    /// raw bytes of `v` (libtorrent `assign(bdecode_node, salt, seq, pk,
    /// sig)`).
    ///
    /// # Errors
    ///
    /// [`ItemError::ValueTooLarge`] when the raw `v` exceeds
    /// [`MAX_VALUE_SIZE`] (libtorrent only asserts this in debug builds) and
    /// [`ItemError::BadSignature`] when verification fails.
    pub fn from_signed_node(
        v: &Node<'_>,
        salt: &[u8],
        seq: SequenceNumber,
        pk: &PublicKey,
        sig: &Signature,
    ) -> Result<Self, ItemError> {
        let raw = v.data_section();
        if raw.len() > MAX_VALUE_SIZE {
            return Err(ItemError::ValueTooLarge { len: raw.len() });
        }
        if !verify_mutable_item(raw, salt, seq, pk, sig) {
            return Err(ItemError::BadSignature);
        }
        Ok(Self::from_signed_entry(
            Entry::from_node(v),
            salt,
            seq,
            pk,
            sig,
        ))
    }

    /// Replaces the contents with an immutable value copied from a decoded
    /// node (libtorrent `assign(bdecode_node const&)`).
    pub fn assign_immutable(&mut self, v: &Node<'_>) {
        *self = Self::immutable_from_node(v);
    }

    /// Replaces the contents with a mutable item after verifying its
    /// signature (libtorrent `bool assign(bdecode_node, salt, seq, pk,
    /// sig)`). Returns `false`, leaving `self` unchanged, when verification
    /// fails or `v` exceeds [`MAX_VALUE_SIZE`].
    pub fn assign_mutable(
        &mut self,
        v: &Node<'_>,
        salt: &[u8],
        seq: SequenceNumber,
        pk: &PublicKey,
        sig: &Signature,
    ) -> bool {
        match Self::from_signed_node(v, salt, seq, pk, sig) {
            Ok(item) => {
                *self = item;
                true
            }
            Err(_) => false,
        }
    }

    /// Resets to an empty value (libtorrent `clear()`, which only resets the
    /// value, leaving key, salt and sequence number as they were).
    pub fn clear(&mut self) {
        self.value = Entry::Undefined;
    }

    /// `true` when the item holds no value (libtorrent `empty()`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self.value, Entry::Undefined)
    }

    /// `true` for a mutable item (libtorrent `is_mutable()`).
    #[must_use]
    pub fn is_mutable(&self) -> bool {
        self.mutable
    }

    /// The value.
    #[must_use]
    pub fn value(&self) -> &Entry {
        &self.value
    }

    /// The owner's public key (all zero for an immutable item).
    #[must_use]
    pub fn pk(&self) -> &PublicKey {
        &self.pk
    }

    /// The signature (all zero for an immutable item).
    #[must_use]
    pub fn sig(&self) -> &Signature {
        &self.sig
    }

    /// The sequence number (`0` for an immutable item).
    #[must_use]
    pub fn seq(&self) -> SequenceNumber {
        self.seq
    }

    /// The salt, as raw bytes (empty when none).
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// The target this item is stored under: the SHA-1 of the encoded value
    /// for an immutable item, of key and salt for a mutable one.
    #[must_use]
    pub fn target(&self) -> Sha1Hash {
        if self.mutable {
            item_target_id(&self.salt, &self.pk)
        } else {
            immutable_item_target_id(&self.value.encode())
        }
    }
}
