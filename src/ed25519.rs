//! Ed25519 over libtorrent-compatible 64-byte expanded secret keys.
//!
//! Provenance: `include/libtorrent/kademlia/ed25519.hpp`,
//! `src/kademlia/ed25519.cpp` and `src/ed25519/{keypair,sign,verify,
//! add_scalar,key_exchange}.cpp` of libtorrent RC_2_1 (commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg, Alden Torres and contributors (the C code is orlp's
//! `ed25519`, itself derived from SUPERCOP ref10).
//!
//! # Key format
//!
//! libtorrent's [`SecretKey`] is the 64-byte SHA-512 expansion of a 32-byte
//! seed: the first 32 bytes are the clamped secret scalar `a`, the last 32
//! the "prefix" hashed into the nonce. [`create_keypair`] produces exactly
//! that, so keys saved by libtorrent (and the fixed key pair of
//! `test_dht.cpp`) work unchanged.
//!
//! # Why this is built on `curve25519-dalek` and not `ed25519-dalek`
//!
//! `ed25519-dalek`'s `hazmat::ExpandedSecretKey::from_bytes` *re-clamps* the
//! scalar half, which breaks keys produced by [`add_scalar`] (their scalar is
//! `a + n mod l`, deliberately not clamped); its `raw_sign` demands a valid
//! `VerifyingKey`, whereas libtorrent signs with whatever 32 bytes the
//! caller supplies; and its `verify` rejects non-canonical `S` while
//! libtorrent only requires `sig[63] & 224 == 0`, accepting `S + l`. A DHT
//! node must accept exactly the items its peers accept, so this module
//! implements the (short) algorithms of the C code on `curve25519-dalek`
//! group and scalar primitives, and the test suite cross-checks every
//! signature and verification against `ed25519-dalek` as a differential
//! oracle (`tests/ed25519.rs`).
//!
//! # Deliberate differences from the C code
//!
//! * [`add_scalar_public`], [`add_scalar_secret`] and [`key_exchange`]
//!   return `Option`: given a public key that is not a point on the curve
//!   the C code computes garbage from uninitialised field elements; here
//!   that is `None`.
//! * Key generation takes the randomness as an argument ([`create_seed`]
//!   takes an [`Rng`]) instead of reading the OS RNG itself.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::rng::Rng;
use crate::types::{PublicKey, SecretKey, Signature};

/// A 32-byte seed from which a key pair is derived
/// (libtorrent `std::array<char, 32>` of `ed25519_create_seed`).
pub type Seed = [u8; 32];

/// A 32-byte shared secret (the output of [`key_exchange`]).
pub type SharedSecret = [u8; 32];

fn sha512<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 64] {
    let mut h = Sha512::new();
    parts.into_iter().for_each(|p| h.update(p));
    h.finalize().into()
}

/// The 32-byte halves of a 64-byte array.
fn halves(b: &[u8; 64]) -> (&[u8; 32], &[u8; 32]) {
    let (lo, hi) = b.split_at(32);
    (
        <&[u8; 32]>::try_from(lo).expect("split_at(32) of 64 bytes"),
        <&[u8; 32]>::try_from(hi).expect("split_at(32) of 64 bytes"),
    )
}

/// Draws a fresh random seed (libtorrent `ed25519_create_seed`, which reads
/// the OS CSPRNG; pass [`crate::rng::SystemRng`] for the same behaviour).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::ed25519::create_seed;
/// use cloudllm_dht::rng::SystemRng;
///
/// let a = create_seed(&mut SystemRng);
/// let b = create_seed(&mut SystemRng);
/// assert_ne!(a, b);
/// ```
#[must_use]
pub fn create_seed(rng: &mut dyn Rng) -> Seed {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    seed
}

/// Derives the key pair a seed determines (libtorrent
/// `ed25519_create_keypair`): SHA-512 the seed, clamp the scalar half
/// (`&= 248`, `[31] &= 63`, `[31] |= 64`), publish `scalar * B`.
///
/// The seed fully determines the pair, so saving the seed is enough; the
/// 64-byte secret key is the cheaper-to-use, larger encoding.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::ed25519::create_keypair;
///
/// // RFC 8032 test vector 1 (the seed is the "secret key" there).
/// let seed: [u8; 32] = [
///     0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
///     0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
/// ];
/// let (pk, _sk) = create_keypair(&seed);
/// assert_eq!(pk.0[0], 0xd7);
/// assert_eq!(pk.0[31], 0x1a);
/// ```
#[must_use]
pub fn create_keypair(seed: &Seed) -> (PublicKey, SecretKey) {
    let mut sk = sha512([seed.as_slice()]);
    sk[0] &= 248;
    sk[31] &= 63;
    sk[31] |= 64;
    let (scalar, _) = halves(&sk);
    let a = Scalar::from_bytes_mod_order(*scalar);
    let pk = EdwardsPoint::mul_base(&a).compress().to_bytes();
    (PublicKey(pk), SecretKey(sk))
}

/// Signs `msg` (libtorrent `ed25519_sign`): `r = H(prefix || msg) mod l`,
/// `R = r B`, `S = r + H(R || pk || msg) * a mod l`, signature `R || S`.
///
/// `pk` is hashed as the caller supplies it (as in libtorrent): pass the
/// key that matches `sk`, or the result will not verify.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::ed25519::{create_keypair, sign, verify};
///
/// let (pk, sk) = create_keypair(&[7; 32]);
/// let sig = sign(b"hello", &pk, &sk);
/// assert!(verify(&sig, b"hello", &pk));
/// assert!(!verify(&sig, b"hellp", &pk));
/// ```
#[must_use]
pub fn sign(msg: &[u8], pk: &PublicKey, sk: &SecretKey) -> Signature {
    let (scalar, prefix) = halves(&sk.0);
    let a = Scalar::from_bytes_mod_order(*scalar);
    let r = Scalar::from_bytes_mod_order_wide(&sha512([prefix.as_slice(), msg]));
    let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
    let hram = Scalar::from_bytes_mod_order_wide(&sha512([&big_r[..], &pk.0[..], msg]));
    let s = hram * a + r;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&big_r);
    sig[32..].copy_from_slice(&s.to_bytes());
    Signature(sig)
}

/// Verifies a signature exactly as libtorrent does (`ed25519_verify`).
///
/// The accepted set is libtorrent's, which is slightly wider than RFC 8032
/// strict verification: `S` only has to fit in 253 bits (`sig[63] & 224 ==
/// 0`), so the malleated `S + l` of a valid signature also verifies, and
/// non-canonical encodings of the public key's `y` are reduced rather than
/// rejected. The check is the cofactorless `R == S B - h A`, compared as
/// bytes. Returns `false` for a public key that is not a curve point.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::ed25519::{create_keypair, sign, verify};
/// use cloudllm_dht::types::Signature;
///
/// let (pk, sk) = create_keypair(&[1; 32]);
/// let sig = sign(b"m", &pk, &sk);
/// assert!(verify(&sig, b"m", &pk));
///
/// let mut bad = sig.0;
/// bad[63] |= 0x20; // S no longer fits in 253 bits
/// assert!(!verify(&Signature(bad), b"m", &pk));
/// ```
#[must_use]
pub fn verify(sig: &Signature, msg: &[u8], pk: &PublicKey) -> bool {
    if sig.0[63] & 224 != 0 {
        return false;
    }
    let Some(a) = CompressedEdwardsY(pk.0).decompress() else {
        return false;
    };
    let (r_bytes, s_bytes) = halves(&sig.0);
    let h = Scalar::from_bytes_mod_order_wide(&sha512([&r_bytes[..], &pk.0[..], msg]));
    // `S` may be >= l (but < 2^253); only B has S as its multiplier and B has
    // order l, so reducing S mod l computes the same point as the C code.
    let s = Scalar::from_bytes_mod_order(*s_bytes);
    let checker = EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &-a, &s).compress();
    // Not constant time: nothing here is secret, and libtorrent's
    // `consttime_equal` guards no secret either.
    checker.as_bytes() == r_bytes
}

/// The scalar `n` of [`add_scalar_public`] / [`add_scalar_secret`]: the
/// caller's 32 bytes with the top bit cleared, read as a number mod `l`.
fn scalar_n(scalar: &Seed) -> Scalar {
    let mut n = *scalar;
    n[31] &= 127;
    Scalar::from_bytes_mod_order(n)
}

/// Adds `scalar` to a public key (libtorrent `ed25519_add_scalar(pk, ..)`):
/// `A' = n B + A`. Lets a third party that only knows the public key
/// enforce randomness on a key pair (see
/// <http://crypto.stackexchange.com/a/6215/4697>).
///
/// The top bit of `scalar` is ignored (`scalar[31] &= 127`). `None` when
/// `pk` is not a curve point.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::ed25519::{add_scalar_public, add_scalar_secret, create_keypair, sign, verify};
///
/// let (pk, sk) = create_keypair(&[3; 32]);
/// let n = [9u8; 32];
/// let pk2 = add_scalar_public(&pk, &n).unwrap();
/// let sk2 = add_scalar_secret(&sk, &n);
/// assert!(verify(&sign(b"x", &pk2, &sk2), b"x", &pk2));
/// ```
#[must_use]
pub fn add_scalar_public(pk: &PublicKey, scalar: &Seed) -> Option<PublicKey> {
    let t = CompressedEdwardsY(pk.0).decompress()?;
    let a = EdwardsPoint::mul_base(&scalar_n(scalar)) + t;
    Some(PublicKey(a.compress().to_bytes()))
}

/// Adds `scalar` to a secret key (libtorrent `ed25519_add_scalar(sk, ..)`):
/// the scalar half becomes `a + n mod l` and the nonce prefix becomes
/// `SHA-512(old prefix || scalar)[..32]`.
///
/// The prefix re-derivation is the fix for orlp/ed25519 issue 3 (without
/// it, a signature under the old and new key with the same nonce prefix
/// leaks the secret). The scalar half is left reduced, *not* clamped, which
/// is why [`sign`] must not clamp.
///
/// Infallible: unlike the public-key variant it never decodes a point.
#[must_use]
pub fn add_scalar_secret(sk: &SecretKey, scalar: &Seed) -> SecretKey {
    let (a_bytes, prefix) = halves(&sk.0);
    let a = Scalar::from_bytes_mod_order(*a_bytes);
    let new_a = scalar_n(scalar) + a;
    // Note: the hash covers `scalar` as given, with its top bit intact.
    let hash = sha512([prefix.as_slice(), scalar.as_slice()]);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&new_a.to_bytes());
    out[32..].copy_from_slice(&hash[..32]);
    SecretKey(out)
}

/// Performs a key exchange (libtorrent `ed25519_key_exchange`, an X25519
/// ladder over the Montgomery form of an Ed25519 key): both sides compute
/// the same 32 bytes from their own secret key and the other's public key.
/// Hash the result before using it as a key.
///
/// `None` when `pk` is not a curve point (the C code accepts any `y` and
/// returns an unspecified value).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::ed25519::{create_keypair, key_exchange};
///
/// let (pk_a, sk_a) = create_keypair(&[1; 32]);
/// let (pk_b, sk_b) = create_keypair(&[2; 32]);
/// assert_eq!(key_exchange(&pk_b, &sk_a), key_exchange(&pk_a, &sk_b));
/// ```
#[must_use]
pub fn key_exchange(pk: &PublicKey, sk: &SecretKey) -> Option<SharedSecret> {
    let point = CompressedEdwardsY(pk.0).decompress()?;
    let (scalar, _) = halves(&sk.0);
    // `mul_clamped` clamps like libtorrent (`&= 248`, `[31] &= 127`,
    // `[31] |= 64`; libtorrent's `&= 63` then `|= 64` is the same mask).
    Some(point.to_montgomery().mul_clamped(*scalar).to_bytes())
}
