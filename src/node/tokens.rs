//! Write tokens: the proof that a requester owns the address it queries from.
//!
//! Provenance: `node::generate_token`, `node::verify_token`,
//! `node::new_write_key` and the `m_secret` member of
//! `src/kademlia/node.cpp` / `include/libtorrent/kademlia/node.hpp`
//! (libtorrent RC_2_1, commit `86d573f2631b0162d3cca5e257217eaf530fdcba`),
//! BSD-3-Clause, Copyright Arvid Norberg and contributors.
//!
//! # Why tokens exist
//!
//! `announce_peer` and BEP 44 `put` change state on the receiving node. A UDP
//! source address is trivially spoofed, so the node hands a token out in
//! every `get_peers` and `get` reply and only honours a write that presents
//! it back. A requester that never saw the reply (a spoofer) cannot know the
//! token. The token is the first four bytes of
//! `SHA-1(ip-as-text || secret || target)`, so the node stores nothing per
//! requester.
//!
//! # Rotation
//!
//! The tracker calls [`WriteTokens::rotate`] every five minutes. The new
//! secret goes in slot 0 and the previous one moves to slot 1; a token is
//! valid against either, so a token is accepted for between five and ten
//! minutes after it was handed out.

use std::net::IpAddr;

use sha1::{Digest, Sha1};

use crate::rng::Rng;
use crate::sha1_hash::Sha1Hash;

/// The length of a write token in bytes (libtorrent `write_token_size`).
pub const WRITE_TOKEN_SIZE: usize = 4;

/// The two rotating secrets a node derives its write tokens from
/// (libtorrent `node::m_secret[2]`).
///
/// `WriteTokens` is deliberately not `Clone` or `Debug`: the secrets must
/// not end up in logs or be duplicated by accident.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::node::tokens::WriteTokens;
/// use cloudllm_dht::rng::TestRng;
/// use cloudllm_dht::Sha1Hash;
///
/// let mut rng = TestRng::new(1);
/// let mut tokens = WriteTokens::new(&mut rng);
/// let ip = "10.1.2.3".parse().unwrap();
/// let target = Sha1Hash([7; 20]);
///
/// let token = tokens.generate(ip, &target);
/// assert!(tokens.verify(&token, ip, &target));
///
/// // One rotation keeps the token valid, a second one expires it.
/// tokens.rotate(&mut rng);
/// assert!(tokens.verify(&token, ip, &target));
/// tokens.rotate(&mut rng);
/// assert!(!tokens.verify(&token, ip, &target));
/// ```
pub struct WriteTokens {
    /// `secret[0]` is current, `secret[1]` the previous one.
    secret: [[u8; WRITE_TOKEN_SIZE]; 2],
}

impl WriteTokens {
    /// Draws both secrets from `rng` (the constructor of `node` calls
    /// `crypto_random_bytes` twice).
    #[must_use]
    pub fn new(rng: &mut dyn Rng) -> Self {
        let mut secret = [[0u8; WRITE_TOKEN_SIZE]; 2];
        secret.iter_mut().for_each(|s| rng.fill_bytes(s));
        Self { secret }
    }

    /// Builds the tokens from fixed secrets: for tests that need to forge
    /// or predict a token.
    #[must_use]
    pub fn from_secrets(current: [u8; WRITE_TOKEN_SIZE], previous: [u8; WRITE_TOKEN_SIZE]) -> Self {
        Self {
            secret: [current, previous],
        }
    }

    /// Generates a fresh current secret and demotes the old one
    /// (libtorrent `node::new_write_key`).
    pub fn rotate(&mut self, rng: &mut dyn Rng) {
        self.secret[1] = self.secret[0];
        rng.fill_bytes(&mut self.secret[0]);
    }

    /// The token for `addr` and `target` under the current secret
    /// (libtorrent `node::generate_token`). Only the IP participates, not
    /// the port, because a NATed peer's source port changes between the
    /// `get_peers` and the `announce_peer`.
    #[must_use]
    pub fn generate(&self, addr: IpAddr, target: &Sha1Hash) -> [u8; WRITE_TOKEN_SIZE] {
        derive(addr, &self.secret[0], target)
    }

    /// `true` when `token` was generated for `addr` and `target` under the
    /// current or the previous secret (libtorrent `node::verify_token`).
    ///
    /// A token of the wrong length is rejected without hashing. The
    /// comparison is constant-time over the four bytes (libtorrent uses
    /// `std::equal`, which short-circuits; the difference cannot matter for
    /// a 32-bit token but costs nothing).
    #[must_use]
    pub fn verify(&self, token: &[u8], addr: IpAddr, target: &Sha1Hash) -> bool {
        if token.len() != WRITE_TOKEN_SIZE {
            return false;
        }
        self.secret
            .iter()
            .any(|s| ct_eq(token, &derive(addr, s, target)))
    }
}

/// `SHA-1(ip text || secret || target)[..4]`.
fn derive(
    addr: IpAddr,
    secret: &[u8; WRITE_TOKEN_SIZE],
    target: &Sha1Hash,
) -> [u8; WRITE_TOKEN_SIZE] {
    let digest = Sha1::new()
        .chain_update(addr.to_string().as_bytes())
        .chain_update(secret)
        .chain_update(target.0)
        .finalize();
    let mut out = [0u8; WRITE_TOKEN_SIZE];
    out.copy_from_slice(&digest[..WRITE_TOKEN_SIZE]);
    out
}

/// Equality without an early exit on the first differing byte.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
