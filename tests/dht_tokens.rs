//! Tests for the write-token scheme of `node::generate_token`,
//! `node::verify_token` and `node::new_write_key` (libtorrent RC_2_1
//! `src/kademlia/node.cpp`). The reference has no dedicated TEST_CASE for
//! the token primitive; `get_peers_announce` in `test_dht.cpp` exercises it
//! end to end (see `tests/dht_node.rs`).

use cloudllm_dht::node::tokens::{WriteTokens, WRITE_TOKEN_SIZE};
use cloudllm_dht::rng::TestRng;
use cloudllm_dht::testing::{addr4, addr6, to_hash};

/// A generated token verifies for the same address and target.
#[test]
fn test_token_roundtrip() {
    let mut rng = TestRng::new(1);
    let t = WriteTokens::new(&mut rng);
    let ih = to_hash("0123456789012345678901234567890123456789");
    let tok = t.generate(addr4("4.3.2.1"), &ih);
    assert_eq!(tok.len(), WRITE_TOKEN_SIZE);
    assert!(t.verify(&tok, addr4("4.3.2.1"), &ih));
}

/// A token is bound to the requester IP and to the target.
#[test]
fn test_token_bound_to_address_and_target() {
    let mut rng = TestRng::new(2);
    let t = WriteTokens::new(&mut rng);
    let ih = to_hash("0123456789012345678901234567890123456789");
    let other = to_hash("0123456789012345678901234567890123456780");
    let tok = t.generate(addr4("4.3.2.1"), &ih);
    assert!(!t.verify(&tok, addr4("4.3.2.2"), &ih));
    assert!(!t.verify(&tok, addr6("2001:db8::1"), &ih));
    assert!(!t.verify(&tok, addr4("4.3.2.1"), &other));
}

/// Tokens of the wrong length never verify, including empty ones and ones
/// that extend a valid token.
#[test]
fn test_token_wrong_length_rejected() {
    let mut rng = TestRng::new(3);
    let t = WriteTokens::new(&mut rng);
    let ih = to_hash("0123456789012345678901234567890123456789");
    let ip = addr4("1.1.1.1");
    let tok = t.generate(ip, &ih);
    assert!(!t.verify(&[], ip, &ih));
    assert!(!t.verify(&tok[..3], ip, &ih));
    let mut long = tok.to_vec();
    long.push(0);
    assert!(!t.verify(&long, ip, &ih));
}

/// One rotation keeps outstanding tokens valid, two expire them
/// (`new_write_key` demotes `m_secret[0]` to `m_secret[1]`).
#[test]
fn test_token_survives_one_rotation_not_two() {
    let mut rng = TestRng::new(4);
    let mut t = WriteTokens::new(&mut rng);
    let ih = to_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let ip = addr4("9.9.9.9");
    let tok = t.generate(ip, &ih);
    t.rotate(&mut rng);
    assert!(t.verify(&tok, ip, &ih));
    t.rotate(&mut rng);
    assert!(!t.verify(&tok, ip, &ih));
}

/// Tokens derived from the previous secret are accepted, and fixed secrets
/// give the documented construction `SHA-1(ip || secret || target)[..4]`.
#[test]
fn test_token_matches_documented_construction() {
    use sha1::{Digest, Sha1};
    let t = WriteTokens::from_secrets(*b"cur!", *b"prev");
    let ih = to_hash("0123456789012345678901234567890123456789");
    let ip = addr4("4.3.2.1");
    let mut h = Sha1::new();
    h.update(b"4.3.2.1");
    h.update(b"cur!");
    h.update(ih.0);
    let expect = h.finalize();
    assert_eq!(&t.generate(ip, &ih)[..], &expect[..4]);

    let mut h = Sha1::new();
    h.update(b"4.3.2.1");
    h.update(b"prev");
    h.update(ih.0);
    let old = h.finalize();
    assert!(t.verify(&old[..4], ip, &ih));
}
