//! Fuzzes BEP 44 item authentication, the gate every remote `put` passes.
//!
//! Part one throws arbitrary (value, salt, seq, key, signature) tuples at
//! `verify_mutable_item` and `Item::from_signed_node`: no panics, and
//! acceptance implies the documented bounds (salt <= 64, payload <= 1200).
//! Part two signs with a key derived from the input and checks that the
//! signature verifies, and that flipping any one byte of the value, salt or
//! signature, or changing the sequence number, makes it fail.
#![no_main]

use arbitrary::Arbitrary;
use cloudllm_dht::bencode::decode;
use cloudllm_dht::ed25519::create_keypair;
use cloudllm_dht::item::{
    sign_mutable_item, signing_payload, verify_mutable_item, Item, MAX_PAYLOAD_SIZE, MAX_SALT_SIZE,
};
use cloudllm_dht::types::{PublicKey, SequenceNumber, Signature};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    v: Vec<u8>,
    salt: Vec<u8>,
    seq: i64,
    pk: [u8; 32],
    sig: Vec<u8>,
    seed: [u8; 32],
    flip: u16,
}

fuzz_target!(|i: Input| {
    let seq = SequenceNumber(i.seq);

    // Part one: an unauthenticated tuple.
    let mut sig = [0u8; 64];
    let n = i.sig.len().min(64);
    sig[..n].copy_from_slice(&i.sig[..n]);
    let (pk, sig) = (PublicKey(i.pk), Signature(sig));
    if verify_mutable_item(&i.v, &i.salt, seq, &pk, &sig) {
        assert!(i.salt.len() <= MAX_SALT_SIZE);
        assert!(signing_payload(&i.v, &i.salt, seq).len() <= MAX_PAYLOAD_SIZE);
    }
    if let Ok(node) = decode(&i.v) {
        let _ = Item::from_signed_node(&node, &i.salt, seq, &pk, &sig);
    }

    // Part two: a genuine signature must verify, and only that one.
    let (pk, sk) = create_keypair(&i.seed);
    let sig = sign_mutable_item(&i.v, &i.salt, seq, &pk, &sk);
    let acceptable = i.salt.len() <= MAX_SALT_SIZE
        && signing_payload(&i.v, &i.salt, seq).len() <= MAX_PAYLOAD_SIZE;
    assert_eq!(verify_mutable_item(&i.v, &i.salt, seq, &pk, &sig), acceptable);
    if !acceptable {
        return;
    }
    assert!(!verify_mutable_item(&i.v, &i.salt, seq.next(), &pk, &sig) || seq.next() == seq);

    let at = usize::from(i.flip);
    let mut bad = sig.0;
    bad[at % 64] ^= 1 << (at / 64 % 8);
    assert!(!verify_mutable_item(&i.v, &i.salt, seq, &pk, &Signature(bad)));
    if !i.v.is_empty() {
        let mut v = i.v.clone();
        let k = at % v.len();
        v[k] ^= 1 << (at / 64 % 8);
        assert!(!verify_mutable_item(&v, &i.salt, seq, &pk, &sig));
    }
    if !i.salt.is_empty() {
        let mut salt = i.salt.clone();
        let k = at % salt.len();
        salt[k] ^= 1 << (at / 64 % 8);
        assert!(!verify_mutable_item(&i.v, &salt, seq, &pk, &sig));
    }
});
