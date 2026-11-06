//! Tests for `item`: the `signing_test1`, `signing_test2`, `signing_test3`
//! and `signing_oversized_salt` cases of libtorrent `test/test_dht.cpp`
//! (RC_2_1, `86d573f2631b0162d3cca5e257217eaf530fdcba`), plus coverage of
//! the signing payload, `Item` and the bounds this port tightens.

use cloudllm_dht::bencode::{decode, Entry};
use cloudllm_dht::item::{
    immutable_item_target_id, item_target_id, sign_mutable_item, signing_payload,
    verify_mutable_item, Item, ItemError, MAX_PAYLOAD_SIZE, MAX_SALT_SIZE, MAX_VALUE_SIZE,
};
use cloudllm_dht::testing::test_keypair;
use cloudllm_dht::types::{SequenceNumber, Signature};

const CONTENT: &[u8] = b"12:Hello World!";

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Port of `TEST_CASE(signing_test1)`: test vector 1, no salt.
#[test]
fn test_signing_test1() {
    let (pk, sk) = test_keypair();
    let sig = sign_mutable_item(CONTENT, b"", SequenceNumber(1), &pk, &sk);
    assert_eq!(
        to_hex(&sig.0),
        concat!(
            "305ac8aeb6c9c151fa120f120ea2cfb923564e11552d06a5d856091e5e853cff",
            "1260d3f39e4999684aa92eb73ffd136e6f4f3ecbfda0ce53a1608ecd7ae21f01"
        )
    );
    assert_eq!(
        item_target_id(b"", &pk).to_string(),
        "4a533d47ec9c7d95b1ad75f576cffc641853b750"
    );
}

/// Port of `TEST_CASE(signing_test2)`: test vector 2, salt `foobar`.
#[test]
fn test_signing_test2() {
    let (pk, sk) = test_keypair();
    let sig = sign_mutable_item(CONTENT, b"foobar", SequenceNumber(1), &pk, &sk);
    assert_eq!(
        to_hex(&sig.0),
        concat!(
            "6834284b6b24c3204eb2fea824d82f88883a3d95e8b4a21b8c0ded553d17d17d",
            "df9a8a7104b1258f30bed3787e6cb896fca78c58f8e03b5f18f14951a87d9a08"
        )
    );
    assert_eq!(
        item_target_id(b"foobar", &pk).to_string(),
        "411eba73b6f087ca51a3795d9c8c938d365e32c1"
    );
}

/// Port of `TEST_CASE(signing_test3)`: test vector 3, the target of an
/// immutable item.
#[test]
fn test_signing_test3() {
    assert_eq!(
        immutable_item_target_id(CONTENT).to_string(),
        "e5f96f6f38320f0f33959cb4d3d656452117aadb"
    );
}

/// Port of `TEST_CASE(signing_oversized_salt)`: an oversized salt is
/// rejected on verification (not truncated, and signing stays in bounds); a
/// maximum-size salt still round-trips.
#[test]
fn test_signing_oversized_salt() {
    let (pk, sk) = test_keypair();
    let big = vec![b'x'; 1200];
    let sig = sign_mutable_item(CONTENT, &big, SequenceNumber(1), &pk, &sk);
    assert!(!verify_mutable_item(
        CONTENT,
        &big,
        SequenceNumber(1),
        &pk,
        &sig
    ));

    let max = vec![b'x'; MAX_SALT_SIZE];
    let sig2 = sign_mutable_item(CONTENT, &max, SequenceNumber(1), &pk, &sk);
    assert!(verify_mutable_item(
        CONTENT,
        &max,
        SequenceNumber(1),
        &pk,
        &sig2
    ));

    // 65 bytes is already over the limit
    let over = vec![b'x'; MAX_SALT_SIZE + 1];
    let sig3 = sign_mutable_item(CONTENT, &over, SequenceNumber(1), &pk, &sk);
    assert!(!verify_mutable_item(
        CONTENT,
        &over,
        SequenceNumber(1),
        &pk,
        &sig3
    ));
}

/// libtorrent signs and verifies a payload truncated to its 1200-byte
/// buffer, so a signature over a 1200-byte prefix would verify for any
/// longer `v` with the same prefix. This port rejects such payloads
/// outright; regression test for that hardening.
#[test]
fn test_verify_rejects_payload_longer_than_buffer() {
    let (pk, sk) = test_keypair();
    let mut v = vec![b'a'; 1300];
    v[0] = b'0'; // content is irrelevant, verification must not look at it
    let seq = SequenceNumber(1);
    let sig = sign_mutable_item(&v, b"", seq, &pk, &sk);
    assert!(!verify_mutable_item(&v, b"", seq, &pk, &sig));
    // a signature over exactly the truncated prefix does not rescue a longer v
    let prefix = signing_payload(&v, b"", seq)[..MAX_PAYLOAD_SIZE].to_vec();
    let sig_prefix = cloudllm_dht::ed25519::sign(&prefix, &pk, &sk);
    assert!(!verify_mutable_item(&v, b"", seq, &pk, &sig_prefix));
    // the largest BEP 44 item (1000-byte v, 64-byte salt) fits comfortably
    let v = vec![b'b'; MAX_VALUE_SIZE];
    let salt = vec![b's'; MAX_SALT_SIZE];
    let sig = sign_mutable_item(&v, &salt, SequenceNumber(i64::MIN), &pk, &sk);
    assert!(verify_mutable_item(
        &v,
        &salt,
        SequenceNumber(i64::MIN),
        &pk,
        &sig
    ));
}

/// The payload layout of BEP 44: optional `4:salt<n>:<salt>`, then
/// `3:seqi<seq>e1:v<v>`; negative and extreme sequence numbers print as
/// plain decimal.
#[test]
fn test_signing_payload_layout() {
    assert_eq!(
        signing_payload(b"i3e", b"", SequenceNumber(0)),
        b"3:seqi0e1:vi3e".to_vec()
    );
    assert_eq!(
        signing_payload(b"i3e", b"ab", SequenceNumber(-5)),
        b"4:salt2:ab3:seqi-5e1:vi3e".to_vec()
    );
    let big = signing_payload(b"", b"", SequenceNumber(i64::MAX));
    assert_eq!(big, b"3:seqi9223372036854775807e1:v".to_vec());
    let small = signing_payload(b"", b"", SequenceNumber(i64::MIN));
    assert_eq!(small, b"3:seqi-9223372036854775808e1:v".to_vec());
    // a 10-byte salt has a two-digit length prefix
    assert!(
        signing_payload(b"", &[b'z'; 10], SequenceNumber(1)).starts_with(b"4:salt10:zzzzzzzzzz")
    );
}

/// A signature binds value, salt, sequence number and key: changing any of
/// them, or any signature bit, fails verification.
#[test]
fn test_verify_binds_every_component() {
    let (pk, sk) = test_keypair();
    let seq = SequenceNumber(42);
    let sig = sign_mutable_item(CONTENT, b"s", seq, &pk, &sk);
    assert!(verify_mutable_item(CONTENT, b"s", seq, &pk, &sig));
    assert!(!verify_mutable_item(
        b"12:Hello World?",
        b"s",
        seq,
        &pk,
        &sig
    ));
    assert!(!verify_mutable_item(CONTENT, b"t", seq, &pk, &sig));
    assert!(!verify_mutable_item(CONTENT, b"", seq, &pk, &sig));
    assert!(!verify_mutable_item(CONTENT, b"s", seq.next(), &pk, &sig));
    let (other, _) = cloudllm_dht::ed25519::create_keypair(&[8; 32]);
    assert!(!verify_mutable_item(CONTENT, b"s", seq, &other, &sig));
    let mut bad = sig.0;
    bad[10] ^= 1;
    assert!(!verify_mutable_item(
        CONTENT,
        b"s",
        seq,
        &pk,
        &Signature(bad)
    ));
    assert!(!verify_mutable_item(
        CONTENT,
        b"s",
        seq,
        &pk,
        &Signature([0; 64])
    ));
}

/// `Item::signed` encodes, signs and keeps the parts; the result verifies
/// through `from_signed_node` on the wire bytes (the BEP 44 get/put path).
#[test]
fn test_item_signed_roundtrips_through_node() {
    let (pk, sk) = test_keypair();
    let v = Entry::from("Hello World!");
    let item = Item::signed(v.clone(), b"foobar", SequenceNumber(1), &pk, &sk).unwrap();
    assert!(item.is_mutable() && !item.is_empty());
    assert_eq!(item.pk(), &pk);
    assert_eq!(item.salt(), b"foobar");
    assert_eq!(item.seq(), SequenceNumber(1));
    assert_eq!(item.value(), &v);
    assert_eq!(
        item.target().to_string(),
        "411eba73b6f087ca51a3795d9c8c938d365e32c1"
    );

    let wire = v.encode();
    let node = decode(&wire).unwrap();
    let again =
        Item::from_signed_node(&node, b"foobar", SequenceNumber(1), &pk, item.sig()).unwrap();
    assert_eq!(again, item);

    let wrong_seq = Item::from_signed_node(&node, b"foobar", SequenceNumber(2), &pk, item.sig());
    assert_eq!(wrong_seq, Err(ItemError::BadSignature));
}

/// `Item::signed` rejects an over-long value and salt, where libtorrent
/// overruns a fixed 1000-byte buffer; `from_signed_node` rejects an
/// over-long `v` (libtorrent only asserts).
#[test]
fn test_item_size_limits() {
    let (pk, sk) = test_keypair();
    let big = Entry::Str(vec![b'x'; MAX_VALUE_SIZE]); // encodes to 1005 bytes
    assert_eq!(
        Item::signed(big.clone(), b"", SequenceNumber(1), &pk, &sk),
        Err(ItemError::ValueTooLarge { len: 1005 })
    );
    let fits = Entry::Str(vec![b'x'; MAX_VALUE_SIZE - 4]);
    assert!(Item::signed(fits, b"", SequenceNumber(1), &pk, &sk).is_ok());
    assert_eq!(
        Item::signed(Entry::Int(1), &[0; 65], SequenceNumber(1), &pk, &sk),
        Err(ItemError::SaltTooLarge { len: 65 })
    );
    let wire = big.encode();
    let node = decode(&wire).unwrap();
    let sig = sign_mutable_item(&wire, b"", SequenceNumber(1), &pk, &sk);
    assert_eq!(
        Item::from_signed_node(&node, b"", SequenceNumber(1), &pk, &sig),
        Err(ItemError::ValueTooLarge { len: 1005 })
    );
}

/// Constructors and accessors: default is empty and immutable; `for_key`
/// is an empty mutable item; `immutable` targets the hash of the encoding;
/// `clear` only drops the value.
#[test]
fn test_item_constructors_and_clear() {
    let blank = Item::new();
    assert!(blank.is_empty() && !blank.is_mutable());
    assert_eq!(blank.seq(), SequenceNumber(0));

    let (pk, sk) = test_keypair();
    let slot = Item::for_key(pk, b"salt");
    assert!(slot.is_empty() && slot.is_mutable());
    assert_eq!(slot.salt(), b"salt");
    assert_eq!(slot.pk(), &pk);

    let imm = Item::immutable(Entry::from("Hello World!"));
    assert!(!imm.is_empty() && !imm.is_mutable());
    assert_eq!(imm.target(), immutable_item_target_id(CONTENT));

    let node_wire = Entry::Int(5).encode();
    let from_node = Item::immutable_from_node(&decode(&node_wire).unwrap());
    assert_eq!(from_node.value(), &Entry::Int(5));

    let mut m = Item::signed(Entry::Int(1), b"", SequenceNumber(3), &pk, &sk).unwrap();
    m.clear();
    assert!(m.is_empty());
    assert!(m.is_mutable());
    assert_eq!(m.seq(), SequenceNumber(3));
}

/// `assign_immutable` and `assign_mutable` replace in place; a failed
/// verification leaves the item untouched.
#[test]
fn test_item_in_place_assign() {
    let (pk, sk) = test_keypair();
    let wire = Entry::from("Hello World!").encode();
    let node = decode(&wire).unwrap();
    let sig = sign_mutable_item(&wire, b"s", SequenceNumber(1), &pk, &sk);
    let mut item = Item::for_key(pk, b"s");
    assert!(!item.assign_mutable(&node, b"s", SequenceNumber(2), &pk, &sig));
    assert!(item.is_empty());
    assert!(item.assign_mutable(&node, b"s", SequenceNumber(1), &pk, &sig));
    assert_eq!(item.seq(), SequenceNumber(1));
    item.assign_immutable(&node);
    assert!(!item.is_mutable());
    assert_eq!(item.value(), &Entry::from("Hello World!"));
}
