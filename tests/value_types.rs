//! The small value types of the public surface: BEP 44 keys, signatures and
//! secret keys, bencode [`Entry`] construction and rendering, and [`Sha1Hash`]
//! accessors. Callers build and print these constantly, so what they show in
//! logs (and what they never show) is part of the contract.

use cloudllm_dht::bencode::Entry;
use cloudllm_dht::types::{PublicKey, SecretKey, Signature};
use cloudllm_dht::Sha1Hash;

/// Keys and signatures print their bytes in lowercase hex; the secret key
/// prints nothing of itself, so it cannot leak into a log.
#[test]
fn test_key_types_debug_output_and_secret_redaction() {
    let pk = PublicKey([0xab; 32]);
    assert_eq!(format!("{pk:?}"), format!("PublicKey({})", "ab".repeat(32)));
    let sig = Signature([0x0f; 64]);
    assert_eq!(
        format!("{sig:?}"),
        format!("Signature({})", "0f".repeat(64))
    );
    let secret = SecretKey([0x42; 64]);
    assert_eq!(format!("{secret:?}"), "SecretKey(<redacted>)");
    assert!(!format!("{secret:?}").contains("42"));
}

/// The byte newtypes convert only from exactly their length, default to zeros
/// and expose their bytes by reference.
#[test]
fn test_key_types_slice_conversion_default_and_views() {
    assert_eq!(PublicKey::LEN, 32);
    assert_eq!(Signature::LEN, 64);
    assert_eq!(SecretKey::LEN, 64);
    assert!(PublicKey::from_slice(&[1; 31]).is_none());
    assert!(PublicKey::from_slice(&[1; 33]).is_none());
    let pk = PublicKey::from_slice(&[7; 32]).expect("32 bytes");
    assert_eq!(pk.as_bytes(), &[7; 32]);
    assert_eq!(pk.as_ref(), &[7u8; 32][..]);
    assert_eq!(PublicKey::default().0, [0; 32]);
    assert_eq!(Signature::default().0, [0; 64]);
    assert_eq!(SecretKey::default().0, [0; 64]);
    assert!(Signature::from_slice(&[0; 64]).is_some());
    assert!(SecretKey::from_slice(&[0; 63]).is_none());
}

/// `Entry::set` and `push` build dictionaries and lists out of an undefined
/// entry; getters answer only for the matching kind.
#[test]
fn test_entry_builders_and_accessors() {
    let mut dict = Entry::Undefined;
    dict.set("a", 1i64).set("b", "text").set(b"c", vec![1u8, 2]);
    assert_eq!(dict.get("a").and_then(Entry::as_int), Some(1));
    assert_eq!(dict.get("b").and_then(Entry::as_bytes), Some(&b"text"[..]));
    assert_eq!(dict.get("c").and_then(Entry::as_bytes), Some(&[1u8, 2][..]));
    assert!(dict.get("missing").is_none());
    assert_eq!(dict.as_dict().map(|d| d.len()), Some(3));
    assert!(dict.as_list().is_none());
    assert!(dict.as_int().is_none());

    let mut list = Entry::Undefined;
    list.push(1i64).push("two").push(Entry::from(true));
    assert_eq!(list.as_list().map(<[Entry]>::len), Some(3));
    assert_eq!(list.as_list().and_then(|l| l[2].as_int()), Some(1));
    assert!(list.as_dict().is_none());
    assert!(list.get("a").is_none());
    assert_eq!(Entry::dict().as_dict().map(|d| d.len()), Some(0));
    assert_eq!(Entry::list().as_list().map(<[Entry]>::len), Some(0));
}

/// Misusing a builder on a value of another kind is a programming error and
/// panics with the entry in the message, as libtorrent's assert does.
#[test]
#[should_panic(expected = "Entry::set on a non-dictionary")]
fn test_entry_set_on_a_list_panics() {
    Entry::list().set("k", 1i64);
}

/// See [`test_entry_set_on_a_list_panics`], for `push` on a dictionary.
#[test]
#[should_panic(expected = "Entry::push on a non-list")]
fn test_entry_push_on_a_dict_panics() {
    Entry::dict().push(1i64);
}

/// Every `From` conversion produces the matching variant, and the compact
/// `Display` form renders all of them, nested.
#[test]
fn test_entry_conversions_and_display() {
    assert_eq!(Entry::from(5i64), Entry::Int(5));
    assert_eq!(Entry::from(false), Entry::Int(0));
    assert_eq!(Entry::from("s"), Entry::Str(b"s".to_vec()));
    assert_eq!(Entry::from(String::from("s")), Entry::Str(b"s".to_vec()));
    assert_eq!(Entry::from(&b"ab"[..]), Entry::Str(b"ab".to_vec()));
    assert_eq!(Entry::from(vec![9u8]), Entry::Str(vec![9]));
    assert_eq!(Entry::from([1u8, 2, 3]), Entry::Str(vec![1, 2, 3]));
    assert_eq!(Entry::from(&[4u8, 5]), Entry::Str(vec![4, 5]));
    assert_eq!(
        Entry::from(vec![Entry::Int(1)]),
        Entry::List(vec![Entry::Int(1)])
    );

    let mut inner = Entry::dict();
    inner.set("k", "v");
    let mut outer = Entry::list();
    outer.push(1i64).push(inner).push(Entry::Undefined);
    assert_eq!(outer.to_string(), "[1, {'k': 'v'}, undefined]");
    assert_eq!(Entry::list().to_string(), "[]");
    assert_eq!(Entry::dict().to_string(), "{}");
}

/// A hash exposes its bytes, prints as 40 lowercase hex digits in `Display`,
/// `Debug` and `to_hex`, indexes by byte and parses back from hex.
#[test]
fn test_sha1_hash_views_and_hex_roundtrip() {
    let h = Sha1Hash::of(b"abc");
    assert_eq!(h.to_hex(), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(h.to_string(), h.to_hex());
    assert_eq!(format!("{h:?}"), format!("Sha1Hash({})", h.to_hex()));
    assert_eq!(h.as_bytes()[0], 0xa9);
    assert_eq!(h[0], 0xa9);
    assert_eq!(h.as_ref().len(), 20);
    assert_eq!(
        Sha1Hash::from_hex(&h.to_hex().to_uppercase()).expect("hex"),
        h
    );
    assert_eq!(Sha1Hash::from_slice(h.as_bytes()), Some(h));
    assert!(Sha1Hash::from_slice(&[0; 19]).is_none());
    assert!(Sha1Hash::from_hex("zz").is_err());
}
