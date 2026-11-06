//! Tests for `msg`: the verifier ported from `TEST_CASE(verify_message)` of
//! libtorrent `test/test_dht.cpp` (RC_2_1,
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), and the typed wire tokens.

use cloudllm_dht::bencode::{decode, NodeKind};
use cloudllm_dht::msg::{
    error_entry, verify_message, ErrorCode, KeyDesc, KeyFlags, MessageType, Query, VerifyError,
    Want,
};

const OPT_CHILDREN: KeyFlags = KeyFlags::OPTIONAL.or(KeyFlags::PARSE_CHILDREN);

fn table() -> [KeyDesc; 7] {
    use NodeKind::{Dict, Str};
    [
        KeyDesc::new("A", Some(Str), 4, KeyFlags::NONE),
        KeyDesc::new("B", Some(Dict), 0, OPT_CHILDREN),
        KeyDesc::new("B1", Some(Str), 0, KeyFlags::NONE),
        KeyDesc::new("B2", Some(Str), 0, KeyFlags::LAST_CHILD),
        KeyDesc::new("C", Some(Dict), 0, OPT_CHILDREN),
        KeyDesc::new("C1", Some(Str), 0, KeyFlags::NONE),
        KeyDesc::new("C2", Some(Str), 0, KeyFlags::LAST_CHILD),
    ]
}

/// TEST_CASE `verify_message`, first message: `A` and the `B` subtree.
#[test]
fn test_verify_message_b_subtree() {
    let m = decode(b"d1:A4:test1:Bd2:B15:test22:B25:test3ee").unwrap();
    let r = verify_message(&m, &table()).unwrap();
    assert_eq!(r[0].unwrap().string_value(), b"test");
    assert!(r[1].is_some());
    assert_eq!(r[2].unwrap().string_value(), b"test2");
    assert_eq!(r[3].unwrap().string_value(), b"test3");
    assert!(r[4..].iter().all(Option::is_none));
}

/// TEST_CASE `verify_message`, second message: the `C` subtree only.
#[test]
fn test_verify_message_c_subtree() {
    let m = decode(b"d1:A4:test1:Cd2:C15:test22:C25:test3ee").unwrap();
    let r = verify_message(&m, &table()).unwrap();
    assert_eq!(r[0].unwrap().string_value(), b"test");
    assert!(r[1..4].iter().all(Option::is_none));
    assert!(r[4].is_some());
    assert_eq!(r[5].unwrap().string_value(), b"test2");
    assert_eq!(r[6].unwrap().string_value(), b"test3");
}

/// TEST_CASE `verify_message`, third message: required `A` missing.
#[test]
fn test_verify_message_missing_key() {
    let m = decode(b"d1:Cd2:C15:test22:C25:test3ee").unwrap();
    let e = verify_message(&m, &table()).unwrap_err();
    assert_eq!(e, VerifyError::MissingKey("A"));
    assert_eq!(e.to_string(), "missing 'A' key");
}

/// TEST_CASE `verify_message`, fourth message: `A` has the wrong size.
#[test]
fn test_verify_message_invalid_size() {
    let m = decode(b"d1:A6:foobare").unwrap();
    let e = verify_message(&m, &table()).unwrap_err();
    assert_eq!(e.to_string(), "invalid value for 'A'");
}

/// TEST_CASE `verify_message`, fifth message: `C` present but `C2` missing.
#[test]
fn test_verify_message_missing_child() {
    let m = decode(b"d1:A4:test1:Cd2:C15:test2ee").unwrap();
    let e = verify_message(&m, &table()).unwrap_err();
    assert_eq!(e.to_string(), "missing 'C2' key");
}

/// TEST_CASE `verify_message`, sixth message: empty strings and keys
/// survive decoding (`[ { "": 1 }, "" ]`).
#[test]
fn test_verify_message_empty_strings() {
    let e = decode(b"ld0:i1ee0:e").unwrap();
    assert_eq!(e.kind(), NodeKind::List);
    assert_eq!(e.list_len(), 2);
    assert_eq!(e.list_at(0).unwrap().dict_find_int_value(b"", 0), 1);
    assert_eq!(e.list_at(1).unwrap().string_value(), b"");
}

/// A non-dictionary message fails first (`not a dictionary`).
#[test]
fn test_verify_message_not_a_dictionary() {
    let m = decode(b"le").unwrap();
    assert_eq!(
        verify_message(&m, &table()).unwrap_err().to_string(),
        "not a dictionary"
    );
}

/// A key of the wrong type is treated as absent.
#[test]
fn test_verify_message_wrong_type_is_missing() {
    let m = decode(b"d1:Ai4ee").unwrap();
    assert_eq!(
        verify_message(&m, &table()).unwrap_err(),
        VerifyError::MissingKey("A")
    );
}

/// `SIZE_DIVISIBLE` accepts multiples (the `nodes` string is a multiple of
/// 26) and rejects the rest; an optional invalid key reads as absent.
#[test]
fn test_verify_message_size_divisible() {
    let desc = [KeyDesc::new(
        "n",
        Some(NodeKind::Str),
        4,
        KeyFlags::OPTIONAL.or(KeyFlags::SIZE_DIVISIBLE),
    )];
    let ok = decode(b"d1:n8:aaaabbbbe").unwrap();
    assert!(verify_message(&ok, &desc).unwrap()[0].is_some());
    let bad = decode(b"d1:n6:aaaabbe").unwrap();
    assert!(verify_message(&bad, &desc).unwrap()[0].is_none());
}

/// An unbalanced table (a `LAST_CHILD` without a parent) is reported, not
/// a panic.
#[test]
fn test_verify_message_unbalanced_table() {
    let desc = [KeyDesc::new("a", None, 0, KeyFlags::LAST_CHILD)];
    let m = decode(b"d1:ai1ee").unwrap();
    assert_eq!(
        verify_message(&m, &desc).unwrap_err(),
        VerifyError::UnbalancedTable
    );
}

/// Every wire token survives `Display` then `FromStr`, and unknown tokens
/// are rejected with a typed error.
#[test]
fn test_wire_enums_roundtrip_and_reject() {
    for q in Query::ALL {
        assert_eq!(q.to_string().parse::<Query>().unwrap(), *q);
    }
    for t in MessageType::ALL {
        assert_eq!(t.to_string().parse::<MessageType>().unwrap(), *t);
    }
    for w in Want::ALL {
        assert_eq!(w.to_string().parse::<Want>().unwrap(), *w);
    }
    assert_eq!(Query::SampleInfohashes.as_str(), "sample_infohashes");
    let e = "frobnicate".parse::<Query>().unwrap_err();
    assert_eq!(e.what, "query");
    assert!("".parse::<MessageType>().is_err());
}

/// Error codes keep libtorrent's numbers and map back from the wire.
#[test]
fn test_error_codes() {
    assert_eq!(ErrorCode::Protocol.code(), 203);
    assert_eq!(ErrorCode::MessageTooBig.code(), 205);
    assert_eq!(ErrorCode::InvalidSignature.code(), 206);
    assert_eq!(ErrorCode::SaltTooBig.code(), 207);
    assert_eq!(ErrorCode::CasMismatch.code(), 301);
    assert_eq!(ErrorCode::SequenceNumberTooLow.code(), 302);
    assert_eq!(ErrorCode::from_code(204), Some(ErrorCode::MethodUnknown));
    assert_eq!(ErrorCode::from_code(999), None);
}

/// `error_entry` builds libtorrent's `incoming_error` reply.
#[test]
fn test_error_entry_wire_form() {
    let e = error_entry(ErrorCode::CasMismatch, "CAS mismatch");
    assert_eq!(e.encode(), b"d1:eli301e12:CAS mismatche1:y1:ee".to_vec());
}
