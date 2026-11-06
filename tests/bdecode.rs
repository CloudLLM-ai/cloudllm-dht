//! Port of libtorrent `test/test_bdecode.cpp` (RC_2_1,
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause,
//! Copyright Arvid Norberg and Steven Siloti.
//!
//! Every `TORRENT_TEST` that exercises behaviour this crate has is ported
//! under its snake_case name. Cases about C++ memory management
//! (`swap*`, `clear`, `copy_root`, `non_owning_refs`, `switch_buffer`) have no
//! Rust counterpart: nodes borrow the input and the borrow checker owns that
//! contract.

use cloudllm_dht::bencode::bdecode::{decode_lenient, parse_int};
use cloudllm_dht::bencode::{
    decode, decode_with_limits, BdecodeError, DecodeError, Entry, Node, NodeKind, MAX_BUFFER_SIZE,
};

fn ok(b: &[u8]) -> Node<'_> {
    decode(b).expect("input should decode")
}

fn fail(b: &[u8]) -> DecodeError {
    decode(b).expect_err("input should fail to decode")
}

fn assert_fail(b: &[u8], code: BdecodeError, position: usize) {
    assert_eq!(fail(b), DecodeError { code, position }, "input {b:?}");
}

fn print(b: &[u8]) -> String {
    decode_lenient(b, 100, 2_000_000)
        .node
        .map(|n| n.print(false, 0))
        .unwrap_or_else(|| "none".into())
}

/// TEST_CASE `integer`
#[test]
fn test_integer() {
    let b = b"i12453e";
    let e = ok(b);
    assert_eq!(e.data_section(), b);
    assert_eq!(e.kind(), NodeKind::Int);
    assert_eq!(e.int_value(), 12453);
}

/// TEST_CASE `construct_string`, `construct_string_literal`,
/// `construct_string_view`: owned entries built from the common string types.
#[test]
fn test_construct_string() {
    assert_eq!(
        Entry::from(String::from("abc123")).as_bytes(),
        Some(&b"abc123"[..])
    );
    assert_eq!(Entry::from("abc123").as_bytes(), Some(&b"abc123"[..]));
}

/// TEST_CASE `construct_integer`
#[test]
fn test_construct_integer() {
    assert_eq!(Entry::from(4).as_int(), Some(4));
}

/// TEST_CASE `string`
#[test]
fn test_string() {
    let b = b"26:abcdefghijklmnopqrstuvwxyz";
    let e = ok(b);
    assert_eq!(e.data_section(), b);
    assert_eq!(e.kind(), NodeKind::Str);
    assert_eq!(e.string_value(), b"abcdefghijklmnopqrstuvwxyz");
    assert_eq!(e.string_length(), 26);
}

/// TEST_CASE `string_prefix1`: a string that is nearly too long.
#[test]
fn test_string_prefix1() {
    let mut test = vec![0u8; 1_000_000 + 8];
    test[..8].copy_from_slice(b"1000000:");
    let e = ok(&test);
    assert_eq!(e.data_section(), &test[..]);
    assert_eq!(e.kind(), NodeKind::Str);
    assert_eq!(e.string_length(), 1_000_000);
    assert_eq!(e.string_offset(), 8);
}

/// TEST_CASE `list`
#[test]
fn test_list() {
    let b = b"li12453e3:aaae";
    let e = ok(b);
    assert_eq!(e.data_section(), b);
    assert_eq!(e.kind(), NodeKind::List);
    assert_eq!(e.list_len(), 2);
    assert_eq!(e.list_at(0).unwrap().kind(), NodeKind::Int);
    assert_eq!(e.list_at(1).unwrap().kind(), NodeKind::Str);
    assert_eq!(e.list_at(0).unwrap().int_value(), 12453);
    assert_eq!(e.list_at(1).unwrap().string_value(), b"aaa");
    assert_eq!(e.list_at(1).unwrap().string_length(), 3);
    assert_eq!(e.list_at(1).unwrap().data_section(), b"3:aaa");
}

/// TEST_CASE `dict`
#[test]
fn test_dict() {
    let b = b"d1:ai12453e1:b3:aaa1:c3:bbb1:X10:0123456789e";
    let e = ok(b);
    assert_eq!(e.data_section(), b);
    assert_eq!(e.kind(), NodeKind::Dict);
    assert_eq!(e.dict_len(), 4);
    assert_eq!(e.dict_find(b"a").unwrap().kind(), NodeKind::Int);
    assert_eq!(e.dict_find(b"a").unwrap().int_value(), 12453);
    assert_eq!(e.dict_find(b"b").unwrap().string_value(), b"aaa");
    assert_eq!(e.dict_find(b"b").unwrap().string_length(), 3);
    assert_eq!(e.dict_find(b"c").unwrap().string_value(), b"bbb");
    assert_eq!(e.dict_find_string_value(b"X", b""), b"0123456789");
    assert_eq!(e.has_soft_error(), Some("unsorted dictionary key"));
}

/// TEST_CASE `dict_key_novalue`
#[test]
fn test_dict_key_novalue() {
    assert_fail(b"d1:ai1e1:be", BdecodeError::ExpectedValue, 10);
}

/// TEST_CASE `dict_nonstring_key`
#[test]
fn test_dict_nonstring_key() {
    assert_fail(b"di5e1:ae", BdecodeError::ExpectedDigit, 1);
}

/// TEST_CASE `dict_null_key`
#[test]
fn test_dict_null_key() {
    let e = ok(b"d3:a\0bi1ee");
    assert_eq!(e.dict_len(), 1);
    let d = e.dict_find(b"a\0b").unwrap();
    assert_eq!(d.kind(), NodeKind::Int);
    assert_eq!(d.int_value(), 1);
}

/// TEST_CASE `dict_unordered_keys`
#[test]
fn test_dict_unordered_keys() {
    for b in [
        &b"d2:abi1e2:aai2ee"[..],
        b"d2:bai1e2:aai2ee",
        b"d2:aai1e1:ai2ee",
    ] {
        assert_eq!(
            ok(b).has_soft_error(),
            Some("unsorted dictionary key"),
            "{b:?}"
        );
    }
    for b in [&b"d1:ai1e2:aai2ee"[..], b"d2:aai1e1:bi2ee"] {
        assert_eq!(ok(b).has_soft_error(), None, "{b:?}");
    }
}

/// TEST_CASE `dict_duplicate_key`
#[test]
fn test_dict_duplicate_key() {
    assert_eq!(
        ok(b"d2:aai1e2:aai2ee").has_soft_error(),
        Some("duplicate dictionary key")
    );
}

/// TEST_CASE `premature_e`
#[test]
fn test_premature_e() {
    assert_eq!(fail(b"e").code, BdecodeError::UnexpectedEof);
}

/// TEST_CASE `negative_length_prefix`
#[test]
fn test_negative_length_prefix() {
    assert_fail(b"-10:foobar", BdecodeError::ExpectedValue, 0);
}

/// TEST_CASE `overflow_length_prefix`
#[test]
fn test_overflow_length_prefix() {
    assert_fail(b"18446744073709551615:foobar", BdecodeError::Overflow, 19);
}

/// TEST_CASE `close_overflow_length_prefix`
#[test]
fn test_close_overflow_length_prefix() {
    assert_fail(b"99999999:foobar", BdecodeError::UnexpectedEof, 8);
}

/// TEST_CASE `overflow_length_prefix2`: the C++ test passes a fake 999999999
/// byte span; here a real (zero-page, lazily committed) buffer over the
/// limit stands in.
#[test]
fn test_overflow_length_prefix2() {
    let mut big = vec![0u8; MAX_BUFFER_SIZE + 1];
    big[..16].copy_from_slice(b"199999999:foobar");
    assert_fail(&big, BdecodeError::LimitExceeded, 0);
}

/// TEST_CASE `leading_zero_length_prefix`
#[test]
fn test_leading_zero_length_prefix() {
    assert_eq!(
        ok(b"06:foobar").has_soft_error(),
        Some("leading zero in string length")
    );
    assert_eq!(ok(b"0:").has_soft_error(), None);
}

/// TEST_CASE `nodigit_int`
#[test]
fn test_nodigit_int() {
    assert_fail(b"ie", BdecodeError::ExpectedDigit, 1);
}

/// TEST_CASE `minus_int`
#[test]
fn test_minus_int() {
    assert_fail(b"i-e", BdecodeError::ExpectedDigit, 2);
}

/// TEST_CASE `interior_minus_int`
#[test]
fn test_interior_minus_int() {
    assert_fail(b"i35412-5633e", BdecodeError::ExpectedDigit, 6);
}

/// TEST_CASE `int_overflow`: lazy overflow reads back as zero.
#[test]
fn test_int_overflow() {
    assert_eq!(ok(b"i18446744073709551615e").int_value(), 0);
}

/// TEST_CASE `int_overflow2`
#[test]
fn test_int_overflow2() {
    assert_fail(b"i184467440737095516154e", BdecodeError::Overflow, 22);
}

/// TEST_CASE `int_truncated`
#[test]
fn test_int_truncated() {
    assert_fail(b"i-", BdecodeError::UnexpectedEof, 2);
}

/// TEST_CASE `int_leading_zero`
#[test]
fn test_int_leading_zero() {
    assert_eq!(
        ok(b"i01e").has_soft_error(),
        Some("leading zero in integer")
    );
    assert_eq!(ok(b"i0e").has_soft_error(), None);
}

/// TEST_CASE `bdecode_error`: message text of the error category.
#[test]
fn test_bdecode_error() {
    assert_eq!(BdecodeError::Overflow.to_string(), "integer overflow");
    assert_eq!(
        BdecodeError::DepthExceeded.to_string(),
        "bencoded nesting depth exceeded"
    );
}

/// TEST_CASE `64bit_int`
#[test]
fn test_64bit_int() {
    assert_eq!(ok(b"i9223372036854775807e").int_value(), i64::MAX);
}

/// TEST_CASE `64bit_int_negative`
#[test]
fn test_64bit_int_negative() {
    assert_eq!(ok(b"i-9223372036854775807e").int_value(), -i64::MAX);
}

/// TEST_CASE `int_invalid_digit`
#[test]
fn test_int_invalid_digit() {
    assert_fail(b"i92337203t854775807e", BdecodeError::ExpectedDigit, 9);
}

/// TEST_CASE `invalid_encoding`
#[test]
fn test_invalid_encoding() {
    let buf: &[u8] = &[
        0x64, 0x31, 0x3a, 0x61, 0x64, 0x32, 0x3a, 0x69, 0x64, 0x32, 0x30, 0x3a, 0x2a, 0x21, 0x19,
        0x89, 0x9f, 0xcd, 0x5f, 0xc9, 0xbc, 0x80, 0xc1, 0x76, 0xfe, 0xe0, 0xc6, 0x84, 0x2d, 0xf6,
        0xfc, 0xb8, 0x39, 0x3a, 0x69, 0x6e, 0x66, 0x6f, 0x5f, 0x68, 0x61, 0xae, 0x68, 0x32, 0x30,
        0x3a, 0x14, 0x78, 0xd5, 0xb0, 0xdc, 0xf6, 0x82, 0x42, 0x32, 0xa0, 0xd6, 0x88, 0xeb, 0x48,
        0x57, 0x01, 0x89, 0x40, 0x4e, 0xbc, 0x65, 0x31, 0x3a, 0x71, 0x39, 0x3a, 0x67, 0x65, 0x74,
        0x5f, 0x70, 0x65, 0x65, 0x72, 0x78, 0xff, 0x3a, 0x74, 0x38, 0x3a, 0xaa, 0xd4, 0xa1, 0x88,
        0x7a, 0x8d, 0xc3, 0xd6, 0x31, 0x3a, 0x79, 0x31, 0xae, 0x71, 0x65, 0x00,
    ];
    // includes the trailing NUL the C++ array carries
    assert!(decode(buf).is_err());
}

/// TEST_CASE `depth_limit`: 1024 nested lists against a limit of 100.
#[test]
fn test_depth_limit() {
    let mut b = vec![b'l'; 1024];
    b.extend(std::iter::repeat_n(b'e', 1024));
    let e = decode_with_limits(&b, 100, 2_000_000).unwrap_err();
    assert_eq!(e.code, BdecodeError::DepthExceeded);
}

/// TEST_CASE `item_limit`
#[test]
fn test_item_limit() {
    let mut b = vec![b'l'];
    b.extend(b"0:".repeat(5119));
    b.push(b'e');
    let e = decode_with_limits(&b, 1000, 1000).unwrap_err();
    assert_eq!(e.code, BdecodeError::LimitExceeded);
}

/// TEST_CASE `unexpected_eof`
#[test]
fn test_unexpected_eof() {
    assert_fail(b"l2:..", BdecodeError::UnexpectedEof, 5);
}

/// TEST_CASE `unexpected_eof2`
#[test]
fn test_unexpected_eof2() {
    assert_fail(b"l2:..0", BdecodeError::UnexpectedEof, 6);
}

/// TEST_CASE `expected_string`
#[test]
fn test_expected_string() {
    assert_fail(b"di2ei0ee", BdecodeError::ExpectedDigit, 1);
}

/// TEST_CASE `unexpected_eof_dict_key`
#[test]
fn test_unexpected_eof_dict_key() {
    assert_fail(b"d1000:..e", BdecodeError::UnexpectedEof, 5);
}

/// TEST_CASE `unexpected_eof_dict_key2`
#[test]
fn test_unexpected_eof_dict_key2() {
    assert_fail(b"d1000:", BdecodeError::UnexpectedEof, 5);
}

/// TEST_CASE `expected_string_dict_key2`
#[test]
fn test_expected_string_dict_key2() {
    assert_fail(b"df00:", BdecodeError::ExpectedDigit, 1);
}

/// TEST_CASE `unexpected_eof_int`
#[test]
fn test_unexpected_eof_int() {
    assert_fail(b"i", BdecodeError::UnexpectedEof, 1);
}

/// TEST_CASE `unexpected_eof_int2`
#[test]
fn test_unexpected_eof_int2() {
    assert_fail(b"i10", BdecodeError::UnexpectedEof, 3);
}

/// TEST_CASE `expected_colon_dict`
#[test]
fn test_expected_colon_dict() {
    assert_fail(b"d1000", BdecodeError::ExpectedColon, 5);
}

/// TEST_CASE `empty_string`
#[test]
fn test_empty_string() {
    assert_eq!(fail(b"").code, BdecodeError::UnexpectedEof);
}

/// TEST_CASE `partial_string`
#[test]
fn test_partial_string() {
    assert_fail(b"100:..", BdecodeError::UnexpectedEof, 3);
}

/// TEST_CASE `list_ints`
#[test]
fn test_list_ints() {
    let mut buf = String::from("l");
    (0..1000).for_each(|i| buf.push_str(&format!("i{i}e")));
    buf.push('e');
    let e = ok(buf.as_bytes());
    assert_eq!(e.kind(), NodeKind::List);
    assert_eq!(e.list_len(), 1000);
    for i in 0..1000 {
        assert_eq!(e.list_int_value_at(i, -1), i as i64);
    }
}

/// TEST_CASE `dict_ints`
#[test]
fn test_dict_ints() {
    let mut buf = String::from("d");
    (0..1000).for_each(|i| buf.push_str(&format!("4:{i:04}i{i}e")));
    buf.push('e');
    let e = ok(buf.as_bytes());
    assert_eq!(e.dict_len(), 1000);
    for i in 0..1000 {
        assert_eq!(e.dict_find_int_value(format!("{i:04}").as_bytes(), -1), i);
    }
}

/// TEST_CASE `dict_at`
#[test]
fn test_dict_at() {
    let e = ok(b"d3:fooi1e3:bari2ee");
    assert_eq!(e.dict_len(), 2);
    let (k, v) = e.dict_at(0).unwrap();
    assert_eq!(
        (k, v.kind(), v.int_value()),
        (&b"foo"[..], NodeKind::Int, 1)
    );
    let (k, v) = e.dict_at(1).unwrap();
    assert_eq!(
        (k, v.kind(), v.int_value()),
        (&b"bar"[..], NodeKind::Int, 2)
    );
}

/// TEST_CASE `string_ptr`: the string borrows the input buffer, at offset 3.
#[test]
fn test_string_ptr() {
    let b = b"l3:fooe";
    let e = ok(b);
    let s = e.list_at(0).unwrap();
    assert_eq!(s.kind(), NodeKind::Str);
    assert_eq!(s.string_value().as_ptr(), b[3..].as_ptr());
    assert_eq!(s.string_length(), 3);
}

/// TEST_CASE `exceed_buf_limit`
#[test]
fn test_exceed_buf_limit() {
    let mut big = vec![0u8; MAX_BUFFER_SIZE + 1];
    big[..7].copy_from_slice(b"l3:fooe");
    assert_eq!(fail(&big).code, BdecodeError::LimitExceeded);
}

/// TEST_CASE `parse_int`
#[test]
fn test_parse_int() {
    let b = b"1234567890e";
    let mut val = 0;
    let (stop, err) = parse_int(b, 0, b.len(), b'e', &mut val);
    assert_eq!((err, val, stop), (None, 1_234_567_890, b.len() - 1));
}

/// TEST_CASE `invalid_digit`
#[test]
fn test_invalid_digit() {
    let b = b"0o";
    let mut val = 0;
    let (stop, err) = parse_int(b, 0, b.len(), b'e', &mut val);
    assert_eq!((err, stop), (Some(BdecodeError::ExpectedDigit), 1));
}

/// TEST_CASE `parse_int_overflow`
#[test]
fn test_parse_int_overflow() {
    let b = b"9223372036854775808:";
    let mut val = 0;
    let (stop, err) = parse_int(b, 0, b.len(), b':', &mut val);
    assert_eq!((err, stop), (Some(BdecodeError::Overflow), 18));
}

/// TEST_CASE `parse_length_overflow`
#[test]
fn test_parse_length_overflow() {
    for b in [
        &b"d1:a1919191010:11111"[..],
        b"d2143289344:a4:aaaae",
        b"d214328934114:a4:aaaae",
        b"d9205357638345293824:a4:aaaae",
        b"d1:a9205357638345293824:11111",
    ] {
        assert_eq!(fail(b).code, BdecodeError::UnexpectedEof, "{b:?}");
    }
}

/// TEST_CASE `expected_colon_string`
#[test]
fn test_expected_colon_string() {
    let b = b"928";
    let mut val = 0;
    let (stop, err) = parse_int(b, 0, b.len(), b':', &mut val);
    assert_eq!((err, stop), (None, 3));
}

/// TEST_CASE `dict_find_funs`
#[test]
fn test_dict_find_funs() {
    let e = ok(b"d1:ai1e1:b3:foo1:cli1ei2ee1:dd1:xi1eee");
    assert_eq!(e.kind(), NodeKind::Dict);
    assert_eq!(e.dict_find_int_value(b"a", 0), 1);
    assert_eq!(e.dict_find_int(b"a").unwrap().kind(), NodeKind::Int);
    assert_eq!(e.dict_find_int_value(b"b", -10), -10);
    assert_eq!(e.dict_find_int_value(b"x", -10), -10);
    assert!(e.dict_find_int(b"b").is_none());
    assert!(e.dict_find_int(b"x").is_none());

    assert_eq!(e.dict_find_string_value(b"b", b""), b"foo");
    assert_eq!(e.dict_find_string(b"b").unwrap().kind(), NodeKind::Str);
    assert_eq!(e.dict_find_string_value(b"c", b"blah"), b"blah");
    assert_eq!(e.dict_find_string_value(b"x", b"blah"), b"blah");
    assert!(e.dict_find_string(b"c").is_none());
    assert!(e.dict_find_string(b"x").is_none());

    let c = e.dict_find_list(b"c").unwrap();
    assert_eq!(c.list_len(), 2);
    assert_eq!(c.list_int_value_at(0, -1), 1);
    assert_eq!(c.list_int_value_at(1, -1), 2);
    assert!(e.dict_find_list(b"d").is_none());

    let d = e.dict_find_dict(b"d").unwrap();
    assert_eq!(d.dict_find_int_value(b"x", 0), 1);
    assert_eq!(d.dict_find_int_value(b"y", -10), -10);
    assert!(e.dict_find_dict(b"c").is_none());
    assert!(e.dict_find_dict(b"x").is_none());

    assert_eq!(e.dict_len(), 4);
    let kinds: Vec<_> = (0..4).map(|i| e.dict_at(i).unwrap()).collect();
    assert_eq!(kinds[0].0, b"a");
    assert_eq!(kinds[0].1.int_value(), 1);
    assert_eq!(kinds[1].0, b"b");
    assert_eq!(kinds[1].1.string_value(), b"foo");
    assert_eq!(kinds[2].1.kind(), NodeKind::List);
    assert_eq!(kinds[3].1.kind(), NodeKind::Dict);
}

/// TEST_CASE `list_at_funs`
#[test]
fn test_list_at_funs() {
    let e = ok(b"li1e3:fooli1ei2eed1:xi1eee");
    assert_eq!(e.kind(), NodeKind::List);
    assert_eq!(e.list_int_value_at(0, 0), 1);
    assert_eq!(e.list_int_value_at(1, -10), -10);
    assert_eq!(e.list_string_value_at(1, b""), b"foo");
    assert_eq!(e.list_string_value_at(2, b"blah"), b"blah");
    let l = e.list_at(2).unwrap();
    assert_eq!((l.kind(), l.list_len()), (NodeKind::List, 2));
    assert_eq!(l.list_int_value_at(0, 0), 1);
    assert_eq!(l.list_int_value_at(1, 0), 2);
    let d = e.list_at(3).unwrap();
    assert_eq!((d.kind(), d.dict_len()), (NodeKind::Dict, 1));
    assert_eq!(d.dict_find_int_value(b"x", 0), 1);
    assert_eq!(d.dict_find_int_value(b"y", -10), -10);
    assert_eq!(e.list_len(), 4);
}

/// TEST_CASE `list_at_reverse`
#[test]
fn test_list_at_reverse() {
    let e = ok(b"li1e3:fooli1ei2eed1:xi1eee");
    assert_eq!(e.list_at(3).unwrap().kind(), NodeKind::Dict);
    assert_eq!(e.list_at(2).unwrap().kind(), NodeKind::List);
    assert_eq!(e.list_string_value_at(1, b""), b"foo");
    assert_eq!(e.list_int_value_at(0, 0), 1);
    assert_eq!(e.list_len(), 4);
}

/// TEST_CASE `dict_find_funs2`: finding the last key.
#[test]
fn test_dict_find_funs2() {
    let e = ok(b"d1:ai1e1:b3:foo1:cli1ei2ee1:dd1:xi1eee");
    assert_eq!(e.dict_find(b"d").unwrap().kind(), NodeKind::Dict);
}

/// TEST_CASE `print_entry`
#[test]
fn test_print_entry() {
    assert_eq!(
        print(b"li1e3:fooli1ei2eed1:xi1eee"),
        "[ 1, 'foo', [ 1, 2 ], { 'x': 1 } ]"
    );
}

/// TEST_CASE `print_entry2`
#[test]
fn test_print_entry2() {
    assert_eq!(
        print(b"d1:ai1e1:b3:foo1:cli1ei2ee1:dd1:xi1eee"),
        "{ 'a': 1, 'b': 'foo', 'c': [ 1, 2 ], 'd': { 'x': 1 } }"
    );
}

/// TEST_CASE `partial_parse`: the tree up to the failure stays printable.
#[test]
fn test_partial_parse() {
    let b = b"d1:ai1e1:b3:foo1:cli1ei2ee1:dd1:xi1-eee";
    assert_eq!(
        decode_lenient(b, 100, 2_000_000).error.unwrap().position,
        35
    );
    assert_eq!(
        print(b),
        "{ 'a': 1, 'b': 'foo', 'c': [ 1, 2 ], 'd': { 'x': {} } }"
    );
}

/// TEST_CASE `partial_parse2`
#[test]
fn test_partial_parse2() {
    let b = b"d1:ai1e1:b3:foo1:cli1ei2ee1:d-d1:xi1eee";
    assert_eq!(
        decode_lenient(b, 100, 2_000_000).error.unwrap().position,
        29
    );
    assert_eq!(print(b), "{ 'a': 1, 'b': 'foo', 'c': [ 1, 2 ], 'd': {} }");
}

/// TEST_CASE `partial_parse3`
#[test]
fn test_partial_parse3() {
    let b = b"d1:ai1e1:b3:foo1:cli1ei2ee-1:dd1:xi1eee";
    assert_eq!(
        decode_lenient(b, 100, 2_000_000).error.unwrap().position,
        26
    );
    assert_eq!(print(b), "{ 'a': 1, 'b': 'foo', 'c': [ 1, 2 ] }");
}

/// TEST_CASE `partial_parse4`
#[test]
fn test_partial_parse4() {
    let b = b"d1:ai1e1:b3:foo1:cli1e-i2ee1:dd1:xi1eee";
    assert_eq!(
        decode_lenient(b, 100, 2_000_000).error.unwrap().position,
        22
    );
    assert_eq!(print(b), "{ 'a': 1, 'b': 'foo', 'c': [ 1 ] }");
}

/// TEST_CASE `partial_parse_string`
#[test]
fn test_partial_parse_string() {
    assert_fail(b"55", BdecodeError::ExpectedColon, 2);
}

/// TEST_CASE `long_string_99999999`
#[test]
fn test_long_string_99999999() {
    let mut input = b"99999999:".to_vec();
    input.resize(9 + 99_999_999, b'_');
    let e = ok(&input);
    assert_eq!(e.kind(), NodeKind::Str);
    assert_eq!(e.string_value(), &input[9..]);
}

/// TEST_CASE `long_string_100000000`: a nine-digit length prefix.
#[test]
fn test_long_string_100000000() {
    let mut input = b"100000000:".to_vec();
    input.resize(10 + 100_000_000, b'_');
    let e = ok(&input);
    assert_eq!(e.kind(), NodeKind::Str);
    assert_eq!(e.string_value(), &input[10..]);
}

/// TEST_CASE `data_offset`
#[test]
fn test_data_offset() {
    let e = ok(b"li1e3:fooli1ei2eed1:xi1eee");
    let offs: Vec<_> = (0..4)
        .map(|i| e.list_at(i).unwrap().data_offset())
        .collect();
    assert_eq!(e.data_offset(), 0);
    assert_eq!(offs, [1, 4, 9, 17]);
}

/// TEST_CASE `string_offset`
#[test]
fn test_string_offset() {
    let e = ok(b"l3:foo3:bare");
    assert_eq!(e.list_at(0).unwrap().string_offset(), 3);
    assert_eq!(e.list_at(1).unwrap().string_offset(), 8);
}

/// TEST_CASE `dict_at_node`
#[test]
fn test_dict_at_node() {
    let e = ok(b"d3:foo3:bar4:test4:teste");
    let (k, v) = e.dict_at_node(0).unwrap();
    assert_eq!((k.string_offset(), v.string_offset()), (3, 8));
    let (k, v) = e.dict_at_node(1).unwrap();
    assert_eq!((k.string_offset(), v.string_offset()), (13, 19));
}

/// Not in libtorrent: an [`Entry`] survives encode, decode and copy back.
#[test]
fn test_entry_roundtrips_through_bdecode() {
    let mut e = Entry::dict();
    e.set("a", 1)
        .set("b", "foo")
        .set("c", Entry::List(vec![1.into(), "x".into()]));
    let bytes = e.encode();
    assert_eq!(Entry::from_node(&ok(&bytes)), e);
    assert_eq!(ok(&bytes).has_soft_error(), None);
}
