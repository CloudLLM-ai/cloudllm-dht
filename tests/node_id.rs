//! Tests for `node_id` and `Sha1Hash`, ported from the node-ID cases of
//! libtorrent `test/test_dht.cpp` (RC_2_1,
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg and contributors, plus the BEP 42 reference vectors.

use cloudllm_dht::node_id::{
    compare_ref, distance, distance_exp, generate_id, generate_id_impl, generate_prefix_mask,
    generate_random_id, matching_prefix, min_distance_exp, verify_id, IdSecret, NodeId,
};
use cloudllm_dht::rng::TestRng;
use cloudllm_dht::testing::{addr4, addr6, rand_v4, to_hash};
use cloudllm_dht::Sha1Hash;

/// TEST_CASE `node_id_testing`: a secret ID verifies until it is tampered
/// with, and `make_id_secret` on a random ID works the same way.
#[test]
fn test_node_id_testing() {
    let mut rng = TestRng::new(1);
    let secret = IdSecret::new(&mut rng);
    let mut rnd = secret.generate_secret_id(&mut rng);
    assert!(secret.verify_secret_id(&rnd));
    rnd.0[19] ^= 0x55;
    assert!(!secret.verify_secret_id(&rnd));

    let mut rnd = generate_random_id(&mut rng);
    secret.make_id_secret(&mut rnd, &mut rng);
    assert!(secret.verify_secret_id(&rnd));
}

/// A secret ID does not verify under a different secret.
#[test]
fn test_secret_id_rejects_other_secret() {
    let mut rng = TestRng::new(2);
    let a = IdSecret::from_value(1);
    let b = IdSecret::from_value(2);
    let id = a.generate_secret_id(&mut rng);
    assert!(a.verify_secret_id(&id));
    assert!(!b.verify_secret_id(&id));
}

/// TEST_CASE `node_id_bucket_distribution`: IDs generated for random IPs
/// land in bucket `i` with probability `2^-(i+1)`, within 5% of the
/// samples.
#[test]
fn test_node_id_bucket_distribution() {
    let mut rng = TestRng::new(42);
    let reference = generate_id(rand_v4(&mut rng), &mut rng);
    let samples: i64 = 100_000;
    let mut per_bucket = [0i64; 160];
    for _ in 0..samples {
        let ip = rand_v4(&mut rng);
        let nid = generate_id(ip, &mut rng);
        per_bucket[(159 - distance_exp(&reference, &nid)) as usize] += 1;
    }
    let mut expected = samples / 2;
    for count in &per_bucket[..25] {
        assert!(
            (count - expected).abs() < samples / 20,
            "bucket count {count} too far from {expected}"
        );
        expected /= 2;
    }
}

/// TEST_CASE `node_id_min_distance_exp`
#[test]
fn test_node_id_min_distance_exp() {
    let n1 = to_hash("0000000000000000000000000000000000000002");
    let n2 = to_hash("0000000000000000000000000000000000000004");
    let n3 = to_hash("0000000000000000000000000000000000000008");
    let zero = Sha1Hash::MIN;
    assert_eq!(min_distance_exp(&zero, &[n1]), 1);
    assert_eq!(min_distance_exp(&zero, &[n1, n1, n2]), 1);
    assert_eq!(min_distance_exp(&zero, &[n1, n1, n2, n1, n2, n3]), 1);
    assert_eq!(min_distance_exp(&zero, &[n3, n2, n2]), 2);
    assert_eq!(min_distance_exp(&zero, &[]), 160);
}

/// TEST_CASE `generate_prefix_mask`
#[test]
fn test_generate_prefix_mask() {
    let cases: &[(usize, &str)] = &[
        (0, "0000000000000000000000000000000000000000"),
        (1, "8000000000000000000000000000000000000000"),
        (2, "c000000000000000000000000000000000000000"),
        (11, "ffe0000000000000000000000000000000000000"),
        (17, "ffff800000000000000000000000000000000000"),
        (37, "fffffffff8000000000000000000000000000000"),
        (8, "ff00000000000000000000000000000000000000"),
        (159, "fffffffffffffffffffffffffffffffffffffffe"),
        (160, "ffffffffffffffffffffffffffffffffffffffff"),
        (161, "ffffffffffffffffffffffffffffffffffffffff"),
        (168, "ffffffffffffffffffffffffffffffffffffffff"),
        (1000, "ffffffffffffffffffffffffffffffffffffffff"),
        (usize::MAX, "ffffffffffffffffffffffffffffffffffffffff"),
    ];
    for (bits, hex) in cases {
        assert_eq!(generate_prefix_mask(*bits), to_hash(hex), "bits {bits}");
    }
}

/// TEST_CASE `distance_exp`. Two rows of the C++ table contain a non-hex
/// `r` that libtorrent's lenient `to_hash` tolerates; they are replaced by
/// valid hashes with the same leading bytes and therefore the same result.
#[test]
fn test_distance_exp() {
    let cases: &[(&str, &str, i32)] = &[
        (
            "ffffffffffffffffffffffffffffffffffffffff",
            "0000000000000000000000000000000000000000",
            159,
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffff",
            "7fffffffffffffffffffffffffffffffffffffff",
            159,
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffff",
            0,
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffff",
            "fffffffffffffffffffffffffffffffffffffffe",
            0,
        ),
        (
            "8000000000000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffffffffffe",
            158,
        ),
        (
            "c000000000000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffffffffffe",
            157,
        ),
        (
            "e000000000000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffffffffffe",
            156,
        ),
        (
            "f000000000000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffffffffffe",
            155,
        ),
        (
            "f8f2340985723049587230495872304958703294",
            "f743589043a890f023980f90e203980d090c3840",
            155,
        ),
        (
            "ffff740985723049587230495872304958703294",
            "ffff889043a890f023980f90e203980d090c3840",
            159 - 16,
        ),
    ];
    for (a, b, want) in cases {
        assert_eq!(distance_exp(&to_hash(a), &to_hash(b)), *want, "{a} {b}");
    }
}

/// `compare_ref` orders by XOR distance to a reference.
#[test]
fn test_compare_ref_orders_by_xor_distance() {
    let reference = to_hash("8000000000000000000000000000000000000000");
    let near = to_hash("8000000000000000000000000000000000000001");
    let far = to_hash("0000000000000000000000000000000000000001");
    assert!(compare_ref(&near, &far, &reference));
    assert!(!compare_ref(&far, &near, &reference));
    assert!(!compare_ref(&near, &near, &reference));
    assert_eq!(
        distance(&near, &reference),
        to_hash("0000000000000000000000000000000000000001")
    );
}

/// `matching_prefix` shifts before it masks.
#[test]
fn test_matching_prefix() {
    let id = to_hash("12ff000000000000000000000000000000000000");
    assert!(matching_prefix(&id, 0xff, 0x12, 0));
    assert!(matching_prefix(&id, 0xf0, 0x20, 4));
    assert!(matching_prefix(&id, 0xff, 0xff, 8));
    assert!(!matching_prefix(&id, 0xff, 0x12, 8));
}

/// BEP 42 reference vectors: the first 21 bits of the generated ID match
/// the specification's table, the last byte is `r`, and the ID verifies.
#[test]
fn test_bep42_reference_vectors() {
    let vectors: &[(&str, u32, [u8; 3])] = &[
        ("124.31.75.21", 1, [0x5f, 0xbf, 0xbf]),
        ("21.75.31.124", 86, [0x5a, 0x3c, 0xe9]),
        ("65.23.51.170", 22, [0xa5, 0xd4, 0x32]),
        ("84.124.73.14", 65, [0x1b, 0x03, 0x21]),
        ("43.213.53.83", 90, [0xe5, 0x6f, 0x6c]),
    ];
    let mut rng = TestRng::new(5);
    for (ip, r, prefix) in vectors {
        let ip = addr4(ip);
        for _ in 0..50 {
            let id = generate_id_impl(ip, *r, &mut rng);
            assert_eq!(
                [id[0], id[1], id[2] & 0xf8],
                [prefix[0], prefix[1], prefix[2] & 0xf8],
                "{ip} r={r}"
            );
            assert_eq!(u32::from(id[19]), *r & 0xff);
            assert!(verify_id(&id, ip));
        }
    }
}

/// `verify_id` rejects an ID generated for another IP, accepts any ID from
/// a local address, and works for IPv6.
#[test]
fn test_verify_id() {
    let mut rng = TestRng::new(11);
    let ip = addr4("124.31.75.21");
    let other = addr4("21.75.31.124");
    let id = generate_id(ip, &mut rng);
    assert!(verify_id(&id, ip));
    assert!(!verify_id(&id, other));
    assert!(verify_id(&id, addr4("192.168.1.1")));
    assert!(verify_id(&Sha1Hash::MAX, addr4("10.1.2.3")));

    let ip6 = addr6("2001:db8:85a3::8a2e:370:7334");
    let id6 = generate_id(ip6, &mut rng);
    assert!(verify_id(&id6, ip6));
    // only the first 64 bits of an IPv6 address feed the ID
    assert!(verify_id(&id6, addr6("2001:db8:85a3::1")));
    assert!(!verify_id(&id6, addr6("2a00:1450:4001:81b::200e")));
    assert!(verify_id(&Sha1Hash::MAX, addr6("fe80::1")));
}

/// Only the masked IP bits matter: the BEP 42 mask means two IPv4
/// addresses that differ in masked-out bits share a valid prefix.
#[test]
fn test_bep42_mask_ignores_low_bits() {
    let mut rng = TestRng::new(3);
    let id = generate_id_impl(addr4("124.31.75.21"), 1, &mut rng);
    // octet 0 mask 0x03, octet 1 0x0f, octet 2 0x3f, octet 3 0xff
    assert!(verify_id(&id, addr4("124.31.75.21")));
    assert!(
        verify_id(&id, addr4("252.47.75.21")),
        "differs only in masked-out bits"
    );
}

/// `Sha1Hash` hex, ordering, xor, shifts and leading zeros.
#[test]
fn test_sha1_hash_basics() {
    let h = to_hash("00ff000000000000000000000000000000000001");
    assert_eq!(h.to_string(), "00ff000000000000000000000000000000000001");
    assert_eq!(h.leading_zeros(), 8);
    assert_eq!(Sha1Hash::MIN.leading_zeros(), 160);
    assert_eq!(Sha1Hash::MAX.leading_zeros(), 0);
    assert_eq!(h.shl(0), h);
    assert_eq!(
        h.shl(8).to_string(),
        "ff00000000000000000000000000000000000100"
    );
    assert_eq!(h.shl(160), Sha1Hash::MIN);
    assert_eq!(h.shl(1000), Sha1Hash::MIN);
    assert_eq!(h ^ h, Sha1Hash::MIN);
    assert_eq!(
        Sha1Hash::of(b"abc").to_string(),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert!(Sha1Hash::from_hex("zz").is_err());
    assert!(Sha1Hash::from_hex(&"g".repeat(40)).is_err());
    assert!(Sha1Hash::from_slice(&[0; 19]).is_none());
    let n: NodeId = "ff".repeat(20).parse().unwrap();
    assert_eq!(n, Sha1Hash::MAX);
}
