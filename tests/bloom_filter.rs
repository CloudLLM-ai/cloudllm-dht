//! Tests for the BEP 33 bloom filter and `announce_flags`: the
//! `bloom_filter` case of libtorrent `test/test_dht.cpp` (RC_2_1,
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`) plus unit coverage for the
//! behaviours it does not reach.

use cloudllm_dht::announce_flags::AnnounceFlags;
use cloudllm_dht::bloom_filter::{count_zero_bits, hash_address, BloomFilter};
use cloudllm_dht::Sha1Hash;

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The filter built in `TEST_CASE(bloom_filter)` (256 IPv4 addresses and,
/// when IPv6 is supported, 1000 IPv6 ones), checked against the BEP 33 test
/// vectors for both the filter bytes and the size estimate.
fn bep33_filter(with_v6: bool) -> BloomFilter<256> {
    let mut test = BloomFilter::<256>::new();
    for i in 0..256 {
        let a: std::net::IpAddr = format!("192.0.2.{i}").parse().unwrap();
        test.set(&hash_address(a));
    }
    if with_v6 {
        for i in 0u32..0x3e8 {
            let a: std::net::IpAddr = format!("2001:db8::{i:x}").parse().unwrap();
            test.set(&hash_address(a));
        }
    }
    test
}

/// Port of `TEST_CASE(bloom_filter)`, the IPv6 branch: BEP 33's published
/// vector (size 1224.93 and the 256 filter bytes).
#[test]
fn test_bloom_filter_bep33_vector_with_ipv6() {
    let test = bep33_filter(true);
    assert!((f64::from(test.size()) - 1224.93).abs() < 0.001);
    let expected = concat!(
        "f6c3f5eaa07ffd91bde89f777f26fb2bff37bdb8fb2bbaa2fd3ddde7bacfff75",
        "ee7ccbaefe5eedb1fbfaff67f6abff5e43ddbca3fd9b9ffdf4ffd3e9dff12d1b",
        "df59db53dbe9fa5b7ff3b8fdfcde1afb8bedd7be2f3ee71ebbbfe93bcdeefe14",
        "8246c2bc5dbff7e7efdcf24fd8dc7adffd8fffdfddfff7a4bbeedf5cb95ce81f",
        "c7fcff1ff4ffffdfe5f7fdcbb7fd79b3fa1fc77bfe07fff905b7b7ffc7fefeff",
        "e0b8370bb0cd3f5b7f2bd93feb4386cfdd6f7fd5bfaf2e9ebffffeecd67adbf7",
        "c67f17efd5d75eba6ffeba7fff47a91eb1bfbb53e8abfb5762abe8ff237279bf",
        "efbfeef5ffc5febfdfe5adffadfee1fb737ffffbfd9f6aeffeee76b6fd8f72ef"
    );
    assert_eq!(to_hex(test.as_bytes()), expected);
}

/// Port of `TEST_CASE(bloom_filter)`, the no-IPv6 branch (the vector BEP 33
/// gives for the 256 IPv4 addresses alone).
#[test]
fn test_bloom_filter_bep33_vector_ipv4_only() {
    let test = bep33_filter(false);
    assert!((f64::from(test.size()) - 257.854).abs() < 0.001);
    let expected = concat!(
        "24c0004020043000102012743e004800",
        "37110820422110008000c0e302854835",
        "a05401a4045021302a306c0600018810",
        "02d8a0a3a8001901b40a800900310008",
        "d2108110c2496a0028700010d804188b",
        "01415200082004088026411104a80404",
        "8002002000080680828c400080cc4002",
        "0c042c0494447280928041402104080d",
        "4240040414a41f0205654800b0811830",
        "d2020042b002c5800004a71d0204804a",
        "0028120a004c10017801490b83400404",
        "4106005421000c86900a002050020351",
        "0060144e900100924a1018141a028012",
        "913f0041802250042280481200002004",
        "430804210101c08111c1080100108000",
        "2038008211004266848606b035001048"
    );
    assert_eq!(to_hex(test.as_bytes()), expected);
}

/// An empty filter estimates 0.5 items (libtorrent caps the zero-bit count
/// at `m - 1`) and finds nothing; a completely full one has no finite
/// estimate and reports infinity, exactly like libtorrent.
#[test]
fn test_bloom_filter_size_of_empty_and_saturated() {
    let empty = BloomFilter::<256>::new();
    assert!((empty.size() - 0.5).abs() < 1e-3);
    assert!(!empty.find(&Sha1Hash::of(b"x")));
    let mut full = BloomFilter::<4>::new();
    for i in 0u32..2000 {
        full.set(&Sha1Hash::of(&i.to_be_bytes()));
    }
    assert_eq!(count_zero_bits(full.as_bytes()), 0);
    assert_eq!(full.size(), f32::INFINITY);
}

/// `set` then `find` has no false negatives, `clear` empties the filter,
/// and the wire form round-trips through `from_bytes`; a wrong length is
/// rejected rather than copied blindly.
#[test]
fn test_bloom_filter_set_find_clear_and_wire_roundtrip() {
    let mut f = BloomFilter::<128>::new();
    let keys: Vec<Sha1Hash> = (0u32..50).map(|i| Sha1Hash::of(&i.to_le_bytes())).collect();
    keys.iter().for_each(|k| f.set(k));
    assert!(keys.iter().all(|k| f.find(k)));
    let copy = BloomFilter::<128>::from_bytes(f.as_bytes()).unwrap();
    assert_eq!(copy, f);
    assert!(BloomFilter::<128>::from_bytes(&[0; 127]).is_none());
    assert!(BloomFilter::<128>::from_bytes(&[0; 129]).is_none());
    f.clear();
    assert_eq!(f, BloomFilter::<128>::new());
    assert!(!keys.iter().any(|k| f.find(k)));
}

/// The index arithmetic reads the first four key bytes little-endian and
/// reduces modulo the bit count: key `01 00 02 00` sets bits 1 and 2.
#[test]
fn test_bloom_filter_index_layout() {
    let mut key = [0u8; 20];
    key[0] = 1;
    key[2] = 2;
    let mut f = BloomFilter::<256>::new();
    f.set(&Sha1Hash(key));
    assert_eq!(f.as_bytes()[0], 0b0000_0110);
    assert_eq!(count_zero_bits(f.as_bytes()), 256 * 8 - 2);
    // 0x0800 = 2048 = the bit count: wraps to bit 0.
    key[0] = 0;
    key[1] = 8;
    let mut g = BloomFilter::<256>::new();
    g.set(&Sha1Hash(key));
    assert_eq!(g.as_bytes()[0] & 1, 1);
}

/// `hash_address` hashes 4 raw bytes for IPv4 and 16 for IPv6.
#[test]
fn test_hash_address_uses_raw_octets() {
    let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
    let octets = match v6 {
        std::net::IpAddr::V6(a) => a.octets(),
        std::net::IpAddr::V4(_) => unreachable!(),
    };
    assert_eq!(hash_address(v6), Sha1Hash::of(&octets));
}

/// Announce flags use libtorrent's bit positions and compose like a bitfield.
#[test]
fn test_announce_flags_bits_and_composition() {
    assert_eq!(AnnounceFlags::SEED.bits(), 1);
    assert_eq!(AnnounceFlags::IMPLIED_PORT.bits(), 2);
    assert_eq!(AnnounceFlags::SSL_TORRENT.bits(), 4);
    let mut f = AnnounceFlags::default();
    assert!(f.is_empty());
    f |= AnnounceFlags::SEED;
    f |= AnnounceFlags::SSL_TORRENT;
    assert!(f.contains(AnnounceFlags::SEED | AnnounceFlags::SSL_TORRENT));
    assert!(!f.contains(AnnounceFlags::IMPLIED_PORT));
    assert!(f.contains(AnnounceFlags::EMPTY));
    assert_eq!(
        f.difference(AnnounceFlags::SEED),
        AnnounceFlags::SSL_TORRENT
    );
    assert_eq!(f & AnnounceFlags::SEED, AnnounceFlags::SEED);
    assert_eq!((!f).bits() & 0b111, 0b010);
    assert_eq!(AnnounceFlags::from_bits(0x80).bits(), 0x80);
}
