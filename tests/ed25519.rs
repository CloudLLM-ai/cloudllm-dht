//! Tests for `ed25519`: the cases of libtorrent `test/test_ed25519.cpp`
//! (RC_2_1, `86d573f2631b0162d3cca5e257217eaf530fdcba`) and differential
//! checks against `ed25519-dalek`, which stands in for "another
//! implementation" (libtorrent itself cannot be called from here).

use cloudllm_dht::ed25519::{
    add_scalar_public, add_scalar_secret, create_keypair, create_seed, key_exchange, sign, verify,
};
use cloudllm_dht::rng::{Rng, SystemRng, TestRng};
use cloudllm_dht::testing::{hex, test_keypair};
use cloudllm_dht::types::{PublicKey, SecretKey, Signature};

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
use ed25519_dalek::{Signature as DalekSig, VerifyingKey};
use sha2::Sha512;

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `test_vector` of `test_ed25519.cpp`: seed -> public key, sign, compare
/// the signature, verify.
fn test_vector(seed: &str, public: &str, sig_hex: &str, message: &str) {
    let seed: [u8; 32] = hex(seed).try_into().unwrap();
    let (pk, sk) = create_keypair(&seed);
    assert_eq!(to_hex(&pk.0), public);
    let msg = hex(message);
    let sig = sign(&msg, &pk, &sk);
    assert_eq!(to_hex(&sig.0), sig_hex);
    assert!(verify(&sig, &msg, &pk));
}

/// Port of `TEST_CASE(ed25519_test_vec1)`: the gnupg/libgcrypt Ed25519
/// vectors (TST 2, 3, 4, 47, 48, 49, 50, 51, 52, 53, 224, 225).
#[test]
fn test_ed25519_test_vec1() {
    test_vector(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
        "72",
    );
    test_vector(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        concat!(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ),
        "af82",
    );
    test_vector(
        "0d4a05b07352a5436e180356da0ae6efa0345ff7fb1572575772e8005ed978e9",
        "e61a185bcef2613a6c7cb79763ce945d3b245d76114dd440bcf5f2dc1aa57057",
        concat!(
            "d9868d52c2bebce5f3fa5a79891970f309cb6591e3e1702a70276fa97c24b3a8",
            "e58606c38c9758529da50ee31b8219cba45271c689afa60b0ea26c99db19b00c"
        ),
        "cbc77b",
    );
    test_vector(
        "89f0d68299ba0a5a83f248ae0c169f8e3849a9b47bd4549884305c9912b46603",
        "aba3e795aab2012acceadd7b3bd9daeeed6ff5258bdcd7c93699c2a3836e3832",
        concat!(
            "2c691fa8d487ce20d5d2fa41559116e0bbf4397cf5240e152556183541d66cf7",
            "53582401a4388d390339dbef4d384743caa346f55f8daba68ba7b9131a8a6e0b"
        ),
        concat!(
            "4f1846dd7ad50e545d4cfbffbb1dc2ff145dc123754d08af4e44ecc0bc8c9141",
            "1388bc7653e2d893d1eac2107d05"
        ),
    );
    test_vector(
        "0a3c1844e2db070fb24e3c95cb1cc6714ef84e2ccd2b9dd2f1460ebf7ecf13b1",
        "72e409937e0610eb5c20b326dc6ea1bbbc0406701c5cd67d1fbde09192b07c01",
        concat!(
            "87f7fdf46095201e877a588fe3e5aaf476bd63138d8a878b89d6ac60631b3458",
            "b9d41a3c61a588e1db8d29a5968981b018776c588780922f5aa732ba6379dd05"
        ),
        concat!(
            "4c8274d0ed1f74e2c86c08d955bde55b2d54327e82062a1f71f70d536fdc8722",
            "cdead7d22aaead2bfaa1ad00b82957"
        ),
    );
    test_vector(
        "c8d7a8818b98dfdb20839c871cb5c48e9e9470ca3ad35ba2613a5d3199c8ab23",
        "90d2efbba4d43e6b2b992ca16083dbcfa2b322383907b0ee75f3e95845d3c47f",
        concat!(
            "fa2e994421aef1d5856674813d05cbd2cf84ef5eb424af6ecd0dc6fdbdc2fe60",
            "5fe985883312ecf34f59bfb2f1c9149e5b9cc9ecda05b2731130f3ed28ddae0b"
        ),
        concat!(
            "783e33c3acbdbb36e819f544a7781d83fc283d3309f5d3d12c8dcd6b0b3d0e89",
            "e38cfd3b4d0885661ca547fb9764abff"
        ),
    );
    test_vector(
        "b482703612d0c586f76cfcb21cfd2103c957251504a8c0ac4c86c9c6f3e429ff",
        "fd711dc7dd3b1dfb9df9704be3e6b26f587fe7dd7ba456a91ba43fe51aec09ad",
        concat!(
            "58832bdeb26feafc31b46277cf3fb5d7a17dfb7ccd9b1f58ecbe6feb97966682",
            "8f239ba4d75219260ecac0acf40f0e5e2590f4caa16bbbcd8a155d347967a607"
        ),
        concat!(
            "29d77acfd99c7a0070a88feb6247a2bce9984fe3e6fbf19d4045042a21ab26cb",
            "d771e184a9a75f316b648c6920db92b87b"
        ),
    );
    test_vector(
        "84e50dd9a0f197e3893c38dbd91fafc344c1776d3a400e2f0f0ee7aa829eb8a2",
        "2c50f870ee48b36b0ac2f8a5f336fb090b113050dbcc25e078200a6e16153eea",
        concat!(
            "69e6a4491a63837316e86a5f4ba7cd0d731ecc58f1d0a264c67c89befdd8d382",
            "9d8de13b33cc0bf513931715c7809657e2bfb960e5c764c971d733746093e500"
        ),
        concat!(
            "f3992cde6493e671f1e129ddca8038b0abdb77bb9035f9f8be54bd5d68c1aeff",
            "724ff47d29344391dc536166b8671cbbf123"
        ),
    );
    test_vector(
        "b322d46577a2a991a4d1698287832a39c487ef776b4bff037a05c7f1812bdeec",
        "eb2bcadfd3eec2986baff32b98e7c4dbf03ff95d8ad5ff9aa9506e5472ff845f",
        concat!(
            "c7b55137317ca21e33489ff6a9bfab97c855dc6f85684a70a9125a261b56d5e6",
            "f149c5774d734f2d8debfc77b721896a8267c23768e9badb910eef83ec258802"
        ),
        concat!(
            "19f1bf5dcf1750c611f1c4a2865200504d82298edd72671f62a7b1471ac3d4a3",
            "0f7de9e5da4108c52a4ce70a3e114a52a3b3c5"
        ),
    );
    test_vector(
        "960cab5034b9838d098d2dcbf4364bec16d388f6376d73a6273b70f82bbc98c0",
        "5e3c19f2415acf729f829a4ebd5c40e1a6bc9fbca95703a9376087ed0937e51a",
        concat!(
            "27d4c3a1811ef9d4360b3bdd133c2ccc30d02c2f248215776cb07ee4177f9b13",
            "fc42dd70a6c2fed8f225c7663c7f182e7ee8eccff20dc7b0e1d5834ec5b1ea01"
        ),
        concat!(
            "f8b21962447b0a8f2e4279de411bea128e0be44b6915e6cda88341a68a0d8183",
            "57db938eac73e0af6d31206b3948f8c48a447308"
        ),
    );
    test_vector(
        "ae1d2c6b171be24c2e413d364dcda97fa476aaf9123d3366b0be03a142fe6e7d",
        "d437f57542c681dd543487408ec7a44bd42a5fd545ce2f4c8297d67bb0b3aa7b",
        concat!(
            "909008f3fcfff43988aee1314b15b1822caaa8dab120bd452af494e08335b44a",
            "94c313c4b145eadd5166eaac034e29b7e6ac7941d5961fc49d260e1c4820b00e"
        ),
        concat!(
            "9e6c2fc76e30f17cd8b498845da44f22d55bec150c6130b411c6339d14b39969",
            "ab1033be687569a991a06f70b2a8a6931a777b0e4be6723cd75e5aa7532813ef",
            "50b3d37271640fa2fb287c0355257641ea935c851c0b6ac68be72c88dfc5856f",
            "b53543fb377b0dbf64808afcc4274aa456855ad28f61267a419bc72166b9ca73",
            "cd3bb79bf7dd259baa75911440974b68e8ba95a78cbbe1cb6ad807a33a1cce2f",
            "406ff7bcbd058b44a311b38ab4d4e61416c4a74d883d6a6a794abd9cf1c03902",
            "8bf1b20e3d4990aae86f32bf06cd8349a7a884cce0165e36a0640e987b9d51"
        ),
    );
    test_vector(
        "0265a7944baccfebf417b87ae1e6df2ff2a544ffb58225a08e092be03f026097",
        "63d327615ea0139be0740b618aff1acfa818d4b0c2cfeaf0da93cdd5245fb5a9",
        concat!(
            "b6c445b7eddca5935c61708d44ea5906bd19cc54224eae3c8e46ce99f5cbbd34",
            "1f26623938f5fe04070b1b02e71fbb7c78a90c0dda66cb143fab02e6a0bae306"
        ),
        concat!(
            "874ed712a2c41c26a2d9527c55233fde0a4ffb86af8e8a1dd0a820502c5a2693",
            "2bf87ee0de72a8874ef2eebf83384d443f7a5f46a1233b4fb514a24699818248",
            "94f325bf86aa0fe1217153d40f3556c43a8ea9269444e149fb70e9415ae0766c",
            "565d93d1d6368f9a23a0ad76f9a09dbf79634aa97178677734d04ef1a5b3f87c",
            "e1ee9fc5a9ac4e7a72c9d7d31ec89e28a845d2e1103c15d6410ce3c723b0cc22",
            "09f698aa9fa288bbbecfd9e5f89cdcb09d3c215feb47a58b71ea70e2abead67f",
            "1b08ea6f561fb93ef05232eedabfc1c7702ab039bc465cf57e207f1093fc8208"
        ),
    );
}

/// Port of `TEST_CASE(create_seed)`: two seeds differ and are not all zero.
#[test]
fn test_create_seed() {
    let s1 = create_seed(&mut SystemRng);
    let s2 = create_seed(&mut SystemRng);
    assert_ne!(s1, s2);
    assert!(s1.iter().filter(|b| **b != 0).count() > 0);
    assert!(s2.iter().filter(|b| **b != 0).count() > 0);
}

/// Port of `TEST_CASE(add_scalar)`: the public key and the secret key are
/// shifted independently by the same scalar; the shifted pair still signs
/// and verifies.
#[test]
fn test_add_scalar() {
    let mut rng = SystemRng;
    let (pk, sk) = create_keypair(&create_seed(&mut rng));
    let n = create_seed(&mut rng);
    let pk1 = add_scalar_public(&pk, &n).expect("valid point");
    let sk1 = add_scalar_secret(&sk, &n);
    let sig = sign(b"Hello world", &pk1, &sk1);
    assert!(verify(&sig, b"Hello world", &pk1));
    // and the original key no longer verifies it
    assert!(!verify(&sig, b"Hello world", &pk));
}

/// Port of `TEST_CASE(key_exchange)`: both sides derive the same secret.
#[test]
fn test_key_exchange() {
    let mut rng = SystemRng;
    let (pk1, sk1) = create_keypair(&create_seed(&mut rng));
    let (pk2, sk2) = create_keypair(&create_seed(&mut rng));
    let secret_b = key_exchange(&pk1, &sk2).unwrap();
    let secret_a = key_exchange(&pk2, &sk1).unwrap();
    assert_eq!(to_hex(&secret_a), to_hex(&secret_b));
}

/// The BEP 44 key pair `get_test_keypair` of `test_dht.cpp` is a valid
/// expanded key: its public key is `scalar * B` of its own secret half, and
/// signatures made with it verify.
#[test]
fn test_fixed_test_keypair_is_consistent() {
    let (pk, sk) = test_keypair();
    let sig = sign(b"abc", &pk, &sk);
    assert!(verify(&sig, b"abc", &pk));
    let esk = ExpandedSecretKey {
        scalar: Scalar::from_bytes_mod_order(sk.0[..32].try_into().unwrap()),
        hash_prefix: sk.0[32..].try_into().unwrap(),
    };
    let vk = VerifyingKey::from_bytes(&pk.0).expect("valid key");
    let oracle = raw_sign::<Sha512>(&esk, b"abc", &vk);
    assert_eq!(oracle.to_bytes(), sig.0);
}

/// Differential test: our signatures are byte-identical to `ed25519-dalek`'s
/// `raw_sign` and verify under dalek's strict verifier, for random seeds and
/// message lengths (including the empty message).
#[test]
fn test_sign_matches_ed25519_dalek_oracle() {
    let mut rng = TestRng::new(0xed25519);
    for len in [0usize, 1, 31, 32, 33, 64, 127, 128, 1000] {
        let (pk, sk) = create_keypair(&create_seed(&mut rng));
        let mut msg = vec![0u8; len];
        rng.fill_bytes(&mut msg);
        let ours = sign(&msg, &pk, &sk);
        let esk = ExpandedSecretKey::from_bytes(&sk.0);
        let vk = VerifyingKey::from_bytes(&pk.0).unwrap();
        let theirs = raw_sign::<Sha512>(&esk, &msg, &vk);
        assert_eq!(ours.0, theirs.to_bytes(), "len {len}");
        assert!(vk
            .verify_strict(&msg, &DalekSig::from_bytes(&ours.0))
            .is_ok());
        assert!(verify(&ours, &msg, &pk));
    }
}

/// A flipped bit anywhere in the message, signature or key is rejected.
#[test]
fn test_verify_rejects_tampering() {
    let (pk, sk) = create_keypair(&[5; 32]);
    let msg = b"tamper me";
    let sig = sign(msg, &pk, &sk);
    for i in 0..64 {
        let mut s = sig.0;
        s[i] ^= 1;
        assert!(!verify(&Signature(s), msg, &pk), "sig byte {i}");
    }
    let mut m = msg.to_vec();
    m[0] ^= 1;
    assert!(!verify(&sig, &m, &pk));
    let (other, _) = create_keypair(&[6; 32]);
    assert!(!verify(&sig, msg, &other));
}

/// A public key that is not on the curve verifies nothing (and must not
/// panic): `y = 2` has no square root `x`.
#[test]
fn test_verify_rejects_non_curve_public_key() {
    let mut y = [0u8; 32];
    y[0] = 2;
    let sig = Signature([0; 64]);
    assert!(!verify(&sig, b"m", &PublicKey(y)));
}

/// libtorrent only requires `sig[63] & 224 == 0`, so the malleated
/// `S + l` of a valid signature (still below 2^253) verifies, where
/// ed25519-dalek's canonical-`S` check rejects it. The compatibility
/// decision documented in `ed25519.rs`: a DHT node must accept what
/// libtorrent accepts. Regression for the "verify (not verify_strict) must
/// accept everything libtorrent accepts" requirement of ARCHITECTURE.md.
#[test]
fn test_verify_accepts_s_plus_l_like_libtorrent() {
    // l = 2^252 + 27742317777372353535851937790883648493 (little endian)
    let l: [u8; 32] = hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
        .try_into()
        .unwrap();
    let (pk, sk) = create_keypair(&[11; 32]);
    // find a message whose S leaves room for + l below 2^253
    for i in 0u32..64 {
        let msg = i.to_le_bytes();
        let sig = sign(&msg, &pk, &sk);
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig.0[32..]);
        let mut carry = 0u16;
        let mut sum = [0u8; 32];
        for k in 0..32 {
            let t = u16::from(s[k]) + u16::from(l[k]) + carry;
            sum[k] = (t & 0xff) as u8;
            carry = t >> 8;
        }
        if carry != 0 || sum[31] & 224 != 0 {
            continue;
        }
        let mut malleated = sig.0;
        malleated[32..].copy_from_slice(&sum);
        assert!(
            verify(&Signature(malleated), &msg, &pk),
            "libtorrent accepts S + l"
        );
        assert!(
            VerifyingKey::from_bytes(&pk.0)
                .unwrap()
                .verify_strict(&msg, &DalekSig::from_bytes(&malleated))
                .is_err(),
            "dalek's verifier would have rejected it"
        );
        return;
    }
    panic!("no message with room for S + l found");
}

/// Keys produced by `add_scalar_secret` carry an unclamped scalar; signing
/// with them must not re-clamp (what `ed25519-dalek`'s
/// `ExpandedSecretKey::from_bytes` would do), or the signature would not
/// verify under the shifted public key. The nonce prefix is re-derived from
/// the old prefix and the full scalar.
#[test]
fn test_add_scalar_secret_is_not_clamped_and_rederives_prefix() {
    let (pk, sk) = create_keypair(&[21; 32]);
    let n = [0xa5u8; 32];
    let sk1 = add_scalar_secret(&sk, &n);
    let pk1 = add_scalar_public(&pk, &n).unwrap();
    assert_ne!(sk1.0[32..], sk.0[32..], "prefix changes with the scalar");
    let expect_prefix = {
        use sha2::Digest;
        let mut h = Sha512::new();
        h.update(&sk.0[32..]);
        h.update(n);
        h.finalize()
    };
    assert_eq!(sk1.0[32..], expect_prefix[..32]);
    let sig = sign(b"m", &pk1, &sk1);
    assert!(verify(&sig, b"m", &pk1));
    // the scalar half is a canonical (reduced) scalar
    let a1: [u8; 32] = sk1.0[..32].try_into().unwrap();
    assert!(bool::from(Scalar::from_canonical_bytes(a1).is_some()));
    // and the public key it derives matches the shifted public key
    let derived =
        curve25519_dalek::edwards::EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(a1));
    assert_eq!(derived.compress().to_bytes(), pk1.0);
}

/// The top bit of the scalar is ignored by `add_scalar` (the doc warning in
/// `ed25519.hpp`): scalars differing only in bit 255 give the same public
/// key and scalar half.
#[test]
fn test_add_scalar_ignores_top_bit() {
    let (pk, sk) = create_keypair(&[2; 32]);
    let mut n = [7u8; 32];
    let a = add_scalar_public(&pk, &n).unwrap();
    let sa = add_scalar_secret(&sk, &n);
    n[31] |= 0x80;
    let b = add_scalar_public(&pk, &n).unwrap();
    let sb = add_scalar_secret(&sk, &n);
    assert_eq!(a, b);
    assert_eq!(sa.0[..32], sb.0[..32]);
    // ...though the nonce prefix hashes the scalar as given
    assert_ne!(sa.0[32..], sb.0[32..]);
}

/// Non-points are reported as `None` by the operations that must decode one
/// (libtorrent computes garbage here).
#[test]
fn test_point_operations_reject_non_points() {
    let mut y = [0u8; 32];
    y[0] = 2;
    let bad = PublicKey(y);
    let (_, sk) = create_keypair(&[1; 32]);
    assert!(add_scalar_public(&bad, &[1; 32]).is_none());
    assert!(key_exchange(&bad, &sk).is_none());
}

/// The key exchange matches an independent X25519 (RFC 7748) computation:
/// the Montgomery u-coordinate of the Ed25519 key is `(1 + y) / (1 - y)`,
/// and ed25519-dalek's `VerifyingKey::to_montgomery` gives it.
#[test]
fn test_key_exchange_matches_x25519_on_montgomery_form() {
    let (pk_a, _) = create_keypair(&[1; 32]);
    let (_, sk_b) = create_keypair(&[2; 32]);
    let vk = VerifyingKey::from_bytes(&pk_a.0).unwrap();
    let u = vk.to_montgomery();
    let expect = u.mul_clamped(sk_b.0[..32].try_into().unwrap());
    assert_eq!(key_exchange(&pk_a, &sk_b).unwrap(), expect.to_bytes());
}

/// `SecretKey` and `Signature` are plain 64-byte values here; both halves of
/// the secret survive `create_keypair`'s clamping contract.
#[test]
fn test_create_keypair_clamps_scalar_half() {
    let mut rng = TestRng::new(9);
    for _ in 0..32 {
        let (_, SecretKey(sk)) = create_keypair(&create_seed(&mut rng));
        assert_eq!(sk[0] & 7, 0);
        assert_eq!(sk[31] & 0xc0, 0x40);
    }
}
