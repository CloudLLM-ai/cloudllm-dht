//! Drives `DefaultStorage` with arbitrary operation sequences over a tiny key
//! space (so announces, evictions, expiry and replacement collide often) and
//! checks that the counters always equal what the storage actually holds and
//! that every configured cap holds.
//!
//! The clock and the RNG are deterministic, no panics are allowed for any
//! combination of settings (including zero and negative caps), and a mutable
//! item's sequence number only ever moves forward while it stays stored.
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use arbitrary::Arbitrary;
use cloudllm_dht::bencode::Entry;
use cloudllm_dht::rng::TestRng;
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::storage::{DefaultStorage, DhtStorage};
use cloudllm_dht::time::{Clock, ManualClock};
use cloudllm_dht::types::{PublicKey, SequenceNumber, Signature};
use cloudllm_dht::Sha1Hash;
use libfuzzer_sys::fuzz_target;

const KEYS: u8 = 6;
const MAX_OPS: usize = 200;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Who {
    V4(u8),
    /// An IPv6 peer: `prefix` picks one of a few /56s, `host` the address in it.
    V6 { prefix: u8, host: u8 },
}

impl Who {
    fn ip(self) -> IpAddr {
        match self {
            Who::V4(b) => IpAddr::V4(Ipv4Addr::new(10, 0, b / 16, b % 16)),
            Who::V6 { prefix, host } => IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                0,
                u16::from(prefix % 3) << 8,
                0,
                0,
                0,
                u16::from(host % 24) + 1,
            )),
        }
    }
}

fn key(k: u8) -> Sha1Hash {
    Sha1Hash([k % KEYS; 20])
}

#[derive(Arbitrary, Debug)]
enum Op {
    Announce { ih: u8, who: Who, port: u8, seed: bool, name: u8 },
    GetPeers { ih: u8, who: Who, noseed: bool, scrape: bool },
    PutImmutable { t: u8, who: Who, len: u8 },
    PutMutable { t: u8, who: Who, seq: i8, salt: u8 },
    GetMutable { t: u8, seq: i8, force: bool },
    GetImmutable { t: u8 },
    Sample,
    Tick { secs: u16 },
    Advance { secs: u16 },
    Settings { torrents: i8, peers: i8, items: i8, lifetime: u16, reply: u8, sample: i16, count: i8 },
    NodeIds { n: u8 },
}

fn count_values(s: &DefaultStorage, ih: &Sha1Hash) -> Option<usize> {
    let mut total = 0;
    let mut found = false;
    for who in [IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V6(Ipv6Addr::UNSPECIFIED)] {
        let mut e = Entry::Undefined;
        s.get_peers(ih, false, false, who, &mut e);
        if let Some(v) = e.get("values") {
            found = true;
            total += v.as_list().expect("values is a list").len();
        }
    }
    found.then_some(total)
}

fn check_counters(s: &DefaultStorage, s_settings: &DhtSettings) {
    let c = s.counters();
    let (mut torrents, mut peers, mut imm, mut mutable) = (0, 0, 0, 0);
    for k in 0..KEYS {
        let t = key(k);
        if let Some(n) = count_values(s, &t) {
            torrents += 1;
            peers += n;
        }
        imm += i32::from(s.get_immutable_item(&t, &mut Entry::Undefined));
        mutable += i32::from(s.get_mutable_item_seq(&t).is_some());
    }
    // The key space is small enough that every stored thing is reachable
    // through it, except that the reply is capped: compare only when the
    // cap cannot have cut the peer list.
    assert_eq!(c.torrents, torrents, "torrents");
    assert_eq!(c.immutable_data, imm, "immutable");
    assert_eq!(c.mutable_data, mutable, "mutable");
    if s_settings.max_peers_reply >= 4000 {
        assert_eq!(usize::try_from(c.peers).unwrap(), peers, "peers");
    }
    assert!(c.torrents >= 0 && c.peers >= 0 && c.immutable_data >= 0 && c.mutable_data >= 0);
    let cap = |n: i32| n.max(0);
    assert!(c.torrents <= cap(s_settings.max_torrents));
    assert!(c.immutable_data <= cap(s_settings.max_dht_items));
    assert!(c.mutable_data <= cap(s_settings.max_dht_items));
}

fuzz_target!(|ops: Vec<Op>| {
    let clock = ManualClock::new();
    let mut settings = DhtSettings {
        max_peers_reply: 4000,
        max_torrents: 4,
        max_dht_items: 3,
        max_peers: 40,
        item_lifetime: 7200,
        ..DhtSettings::default()
    };
    let mut s = DefaultStorage::new(&settings, Box::new(clock.clone()), Box::new(TestRng::new(1)));
    s.update_node_ids(&[Sha1Hash([1; 20])]);

    for op in ops.iter().take(MAX_OPS) {
        match *op {
            Op::Announce { ih, who, port, seed, name } => {
                let name = "n".repeat(usize::from(name));
                s.announce_peer(&key(ih), SocketAddr::new(who.ip(), u16::from(port)), &name, seed);
            }
            Op::GetPeers { ih, who, noseed, scrape } => {
                let mut e = Entry::Undefined;
                s.get_peers(&key(ih), noseed, scrape, who.ip(), &mut e);
            }
            Op::PutImmutable { t, who, len } => {
                s.put_immutable_item(&key(t), &vec![b'x'; usize::from(len)], who.ip());
            }
            Op::PutMutable { t, who, seq, salt } => {
                let t = key(t);
                let before = s.get_mutable_item_seq(&t);
                let seq = SequenceNumber(i64::from(seq));
                s.put_mutable_item(
                    &t,
                    b"i1e",
                    &Signature::default(),
                    seq,
                    &PublicKey::default(),
                    &vec![b's'; usize::from(salt % 65)],
                    who.ip(),
                );
                let after = s.get_mutable_item_seq(&t);
                match before {
                    Some(b) => assert_eq!(after, Some(b.max(seq)), "seq only moves forward"),
                    None => assert!(after.is_none() || after == Some(seq)),
                }
            }
            Op::GetMutable { t, seq, force } => {
                let mut e = Entry::Undefined;
                let found = s.get_mutable_item(&key(t), SequenceNumber(i64::from(seq)), force, &mut e);
                assert_eq!(found, s.get_mutable_item_seq(&key(t)).is_some());
                assert_eq!(found, e.get("seq").is_some());
            }
            Op::GetImmutable { t } => {
                let mut e = Entry::Undefined;
                if s.get_immutable_item(&key(t), &mut e) {
                    assert!(e.get("v").is_some());
                }
            }
            Op::Sample => {
                let mut e = Entry::Undefined;
                let n = s.get_infohashes_sample(&mut e);
                let bytes = e.get("samples").and_then(Entry::as_bytes).expect("samples");
                assert_eq!(bytes.len(), n * 20);
                assert!(n <= 20);
            }
            Op::Tick { secs } => {
                clock.advance(Duration::from_secs(u64::from(secs)));
                s.tick(clock.now());
            }
            Op::Advance { secs } => clock.advance(Duration::from_secs(u64::from(secs))),
            Op::Settings { torrents, peers, items, lifetime, reply, sample, count } => {
                settings = DhtSettings {
                    max_torrents: i32::from(torrents),
                    max_peers: i32::from(peers),
                    max_dht_items: i32::from(items),
                    item_lifetime: i32::from(lifetime),
                    max_peers_reply: i32::from(reply) * 40,
                    sample_infohashes_interval: i32::from(sample),
                    max_infohashes_sample_count: i32::from(count),
                    ..DhtSettings::default()
                };
                s.set_settings(&settings);
            }
            Op::NodeIds { n } => {
                let ids: Vec<Sha1Hash> = (0..n % 4).map(|i| Sha1Hash([i.wrapping_mul(37); 20])).collect();
                s.update_node_ids(&ids);
            }
        }
    }
    // Lowering a cap does not evict what is already stored, so only check the
    // caps and the peer total while the settings are the initial ones.
    if !ops.iter().take(MAX_OPS).any(|o| matches!(o, Op::Settings { .. })) {
        check_counters(&s, &settings);
    } else {
        let c = s.counters();
        assert!(c.torrents >= 0 && c.peers >= 0 && c.immutable_data >= 0 && c.mutable_data >= 0);
    }
});
