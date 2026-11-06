//! Fuzzes what every traversal does with an untrusted response: the
//! `get_peers`, obfuscated `get_peers`, bootstrap, `get`, `put`,
//! `sample_infohashes` and direct-request observers all parse
//! attacker-controlled bytes (libtorrent's `dht_*_reply.cpp` fuzzers).
//!
//! The first byte picks the traversal and whether the response carries a
//! valid node ID; the rest is bencoded and used as the `r` dictionary of a
//! response to every request the traversal sends, for a few rounds.
//!
//! Invariants: no panic; after every request has timed out no traversal,
//! observer or transaction is left (nothing leaks, whatever the replies).
#![no_main]

use std::net::SocketAddr;
use std::time::Duration;

use cloudllm_dht::bencode::{decode, Entry};
use cloudllm_dht::ctx::{NodeCtx, TableOps};
use cloudllm_dht::net::Protocol;
use cloudllm_dht::node_id::IdSecret;
use cloudllm_dht::rng::TestRng;
use cloudllm_dht::rpc_manager::RpcManager;
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::testing::{test_keypair, MockSocket};
use cloudllm_dht::time::Time;
use cloudllm_dht::traversal::direct_request::direct_request;
use cloudllm_dht::traversal::get_item::{get_immutable, get_mutable};
use cloudllm_dht::traversal::get_peers::{announce, get_peers};
use cloudllm_dht::traversal::put_data::put_mutable;
use cloudllm_dht::traversal::refresh::bootstrap;
use cloudllm_dht::traversal::sample_infohashes::sample_infohashes;
use cloudllm_dht::traversal::Traversals;
use cloudllm_dht::announce_flags::AnnounceFlags;
use cloudllm_dht::Sha1Hash;
use libfuzzer_sys::fuzz_target;

struct Table(Vec<(Sha1Hash, SocketAddr)>);

impl TableOps for Table {
    fn bucket_size(&self) -> usize {
        8
    }
    fn heard_about(&mut self, _: Sha1Hash, _: SocketAddr, _: Time) {}
    fn node_failed(&mut self, _: Sha1Hash, _: SocketAddr) {}
    fn node_seen(&mut self, _: Sha1Hash, _: SocketAddr, _: u16, _: Time) -> bool {
        false
    }
    fn closest_including_failed(&self, _: &Sha1Hash) -> Vec<(Sha1Hash, SocketAddr)> {
        self.0.clone()
    }
    fn router_nodes(&self) -> Vec<SocketAddr> {
        Vec::new()
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else { return };
    let Ok(body) = decode(body) else { return };
    let r_body = Entry::from_node(&body);
    if !matches!(r_body, Entry::Dict(_)) {
        return;
    }

    let id = Sha1Hash([0x11; 20]);
    let settings = DhtSettings {
        privacy_lookups: sel & 0x40 != 0,
        ..DhtSettings::default()
    };
    let seeds: Vec<(Sha1Hash, SocketAddr)> = (1..=3u8)
        .map(|i| (Sha1Hash([i; 20]), SocketAddr::from(([20 + i, 0, 0, 1], 6881))))
        .collect();
    let mut table = Table(seeds.clone());
    let mut rpc = RpcManager::new(id);
    let mut sock = MockSocket::new();
    let mut rng = TestRng::new(1);
    let mut events = Vec::new();
    let mut traversals = Traversals::new();
    let mut now = Time::ZERO;
    let (pk, sk) = test_keypair();
    let ep = seeds[0].1;

    macro_rules! ctx {
        () => {
            NodeCtx::new(
                now, id, Protocol::V4, &settings, &mut table, &mut rpc, &mut sock, &mut rng,
                &mut events, IdSecret::from_value(7),
            )
        };
    }

    {
        let mut ctx = ctx!();
        let t = match sel % 9 {
            0 => get_peers(&mut ctx, Sha1Hash([9; 20]), AnnounceFlags::EMPTY),
            1 => announce(&mut ctx, Sha1Hash([9; 20]), 6881, AnnounceFlags::SEED),
            2 => bootstrap(&mut ctx, &[ep], true),
            3 => get_immutable(&mut ctx, Sha1Hash([9; 20])),
            4 => get_mutable(&mut ctx, pk, b"salt"),
            5 => put_mutable(
                &mut ctx,
                pk,
                b"",
                Box::new(move |i| {
                    if let Ok(n) = cloudllm_dht::item::Item::signed(
                        Entry::from("v"),
                        b"",
                        i.seq().next(),
                        &pk,
                        &sk,
                    ) {
                        *i = n;
                    }
                }),
            ),
            6 => sample_infohashes(&mut ctx, ep, Sha1Hash([9; 20])),
            7 => {
                let mut q = Entry::dict();
                q.set("q", "x");
                direct_request(&mut ctx, ep, q, 1)
            }
            _ => bootstrap(&mut ctx, &[], false),
        };
        traversals.spawn(&mut ctx, t);
    }

    for _ in 0..4 {
        let packets = std::mem::take(&mut sock.sent);
        if packets.is_empty() {
            break;
        }
        for (to, p) in packets {
            let Some(t) = p.get("t").and_then(Entry::as_bytes) else { continue };
            let mut r = r_body.clone();
            if sel & 0x80 != 0 {
                r.set("id", vec![0x22u8; 20]);
            }
            let mut e = Entry::dict();
            e.set("y", "r").set("t", t.to_vec()).set("r", r);
            let bytes = e.encode();
            let Ok(n) = decode(&bytes) else { continue };
            let mut ctx = ctx!();
            traversals.incoming(&mut ctx, to, &n);
        }
    }

    // everything still outstanding times out
    now = now + Duration::from_secs(60);
    for _ in 0..3 {
        let mut ctx = ctx!();
        traversals.tick(&mut ctx);
        now = now + Duration::from_secs(20);
    }
    let _ = std::mem::take(&mut sock.sent);
    assert_eq!(rpc.num_transactions(), 0, "transactions leaked");
    assert_eq!(rpc.num_allocated_observers(), 0, "observers leaked");
    assert!(traversals.is_empty(), "traversals leaked");
});
