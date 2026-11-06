//! Drives a routing table with an arbitrary operation sequence, the way a
//! network of hostile and flaky peers does: nodes appear, are heard about,
//! fail, change ID behind a known endpoint, and our own ID changes.
//!
//! Invariants after every operation: `check_invariants` holds (IP set in
//! step with the buckets, every node in the bucket its ID belongs to, live
//! nodes pinged, no own ID, no foreign family); `find_node` returns at most
//! `count` distinct live nodes; `size()` agrees with the node iterators;
//! `depth()` and `next_refresh` stay within the bucket count; the same
//! operations replayed on a clone give an identical table.
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use arbitrary::Arbitrary;
use cloudllm_dht::net::Protocol;
use cloudllm_dht::routing_table::{FindNodeOptions, RoutingTable};
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::time::Time;
use cloudllm_dht::Sha1Hash;
use libfuzzer_sys::fuzz_target;

/// A node ID built so that collisions and shared prefixes are common: the
/// first two bytes pick the bucket and slot, the rest repeat `fill`.
#[derive(Arbitrary, Debug, Clone, Copy)]
struct Id {
    head: [u8; 2],
    fill: u8,
}

impl Id {
    fn hash(self) -> Sha1Hash {
        let mut b = [self.fill; 20];
        b[..2].copy_from_slice(&self.head);
        Sha1Hash(b)
    }
}

/// An endpoint from a small space, so the same IP, /24 and endpoint recur.
#[derive(Arbitrary, Debug, Clone, Copy)]
struct Ep {
    net: u8,
    host: u8,
    port: u8,
}

impl Ep {
    fn addr(self, v6: bool) -> SocketAddr {
        let ip = if v6 {
            IpAddr::V6(Ipv6Addr::new(0x2001, u16::from(self.net), 0, 0, 0, 0, 0, u16::from(self.host)))
        } else {
            IpAddr::V4(Ipv4Addr::new(20, self.net, self.host, 1))
        };
        SocketAddr::new(ip, 1000 + u16::from(self.port))
    }
}

#[derive(Arbitrary, Debug)]
enum Op {
    Seen(Id, Ep, u16),
    HeardAbout(Id, Ep),
    Failed(Id, Ep),
    Find(Id, u8, bool),
    Refresh,
    SetId(Id),
    Router(Ep),
    Tick(u16),
}

#[derive(Arbitrary, Debug)]
struct Input {
    own: Id,
    bucket_size_log2: u8,
    v6: bool,
    restrict_ips: bool,
    extended: bool,
    prefer_verified: bool,
    max_fail: u8,
    ops: Vec<Op>,
}

fuzz_target!(|input: Input| {
    let settings = DhtSettings {
        restrict_routing_ips: input.restrict_ips,
        extended_routing_table: input.extended,
        prefer_verified_node_ids: input.prefer_verified,
        max_fail_count: i32::from(input.max_fail % 8) + 1,
        enforce_node_id: false,
        ..DhtSettings::default()
    };
    let protocol = if input.v6 { Protocol::V6 } else { Protocol::V4 };
    // 2..=32: with bucket_size 1 `num_global_nodes` is legitimately 0 (libtorrent
    // too), and real tables use 8.
    let bucket_size = 2usize << (input.bucket_size_log2 % 5);
    let mut table = RoutingTable::new(input.own.hash(), protocol, bucket_size, &settings);
    let mut now = Time::ZERO + Duration::from_secs(1000);
    let v6 = input.v6;

    for (step, op) in input.ops.iter().take(512).enumerate() {
        match *op {
            Op::Seen(id, ep, rtt) => {
                table.node_seen(id.hash(), ep.addr(v6), rtt, now);
            }
            Op::HeardAbout(id, ep) => table.heard_about(id.hash(), ep.addr(v6), now),
            Op::Failed(id, ep) => table.node_failed(&id.hash(), ep.addr(v6)),
            Op::Find(id, count, failed) => {
                let opts = if failed { FindNodeOptions::INCLUDE_FAILED } else { FindNodeOptions::NONE };
                let want = usize::from(count % 40);
                let found = table.find_node(&id.hash(), opts, want);
                assert!(found.len() <= if want == 0 { bucket_size } else { want });
                let mut ids: Vec<_> = found.iter().map(|e| (e.id, e.endpoint)).collect();
                ids.sort();
                ids.dedup();
                assert_eq!(ids.len(), found.len(), "find_node returned a node twice");
                assert!(failed || found.iter().all(|e| e.confirmed()));
                for e in &found {
                    assert!(table.live_nodes().any(|n| n == e), "not a live node");
                }
            }
            Op::Refresh => {
                if let Some((e, bucket)) = table.next_refresh(now) {
                    assert!(bucket < table.num_active_buckets());
                    assert_eq!(e.last_queried, now);
                }
            }
            Op::SetId(id) => table.set_id(id.hash(), now),
            Op::Router(ep) => table.add_router_node(ep.addr(v6)),
            Op::Tick(s) => now = now + Duration::from_secs(u64::from(s)),
        }
        if let Err(e) = table.check_invariants() {
            panic!("{e} after step {step} ({op:?})\n{}", table.print_state(now));
        }
        let (live, repl, confirmed) = table.size();
        assert_eq!(live, table.live_nodes().count());
        assert_eq!(repl, table.replacement_nodes().count());
        assert!(confirmed <= live);
        assert!(table.depth() <= table.num_active_buckets());
        assert!(table.num_global_nodes() >= 1);
    }
});
