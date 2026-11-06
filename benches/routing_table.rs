//! Benchmarks of the routing table's hot paths: answering `find_node`
//! (every incoming query and every traversal step), inserting nodes
//! (`node_seen` on every reply) and `classify_prefix`.
//!
//! Run with `cargo bench --bench routing_table`; add `-- --save-baseline x`
//! to keep a baseline and `-- --baseline x` to compare.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use cloudllm_dht::net::Protocol;
use cloudllm_dht::node_id::{generate_id_impl, generate_random_id};
use cloudllm_dht::rng::{Rng, TestRng};
use cloudllm_dht::routing_table::{classify_prefix, FindNodeOptions, RoutingTable};
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::time::Time;
use cloudllm_dht::Sha1Hash;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

/// `n` distinct (ID, endpoint) pairs with BEP 42 valid IDs.
fn contacts(rng: &mut TestRng, n: usize) -> Vec<(Sha1Hash, SocketAddr)> {
    (0..n)
        .map(|i| {
            let ip = IpAddr::V4(Ipv4Addr::from(rng.next_u32() | 0x0100_0000));
            let id = generate_id_impl(ip, rng.next_u32(), rng);
            (id, SocketAddr::new(ip, 1024 + (i % 60_000) as u16))
        })
        .collect()
}

fn now() -> Time {
    Time::ZERO + Duration::from_secs(1000)
}

fn filled_table(rng: &mut TestRng, nodes: usize) -> RoutingTable {
    let mut table = RoutingTable::new(
        generate_random_id(rng),
        Protocol::V4,
        8,
        &DhtSettings::default(),
    );
    for (id, ep) in contacts(rng, nodes) {
        table.node_seen(id, ep, 40, now());
    }
    table
}

fn bench_find_node(c: &mut Criterion) {
    let mut rng = TestRng::new(1);
    let table = filled_table(&mut rng, 20_000);
    let targets: Vec<Sha1Hash> = (0..1024).map(|_| generate_random_id(&mut rng)).collect();
    let mut i = 0;
    c.bench_function("find_node/8_of_full_table", |b| {
        b.iter(|| {
            i = (i + 1) % targets.len();
            black_box(table.find_node(black_box(&targets[i]), FindNodeOptions::NONE, 8))
        });
    });
}

fn bench_node_seen(c: &mut Criterion) {
    let mut rng = TestRng::new(2);
    let seed_table = filled_table(&mut rng, 5_000);
    let fresh = contacts(&mut rng, 4096);
    // Mostly rejected or cached nodes: the steady state of a full table.
    c.bench_function("node_seen/into_populated_table", |b| {
        b.iter_batched(
            || seed_table.clone(),
            |mut t| {
                for (id, ep) in &fresh[..64] {
                    black_box(t.node_seen(*id, *ep, 35, now()));
                }
                t
            },
            BatchSize::LargeInput,
        );
    });
    let known: Vec<_> = seed_table
        .live_nodes()
        .map(|e| (e.id, e.endpoint))
        .collect();
    let mut t = seed_table;
    let mut i = 0;
    c.bench_function("node_seen/refresh_known_node", |b| {
        b.iter(|| {
            i = (i + 1) % known.len();
            let (id, ep) = known[i];
            black_box(t.node_seen(id, ep, 35, now()))
        });
    });
}

fn bench_classify_prefix(c: &mut Criterion) {
    let mut rng = TestRng::new(3);
    let ids: Vec<Sha1Hash> = (0..256).map(|_| generate_random_id(&mut rng)).collect();
    c.bench_function("classify_prefix", |b| {
        b.iter(|| {
            ids.iter()
                .map(|id| u32::from(classify_prefix(black_box(5), false, 8, id)))
                .sum::<u32>()
        });
    });
}

criterion_group!(
    benches,
    bench_find_node,
    bench_node_seen,
    bench_classify_prefix
);
criterion_main!(benches);
