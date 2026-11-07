//! Soak test: a long in-memory simulation of a Mainline DHT under churn and
//! sustained BEP 5 / BEP 44 traffic, checking that it keeps working and keeps
//! its state bounded.
//!
//! The network is the one of `tests/sim_support` (deterministic, seeded, in
//! simulated time): a couple of hundred nodes, each seeded with a routing
//! table. Every round of 30 simulated seconds:
//!
//! 1. **Churn.** A few percent of the online nodes go offline for a few rounds
//!    (a host switched off: it neither sends nor receives), and a few nodes
//!    leave for good and are replaced by fresh joiners with new IDs and
//!    addresses, seeded with a handful of live nodes.
//! 2. **Traffic.** Random online nodes start operations: immutable puts and gets,
//!    mutable puts (a fixed set of publishers, rising sequence numbers) and
//!    gets, announces and `get_peers`.
//! 3. **Accounting.** Every operation must end exactly once and leave nothing in
//!    flight, and its result is checked against what was acknowledged before.
//!
//! The run asserts:
//!
//! - **It keeps working.** Over the whole run, at least 90% of the immutable
//!   gets of a stored item return it; at least 90% of the mutable gets return a
//!   sequence number no lower than the highest acknowledged put; at least 95% of
//!   the puts are acknowledged by some node.
//! - **No operation leaks.** After every round no node has an operation in
//!   flight, and no operation ended twice or not at all.
//! - **State stays bounded.** Every epoch, every online node's stored items,
//!   torrents and peers are within the settings' caps and its routing table
//!   within its bucket capacity, however many items were put.
//! - **Memory stays flat** (long run only): the process's resident size at the
//!   end is within 1.5x of its level after warm-up plus 64 MiB.
//!
//! `soak_smoke` runs a small version in the normal test run so the harness
//! cannot rot. `soak_long` is `#[ignore]`d: `make soak SOAK_SECONDS=600`, or the
//! weekly `soak.yml` for an hour. The run ends when `SOAK_SECONDS` of wall
//! clock have passed, however many simulated hours that covers. Statistics are
//! printed. See docs/ENGINEERING.md, "Soak test".

mod sim_support;

use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cloudllm_dht::announce_flags::AnnounceFlags;
use cloudllm_dht::bencode::Entry;
use cloudllm_dht::ed25519::create_keypair;
use cloudllm_dht::events::{Event, OpId};
use cloudllm_dht::item::{immutable_item_target_id, Item};
use cloudllm_dht::rng::{Rng, TestRng};
use cloudllm_dht::types::{PublicKey, SecretKey, SequenceNumber};
use cloudllm_dht::Sha1Hash;
use sim_support::{build_network, net_node, net_settings, SimNet};

/// Simulated time per round.
const ROUND: Duration = Duration::from_secs(30);
/// Operations started per round.
const OPS_PER_ROUND: usize = 6;
/// Rounds between state-bound checks.
const EPOCH: usize = 10;
/// Percent of online nodes that go offline for a while each round.
const OFFLINE_PERCENT: u32 = 2;
/// Percent of nodes replaced by fresh joiners each round.
const REPLACE_PERMILLE: u32 = 5;
/// Mutable-item publishers.
const PUBLISHERS: usize = 8;
/// Resident memory may grow by this factor plus [`RSS_SLACK_KB`] over its
/// level after warm-up before the run calls it a leak.
const RSS_FACTOR: f64 = 1.5;
const RSS_SLACK_KB: u64 = 64 * 1024;

/// What an operation was started for, and what it must be judged against.
enum Pending {
    PutImmutable { target: Sha1Hash },
    GetImmutable { target: Sha1Hash },
    PutMutable { publisher: usize, seq: i64 },
    GetMutable { publisher: usize, min_seq: i64 },
    Announce,
    GetPeers,
}

/// An operation that has been started and not yet judged. A lookup that has to
/// wait out requests to offline nodes can take longer than a round, so the
/// results are gathered across rounds until the operation ends.
struct Outstanding {
    peer: usize,
    op: OpId,
    pending: Pending,
    started: u32,
    results: Vec<Event>,
    ends: u32,
}

/// Rounds an operation may take before the run calls it stuck. A lookup
/// serially timing out on offline nodes takes minutes of simulated time, not
/// hours.
const MAX_AGE_ROUNDS: u32 = 20;

/// Counters of the whole run.
#[derive(Default, Debug)]
struct Stats {
    puts: u32,
    puts_acked: u32,
    imm_gets: u32,
    imm_found: u32,
    mut_gets: u32,
    mut_fresh: u32,
    other_ops: u32,
    rounds: u32,
    went_offline: u32,
    replaced: u32,
}

/// Resident set size of this process in KiB (0 when `ps` is unavailable).
fn rss_kib() -> u64 {
    Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(0)
}

/// Everything a run needs to remember between rounds.
struct World {
    sim: SimNet,
    rng: TestRng,
    /// Rounds until each offline node returns (absent when online).
    offline_for: HashMap<usize, u32>,
    publishers: Vec<(PublicKey, SecretKey)>,
    /// Highest acknowledged sequence number per publisher.
    acked_seq: Vec<i64>,
    /// Stored immutable items: target and value, most recent last.
    stored: Vec<(Sha1Hash, Entry)>,
    next_seq: i64,
    outstanding: Vec<Outstanding>,
    stats: Stats,
}

impl World {
    fn new(nodes: usize, seed: u64) -> Self {
        let mut sim = SimNet::new(seed);
        build_network(&mut sim, nodes, false, seed + 1);
        // A tracker that was not started runs no timers, so a request to a
        // node that never answers would wait forever; real nodes are started.
        let now = sim.now();
        for i in 0..nodes {
            sim.peers[i].dht.start(now);
            sim.poke(i);
        }
        sim.run_for(Duration::from_secs(5));
        let publishers = (0..PUBLISHERS)
            .map(|i| create_keypair(&[i as u8 + 1; 32]))
            .collect();
        Self {
            sim,
            rng: TestRng::new(seed + 2),
            offline_for: HashMap::new(),
            publishers,
            acked_seq: vec![0; PUBLISHERS],
            stored: Vec::new(),
            next_seq: 1,
            outstanding: Vec::new(),
            stats: Stats::default(),
        }
    }

    fn online(&self) -> Vec<usize> {
        (0..self.sim.peers.len())
            .filter(|i| self.sim.peers[*i].online)
            .collect()
    }

    fn pick(&mut self, from: &[usize]) -> usize {
        from[self.rng.random(from.len() as u32 - 1) as usize]
    }

    /// Returning nodes come back, some online nodes go offline, a few are
    /// replaced by fresh joiners.
    fn churn(&mut self) {
        let returning: Vec<usize> = self
            .offline_for
            .iter_mut()
            .filter_map(|(i, left)| {
                *left -= 1;
                (*left == 0).then_some(*i)
            })
            .collect();
        for i in returning {
            self.offline_for.remove(&i);
            self.sim.set_online(i, true);
        }
        let online = self.online();
        for &i in &online {
            if self.rng.random(99) < OFFLINE_PERCENT {
                self.sim.set_online(i, false);
                self.offline_for.insert(i, 1 + self.rng.random(4));
                self.stats.went_offline += 1;
            } else if self.rng.random(999) < REPLACE_PERMILLE
                && !self.outstanding.iter().any(|o| o.peer == i)
            {
                self.replace(i);
            }
        }
    }

    /// A fresh node takes over slot `i`, knowing a handful of live nodes.
    fn replace(&mut self, i: usize) {
        let settings = net_settings();
        let dht = net_node(&mut self.rng, false, &self.sim.clock, &settings);
        self.sim.replace_peer(i, dht);
        let now = self.sim.now();
        self.sim.peers[i].dht.start(now);
        self.offline_for.remove(&i);
        let live: Vec<usize> = self.online().into_iter().filter(|&p| p != i).collect();
        let now = self.sim.now();
        let (sid, _) = self.sim.peers[i].addrs[0];
        for _ in 0..16 {
            let j = self.pick(&live);
            let (jsid, jaddr) = self.sim.peers[j].addrs[0];
            let nid = self.sim.peers[j].dht.node(jsid).expect("node").nid();
            self.sim.peers[i]
                .dht
                .node_mut(sid)
                .expect("node")
                .table_mut()
                .node_seen(nid, jaddr, 50, now);
        }
        self.stats.replaced += 1;
    }

    /// Starts one operation at a random online node.
    fn start_op(&mut self) {
        let online = self.online();
        let me = self.pick(&online);
        let now = self.sim.now();
        let roll = self.rng.random(99);
        let (op, pending) = match roll {
            0..=24 => {
                let value = Entry::from(format!("immutable {}", self.rng.next_u32()));
                let target = immutable_item_target_id(&value.encode());
                self.stored.push((target, value.clone()));
                // Only the newest are read back, so an hour-long run does not
                // grow the test's own memory.
                if self.stored.len() > 200 {
                    self.stored.drain(..self.stored.len() - 200);
                }
                (
                    self.sim.peers[me].dht.put_immutable_item(value, now),
                    Pending::PutImmutable { target },
                )
            }
            25..=49 if !self.stored.is_empty() => {
                let from = self.stored.len().saturating_sub(40);
                let k = from + self.rng.random((self.stored.len() - from) as u32 - 1) as usize;
                let target = self.stored[k].0;
                (
                    self.sim.peers[me].dht.get_immutable_item(target, now),
                    Pending::GetImmutable { target },
                )
            }
            50..=64 => {
                let publisher = self.rng.random(PUBLISHERS as u32 - 1) as usize;
                let (pk, sk) = self.publishers[publisher];
                let seq = self.next_seq;
                self.next_seq += 1;
                let cb = Arc::new(move |item: &mut Item| {
                    *item = Item::signed(
                        Entry::from(format!("mutable {seq}")),
                        b"",
                        SequenceNumber(seq),
                        &pk,
                        &sk,
                    )
                    .expect("a small item");
                });
                (
                    self.sim.peers[me].dht.put_mutable_item(pk, b"", cb, now),
                    Pending::PutMutable { publisher, seq },
                )
            }
            65..=84 => {
                let publisher = self.rng.random(PUBLISHERS as u32 - 1) as usize;
                let (pk, _) = self.publishers[publisher];
                let min_seq = self.acked_seq[publisher];
                (
                    self.sim.peers[me].dht.get_mutable_item(pk, b"", now),
                    Pending::GetMutable { publisher, min_seq },
                )
            }
            85..=92 => {
                let ih = Sha1Hash::of(&self.rng.random(63).to_le_bytes());
                (
                    self.sim.peers[me]
                        .dht
                        .announce(ih, 6881, AnnounceFlags::EMPTY, now),
                    Pending::Announce,
                )
            }
            _ => {
                let ih = Sha1Hash::of(&self.rng.random(63).to_le_bytes());
                (self.sim.peers[me].dht.get_peers(ih, now), Pending::GetPeers)
            }
        };
        self.sim.poke(me);
        self.outstanding.push(Outstanding {
            peer: me,
            op,
            pending,
            started: self.stats.rounds,
            results: Vec::new(),
            ends: 0,
        });
    }

    /// One round: churn, traffic, simulated time, and the accounting.
    fn round(&mut self, with_traffic: bool) {
        if with_traffic {
            self.churn();
            for _ in 0..OPS_PER_ROUND {
                self.start_op();
            }
        }
        self.sim.run_for(ROUND);
        self.collect_events();
        self.stats.rounds += 1;
        self.judge_finished();
        for (i, p) in self.sim.peers.iter().enumerate() {
            let mine = self.outstanding.iter().filter(|o| o.peer == i).count();
            assert!(
                p.dht.operations_in_flight() <= mine,
                "node {i} has {} operations in flight but only {mine} outstanding",
                p.dht.operations_in_flight()
            );
        }
    }

    /// Takes every node's events (so queues cannot grow) and files the ones
    /// of outstanding operations.
    fn collect_events(&mut self) {
        for i in 0..self.sim.peers.len() {
            for event in self.sim.peers[i].dht.drain_events() {
                let (op, ended) = match &event {
                    Event::Operation { op, .. } => (*op, false),
                    Event::OperationDone { op } | Event::OperationCancelled { op } => (*op, true),
                    _ => continue,
                };
                let Some(o) = self
                    .outstanding
                    .iter_mut()
                    .find(|o| o.peer == i && o.op == op)
                else {
                    panic!("node {i} reported an event for operation {op:?} that is not outstanding: {event:?}");
                };
                if ended {
                    o.ends += 1;
                } else {
                    o.results.push(event);
                }
            }
        }
    }

    /// Judges the operations that ended and fails the ones that did not in
    /// time.
    fn judge_finished(&mut self) {
        let round = self.stats.rounds;
        let (ended, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.outstanding)
            .into_iter()
            .partition(|o| o.ends > 0);
        for o in &rest {
            assert!(
                round - o.started <= MAX_AGE_ROUNDS,
                "operation {:?} of node {} did not end in {MAX_AGE_ROUNDS} rounds",
                o.op,
                o.peer
            );
        }
        self.outstanding = rest;
        for o in ended {
            assert_eq!(
                o.ends, 1,
                "operation {:?} of node {} ended {} times",
                o.op, o.peer, o.ends
            );
            self.judge(&o);
        }
    }

    /// Stops the traffic and runs until every operation has ended; nothing may
    /// be left in flight anywhere.
    fn finish(&mut self) {
        for i in self.offline_for.keys().copied().collect::<Vec<_>>() {
            self.sim.set_online(i, true);
        }
        self.offline_for.clear();
        for _ in 0..=MAX_AGE_ROUNDS {
            if self.outstanding.is_empty() {
                break;
            }
            self.round(false);
        }
        assert!(self.outstanding.is_empty(), "operations never ended");
        for (i, p) in self.sim.peers.iter().enumerate() {
            assert_eq!(
                p.dht.operations_in_flight(),
                0,
                "node {i} leaked an operation"
            );
        }
    }

    fn judge(&mut self, o: &Outstanding) {
        let results: Vec<&Event> = o
            .results
            .iter()
            .filter_map(|e| match e {
                Event::Operation { result, .. } => Some(&**result),
                _ => None,
            })
            .collect();
        match &o.pending {
            Pending::PutImmutable { target } => {
                self.stats.puts += 1;
                self.stats.puts_acked += u32::from(results.iter().any(|r| {
                    matches!(r, Event::PutDone { responses, target: t, .. }
                        if *responses > 0 && t == target)
                }));
            }
            &Pending::PutMutable { publisher, seq } => {
                self.stats.puts += 1;
                let acked = results
                    .iter()
                    .any(|r| matches!(r, Event::PutDone { responses, .. } if *responses > 0));
                self.stats.puts_acked += u32::from(acked);
                if acked {
                    self.acked_seq[publisher] = self.acked_seq[publisher].max(seq);
                }
            }
            &Pending::GetImmutable { target } => {
                self.stats.imm_gets += 1;
                let value = &self
                    .stored
                    .iter()
                    .find(|(t, _)| *t == target)
                    .expect("known")
                    .1;
                self.stats.imm_found += u32::from(results.iter().any(
                    |r| matches!(r, Event::GetItemDone { item, .. } if item.value() == value),
                ));
            }
            &Pending::GetMutable { publisher, min_seq } => {
                if min_seq == 0 {
                    return; // nothing was acknowledged yet, so nothing is owed
                }
                self.stats.mut_gets += 1;
                let (pk, _) = self.publishers[publisher];
                let best = results
                    .iter()
                    .filter_map(|r| match r {
                        Event::GetItemDone { item, .. } if item.pk() == &pk => Some(item.seq().0),
                        _ => None,
                    })
                    .max()
                    .unwrap_or(0);
                self.stats.mut_fresh += u32::from(best >= min_seq);
            }
            Pending::Announce | Pending::GetPeers => self.stats.other_ops += 1,
        }
    }

    /// Stored items, torrents, peers and routing tables of every online node
    /// are within their caps.
    fn assert_state_bounded(&self) {
        let settings = net_settings();
        let cap = |n: i32| usize::try_from(n).expect("a positive cap");
        for (i, p) in self.sim.peers.iter().enumerate().filter(|(_, p)| p.online) {
            let c = p.dht.storage().counters();
            assert!(
                c.immutable_data >= 0 && c.immutable_data <= settings.max_dht_items,
                "node {i}: {} immutable items, cap {}",
                c.immutable_data,
                settings.max_dht_items
            );
            assert!(
                c.mutable_data >= 0 && c.mutable_data <= settings.max_dht_items,
                "node {i}: {} mutable items, cap {}",
                c.mutable_data,
                settings.max_dht_items
            );
            assert!(
                c.torrents >= 0 && c.torrents <= settings.max_torrents,
                "node {i}: {} torrents",
                c.torrents
            );
            assert!(
                c.peers >= 0
                    && cap(c.peers) <= cap(settings.max_peers) * cap(settings.max_torrents),
                "node {i}: {} peers",
                c.peers
            );
            let (sid, _) = p.addrs[0];
            let table = p.dht.node(sid).expect("node").table();
            let (live, replacements, _) = table.size();
            let capacity = table.bucket_size() * 160;
            assert!(
                live <= capacity,
                "node {i}: {live} live table entries, capacity {capacity}"
            );
            assert!(
                replacements <= capacity,
                "node {i}: {replacements} replacement entries, capacity {capacity}"
            );
        }
    }
}

/// The scenario: rounds until `rounds` have run or `wall` has passed.
fn run_soak(nodes: usize, rounds: usize, wall: Duration, check_memory: bool) {
    let started = Instant::now();
    let mut world = World::new(nodes, 20_261_106);
    let mut warm_rss = 0;
    let mut round = 0;
    while round < rounds && started.elapsed() < wall {
        world.round(true);
        round += 1;
        if round % EPOCH == 0 {
            world.assert_state_bounded();
            let rss = rss_kib();
            if round == EPOCH * 3 {
                warm_rss = rss;
            }
            if round % (EPOCH * 50) == 0 || round == EPOCH {
                println!(
                "soak: round {round:5}  simulated {:6.1} h  rss {rss:7} KiB  wall {:5.0} s  {:?}",
                f64::from(world.stats.rounds) * ROUND.as_secs_f64() / 3600.0,
                started.elapsed().as_secs_f64(),
                world.stats
            );
            }
        }
    }
    world.finish();
    world.assert_state_bounded();
    let s = &world.stats;
    println!("soak: finished {s:?}");

    assert!(s.puts > 0 && s.imm_gets > 0, "the run did nothing: {s:?}");
    let rate = |hit: u32, of: u32| f64::from(hit) / f64::from(of.max(1));
    assert!(
        rate(s.puts_acked, s.puts) >= 0.95,
        "puts acknowledged: {s:?}"
    );
    assert!(
        rate(s.imm_found, s.imm_gets) >= 0.90,
        "immutable gets found: {s:?}"
    );
    assert!(
        rate(s.mut_fresh, s.mut_gets) >= 0.90,
        "mutable gets fresh: {s:?}"
    );
    if check_memory {
        let end = rss_kib();
        let allowed = (warm_rss as f64 * RSS_FACTOR) as u64 + RSS_SLACK_KB;
        assert!(
            warm_rss > 0 && end <= allowed,
            "resident memory grew from {warm_rss} KiB (after warm-up) to {end} KiB (allowed {allowed})"
        );
    }
}

/// A small, fast version in the ordinary test run: 60 nodes, 20 rounds (ten
/// simulated minutes) with churn and traffic; delivery, operation accounting
/// and state bounds, but no memory judgement.
#[test]
fn soak_smoke() {
    run_soak(60, 20, Duration::from_secs(120), false);
}

/// The long run, for `make soak` and the weekly workflow: 200 nodes until
/// `SOAK_SECONDS` (default 600) of wall clock have passed. `#[ignore]` keeps it
/// out of `cargo test`.
#[test]
#[ignore = "long-running; run with `make soak`"]
fn soak_long() {
    let seconds: u64 = std::env::var("SOAK_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600);
    assert!(
        seconds >= 60,
        "SOAK_SECONDS must be at least 60 to judge growth"
    );
    run_soak(200, usize::MAX, Duration::from_secs(seconds), true);
}
