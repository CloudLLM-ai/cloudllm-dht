//! Fuzzes `Dht` as its callers drive it: an arbitrary interleaving of
//! operations (BEP 44 gets and puts, peer lookups, announces), datagram
//! deliveries from a small simulated peer set (delivered late, dropped,
//! duplicated or replaced by raw bytes), unreachable-endpoint reports and
//! clock advances, followed by a drain and a shutdown.
//!
//! Covers every operation kind (BEP 44 gets and puts, peer lookups,
//! announces, bootstrap, samples, direct requests).
//!
//! Invariants: no panic; the output queues stay bounded; every operation
//! that was started ends exactly once (`OperationDone`, or
//! `OperationCancelled` at shutdown), no operation is tagged after it ended,
//! and `operations_in_flight` is zero at the end.
#![no_main]

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cloudllm_dht::announce_flags::AnnounceFlags;
use cloudllm_dht::bencode::Entry;
use cloudllm_dht::dht_state::DhtState;
use cloudllm_dht::ed25519::create_keypair;
use cloudllm_dht::events::OpId;
use cloudllm_dht::item::Item;
use cloudllm_dht::rng::TestRng;
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::time::Time;
use cloudllm_dht::tracker::{Datagram, Dht, SocketErrorKind, SocketId};
use cloudllm_dht::types::SequenceNumber;
use cloudllm_dht::Sha1Hash;
use libfuzzer_sys::fuzz_target;

const PEERS: usize = 3;
const MAX_QUEUE: usize = 20_000;

struct Net {
    dut: Dht,
    dut_sock: SocketId,
    dut_addr: SocketAddr,
    peers: Vec<(Dht, SocketId, SocketAddr)>,
    /// Datagrams in flight: (destination index, source, payload); the DUT is
    /// destination `PEERS`.
    flight: VecDeque<(usize, SocketAddr, Vec<u8>)>,
    now: Time,
    /// Per operation: how many terminal events it has seen.
    ended: BTreeMap<OpId, u32>,
}

fn settings() -> DhtSettings {
    DhtSettings {
        ignore_dark_internet: false,
        restrict_routing_ips: false,
        ..DhtSettings::default()
    }
}

impl Net {
    fn new(seed: u8) -> Self {
        let now = Time::ZERO + Duration::from_secs(1000);
        let mut peers = Vec::new();
        for i in 0..PEERS {
            let addr: SocketAddr = format!("20.0.{}.1:6881", i + 1).parse().unwrap();
            let mut d = Dht::builder(settings())
                .rng(Box::new(TestRng::new(u64::from(seed) + i as u64 + 100)))
                .build();
            let s = d.add_socket(addr, Some(addr.ip()), now);
            peers.push((d, s, addr));
        }
        let state = DhtState {
            nodes: peers.iter().map(|p| p.2).collect(),
            ..DhtState::default()
        };
        let dut_addr: SocketAddr = "30.0.0.1:6881".parse().unwrap();
        let mut dut = Dht::builder(settings())
            .state(state)
            .rng(Box::new(TestRng::new(u64::from(seed))))
            .build();
        let dut_sock = dut.add_socket(dut_addr, Some(dut_addr.ip()), now);
        dut.start(now);
        let mut n = Self {
            dut,
            dut_sock,
            dut_addr,
            peers,
            flight: VecDeque::new(),
            now,
            ended: BTreeMap::new(),
        };
        n.collect();
        n
    }

    fn dest_of(&self, to: SocketAddr) -> Option<usize> {
        if to == self.dut_addr {
            return Some(PEERS);
        }
        self.peers.iter().position(|p| p.2 == to)
    }

    fn note_events(&mut self) {
        for ev in self.dut.drain_events() {
            let Some(op) = ev.op() else { continue };
            let count = self.ended.entry(op).or_default();
            assert_eq!(*count, 0, "event for {op:?} after it ended: {ev:?}");
            if ev.ends_operation() {
                *count += 1;
            }
        }
    }

    /// Moves everything the nodes produced into the flight queue.
    fn collect(&mut self) {
        while let Some(Datagram { to, payload, .. }) = self.dut.poll_transmit() {
            if let Some(d) = self.dest_of(to) {
                self.flight.push_back((d, self.dut_addr, payload));
            }
        }
        for i in 0..self.peers.len() {
            while let Some(Datagram { to, payload, .. }) = self.peers[i].0.poll_transmit() {
                if let Some(d) = self.dest_of(to) {
                    let from = self.peers[i].2;
                    self.flight.push_back((d, from, payload));
                }
            }
        }
        self.flight.truncate(MAX_QUEUE);
        self.note_events();
    }

    fn deliver(&mut self, idx: usize, drop_it: bool, dup: bool) {
        if self.flight.is_empty() {
            return;
        }
        let k = idx % self.flight.len();
        let Some((to, from, payload)) = self.flight.remove(k) else {
            return;
        };
        if drop_it {
            return;
        }
        for _ in 0..=usize::from(dup) {
            if to == PEERS {
                self.dut.incoming_packet(self.dut_sock, from, &payload, self.now);
            } else {
                let (d, s, _) = &mut self.peers[to];
                d.incoming_packet(*s, from, &payload, self.now);
            }
        }
        self.collect();
    }

    fn advance(&mut self, ms: u64) {
        self.now = self.now + Duration::from_millis(ms);
        self.dut.poll(self.now);
        self.collect();
    }
}

fn item_cb(key: u8, text: u8) -> Arc<dyn Fn(&mut Item) + Send + Sync> {
    let (pk, sk) = create_keypair(&[key; 32]);
    Arc::new(move |i: &mut Item| {
        let seq = SequenceNumber(i.seq().0.max(0).saturating_add(1));
        if let Ok(new) = Item::signed(Entry::from(vec![text]), b"", seq, &pk, &sk) {
            *i = new;
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&seed, ops)) = data.split_first() else {
        return;
    };
    let mut net = Net::new(seed);
    let mut started: Vec<OpId> = Vec::new();
    let mut i = 0;
    let mut next = |i: &mut usize| {
        let b = ops.get(*i).copied();
        *i += 1;
        b
    };
    while let Some(op) = next(&mut i) {
        let arg = next(&mut i).unwrap_or(0);
        let now = net.now;
        match op % 15 {
            0 => started.push(net.dut.get_immutable_item(Sha1Hash([arg % 4; 20]), now)),
            1 => {
                let (pk, _) = create_keypair(&[arg % 3; 32]);
                started.push(net.dut.get_mutable_item(pk, b"", now));
            }
            2 => started.push(
                net.dut
                    .put_immutable_item(Entry::from(vec![arg % 4]), now),
            ),
            3 => {
                let (pk, _) = create_keypair(&[arg % 3; 32]);
                started.push(net.dut.put_mutable_item(pk, b"", item_cb(arg % 3, arg), now));
            }
            4 => started.push(net.dut.get_peers(Sha1Hash([arg % 4; 20]), now)),
            5 => started.push(net.dut.announce(
                Sha1Hash([arg % 4; 20]),
                6881,
                AnnounceFlags::EMPTY,
                now,
            )),
            6 | 7 => net.deliver(usize::from(arg), arg & 0x80 != 0 && op % 15 == 7, arg & 0x40 != 0),
            8 => net.advance(u64::from(arg) * 20),
            9 => {
                let from = net.peers[usize::from(arg) % PEERS].2;
                net.dut.socket_error(SocketErrorKind::ConnectionRefused, from, now);
                net.collect();
            }
            10 => {
                // raw bytes from a known peer
                let end = (i + usize::from(arg)).min(ops.len());
                let raw = ops[i.min(end)..end].to_vec();
                i = end;
                let from = net.peers[usize::from(arg) % PEERS].2;
                net.dut.incoming_packet(net.dut_sock, from, &raw, now);
                net.collect();
            }
            11 => {
                net.dut.poll(now);
                net.collect();
            }
            12 => {
                let seeds: Vec<SocketAddr> = net.peers.iter().map(|p| p.2).collect();
                started.push(net.dut.bootstrap(&seeds, now));
            }
            13 => {
                let ep = net.peers[usize::from(arg) % PEERS].2;
                started.push(net.dut.sample_infohashes(ep, Sha1Hash([arg; 20]), now));
            }
            _ => {
                let ep = net.peers[usize::from(arg) % PEERS].2;
                let mut req = Entry::dict();
                req.set("q", "ping");
                started.push(net.dut.direct_request(ep, req, now));
            }
        }
        assert!(net.flight.len() <= MAX_QUEUE);
    }
    // Drain: deliver everything and let timeouts run. Every step is
    // counted so a drain that does not terminate fails with a message
    // instead of hanging the fuzzer.
    const MAX_DELIVERIES: usize = 300_000;
    const MAX_ROUNDS: usize = 600;
    let mut deliveries = 0usize;
    let mut rounds = 0usize;
    loop {
        while !net.flight.is_empty() {
            net.deliver(0, false, false);
            deliveries += 1;
            assert!(
                deliveries <= MAX_DELIVERIES,
                "drain did not terminate: {deliveries} deliveries, {} in flight, {} operations running",
                net.flight.len(),
                net.dut.operations_in_flight()
            );
        }
        if net.dut.operations_in_flight() == 0 {
            break;
        }
        net.advance(5_000);
        rounds += 1;
        assert!(
            rounds <= MAX_ROUNDS,
            "{} operations still running after {rounds} clock steps ({} s) with no traffic",
            net.dut.operations_in_flight(),
            rounds * 5
        );
    }
    net.dut.shutdown(net.now);
    net.collect();
    for op in started {
        assert_eq!(net.ended.get(&op).copied(), Some(1), "{op:?} did not end exactly once");
    }
    assert_eq!(net.dut.operations_in_flight(), 0);
});
