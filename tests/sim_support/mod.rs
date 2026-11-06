//! A deterministic in-memory network of [`Dht`]s: the replacement for
//! libtorrent's `libsimulator` in `simulation/test_dht.cpp` and friends
//! (RC_2_1, commit `86d573f2631b0162d3cca5e257217eaf530fdcba`).
//!
//! [`SimNet`] owns the peers, a [`ManualClock`], and a queue of datagrams in
//! flight. It moves time to the next datagram arrival or the next peer
//! timer, delivers, collects what the peers sent, and repeats. A seeded
//! [`TestRng`] draws link latencies, so a run is reproducible.

#![allow(dead_code)]

use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap};
use std::net::SocketAddr;
use std::time::Duration;

use cloudllm_dht::dht_state::DhtState;
use cloudllm_dht::node_id::{distance_exp, generate_id_impl};
use cloudllm_dht::rng::{Rng, TestRng};
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::storage::DefaultStorage;
use cloudllm_dht::testing::{rand_v4, rand_v6};
use cloudllm_dht::time::{Clock, ManualClock, Time};
use cloudllm_dht::tracker::{Datagram, Dht, SocketErrorKind, SocketId};

/// One datagram in flight.
struct InFlight {
    at: Time,
    seq: u64,
    to_peer: usize,
    to_socket: SocketId,
    from: SocketAddr,
    payload: Vec<u8>,
}

impl PartialEq for InFlight {
    fn eq(&self, o: &Self) -> bool {
        (self.at, self.seq) == (o.at, o.seq)
    }
}
impl Eq for InFlight {}
impl PartialOrd for InFlight {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for InFlight {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (self.at, self.seq).cmp(&(o.at, o.seq))
    }
}

/// A peer on the network.
pub struct SimPeer {
    /// The DHT it runs.
    pub dht: Dht,
    /// Its sockets and their addresses.
    pub addrs: Vec<(SocketId, SocketAddr)>,
}

/// The network.
pub struct SimNet {
    /// The shared simulated clock.
    pub clock: ManualClock,
    /// Everyone on the network.
    pub peers: Vec<SimPeer>,
    by_addr: HashMap<SocketAddr, (usize, SocketId)>,
    queue: BinaryHeap<Reverse<InFlight>>,
    dirty: BTreeSet<usize>,
    seq: u64,
    rng: TestRng,
    /// Datagrams delivered so far.
    pub delivered: u64,
    /// Datagrams sent to an address nobody listens on.
    pub undeliverable: u64,
    /// Probability (in 1/1000) that a datagram is lost.
    pub loss_permille: u32,
}

impl SimNet {
    /// An empty network starting at t = 1000 s (the table code treats
    /// [`Time::ZERO`] as "never").
    pub fn new(seed: u64) -> Self {
        let clock = ManualClock::new();
        clock.advance(Duration::from_secs(1000));
        Self {
            clock,
            peers: Vec::new(),
            by_addr: HashMap::new(),
            queue: BinaryHeap::new(),
            dirty: BTreeSet::new(),
            seq: 0,
            rng: TestRng::new(seed),
            delivered: 0,
            undeliverable: 0,
            loss_permille: 0,
        }
    }

    /// The current simulated time.
    pub fn now(&self) -> Time {
        self.clock.now()
    }

    /// Adds a peer that already has its sockets registered; returns its
    /// index.
    pub fn add_peer(&mut self, dht: Dht) -> usize {
        let addrs: Vec<_> = dht.sockets().collect();
        let idx = self.peers.len();
        for (id, a) in &addrs {
            self.by_addr.insert(*a, (idx, *id));
        }
        self.peers.push(SimPeer { dht, addrs });
        self.dirty.insert(idx);
        idx
    }

    /// Tells the network a peer was touched from outside (a test called one
    /// of its operations), so its output gets collected.
    pub fn poke(&mut self, peer: usize) {
        self.dirty.insert(peer);
    }

    fn collect(&mut self) {
        let dirty = std::mem::take(&mut self.dirty);
        for idx in dirty {
            while let Some(Datagram {
                socket,
                to,
                payload,
            }) = self.peers[idx].dht.poll_transmit()
            {
                let from = self.peers[idx]
                    .addrs
                    .iter()
                    .find(|(s, _)| *s == socket)
                    .map(|(_, a)| *a)
                    .expect("a datagram from a registered socket");
                if self.loss_permille > 0 && self.rng.random(999) < self.loss_permille {
                    continue;
                }
                let latency = Duration::from_millis(u64::from(20 + self.rng.random(80)));
                match self.by_addr.get(&to) {
                    Some(&(to_peer, to_socket)) => {
                        self.seq += 1;
                        self.queue.push(Reverse(InFlight {
                            at: self.clock.now() + latency,
                            seq: self.seq,
                            to_peer,
                            to_socket,
                            from,
                            payload,
                        }));
                    }
                    None => self.undeliverable += 1,
                }
            }
        }
    }

    fn next_event(&self) -> Option<Time> {
        let timer = self.peers.iter().filter_map(|p| p.dht.next_timeout()).min();
        let arrival = self.queue.peek().map(|Reverse(f)| f.at);
        [timer, arrival].into_iter().flatten().min()
    }

    /// Runs until `deadline`, or until `stop` says so after any step.
    pub fn run_until(&mut self, deadline: Time, mut stop: impl FnMut(&mut SimNet) -> bool) {
        loop {
            self.collect();
            if stop(self) {
                return;
            }
            let Some(next) = self.next_event() else {
                break;
            };
            if next > deadline {
                break;
            }
            let now = self.clock.now();
            if next > now {
                self.clock.advance(next - now);
            }
            let now = self.clock.now();
            while self.queue.peek().is_some_and(|Reverse(f)| f.at <= now) {
                let Reverse(f) = self.queue.pop().expect("peeked");
                self.delivered += 1;
                self.peers[f.to_peer]
                    .dht
                    .incoming_packet(f.to_socket, f.from, &f.payload, now);
                self.dirty.insert(f.to_peer);
            }
            for idx in 0..self.peers.len() {
                if self.peers[idx].dht.next_timeout().is_some_and(|t| t <= now) {
                    self.peers[idx].dht.poll(now);
                    self.dirty.insert(idx);
                }
            }
        }
        let now = self.clock.now();
        if deadline > now {
            self.clock.advance(deadline - now);
        }
        self.collect();
    }

    /// Runs for `d` of simulated time.
    pub fn run_for(&mut self, d: Duration) {
        let deadline = self.now() + d;
        self.run_until(deadline, |_| false);
    }

    /// Reports an unreachable endpoint to `peer` (the ICMP the OS would
    /// deliver).
    pub fn unreachable(&mut self, peer: usize, ep: SocketAddr) {
        let now = self.now();
        self.peers[peer]
            .dht
            .socket_error(SocketErrorKind::ConnectionRefused, ep, now);
        self.dirty.insert(peer);
    }
}

/// Settings of `dht_network`: dark-internet filtering and routing-table IP
/// restriction are off.
pub fn net_settings() -> DhtSettings {
    DhtSettings {
        ignore_dark_internet: false,
        restrict_routing_ips: false,
        ..DhtSettings::default()
    }
}

/// A network node of `dht_network`: one socket on port 6881 at a random
/// public address, ID `generate_id_impl(addr, 0)`, its own storage.
pub fn net_node(rng: &mut TestRng, v6: bool, clock: &ManualClock, settings: &DhtSettings) -> Dht {
    let ip = if v6 { rand_v6(rng) } else { rand_v4(rng) };
    let id = generate_id_impl(ip, 0, rng);
    let state = DhtState {
        nids: vec![(ip, id)],
        ..DhtState::default()
    };
    let storage = DefaultStorage::new(
        settings,
        Box::new(clock.clone()),
        Box::new(TestRng::new(rng.next_u32().into())),
    );
    let mut dht = Dht::builder(settings.clone())
        .state(state)
        .storage(Box::new(storage))
        .rng(Box::new(TestRng::new(rng.next_u32().into())))
        .build();
    dht.add_socket(SocketAddr::new(ip, 6881), Some(ip), clock.now());
    dht
}

/// Builds `n` network nodes and seeds each routing table with a random
/// subset of the others in proportion to the bucket it would fall into
/// (`dht_node::bootstrap` of `simulation/setup_dht.cpp`). Returns the peer
/// indices and the endpoints of the first eight, the "router nodes".
pub fn build_network(
    sim: &mut SimNet,
    n: usize,
    v6: bool,
    seed: u64,
) -> (Vec<usize>, Vec<SocketAddr>) {
    let settings = net_settings();
    let mut rng = TestRng::new(seed);
    let first = sim.peers.len();
    let mut infos = Vec::with_capacity(n);
    for _ in 0..n {
        let dht = net_node(&mut rng, v6, &sim.clock, &settings);
        let (sid, addr) = dht.sockets().next().expect("one socket");
        let nid = dht.node(sid).expect("node").nid();
        sim.add_peer(dht);
        infos.push((nid, addr));
    }
    let now = sim.now();
    for (k, info) in infos.iter().enumerate() {
        let (id, _) = *info;
        let mut left = [8usize; 160];
        left[0] = 128;
        left[1] = 64;
        left[2] = 32;
        left[3] = 16;
        let mut order: Vec<usize> = (0..infos.len()).collect();
        let (sid, _) = sim.peers[first + k].addrs[0];
        while !order.is_empty() {
            let i = rng.random(order.len() as u32 - 1) as usize;
            let (nid, ep) = infos[order[i]];
            order.swap_remove(i);
            if nid == id {
                continue;
            }
            let bucket = usize::try_from(159 - distance_exp(&id, &nid)).expect("bucket");
            if left[bucket] == 0 {
                continue;
            }
            left[bucket] -= 1;
            let rtt = (rng.random(300) + 10) as u16;
            let table = sim.peers[first + k]
                .dht
                .node_mut(sid)
                .expect("node")
                .table_mut();
            let added = table.node_seen(nid, ep, rtt, now);
            assert!(added, "seeding must add the node: bucket {bucket} left {} size {:?} depth {} me {id} other {nid} ep {ep}", left[bucket], table.size(), table.depth());
        }
    }
    let routers = infos.iter().take(8).map(|(_, a)| *a).collect();
    ((first..first + n).collect(), routers)
}
