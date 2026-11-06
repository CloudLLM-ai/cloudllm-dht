//! Simulation tests ported from libtorrent RC_2_1 `simulation/test_dht.cpp`,
//! `simulation/test_dht_rate_limit.cpp` and `simulation/test_dht_bootstrap.cpp`
//! (commit `86d573f2631b0162d3cca5e257217eaf530fdcba`) onto the in-memory
//! network of `tests/sim_support`.

mod sim_support;

use std::net::SocketAddr;
use std::time::Duration;

use cloudllm_dht::announce_flags::AnnounceFlags;
use cloudllm_dht::bencode::decode;
use cloudllm_dht::dht_state::DhtState;
use cloudllm_dht::events::Event;
use cloudllm_dht::rng::{Rng, TestRng};
use cloudllm_dht::testing::{ep, rand_v4, rand_v6};
use cloudllm_dht::time::Time;
use cloudllm_dht::tracker::{Dht, SocketId};
use cloudllm_dht::Sha1Hash;
use sim_support::{build_network, net_settings, SimNet};

/// The session under test of the `setup_swarm` tests: a dual-stack tracker
/// whose state names eight router nodes of each network, started at `now`.
fn session(
    sim: &mut SimNet,
    routers4: &[SocketAddr],
    routers6: &[SocketAddr],
    seed: u64,
) -> (usize, Vec<SocketId>) {
    let mut rng = TestRng::new(seed);
    let ip4 = rand_v4(&mut rng);
    let ip6 = rand_v6(&mut rng);
    let state = DhtState {
        nodes: routers4.to_vec(),
        nodes6: routers6.to_vec(),
        ..DhtState::default()
    };
    let storage = cloudllm_dht::storage::DefaultStorage::new(
        &net_settings(),
        Box::new(sim.clock.clone()),
        Box::new(TestRng::new(seed + 1)),
    );
    let mut dht = Dht::builder(net_settings())
        .state(state)
        .storage(Box::new(storage))
        .rng(Box::new(TestRng::new(seed + 2)))
        .build();
    let now = sim.now();
    let mut sockets = Vec::new();
    if !routers4.is_empty() {
        sockets.push(dht.add_socket(SocketAddr::new(ip4, 6881), Some(ip4), now));
    }
    if !routers6.is_empty() {
        sockets.push(dht.add_socket(SocketAddr::new(ip6, 6881), Some(ip6), now));
    }
    dht.start(now);
    (sim.add_peer(dht), sockets)
}

/// Ports `TEST_CASE(dht_bootstrap)` of `simulation/test_dht.cpp`: a node
/// that knows eight routers of a 3000-node network builds a routing table at
/// least eight buckets deep holding at least 50 nodes within 500 seconds.
///
/// libtorrent's session also has a torrent whose peer searches keep the
/// DHT busy; here a `get_peers` for a fresh random hash every second
/// plays that role.
#[test]
fn test_sim_dht_bootstrap() {
    let mut sim = SimNet::new(1);
    let (_, routers) = build_network(&mut sim, 3000, false, 11);
    let (me, _) = session(&mut sim, &routers, &[], 100);
    let mut rng = TestRng::new(5);
    let mut depth = 0;
    let mut nodes = 0;
    for _ in 0..500 {
        let now = sim.now();
        sim.peers[me].dht.get_peers(rng.random_hash(), now);
        sim.poke(me);
        sim.run_for(Duration::from_secs(1));
        let now = sim.now();
        for (_, st) in sim.peers[me].dht.status(now) {
            depth = depth.max(st.table.len());
            nodes = nodes.max(
                st.table
                    .iter()
                    .map(|b| b.num_nodes + b.num_replacements)
                    .sum::<usize>(),
            );
        }
    }
    assert!(depth >= 8, "routing table depth {depth}");
    assert!(nodes >= 50, "routing table nodes {nodes}");
}

/// Ports `TEST_CASE(dht_dual_stack_get_peers)`: announce from the dual-stack
/// session, then look the hash up; peers of both families come back.
///
/// The announcing node is the session itself, so the peers returned are its
/// own two listen endpoints, one per family.
#[test]
fn test_sim_dht_dual_stack_get_peers() {
    let mut sim = SimNet::new(2);
    let (_, routers4) = build_network(&mut sim, 100, false, 21);
    let (_, routers6) = build_network(&mut sim, 100, true, 22);
    let (me, _) = session(&mut sim, &routers4, &routers6, 200);
    let ih = Sha1Hash(*b"01234567890123456789");
    sim.run_for(Duration::from_secs(2));
    let now = sim.now();
    sim.peers[me]
        .dht
        .announce(ih, 6881, AnnounceFlags::EMPTY, now);
    sim.poke(me);
    sim.run_for(Duration::from_secs(2));
    let now = sim.now();
    sim.peers[me].dht.get_peers(ih, now);
    sim.poke(me);
    sim.run_for(Duration::from_secs(2));
    let (mut v4, mut v6) = (false, false);
    for e in sim.peers[me].dht.drain_events() {
        if let Event::GetPeersReply { peers, .. } = e {
            v4 |= peers.iter().any(SocketAddr::is_ipv4);
            v6 |= peers.iter().any(SocketAddr::is_ipv6);
        }
    }
    assert!(v4 && v6, "got v4 peers: {v4}, v6 peers: {v6}");
}

/// Ports `TEST_CASE(dht_rate_limit)` of `simulation/test_dht_rate_limit.cpp`:
/// 2000 pings, one every 10 ms, against a node limited to 400 bytes/s of
/// upload; the achieved response rate is within 5% of the limit and every
/// ping is either answered or counted as dropped.
#[test]
fn test_sim_dht_rate_limit() {
    let mut settings = net_settings();
    settings.block_ratelimit = 100_000; // disable the DoS blocker
    settings.upload_rate_limit = 400;
    let mut now = Time::ZERO + Duration::from_secs(1000);
    let mut dht = Dht::builder(settings)
        .rng(Box::new(TestRng::new(1)))
        .build();
    let me = dht.add_socket(
        ep("40.30.20.10", 8888),
        Some("40.30.20.10".parse().unwrap()),
        now,
    );
    let from = ep("10.20.30.40", 4444);
    let ping: &[u8] = b"d1:ad2:id20:ababababababababababe1:y1:q1:q4:pinge";
    let start = now;
    let mut bytes = 0usize;
    for _ in 0..2000 {
        now = now + Duration::from_millis(10);
        assert!(dht.incoming_packet(me, from, ping, now));
        while let Some(d) = dht.poll_transmit() {
            bytes += d.payload.len();
        }
    }
    // one second to let the dust settle, as the original does
    let elapsed = (now - start).as_secs_f32() + 1.0;
    let rate = (bytes as f32 - 400.0) / elapsed;
    assert!(
        (rate - 400.0).abs() < 400.0 * 0.05,
        "average upload rate {rate}"
    );
    assert_eq!(dht.counters().messages_in, 2000);
    let n = dht.node_counters();
    assert_eq!(
        dht.counters().messages_in_dropped + n.messages_in_dropped + n.ping_in,
        2000
    );
}

/// Ports `TEST_CASE(dht_delete_socket)`: removing the socket of a running
/// tracker between two timer firings must not trip over the dead node.
#[test]
fn test_sim_dht_delete_socket() {
    let mut now = Time::ZERO + Duration::from_secs(1000);
    let mut dht = Dht::builder(net_settings())
        .rng(Box::new(TestRng::new(1)))
        .build();
    dht.start(now);
    let me = dht.add_socket(
        ep("40.30.20.10", 8888),
        Some("40.30.20.10".parse().unwrap()),
        now,
    );
    now = now + Duration::from_secs(2);
    dht.poll(now);
    dht.remove_socket(me);
    now = now + Duration::from_secs(1);
    dht.poll(now);
    dht.stop();
    assert_eq!(dht.sockets().count(), 0);
}

/// Ports `TEST_CASE(dht_bootstrap)` of `simulation/test_dht_bootstrap.cpp`:
/// the first request a freshly started node sends to a seed node carries
/// `bs = 1`.
#[test]
fn test_sim_dht_bootstrap_first_packet_has_bs() {
    let now = Time::ZERO + Duration::from_secs(1000);
    let state = DhtState {
        nodes: vec![ep("10.0.0.10", 25401)],
        ..DhtState::default()
    };
    let mut dht = Dht::builder(net_settings())
        .state(state)
        .rng(Box::new(TestRng::new(1)))
        .build();
    dht.add_socket(ep("10.0.0.1", 6881), None, now);
    dht.start(now);
    let d = dht.poll_transmit().expect("a request to the seed node");
    assert_eq!(d.to, ep("10.0.0.10", 25401));
    let m = decode(&d.payload).expect("a valid message");
    assert_eq!(
        m.dict_find_dict(b"a")
            .expect("a")
            .dict_find_int_value(b"bs", -1),
        1
    );
}
