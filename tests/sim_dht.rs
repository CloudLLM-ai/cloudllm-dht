//! Simulation tests ported from libtorrent RC_2_1 `simulation/test_dht.cpp`,
//! `simulation/test_dht_rate_limit.cpp` and `simulation/test_dht_bootstrap.cpp`
//! (commit `86d573f2631b0162d3cca5e257217eaf530fdcba`) onto the in-memory
//! network of `tests/sim_support`.

mod sim_support;

use std::net::SocketAddr;
use std::time::Duration;

use cloudllm_dht::announce_flags::AnnounceFlags;
use cloudllm_dht::bencode::{decode, Entry};
use cloudllm_dht::dht_state::DhtState;
use cloudllm_dht::events::{Event, OpId};
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
    let op = sim.peers[me].dht.get_peers(ih, now);
    sim.poke(me);
    sim.run_for(Duration::from_secs(2));
    let (mut v4, mut v6) = (false, false);
    let events = sim.peers[me].dht.drain_events();
    for e in results_of(&events, op) {
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

/// The result events tagged with `op`, in order.
fn results_of(events: &[Event], op: OpId) -> Vec<&Event> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Operation { op: o, result } if *o == op => Some(&**result),
            _ => None,
        })
        .collect()
}

/// Ports `TEST_CASE(dht_dual_stack_immutable_item)`: put an immutable item
/// through the dual-stack session and get it back; exactly one result
/// arrives for the get operation.
#[test]
fn test_sim_dht_dual_stack_immutable_item() {
    let mut sim = SimNet::new(3);
    let (_, routers4) = build_network(&mut sim, 100, false, 31);
    let (_, routers6) = build_network(&mut sim, 100, true, 32);
    let (me, _) = session(&mut sim, &routers4, &routers6, 300);
    sim.run_for(Duration::from_secs(2));
    let now = sim.now();
    let value = Entry::from("immutable item");
    let target = cloudllm_dht::item::immutable_item_target_id(&value.encode());
    let put = sim.peers[me].dht.put_immutable_item(value.clone(), now);
    sim.poke(me);
    sim.run_for(Duration::from_secs(2));
    let events = sim.peers[me].dht.drain_events();
    let puts = results_of(&events, put);
    assert_eq!(puts.len(), 1);
    assert!(
        matches!(puts[0], Event::PutDone { responses, target: t, .. } if *responses > 0 && *t == target),
        "put acknowledged: {puts:?}"
    );

    let now = sim.now();
    let get = sim.peers[me].dht.get_immutable_item(target, now);
    sim.poke(me);
    sim.run_for(Duration::from_secs(2));
    let events = sim.peers[me].dht.drain_events();
    let found = results_of(&events, get);
    assert_eq!(found.len(), 1, "one answer per request");
    assert!(matches!(found[0], Event::GetItemDone { item, .. } if item.value() == &value));
    assert_eq!(sim.peers[me].dht.operations_in_flight(), 0);
}

/// Ports `TEST_CASE(dht_dual_stack_mutable_item)`: the data callback runs
/// once per stack (two), the item is stored, and an authoritative
/// `GetItemDone` returns it.
#[test]
fn test_sim_dht_dual_stack_mutable_item() {
    use cloudllm_dht::ed25519::create_keypair;
    use cloudllm_dht::item::Item;
    use cloudllm_dht::types::SequenceNumber;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let mut sim = SimNet::new(4);
    let (_, routers4) = build_network(&mut sim, 100, false, 41);
    let (_, routers6) = build_network(&mut sim, 100, true, 42);
    let (me, _) = session(&mut sim, &routers4, &routers6, 400);
    sim.run_for(Duration::from_secs(2));
    let (pk, sk) = create_keypair(&[0u8; 32]);
    let count = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::clone(&count);
    let now = sim.now();
    sim.peers[me].dht.put_mutable_item(
        pk,
        b"",
        Arc::new(move |item: &mut Item| {
            c2.fetch_add(1, Ordering::SeqCst);
            *item = Item::signed(
                Entry::from("mutable item"),
                b"",
                SequenceNumber(1),
                &pk,
                &sk,
            )
            .expect("a small item");
        }),
        now,
    );
    sim.poke(me);
    sim.run_for(Duration::from_secs(2));
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "one data callback per stack"
    );
    sim.peers[me].dht.drain_events();

    let now = sim.now();
    let get = sim.peers[me].dht.get_mutable_item(pk, b"", now);
    sim.poke(me);
    sim.run_for(Duration::from_secs(2));
    let events = sim.peers[me].dht.drain_events();
    let authoritative: Vec<_> = results_of(&events, get)
        .into_iter()
        .filter_map(|e| match e {
            Event::GetItemDone {
                item,
                authoritative: true,
                ..
            } => Some(item),
            _ => None,
        })
        .collect();
    assert_eq!(authoritative.len(), 1);
    assert_eq!(authoritative[0].pk(), &pk);
    assert_eq!(authoritative[0].value(), &Entry::from("mutable item"));
}

/// Two concurrent gets of the same immutable target each get their own
/// tagged result; two concurrent gets of the same mutable key likewise, and
/// a put of that key running meanwhile steals neither.
#[test]
fn test_sim_dht_concurrent_same_target_operations() {
    use cloudllm_dht::ed25519::create_keypair;
    use cloudllm_dht::item::Item;
    use cloudllm_dht::types::SequenceNumber;
    use std::sync::Arc;

    let mut sim = SimNet::new(6);
    let (_, routers4) = build_network(&mut sim, 60, false, 61);
    let (me, _) = session(&mut sim, &routers4, &[], 600);
    sim.run_for(Duration::from_secs(2));
    let value = Entry::from("shared value");
    let target = cloudllm_dht::item::immutable_item_target_id(&value.encode());
    let now = sim.now();
    sim.peers[me].dht.put_immutable_item(value.clone(), now);
    sim.poke(me);
    sim.run_for(Duration::from_secs(3));
    sim.peers[me].dht.drain_events();

    let now = sim.now();
    let g1 = sim.peers[me].dht.get_immutable_item(target, now);
    let g2 = sim.peers[me].dht.get_immutable_item(target, now);
    assert_ne!(g1, g2);
    sim.poke(me);
    sim.run_for(Duration::from_secs(3));
    let events = sim.peers[me].dht.drain_events();
    for g in [g1, g2] {
        let r = results_of(&events, g);
        assert_eq!(r.len(), 1, "operation {g:?} got exactly one result");
        assert!(matches!(r[0], Event::GetItemDone { item, .. } if item.value() == &value));
    }

    // mutable: two puts of one slot in a row (the second sees the first),
    // with two gets running at the same time
    let (pk, sk) = create_keypair(&[3u8; 32]);
    let cb = |seq_text: (i64, &'static str)| {
        Arc::new(move |i: &mut Item| {
            let next = SequenceNumber(i.seq().0.max(0) + 1);
            assert_eq!(next.0, seq_text.0, "the callback sees the previous put");
            *i = Item::signed(Entry::from(seq_text.1), b"", next, &pk, &sk).unwrap();
        })
    };
    let now = sim.now();
    let p1 = sim.peers[me]
        .dht
        .put_mutable_item(pk, b"", cb((1, "one")), now);
    let p2 = sim.peers[me]
        .dht
        .put_mutable_item(pk, b"", cb((2, "two")), now);
    let m1 = sim.peers[me].dht.get_mutable_item(pk, b"", now);
    let m2 = sim.peers[me].dht.get_mutable_item(pk, b"", now);
    sim.poke(me);
    sim.run_for(Duration::from_secs(10));
    let events = sim.peers[me].dht.drain_events();
    for p in [p1, p2] {
        let r = results_of(&events, p);
        assert_eq!(r.len(), 1, "put {p:?}");
        assert!(matches!(r[0], Event::PutDone { responses, .. } if *responses > 0));
    }
    for m in [m1, m2] {
        let r = results_of(&events, m);
        assert!(
            matches!(
                r.last(),
                Some(Event::GetItemDone {
                    authoritative: true,
                    ..
                })
            ),
            "get {m:?} finished: {r:?}"
        );
    }
    assert_eq!(sim.peers[me].dht.operations_in_flight(), 0);
}

/// `direct_request` and `sample_infohashes` through the tracker: each
/// answer is tagged with its operation, a request to a dead address times
/// out with `None`, and every operation ends exactly once.
#[test]
fn test_sim_dht_direct_request_and_sample() {
    let mut sim = SimNet::new(5);
    let (_, routers4) = build_network(&mut sim, 20, false, 51);
    let (me, _) = session(&mut sim, &routers4, &[], 500);
    sim.run_for(Duration::from_secs(2));
    sim.peers[me].dht.drain_events();
    let now = sim.now();
    let mut ping = Entry::dict();
    ping.set("q", "ping");
    let d1 = sim.peers[me]
        .dht
        .direct_request(routers4[0], ping.clone(), now);
    let d2 = sim.peers[me]
        .dht
        .direct_request(ep("40.1.1.1", 1), ping, now);
    let s1 = sim.peers[me]
        .dht
        .sample_infohashes(routers4[1], Sha1Hash([1; 20]), now);
    let s2 = sim.peers[me]
        .dht
        .sample_infohashes(routers4[1], Sha1Hash([2; 20]), now);
    sim.poke(me);
    sim.run_for(Duration::from_secs(20));
    let events = sim.peers[me].dht.drain_events();
    let reply_of = |op: OpId| {
        results_of(&events, op).into_iter().find_map(|e| match e {
            Event::DirectResponse { reply, .. } => Some(reply.clone()),
            _ => None,
        })
    };
    assert!(matches!(reply_of(d1), Some(Some(_))));
    assert_eq!(reply_of(d2), Some(None));
    for s in [s1, s2] {
        assert!(results_of(&events, s)
            .iter()
            .any(|e| matches!(e, Event::SampleInfohashes { from, .. } if *from == routers4[1])));
    }
    for op in [d1, d2, s1, s2] {
        assert_eq!(ends_of(&events, op), 1, "operation {op:?} ends once");
    }
    assert_eq!(sim.peers[me].dht.operations_in_flight(), 0);
}

/// How many events end `op`.
fn ends_of(events: &[Event], op: OpId) -> usize {
    events
        .iter()
        .filter(|e| e.ends_operation() && e.op() == Some(op))
        .count()
}

/// Peer lookups and announces are operations too: each of two concurrent
/// lookups of one info-hash gets the announced peers tagged with its own id,
/// and each completes once.
#[test]
fn test_sim_dht_peer_operations_complete() {
    let mut sim = SimNet::new(7);
    let (_, routers4) = build_network(&mut sim, 60, false, 71);
    let (me, _) = session(&mut sim, &routers4, &[], 700);
    sim.run_for(Duration::from_secs(2));
    sim.peers[me].dht.drain_events();
    let ih = Sha1Hash([8; 20]);
    let now = sim.now();
    let a = sim.peers[me]
        .dht
        .announce(ih, 4321, AnnounceFlags::EMPTY, now);
    sim.poke(me);
    sim.run_for(Duration::from_secs(30));
    let events = sim.peers[me].dht.drain_events();
    assert_eq!(ends_of(&events, a), 1);
    assert!(matches!(
        events
            .iter()
            .find(|e| e.op() == Some(a) && e.ends_operation()),
        Some(Event::OperationDone { .. })
    ));

    let now = sim.now();
    let g1 = sim.peers[me].dht.get_peers(ih, now);
    let g2 = sim.peers[me].dht.get_peers(ih, now);
    assert_ne!(g1, g2);
    sim.poke(me);
    sim.run_for(Duration::from_secs(30));
    let events = sim.peers[me].dht.drain_events();
    for g in [g1, g2] {
        let peers: Vec<_> = results_of(&events, g)
            .into_iter()
            .flat_map(|e| match e {
                Event::GetPeersReply { peers, .. } => peers.clone(),
                _ => Vec::new(),
            })
            .collect();
        assert!(peers.iter().any(|p| p.port() == 4321), "{g:?}: {peers:?}");
        let mut dedup = peers.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), peers.len(), "each peer once per operation");
        assert_eq!(ends_of(&events, g), 1);
    }
    assert_eq!(sim.peers[me].dht.operations_in_flight(), 0);
}

/// `Dht::bootstrap` is an operation that ends once the lookup finished.
#[test]
fn test_sim_dht_bootstrap_operation_completes() {
    let mut sim = SimNet::new(8);
    let (_, routers4) = build_network(&mut sim, 30, false, 81);
    let (me, _) = session(&mut sim, &routers4, &[], 800);
    sim.run_for(Duration::from_secs(30));
    sim.peers[me].dht.drain_events();
    let now = sim.now();
    let op = sim.peers[me].dht.bootstrap(&routers4, now);
    sim.poke(me);
    sim.run_for(Duration::from_secs(30));
    let events = sim.peers[me].dht.drain_events();
    assert_eq!(ends_of(&events, op), 1);
}

/// Operations that are still running when a socket is removed are
/// cancelled, whatever their kind.
#[test]
fn test_sim_dht_remove_socket_cancels_operations() {
    let now = Time::ZERO + Duration::from_secs(1000);
    let mut dht = Dht::builder(net_settings())
        .rng(Box::new(TestRng::new(1)))
        .build();
    let sock = dht.add_socket(ep("10.0.0.1", 6881), None, now);
    dht.add_router_node(ep("40.1.1.1", 1));
    let ih = Sha1Hash([6; 20]);
    let ops = [
        dht.get_peers(ih, now),
        dht.announce(ih, 1, AnnounceFlags::EMPTY, now),
        dht.get_immutable_item(ih, now),
    ];
    assert_eq!(dht.operations_in_flight(), 3);
    dht.remove_socket(sock);
    let events = dht.drain_events();
    for op in ops {
        assert_eq!(ends_of(&events, op), 1, "{op:?}");
    }
    assert_eq!(dht.operations_in_flight(), 0);
}

/// `Dht::shutdown` aborts outstanding requests: nothing stays in the
/// transaction table and no observer or lookup is left behind.
#[test]
fn test_sim_dht_shutdown_aborts_requests() {
    let now = Time::ZERO + Duration::from_secs(1000);
    let mut dht = Dht::builder(net_settings())
        .rng(Box::new(TestRng::new(1)))
        .build();
    let sock = dht.add_socket(ep("10.0.0.1", 6881), None, now);
    let mut ping = Entry::dict();
    ping.set("q", "ping");
    dht.direct_request(ep("40.1.1.1", 1), ping, now);
    assert_eq!(dht.node(sock).unwrap().rpc().num_transactions(), 1);
    dht.shutdown(now);
    let node = dht.node(sock).unwrap();
    assert_eq!(node.rpc().num_transactions(), 0);
    assert_eq!(node.rpc().num_allocated_observers(), 0);
    assert_eq!(node.num_lookups(), 0);
}

/// Operations still running at shutdown are cancelled, not left dangling.
#[test]
fn test_sim_dht_shutdown_cancels_operations() {
    let now = Time::ZERO + Duration::from_secs(1000);
    let mut dht = Dht::builder(net_settings())
        .rng(Box::new(TestRng::new(1)))
        .build();
    dht.add_socket(ep("10.0.0.1", 6881), None, now);
    // a silent router keeps every lookup waiting for an answer
    dht.add_router_node(ep("40.1.1.1", 1));
    let g = dht.get_immutable_item(Sha1Hash([5; 20]), now);
    let p = dht.put_immutable_item(Entry::from("x"), now);
    let p2 = dht.put_immutable_item(Entry::from("x"), now);
    assert_eq!(dht.operations_in_flight(), 3);
    dht.shutdown(now);
    // every operation ends exactly once: an aborted lookup reports what it
    // has (nothing), anything that cannot be finished is cancelled
    let events = dht.drain_events();
    for op in [g, p, p2] {
        let ends = ends_of(&events, op);
        assert_eq!(ends, 1, "operation {op:?}: {events:?}");
    }
    assert_eq!(dht.operations_in_flight(), 0);
}

/// A node that learns of an entry carrying its own endpoint under another
/// ID (a peer can report any `ip:port` in `nodes`) must not loop forever
/// asking itself: every operation still ends.
#[test]
fn test_sim_dht_node_listed_at_own_address_does_not_stall_operations() {
    let mut now = Time::ZERO + Duration::from_secs(1000);
    let me_addr = ep("30.0.0.1", 6881);
    let mut dht = Dht::builder(net_settings())
        .rng(Box::new(TestRng::new(1)))
        .build();
    let sock = dht.add_socket(me_addr, Some(me_addr.ip()), now);
    dht.start(now);
    let ghost = Sha1Hash([0x42; 20]);
    dht.node_mut(sock)
        .unwrap()
        .table_mut()
        .node_seen(ghost, me_addr, 10, now);
    let op = dht.get_immutable_item(Sha1Hash([9; 20]), now);
    let mut steps = 0;
    while dht.operations_in_flight() > 0 {
        while let Some(d) = dht.poll_transmit() {
            // everything sent to ourselves is looped back
            if d.to == me_addr {
                dht.incoming_packet(sock, me_addr, &d.payload, now);
            }
        }
        now = now + Duration::from_secs(1);
        dht.poll(now);
        steps += 1;
        assert!(steps < 300, "the operation never ended");
    }
    let events = dht.drain_events();
    assert_eq!(ends_of(&events, op), 1);
}

/// Regression test for the `dht_ops` finding `crash-fc57aea…`: hundreds of
/// puts of one slot queue up and run one at a time, which is slow but not
/// stuck. Every one of them ends exactly once, in the order started, with
/// each data callback seeing the sequence number the previous one wrote.
#[test]
fn test_sim_dht_queued_puts_of_one_slot_all_complete_in_order() {
    use cloudllm_dht::ed25519::create_keypair;
    use cloudllm_dht::item::Item;
    use cloudllm_dht::types::SequenceNumber;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;

    let mut sim = SimNet::new(9);
    let (_, routers4) = build_network(&mut sim, 30, false, 91);
    let (me, _) = session(&mut sim, &routers4, &[], 900);
    sim.run_for(Duration::from_secs(2));
    sim.peers[me].dht.drain_events();
    let (pk, sk) = create_keypair(&[1u8; 32]);
    let last_seq = Arc::new(AtomicI64::new(0));
    let ops: Vec<OpId> = (0..60)
        .map(|n| {
            let seen = Arc::clone(&last_seq);
            let cb = Arc::new(move |i: &mut Item| {
                let next = i.seq().0.max(0) + 1;
                // the callbacks run in order: each sees the previous seq
                assert!(next > seen.load(Ordering::SeqCst));
                seen.store(next, Ordering::SeqCst);
                *i = Item::signed(Entry::from(n as i64), b"", SequenceNumber(next), &pk, &sk)
                    .unwrap();
            });
            let now = sim.now();
            sim.peers[me].dht.put_mutable_item(pk, b"", cb, now)
        })
        .collect();
    sim.poke(me);
    sim.run_for(Duration::from_secs(900));
    let events = sim.peers[me].dht.drain_events();
    let finished: Vec<OpId> = events
        .iter()
        .filter_map(|e| match e {
            Event::OperationDone { op } => Some(*op),
            _ => None,
        })
        .collect();
    assert_eq!(finished, ops, "all puts end once, in the order started");
    assert_eq!(sim.peers[me].dht.operations_in_flight(), 0);
}

/// Regression test for the self-queries behind the `dht_ops` finding
/// `crash-fc57aea…`: other nodes list *us* in their `nodes` replies (we are
/// often among the closest to a target), and a lookup used to add that entry
/// and query itself. Every such request was answered from our own address,
/// fed the DoS blocker, and made puts crawl. A lookup must never contact
/// the node's own ID.
#[test]
fn test_sim_dht_lookups_never_query_ourselves() {
    use cloudllm_dht::ed25519::create_keypair;
    use cloudllm_dht::item::Item;
    use cloudllm_dht::types::SequenceNumber;
    use std::sync::Arc;

    let mut sim = SimNet::new(10);
    let (net, routers4) = build_network(&mut sim, 12, false, 101);
    let (me, socks) = session(&mut sim, &routers4, &[], 1000);
    let (my_id, my_addr) = {
        let n = sim.peers[me].dht.node(socks[0]).unwrap();
        (n.nid(), sim.peers[me].addrs[0].1)
    };
    let now = sim.now();
    // every network node knows us and will report us in `nodes`
    for i in net {
        let (sid, _) = sim.peers[i].addrs[0];
        sim.peers[i]
            .dht
            .node_mut(sid)
            .unwrap()
            .table_mut()
            .node_seen(my_id, my_addr, 10, now);
    }
    sim.run_for(Duration::from_secs(2));
    let (pk, sk) = create_keypair(&[4u8; 32]);
    for round in 0..5 {
        let now = sim.now();
        let ih = Sha1Hash([round; 20]);
        sim.peers[me].dht.get_peers(ih, now);
        sim.peers[me].dht.get_immutable_item(ih, now);
        let (pk, sk) = (pk, sk);
        sim.peers[me].dht.put_mutable_item(
            pk,
            b"",
            Arc::new(move |i: &mut Item| {
                let seq = SequenceNumber(i.seq().0.max(0) + 1);
                *i = Item::signed(Entry::from("v"), b"", seq, &pk, &sk).unwrap();
            }),
            now,
        );
        sim.poke(me);
        sim.run_for(Duration::from_secs(20));
    }
    let n = sim.peers[me].dht.node_counters();
    assert_eq!(
        (n.get_in, n.put_in, n.get_peers_in, n.find_node_in),
        (0, 0, 0, 0),
        "we queried ourselves: {n:?}"
    );
    assert_eq!(sim.peers[me].dht.operations_in_flight(), 0);
}
