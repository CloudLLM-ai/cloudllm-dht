//! Tests for the traversal algorithm base (`traversal_algorithm.cpp`) and
//! the lookups built on it, including the `test_dht.cpp` cases that drive
//! them (libtorrent RC_2_1, `86d573f2631b0162d3cca5e257217eaf530fdcba`).

mod common;

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

use cloudllm_dht::announce_flags::AnnounceFlags;
use cloudllm_dht::bencode::{Entry, NodeKind};
use cloudllm_dht::ctx::NodeCtx;
use cloudllm_dht::events::Event;
use cloudllm_dht::msg::{verify_message, KeyDesc, KeyFlags};
use cloudllm_dht::net::{write_nodes, Protocol};
use cloudllm_dht::node_id::{compare_ref, NodeId};
use cloudllm_dht::observer::{ObserverFlags, ObserverId};
use cloudllm_dht::rng::Rng;
use cloudllm_dht::testing::{ep, rand_v4, rand_v6, to_hash, Encoded, MsgArgs};
use cloudllm_dht::traversal::algorithm::{add_entry, base_done, set_id, Plain, MAX_RESULTS};
use cloudllm_dht::traversal::direct_request::direct_request;
use cloudllm_dht::traversal::get_peers::announce;
use cloudllm_dht::traversal::refresh::bootstrap;
use cloudllm_dht::traversal::sample_infohashes::sample_infohashes;
use cloudllm_dht::traversal::Traversal;
use cloudllm_dht::Sha1Hash;

use common::World;

fn targets(t: &Plain, ctx: &NodeCtx<'_>) -> Vec<SocketAddr> {
    t.algo()
        .results()
        .iter()
        .map(|o| ctx.rpc.observers.get(*o).expect("live").target)
        .collect()
}

fn ids(t: &Plain, ctx: &NodeCtx<'_>) -> Vec<NodeId> {
    t.algo()
        .results()
        .iter()
        .map(|o| ctx.rpc.observers.get(*o).expect("live").id)
        .collect()
}

/// Initial nodes whose ID is unknown stay unsorted at the tail of the result
/// list; learning one's ID moves it to the sorted head. Ports
/// `unsorted_traversal_results` from `test_dht.cpp`.
#[test]
fn test_unsorted_traversal_results() {
    let mut w = World::v4();
    let our_id = w.id;
    w.run(|ctx, _| {
        let mut algo = Plain::new(ctx, our_id);
        let mut eps = Vec::new();
        for i in 0..10u16 {
            let e = SocketAddr::new(rand_v4(&mut *ctx.rng), 1000 + i);
            eps.push(e);
            add_entry(&mut algo, ctx, Sha1Hash::MIN, e, ObserverFlags::INITIAL);
        }

        // we should have 10 unsorted nodes now
        assert_eq!(algo.algo().num_sorted_results(), 0);
        assert_eq!(targets(&algo, ctx), eps);

        // setting the node ID, regardless of what we set it to, makes this
        // observer sorted: it moves to the beginning of the result list
        let fifth: ObserverId = algo.algo().results()[5];
        set_id(&mut algo, ctx, fifth, Sha1Hash(*b"abababababababababab"));

        assert_eq!(algo.algo().num_sorted_results(), 1);
        let t = targets(&algo, ctx);
        assert_eq!(t.len(), eps.len());
        assert_eq!(t[0], eps[5]);
        base_done(&mut algo, ctx);
    });
}

/// Nodes with known IDs are kept ordered by XOR distance to the target no
/// matter the order they arrive in.
#[test]
fn test_add_entry_keeps_results_sorted_by_distance() {
    let mut w = World::v4();
    w.settings.restrict_search_ips = false;
    let target = Sha1Hash([0x80; 20]);
    w.run(|ctx, _| {
        let mut algo = Plain::new(ctx, target);
        let mut all = Vec::new();
        for i in 0..40u8 {
            let id = Sha1Hash([
                i.wrapping_mul(37),
                i,
                i ^ 0x5a,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                i,
            ]);
            all.push(id);
            let e = ep("10.0.0.1", 2000 + u16::from(i));
            add_entry(&mut algo, ctx, id, e, ObserverFlags::EMPTY);
        }
        let got = ids(&algo, ctx);
        assert_eq!(got.len(), 40);
        assert_eq!(algo.algo().num_sorted_results(), 40);
        for pair in got.windows(2) {
            assert!(
                !compare_ref(&pair[1], &pair[0], &target),
                "{pair:?} out of order"
            );
        }
        base_done(&mut algo, ctx);
    });
}

/// A node whose ID is already in the list is not added twice.
#[test]
fn test_add_entry_ignores_duplicate_ids() {
    let mut w = World::v4();
    w.run(|ctx, _| {
        let mut algo = Plain::new(ctx, Sha1Hash::MAX);
        let id = Sha1Hash([7; 20]);
        add_entry(&mut algo, ctx, id, ep("1.1.1.1", 1), ObserverFlags::EMPTY);
        add_entry(&mut algo, ctx, id, ep("2.2.2.2", 2), ObserverFlags::EMPTY);
        assert_eq!(algo.algo().results().len(), 1);
        assert_eq!(
            ctx.rpc.num_allocated_observers(),
            1,
            "the rejected one is not leaked"
        );
        base_done(&mut algo, ctx);
    });
}

/// With `restrict_search_ips`, a second node from the same /24 is refused
/// unless it carries the `INITIAL` flag; IPv6 nodes are grouped by /64.
#[test]
fn test_add_entry_restricts_search_ips() {
    let mut w = World::v4();
    w.run(|ctx, _| {
        let mut algo = Plain::new(ctx, Sha1Hash::MAX);
        add_entry(
            &mut algo,
            ctx,
            Sha1Hash([1; 20]),
            ep("10.1.2.3", 1),
            ObserverFlags::EMPTY,
        );
        add_entry(
            &mut algo,
            ctx,
            Sha1Hash([2; 20]),
            ep("10.1.2.99", 2),
            ObserverFlags::EMPTY,
        );
        assert_eq!(algo.algo().results().len(), 1, "same /24");
        add_entry(
            &mut algo,
            ctx,
            Sha1Hash([3; 20]),
            ep("10.1.3.99", 3),
            ObserverFlags::EMPTY,
        );
        assert_eq!(algo.algo().results().len(), 2, "different /24");
        add_entry(
            &mut algo,
            ctx,
            Sha1Hash([4; 20]),
            ep("10.1.2.50", 4),
            ObserverFlags::INITIAL,
        );
        assert_eq!(algo.algo().results().len(), 3, "initial nodes are exempt");

        add_entry(
            &mut algo,
            ctx,
            Sha1Hash([5; 20]),
            ep("2001:db8:0:1::1", 5),
            ObserverFlags::EMPTY,
        );
        add_entry(
            &mut algo,
            ctx,
            Sha1Hash([6; 20]),
            ep("2001:db8:0:1::2", 6),
            ObserverFlags::EMPTY,
        );
        add_entry(
            &mut algo,
            ctx,
            Sha1Hash([7; 20]),
            ep("2001:db8:0:2::1", 7),
            ObserverFlags::EMPTY,
        );
        assert_eq!(
            algo.algo().results().len(),
            5,
            "same /64 refused, other /64 kept"
        );
        base_done(&mut algo, ctx);
    });
}

/// With the restriction off, same-/24 nodes are all kept.
#[test]
fn test_add_entry_unrestricted() {
    let mut w = World::v4();
    w.settings.restrict_search_ips = false;
    w.run(|ctx, _| {
        let mut algo = Plain::new(ctx, Sha1Hash::MAX);
        for i in 1..=5u8 {
            add_entry(
                &mut algo,
                ctx,
                Sha1Hash([i; 20]),
                ep("10.1.2.3", u16::from(i)),
                ObserverFlags::EMPTY,
            );
        }
        assert_eq!(algo.algo().results().len(), 5);
        base_done(&mut algo, ctx);
    });
}

/// The result list never exceeds 100 entries; the farthest are dropped and
/// their observers freed.
#[test]
fn test_result_list_is_capped() {
    let mut w = World::v4();
    w.settings.restrict_search_ips = false;
    w.run(|ctx, _| {
        let mut algo = Plain::new(ctx, Sha1Hash::MIN);
        for i in 0..150u8 {
            let id = Sha1Hash([
                i.wrapping_add(1),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                i,
            ]);
            add_entry(
                &mut algo,
                ctx,
                id,
                ep("10.0.0.1", 3000 + u16::from(i)),
                ObserverFlags::EMPTY,
            );
        }
        assert_eq!(algo.algo().results().len(), MAX_RESULTS);
        assert_eq!(algo.algo().num_sorted_results(), MAX_RESULTS);
        assert_eq!(ctx.rpc.num_allocated_observers(), MAX_RESULTS);
        let got = ids(&algo, ctx);
        assert_eq!(got.first().map(|i| i.0[0]), Some(1), "closest kept");
        assert!(got.iter().all(|i| i.0[0] <= 100), "farthest dropped");
        base_done(&mut algo, ctx);
        assert_eq!(ctx.rpc.num_allocated_observers(), 0);
    });
}

type RandAddr = fn(&mut dyn Rng) -> IpAddr;

fn world_for(protocol: Protocol) -> World {
    match protocol {
        Protocol::V4 => World::v4(),
        Protocol::V6 => World::v6(),
    }
}

fn nodes_args(protocol: Protocol, packed: &[u8]) -> MsgArgs {
    match protocol {
        Protocol::V4 => MsgArgs::new().nodes(packed),
        Protocol::V6 => MsgArgs::new().nodes6(packed),
    }
}

/// The libtorrent `find_node_desc` table used by the bootstrap tests.
fn find_node_desc(want: bool) -> Vec<KeyDesc> {
    use NodeKind::{Dict, List, Str};
    let mut d = vec![
        KeyDesc::new("y", Some(Str), 1, KeyFlags::NONE),
        KeyDesc::new("t", Some(Str), 2, KeyFlags::NONE),
        KeyDesc::new("q", Some(Str), 9, KeyFlags::NONE),
        KeyDesc::new("a", Some(Dict), 0, KeyFlags::PARSE_CHILDREN),
        KeyDesc::new("id", Some(Str), 20, KeyFlags::NONE),
        KeyDesc::new("target", Some(Str), 20, KeyFlags::OPTIONAL),
    ];
    if want {
        d.push(KeyDesc::new("info_hash", Some(Str), 20, KeyFlags::OPTIONAL));
        d.push(KeyDesc::new("want", Some(List), 0, KeyFlags::LAST_CHILD));
    } else {
        d.push(KeyDesc::new(
            "info_hash",
            Some(Str),
            20,
            KeyFlags::OPTIONAL.or(KeyFlags::LAST_CHILD),
        ));
    }
    d
}

fn query_name(e: &Entry) -> String {
    String::from_utf8_lossy(e.get("q").and_then(Entry::as_bytes).expect("q")).into_owned()
}

fn args_of<'a>(e: &'a Entry, key: &str) -> Option<&'a Entry> {
    e.get("a").and_then(|a| a.get(key))
}

/// The shape of a bootstrap request: `y=q`, a two byte `t`, `q` of
/// `get_peers` (libtorrent accepts `find_node` too) and a 20-byte `id`.
fn assert_find_node_request(packet: &Entry, want: bool) {
    let enc = Encoded::from_entry(packet);
    let n = enc.node();
    let found = verify_message(&n, &find_node_desc(want))
        .unwrap_or_else(|e| panic!("invalid find_node request {packet}: {e}"));
    assert_eq!(found[0].unwrap().string_value(), b"q");
    let q = found[2].unwrap().string_value();
    assert!(q == b"find_node" || q == b"get_peers");
}

fn run_bootstrap(rand: RandAddr, protocol: Protocol) {
    let mut w = world_for(protocol);
    let initial_node = SocketAddr::new(rand(&mut w.rng), 1234);

    w.run(|ctx, trs| {
        let t = bootstrap(ctx, &[initial_node], true);
        trs.spawn(ctx, t);
    });

    assert_eq!(w.sock.sent.len(), 1);
    assert_eq!(w.sock.sent[0].0, initial_node);
    let request = w.sock.sent[0].1.clone();
    assert_find_node_request(&request, false);
    assert_eq!(
        args_of(&request, "bs"),
        Some(&Entry::Int(1)),
        "seed nodes are told we bootstrap"
    );

    // the response lists one node, whose ID we are not told (the all zero ID)
    let found_node = SocketAddr::new(rand(&mut w.rng), 2235);
    w.sock.clear();
    let packed = write_nodes([(&Sha1Hash::MIN, &found_node)]);
    w.respond(&request, initial_node, &nodes_args(protocol, &packed));

    assert_eq!(w.sock.sent.len(), 1);
    assert_eq!(w.sock.sent[0].0, found_node);
    let request = w.sock.sent[0].1.clone();
    assert_find_node_request(&request, false);
    assert!(
        args_of(&request, "bs").is_none(),
        "only seed nodes get the bs flag"
    );

    w.sock.clear();
    w.respond(&request, found_node, &MsgArgs::new());
    assert!(w.sock.sent.is_empty());
    // libtorrent checks routing_table::num_global_nodes() == 3 here; the
    // table is a fake, so check what it was told instead: both nodes
    // answered, and the second was heard about from the first
    assert_eq!(w.table.seen.len(), 2);
    assert_eq!(w.table.heard.len(), 1);
    assert_eq!(w.table.heard[0].1, found_node);
    assert_eq!(w.take_events(), vec![Event::BootstrapDone]);
    assert!(
        w.traversals.is_empty(),
        "a finished bootstrap with nothing in flight is dropped"
    );
    assert_eq!(w.rpc.num_allocated_observers(), 0);
}

/// A bootstrap asks its seed node, learns a node from the response, asks it
/// too, and finishes when nothing is left. Ports `bootstrap_v4`.
#[test]
fn test_bootstrap_v4() {
    run_bootstrap(rand_v4, Protocol::V4);
}

/// Ports `bootstrap_v6`.
#[test]
fn test_bootstrap_v6() {
    run_bootstrap(rand_v6, Protocol::V6);
}

fn run_bootstrap_want(node_protocol: Protocol, seed_rand: RandAddr, want: &str) {
    let mut w = world_for(node_protocol);
    let seed = SocketAddr::new(seed_rand(&mut w.rng), 1234);
    w.run(|ctx, trs| {
        let t = bootstrap(ctx, &[seed], false);
        trs.spawn(ctx, t);
    });
    assert_eq!(w.sock.sent.len(), 1);
    assert_eq!(w.sock.sent[0].0, seed);
    let request = w.sock.sent[0].1.clone();
    assert_find_node_request(&request, true);
    let enc = Encoded::from_entry(&request);
    let n = enc.node();
    let found = verify_message(&n, &find_node_desc(true)).unwrap();
    let want_list = found[7].expect("want");
    assert_eq!(want_list.list_len(), 1);
    assert_eq!(want_list.list_string_value_at(0, b""), want.as_bytes());
}

/// A v4 node bootstrapping from a v6 node asks for v4 nodes with
/// `want = ["n4"]`. Ports `bootstrap_want_v4`.
#[test]
fn test_bootstrap_want_v4() {
    run_bootstrap_want(Protocol::V4, rand_v6, "n4");
}

/// Ports `bootstrap_want_v6`.
#[test]
fn test_bootstrap_want_v6() {
    run_bootstrap_want(Protocol::V6, rand_v4, "n6");
}

fn run_short_nodes(rand: RandAddr, protocol: Protocol) {
    let mut w = world_for(protocol);
    let initial_node = SocketAddr::new(rand(&mut w.rng), 1234);
    w.run(|ctx, trs| {
        let t = bootstrap(ctx, &[initial_node], true);
        trs.spawn(ctx, t);
    });
    assert_eq!(w.sock.sent.len(), 1);
    let request = w.sock.sent[0].1.clone();
    assert_find_node_request(&request, false);

    let found_node = SocketAddr::new(rand(&mut w.rng), 2235);
    w.sock.clear();
    let packed = write_nodes([(&Sha1Hash::MIN, &found_node)]);
    // chop one byte off of the nodes string
    w.respond(&request, initial_node, &nodes_args(protocol, &packed[1..]));
    assert!(w.sock.sent.is_empty(), "a truncated node must be ignored");
    assert!(w.table.heard.is_empty());
}

/// A `nodes` string with a byte missing yields no node: the traversal asks
/// nobody new. Ports `short_nodes_v4`.
#[test]
fn test_short_nodes_v4() {
    run_short_nodes(rand_v4, Protocol::V4);
}

/// Ports `short_nodes_v6`.
#[test]
fn test_short_nodes_v6() {
    run_short_nodes(rand_v6, Protocol::V6);
}

fn peers_in(events: &[Event]) -> BTreeSet<SocketAddr> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::GetPeersReply { peers, .. } => Some(peers.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect()
}

fn run_get_peers(rand: RandAddr, protocol: Protocol) {
    let mut w = world_for(protocol);
    let target = to_hash("1234876923549721020394873245098347598635");
    let initial_node = SocketAddr::new(rand(&mut w.rng), 1234);
    let initial_node_id = to_hash("1111111111222222222233333333334444444444");
    w.table.add_node(initial_node_id, initial_node);

    w.run(|ctx, trs| {
        let t = announce(ctx, target, 1234, AnnounceFlags::EMPTY);
        trs.spawn(ctx, t);
    });

    assert_eq!(w.sock.sent.len(), 1);
    assert_eq!(w.sock.sent[0].0, initial_node);
    let request = w.sock.sent[0].1.clone();
    assert_eq!(query_name(&request), "get_peers");
    assert_eq!(
        args_of(&request, "info_hash").and_then(Entry::as_bytes),
        Some(&target.0[..])
    );

    let mut peers: [BTreeSet<SocketAddr>; 2] = [BTreeSet::new(), BTreeSet::new()];
    for port in 4111..=4113 {
        peers[0].insert(SocketAddr::new(rand(&mut w.rng), port));
    }
    let next_node = SocketAddr::new(rand(&mut w.rng), 2235);
    let packed = write_nodes([(&Sha1Hash::MIN, &next_node)]);

    w.sock.clear();
    let args = nodes_args(protocol, &packed)
        .token(b"10")
        .port(1234)
        .peers(&peers[0]);
    w.respond(&request, initial_node, &args);
    assert_eq!(w.sock.sent.len(), 1);
    assert_eq!(w.sock.sent[0].0, next_node);
    let request = w.sock.sent[0].1.clone();
    assert_eq!(query_name(&request), "get_peers");
    assert_eq!(
        args_of(&request, "info_hash").and_then(Entry::as_bytes),
        Some(&target.0[..])
    );

    for port in 4114..=4116 {
        peers[1].insert(SocketAddr::new(rand(&mut w.rng), port));
    }
    w.sock.clear();
    w.respond(
        &request,
        next_node,
        &MsgArgs::new().token(b"11").port(1234).peers(&peers[1]),
    );

    assert_eq!(w.sock.sent.len(), 2, "announce_peer to both nodes");
    for (_, p) in &w.sock.sent {
        assert_eq!(query_name(p), "announce_peer");
        assert_eq!(args_of(p, "port"), Some(&Entry::Int(1234)));
        assert_eq!(args_of(p, "seed"), Some(&Entry::Int(0)));
        assert!(args_of(p, "implied_port").is_none());
        assert_eq!(
            args_of(p, "info_hash").and_then(Entry::as_bytes),
            Some(&target.0[..])
        );
    }
    let tokens: BTreeSet<Vec<u8>> = w
        .sock
        .sent
        .iter()
        .map(|(_, p)| {
            args_of(p, "token")
                .and_then(Entry::as_bytes)
                .unwrap()
                .to_vec()
        })
        .collect();
    assert_eq!(tokens, BTreeSet::from([b"10".to_vec(), b"11".to_vec()]));
    let dests: BTreeSet<SocketAddr> = w.sock.sent.iter().map(|(d, _)| *d).collect();
    assert_eq!(dests, BTreeSet::from([initial_node, next_node]));

    let got = peers_in(&w.take_events());
    let want: BTreeSet<SocketAddr> = peers[0].union(&peers[1]).copied().collect();
    assert_eq!(got, want);
}

/// A lookup walks from the node in the table to the node it names, collects
/// the peers both return, and announces to both. Ports `get_peers_v4`.
#[test]
fn test_get_peers_v4() {
    run_get_peers(rand_v4, Protocol::V4);
}

/// Ports `get_peers_v6`.
#[test]
fn test_get_peers_v6() {
    run_get_peers(rand_v6, Protocol::V6);
}

fn node_id(n: u8) -> NodeId {
    // IDs that differ in the first byte, so their order against any target
    // is predictable
    let mut b = [0u8; 20];
    b[0] = n;
    Sha1Hash(b)
}

fn lookup_world(nodes: u8) -> (World, Vec<(NodeId, SocketAddr)>) {
    let mut w = World::v4();
    let mut v = Vec::new();
    for i in 1..=nodes {
        let n = (node_id(i), ep(&format!("{}.{}.0.1", 20 + i, i), 6881));
        w.table.add_node(n.0, n.1);
        v.push(n);
    }
    (w, v)
}

fn start_get_peers(w: &mut World, target: NodeId, flags: AnnounceFlags) {
    w.run(|ctx, trs| {
        let t = cloudllm_dht::traversal::get_peers::get_peers(ctx, target, flags);
        trs.spawn(ctx, t);
    });
}

fn status(w: &mut World) -> Vec<cloudllm_dht::traversal::LookupStatus> {
    w.run(|ctx, trs| trs.status(ctx))
}

/// A seed asked to leave seeds out sends `noseed = 1`; otherwise the key is
/// absent.
#[test]
fn test_get_peers_noseed() {
    let (mut w, _) = lookup_world(1);
    start_get_peers(&mut w, node_id(0), AnnounceFlags::SEED);
    assert_eq!(args_of(&w.sock.sent[0].1, "noseed"), Some(&Entry::Int(1)));

    let (mut w, _) = lookup_world(1);
    start_get_peers(&mut w, node_id(0), AnnounceFlags::EMPTY);
    assert!(args_of(&w.sock.sent[0].1, "noseed").is_none());
}

/// A lookup asks at most `search_branching` nodes at once, the closest
/// first, and asks the next one as each answers.
#[test]
fn test_lookup_respects_branch_factor() {
    let (mut w, nodes) = lookup_world(6);
    w.settings.search_branching = 2;
    start_get_peers(&mut w, node_id(0), AnnounceFlags::EMPTY);
    let sent: Vec<SocketAddr> = w.sock.sent.iter().map(|(d, _)| *d).collect();
    assert_eq!(
        sent,
        vec![nodes[0].1, nodes[1].1],
        "the two closest to the target"
    );
    let st = status(&mut w);
    assert_eq!(
        (
            st[0].branch_factor,
            st[0].outstanding_requests,
            st[0].nodes_left
        ),
        (2, 2, 4)
    );

    let request = w.take_packet(nodes[0].1).unwrap();
    w.sock.clear();
    w.respond(&request, nodes[0].1, &MsgArgs::new().nid(&nodes[0].0));
    assert_eq!(w.sock.sent.len(), 1);
    assert_eq!(w.sock.sent[0].0, nodes[2].1);
}

/// After the short timeout a request keeps its slot but the branch factor
/// grows, so another node is asked. The node is also reported as failed to
/// the table. A late response restores the branch factor.
#[test]
fn test_short_timeout_opens_a_slot_and_late_reply_restores_it() {
    let (mut w, nodes) = lookup_world(4);
    w.settings.search_branching = 2;
    start_get_peers(&mut w, node_id(0), AnnounceFlags::EMPTY);
    assert_eq!(w.sock.sent.len(), 2);
    let first = w.sock.sent[0].1.clone();

    w.advance(std::time::Duration::from_secs(1));
    w.tick();
    // two short timeouts: branch factor 2 -> 4, so both others go out
    assert_eq!(w.sock.sent.len(), 4);
    let st = status(&mut w);
    assert_eq!(st[0].branch_factor, 4);
    assert_eq!(st[0].first_timeout, 2);
    assert_eq!(
        w.table.failed.len(),
        2,
        "a short timeout already counts as a failure"
    );

    // a second tick must not report the same short timeouts again
    w.tick();
    assert_eq!(w.table.failed.len(), 2);
    assert_eq!(w.sock.sent.len(), 4);

    w.respond(&first, nodes[0].1, &MsgArgs::new().nid(&nodes[0].0));
    let st = status(&mut w);
    assert_eq!(
        st[0].branch_factor, 3,
        "the answered request gave its extra slot back"
    );
    assert_eq!(st[0].responses, 1);
}

/// When every request times out the lookup finishes, drops itself and
/// reports each node failed.
#[test]
fn test_lookup_ends_when_all_requests_time_out() {
    let (mut w, nodes) = lookup_world(3);
    start_get_peers(&mut w, node_id(0), AnnounceFlags::EMPTY);
    assert_eq!(w.sock.sent.len(), 3);
    w.advance(std::time::Duration::from_secs(15));
    w.tick();
    assert!(w.traversals.is_empty());
    assert_eq!(w.rpc.num_allocated_observers(), 0);
    assert_eq!(w.rpc.num_transactions(), 0);
    for (id, ep) in nodes {
        assert!(w.table.failed.contains(&(id, ep)));
    }
    assert!(peers_in(&w.take_events()).is_empty());
}

/// An error response fails the request like a timeout, at once.
#[test]
fn test_error_response_fails_the_request() {
    let (mut w, nodes) = lookup_world(1);
    start_get_peers(&mut w, node_id(0), AnnounceFlags::EMPTY);
    let request = w.sock.sent[0].1.clone();
    let mut err = Entry::dict();
    err.set("y", "e")
        .set("t", request.get("t").unwrap().clone())
        .set(
            "e",
            Entry::List(vec![
                Entry::Int(201),
                Entry::from("A Generic Error Ocurred"),
            ]),
        );
    w.incoming(nodes[0].1, &err);
    assert_eq!(w.table.failed, vec![nodes[0]]);
    assert!(
        w.table.seen.is_empty(),
        "an error is not proof of a working node"
    );
    assert!(w.traversals.is_empty());
}

/// With no nodes in the table, the router nodes seed the lookup; they are
/// flagged initial, so the restriction on one node per /24 does not apply.
#[test]
fn test_routers_seed_an_empty_lookup() {
    let mut w = World::v4();
    w.table.routers = vec![ep("5.5.5.1", 6881), ep("5.5.5.2", 6881)];
    start_get_peers(&mut w, node_id(0), AnnounceFlags::EMPTY);
    let dests: BTreeSet<SocketAddr> = w.sock.sent.iter().map(|(d, _)| *d).collect();
    assert_eq!(dests, w.table.routers.iter().copied().collect());
}

/// A lookup with nobody to ask ends immediately and leaves nothing behind.
#[test]
fn test_lookup_with_no_nodes_ends_immediately() {
    let mut w = World::v4();
    start_get_peers(&mut w, node_id(0), AnnounceFlags::EMPTY);
    assert!(w.sock.sent.is_empty());
    assert!(w.traversals.is_empty());
}

/// Nodes the IP filter blocks are not added from responses.
#[test]
fn test_ip_filter_blocks_discovered_nodes() {
    let (mut w, nodes) = lookup_world(1);
    start_get_peers(&mut w, node_id(0), AnnounceFlags::EMPTY);
    let request = w.sock.sent[0].1.clone();
    let blocked = ep("66.66.66.66", 1);
    let allowed = ep("77.77.77.77", 1);
    let packed = write_nodes([(&node_id(9), &blocked), (&node_id(10), &allowed)]);
    w.sock.clear();
    let blocked_ip = blocked.ip();
    let resp = cloudllm_dht::testing::build_response(
        request.get("t").and_then(Entry::as_bytes).unwrap(),
        &MsgArgs::new().nid(&nodes[0].0).nodes(&packed),
        &mut w.rng,
    );
    let enc = Encoded::from_entry(&resp);
    let n = enc.node();
    let filter = move |ip: IpAddr| ip == blocked_ip;
    w.run_with_filter(&filter, |ctx, trs| trs.incoming(ctx, nodes[0].1, &n));
    let dests: Vec<SocketAddr> = w.sock.sent.iter().map(|(d, _)| *d).collect();
    assert_eq!(dests, vec![allowed]);
}

/// A response that lists a peer string in the mainline compact form (one
/// string of 6-byte endpoints) from an IPv4 sender is split into peers.
#[test]
fn test_get_peers_reads_the_compact_peer_form() {
    let (mut w, nodes) = lookup_world(1);
    start_get_peers(&mut w, node_id(0), AnnounceFlags::EMPTY);
    let request = w.sock.sent[0].1.clone();
    let p1 = ep("1.2.3.4", 1000);
    let p2 = ep("5.6.7.8", 2000);
    let mut packed = Vec::new();
    cloudllm_dht::net::write_endpoint(&p1, &mut packed);
    cloudllm_dht::net::write_endpoint(&p2, &mut packed);
    packed.push(0xee); // a stray byte is ignored
    let mut a = MsgArgs::new().nid(&nodes[0].0);
    a.a.set("values", Entry::List(vec![Entry::Str(packed)]));
    w.respond(&request, nodes[0].1, &a);
    assert_eq!(peers_in(&w.take_events()), BTreeSet::from([p1, p2]));
}

/// A `values` entry of the wrong type is ignored; the response still
/// counts. A non-string in the list stops the parse and keeps what came
/// before.
#[test]
fn test_get_peers_tolerates_odd_values() {
    let (mut w, nodes) = lookup_world(1);
    start_get_peers(&mut w, node_id(0), AnnounceFlags::EMPTY);
    let request = w.sock.sent[0].1.clone();
    let mut a = MsgArgs::new().nid(&nodes[0].0);
    a.a.set("values", Entry::Int(5));
    w.respond(&request, nodes[0].1, &a);
    assert!(peers_in(&w.take_events()).is_empty());
    assert_eq!(w.table.seen.len(), 1);

    let (mut w, nodes) = lookup_world(1);
    start_get_peers(&mut w, node_id(0), AnnounceFlags::EMPTY);
    let request = w.sock.sent[0].1.clone();
    let good = ep("9.9.9.9", 99);
    let mut b = Vec::new();
    cloudllm_dht::net::write_endpoint(&good, &mut b);
    let mut a = MsgArgs::new().nid(&nodes[0].0);
    a.a.set(
        "values",
        Entry::List(vec![Entry::Str(b), Entry::Int(1), Entry::Str(vec![0; 6])]),
    );
    w.respond(&request, nodes[0].1, &a);
    assert_eq!(peers_in(&w.take_events()), BTreeSet::from([good]));
}

/// A node that answers without a write token is not announced to; one that
/// answers with a token is.
#[test]
fn test_announce_only_to_nodes_that_gave_a_token() {
    let (mut w, nodes) = lookup_world(2);
    w.run(|ctx, trs| {
        let t = announce(
            ctx,
            node_id(0),
            6881,
            AnnounceFlags::SEED | AnnounceFlags::IMPLIED_PORT,
        );
        trs.spawn(ctx, t);
    });
    assert_eq!(w.sock.sent.len(), 2);
    let r0 = w.take_packet(nodes[0].1).unwrap();
    let r1 = w.take_packet(nodes[1].1).unwrap();
    w.respond(
        &r0,
        nodes[0].1,
        &MsgArgs::new().nid(&nodes[0].0).token(b"tk"),
    );
    w.respond(&r1, nodes[1].1, &MsgArgs::new().nid(&nodes[1].0));
    assert_eq!(w.sock.sent.len(), 1);
    let (dst, p) = &w.sock.sent[0];
    assert_eq!(*dst, nodes[0].1);
    assert_eq!(query_name(p), "announce_peer");
    assert_eq!(
        args_of(p, "token").and_then(Entry::as_bytes),
        Some(&b"tk"[..])
    );
    assert_eq!(args_of(p, "seed"), Some(&Entry::Int(1)));
    assert_eq!(args_of(p, "implied_port"), Some(&Entry::Int(1)));
    assert_eq!(args_of(p, "port"), Some(&Entry::Int(6881)));
}

/// The announce_peer requests are not part of the lookup: it is dropped
/// when it finishes, and answering them later (or never) is harmless.
#[test]
fn test_announce_requests_outlive_the_lookup() {
    let (mut w, nodes) = lookup_world(1);
    w.run(|ctx, trs| {
        let t = announce(ctx, node_id(0), 6881, AnnounceFlags::EMPTY);
        trs.spawn(ctx, t);
    });
    let r = w.sock.sent[0].1.clone();
    w.sock.clear();
    w.respond(&r, nodes[0].1, &MsgArgs::new().nid(&nodes[0].0).token(b"x"));
    assert!(w.traversals.is_empty());
    assert_eq!(
        w.rpc.num_transactions(),
        1,
        "the announce_peer is outstanding"
    );
    let announce_packet = w.sock.sent[0].1.clone();
    w.respond(
        &announce_packet,
        nodes[0].1,
        &MsgArgs::new().nid(&nodes[0].0),
    );
    assert_eq!(w.rpc.num_transactions(), 0);
    assert_eq!(w.rpc.num_allocated_observers(), 0);
}

/// A bootstrap that finishes with candidates it never asked pings them, so
/// the routing table learns of them if they answer (`bootstrap::done`).
#[test]
fn test_bootstrap_pings_candidates_it_did_not_reach() {
    let mut w = World::v4();
    let seeds: Vec<SocketAddr> = (1..=20u8)
        .map(|i| ep(&format!("30.{i}.0.1"), 6881))
        .collect();
    w.run(|ctx, trs| {
        let t = bootstrap(ctx, &seeds, false);
        trs.spawn(ctx, t);
    });
    // 5 requests in flight (the default branch factor); answer until the
    // lookup has 8 live nodes
    let mut asked = BTreeSet::new();
    let mut answered = 0;
    while answered < 8 {
        asked.extend(w.sock.sent.iter().map(|(d, _)| *d));
        let (dst, packet) = w.sock.sent.remove(0);
        w.respond(&packet, dst, &MsgArgs::new());
        answered += 1;
    }
    asked.extend(w.sock.sent.iter().map(|(d, _)| *d));
    let st = status(&mut w);
    assert_eq!(
        (st[0].outstanding_requests, st[0].nodes_left),
        (0, 0),
        "the lookup is done and has emptied its list"
    );
    assert_eq!(
        w.traversals.len(),
        1,
        "but cancelled requests still refer to it"
    );
    w.advance(std::time::Duration::from_secs(1));
    w.tick();
    assert!(
        w.traversals.is_empty(),
        "tick drops the cancelled requests and with them the lookup"
    );
    let pings: BTreeSet<SocketAddr> = w.pings.iter().copied().collect();
    let never_asked: BTreeSet<SocketAddr> = seeds
        .iter()
        .copied()
        .filter(|s| !asked.contains(s))
        .collect();
    assert!(!never_asked.is_empty());
    assert_eq!(pings, never_asked);
}

/// ICMP unreachable fails the request to that node.
#[test]
fn test_unreachable_fails_the_request() {
    let (mut w, nodes) = lookup_world(1);
    start_get_peers(&mut w, node_id(0), AnnounceFlags::EMPTY);
    w.run(|ctx, trs| trs.unreachable(ctx, nodes[0].1));
    assert_eq!(w.table.failed, vec![nodes[0]]);
    assert!(w.traversals.is_empty());
}

/// libtorrent behaviour kept on purpose: peers in a response that arrives
/// after the lookup finished are still reported.
#[test]
fn test_late_response_still_reports_peers() {
    let (mut w, nodes) = lookup_world(2);
    w.settings.search_branching = 2;
    start_get_peers(&mut w, node_id(0), AnnounceFlags::EMPTY);
    // k = 1: one live node ends the lookup while the other request is open
    w.table.k = 1;
    let r0 = w.take_packet(nodes[0].1).unwrap();
    let r1 = w.take_packet(nodes[1].1).unwrap();
    w.respond(&r0, nodes[0].1, &MsgArgs::new().nid(&nodes[0].0));
    assert_eq!(
        w.traversals.len(),
        1,
        "finished, but a request is still in flight"
    );
    let late = ep("8.8.8.8", 8888);
    let peers = BTreeSet::from([late]);
    w.respond(
        &r1,
        nodes[1].1,
        &MsgArgs::new().nid(&nodes[1].0).peers(&peers),
    );
    assert_eq!(peers_in(&w.take_events()), BTreeSet::from([late]));
    assert!(w.traversals.is_empty(), "dropped with its last observer");
    assert_eq!(w.rpc.num_allocated_observers(), 0);
}

fn obfuscated_world() -> (World, Vec<(NodeId, SocketAddr)>) {
    let (mut w, nodes) = lookup_world(3);
    w.settings.privacy_lookups = true;
    (w, nodes)
}

/// A privacy lookup first asks about a target that shares only the leading
/// bits with the real one: the prefix shared with the node plus four (see
/// `obfuscate`).
#[test]
fn test_obfuscated_get_peers_hides_the_target() {
    let (mut w, nodes) = obfuscated_world();
    let target = to_hash("ffffffffffffffffffffffffffffffffffffffff");
    start_get_peers(&mut w, target, AnnounceFlags::EMPTY);
    assert_eq!(w.sock.sent.len(), 3);
    assert_eq!(status(&mut w)[0].kind, "get_peers [obfuscated]");
    for (dst, packet) in &w.sock.sent {
        let sent = args_of(packet, "info_hash")
            .and_then(Entry::as_bytes)
            .unwrap();
        let node_id = nodes.iter().find(|n| n.1 == *dst).unwrap().0;
        let shared = (target.0.iter().zip(node_id.0.iter()))
            .map(|(a, b)| (a ^ b).leading_zeros() as usize)
            .scan(true, |all, lz| {
                let r = if *all { Some(lz) } else { Some(0) };
                *all = *all && lz == 8;
                r
            })
            .sum::<usize>();
        // the bits we reveal (see `obfuscate`: libtorrent's distance_exp is
        // 159 - clz, so that is the shared prefix + 4), never more than 160
        let revealed = (shared + 4).min(160);
        let first_diff_bit = sent
            .iter()
            .zip(target.0.iter())
            .map(|(a, b)| (a ^ b).leading_zeros() as usize)
            .scan(true, |all, lz| {
                let r = if *all { Some(lz) } else { Some(0) };
                *all = *all && lz == 8;
                r
            })
            .sum::<usize>();
        assert!(
            first_diff_bit >= revealed.min(160),
            "{first_diff_bit} < {revealed}"
        );
        assert_ne!(sent, &target.0[..], "the real target is not sent");
    }
    let outgoing: Vec<_> = w
        .take_events()
        .into_iter()
        .filter(|e| matches!(e, Event::OutgoingGetPeers { .. }))
        .collect();
    assert_eq!(outgoing.len(), 3);
}

/// When the obfuscated phase ends, a plain lookup starts from the live
/// nodes and the peers it finds are what the caller gets. The first phase
/// reports no peers.
#[test]
fn test_obfuscated_get_peers_hands_over_to_a_plain_lookup() {
    let (mut w, nodes) = obfuscated_world();
    let target = to_hash("ffffffffffffffffffffffffffffffffffffffff");
    start_get_peers(&mut w, target, AnnounceFlags::EMPTY);
    let ids: Vec<NodeId> = nodes.iter().map(|n| n.0).collect();
    // phase one: everyone answers; one even claims to have peers, which an
    // obfuscated observer does not read
    let packets: Vec<_> = std::mem::take(&mut w.sock.sent);
    let stray = BTreeSet::from([ep("4.4.4.4", 4)]);
    for ((dst, packet), id) in packets.iter().zip(ids.iter()) {
        let _ = id;
        let nid = nodes.iter().find(|n| n.1 == *dst).unwrap().0;
        w.respond(packet, *dst, &MsgArgs::new().nid(&nid).peers(&stray));
    }
    assert!(peers_in(&w.take_events()).is_empty());
    // phase two: plain get_peers with the real info-hash to the same nodes
    assert_eq!(w.sock.sent.len(), 3);
    for (_, p) in &w.sock.sent {
        assert_eq!(query_name(p), "get_peers");
        assert_eq!(
            args_of(p, "info_hash").and_then(Entry::as_bytes),
            Some(&target.0[..])
        );
    }
    assert_eq!(status(&mut w)[0].kind, "get_peers");
    let peers = BTreeSet::from([ep("6.6.6.6", 6)]);
    let packets: Vec<_> = std::mem::take(&mut w.sock.sent);
    for (dst, packet) in &packets {
        let nid = nodes.iter().find(|n| n.1 == *dst).unwrap().0;
        w.respond(packet, *dst, &MsgArgs::new().nid(&nid).peers(&peers));
    }
    assert_eq!(peers_in(&w.take_events()), peers);
    assert!(w.traversals.is_empty());
}

fn sample_desc() -> Vec<KeyDesc> {
    use NodeKind::{Dict, Str};
    vec![
        KeyDesc::new("y", Some(Str), 1, KeyFlags::NONE),
        KeyDesc::new("t", Some(Str), 2, KeyFlags::NONE),
        KeyDesc::new("q", Some(Str), 17, KeyFlags::NONE),
        KeyDesc::new("a", Some(Dict), 0, KeyFlags::PARSE_CHILDREN),
        KeyDesc::new("id", Some(Str), 20, KeyFlags::NONE),
        KeyDesc::new("target", Some(Str), 20, KeyFlags::LAST_CHILD),
    ]
}

fn start_sample(w: &mut World, to: SocketAddr, target: NodeId) -> Entry {
    w.run(|ctx, trs| {
        let t = sample_infohashes(ctx, to, target);
        trs.spawn(ctx, t);
    });
    assert_eq!(w.sock.sent.len(), 1);
    assert_eq!(w.sock.sent[0].0, to);
    w.sock.sent[0].1.clone()
}

/// A BEP 51 request goes to the given node with the sample target, and the
/// answer (interval, count, samples, nodes) arrives as one event. Ports
/// `sample_infohashes` from `test_dht.cpp`.
#[test]
fn test_sample_infohashes() {
    let mut w = World::v4();
    let initial_node = ep("21.1.1.1", 6881);
    let target = to_hash("0123456789abcdef0123456789abcdef01234567");
    let request = start_sample(&mut w, initial_node, target);
    let enc = Encoded::from_entry(&request);
    let n = enc.node();
    let found = verify_message(&n, &sample_desc()).expect("a valid sample_infohashes request");
    assert_eq!(found[0].unwrap().string_value(), b"q");
    assert_eq!(found[2].unwrap().string_value(), b"sample_infohashes");
    assert_eq!(found[5].unwrap().string_value(), &target.0[..]);

    let nid = w.rng.random_hash();
    let (h1, h2) = (w.rng.random_hash(), w.rng.random_hash());
    let (ep1, ep2) = (ep("22.2.2.2", 2222), ep("23.3.3.3", 3333));
    let sample = to_hash("1000000000000000000000000000000000000001");
    let packed = write_nodes([(&h1, &ep1), (&h2, &ep2)]);
    w.sock.clear();
    w.respond(
        &request,
        initial_node,
        &MsgArgs::new()
            .nid(&nid)
            .interval(10)
            .num(2)
            .samples(&[sample])
            .nodes(&packed),
    );
    assert!(
        w.sock.sent.is_empty(),
        "the reported nodes are not followed"
    );
    let events = w.take_events();
    assert_eq!(
        events,
        vec![Event::SampleInfohashes {
            from: initial_node,
            nid,
            interval: std::time::Duration::from_secs(10),
            num: 2,
            samples: vec![sample],
            nodes: vec![(h1, ep1), (h2, ep2)],
        }]
    );
    assert!(w.traversals.is_empty());
    assert_eq!(w.rpc.num_allocated_observers(), 0);
}

/// A response with an invalid interval, count or sample string fails the
/// request instead of reporting: no event.
#[test]
fn test_sample_infohashes_rejects_bad_responses() {
    let sample = to_hash("1000000000000000000000000000000000000001");
    let good = MsgArgs::new().interval(10).num(2).samples(&[sample]);
    let bad: Vec<(&str, MsgArgs)> = vec![
        (
            "interval too large",
            MsgArgs::new().interval(21601).num(2).samples(&[sample]),
        ),
        (
            "negative interval",
            MsgArgs::new().interval(-1).num(2).samples(&[sample]),
        ),
        ("no interval", {
            let mut a = good.clone();
            if let Entry::Dict(m) = &mut a.a {
                m.remove(&b"interval"[..]);
            }
            a
        }),
        (
            "negative num",
            MsgArgs::new().interval(10).num(-1).samples(&[sample]),
        ),
        (
            "num beyond i32",
            MsgArgs::new()
                .interval(10)
                .num(i64::from(i32::MAX) + 1)
                .samples(&[sample]),
        ),
        ("no samples", {
            let mut a = good.clone();
            if let Entry::Dict(m) = &mut a.a {
                m.remove(&b"samples"[..]);
            }
            a
        }),
        ("samples not a multiple of 20", {
            let mut a = good.clone();
            a.a.set("samples", vec![0u8; 21]);
            a
        }),
    ];
    for (why, args) in bad {
        let mut w = World::v4();
        let node = ep("21.1.1.1", 6881);
        let request = start_sample(
            &mut w,
            node,
            to_hash("00000000000000000000000000000000000000ff"),
        );
        w.respond(&request, node, &args);
        assert!(w.take_events().is_empty(), "{why}");
        assert!(w.traversals.is_empty(), "{why}");
    }
    // the boundary values are fine
    for (interval, num) in [(0, 0), (21600, i64::from(i32::MAX))] {
        let mut w = World::v4();
        let node = ep("21.1.1.1", 6881);
        let request = start_sample(
            &mut w,
            node,
            to_hash("00000000000000000000000000000000000000ff"),
        );
        w.respond(
            &request,
            node,
            &MsgArgs::new().interval(interval).num(num).samples(&[]),
        );
        assert_eq!(w.take_events().len(), 1, "interval {interval}, num {num}");
    }
}

/// An empty `samples` string is a valid (empty) sample.
#[test]
fn test_sample_infohashes_empty_sample_is_valid() {
    let mut w = World::v4();
    let node = ep("21.1.1.1", 6881);
    let request = start_sample(&mut w, node, Sha1Hash::MIN);
    w.respond(
        &request,
        node,
        &MsgArgs::new().interval(5).num(0).samples(&[]),
    );
    match &w.take_events()[..] {
        [Event::SampleInfohashes {
            samples, num: 0, ..
        }] => assert!(samples.is_empty()),
        other => panic!("{other:?}"),
    }
}

/// A sample request that times out reports nothing and leaves nothing
/// behind.
#[test]
fn test_sample_infohashes_timeout() {
    let mut w = World::v4();
    start_sample(&mut w, ep("21.1.1.1", 6881), Sha1Hash::MIN);
    w.advance(std::time::Duration::from_secs(15));
    w.tick();
    assert!(w.take_events().is_empty());
    assert!(w.traversals.is_empty());
    assert_eq!(w.rpc.num_allocated_observers(), 0);
}

/// A direct request is delivered as sent (with `y`, `t` and `id` added) and
/// the response comes back whole, tagged with the caller's token. Ports the
/// first half of `direct_dht_request`, with the responder simulated by
/// hand since query handling belongs to the node.
#[test]
fn test_direct_dht_request() {
    let mut w = World::v4();
    let responder = ep("127.0.0.1", 42434);
    let mut q = Entry::dict();
    q.set("q", "test_good");
    w.run(|ctx, trs| {
        let t = direct_request(ctx, responder, q, 12345);
        trs.spawn(ctx, t);
    });
    assert_eq!(w.sock.sent.len(), 1);
    assert_eq!(w.sock.sent[0].0, responder);
    let request = w.sock.sent[0].1.clone();
    assert_eq!(query_name(&request), "test_good");
    assert_eq!(request.get("y").and_then(Entry::as_bytes), Some(&b"q"[..]));

    let mut args = MsgArgs::new();
    args.a.set("good", Entry::Int(1));
    w.respond(&request, responder, &args);
    match &w.take_events()[..] {
        [Event::DirectResponse {
            token: 12345,
            from,
            reply: Some(r),
        }] => {
            assert_eq!(*from, responder);
            assert_eq!(r.get("r").and_then(|r| r.get("good")), Some(&Entry::Int(1)));
            assert_eq!(r.get("y").and_then(Entry::as_bytes), Some(&b"r"[..]));
        }
        other => panic!("{other:?}"),
    }
    assert!(w.traversals.is_empty());
    assert_eq!(w.rpc.num_allocated_observers(), 0);
}

/// A direct request nobody answers ends with `reply: None` after the
/// timeout and does not mark the node failed. Ports the second half of
/// `direct_dht_request`.
#[test]
fn test_direct_dht_request_failed() {
    let mut w = World::v4();
    let dead = ep("127.0.0.1", 53545);
    let mut q = Entry::dict();
    q.set("q", "test_good");
    w.run(|ctx, trs| {
        let t = direct_request(ctx, dead, q, 123_456);
        trs.spawn(ctx, t);
    });
    w.advance(std::time::Duration::from_secs(15));
    w.tick();
    assert_eq!(
        w.take_events(),
        vec![Event::DirectResponse {
            token: 123_456,
            from: dead,
            reply: None
        }]
    );
    assert!(
        w.table.failed.iter().all(|f| f.0 == Sha1Hash::MIN),
        "no failure is reported for the real node"
    );
    assert!(w.traversals.is_empty());
}

/// An error response to a direct request is delivered as "no reply", like a
/// timeout.
#[test]
fn test_direct_dht_request_error_response() {
    let mut w = World::v4();
    let node = ep("127.0.0.1", 42434);
    let mut q = Entry::dict();
    q.set("q", "x");
    w.run(|ctx, trs| {
        let t = direct_request(ctx, node, q, 7);
        trs.spawn(ctx, t);
    });
    let request = w.sock.sent[0].1.clone();
    let mut err = Entry::dict();
    err.set("y", "e")
        .set("t", request.get("t").unwrap().clone())
        .set(
            "e",
            Entry::List(vec![Entry::Int(204), Entry::from("Method Unknown")]),
        );
    w.incoming(node, &err);
    assert_eq!(
        w.take_events(),
        vec![Event::DirectResponse {
            token: 7,
            from: node,
            reply: None
        }]
    );
}
