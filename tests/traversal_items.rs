//! Tests for the BEP 44 traversals: `get_item`, `put_data` and the put
//! entry points, ported from `test_dht.cpp` (`mutable_get_*`,
//! `immutable_get`, `immutable_put`, `mutable_put`, `traversal_done`;
//! libtorrent RC_2_1, `86d573f2631b0162d3cca5e257217eaf530fdcba`) plus tests
//! of the item-specific rules: signature checks, sequence numbers, the
//! authoritative callback.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cloudllm_dht::bencode::{Entry, NodeKind};
use cloudllm_dht::events::Event;
use cloudllm_dht::item::{immutable_item_target_id, item_target_id, sign_mutable_item, Item};
use cloudllm_dht::msg::{verify_message, KeyDesc, KeyFlags};
use cloudllm_dht::net::{write_nodes, Protocol};
use cloudllm_dht::node_id::NodeId;
use cloudllm_dht::rng::Rng;
use cloudllm_dht::testing::{ep, rand_v4, rand_v6, test_keypair, to_hash, Encoded, MsgArgs};
use cloudllm_dht::traversal::get_item::{get_immutable, get_mutable};
use cloudllm_dht::traversal::put_data::{put_immutable, put_mutable};
use cloudllm_dht::types::SequenceNumber;
use cloudllm_dht::Sha1Hash;

use common::World;

/// One of the test items of `test_dht.cpp`: a dictionary and its target.
struct TestItem {
    ent: Entry,
    target: NodeId,
}

fn make_item(rng: &mut dyn Rng, num: i64) -> TestItem {
    let next = rng.random_hash();
    let mut ent = Entry::dict();
    ent.set("next", next.0.to_vec())
        .set("A", "a")
        .set("B", "b")
        .set("num_peers", Entry::Int(num));
    let target = immutable_item_target_id(&ent.encode());
    TestItem { ent, target }
}

fn items(w: &mut World) -> Vec<TestItem> {
    (1..=8).map(|n| make_item(&mut w.rng, n)).collect()
}

/// `build_nodes()`: eight nodes whose IDs are the item targets.
fn build_nodes(items: &[TestItem]) -> Vec<(NodeId, SocketAddr)> {
    (0..8u8)
        .map(|i| {
            let o = i + 1;
            (
                items[usize::from(i)].target,
                ep(&format!("{o}.{o}.{o}.{o}"), 1231 + u16::from(i)),
            )
        })
        .collect()
}

fn get_desc() -> Vec<KeyDesc> {
    use NodeKind::{Dict, Str};
    vec![
        KeyDesc::new("y", Some(Str), 1, KeyFlags::NONE),
        KeyDesc::new("t", Some(Str), 2, KeyFlags::NONE),
        KeyDesc::new("q", Some(Str), 3, KeyFlags::NONE),
        KeyDesc::new("a", Some(Dict), 0, KeyFlags::PARSE_CHILDREN),
        KeyDesc::new("id", Some(Str), 20, KeyFlags::NONE),
        KeyDesc::new("target", Some(Str), 20, KeyFlags::LAST_CHILD),
    ]
}

fn assert_get_request(request: &Entry, target: &NodeId) {
    let enc = Encoded::from_entry(request);
    let n = enc.node();
    let found = verify_message(&n, &get_desc())
        .unwrap_or_else(|e| panic!("invalid get request {request}: {e}"));
    assert_eq!(found[0].unwrap().string_value(), b"q");
    assert_eq!(found[2].unwrap().string_value(), b"get");
    assert_eq!(found[5].unwrap().string_value(), &target.0[..]);
}

fn put_mutable_desc() -> Vec<KeyDesc> {
    use NodeKind::{Dict, Int, Str};
    vec![
        KeyDesc::new("y", Some(Str), 1, KeyFlags::NONE),
        KeyDesc::new("t", Some(Str), 2, KeyFlags::NONE),
        KeyDesc::new("q", Some(Str), 3, KeyFlags::NONE),
        KeyDesc::new("a", Some(Dict), 0, KeyFlags::PARSE_CHILDREN),
        KeyDesc::new("id", Some(Str), 20, KeyFlags::NONE),
        KeyDesc::new("cas", Some(Str), 20, KeyFlags::OPTIONAL),
        KeyDesc::new("k", Some(Str), 32, KeyFlags::NONE),
        KeyDesc::new("seq", Some(Int), 0, KeyFlags::NONE),
        KeyDesc::new("sig", Some(Str), 64, KeyFlags::NONE),
        KeyDesc::new("token", Some(Str), 2, KeyFlags::NONE),
        KeyDesc::new("v", None, 0, KeyFlags::LAST_CHILD),
    ]
}

fn put_immutable_desc() -> Vec<KeyDesc> {
    use NodeKind::{Dict, Str};
    vec![
        KeyDesc::new("y", Some(Str), 1, KeyFlags::NONE),
        KeyDesc::new("t", Some(Str), 2, KeyFlags::NONE),
        KeyDesc::new("q", Some(Str), 3, KeyFlags::NONE),
        KeyDesc::new("a", Some(Dict), 0, KeyFlags::PARSE_CHILDREN),
        KeyDesc::new("id", Some(Str), 20, KeyFlags::NONE),
        KeyDesc::new("token", Some(Str), 2, KeyFlags::NONE),
        KeyDesc::new("v", None, 0, KeyFlags::LAST_CHILD),
    ]
}

/// The authoritative, non-empty items among the events (the callback of
/// libtorrent's `get_mutable_item_cb` and `get_immutable_item_cb`).
fn authoritative_items(events: &[Event]) -> Vec<Item> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::GetItemDone {
                item,
                authoritative: true,
                ..
            } if !item.is_empty() => Some(item.clone()),
            _ => None,
        })
        .collect()
}

fn world_for(protocol: Protocol) -> World {
    match protocol {
        Protocol::V4 => World::v4(),
        Protocol::V6 => World::v6(),
    }
}

fn run_mutable_get(
    rand: fn(&mut dyn Rng) -> std::net::IpAddr,
    protocol: Protocol,
    with_salt: bool,
) {
    let mut w = world_for(protocol);
    let its = items(&mut w);
    let (pk, sk) = test_keypair();
    let seq = SequenceNumber(4);
    let salt: &[u8] = if with_salt { b"foobar" } else { b"" };

    let initial_node = SocketAddr::new(rand(&mut w.rng), 1234);
    let initial_node_id = to_hash("1111111111222222222233333333334444444444");
    w.table.add_node(initial_node_id, initial_node);

    // a put of an item with `salt`, started with an empty salt: the lookup
    // phase sends one request, to the only node we know
    let put_item = Item::signed(its[0].ent.clone(), salt, seq, &pk, &sk).unwrap();
    let data_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&data_calls);
    w.run(|ctx, trs| {
        let t = put_mutable(
            ctx,
            pk,
            b"",
            Box::new(move |i| {
                calls.fetch_add(1, Ordering::SeqCst);
                *i = put_item.clone();
            }),
        );
        trs.spawn(ctx, t);
    });
    assert_eq!(w.sock.sent.len(), 1);

    // mutable get
    w.sock.clear();
    w.run(|ctx, trs| {
        let t = get_mutable(ctx, pk, salt);
        trs.spawn(ctx, t);
    });
    assert_eq!(w.sock.sent.len(), 1);
    assert_eq!(w.sock.sent[0].0, initial_node);
    let request = w.sock.sent[0].1.clone();
    assert_get_request(&request, &item_target_id(salt, &pk));

    w.sock.clear();
    let sig = sign_mutable_item(&its[0].ent.encode(), salt, seq, &pk, &sk);
    let args = MsgArgs::new()
        .token(b"10")
        .port(1234)
        .value(its[0].ent.clone())
        .key(&pk)
        .sig(&sig)
        .salt(salt)
        .seq(seq);
    w.respond(&request, initial_node, &args);

    assert!(w.sock.sent.is_empty());
    let got = authoritative_items(&w.take_events());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].value(), &its[0].ent);
    assert_eq!(*got[0].pk(), pk);
    assert_eq!(*got[0].sig(), sig);
    assert_eq!(got[0].seq(), seq);
    assert_eq!(got[0].salt(), salt);
    assert_eq!(
        data_calls.load(Ordering::SeqCst),
        0,
        "the put's own lookup is still waiting"
    );
}

/// Ports `mutable_get_v4`.
#[test]
fn test_mutable_get_v4() {
    run_mutable_get(rand_v4, Protocol::V4, false);
}

/// Ports `mutable_get_salt_v4`.
#[test]
fn test_mutable_get_salt_v4() {
    run_mutable_get(rand_v4, Protocol::V4, true);
}

/// Ports `mutable_get_v6`.
#[test]
fn test_mutable_get_v6() {
    run_mutable_get(rand_v6, Protocol::V6, false);
}

/// Ports `mutable_get_salt_v6`.
#[test]
fn test_mutable_get_salt_v6() {
    run_mutable_get(rand_v6, Protocol::V6, true);
}

/// An immutable item arrives, is checked against its target, and ends the
/// lookup at once. Ports `immutable_get`.
#[test]
fn test_immutable_get() {
    let mut w = World::v4();
    let its = items(&mut w);
    let initial_node = ep("4.4.4.4", 1234);
    w.table.add_node(
        to_hash("1111111111222222222233333333334444444444"),
        initial_node,
    );

    w.run(|ctx, trs| {
        let t = get_immutable(ctx, its[0].target);
        trs.spawn(ctx, t);
    });
    assert_eq!(w.sock.sent.len(), 1);
    assert_eq!(w.sock.sent[0].0, initial_node);
    let request = w.sock.sent[0].1.clone();
    assert_get_request(&request, &its[0].target);

    w.sock.clear();
    w.respond(
        &request,
        initial_node,
        &MsgArgs::new()
            .token(b"10")
            .port(1234)
            .value(its[0].ent.clone()),
    );
    assert!(w.sock.sent.is_empty());
    let got = authoritative_items(&w.take_events());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].value(), &its[0].ent);
    assert!(!got[0].is_mutable());
    assert!(w.traversals.is_empty());
}

/// A value that does not hash to the target is not the item, whoever sends
/// it: the lookup goes on and ends with an empty, authoritative result.
#[test]
fn test_immutable_get_ignores_a_value_of_the_wrong_hash() {
    let mut w = World::v4();
    let its = items(&mut w);
    let node = ep("4.4.4.4", 1234);
    w.table.add_node(Sha1Hash([0x11; 20]), node);
    w.run(|ctx, trs| {
        let t = get_immutable(ctx, its[0].target);
        trs.spawn(ctx, t);
    });
    let request = w.sock.sent[0].1.clone();
    w.respond(
        &request,
        node,
        &MsgArgs::new().token(b"10").value(its[1].ent.clone()),
    );
    let events = w.take_events();
    assert!(authoritative_items(&events).is_empty());
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::GetItemDone { item, authoritative: true, .. } if item.is_empty()
        )),
        "the lookup ends and reports that nothing was found"
    );
}

/// The mutable lookup keeps the highest sequence number among the answers,
/// reports each improvement as non-authoritative, and the winner at the
/// end as authoritative.
#[test]
fn test_mutable_get_keeps_the_highest_sequence_number() {
    let mut w = World::v4();
    let its = items(&mut w);
    let (pk, sk) = test_keypair();
    let nodes: Vec<(NodeId, SocketAddr)> = (1..=3u8)
        .map(|i| (Sha1Hash([i; 20]), ep(&format!("{i}0.0.0.1"), 6881)))
        .collect();
    for n in &nodes {
        w.table.add_node(n.0, n.1);
    }
    w.run(|ctx, trs| {
        let t = get_mutable(ctx, pk, b"");
        trs.spawn(ctx, t);
    });
    assert_eq!(w.sock.sent.len(), 3);
    let requests: Vec<Entry> = nodes.iter().map(|n| w.take_packet(n.1).unwrap()).collect();

    let answer = |seq: i64, ent: &Entry| {
        let sig = sign_mutable_item(&ent.encode(), b"", SequenceNumber(seq), &pk, &sk);
        MsgArgs::new()
            .token(b"tk")
            .value(ent.clone())
            .key(&pk)
            .sig(&sig)
            .seq(SequenceNumber(seq))
    };
    // seq 5 first, then a stale 3 (ignored), then 9
    w.respond(
        &requests[0],
        nodes[0].1,
        &answer(5, &its[0].ent).nid(&nodes[0].0),
    );
    w.respond(
        &requests[1],
        nodes[1].1,
        &answer(3, &its[1].ent).nid(&nodes[1].0),
    );
    w.respond(
        &requests[2],
        nodes[2].1,
        &answer(9, &its[2].ent).nid(&nodes[2].0),
    );

    let events = w.take_events();
    let seqs: Vec<(i64, bool)> = events
        .iter()
        .filter_map(|e| match e {
            Event::GetItemDone {
                item,
                authoritative,
                ..
            } if !item.is_empty() => Some((item.seq().0, *authoritative)),
            _ => None,
        })
        .collect();
    assert_eq!(seqs, vec![(5, false), (9, false), (9, true)]);
}

/// A mutable answer with a bad signature, for the wrong key, or with `k` and
/// `sig` but no `seq` is not accepted; the last of these also fails the
/// request.
#[test]
fn test_mutable_get_rejects_forged_answers() {
    let (pk, sk) = test_keypair();
    let other = Sha1Hash([0xee; 20]); // not a key, just different bytes
    let _ = other;
    let ent = {
        let mut e = Entry::dict();
        e.set("a", "b");
        e
    };
    let good_sig = sign_mutable_item(&ent.encode(), b"", SequenceNumber(1), &pk, &sk);
    let mut bad_sig = good_sig;
    bad_sig.0[0] ^= 1;

    for (why, args, fails_request) in [
        (
            "bad signature",
            MsgArgs::new()
                .value(ent.clone())
                .key(&pk)
                .sig(&bad_sig)
                .seq(SequenceNumber(1)),
            false,
        ),
        (
            "signature of another sequence number",
            MsgArgs::new()
                .value(ent.clone())
                .key(&pk)
                .sig(&good_sig)
                .seq(SequenceNumber(2)),
            false,
        ),
        (
            "key of another item",
            MsgArgs::new()
                .value(ent.clone())
                .key(&cloudllm_dht::types::PublicKey([9; 32]))
                .sig(&good_sig)
                .seq(SequenceNumber(1)),
            false,
        ),
        (
            "k and sig without seq",
            MsgArgs::new().value(ent.clone()).key(&pk).sig(&good_sig),
            true,
        ),
    ] {
        let mut w = World::v4();
        let node = ep("4.4.4.4", 1234);
        w.table.add_node(Sha1Hash([0x11; 20]), node);
        w.run(|ctx, trs| {
            let t = get_mutable(ctx, pk, b"");
            trs.spawn(ctx, t);
        });
        let request = w.sock.sent[0].1.clone();
        w.respond(&request, node, &args.token(b"10"));
        let events = w.take_events();
        assert!(authoritative_items(&events).is_empty(), "{why}");
        assert_eq!(!w.table.failed.is_empty(), fails_request, "{why}");
    }
}

fn run_immutable_put(loop_n: usize) {
    let mut w = World::v4();
    w.settings.search_branching = 8;
    let its = items(&mut w);
    let nodes = build_nodes(&its);
    for n in &nodes {
        w.table.add_node(n.0, n.1);
    }
    let value = Entry::from("Hello world");
    let flat = value.encode();
    let target = immutable_item_target_id(&flat);

    w.run(|ctx, trs| {
        let t = put_immutable(ctx, target, value.clone());
        trs.spawn(ctx, t);
    });
    assert_eq!(w.sock.sent.len(), 8, "a get to each node");

    for (idx, node) in nodes.iter().enumerate() {
        let request = w.take_packet(node.1).expect("a get request for this node");
        assert_get_request(&request, &target);
        let tok = format!("{idx:02}");
        let args = MsgArgs::new()
            .token(tok.as_bytes())
            .port(1234)
            .nid(&node.0)
            .nodes(&write_nodes([(&node.0, &node.1)]));
        w.respond(&request, node.1, &args);
    }
    assert_eq!(w.sock.sent.len(), 8, "a put to each node");

    for (idx, node) in nodes.iter().enumerate() {
        let request = w.take_packet(node.1).expect("a put request for this node");
        let enc = Encoded::from_entry(&request);
        let n = enc.node();
        let found = verify_message(&n, &put_immutable_desc())
            .unwrap_or_else(|e| panic!("invalid immutable put request {request}: {e}"));
        assert_eq!(found[0].unwrap().string_value(), b"q");
        assert_eq!(found[2].unwrap().string_value(), b"put");
        assert_eq!(found[6].unwrap().data_section(), &flat[..]);
        assert_eq!(
            found[5].unwrap().string_value(),
            format!("{idx:02}").as_bytes()
        );
        if idx < loop_n {
            w.respond(&request, node.1, &MsgArgs::new());
        }
    }
    // the others never answer
    w.advance(Duration::from_secs(15));
    w.tick();
    let done: Vec<usize> = w
        .take_events()
        .iter()
        .filter_map(|e| match e {
            Event::PutDone {
                responses,
                target: t,
                ..
            } => {
                assert_eq!(*t, target);
                Some(*responses)
            }
            _ => None,
        })
        .collect();
    assert_eq!(done, vec![loop_n]);
    assert!(w.traversals.is_empty());
    assert_eq!(w.rpc.num_allocated_observers(), 0);
}

/// An immutable put looks the target up, then writes the value with each
/// node's token to the eight closest nodes, and reports how many answered.
/// Ports `immutable_put` (nine rounds, 0 to 8 nodes acknowledging).
#[test]
fn test_immutable_put() {
    for loop_n in 0..9 {
        run_immutable_put(loop_n);
    }
}

fn run_mutable_put(loop_n: usize) {
    let mut w = World::v4();
    w.settings.search_branching = 8;
    let its = items(&mut w);
    let nodes = build_nodes(&its);
    for n in &nodes {
        w.table.add_node(n.0, n.1);
    }
    let (pk, sk) = test_keypair();
    let seq = SequenceNumber(4);
    let put_item = Item::signed(its[0].ent.clone(), b"", seq, &pk, &sk).unwrap();
    let sig = *put_item.sig();
    let seen: Arc<Mutex<Vec<Item>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_in_cb = Arc::clone(&seen);
    let item_in_cb = put_item.clone();
    w.run(|ctx, trs| {
        let t = put_mutable(
            ctx,
            pk,
            b"",
            Box::new(move |i| {
                if !i.is_empty() {
                    seen_in_cb.lock().unwrap().push(i.clone());
                }
                *i = item_in_cb.clone();
            }),
        );
        trs.spawn(ctx, t);
    });
    assert_eq!(w.sock.sent.len(), 8);

    for (idx, node) in nodes.iter().enumerate() {
        let request = w.take_packet(node.1).expect("a get request for this node");
        assert_get_request(&request, &item_target_id(b"", &pk));
        let tok = format!("{idx:02}");
        let args = MsgArgs::new()
            .token(tok.as_bytes())
            .port(1234)
            .nid(&node.0)
            .nodes(&write_nodes([(&node.0, &node.1)]));
        w.respond(&request, node.1, &args);
    }
    assert_eq!(w.sock.sent.len(), 8);
    assert!(
        seen.lock().unwrap().is_empty(),
        "nobody had the item, so the callback saw an empty one"
    );

    let itemv = its[0].ent.encode();
    for (idx, node) in nodes.iter().enumerate() {
        let request = w.take_packet(node.1).expect("a put request for this node");
        let enc = Encoded::from_entry(&request);
        let n = enc.node();
        let found = verify_message(&n, &put_mutable_desc())
            .unwrap_or_else(|e| panic!("invalid put request {request}: {e}"));
        assert_eq!(found[0].unwrap().string_value(), b"q");
        assert_eq!(found[2].unwrap().string_value(), b"put");
        assert_eq!(found[6].unwrap().string_value(), &pk.0[..]);
        assert_eq!(found[7].unwrap().int_value(), seq.0);
        assert_eq!(found[8].unwrap().string_value(), &sig.0[..]);
        assert_eq!(found[10].unwrap().data_section(), &itemv[..]);
        assert_eq!(
            found[9].unwrap().string_value(),
            format!("{idx:02}").as_bytes()
        );
        assert!(
            n.dict_find_dict(b"a").unwrap().dict_find(b"salt").is_none(),
            "no salt, no salt key"
        );
        if idx < loop_n {
            w.respond(&request, node.1, &MsgArgs::new());
        }
    }
    w.advance(Duration::from_secs(15));
    w.tick();
    let done: Vec<usize> = w
        .take_events()
        .iter()
        .filter_map(|e| match e {
            Event::PutDone {
                responses, item, ..
            } => {
                assert_eq!(*item, put_item);
                Some(*responses)
            }
            _ => None,
        })
        .collect();
    assert_eq!(done, vec![loop_n]);
}

/// A mutable put: the lookup finds no item, the callback supplies the one to
/// store, and the put carries its key, sequence number, signature and value.
/// Ports `mutable_put`.
#[test]
fn test_mutable_put() {
    for loop_n in 0..9 {
        run_mutable_put(loop_n);
    }
}

/// A salt is sent as `salt` only when there is one.
#[test]
fn test_mutable_put_sends_the_salt() {
    let mut w = World::v4();
    w.settings.search_branching = 8;
    let its = items(&mut w);
    let node = (its[0].target, ep("1.1.1.1", 1231));
    w.table.add_node(node.0, node.1);
    let (pk, sk) = test_keypair();
    let put_item =
        Item::signed(its[0].ent.clone(), b"foobar", SequenceNumber(1), &pk, &sk).unwrap();
    w.run(|ctx, trs| {
        let t = put_mutable(ctx, pk, b"foobar", Box::new(move |i| *i = put_item.clone()));
        trs.spawn(ctx, t);
    });
    let request = w.take_packet(node.1).unwrap();
    w.respond(&request, node.1, &MsgArgs::new().token(b"tk").nid(&node.0));
    let put = w.take_packet(node.1).expect("a put");
    assert_eq!(
        put.get("a").unwrap().get("salt").and_then(Entry::as_bytes),
        Some(&b"foobar"[..])
    );
}

/// The data callback of a mutable put sees the authoritative item the
/// network holds, which is how a caller computes the next sequence number.
#[test]
fn test_mutable_put_callback_sees_the_current_item() {
    let mut w = World::v4();
    let its = items(&mut w);
    let node = (Sha1Hash([0x42; 20]), ep("1.1.1.1", 1231));
    w.table.add_node(node.0, node.1);
    let (pk, sk) = test_keypair();
    let current = Item::signed(its[0].ent.clone(), b"", SequenceNumber(7), &pk, &sk).unwrap();
    let seen = Arc::new(Mutex::new(None));
    let seen_cb = Arc::clone(&seen);
    let (pk2, sk2) = (pk, sk);
    let next_value = its[1].ent.clone();
    w.run(|ctx, trs| {
        let t = put_mutable(
            ctx,
            pk,
            b"",
            Box::new(move |i| {
                *seen_cb.lock().unwrap() = Some(i.clone());
                let next = i.seq().next();
                *i = Item::signed(next_value.clone(), b"", next, &pk2, &sk2).unwrap();
            }),
        );
        trs.spawn(ctx, t);
    });
    let request = w.take_packet(node.1).unwrap();
    let args = MsgArgs::new()
        .token(b"tk")
        .nid(&node.0)
        .value(current.value().clone())
        .key(&pk)
        .sig(current.sig())
        .seq(current.seq());
    w.respond(&request, node.1, &args);
    assert_eq!(
        seen.lock().unwrap().as_ref().map(Item::seq),
        Some(SequenceNumber(7))
    );
    let put = w.take_packet(node.1).expect("a put");
    assert_eq!(put.get("a").unwrap().get("seq"), Some(&Entry::Int(8)));
}

/// `done()` runs once even when the farthest node answers after the lookup
/// completed (libtorrent PR 252): the data callback is called once and the
/// put goes to the eight nodes that answered in time. Ports
/// `traversal_done`.
#[test]
fn test_traversal_done() {
    let mut w = World::v4();
    // the branching factor is k, to make this a little easier
    w.settings.search_branching = 8;
    let (pk, sk) = test_keypair();
    let seq = SequenceNumber(4);
    let its = items(&mut w);

    let target = Sha1Hash::of(&pk.0);
    // K + 1 nodes to create the failing sequence; invert the ith most
    // significant byte so the nodes are progressively closer to the target
    let nodes: Vec<(NodeId, SocketAddr)> = (0..9u8)
        .map(|i| {
            let mut id = target;
            id.0[usize::from(i)] = !id.0[usize::from(i)];
            let o = i + 1;
            (id, ep(&format!("{o}.{o}.{o}.{o}"), 1231 + u16::from(i)))
        })
        .collect();
    // the first k nodes are in the routing table
    for n in &nodes[..8] {
        w.table.add_node(n.0, n.1);
    }
    let put_item = Item::signed(its[0].ent.clone(), b"", seq, &pk, &sk).unwrap();
    let put_count = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&put_count);
    w.run(|ctx, trs| {
        let t = put_mutable(
            ctx,
            pk,
            b"",
            Box::new(move |i| {
                count.fetch_add(1, Ordering::SeqCst);
                *i = put_item.clone();
            }),
        );
        trs.spawn(ctx, t);
    });
    assert_eq!(w.sock.sent.len(), 8);

    // first the k closest nodes answer; once they have, the response of the
    // farthest must not trigger a second completion
    let mut order: Vec<usize> = (1..9).collect();
    order.push(0);
    for i in order {
        let request = w
            .take_packet(nodes[i].1)
            .unwrap_or_else(|| panic!("a request for node {i}"));
        assert_get_request(&request, &item_target_id(b"", &pk));
        let tok = format!("{i:02}");
        let mut args = MsgArgs::new()
            .token(tok.as_bytes())
            .port(1234)
            .nid(&nodes[i].0);
        // the address of the closest node is in the first response
        if i == 1 {
            args = args.nodes(&write_nodes([(&nodes[8].0, &nodes[8].1)]));
        }
        w.respond(&request, nodes[i].1, &args);
    }
    assert_eq!(put_count.load(Ordering::SeqCst), 1);
    // k nodes now have outstanding put requests
    assert_eq!(w.sock.sent.len(), 8);
    for (_, p) in &w.sock.sent {
        assert_eq!(p.get("q").and_then(Entry::as_bytes), Some(&b"put"[..]));
    }
}
