//! Tests for the RPC manager (`rpc_manager.cpp`) and the observer arena
//! (`observer.hpp`), including the `test_dht.cpp` cases that exercise them
//! directly: `rpc_reply_ignores_wrong_port`, `invalid_error_msg` and
//! `rpc_invalid_error_msg` (libtorrent RC_2_1,
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`).

mod common;

use std::time::Duration;

use cloudllm_dht::bencode::Entry;
use cloudllm_dht::net::Protocol;
use cloudllm_dht::node_id::NodeId;
use cloudllm_dht::observer::{
    Observer, ObserverFlags, ObserverId, ObserverKind, Observers, TraversalId,
};
use cloudllm_dht::rng::Rng;
use cloudllm_dht::rpc_manager::{Incoming, MIN_TICK, SHORT_TIMEOUT, TIMEOUT};
use cloudllm_dht::testing::{build_response, ep, Encoded, MsgArgs};
use cloudllm_dht::time::Time;
use cloudllm_dht::Sha1Hash;

use common::World;

fn query(q: &str) -> Entry {
    let mut e = Entry::dict();
    e.set("q", q);
    e
}

/// Inserts a queried detached observer for `target` and invokes `e` with it.
fn invoke_null(w: &mut World, e: Entry, target: std::net::SocketAddr) -> (ObserverId, bool) {
    w.run(|ctx, _| {
        let mut o = Observer::new(ObserverKind::Null, None, NodeId::MIN, target, ctx.now);
        o.flags |= ObserverFlags::QUERIED;
        let id = ctx.rpc.observers.insert(o);
        let sent = ctx.invoke(e, target, id);
        // like `invoke_detached`: from here on only the transaction holds it
        ctx.rpc.observers.release(id);
        (id, sent)
    })
}

fn tid_of(e: &Entry) -> Vec<u8> {
    e.get("t").and_then(Entry::as_bytes).expect("t").to_vec()
}

/// A reply that carries the right transaction id but comes from another
/// port is not matched (and does not consume the transaction); the right
/// endpoint is. Ports `rpc_reply_ignores_wrong_port` from `test_dht.cpp`.
#[test]
fn test_rpc_reply_ignores_wrong_port() {
    let mut w = World::v4();
    let source = ep("10.0.0.1", 20);
    let wrong_port = ep("10.0.0.1", 21);

    let (obs, sent) = invoke_null(&mut w, query("ping"), source);
    assert!(sent);
    assert_eq!(w.sock.sent.len(), 1);
    let packet = w.sock.sent[0].1.clone();

    let response_id = w.rng.random_hash();
    let resp = build_response(
        &tid_of(&packet),
        &MsgArgs::new().nid(&response_id),
        &mut w.rng,
    );
    let enc = Encoded::from_entry(&resp);
    let n = enc.node();

    let r = w.run(|ctx, _| ctx.rpc_incoming(wrong_port, &n));
    assert_eq!(r, Incoming::Ignored);
    assert_eq!(w.rpc.num_transactions(), 1);

    let r = w.run(|ctx, _| ctx.rpc_incoming(source, &n));
    match r {
        Incoming::Reply { observer, id, .. } => {
            assert_eq!(observer, obs);
            assert_eq!(id, response_id);
        }
        other => panic!("expected a reply, got {other:?}"),
    }
    assert_eq!(w.rpc.num_transactions(), 0);
}

/// An error whose `e` is a string instead of the `[code, text]` list still
/// matches its request, and marks it failed rather than crashing. Covers
/// `invalid_error_msg` / `rpc_invalid_error_msg` of `test_dht.cpp`, which
/// there only check a log line (the log output is not ported).
#[test]
fn test_rpc_invalid_error_msg() {
    let mut w = World::v4();
    let source = ep("10.0.0.1", 20);
    let mut req = query("bogus_query");
    req.set("y", "q").set("t", b"\0\0\0\0".to_vec());
    let (obs, sent) = invoke_null(&mut w, req, source);
    assert!(sent);
    let packet = w.sock.sent[0].1.clone();

    let mut err = Entry::dict();
    err.set("y", "e")
        .set("e", "Malformed Error")
        .set("t", tid_of(&packet));
    let enc = Encoded::from_entry(&err);
    let n = enc.node();
    let r = w.run(|ctx, _| ctx.rpc_incoming(source, &n));
    assert_eq!(r, Incoming::Failed(obs));
}

/// A message without a transaction id, or with one we never issued, is
/// ignored without effect (libtorrent comments out the error reply to
/// avoid amplification).
#[test]
fn test_rpc_incoming_ignores_unknown_transactions() {
    let mut w = World::v4();
    let source = ep("10.0.0.1", 20);
    let (_, _) = invoke_null(&mut w, query("ping"), source);

    let mut no_t = Entry::dict();
    no_t.set("y", "e").set("e", "Malformed Error");
    let enc = Encoded::from_entry(&no_t);
    assert_eq!(
        w.run(|ctx, _| ctx.rpc_incoming(source, &enc.node())),
        Incoming::Ignored
    );

    let mut e = Entry::dict();
    e.set("y", "r")
        .set("t", b"zz".to_vec())
        .set("r", Entry::dict());
    let enc = Encoded::from_entry(&e);
    // a transaction id of the wrong size maps to 0xffff and matches nothing
    let mut long_t = Entry::dict();
    long_t.set("y", "r").set("t", b"zzz".to_vec());
    let enc2 = Encoded::from_entry(&long_t);
    assert_eq!(
        w.run(|ctx, _| ctx.rpc_incoming(source, &enc.node())),
        Incoming::Ignored
    );
    assert_eq!(
        w.run(|ctx, _| ctx.rpc_incoming(source, &enc2.node())),
        Incoming::Ignored
    );
    assert_eq!(w.rpc.num_transactions(), 1);
}

/// `invoke` turns the bare query into a complete one: `y`, `a.id`, a
/// two-byte `t`, and nothing else for a native, non-read-only node.
#[test]
fn test_invoke_completes_the_query() {
    let mut w = World::v4();
    let target = ep("10.0.0.2", 6881);
    let (_, sent) = invoke_null(&mut w, query("ping"), target);
    assert!(sent);
    let (to, e) = w.sock.sent[0].clone();
    assert_eq!(to, target);
    assert_eq!(e.get("y").and_then(Entry::as_bytes), Some(&b"q"[..]));
    assert_eq!(e.get("q").and_then(Entry::as_bytes), Some(&b"ping"[..]));
    assert_eq!(tid_of(&e).len(), 2);
    let a = e.get("a").expect("a");
    assert_eq!(a.get("id").and_then(Entry::as_bytes), Some(&w.id.0[..]));
    assert!(a.get("want").is_none());
    assert!(e.get("ro").is_none());
}

/// A read-only node (BEP 43) marks its queries with `ro = 1`.
#[test]
fn test_invoke_marks_read_only_nodes() {
    let mut w = World::v4();
    w.settings.read_only = true;
    invoke_null(&mut w, query("ping"), ep("10.0.0.2", 6881));
    assert_eq!(w.sock.sent[0].1.get("ro"), Some(&Entry::Int(1)));
}

/// A query to a node of the other address family asks for our family's
/// nodes with `want` (BEP 32), `n4` from a v4 node and `n6` from a v6 node.
#[test]
fn test_invoke_adds_want_for_foreign_family() {
    let mut w = World::v4();
    invoke_null(&mut w, query("get_peers"), ep("2001:db8::1", 6881));
    let want = w.sock.sent[0]
        .1
        .get("a")
        .unwrap()
        .get("want")
        .unwrap()
        .clone();
    assert_eq!(want, Entry::List(vec![Entry::from("n4")]));

    let mut w = World::new(Sha1Hash([0x22; 20]), Protocol::V6);
    invoke_null(&mut w, query("get_peers"), ep("1.2.3.4", 6881));
    let want = w.sock.sent[0]
        .1
        .get("a")
        .unwrap()
        .get("want")
        .unwrap()
        .clone();
    assert_eq!(want, Entry::List(vec![Entry::from("n6")]));
}

/// If the transport refuses the packet nothing is tracked, and the
/// observer is not kept alive by the manager.
#[test]
fn test_invoke_failure_tracks_nothing() {
    struct Refuse;
    impl cloudllm_dht::transport::Transport for Refuse {
        fn has_quota(&mut self) -> bool {
            false
        }
        fn send_packet(&mut self, _: &Entry, _: std::net::SocketAddr) -> bool {
            false
        }
    }
    let mut w = World::v4();
    let target = ep("10.0.0.2", 6881);
    let mut refuse = Refuse;
    let mut ctx = cloudllm_dht::ctx::NodeCtx::new(
        w.now,
        w.id,
        w.protocol,
        &w.settings,
        &mut w.table,
        &mut w.rpc,
        &mut refuse,
        &mut w.rng,
        &mut w.events,
        w.secret,
    );
    let sent = ctx.invoke_detached(ObserverKind::Ping, NodeId::MIN, target, query("ping"));
    assert!(!sent);
    assert_eq!(w.rpc.num_transactions(), 0);
    assert_eq!(w.rpc.num_allocated_observers(), 0);
}

/// Two requests may draw the same 16-bit transaction id; the response is
/// matched on id *and* endpoint, so each reaches its own observer.
#[test]
fn test_transaction_id_collision_is_resolved_by_endpoint() {
    struct Constant;
    impl cloudllm_dht::rng::Rng for Constant {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0x7f);
        }
        fn next_u32(&mut self) -> u32 {
            0x0000_7fff
        }
        fn random(&mut self, _max: u32) -> u32 {
            0x7fff
        }
    }
    let mut w = World::v4();
    let (a, b) = (ep("10.0.0.1", 1), ep("10.0.0.2", 2));
    let mut rng = Constant;
    let mut ctx = cloudllm_dht::ctx::NodeCtx::new(
        w.now,
        w.id,
        w.protocol,
        &w.settings,
        &mut w.table,
        &mut w.rpc,
        &mut w.sock,
        &mut rng,
        &mut w.events,
        w.secret,
    );
    let sent_a = ctx.invoke_detached(ObserverKind::Null, NodeId::MIN, a, query("ping"));
    let sent_b = ctx.invoke_detached(ObserverKind::Null, NodeId::MIN, b, query("ping"));
    assert!(sent_a && sent_b);
    assert_eq!(w.sock.sent[0].1.get("t"), w.sock.sent[1].1.get("t"));

    let id = Sha1Hash([9; 20]);
    let mut resp = Entry::dict();
    resp.set("y", "r")
        .set("t", tid_of(&w.sock.sent[0].1))
        .set("r", {
            let mut r = Entry::dict();
            r.set("id", id.0);
            r
        });
    let enc = Encoded::from_entry(&resp);
    let n = enc.node();
    let r = w.run(|ctx, _| ctx.rpc_incoming(b, &n));
    assert!(matches!(r, Incoming::Reply { .. }));
    assert_eq!(
        w.rpc.num_transactions(),
        1,
        "the request to `a` is still pending"
    );
    let r = w.run(|ctx, _| ctx.rpc_incoming(b, &n));
    assert_eq!(
        r,
        Incoming::Ignored,
        "a second reply from b matches nothing"
    );
}

/// A response without `r`, or with an `id` that is not 20 bytes, fails the
/// request instead of reaching the observer.
#[test]
fn test_malformed_responses_fail_the_request() {
    for r in [None, Some(Entry::dict()), {
        let mut r = Entry::dict();
        r.set("id", b"short".to_vec());
        Some(r)
    }] {
        let mut w = World::v4();
        let source = ep("10.0.0.1", 20);
        let (obs, _) = invoke_null(&mut w, query("ping"), source);
        let packet = w.sock.sent[0].1.clone();
        let mut resp = Entry::dict();
        resp.set("y", "r").set("t", tid_of(&packet));
        if let Some(r) = r {
            resp.set("r", r);
        }
        let enc = Encoded::from_entry(&resp);
        assert_eq!(
            w.run(|ctx, _| ctx.rpc_incoming(source, &enc.node())),
            Incoming::Failed(obs)
        );
    }
}

/// With `enforce_node_id` a response from a node whose ID does not match
/// its address (BEP 42) fails; without it, it is accepted.
#[test]
fn test_enforce_node_id_rejects_unverifiable_ids() {
    for enforce in [false, true] {
        let mut w = World::v4();
        w.settings.enforce_node_id = enforce;
        let source = ep("124.31.75.21", 20);
        let (obs, _) = invoke_null(&mut w, query("ping"), source);
        let packet = w.sock.sent[0].1.clone();
        // an ID that does not match 124.31.75.21
        let resp = build_response(
            &tid_of(&packet),
            &MsgArgs::new().nid(&Sha1Hash([0x55; 20])),
            &mut w.rng,
        );
        let enc = Encoded::from_entry(&resp);
        let r = w.run(|ctx, _| ctx.rpc_incoming(source, &enc.node()));
        if enforce {
            assert_eq!(r, Incoming::Failed(obs));
        } else {
            assert!(matches!(r, Incoming::Reply { .. }));
        }
    }
}

/// The reported round-trip time is the time since the request was sent.
#[test]
fn test_reply_reports_round_trip_time() {
    let mut w = World::v4();
    let source = ep("10.0.0.1", 20);
    invoke_null(&mut w, query("ping"), source);
    let packet = w.sock.sent[0].1.clone();
    w.advance(Duration::from_millis(137));
    let resp = build_response(&tid_of(&packet), &MsgArgs::new(), &mut w.rng);
    let enc = Encoded::from_entry(&resp);
    let r = w.run(|ctx, _| ctx.rpc_incoming(source, &enc.node()));
    match r {
        Incoming::Reply { rtt, .. } => assert_eq!(rtt, 137),
        other => panic!("{other:?}"),
    }
}

/// `tick` reports nothing for an idle manager and asks to be called again
/// after the short timeout.
#[test]
fn test_tick_idle() {
    let mut w = World::v4();
    let out = w.run(|ctx, _| ctx.rpc_tick());
    assert_eq!(out.next, SHORT_TIMEOUT);
    assert!(out.timeouts.is_empty() && out.short_timeouts.is_empty());
}

/// A request is reported once at the short timeout and once at the full
/// timeout, and the time to the next tick follows the oldest request but is
/// never below 200 ms.
#[test]
fn test_tick_reports_short_then_full_timeout() {
    let mut w = World::v4();
    let target = ep("10.0.0.1", 20);
    let (obs, _) = invoke_null(&mut w, query("ping"), target);

    w.advance(Duration::from_millis(500));
    let out = w.run(|ctx, _| ctx.rpc_tick());
    assert!(out.timeouts.is_empty() && out.short_timeouts.is_empty());
    assert_eq!(out.next, SHORT_TIMEOUT, "never more than one second");

    w.advance(Duration::from_millis(500));
    let out = w.run(|ctx, _| ctx.rpc_tick());
    assert_eq!(out.short_timeouts, vec![obs]);
    assert!(out.timeouts.is_empty());

    w.advance(TIMEOUT - SHORT_TIMEOUT);
    let out = w.run(|ctx, _| ctx.rpc_tick());
    assert_eq!(out.timeouts, vec![obs]);
    assert_eq!(w.rpc.num_transactions(), 0);
    assert!(out.next >= MIN_TICK);
}

/// A request that was cancelled (flagged done) is dropped by `tick` without
/// being reported, and its observer is freed.
#[test]
fn test_tick_drops_cancelled_requests() {
    let mut w = World::v4();
    let (obs, _) = invoke_null(&mut w, query("ping"), ep("10.0.0.1", 20));
    w.run(|ctx, _| ctx.rpc.observers.get_mut(obs).unwrap().flags |= ObserverFlags::DONE);
    w.advance(Duration::from_secs(1));
    let out = w.run(|ctx, _| ctx.rpc_tick());
    assert!(out.timeouts.is_empty() && out.short_timeouts.is_empty());
    assert_eq!(w.rpc.num_transactions(), 0);
    assert_eq!(w.rpc.num_allocated_observers(), 0);
}

/// `unreachable` cancels the first request to the endpoint and only that
/// one (libtorrent `break`s after the first match).
#[test]
fn test_unreachable_takes_only_the_first_match() {
    let mut w = World::v4();
    let target = ep("10.0.0.1", 20);
    let (first, _) = invoke_null(&mut w, query("ping"), target);
    let (second, _) = invoke_null(&mut w, query("ping"), target);
    let got = w.run(|ctx, _| ctx.rpc_unreachable(target));
    assert!(got == Some(first) || got == Some(second));
    assert_eq!(w.rpc.num_transactions(), 1);
    assert_eq!(w.run(|ctx, _| ctx.rpc_unreachable(ep("10.9.9.9", 1))), None);
}

/// libtorrent quirk, kept: a ping or announce observer has no traversal
/// results, so its short timeout is never recorded and `tick` reports it on
/// every tick until the full timeout, each time counting a routing-table
/// failure for the node.
#[test]
fn test_detached_short_timeout_repeats_every_tick() {
    let mut w = World::v4();
    let target = ep("10.0.0.1", 20);
    let id = Sha1Hash([0x33; 20]);
    w.run(|ctx, _| {
        ctx.invoke_detached(ObserverKind::Ping, id, target, query("ping"));
    });
    for _ in 0..3 {
        w.advance(Duration::from_secs(1));
        w.tick();
    }
    assert_eq!(w.table.failed.len(), 3);
    assert!(w.table.failed.iter().all(|f| *f == (id, target)));
    w.advance(TIMEOUT);
    w.tick();
    assert_eq!(w.table.failed.len(), 4, "plus the final timeout");
    assert_eq!(w.rpc.num_allocated_observers(), 0);
}

/// A ping's response teaches the table the nodes it lists, and the
/// observer is released afterwards.
#[test]
fn test_ping_reply_reports_listed_nodes() {
    let mut w = World::v4();
    let target = ep("10.0.0.1", 20);
    w.run(|ctx, _| {
        ctx.invoke_detached(ObserverKind::Ping, NodeId::MIN, target, query("get_peers"));
    });
    let packet = w.sock.sent[0].1.clone();
    let listed = (Sha1Hash([0x77; 20]), ep("11.0.0.9", 99));
    let packed = cloudllm_dht::net::write_nodes([(&listed.0, &listed.1)]);
    let sender = Sha1Hash([0x44; 20]);
    w.respond(&packet, target, &MsgArgs::new().nid(&sender).nodes(&packed));
    assert_eq!(w.table.heard, vec![listed]);
    assert_eq!(w.table.seen.len(), 1);
    assert_eq!(w.table.seen[0].0, sender);
    assert_eq!(w.rpc.num_allocated_observers(), 0);
    assert_eq!(w.rpc.num_transactions(), 0);
}

/// The arena frees an observer when its last holder lets go, rejects stale
/// handles, and reuses slots without confusing generations.
#[test]
fn test_observer_arena_reference_counting() {
    let mut arena = Observers::default();
    let mk = |t| {
        Observer::new(
            ObserverKind::Null,
            Some(TraversalId(t)),
            NodeId::MIN,
            ep("1.1.1.1", 1),
            Time::ZERO,
        )
    };
    let a = arena.insert(mk(1));
    let b = arena.insert(mk(1));
    assert_eq!(arena.len(), 2);
    assert_eq!(arena.live_for(TraversalId(1)), 2);
    arena.acquire(a);
    assert!(!arena.release(a));
    assert!(arena.release(a));
    assert!(arena.get(a).is_none(), "stale handle");
    assert!(!arena.release(a), "double release is harmless");
    let c = arena.insert(mk(2));
    assert!(
        arena.get(a).is_none(),
        "the reused slot has a new generation"
    );
    assert!(arena.get(c).is_some());
    assert!(arena.release(b));
    assert_eq!(arena.take_idle(), vec![TraversalId(1)]);
    assert!(arena.release(c));
    assert!(arena.is_empty());
}
