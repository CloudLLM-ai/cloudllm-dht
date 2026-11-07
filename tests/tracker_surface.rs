//! The `Dht` tracker's control surface, driven one datagram at a time with no
//! network: the request hook, replaced settings, counters, socket errors,
//! direct requests, external-address changes, state and status snapshots.
//! The routing and lookup behavior behind them is covered by the node,
//! traversal and simulation suites; these tests pin what an embedder sees.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use cloudllm_dht::bencode::Entry;
use cloudllm_dht::events::Event;
use cloudllm_dht::rng::TestRng;
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::testing::{addr4, ep};
use cloudllm_dht::time::Time;
use cloudllm_dht::tracker::{Dht, SocketErrorKind, SocketId};

const PING: &[u8] = b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:t2:aa1:y1:qe";

fn now() -> Time {
    Time::ZERO + Duration::from_secs(1_000)
}

/// A tracker with one IPv4 socket at 10.0.0.1:6881.
fn dht() -> (Dht, SocketId) {
    let mut dht = Dht::builder(DhtSettings::default())
        .rng(Box::new(TestRng::new(7)))
        .build();
    let socket = dht.add_socket(ep("10.0.0.1", 6881), None, now());
    (dht, socket)
}

/// The bytes of everything queued for sending.
fn transmitted(dht: &mut Dht) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| dht.poll_transmit())
        .map(|d| d.payload)
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A request hook sees the query name, may answer it itself (its response is
/// sent as is and the built-in handler is skipped), and removing it restores
/// the built-in answer.
#[test]
fn test_request_hook_answers_a_query_and_can_be_removed() {
    let (mut dht, socket) = dht();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    dht.set_request_hook(Some(Box::new(move |name, _msg, reply| {
        log.lock().expect("log").push(name.to_string());
        reply.set("hooked", "yes");
        true
    })));
    dht.incoming_packet(socket, ep("4.4.4.4", 4000), PING, now());
    let sent = transmitted(&mut dht);
    assert_eq!(sent.len(), 1);
    assert!(contains(&sent[0], b"hooked"), "the hook's answer was sent");
    assert_eq!(*seen.lock().expect("log"), ["ping"]);

    dht.set_request_hook(None);
    dht.incoming_packet(socket, ep("4.4.4.5", 4000), PING, now());
    let sent = transmitted(&mut dht);
    assert_eq!(sent.len(), 1);
    assert!(!contains(&sent[0], b"hooked"));
    assert_eq!(seen.lock().expect("log").len(), 1, "the hook is gone");
}

/// A hook that declines (returns false) leaves the built-in handler to answer.
#[test]
fn test_request_hook_returning_false_falls_through() {
    let (mut dht, socket) = dht();
    dht.set_request_hook(Some(Box::new(|_, _, _| false)));
    dht.incoming_packet(socket, ep("4.4.4.4", 4000), PING, now());
    assert_eq!(transmitted(&mut dht).len(), 1);
}

/// Replaced settings are the ones in force, and they take effect: with the
/// dark-internet filter switched on, a query from a dark-internet address is dropped
/// and counted.
#[test]
fn test_set_settings_takes_effect() {
    let (mut dht, socket) = dht();
    let mut settings = dht.settings().clone();
    settings.ignore_dark_internet = true;
    settings.max_dht_items = 11;
    dht.set_settings(settings);
    assert_eq!(dht.settings().max_dht_items, 11);

    let dropped = dht.counters().messages_in_dropped;
    dht.incoming_packet(socket, ep("3.1.1.1", 4000), PING, now());
    assert_eq!(dht.counters().messages_in_dropped, dropped + 1);
    assert!(transmitted(&mut dht).is_empty());
}

/// Counters follow the traffic: a query in and its answer out are counted
/// with their bytes, and the node-level counters count the query by kind.
#[test]
fn test_counters_follow_traffic() {
    let (mut dht, socket) = dht();
    assert_eq!(dht.counters().messages_in, 0);
    dht.incoming_packet(socket, ep("4.4.4.4", 4000), PING, now());
    let sent = transmitted(&mut dht);
    let counters = dht.counters();
    assert_eq!(counters.messages_in, 1);
    assert_eq!(counters.bytes_in, PING.len() as u64);
    assert_eq!(counters.messages_out, 1);
    assert_eq!(counters.bytes_out, sent[0].len() as u64);
    let node = dht.node_counters();
    assert!(node.ping_in == 1, "the ping was counted: {node:?}");
}

/// Nodes and storage are reachable by socket; an unknown socket has none.
#[test]
fn test_node_and_storage_accessors() {
    let (mut dht, socket) = dht();
    assert!(dht.node(socket).is_some());
    assert!(dht.node_mut(socket).is_some());
    assert!(dht.node(SocketId(999)).is_none());
    assert!(dht.node_mut(SocketId(999)).is_none());
    let counters = dht.storage().counters();
    assert_eq!((counters.torrents, counters.peers), (0, 0));
    assert_eq!((counters.immutable_data, counters.mutable_data), (0, 0));
}

/// An embedder's ICMP: "unreachable" ends a request waiting on that endpoint
/// at once (the answer is a timeout-shaped `None`), anything else is ignored.
#[test]
fn test_socket_error_fails_the_waiting_request() {
    let (mut dht, _) = dht();
    let target = ep("5.5.5.5", 6881);
    let op = dht.direct_request(target, Entry::dict(), now());
    assert_eq!(transmitted(&mut dht).len(), 1, "the request went out");
    dht.drain_events();

    dht.socket_error(SocketErrorKind::Other, target, now());
    assert!(dht.drain_events().is_empty(), "other errors are ignored");

    dht.socket_error(SocketErrorKind::ConnectionRefused, target, now());
    let events = dht.drain_events();
    assert!(
        events.iter().any(|e| matches!(e,
            Event::Operation { op: o, result } if *o == op
                && matches!(**result, Event::DirectResponse { reply: None, .. }))),
        "{events:?}"
    );
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::OperationDone { op: o } if *o == op)));
    assert_eq!(dht.operations_in_flight(), 0);
}

/// A direct request to a family the tracker has no node for is answered at
/// once with `None` and finishes, without sending anything.
#[test]
fn test_direct_request_without_a_node_of_that_family() {
    let (mut dht, _) = dht();
    let v6 = ep("2001:db8::1", 6881);
    let op = dht.direct_request(v6, Entry::dict(), now());
    let events = dht.drain_events();
    assert!(events.iter().any(|e| matches!(e,
        Event::Operation { op: o, result } if *o == op
            && matches!(**result, Event::DirectResponse { reply: None, .. }))));
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::OperationDone { op: o } if *o == op)));
    assert!(transmitted(&mut dht).is_empty());
}

/// `add_node` sends the endpoint a refresh query (a `get_peers` for the table's far end), and `sample_infohashes` asks it for a
/// sample; both leave from the node of the endpoint's family.
#[test]
fn test_add_node_and_sample_infohashes_send_queries() {
    let (mut dht, _) = dht();
    let peer = ep("6.6.6.6", 6881);
    dht.add_node(peer, now());
    let sent: Vec<_> = std::iter::from_fn(|| dht.poll_transmit()).collect();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to, peer);
    assert!(contains(&sent[0].payload, b"9:get_peers"));

    let op = dht.sample_infohashes(peer, cloudllm_dht::Sha1Hash::of(b"t"), now());
    let sent: Vec<_> = std::iter::from_fn(|| dht.poll_transmit()).collect();
    assert_eq!(sent.len(), 1);
    assert!(contains(&sent[0].payload, b"sample_infohashes"));
    // Each error fails the first request outstanding to the endpoint: the
    // refresh from `add_node`, then the sample.
    for _ in 0..2 {
        dht.socket_error(SocketErrorKind::ConnectionRefused, peer, now());
    }
    let events = dht.drain_events();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::OperationDone { op: o } if *o == op)));
}

/// A newly learned external address re-derives the node ID (BEP 42), and the
/// persisted state names the node by its local address. An unknown socket is
/// ignored.
#[test]
fn test_external_address_changes_the_node_id_and_state_reports_it() {
    let (mut dht, socket) = dht();
    let before = dht.node(socket).expect("node").nid();
    assert_eq!(dht.state().nids, [(addr4("10.0.0.1"), before)]);

    dht.set_external_address(SocketId(999), addr4("203.0.113.9"), now());
    assert_eq!(dht.node(socket).expect("node").nid(), before);

    dht.set_external_address(socket, addr4("203.0.113.9"), now());
    let after = dht.node(socket).expect("node").nid();
    assert_ne!(before, after, "the ID follows the external address");
    assert_eq!(dht.state().nids, [(addr4("10.0.0.1"), after)]);
    assert!(dht.live_nodes(&after).is_empty());
    assert!(dht.live_nodes(&before).is_empty());
}

/// `status` has one entry per node, naming its ID and covering its buckets.
#[test]
fn test_status_has_one_entry_per_node() {
    let (mut dht, socket) = dht();
    let id = dht.node(socket).expect("node").nid();
    let status = dht.status(now());
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].0, socket);
    assert_eq!(status[0].1.our_id, id);
    assert!(status[0].1.requests.is_empty());
}
