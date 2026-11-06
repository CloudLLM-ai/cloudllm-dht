//! Node-level tests ported from libtorrent RC_2_1 `test/test_dht.cpp`
//! (commit `86d573f2631b0162d3cca5e257217eaf530fdcba`): the cases that drive
//! `dht::node` with hand-built datagrams and inspect the responses.

mod node_support;

use cloudllm_dht::bencode::NodeKind;
use cloudllm_dht::msg::{verify_message, KeyDesc, KeyFlags};
use cloudllm_dht::testing::{ep, rand_v4, rand_v6, MsgArgs};
use cloudllm_dht::Sha1Hash;
use node_support::Fixture;

const fn kd(name: &'static str, kind: Option<NodeKind>, size: usize, flags: KeyFlags) -> KeyDesc {
    KeyDesc::new(name, kind, size, flags)
}

/// `err_desc` of `test_dht.cpp`.
const ERR_DESC: [KeyDesc; 2] = [
    kd("y", Some(NodeKind::Str), 1, KeyFlags::NONE),
    kd("e", Some(NodeKind::List), 2, KeyFlags::NONE),
];

/// Ports `TEST_CASE(ping)`: a `ping` is answered with `y=r`, the same
/// transaction id and the node's ID.
#[test]
fn test_ping() {
    let mut rng = cloudllm_dht::rng::TestRng::new(1);
    let mut t = Fixture::new(cloudllm_dht::testing::ep(
        &rand_v4(&mut rng).to_string(),
        20,
    ));
    let response = t.request("ping", &MsgArgs::new()).expect("a response");
    let m = response.node();
    let desc = [
        kd("y", Some(NodeKind::Str), 1, KeyFlags::NONE),
        kd("t", Some(NodeKind::Str), 2, KeyFlags::NONE),
        kd("r", Some(NodeKind::Dict), 0, KeyFlags::PARSE_CHILDREN),
        kd("id", Some(NodeKind::Str), 20, KeyFlags::LAST_CHILD),
    ];
    let keys = verify_message(&m, &desc).expect("a valid pong");
    assert_eq!(keys[0].unwrap().string_value(), b"r");
    assert_eq!(keys[1].unwrap().string_value(), b"10");
    assert_eq!(keys[3].unwrap().string_value(), &t.node.nid().0);
}

/// Ports `TEST_CASE(invalid_message)`: a `find_node` without `target` is
/// answered with an error naming the missing key.
#[test]
fn test_invalid_message() {
    let mut rng = cloudllm_dht::rng::TestRng::new(2);
    let mut t = Fixture::new(ep(&rand_v4(&mut rng).to_string(), 20));
    let response = t.request("find_node", &MsgArgs::new()).expect("a response");
    let m = response.node();
    let keys = verify_message(&m, &ERR_DESC).expect("a valid error");
    assert_eq!(keys[0].unwrap().string_value(), b"e");
    let e = keys[1].unwrap();
    assert_eq!(e.list_int_value_at(0, 0), 203);
    assert_eq!(e.list_string_value_at(1, b""), b"missing 'target' key");
}

const IH: Sha1Hash = Sha1Hash(*b"01010101010101010101");

/// Ports `TEST_CASE(get_peers_announce)`: `get_peers` hands out a write
/// token and the matching `announce_peer` is accepted.
#[test]
fn test_get_peers_announce() {
    let mut rng = cloudllm_dht::rng::TestRng::new(3);
    let mut t = Fixture::new(ep(&rand_v4(&mut rng).to_string(), 20));
    let response = t
        .request("get_peers", &MsgArgs::new().info_hash(&IH))
        .expect("a response");
    let m = response.node();
    let desc = [
        kd("y", Some(NodeKind::Str), 1, KeyFlags::NONE),
        kd("r", Some(NodeKind::Dict), 0, KeyFlags::PARSE_CHILDREN),
        kd("token", Some(NodeKind::Str), 0, KeyFlags::NONE),
        kd("id", Some(NodeKind::Str), 20, KeyFlags::LAST_CHILD),
    ];
    let keys = verify_message(&m, &desc).expect("a valid get_peers response");
    assert_eq!(keys[0].unwrap().string_value(), b"r");
    let token = keys[2].unwrap().string_value().to_vec();

    let response = t
        .request(
            "announce_peer",
            &MsgArgs::new()
                .info_hash(&IH)
                .name("test")
                .token(&token)
                .port(8080),
        )
        .expect("a response");
    let m = response.node();
    let desc = [
        kd("y", Some(NodeKind::Str), 1, KeyFlags::NONE),
        kd("r", Some(NodeKind::Dict), 0, KeyFlags::PARSE_CHILDREN),
        kd("id", Some(NodeKind::Str), 20, KeyFlags::LAST_CHILD),
    ];
    let keys = verify_message(&m, &desc).expect("a valid announce response");
    assert_eq!(keys[0].unwrap().string_value(), b"r");
}

/// Shared body of `id_enforcement_v4/v6` (`test_id_enforcement`).
fn id_enforcement(v6: bool) {
    let mut rng = cloudllm_dht::rng::TestRng::new(4);
    let rand_addr = if v6 {
        rand_v6(&mut rng)
    } else {
        rand_v4(&mut rng)
    };
    let mut settings = node_support::test_settings();
    settings.enforce_node_id = true;
    let mut t = Fixture::with_settings(ep(&rand_addr.to_string(), 20), settings);

    let (source, mut nid, valid_first) = if v6 {
        (
            ep("2001:b829:2123:be84:e16c:d6ae:5290:49f1", 1),
            cloudllm_dht::testing::to_hash("0a8ad123be84e16cd6ae529049f1f1bbe9ebb304"),
            0x0a,
        )
    } else {
        // one of the test vectors from http://libtorrent.org/dht_sec.html
        (
            ep("124.31.75.21", 1),
            cloudllm_dht::testing::to_hash("5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401"),
            0x5f,
        )
    };
    nid.0[0] = 0x18; // an invalid node ID for `source`
    let nodes_num = t.node.size().1;
    let args = |nid: &Sha1Hash| {
        MsgArgs::new()
            .target(&Sha1Hash(*b"01010101010101010101"))
            .nid(nid)
    };
    let response = t
        .request_from("find_node", source, &args(&nid))
        .expect("a response");
    let m = response.node();
    let keys = verify_message(&m, &ERR_DESC).expect("an error response");
    assert_eq!(keys[0].unwrap().string_value(), b"e");
    assert_eq!(
        keys[1].unwrap().list_string_value_at(1, b""),
        b"invalid node ID"
    );
    // a node with an invalid node-id is not added to the routing table
    assert_eq!(t.node.size().1, nodes_num);

    nid.0[0] = valid_first;
    let response = t
        .request_from("find_node", source, &args(&nid))
        .expect("a response");
    let m = response.node();
    assert_eq!(m.dict_find_string_value(b"y", b""), b"r");
    // the node with a valid node-id lands in the replacement bucket (it was
    // never pinged)
    assert_eq!(t.node.size().1, nodes_num + 1);
}

/// Ports `TEST_CASE(id_enforcement_v4)`.
#[test]
fn test_id_enforcement_v4() {
    id_enforcement(false);
}

/// Ports `TEST_CASE(id_enforcement_v6)`.
#[test]
fn test_id_enforcement_v6() {
    id_enforcement(true);
}

/// Ports `TEST_CASE(multi_home)`: a query that arrives on a socket other
/// than the node's own is ignored.
#[test]
fn test_multi_home() {
    let mut rng = cloudllm_dht::rng::TestRng::new(5);
    let mut t = Fixture::new(ep(&rand_v4(&mut rng).to_string(), 20));
    let entry = cloudllm_dht::testing::build_query("ping", &MsgArgs::new(), "10", &mut rng);
    t.deliver_on(
        t.source,
        &entry.encode(),
        false,
        &cloudllm_dht::node::query::NoForeignTables,
    );
    assert!(t.sock.sent.is_empty());
}

/// Ports `TEST_CASE(node_set_id)`: after the external address changes the
/// node re-derives its ID and answers with the new one.
#[test]
fn test_node_set_id() {
    let mut rng = cloudllm_dht::rng::TestRng::new(6);
    let mut t = Fixture::new(ep(&rand_v4(&mut rng).to_string(), 20));
    let old_nid = t.node.nid();
    let external = cloudllm_dht::testing::addr4("237.0.0.1");
    let changed = t.with_env(|node, env| node.update_node_id(env, external));
    assert!(changed);
    assert_ne!(old_nid, t.node.nid());
    assert!(cloudllm_dht::node_id::verify_id(&t.node.nid(), external));
    // already valid for that address: nothing changes
    let again = t.with_env(|node, env| node.update_node_id(env, external));
    assert!(!again);

    let response = t.request("ping", &MsgArgs::new()).expect("a response");
    let m = response.node();
    let r = m.dict_find_dict(b"r").expect("an r dictionary");
    assert_eq!(r.dict_find_string_value(b"id", b""), &t.node.nid().0);
}

/// Ports the first half of `TEST_CASE(read_only_node)`: a read-only node
/// answers no query and does not learn the sender.
#[test]
fn test_read_only_node_ignores_queries() {
    let mut settings = node_support::test_settings();
    settings.read_only = true;
    let mut t = Fixture::with_settings(ep("10.0.0.1", 20), settings);
    assert!(t.request("ping", &MsgArgs::new()).is_none());
    let target = Sha1Hash(*b"01010101010101010101");
    assert!(t.request("get", &MsgArgs::new().target(&target)).is_none());
    assert_eq!(t.node.size().0, 0);
    assert_eq!(t.node.size().1, 0);
}

/// Ports the tail of `TEST_CASE(read_only_node)`: once `read_only` is
/// switched off the sender of a query lands in the replacement bucket.
#[test]
fn test_read_only_node_off_learns_sender() {
    let mut settings = node_support::test_settings();
    settings.read_only = true;
    let mut t = Fixture::with_settings(ep("10.0.0.1", 20), settings.clone());
    let target = Sha1Hash(*b"01010101010101010101");
    assert!(t.request("get", &MsgArgs::new().target(&target)).is_none());
    settings.read_only = false;
    t.node.set_settings(settings);
    t.request("get", &MsgArgs::new().target(&target))
        .expect("a response once the node is no longer read-only");
    assert_eq!(t.node.size().1, 1);
}

/// BEP 43: a query from a read-only sender (`ro` = 1) is answered but the
/// sender is not added to the routing table.
#[test]
fn test_ro_sender_not_added_to_table() {
    let mut t = Fixture::new(ep("10.0.0.1", 20));
    let mut entry = cloudllm_dht::testing::build_query(
        "ping",
        &MsgArgs::new(),
        "10",
        &mut cloudllm_dht::rng::TestRng::new(9),
    );
    entry.set("ro", cloudllm_dht::bencode::Entry::Int(1));
    t.deliver(t.source, &entry.encode());
    assert!(t.sock.take_packet(t.source).is_some());
    assert_eq!(t.node.size().1, 0);
    assert_eq!(t.node.size().0, 0);
}

/// Ports `TEST_CASE(dht_dual_stack)`: a v4 node answers `want: n6` with
/// `nodes6` from the v6 node's table and vice versa; asking for both yields
/// both lists.
#[test]
fn test_dht_dual_stack() {
    use cloudllm_dht::net::{read_nodes, Protocol};
    let mut f4 = Fixture::new(ep("10.0.0.1", 20));
    let mut f6 = Fixture::new(ep("10::1", 20));
    let id = cloudllm_dht::testing::to_hash("3123456789abcdef01232456789abcdef0123456");
    let now = f4.now();
    f4.node
        .table_mut()
        .node_seen(id, ep("4.4.4.4", 4440), 10, now);
    f6.node.table_mut().node_seen(id, ep("4::4", 4441), 10, now);
    let target = Sha1Hash(*b"01010101010101010101");

    // v4 node requesting v6 nodes
    let view6 = node_support::TableView(f6.node.table());
    let src4 = f4.source;
    let r = f4
        .request_foreign(
            "find_node",
            src4,
            &MsgArgs::new().target(&target).want("n6"),
            &view6,
        )
        .expect("a response");
    let m = r.node();
    let nodes6 = m
        .dict_find_dict(b"r")
        .and_then(|r| r.dict_find_string(b"nodes6"))
        .expect("nodes6");
    let got = read_nodes(Protocol::V6, nodes6.string_value());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].id, id);
    assert_eq!(got[0].ep, ep("4::4", 4441));

    // v6 node requesting v4 nodes
    let view4 = node_support::TableView(f4.node.table());
    let src6 = f6.source;
    let r = f6
        .request_foreign(
            "get_peers",
            src6,
            &MsgArgs::new().info_hash(&target).want("n4"),
            &view4,
        )
        .expect("a response");
    let m = r.node();
    let nodes = m
        .dict_find_dict(b"r")
        .and_then(|r| r.dict_find_string(b"nodes"))
        .expect("nodes");
    let got = read_nodes(Protocol::V4, nodes.string_value());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].ep, ep("4.4.4.4", 4440));

    // v6 node requesting both
    let r = f6
        .request_foreign(
            "find_node",
            src6,
            &MsgArgs::new().target(&target).want("n4").want("n6"),
            &view4,
        )
        .expect("a response");
    let m = r.node();
    let rd = m.dict_find_dict(b"r").expect("r");
    let n4 = read_nodes(
        Protocol::V4,
        rd.dict_find_string(b"nodes").expect("nodes").string_value(),
    );
    let n6 = read_nodes(
        Protocol::V6,
        rd.dict_find_string(b"nodes6")
            .expect("nodes6")
            .string_value(),
    );
    assert_eq!(
        (n4[0].ep, n6[0].ep),
        (ep("4.4.4.4", 4440), ep("4::4", 4441))
    );
}

/// Without a `want` list the node answers with its own family's key only,
/// and a `want` for a family nobody serves yields no list at all
/// (`get_foreign_node` returning null).
#[test]
fn test_want_for_unserved_family_is_skipped() {
    let mut t = Fixture::new(ep("10.0.0.1", 20));
    let target = Sha1Hash(*b"01010101010101010101");
    let r = t
        .request("find_node", &MsgArgs::new().target(&target))
        .expect("a response");
    let m = r.node();
    let rd = m.dict_find_dict(b"r").expect("r");
    assert!(rd.dict_find_string(b"nodes").is_some());
    assert!(rd.dict_find_string(b"nodes6").is_none());

    let r = t
        .request("find_node", &MsgArgs::new().target(&target).want("n6"))
        .expect("a response");
    let m = r.node();
    let rd = m.dict_find_dict(b"r").expect("r");
    assert!(rd.dict_find_string(b"nodes6").is_none());
    assert!(rd.dict_find_string(b"nodes").is_none());
}

/// The `[code, text]` of an error response, or `None` for a success.
fn error_of(e: &cloudllm_dht::testing::Encoded) -> Option<(i64, String)> {
    let m = e.node();
    if m.dict_find_string_value(b"y", b"") != b"e" {
        return None;
    }
    let l = m.dict_find_list(b"e")?;
    Some((
        l.list_int_value_at(0, 0),
        String::from_utf8_lossy(l.list_string_value_at(1, b"")).into_owned(),
    ))
}

fn token_for(t: &mut Fixture, target: &Sha1Hash) -> Vec<u8> {
    let r = t
        .request("get_peers", &MsgArgs::new().info_hash(target))
        .expect("a response");
    let m = r.node();
    m.dict_find_dict(b"r")
        .expect("r")
        .dict_find_string_value(b"token", b"")
        .to_vec()
}

/// An `announce_peer` with a token that was not handed out is refused with
/// `invalid token`, and counted.
#[test]
fn test_announce_with_bad_token_is_rejected() {
    let mut t = Fixture::new(ep("10.0.0.1", 20));
    let r = t
        .request(
            "announce_peer",
            &MsgArgs::new().info_hash(&IH).token(b"nope").port(1),
        )
        .expect("a response");
    assert_eq!(error_of(&r), Some((203, "invalid token".to_owned())));
    assert_eq!(t.node.counters().invalid_announce, 1);
    assert_eq!(t.node.counters().announce_peer_in, 0);
}

/// A token is bound to the requester's IP: another address cannot use it.
#[test]
fn test_token_is_bound_to_the_requester_ip() {
    let mut t = Fixture::new(ep("10.0.0.1", 20));
    let token = token_for(&mut t, &IH);
    let r = t
        .request_from(
            "announce_peer",
            ep("10.0.0.2", 20),
            &MsgArgs::new().info_hash(&IH).token(&token).port(1),
        )
        .expect("a response");
    assert_eq!(error_of(&r), Some((203, "invalid token".to_owned())));
}

/// Ports the `port` handling of `node::incoming_request`: ports outside
/// 0..65535 are refused, `implied_port` substitutes the packet's source
/// port.
#[test]
fn test_announce_port_validation_and_implied_port() {
    let mut t = Fixture::new(ep("10.0.0.1", 20));
    let token = token_for(&mut t, &IH);
    let bad = |port: i64, t: &mut Fixture| {
        let r = t
            .request(
                "announce_peer",
                &MsgArgs::new().info_hash(&IH).token(&token).port(port),
            )
            .expect("a response");
        error_of(&r)
    };
    assert_eq!(bad(65536, &mut t), Some((203, "invalid port".to_owned())));
    assert_eq!(bad(-1, &mut t), Some((203, "invalid port".to_owned())));
    assert_eq!(bad(65535, &mut t), None);

    // implied_port makes the stored port the source port, so an otherwise
    // invalid explicit port no longer matters
    let mut entry = cloudllm_dht::testing::build_query(
        "announce_peer",
        &MsgArgs::new().info_hash(&IH).token(&token).port(99_999),
        "10",
        &mut cloudllm_dht::rng::TestRng::new(1),
    );
    entry.set("a", {
        let mut a = entry.get("a").cloned().expect("a");
        a.set("implied_port", cloudllm_dht::bencode::Entry::Int(1));
        a
    });
    t.deliver(t.source, &entry.encode());
    let r = t.sock.take_packet(t.source).expect("a response");
    assert_eq!(r.get("y"), Some(&cloudllm_dht::bencode::Entry::from("r")));
}

/// Queries the node does not know are treated as `find_node` when they
/// carry a `target` or `info_hash`, otherwise answered with `unknown
/// message` (forward compatibility, `node::incoming_request`).
#[test]
fn test_unknown_query_falls_back_to_find_node() {
    let mut t = Fixture::new(ep("10.0.0.1", 20));
    let target = Sha1Hash(*b"01010101010101010101");
    let r = t
        .request("future_query", &MsgArgs::new().target(&target))
        .expect("a response");
    let m = r.node();
    assert_eq!(m.dict_find_string_value(b"y", b""), b"r");
    assert!(m
        .dict_find_dict(b"r")
        .unwrap()
        .dict_find_string(b"nodes")
        .is_some());

    let r = t
        .request("future_query", &MsgArgs::new().info_hash(&target))
        .expect("a response");
    assert_eq!(r.node().dict_find_string_value(b"y", b""), b"r");

    let r = t
        .request("future_query", &MsgArgs::new())
        .expect("a response");
    assert_eq!(error_of(&r), Some((203, "unknown message".to_owned())));
}

/// A message without a one-byte `y` gets no answer at all (an error reply
/// would be an amplification vector), and a query without `a.id` gets a
/// protocol error.
#[test]
fn test_garbage_is_not_answered_but_missing_id_is_an_error() {
    let mut t = Fixture::new(ep("10.0.0.1", 20));
    t.deliver(t.source, b"d1:q4:ping1:t2:aae");
    assert!(t.sock.sent.is_empty());
    t.deliver(t.source, b"d1:y2:qq1:q4:ping1:t2:aae");
    assert!(t.sock.sent.is_empty());

    t.deliver(t.source, b"d1:ade1:q4:ping1:t2:aa1:y1:qe");
    let r = t.sock.take_packet(t.source).expect("an error response");
    assert_eq!(
        error_of(&cloudllm_dht::testing::Encoded::from_entry(&r)),
        Some((203, "missing 'id' key".to_owned()))
    );
}

/// The response carries the requester's address (`ip`) and mirrors its
/// port in `r.p`.
#[test]
fn test_response_reports_ip_and_port() {
    let mut t = Fixture::new(ep("10.1.2.3", 4321));
    let r = t.request("ping", &MsgArgs::new()).expect("a response");
    let m = r.node();
    assert_eq!(
        m.dict_find_string_value(b"ip", b""),
        [10, 1, 2, 3, 0x10, 0xe1]
    );
    assert_eq!(
        m.dict_find_dict(b"r").unwrap().dict_find_int_value(b"p", 0),
        4321
    );
}

/// When the upload quota is exhausted queries are dropped and counted
/// (`dht_messages_in_dropped`).
#[test]
fn test_no_quota_drops_queries() {
    let mut t = Fixture::new(ep("10.0.0.1", 20));
    t.sock.out_of_quota = true;
    assert!(t.request("ping", &MsgArgs::new()).is_none());
    assert_eq!(t.node.counters().messages_in_dropped, 1);
    t.sock.out_of_quota = false;
    assert!(t.request("ping", &MsgArgs::new()).is_some());
}

/// The `on_dht_request` hook may take over the response.
#[test]
fn test_request_hook_can_answer() {
    let mut t = Fixture::new(ep("10.0.0.1", 20));
    t.hook = Some(Box::new(|q, _m, response| {
        if q == "ping" {
            let mut r = response.get("r").cloned().expect("r so far");
            r.set("hooked", 1);
            response.set("r", r);
            true
        } else {
            false
        }
    }));
    let r = t.request("ping", &MsgArgs::new()).expect("a response");
    assert_eq!(
        r.node()
            .dict_find_dict(b"r")
            .unwrap()
            .dict_find_int_value(b"hooked", 0),
        1
    );
    let target = Sha1Hash(*b"01010101010101010101");
    let r = t
        .request("find_node", &MsgArgs::new().target(&target))
        .expect("a response");
    assert!(r
        .node()
        .dict_find_dict(b"r")
        .unwrap()
        .dict_find_int(b"hooked")
        .is_none());
}

/// `get_peers` and `announce_peer` queue notification events, and the
/// `ip` a remote reports becomes an `ExternalAddress` event only when it
/// arrives on the node's own socket.
#[test]
fn test_notification_events() {
    use cloudllm_dht::events::Event;
    let mut t = Fixture::new(ep("10.0.0.1", 20));
    let token = token_for(&mut t, &IH);
    t.request(
        "announce_peer",
        &MsgArgs::new().info_hash(&IH).token(&token).port(7),
    )
    .expect("a response");
    let ev = t.drain_events();
    assert!(ev
        .iter()
        .any(|e| matches!(e, Event::IncomingGetPeers { info_hash, .. } if *info_hash == IH)));
    assert!(ev
        .iter()
        .any(|e| matches!(e, Event::IncomingAnnounce { port: 7, .. })));

    // a response claiming our address, own socket vs. other socket
    let mut resp = cloudllm_dht::bencode::Entry::dict();
    resp.set("y", "r")
        .set("t", "zz")
        .set("ip", vec![1, 2, 3, 4, 0, 80]);
    resp.set("r", {
        let mut r = cloudllm_dht::bencode::Entry::dict();
        r.set("id", [7u8; 20]);
        r
    });
    t.deliver_on(
        ep("5.5.5.5", 1),
        &resp.encode(),
        false,
        &cloudllm_dht::node::query::NoForeignTables,
    );
    assert!(t.drain_events().is_empty());
    t.deliver(ep("5.5.5.5", 1), &resp.encode());
    let ev = t.drain_events();
    assert!(ev.iter().any(|e| matches!(e,
        Event::ExternalAddress { addr, source }
            if *addr == cloudllm_dht::testing::addr4("1.2.3.4")
            && *source == cloudllm_dht::testing::addr4("5.5.5.5"))));
}

/// Shared body of `scrape_v4/v6` (`test_scrape`): announce from 100 random
/// IPs, 50 downloaders and 50 seeds, then check the BEP 33 bloom filters
/// estimate both populations.
fn scrape(v6: bool) {
    use cloudllm_dht::bloom_filter::BloomFilter;
    let mut rng = cloudllm_dht::rng::TestRng::new(7);
    let pick = |rng: &mut cloudllm_dht::rng::TestRng| if v6 { rand_v6(rng) } else { rand_v4(rng) };
    let mut t = Fixture::new(ep(&pick(&mut rng).to_string(), 20));
    for i in 0..100 {
        let source = ep(&pick(&mut rng).to_string(), 6000);
        t.source = source;
        let token = token_for(&mut t, &IH);
        t.request(
            "announce_peer",
            &MsgArgs::new()
                .info_hash(&IH)
                .name("test")
                .token(&token)
                .port(8080)
                .seed(i >= 50),
        )
        .expect("a response");
    }
    let r = t
        .request("get_peers", &MsgArgs::new().info_hash(&IH).scrape(true))
        .expect("a response");
    let m = r.node();
    let rd = m.dict_find_dict(b"r").expect("r");
    assert_eq!(rd.dict_find_string_value(b"n", b""), b"test");
    let downloaders = BloomFilter::<256>::from_bytes(rd.dict_find_string_value(b"BFpe", b""))
        .expect("a 256 byte BFpe");
    let seeds = BloomFilter::<256>::from_bytes(rd.dict_find_string_value(b"BFsd", b""))
        .expect("a 256 byte BFsd");
    assert!((seeds.size() - 50.0).abs() <= 3.0, "seeds {}", seeds.size());
    assert!(
        (downloaders.size() - 50.0).abs() <= 3.0,
        "downloaders {}",
        downloaders.size()
    );
}

/// Ports `TEST_CASE(scrape_v4)`.
#[test]
fn test_scrape_v4() {
    scrape(false);
}

/// Ports `TEST_CASE(scrape_v6)`.
#[test]
fn test_scrape_v6() {
    scrape(true);
}

mod put {
    //! Ports `TEST_CASE(put_v4)` / `put_v6` (`test_put`).

    use super::*;
    use cloudllm_dht::bencode::Entry;
    use cloudllm_dht::ed25519::{create_keypair, create_seed};
    use cloudllm_dht::item::{item_target_id, sign_mutable_item, verify_mutable_item};
    use cloudllm_dht::rng::{Rng, TestRng};
    use cloudllm_dht::types::SequenceNumber;

    /// `announce_item`: a dictionary and its SHA-1 target.
    struct AnnounceItem {
        num_peers: u32,
        ent: Entry,
        target: Sha1Hash,
    }

    fn announce_item(rng: &mut TestRng) -> AnnounceItem {
        let num_peers = rng.random(5) + 2;
        let mut ent = Entry::dict();
        ent.set("next", rng.random_hash().0)
            .set("A", "a")
            .set("B", "b")
            .set("num_peers", i64::from(num_peers));
        let target = Sha1Hash::of(&ent.encode());
        AnnounceItem {
            num_peers,
            ent,
            target,
        }
    }

    fn token_of(r: &cloudllm_dht::testing::Encoded) -> Vec<u8> {
        let m = r.node();
        m.dict_find_dict(b"r")
            .expect("get response has r")
            .dict_find_string_value(b"token", b"")
            .to_vec()
    }

    /// `announce_immutable_items`: 1000 requesters each `get` then `put`
    /// eight items; storage holds four items at most, so exactly four
    /// survive.
    fn announce_immutable_items(
        t: &mut Fixture,
        eps: &[std::net::SocketAddr],
        items: &[AnnounceItem],
    ) {
        for (i, from) in eps.iter().enumerate() {
            for item in items {
                // MSRV 1.88 has no `is_multiple_of`
                #[allow(clippy::manual_is_multiple_of)]
                let skip = i as u32 % item.num_peers == 0;
                if skip {
                    continue;
                }
                let r = t
                    .request_from("get", *from, &MsgArgs::new().target(&item.target))
                    .expect("a get response");
                assert_eq!(r.node().dict_find_string_value(b"y", b""), b"r");
                // the response tells the requester its address
                let mut ip = Vec::new();
                cloudllm_dht::net::write_endpoint(from, &mut ip);
                assert_eq!(r.node().dict_find_string_value(b"ip", b""), &ip[..]);
                let token = token_of(&r);
                let r = t
                    .request_from(
                        "put",
                        *from,
                        &MsgArgs::new()
                            .token(&token)
                            .target(&item.target)
                            .value(item.ent.clone()),
                    )
                    .expect("a put response");
                assert_eq!(
                    r.node().dict_find_string_value(b"y", b""),
                    b"r",
                    "put failed: {}",
                    r.node().print(true, 0)
                );
            }
        }
        let stored = items
            .iter()
            .enumerate()
            .filter(|(j, item)| {
                let r = t
                    .request_from("get", eps[*j], &MsgArgs::new().target(&item.target))
                    .expect("a get response");
                let m = r.node();
                m.dict_find_dict(b"r")
                    .is_some_and(|r| r.dict_find_dict(b"v").is_some())
            })
            .count();
        assert_eq!(stored, 4);
    }

    fn run(v6: bool) {
        let mut rng = TestRng::new(11);
        let pick = |rng: &mut TestRng| if v6 { rand_v6(rng) } else { rand_v4(rng) };
        let mut t = Fixture::new(ep(&pick(&mut rng).to_string(), 20));
        t.node.new_write_key(&mut rng);
        // `storage->update_node_ids({node_id::min()})` in dht_test_setup
        t.storage.update_node_ids(&[Sha1Hash::MIN]);

        let eps: Vec<_> = (0..1000)
            .map(|_| ep(&pick(&mut rng).to_string(), (rng.random(16534) + 1) as u16))
            .collect();
        let items: Vec<_> = (0..8).map(|_| announce_item(&mut rng)).collect();
        announce_immutable_items(&mut t, &eps, &items);

        for with_salt in [false, true] {
            mutable_round(&mut t, &mut rng, &items, with_salt);
        }
    }

    fn error_code(r: &cloudllm_dht::testing::Encoded) -> Option<i64> {
        let m = r.node();
        (m.dict_find_string_value(b"y", b"") == b"e").then(|| {
            m.dict_find_list(b"e")
                .map_or(0, |l| l.list_int_value_at(0, 0))
        })
    }

    fn mutable_round(t: &mut Fixture, rng: &mut TestRng, items: &[AnnounceItem], with_salt: bool) {
        let mut seq = SequenceNumber(4);
        let (pk, sk) = create_keypair(&create_seed(rng));
        let salt: &[u8] = if with_salt { b"foobar" } else { b"" };
        let target_id = item_target_id(salt, &pk);
        let r = t
            .request("get", &MsgArgs::new().target(&target_id))
            .expect("a get response");
        let token = token_of(&r);

        let itemv = items[0].ent.encode();
        let sig = sign_mutable_item(&itemv, salt, seq, &pk, &sk);
        assert!(verify_mutable_item(&itemv, salt, seq, &pk, &sig));
        let put_args = |token: &[u8], v: &Entry, sig: &_, seq: SequenceNumber| {
            MsgArgs::new()
                .token(token)
                .value(v.clone())
                .key(&pk)
                .sig(sig)
                .seq(seq)
                .salt(salt)
        };
        let r = t
            .request("put", &put_args(&token, &items[0].ent, &sig, seq))
            .expect("a put response");
        assert_eq!(r.node().dict_find_string_value(b"y", b""), b"r");

        // get it back: value bytes, sequence number and signature
        let r = t
            .request("get", &MsgArgs::new().target(&target_id))
            .expect("a get response");
        let m = r.node();
        let rd = m.dict_find_dict(b"r").expect("r");
        assert_eq!(rd.dict_find(b"v").expect("v").data_section(), &itemv[..]);
        assert_eq!(rd.dict_find_int_value(b"seq", -1), seq.0);
        assert_eq!(rd.dict_find_string_value(b"sig", b""), &sig.0);
        assert_eq!(rd.dict_find_string_value(b"k", b""), &pk.0);

        // a broken signature is refused with 206
        let mut broken = sig;
        broken.0[2] ^= 0xaa;
        let r = t
            .request("put", &put_args(&token, &items[0].ent, &broken, seq))
            .expect("a put response");
        assert_eq!(error_code(&r), Some(206));

        // conditional get: with the previous sequence number the value is
        // returned, with the current one it is withheld
        let r = t
            .request("get", &MsgArgs::new().target(&target_id).seq(seq.prev()))
            .expect("a get response");
        let m = r.node();
        let rd = m.dict_find_dict(b"r").expect("r");
        assert!(
            rd.dict_find(b"v").is_some()
                && rd.dict_find(b"k").is_some()
                && rd.dict_find(b"sig").is_some()
        );
        let r = t
            .request("get", &MsgArgs::new().target(&target_id).seq(seq))
            .expect("a get response");
        let m = r.node();
        let rd = m.dict_find_dict(b"r").expect("r");
        assert!(
            rd.dict_find(b"v").is_none()
                && rd.dict_find(b"k").is_none()
                && rd.dict_find(b"sig").is_none()
        );

        // CAS put: replaces when the expected sequence number matches...
        let cas = seq;
        seq = seq.next();
        let itemv1 = items[1].ent.encode();
        let sig1 = sign_mutable_item(&itemv1, salt, seq, &pk, &sk);
        assert!(verify_mutable_item(&itemv1, salt, seq, &pk, &sig1));
        let cas_args = put_args(&token, &items[1].ent, &sig1, seq).cas(cas);
        let r = t.request("put", &cas_args).expect("a put response");
        assert_eq!(r.node().dict_find_string_value(b"y", b""), b"r");
        // ...and a second identical put fails: the stored seq moved on (301)
        let r = t.request("put", &cas_args).expect("a put response");
        assert_eq!(error_code(&r), Some(301));
    }

    /// Ports `TEST_CASE(put_v4)`.
    #[test]
    fn test_put_v4() {
        run(false);
    }

    /// Ports `TEST_CASE(put_v6)`.
    #[test]
    fn test_put_v6() {
        run(true);
    }
}

mod put_errors {
    //! `put` error paths of `node::incoming_request`, and regression tests
    //! for the libtorrent defects found while porting.

    use super::*;
    use cloudllm_dht::bencode::Entry;
    use cloudllm_dht::ed25519::{create_keypair, create_seed};
    use cloudllm_dht::item::{item_target_id, sign_mutable_item};
    use cloudllm_dht::rng::TestRng;
    use cloudllm_dht::testing::Encoded;
    use cloudllm_dht::types::SequenceNumber;

    fn get_token(t: &mut Fixture, target: &Sha1Hash) -> Vec<u8> {
        let r = t
            .request("get", &MsgArgs::new().target(target))
            .expect("a get response");
        let m = r.node();
        m.dict_find_dict(b"r")
            .unwrap()
            .dict_find_string_value(b"token", b"")
            .to_vec()
    }

    fn code_text(r: &Encoded) -> Option<(i64, String)> {
        super::error_of(r)
    }

    /// An immutable `put` stores the value under `SHA-1(bencoded value)`
    /// and a later `get` returns it.
    #[test]
    fn test_immutable_put_roundtrip() {
        let mut t = Fixture::new(ep("10.0.0.1", 20));
        let v = Entry::from("Hello World!");
        let target = Sha1Hash::of(&v.encode());
        let token = get_token(&mut t, &target);
        let r = t
            .request("put", &MsgArgs::new().token(&token).value(v))
            .expect("a response");
        assert_eq!(code_text(&r), None);
        let r = t
            .request("get", &MsgArgs::new().target(&target))
            .expect("a response");
        let m = r.node();
        let stored = m
            .dict_find_dict(b"r")
            .unwrap()
            .dict_find(b"v")
            .unwrap()
            .data_section();
        assert_eq!(stored, b"12:Hello World!");
    }

    /// A `put` without a valid token is refused, whichever kind of item.
    #[test]
    fn test_put_requires_a_token_for_the_target() {
        let mut t = Fixture::new(ep("10.0.0.1", 20));
        let v = Entry::from("x");
        let r = t
            .request("put", &MsgArgs::new().token(b"abcd").value(v.clone()))
            .expect("a response");
        assert_eq!(code_text(&r), Some((203, "invalid token".to_owned())));
        // a token minted for some other target does not work either
        let other = get_token(&mut t, &Sha1Hash([9; 20]));
        let r = t
            .request("put", &MsgArgs::new().token(&other).value(v))
            .expect("a response");
        assert_eq!(code_text(&r), Some((203, "invalid token".to_owned())));
        assert_eq!(t.node.counters().invalid_put, 2);
    }

    /// Values over 1000 bytes get error 205; exactly 1000 is accepted.
    #[test]
    fn test_put_value_size_limit() {
        let mut t = Fixture::new(ep("10.0.0.1", 20));
        // "996:" + 996 bytes = 1000 encoded bytes
        let fits = Entry::Str(vec![b'a'; 996]);
        assert_eq!(fits.encode().len(), 1000);
        let target = Sha1Hash::of(&fits.encode());
        let token = get_token(&mut t, &target);
        let r = t
            .request("put", &MsgArgs::new().token(&token).value(fits))
            .expect("a response");
        assert_eq!(code_text(&r), None);

        let big = Entry::Str(vec![b'a'; 997]);
        assert_eq!(big.encode().len(), 1001);
        let r = t
            .request("put", &MsgArgs::new().token(b"abcd").value(big))
            .expect("a response");
        assert_eq!(code_text(&r), Some((205, "message too big".to_owned())));
    }

    /// A salt over 64 bytes gets error 207.
    #[test]
    fn test_put_salt_size_limit() {
        let mut t = Fixture::new(ep("10.0.0.1", 20));
        let (pk, sk) = create_keypair(&create_seed(&mut TestRng::new(1)));
        let v = Entry::from("x");
        let salt = vec![b's'; 65];
        let sig = sign_mutable_item(&v.encode(), &salt, SequenceNumber(1), &pk, &sk);
        let r = t
            .request(
                "put",
                &MsgArgs::new()
                    .token(b"abcd")
                    .value(v)
                    .key(&pk)
                    .sig(&sig)
                    .seq(SequenceNumber(1))
                    .salt(&salt),
            )
            .expect("a response");
        assert_eq!(code_text(&r), Some((207, "salt too big".to_owned())));
    }

    /// A negative sequence number is a protocol error, an older sequence
    /// number than the stored one gets 302.
    #[test]
    fn test_put_sequence_number_rules() {
        let mut t = Fixture::new(ep("10.0.0.1", 20));
        let (pk, sk) = create_keypair(&create_seed(&mut TestRng::new(2)));
        let target = item_target_id(b"", &pk);
        let token = get_token(&mut t, &target);
        let v = Entry::from("x");
        let put = |t: &mut Fixture, seq: i64| {
            let sig = sign_mutable_item(&v.encode(), b"", SequenceNumber(seq), &pk, &sk);
            let r = t
                .request(
                    "put",
                    &MsgArgs::new()
                        .token(&token)
                        .value(v.clone())
                        .key(&pk)
                        .sig(&sig)
                        .seq(SequenceNumber(seq)),
                )
                .expect("a response");
            code_text(&r)
        };
        assert_eq!(
            put(&mut t, -1),
            Some((203, "invalid (negative) sequence number".to_owned()))
        );
        assert_eq!(put(&mut t, 5), None);
        assert_eq!(
            put(&mut t, 4),
            Some((302, "old sequence number".to_owned()))
        );
        // the same sequence number refreshes the item
        assert_eq!(put(&mut t, 5), None);
        assert_eq!(put(&mut t, 6), None);
    }

    /// A `put` whose argument dictionary is not canonically bencoded is
    /// refused, because the signed value would not round-trip.
    #[test]
    fn test_put_rejects_non_canonical_bencoding() {
        let mut t = Fixture::new(ep("10.0.0.1", 20));
        // keys of `a` out of order (`v` before `token`)
        let id = [b'i'; 20];
        let mut msg = b"d1:ad2:id20:".to_vec();
        msg.extend_from_slice(&id);
        msg.extend_from_slice(b"1:v1:x5:token4:abcde1:q3:put1:t2:aa1:y1:qe");
        t.deliver(t.source, &msg);
        let r = t.sock.take_packet(t.source).expect("a response");
        let (code, text) = error_of(&Encoded::from_entry(&r)).expect("an error");
        assert_eq!(code, 203);
        assert_eq!(text, "unsorted dictionary key");
    }

    /// Regression test for a libtorrent defect (RC_2_1 `node::incoming_request`,
    /// `put`): a message with a public key `k` but no `seq`/`sig` was not a
    /// "mutable put", yet its target was still computed from `k` and `salt`,
    /// so the value was stored as an *immutable* item under a mutable
    /// target. `get` consults the immutable table first, so anyone holding
    /// a token for the target (every `get` hands one out) could shadow a
    /// mutable item with unsigned data. The port rejects such a put.
    #[test]
    fn test_put_with_key_but_no_signature_is_rejected() {
        let mut t = Fixture::new(ep("10.0.0.1", 20));
        let (pk, sk) = create_keypair(&create_seed(&mut TestRng::new(3)));
        let target = item_target_id(b"", &pk);
        let token = get_token(&mut t, &target);

        // the legitimate owner stores a signed item
        let real = Entry::from("real");
        let sig = sign_mutable_item(&real.encode(), b"", SequenceNumber(1), &pk, &sk);
        let r = t
            .request(
                "put",
                &MsgArgs::new()
                    .token(&token)
                    .value(real.clone())
                    .key(&pk)
                    .sig(&sig)
                    .seq(SequenceNumber(1)),
            )
            .expect("a response");
        assert_eq!(code_text(&r), None);

        // an attacker presents the same key without a signature
        let r = t
            .request(
                "put",
                &MsgArgs::new()
                    .token(&token)
                    .value(Entry::from("fake"))
                    .key(&pk),
            )
            .expect("a response");
        assert_eq!(
            code_text(&r),
            Some((203, "incomplete mutable put".to_owned()))
        );
        // and with a seq but no signature
        let r = t
            .request(
                "put",
                &MsgArgs::new()
                    .token(&token)
                    .value(Entry::from("fake"))
                    .key(&pk)
                    .seq(SequenceNumber(9)),
            )
            .expect("a response");
        assert!(code_text(&r).is_some());

        // the real item is still what `get` returns
        let r = t
            .request("get", &MsgArgs::new().target(&target))
            .expect("a response");
        let m = r.node();
        let rd = m.dict_find_dict(b"r").unwrap();
        assert_eq!(rd.dict_find(b"v").unwrap().data_section(), b"4:real");
        assert_eq!(rd.dict_find_string_value(b"sig", b""), &sig.0);
    }
}
