//! Tests for `routing_table`, ported from the routing-table cases of
//! libtorrent `test/test_dht.cpp` (RC_2_1,
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg and contributors, plus tests of the behaviour of
//! `routing_table.cpp` that no libtorrent test covers and regression tests.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use cloudllm_dht::net::Protocol;
use cloudllm_dht::node_entry::{NodeEntry, NEVER_PINGED};
use cloudllm_dht::node_id::{
    compare_ref, distance_exp, generate_id_impl, generate_random_id, NodeId,
};
use cloudllm_dht::rng::{Rng, TestRng};
use cloudllm_dht::routing_table::{
    all_in_same_bucket, classify_prefix, compare_ip_cidr, mostly_verified_nodes, replace_node_impl,
    AddNodeStatus, FindNodeOptions, IpSet, RoutingTable, RoutingTableError,
};
use cloudllm_dht::settings::DhtSettings;
use cloudllm_dht::testing::{add_and_replace, addr4, addr6, rand_v4, rand_v6, to_hash};
use cloudllm_dht::time::Time;
use cloudllm_dht::Sha1Hash;

type RandAddr = fn(&mut dyn Rng) -> IpAddr;

/// A moment safely after [`Time::ZERO`] ("never").
fn now() -> Time {
    Time::from_duration(Duration::from_secs(10_000))
}

/// libtorrent's `test_settings()` (the part that matters here):
/// `dht_enforce_node_id` off.
fn test_settings() -> DhtSettings {
    DhtSettings {
        enforce_node_id: false,
        ..DhtSettings::default()
    }
}

/// libtorrent's `rand_udp_ep`: a random address and a port that cycles, so
/// the same "random" port is never produced twice in a row.
struct EpGen {
    rng: TestRng,
    port: u16,
}

impl EpGen {
    fn new(seed: u64) -> Self {
        Self {
            rng: TestRng::new(seed),
            port: 0,
        }
    }

    fn ep_with(&mut self, rand_addr: RandAddr) -> SocketAddr {
        self.port = (self.port + 1) % 14037;
        SocketAddr::new(rand_addr(&mut self.rng), self.port + 1024)
    }

    fn ep(&mut self) -> SocketAddr {
        self.ep_with(rand_v4)
    }
}

fn v4_table(id: NodeId, bucket_size: usize, s: &DhtSettings) -> RoutingTable {
    RoutingTable::new(id, Protocol::V4, bucket_size, s)
}

/// A `Vec`-shuffle with the test RNG (libtorrent `aux::random_shuffle`).
fn shuffled_bytes(rng: &mut TestRng) -> Vec<u8> {
    let mut v: Vec<u8> = (0..=255).collect();
    for i in (1..v.len()).rev() {
        let j = rng.random(u32::try_from(i).unwrap()) as usize;
        v.swap(i, j);
    }
    v
}

fn all_nodes(t: &RoutingTable) -> Vec<NodeEntry> {
    let mut v = Vec::new();
    t.for_each_node(|e| v.push(*e), |_| {});
    v
}

fn sum_distance_exp(s: i32, e: &NodeEntry, reference: &NodeId) -> i32 {
    s + distance_exp(&e.id, reference)
}

/// Builds a node entry on a fresh random endpoint with the given properties
/// (the `n()` helper of `test_dht.cpp`).
fn n(
    g: &mut EpGen,
    ips: Option<&mut IpSet>,
    nid: &str,
    verified: bool,
    rtt: u16,
    failed: u8,
) -> NodeEntry {
    let mut e = NodeEntry::unknown_id(g.ep());
    if let Some(ips) = ips {
        ips.insert(e.addr());
    }
    e.verified = verified;
    e.rtt = rtt;
    e.id = to_hash(nid);
    if failed != 0 {
        e.timeout_count = failed;
    }
    e
}

// ---------------------------------------------------------------------
// TEST_CASE routing_table_v4 / routing_table_v6
// ---------------------------------------------------------------------

fn test_routing_table(rand_addr: RandAddr, v6: bool, seed: u64) {
    let mut g = EpGen::new(seed);
    let mut s = test_settings();
    s.extended_routing_table = false;
    let nid = to_hash("3123456789abcdef01232456789abcdef0123456");
    let bucket_size = 8;
    let protocol = if v6 { Protocol::V6 } else { Protocol::V4 };
    let mut table = RoutingTable::new(nid, protocol, bucket_size, &s);
    assert_eq!(table.size().0, 0);

    let (node_addr, node_near_addr) = if v6 {
        (
            addr6("2001:1111:1111:1111:1111:1111:1111:1111"),
            addr6("2001:1111:1111:1111:eeee:eeee:eeee:eeee"),
        )
    } else {
        (addr4("4.4.4.4"), addr4("4.4.4.5"))
    };
    let at = |ip: IpAddr, port: u16| SocketAddr::new(ip, port);

    // test a node with the same IP:port changing ID
    let tmp = generate_id_impl(node_addr, 1, &mut g.rng);
    table.node_seen(tmp, at(node_addr, 4), 10, now());

    let nodes = table.find_node(&nid, FindNodeOptions::NONE, 10);
    assert_eq!(table.bucket_len(0), 1);
    assert_eq!(table.size().0, 1);
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].id, tmp);
    assert_eq!(nodes[0].addr(), node_addr);
    assert_eq!(nodes[0].port(), 4);
    assert_eq!(nodes[0].timeout_count, 0);

    // set timeout_count to 1
    table.node_failed(&tmp, at(node_addr, 4));
    let nodes = all_nodes(&table);
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].id, tmp);
    assert_eq!(nodes[0].timeout_count, 1);

    // add the exact same node again, it should set the timeout_count to 0
    table.node_seen(tmp, at(node_addr, 4), 10, now());
    let nodes = all_nodes(&table);
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].timeout_count, 0);

    // test adding the same node ID again with a different IP (should be ignored)
    table.node_seen(tmp, at(node_addr, 5), 10, now());
    let nodes = table.find_node(&nid, FindNodeOptions::NONE, 10);
    assert_eq!(table.bucket_len(0), 1);
    assert_eq!(nodes[0].id, tmp);
    assert_eq!(nodes[0].addr(), node_addr);
    assert_eq!(nodes[0].port(), 4);

    // test adding a node that ends up in the same bucket with an IP very
    // close to the current one (should be ignored) if restrict_routing_ips
    table.node_seen(tmp, at(node_near_addr, 5), 10, now());
    let nodes = table.find_node(&nid, FindNodeOptions::NONE, 10);
    assert_eq!(table.bucket_len(0), 1);
    assert_eq!(nodes[0].id, tmp);
    assert_eq!(nodes[0].addr(), node_addr);
    assert_eq!(nodes[0].port(), 4);

    // test adding the same IP:port again with a new node ID (should remove the node)
    let id = generate_id_impl(node_addr, 2, &mut g.rng);
    table.node_seen(id, at(node_addr, 4), 10, now());
    let nodes = table.find_node(&id, FindNodeOptions::NONE, 10);
    assert_eq!(table.bucket_len(0), 0);
    assert_eq!(nodes.len(), 0);

    s.restrict_routing_ips = false;
    table.set_settings(&s);

    let ep = g.ep_with(rand_addr);
    let id = generate_id_impl(ep.ip(), 2, &mut g.rng);
    table.node_seen(id, ep, 10, now());

    for _ in 0..10_000 {
        let ep = g.ep_with(rand_addr);
        let id = generate_id_impl(ep.ip(), 6, &mut g.rng);
        table.node_seen(id, ep, 20 + u16::from(id.0[19]), now());
    }
    println!("active buckets: {}", table.num_active_buckets());
    assert!(table.num_active_buckets() == 11 || table.num_active_buckets() == 12);
    assert!(table.size().0 >= bucket_size * 10);
    table.check_invariants().unwrap();

    println!("{}", table.print_state(now()));

    let mut nodes = all_nodes(&table);
    println!("nodes: {}", nodes.len());

    let id = generate_random_id(&mut g.rng);
    let all = table.find_node(&id, FindNodeOptions::NONE, nodes.len() * 2);
    println!("returned-all: {}", all.len());
    assert_eq!(all.len(), nodes.len());

    // This makes sure enough of the nodes returned are actually part of the
    // closest nodes
    for _ in 0..50 {
        let id = generate_random_id(&mut g.rng);
        let temp = table.find_node(&id, FindNodeOptions::NONE, bucket_size * 2);
        assert_eq!(temp.len(), (bucket_size * 2).min(nodes.len()));

        nodes.sort_by(|a, b| {
            use std::cmp::Ordering::{Equal, Greater, Less};
            if compare_ref(&a.id, &b.id, &id) {
                Less
            } else if compare_ref(&b.id, &a.id, &id) {
                Greater
            } else {
                Equal
            }
        });
        let expected = nodes[..temp.len()]
            .iter()
            .fold(0, |s, e| sum_distance_exp(s, e, &id));
        let sum_hits = temp.iter().fold(0, |s, e| sum_distance_exp(s, e, &id));
        assert_eq!(bucket_size * 2, temp.len());
        assert_eq!(expected, sum_hits);

        let unique: BTreeSet<_> = temp.iter().map(|e| e.id).collect();
        assert_eq!(unique.len(), temp.len(), "no duplicates");
    }

    // The BEP 42 vectors checked at the end of this test case in libtorrent.
    let ips = [
        "124.31.75.21",
        "21.75.31.124",
        "65.23.51.170",
        "84.124.73.14",
        "43.213.53.83",
    ];
    let rs = [1u32, 86, 22, 65, 90];
    let prefixes: [[u8; 3]; 5] = [
        [0x5f, 0xbf, 0xbf],
        [0x5a, 0x3c, 0xe9],
        [0xa5, 0xd4, 0x32],
        [0x1b, 0x03, 0x21],
        [0xe5, 0x6f, 0x6c],
    ];
    for i in 0..5 {
        let id = generate_id_impl(addr4(ips[i]), rs[i], &mut g.rng);
        assert_eq!(id.0[0], prefixes[i][0]);
        assert_eq!(id.0[1], prefixes[i][1]);
        assert_eq!(id.0[2] & 0xf8, prefixes[i][2] & 0xf8);
        assert_eq!(u32::from(id.0[19]), rs[i]);
    }
}

/// TEST_CASE `routing_table_v4`.
#[test]
fn test_routing_table_v4() {
    test_routing_table(rand_v4, false, 1);
}

/// TEST_CASE `routing_table_v4` with other random streams: the bucket count
/// bounds are statistical, so check several seeds.
#[test]
fn test_routing_table_v4_other_seeds() {
    for seed in 2..8 {
        test_routing_table(rand_v4, false, seed);
    }
}

/// TEST_CASE `routing_table_v6`.
#[test]
fn test_routing_table_v6() {
    test_routing_table(rand_v6, true, 1);
}

// ---------------------------------------------------------------------
// TEST_CASE routing_table_uniform / balance / extended / set_id / for_each
// ---------------------------------------------------------------------

/// TEST_CASE `routing_table_uniform`: 256 evenly distributed nodes fill the
/// top five buckets, i.e. six buckets exist.
#[test]
fn test_routing_table_uniform() {
    let mut g = EpGen::new(11);
    let mut s = test_settings();
    s.extended_routing_table = false;
    // it's difficult to generate valid nodes with specific node IDs, so just
    // turn off that check
    s.prefer_verified_node_ids = false;
    let mut id = to_hash("1234876923549721020394873245098347598635");
    let diff = to_hash("15764f7459456a9453f8719b09547c11d5f34061");
    let mut tbl = v4_table(id, 8, &s);

    // insert 256 nodes evenly distributed across the ID space. We expect to
    // fill the top 5 buckets
    for i in (0..=255u8).rev() {
        add_and_replace(&mut id, &diff);
        // start from distant nodes and work our way in closer to the node id
        id.0[0] ^= i;
        let ep = g.ep();
        tbl.node_seen(id, ep, 20 + u16::from(id.0[19]), now());
        // restore the first byte of the node ID
        id.0[0] ^= i;
    }
    println!("num_active_buckets: {}", tbl.num_active_buckets());
    // number of nodes per tree level: 128, 64, 32, 16, 8, i.e. five levels
    // plus the (empty-ish) last one
    assert_eq!(tbl.num_active_buckets(), 6);
    tbl.check_invariants().unwrap();
}

/// TEST_CASE `routing_table_balance`: nodes that would force an unbalanced
/// table do not.
#[test]
fn test_routing_table_balance() {
    let mut g = EpGen::new(12);
    let mut s = test_settings();
    s.extended_routing_table = false;
    s.prefer_verified_node_ids = false;
    let mut id = to_hash("1234876923549721020394873245098347598635");
    let mut tbl = v4_table(id, 8, &s);

    // insert nodes that will force it to split and make sure we don't end up
    // with a table completely out of balance
    for i in 0..32u32 {
        id.0[0] = ((i << 3) & 0xff) as u8;
        let ep = g.ep();
        tbl.node_seen(id, ep, 20 + u16::from(id.0[19]), now());
    }
    println!("num_active_buckets: {}", tbl.num_active_buckets());
    assert_eq!(tbl.num_active_buckets(), 2);
    tbl.check_invariants().unwrap();
}

/// TEST_CASE `routing_table_extended`: with the extended table the same
/// 256-node load also yields six buckets.
#[test]
fn test_routing_table_extended() {
    let mut g = EpGen::new(13);
    let mut s = test_settings();
    s.extended_routing_table = true;
    s.prefer_verified_node_ids = false;
    let mut id = to_hash("1234876923549721020394873245098347598635");
    let diff = to_hash("15764f7459456a9453f8719b09547c11d5f34061");

    // we can't add the nodes in straight 0,1,2,3 order. That way the routing
    // table would get unbalanced and intermediate nodes would be dropped
    let prefixes = shuffled_bytes(&mut g.rng);
    let mut tbl = v4_table(id, 8, &s);
    for p in prefixes {
        add_and_replace(&mut id, &diff);
        id.0[0] = p;
        let ep = g.ep();
        tbl.node_seen(id, ep, 20 + u16::from(id.0[19]), now());
    }
    assert_eq!(tbl.num_active_buckets(), 6);
    tbl.check_invariants().unwrap();
}

/// TEST_CASE `routing_table_set_id`: after changing our ID to the opposite
/// end of the space the table is shallower and only holds nodes it held
/// before.
#[test]
fn test_routing_table_set_id() {
    let mut g = EpGen::new(14);
    let mut s = test_settings();
    s.enforce_node_id = false;
    s.extended_routing_table = false;
    s.prefer_verified_node_ids = false;
    let mut id = to_hash("0000000000000000000000000000000000000000");

    let prefixes = shuffled_bytes(&mut g.rng);
    let mut tbl = v4_table(id, 8, &s);
    for p in prefixes {
        id.0[0] = p;
        let ep = g.ep();
        tbl.node_seen(id, ep, 20 + u16::from(id.0[19]), now());
    }
    assert_eq!(tbl.num_active_buckets(), 6);

    let mut original = BTreeSet::new();
    tbl.for_each_entry(|e| {
        original.insert(e.id);
    });

    id = to_hash("ffffffffffffffffffffffffffffffffffffffff");
    tbl.set_id(id, now());
    assert_eq!(tbl.id(), id);

    assert!(tbl.num_active_buckets() <= 4);
    let mut remaining = BTreeSet::new();
    tbl.for_each_entry(|e| {
        remaining.insert(e.id);
    });
    // all remaining nodes also exist in the original nodes
    assert!(remaining.is_subset(&original));
    tbl.check_invariants().unwrap();
}

/// TEST_CASE `routing_table_for_each`: live and replacement nodes are
/// visited separately, or together by the single-callback form.
#[test]
fn test_routing_table_for_each() {
    let mut g = EpGen::new(15);
    let mut s = test_settings();
    s.extended_routing_table = false;
    s.prefer_verified_node_ids = false;
    let mut id = to_hash("1234876923549721020394873245098347598635");
    let mut tbl = v4_table(id, 2, &s);

    for i in 0..32u32 {
        id.0[0] = ((i << 3) & 0xff) as u8;
        let ep = g.ep();
        tbl.node_seen(id, ep, 20 + u16::from(id.0[19]), now());
    }

    let (nodes, replacements, _) = tbl.size();
    println!("num_active_buckets: {}", tbl.num_active_buckets());
    assert_eq!(tbl.num_active_buckets(), 2);
    assert_eq!(nodes, 4);
    assert_eq!(replacements, 4);

    let mut v = Vec::new();
    tbl.for_each_node(|e| v.push(*e), |_| {});
    assert_eq!(v.len(), 4);
    v.clear();
    tbl.for_each_node(|_| {}, |e| v.push(*e));
    assert_eq!(v.len(), 4);
    v.clear();
    tbl.for_each_entry(|e| v.push(*e));
    assert_eq!(v.len(), 8);
}

// ---------------------------------------------------------------------
// TEST_CASE dht_verify_node_address
// ---------------------------------------------------------------------

/// TEST_CASE `dht_verify_node_address`: a different IP claiming a known ID
/// is ignored; the known IP:port with a different ID evicts the node.
#[test]
fn test_dht_verify_node_address() {
    let s = DhtSettings {
        extended_routing_table: false,
        ..DhtSettings::default()
    };
    let id = to_hash("3123456789abcdef01232456789abcdef0123456");
    let mut table = v4_table(id, 8, &s);
    assert_eq!(table.size().0, 0);

    let mut tmp = id;
    let diff = to_hash("15764f7459456a9453f8719b09547c11d5f34061");
    add_and_replace(&mut tmp, &diff);
    table.node_seen(tmp, SocketAddr::new(addr4("4.4.4.4"), 4), 10, now());
    let nodes = table.find_node(&id, FindNodeOptions::NONE, 10);
    assert_eq!(table.size().0, 1);
    assert_eq!(nodes.len(), 1);

    // incorrect data, wrong IP
    table.node_seen(tmp, SocketAddr::new(addr4("4.4.4.6"), 4), 10, now());
    let nodes = table.find_node(&id, FindNodeOptions::NONE, 10);
    assert_eq!(table.size().0, 1);
    assert_eq!(nodes.len(), 1);

    // incorrect data, wrong id, should cause node to be removed
    table.node_seen(
        to_hash("0123456789abcdef01232456789abcdef0123456"),
        SocketAddr::new(addr4("4.4.4.4"), 4),
        10,
        now(),
    );
    let nodes = table.find_node(&id, FindNodeOptions::NONE, 10);
    assert_eq!(table.size().0, 0);
    assert_eq!(nodes.len(), 0);
}

// ---------------------------------------------------------------------
// TEST_CASE compare_ip_cidr / mostly_verified_nodes / classify_prefix
// ---------------------------------------------------------------------

/// TEST_CASE `compare_ip_cidr`: /24 for IPv4, /64 for IPv6.
#[test]
fn test_compare_ip_cidr() {
    let v4: [(&str, &str, bool); 8] = [
        ("10.255.255.0", "10.255.255.255", true),
        ("11.0.0.0", "10.255.255.255", false),
        ("0.0.0.0", "128.255.255.255", false),
        ("0.0.0.0", "127.255.255.255", false),
        ("255.255.255.0", "255.255.255.255", true),
        ("255.254.255.0", "255.255.255.255", false),
        ("0.0.0.0", "0.0.0.0", true),
        ("255.255.255.255", "255.255.255.255", true),
    ];
    for (a, b, expected) in v4 {
        assert_eq!(compare_ip_cidr(addr4(a), addr4(b)), expected, "{a} {b}");
    }

    let v6: [(&str, &str, bool); 10] = [
        ("::1", "::ffff:ffff:ffff:ffff", true),
        ("::2:0000:0000:0000:0000", "::1:ffff:ffff:ffff:ffff", false),
        ("::ff:0000:0000:0000:0000", "::ffff:ffff:ffff:ffff", false),
        (
            "::caca:0000:0000:0000:0000",
            "::ffff:ffff:ffff:ffff:ffff",
            false,
        ),
        ("::a:0000:0000:0000:0000", "::b:ffff:ffff:ffff:ffff", false),
        ("::7f:0000:0000:0000:0000", "::ffff:ffff:ffff:ffff", false),
        ("7f::", "ff::", false),
        ("ff::", "ff::", true),
        ("::", "::", true),
        (
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            true,
        ),
    ];
    for (a, b, expected) in v6 {
        assert_eq!(compare_ip_cidr(addr6(a), addr6(b)), expected, "{a} {b}");
    }
}

/// Addresses of different families are never "close" (libtorrent asserts
/// that the families match).
#[test]
fn test_compare_ip_cidr_mixed_families_are_not_close() {
    assert!(!compare_ip_cidr(addr4("1.2.3.4"), addr6("::1")));
    assert!(!compare_ip_cidr(addr6("::1"), addr4("0.0.0.1")));
}

fn fake_node(verified: bool) -> NodeEntry {
    let mut e = NodeEntry::unknown_id("1.2.3.4:5".parse().unwrap());
    e.verified = verified;
    e
}

/// TEST_CASE `mostly_verified_nodes`.
#[test]
fn test_mostly_verified_nodes() {
    let (t, f) = (fake_node(true), fake_node(false));
    // an empty bucket is OK
    assert!(mostly_verified_nodes(&[]));
    assert!(mostly_verified_nodes(&[t]));
    assert!(mostly_verified_nodes(&[t, f]));
    assert!(mostly_verified_nodes(&[t, t, f]));
    assert!(mostly_verified_nodes(&[t, t, t, f]));

    // a large bucket with only half of the nodes verified, does not count
    // as "mostly"
    assert!(!mostly_verified_nodes(&[
        t, f, t, f, t, f, t, f, t, f, t, f
    ]));

    // 1 of 3 is not "mostly"
    assert!(!mostly_verified_nodes(&[f, t, f]));

    assert!(!mostly_verified_nodes(&[f]));
    assert!(!mostly_verified_nodes(&[f, f]));
    assert!(!mostly_verified_nodes(&[f, f, f]));
}

/// `prefix` followed by the repeating filler `cd`, to 40 hex digits: the
/// shape of the literals in the `classify_prefix` test case.
fn h(prefix: &str) -> NodeId {
    let filler: String = "cd".chars().cycle().take(40 - prefix.len()).collect();
    to_hash(&format!("{prefix}{filler}"))
}

fn check_classify(idx: usize, last: bool, bucket_size: usize, cases: &[(&str, u8)]) {
    for (prefix, expected) in cases {
        assert_eq!(
            classify_prefix(idx, last, bucket_size, &h(prefix)),
            *expected,
            "classify_prefix({idx}, {last}, {bucket_size}, {prefix}..)"
        );
    }
}

/// TEST_CASE `classify_prefix`: the slot of an ID in the last bucket, in
/// buckets already split, and for larger buckets.
#[test]
fn test_classify_prefix() {
    let digits = ["0", "2", "4", "6", "8", "a", "c", "e", "f"];
    let eight: [u8; 9] = [0, 1, 2, 3, 4, 5, 6, 7, 7];
    // the last bucket in the routing table
    for (idx, lead) in [(0, ""), (4, "c"), (8, "dc"), (12, "cdc")] {
        let prefixes: Vec<String> = digits.iter().map(|d| format!("{lead}{d}")).collect();
        let cases: Vec<(&str, u8)> = prefixes.iter().map(String::as_str).zip(eight).collect();
        check_classify(idx, true, 8, &cases);
    }

    // not the last bucket in the routing table
    check_classify(
        11,
        false,
        8,
        &[
            ("cdc0", 0),
            ("cdc2", 1),
            ("cdc4", 2),
            ("cdc6", 3),
            ("cdc8", 4),
            ("cdca", 5),
            ("cdcc", 6),
            ("cdce", 7),
            ("cdcf", 7),
        ],
    );
    check_classify(
        12,
        false,
        8,
        &[
            ("cdc8", 0),
            ("cdc9", 1),
            ("cdca", 2),
            ("cdcb", 3),
            ("cdcc", 4),
            ("cdcd", 5),
            ("cdce", 6),
            ("cdcf", 7),
            ("cdc7", 7),
        ],
    );

    // larger bucket
    let sixteen: Vec<(String, u8)> = (0..16u8).map(|d| (format!("cdc{d:x}"), d)).collect();
    let cases: Vec<(&str, u8)> = sixteen.iter().map(|(p, e)| (p.as_str(), *e)).collect();
    check_classify(12, true, 16, &cases);
}

/// A direct, slow definition of `classify_prefix` (shift the whole ID, take
/// the top bits of the first byte) agrees with the byte-wise one for every
/// bucket index, both flavours of `last_bucket`, and every power of two up
/// to 256.
#[test]
fn test_classify_prefix_matches_the_shift_definition() {
    let mut rng = TestRng::new(5);
    for _ in 0..200 {
        let id = generate_random_id(&mut rng);
        for idx in 0..170usize {
            for last in [true, false] {
                for bits in 0..=8u32 {
                    let size = 1usize << bits;
                    let shifted = id.shl(idx + usize::from(!last));
                    let expected = if bits == 0 {
                        0
                    } else {
                        shifted.0[0] >> (8 - bits)
                    };
                    assert_eq!(
                        classify_prefix(idx, last, size, &id),
                        expected,
                        "idx {idx} last {last} size {size}"
                    );
                }
            }
        }
    }
}

/// `classify_prefix` never panics and stays below the bucket size even for
/// sizes that are not powers of two or are zero (libtorrent only asserts).
#[test]
fn test_classify_prefix_tolerates_odd_bucket_sizes() {
    let id = Sha1Hash::MAX;
    assert_eq!(classify_prefix(0, true, 0, &id), 0);
    assert_eq!(classify_prefix(0, true, 1, &id), 0);
    assert!(classify_prefix(0, true, 7, &id) < 4);
    assert_eq!(classify_prefix(0, true, 256, &id), 255);
    assert_eq!(classify_prefix(0, true, 4096, &id), 255);
    assert_eq!(
        classify_prefix(1000, false, 8, &id),
        0,
        "past the end reads zeros"
    );
}

// ---------------------------------------------------------------------
// TEST_CASE replace_node_impl / all_in_same_bucket
// ---------------------------------------------------------------------

fn bucket(g: &mut EpGen, p: &mut IpSet, specs: &[(&str, u16, u8)]) -> Vec<NodeEntry> {
    specs
        .iter()
        .map(|(id, rtt, failed)| n(g, Some(p), id, true, *rtt, *failed))
        .collect()
}

/// TEST_CASE `replace_node_impl`: replace the node in the same prefix slot.
#[test]
fn test_replace_node_impl_replaces_same_prefix_slot() {
    let mut g = EpGen::new(21);
    let mut p = IpSet::default();
    let mut b = bucket(
        &mut g,
        &mut p,
        &[
            ("1fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("3fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("5fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("7fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("9fffffffffffffffffffffffffffffffffffffff", 50, 0), // <== replaced
            ("bfffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("dfffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("ffffffffffffffffffffffffffffffffffffffff", 50, 0),
        ],
    );
    assert_eq!(p.len(), 8);
    let e = n(
        &mut g,
        None,
        "9fcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        true,
        0,
        0,
    );
    assert_eq!(
        replace_node_impl(&e, &mut b, &mut p, 0, 8, true),
        AddNodeStatus::NodeAdded
    );
    assert_eq!(b[4].id, to_hash("9fcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"));
    assert_eq!(p.len(), 8);
}

/// TEST_CASE `replace_node_impl`: only try to replace the specific prefix
/// slot; if that fails (RTT is higher) replace nothing else.
#[test]
fn test_replace_node_impl_keeps_better_node_in_slot() {
    let mut g = EpGen::new(22);
    let mut p = IpSet::default();
    let mut b = bucket(
        &mut g,
        &mut p,
        &[
            ("1fffffffffffffffffffffffffffffffffffffff", 500, 0),
            ("3fffffffffffffffffffffffffffffffffffffff", 500, 0),
            ("5fffffffffffffffffffffffffffffffffffffff", 500, 0),
            ("7fffffffffffffffffffffffffffffffffffffff", 500, 0),
            ("9fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("bfffffffffffffffffffffffffffffffffffffff", 500, 0),
            ("dfffffffffffffffffffffffffffffffffffffff", 500, 0),
            ("ffffffffffffffffffffffffffffffffffffffff", 500, 0),
        ],
    );
    let e = n(
        &mut g,
        None,
        "9fcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        true,
        100,
        0,
    );
    assert_ne!(
        replace_node_impl(&e, &mut b, &mut p, 0, 8, true),
        AddNodeStatus::NodeAdded
    );
    assert_eq!(b[4].id, to_hash("9fffffffffffffffffffffffffffffffffffffff"));
    assert_eq!(p.len(), 8);
}

/// TEST_CASE `replace_node_impl`: with several candidates, the one with the
/// highest RTT among the crowded prefix slots is replaced.
#[test]
fn test_replace_node_impl_picks_worst_of_crowded_slots() {
    let mut g = EpGen::new(23);
    let mut p = IpSet::default();
    let mut b = bucket(
        &mut g,
        &mut p,
        &[
            ("1fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("3fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("5fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("7fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("bfffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("bfffffffffffffffffffffffffffffffffffffff", 51, 0), // <== replaced
            ("dfffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("ffffffffffffffffffffffffffffffffffffffff", 50, 0),
        ],
    );
    let e = n(
        &mut g,
        None,
        "9fcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        true,
        50,
        0,
    );
    assert_eq!(
        replace_node_impl(&e, &mut b, &mut p, 0, 8, true),
        AddNodeStatus::NodeAdded
    );
    assert_eq!(b[5].id, to_hash("9fcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"));
    assert_eq!(p.len(), 8);
}

/// TEST_CASE `replace_node_impl`: a node with fail count > 0 is replaced
/// regardless of anything else.
#[test]
fn test_replace_node_impl_prefers_failed_node() {
    let mut g = EpGen::new(24);
    let mut p = IpSet::default();
    let mut b = bucket(
        &mut g,
        &mut p,
        &[
            ("1fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("3fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("5fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("7fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("9fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("bfffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("dfffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("ffffffffffffffffffffffffffffffffffffffff", 50, 1), // <== replaced
        ],
    );
    let e = n(
        &mut g,
        None,
        "9fcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        true,
        50,
        0,
    );
    assert_eq!(
        replace_node_impl(&e, &mut b, &mut p, 0, 8, true),
        AddNodeStatus::NodeAdded
    );
    assert_eq!(b[7].id, to_hash("9fcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"));
    assert_eq!(p.len(), 8);
}

/// Ties between equally bad candidates go to the first in bucket order, like
/// C++ `std::max_element` (Rust's `max_by` would pick the last one).
#[test]
fn test_replace_node_impl_breaks_ties_towards_the_first_candidate() {
    let mut g = EpGen::new(25);
    let mut p = IpSet::default();
    let mut b = bucket(
        &mut g,
        &mut p,
        &[
            ("1fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("3fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("5fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("7fffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("bfffffffffffffffffffffffffffffffffffffff", 70, 0), // <== first of the tie
            ("bfffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("dfffffffffffffffffffffffffffffffffffffff", 50, 0),
            ("dfffffffffffffffffffffffffffffffffffffff", 70, 0), // same RTT, later slot
        ],
    );
    let e = n(
        &mut g,
        None,
        "9fcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        true,
        50,
        0,
    );
    assert_eq!(
        replace_node_impl(&e, &mut b, &mut p, 0, 8, true),
        AddNodeStatus::NodeAdded
    );
    assert_eq!(b[4].id, e.id, "slot 5 comes before slot 6");
    // and the same for equal failure counts: first of the failed ones
    let mut b = bucket(
        &mut g,
        &mut p,
        &[
            ("1fffffffffffffffffffffffffffffffffffffff", 50, 2),
            ("3fffffffffffffffffffffffffffffffffffffff", 50, 2),
        ],
    );
    let e = n(
        &mut g,
        None,
        "5fcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        true,
        50,
        0,
    );
    assert_eq!(
        replace_node_impl(&e, &mut b, &mut p, 0, 2, true),
        AddNodeStatus::NodeAdded
    );
    assert_eq!(b[0].id, e.id);
}

/// An empty bucket has no victim; libtorrent would dereference `end()`.
#[test]
fn test_replace_node_impl_on_an_empty_bucket_finds_no_victim() {
    let mut g = EpGen::new(26);
    let mut p = IpSet::default();
    let e = n(
        &mut g,
        None,
        "9fcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        true,
        50,
        0,
    );
    assert_eq!(
        replace_node_impl(&e, &mut [], &mut p, 0, 8, true),
        AddNodeStatus::NeedBucketSplit
    );
}

/// TEST_CASE `all_in_same_bucket`.
#[test]
fn test_all_in_same_bucket() {
    let mut g = EpGen::new(27);
    let node = |g: &mut EpGen, id: &str| n(g, None, id, true, 0, 0);
    assert!(all_in_same_bucket(
        &[],
        &to_hash("8000000000000000000000000000000000000000"),
        0
    ));
    assert!(all_in_same_bucket(
        &[],
        &to_hash("8000000000000000000000000000000000000001"),
        1
    ));
    assert!(all_in_same_bucket(
        &[],
        &to_hash("8000000000000000000000000000000000000002"),
        2
    ));
    assert!(all_in_same_bucket(
        &[],
        &to_hash("8000000000000000000000000000000000000003"),
        3
    ));

    let b = [node(&mut g, "0000000000000000000000000000000000000000")];
    assert!(!all_in_same_bucket(
        &b,
        &to_hash("8000000000000000000000000000000000000000"),
        0
    ));

    let b = [
        node(&mut g, "8000000000000000000000000000000000000000"),
        node(&mut g, "f000000000000000000000000000000000000000"),
    ];
    assert!(all_in_same_bucket(
        &b,
        &to_hash("8000000000000000000000000000000000000000"),
        0
    ));

    let b = [
        node(&mut g, "8000000000000000000000000000000000000000"),
        node(&mut g, "0000000000000000000000000000000000000000"),
    ];
    assert!(!all_in_same_bucket(
        &b,
        &to_hash("8000000000000000000000000000000000000000"),
        0
    ));

    let b = [
        node(&mut g, "0800000000000000000000000000000000000000"),
        node(&mut g, "0000000000000000000000000000000000000000"),
    ];
    assert!(!all_in_same_bucket(
        &b,
        &to_hash("0800000000000000000000000000000000000000"),
        4
    ));

    let b = [
        node(&mut g, "0800000000000000000000000000000000000000"),
        node(&mut g, "0800000000000000000000000000000000000000"),
    ];
    assert!(all_in_same_bucket(
        &b,
        &to_hash("0800000000000000000000000000000000000000"),
        4
    ));

    let b = [
        node(&mut g, "0007000000000000000000000000000000000000"),
        node(&mut g, "0004000000000000000000000000000000000000"),
    ];
    assert!(all_in_same_bucket(
        &b,
        &to_hash("0005000000000000000000000000000000000000"),
        13
    ));
}

/// A bit index past the end of the ID reads as zero instead of indexing out
/// of bounds as libtorrent's would.
#[test]
fn test_all_in_same_bucket_tolerates_out_of_range_bit_index() {
    let mut g = EpGen::new(28);
    let b = [n(
        &mut g,
        None,
        "ffffffffffffffffffffffffffffffffffffffff",
        true,
        0,
        0,
    )];
    assert!(all_in_same_bucket(&b, &Sha1Hash::MAX, 400));
}

// ---------------------------------------------------------------------
// IpSet
// ---------------------------------------------------------------------

/// `ip_set` is a multiset: duplicates count, and each `erase` removes one.
#[test]
fn test_ip_set_is_a_multiset() {
    let mut s = IpSet::default();
    assert!(s.is_empty());
    let a = addr4("1.2.3.4");
    let b = addr6("2001::1");
    s.insert(a);
    s.insert(a);
    s.insert(b);
    assert_eq!(s.len(), 3);
    assert!(s.erase(a));
    assert!(s.exists(a));
    assert!(s.erase(a));
    assert!(!s.exists(a));
    assert!(!s.erase(a), "erasing an absent address reports it");
    assert_eq!(s.len(), 1);
    s.clear();
    assert!(s.is_empty() && !s.exists(b));
}

/// An IPv4-mapped IPv6 address is a different element from the IPv4 address
/// (libtorrent keeps separate v4 and v6 sets).
#[test]
fn test_ip_set_keeps_families_apart() {
    let mut s = IpSet::default();
    s.insert(addr4("1.2.3.4"));
    assert!(!s.exists(addr6("::ffff:1.2.3.4")));
}

// ---------------------------------------------------------------------
// behaviour not covered by libtorrent's tests
// ---------------------------------------------------------------------

fn ep4(a: &str, port: u16) -> SocketAddr {
    SocketAddr::new(addr4(a), port)
}

/// An id whose first byte is `first` and whose other bytes come from `rest`.
fn id_with(first: u8, rest: u8) -> NodeId {
    let mut id = Sha1Hash([rest; 20]);
    id.0[0] = first;
    id
}

fn plain_settings() -> DhtSettings {
    DhtSettings {
        enforce_node_id: false,
        extended_routing_table: false,
        prefer_verified_node_ids: false,
        ..DhtSettings::default()
    }
}

/// `RoutingTable::try_new` rejects bucket sizes that are not powers of two.
#[test]
fn test_try_new_rejects_bad_bucket_sizes() {
    let s = DhtSettings::default();
    let id = Sha1Hash::MIN;
    for bad in [0usize, 3, 6, 12] {
        assert_eq!(
            RoutingTable::try_new(id, Protocol::V4, bad, &s).unwrap_err(),
            RoutingTableError::InvalidBucketSize(bad)
        );
    }
    for good in [1usize, 2, 8, 16] {
        assert!(RoutingTable::try_new(id, Protocol::V4, good, &s).is_ok());
    }
}

/// `new` panics on a bad bucket size, with a message.
#[test]
#[should_panic(expected = "power of two")]
fn test_new_panics_on_bad_bucket_size() {
    let _ = RoutingTable::new(Sha1Hash::MIN, Protocol::V4, 7, &DhtSettings::default());
}

/// An empty table: nothing to find, depth 0, one estimated global node.
#[test]
fn test_empty_table() {
    let mut t = v4_table(Sha1Hash::MIN, 8, &DhtSettings::default());
    assert_eq!(t.size(), (0, 0, 0));
    assert_eq!(t.num_active_buckets(), 0);
    assert!(t
        .find_node(&Sha1Hash::MAX, FindNodeOptions::INCLUDE_FAILED, 0)
        .is_empty());
    assert_eq!(t.num_global_nodes(), 1);
    assert_eq!(t.depth(), 0);
    assert!(t.status().is_empty());
    assert!(t.next_refresh(now()).is_none());
    assert_eq!(t.bucket_len(5), 0);
    assert!(!t.is_full(0));
    t.check_invariants().unwrap();
}

/// Regression for a libtorrent bug (see the module docs of
/// `routing_table`): `routing_table::depth()` stores -1 when it is called on
/// an empty table and returns it forever after, even once nodes arrive. Here
/// the depth is recomputed once the table has buckets.
#[test]
fn test_depth_recovers_after_empty_table() {
    let s = plain_settings();
    let mut g = EpGen::new(31);
    let mut t = v4_table(Sha1Hash::MIN, 8, &s);
    assert_eq!(t.depth(), 0); // called while empty, as node::tick does
                              // fill the first buckets: 40 nodes with first bytes spread over the space
    for i in 0..64u8 {
        let ep = g.ep();
        t.node_seen(id_with(i << 2, i), ep, 10, now());
    }
    assert!(t.num_active_buckets() >= 2, "{}", t.print_state(now()));
    assert_eq!(t.depth(), 1, "depth stuck at the empty-table value");
}

/// `depth()` walks from its previous value (a hysteresis): it is reached by
/// going deeper while the next bucket is half full.
#[test]
fn test_depth_follows_half_full_buckets() {
    let s = plain_settings();
    let mut g = EpGen::new(32);
    let mut t = v4_table(Sha1Hash::MIN, 8, &s);
    for i in 0..255u8 {
        let ep = g.ep();
        t.node_seen(id_with(i, 1), ep, 10, now());
    }
    let d = t.depth();
    assert!(d >= 1 && d < t.num_active_buckets(), "depth {d}");
    assert_eq!(t.depth(), d, "repeatable once settled");
}

/// A node with our own ID, or of the other address family, is rejected.
#[test]
fn test_rejects_own_id_and_foreign_family() {
    let mut t = v4_table(id_with(0x10, 0), 8, &plain_settings());
    assert!(!t.node_seen(t.id(), ep4("4.4.4.4", 1), 10, now()));
    let v6: SocketAddr = "[2001::1]:1".parse().unwrap();
    assert!(!t.node_seen(id_with(0x80, 0), v6, 10, now()));
    assert!(!t.add_node(NodeEntry::new(id_with(0x80, 0), v6, 10, true), now()));
    assert_eq!(t.size(), (0, 0, 0));
    assert!(t.native_address(&addr4("1.2.3.4")) && !t.native_address(&addr6("::1")));
    assert!(t.native_endpoint(&ep4("1.2.3.4", 1)) && !t.native_endpoint(&v6));
}

/// Router nodes are never added to the table, and are listed in order.
#[test]
fn test_router_nodes_are_never_added() {
    let mut t = v4_table(id_with(0x10, 0), 8, &plain_settings());
    let r = ep4("9.9.9.9", 6881);
    t.add_router_node(r);
    t.add_router_node(ep4("1.1.1.1", 6881));
    t.add_router_node(r);
    assert!(!t.node_seen(id_with(0x80, 0), r, 10, now()));
    assert!(t.node_seen(id_with(0x80, 0), ep4("9.9.9.9", 6882), 10, now()));
    let routers: Vec<_> = t.router_nodes().copied().collect();
    assert_eq!(routers, [ep4("1.1.1.1", 6881), r]);
}

/// The IP filter blocks nodes, but not router nodes (which are not stored).
#[test]
fn test_ip_filter_blocks_nodes() {
    let mut t = v4_table(id_with(0x10, 0), 8, &plain_settings());
    t.set_ip_filter(Some(Arc::new(|a| a == addr4("4.4.4.4"))));
    assert!(!t.node_seen(id_with(0x80, 0), ep4("4.4.4.4", 1), 10, now()));
    assert!(t.node_seen(id_with(0x80, 1), ep4("4.4.5.5", 1), 10, now()));
    t.set_ip_filter(None);
    assert!(t.node_seen(id_with(0x80, 2), ep4("4.4.4.4", 1), 10, now()));
}

/// With `enforce_node_id` a node whose ID does not match its IP is refused
/// by `node_seen` and `heard_about`; matching IDs are accepted.
#[test]
fn test_enforce_node_id() {
    let mut s = plain_settings();
    s.enforce_node_id = true;
    let mut g = EpGen::new(33);
    let mut t = v4_table(id_with(0x10, 0), 8, &s);
    let ip = addr4("124.31.75.21");
    let good = generate_id_impl(ip, 1, &mut g.rng);
    let mut bad = good;
    bad.0[0] ^= 1;
    assert!(!t.node_seen(bad, SocketAddr::new(ip, 1), 10, now()));
    t.heard_about(bad, SocketAddr::new(ip, 2), now());
    assert_eq!(t.size(), (0, 0, 0));
    assert!(t.node_seen(good, SocketAddr::new(ip, 1), 10, now()));
    assert_eq!(t.size(), (1, 0, 1));
}

/// A heard-about node cannot be live; it waits in the replacement cache
/// (not confirmed, not returned by `find_node` unless asked) until it
/// answers, when `node_seen` promotes it.
#[test]
fn test_heard_about_goes_to_replacements_until_seen() {
    let mut t = v4_table(id_with(0x10, 0), 8, &plain_settings());
    let id = id_with(0x80, 3);
    let ep = ep4("4.4.4.4", 1);
    t.heard_about(id, ep, now());
    assert_eq!(t.size(), (0, 1, 0));
    assert!(t
        .find_node(&id, FindNodeOptions::INCLUDE_FAILED, 8)
        .is_empty());
    assert_eq!(
        t.replacement_nodes().next().unwrap().timeout_count,
        NEVER_PINGED
    );

    assert!(t.node_seen(id, ep, 25, now()));
    assert_eq!(t.size(), (1, 0, 1));
    let found = t.find_node(&id, FindNodeOptions::NONE, 8);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].rtt, 25);
    t.check_invariants().unwrap();
}

/// `find_node` hides unconfirmed (failed) nodes unless `INCLUDE_FAILED`.
#[test]
fn test_find_node_include_failed() {
    let mut t = v4_table(id_with(0x10, 0), 8, &plain_settings());
    let (a, b) = (id_with(0x80, 1), id_with(0x90, 2));
    t.node_seen(a, ep4("4.4.4.4", 1), 10, now());
    t.node_seen(b, ep4("5.5.5.5", 1), 10, now());
    t.node_failed(&a, ep4("4.4.4.4", 1));
    let ids = |v: Vec<NodeEntry>| v.into_iter().map(|e| e.id).collect::<BTreeSet<_>>();
    assert_eq!(
        ids(t.find_node(&a, FindNodeOptions::NONE, 8)),
        BTreeSet::from([b])
    );
    assert_eq!(
        ids(t.find_node(&a, FindNodeOptions::INCLUDE_FAILED, 8)),
        BTreeSet::from([a, b])
    );
}

/// `find_node` with `count == 0` means `bucket_size`, and a smaller count
/// returns exactly the closest nodes of a single bucket.
#[test]
fn test_find_node_count_semantics() {
    let mut g = EpGen::new(34);
    let mut t = v4_table(id_with(0x00, 0), 8, &plain_settings());
    for i in 0..8u8 {
        let ep = g.ep();
        t.node_seen(id_with(0x80 | i, 7), ep, 10, now());
    }
    let target = id_with(0x80, 0);
    assert_eq!(t.find_node(&target, FindNodeOptions::NONE, 0).len(), 8);
    let two = t.find_node(&target, FindNodeOptions::NONE, 2);
    assert_eq!(two.len(), 2);
    let want: BTreeSet<_> = [id_with(0x80, 7), id_with(0x81, 7)].into();
    assert_eq!(two.iter().map(|e| e.id).collect::<BTreeSet<_>>(), want);
}

/// When the target's own bucket has too few nodes, `find_node` continues
/// with the closer buckets and then the farther ones.
#[test]
fn test_find_node_spills_into_neighbouring_buckets() {
    let mut g = EpGen::new(35);
    let mut t = v4_table(id_with(0x00, 0), 2, &plain_settings());
    for first in [0x80u8, 0x90, 0x40, 0x50, 0x20, 0x10, 0x01] {
        let ep = g.ep();
        t.node_seen(id_with(first, 7), ep, 10, now());
    }
    let target = id_with(0x42, 0);
    let got = t.find_node(&target, FindNodeOptions::NONE, 100);
    assert_eq!(
        got.len(),
        t.size().0,
        "every live node is eventually returned"
    );
    // libtorrent takes whole buckets in table order (the target's bucket, then
    // the ones closer to us) and only ranks within the last one it needs, so
    // 0x20 (bucket 2) is taken before the nearer 0x01 (bucket 7).
    let top3 = t.find_node(&target, FindNodeOptions::NONE, 3);
    let want: BTreeSet<_> = [0x40u8, 0x50, 0x20].map(|b| id_with(b, 7)).into();
    assert_eq!(top3.iter().map(|e| e.id).collect::<BTreeSet<_>>(), want);
}

/// With `restrict_routing_ips`, a second node from the same /24 is refused
/// in the same bucket, but accepted when the restriction is off.
#[test]
fn test_restrict_routing_ips_same_slash_24() {
    let mut s = plain_settings();
    let mut t = v4_table(id_with(0x10, 0), 8, &s);
    assert!(t.node_seen(id_with(0x80, 1), ep4("4.4.4.4", 1), 10, now()));
    assert!(!t.node_seen(id_with(0x80, 2), ep4("4.4.4.9", 1), 10, now()));
    assert!(
        !t.node_seen(id_with(0x80, 3), ep4("4.4.4.4", 2), 10, now()),
        "same IP, other port"
    );
    s.restrict_routing_ips = false;
    t.set_settings(&s);
    assert!(t.node_seen(id_with(0x80, 2), ep4("4.4.4.9", 1), 10, now()));
    assert!(t.node_seen(id_with(0x80, 3), ep4("4.4.4.4", 2), 10, now()));
    assert_eq!(t.size().0, 3);
    t.check_invariants().unwrap();
}

/// Removing a node frees its IP for another node (the IP set stays in step
/// when nodes leave, including via `node_failed` and eviction).
#[test]
fn test_ip_is_released_when_a_node_is_removed() {
    let s = plain_settings();
    let mut t = v4_table(id_with(0x10, 0), 8, &s);
    let (id, ep) = (id_with(0x80, 1), ep4("4.4.4.4", 1));
    t.node_seen(id, ep, 10, now());
    for _ in 0..s.max_fail_count {
        t.node_failed(&id, ep);
    }
    assert_eq!(t.size().0, 0);
    t.check_invariants().unwrap();
    assert!(
        t.node_seen(id_with(0x81, 1), ep4("4.4.4.5", 1), 10, now()),
        "IP free again"
    );
}

/// `node_failed` without a replacement: the node stays (with a growing fail
/// count) until `max_fail_count` failures, then goes. A mismatched endpoint
/// and our own ID are ignored.
#[test]
fn test_node_failed_without_replacement_removes_at_max_fail_count() {
    let s = DhtSettings {
        max_fail_count: 3,
        ..plain_settings()
    };
    let mut t = v4_table(id_with(0x10, 0), 2, &s);
    let (a, ea) = (id_with(0x80, 1), ep4("4.4.4.4", 1));
    t.node_seen(a, ea, 10, now());

    t.node_failed(&a, ep4("4.4.4.4", 99)); // other endpoint claiming the ID
    t.node_failed(&t.id(), ea);
    assert_eq!(t.live_nodes().next().unwrap().timeout_count, 0);

    t.node_failed(&a, ea);
    t.node_failed(&a, ea);
    assert_eq!(t.live_nodes().next().unwrap().fail_count(), 2);
    t.node_failed(&a, ea);
    assert_eq!(t.size().0, 0, "three of three failures");
    t.check_invariants().unwrap();
}

/// `node_failed` with a replacement waiting: the failed node is replaced at
/// the first failure, and the replacement becomes live.
#[test]
fn test_node_failed_with_replacement_swaps_at_once() {
    let mut t = v4_table(id_with(0x10, 0), 2, &plain_settings());
    let (a, b, c) = (id_with(0x80, 1), id_with(0x90, 2), id_with(0xa0, 3));
    let (ea, eb, ec) = (ep4("4.4.4.4", 1), ep4("5.5.5.5", 1), ep4("6.6.6.6", 1));
    t.node_seen(a, ea, 10, now());
    t.node_seen(b, eb, 10, now());
    // the bucket cannot split (all three share the top bit) and nothing is
    // worse than c, so c waits in the replacement cache
    assert!(t.node_seen(c, ec, 10, now()));
    assert_eq!(t.size(), (2, 1, 2));
    t.node_failed(&a, ea);
    assert_eq!(
        t.live_nodes().map(|e| e.id).collect::<BTreeSet<_>>(),
        BTreeSet::from([b, c])
    );
    assert_eq!(t.size().1, 0);
    t.check_invariants().unwrap();
}

/// A node that failed is replaced at once by a confirmed newcomer, even when
/// the newcomer is not better (a stale node loses to anything).
#[test]
fn test_failed_node_is_replaced_by_a_newcomer() {
    let mut t = v4_table(id_with(0x10, 0), 2, &plain_settings());
    let (a, b, c) = (id_with(0x80, 1), id_with(0x90, 2), id_with(0xa0, 3));
    let (ea, eb, ec) = (ep4("4.4.4.4", 1), ep4("5.5.5.5", 1), ep4("6.6.6.6", 1));
    t.node_seen(a, ea, 10, now());
    t.node_seen(b, eb, 10, now());
    t.node_failed(&a, ea);
    assert!(t.node_seen(c, ec, 10, now()));
    assert_eq!(
        t.live_nodes().map(|e| e.id).collect::<BTreeSet<_>>(),
        BTreeSet::from([b, c])
    );
    assert_eq!(t.size(), (2, 0, 2));
    t.check_invariants().unwrap();
}

/// A replacement that never answered is dropped by `node_failed` marking,
/// and a failed replacement is not promoted over a good one.
#[test]
fn test_node_failed_on_replacement_counts_failures() {
    let mut t = v4_table(id_with(0x10, 0), 1, &plain_settings());
    let (a, b) = (id_with(0x80, 1), id_with(0x90, 2));
    t.node_seen(a, ep4("4.4.4.4", 1), 10, now());
    assert!(t.node_seen(b, ep4("5.5.5.5", 1), 10, now()));
    assert_eq!(t.size(), (1, 1, 1));
    t.node_failed(&b, ep4("5.5.5.5", 1));
    assert_eq!(t.replacement_nodes().next().unwrap().timeout_count, 1);
}

/// The same endpoint reappearing with another ID (and having answered) evicts
/// the old entry and schedules the other nodes of its bucket for re-pinging
/// when they were last queried more than five minutes ago.
#[test]
fn test_changed_id_evicts_and_schedules_reping() {
    let mut t = v4_table(id_with(0x10, 0), 8, &plain_settings());
    let t0 = now();
    let old_ep = ep4("4.4.4.4", 1);
    t.node_seen(id_with(0x80, 1), old_ep, 10, t0);
    t.node_seen(id_with(0x81, 2), ep4("5.5.5.5", 1), 10, t0);
    let later = t0 + Duration::from_secs(6 * 60);
    t.node_seen(id_with(0x82, 3), ep4("6.6.6.6", 1), 10, later);
    assert!(!t.node_seen(id_with(0x83, 4), old_ep, 10, later));
    assert_eq!(t.size().0, 2);
    let stamps: Vec<_> = t
        .live_nodes()
        .map(|e| (e.addr(), e.last_queried == Time::ZERO))
        .collect();
    assert!(
        stamps.contains(&(addr4("5.5.5.5"), true)),
        "old node scheduled"
    );
    assert!(
        stamps.contains(&(addr4("6.6.6.6"), false)),
        "recent node untouched"
    );
    t.check_invariants().unwrap();
}

/// A not-yet-confirmed claim on a known endpoint with a new ID never replaces
/// the existing entry (poisoning protection), and with the restriction off
/// it does not evict it either.
#[test]
fn test_unconfirmed_id_change_does_not_evict() {
    let s = plain_settings();
    let mut t = v4_table(id_with(0x10, 0), 8, &s);
    let ep = ep4("4.4.4.4", 1);
    t.node_seen(id_with(0x80, 1), ep, 10, now());
    t.heard_about(id_with(0x80, 2), ep, now());
    assert_eq!(t.size(), (1, 0, 1));
    assert_eq!(t.live_nodes().next().unwrap().id, id_with(0x80, 1));
}

/// A node first learned without an ID (all zeros) is replaced by the real
/// entry when the ID arrives.
#[test]
fn test_unknown_id_entry_is_replaced_by_real_id() {
    let mut t = v4_table(id_with(0x10, 0), 8, &plain_settings());
    let ep = ep4("4.4.4.4", 1);
    let mut unknown = NodeEntry::unknown_id(ep);
    unknown.timeout_count = 0;
    assert!(t.add_node(unknown, now()));
    assert_eq!(t.live_nodes().next().unwrap().id, Sha1Hash::MIN);
    assert!(t.node_seen(id_with(0x80, 9), ep, 10, now()));
    assert_eq!(t.size(), (1, 0, 1));
    assert_eq!(t.live_nodes().next().unwrap().id, id_with(0x80, 9));
    t.check_invariants().unwrap();
}

/// A node already live is refreshed: failures cleared and RTT averaged.
#[test]
fn test_node_seen_refreshes_a_live_node() {
    let mut t = v4_table(id_with(0x10, 0), 8, &plain_settings());
    let (id, ep) = (id_with(0x80, 1), ep4("4.4.4.4", 1));
    t.node_seen(id, ep, 90, now());
    t.node_failed(&id, ep);
    t.node_seen(id, ep, 30, now());
    let e = *t.live_nodes().next().unwrap();
    assert_eq!(e.timeout_count, 0);
    assert_eq!(e.rtt, 90 * 2 / 3 + 30 / 3);
}

/// A full bucket that cannot split caches new confirmed nodes in the
/// replacement bucket, which is bounded by `bucket_size`.
#[test]
fn test_replacement_bucket_is_bounded() {
    let s = plain_settings();
    let mut g = EpGen::new(36);
    let mut t = v4_table(id_with(0x00, 0), 2, &s);
    // all in the farthest bucket (first bit differs), same slot pattern
    for i in 0..10u8 {
        let ep = g.ep();
        t.node_seen(id_with(0x80 | i, 5), ep, 10 + u16::from(i), now());
    }
    let (live, repl, _) = t.size();
    assert_eq!(live, 2);
    assert!(repl <= 2, "replacements {repl}");
    t.check_invariants().unwrap();
}

/// A bucket promotes replacements by quality: the lowest RTT (verified
/// first) is promoted when a live node is removed.
#[test]
fn test_fill_from_replacements_prefers_low_rtt() {
    let s = plain_settings();
    let mut g = EpGen::new(37);
    let mut t = v4_table(id_with(0x00, 0), 1, &s);
    let live = id_with(0x80, 1);
    let live_ep = g.ep();
    t.node_seen(live, live_ep, 10, now());
    let slow = (id_with(0x81, 2), g.ep());
    let fast = (id_with(0x82, 3), g.ep());
    // not better than the live one, so they are cached
    assert!(t.node_seen(slow.0, slow.1, 900, now()));
    assert!(t.node_seen(fast.0, fast.1, 200, now()));
    assert_eq!(t.size().1, 1, "bucket_size 1: only one replacement is kept");
    t.node_failed(&live, live_ep);
    assert_eq!(t.size().0, 1);
    let promoted = t.live_nodes().next().unwrap().id;
    assert!(promoted == slow.0 || promoted == fast.0);
    t.check_invariants().unwrap();
}

/// `bucket_limit`: 16x, 8x, 4x, 2x for the first four buckets with the
/// extended table, `bucket_size` otherwise.
#[test]
fn test_bucket_limit() {
    let mut s = DhtSettings {
        extended_routing_table: true,
        ..DhtSettings::default()
    };
    let t = v4_table(Sha1Hash::MIN, 8, &s);
    let limits: Vec<_> = (0..6).map(|i| t.bucket_limit(i)).collect();
    assert_eq!(limits, [128, 64, 32, 16, 8, 8]);
    s.extended_routing_table = false;
    let t = v4_table(Sha1Hash::MIN, 8, &s);
    assert!((0..6).all(|i| t.bucket_limit(i) == 8));
}

/// `is_full` needs both the live bucket and the replacement cache full.
#[test]
fn test_is_full() {
    let s = plain_settings();
    let mut g = EpGen::new(38);
    let mut t = v4_table(id_with(0x00, 0), 2, &s);
    assert!(!t.is_full(0));
    for i in 0..8u8 {
        let ep = g.ep();
        t.node_seen(id_with(0x80 | i, 5), ep, 10, now());
    }
    assert!(t.is_full(0));
    assert!(!t.is_full(1) && !t.is_full(99));
}

/// `num_global_nodes` for a few shapes: a lone partial bucket, one full
/// bucket, and the saturating case.
#[test]
fn test_num_global_nodes() {
    let s = plain_settings();
    let mut g = EpGen::new(39);
    let mut t = v4_table(id_with(0x00, 0), 8, &s);
    for i in 0..3u8 {
        let ep = g.ep();
        t.node_seen(id_with(0x80 | i, 5), ep, 10, now());
    }
    assert_eq!(t.num_global_nodes(), 1 + 3);
    for i in 3..8u8 {
        let ep = g.ep();
        t.node_seen(id_with(0x80 | i, 5), ep, 10, now());
    }
    // one full bucket and nothing beyond: 2 << 1 * 8 = (2 << deepest_bucket) * size
    assert_eq!(t.num_global_nodes(), (2u64 << 1) * 8);
}

/// `next_refresh` picks never-queried nodes first (closest bucket first),
/// stamps them, and then falls back to the least recently queried node.
#[test]
fn test_next_refresh_order_and_stamping() {
    let s = plain_settings();
    let mut t = v4_table(id_with(0x00, 0), 8, &s);
    let t0 = now();
    // node_seen stamps pinged nodes with `now`: nothing is "never queried"
    let (a, b) = (id_with(0x80, 1), id_with(0x40, 2));
    t.node_seen(a, ep4("4.4.4.4", 1), 10, t0);
    t.node_seen(b, ep4("5.5.5.5", 1), 10, t0 + Duration::from_secs(10));

    let later = t0 + Duration::from_secs(60);
    let (first, _) = t.next_refresh(later).unwrap();
    assert_eq!(first.id, a, "the node queried longest ago");
    assert_eq!(first.last_queried, later);
    let (second, _) = t.next_refresh(later + Duration::from_secs(1)).unwrap();
    assert_eq!(second.id, b);
    let (third, _) = t.next_refresh(later + Duration::from_secs(2)).unwrap();
    assert_eq!(third.id, a);
}

/// A never-queried live node wins immediately, in the bucket closest to us.
#[test]
fn test_next_refresh_prefers_never_queried_close_nodes() {
    let s = plain_settings();
    let mut t = v4_table(id_with(0x00, 0), 8, &s);
    let t0 = now();
    for (i, first) in [0x80u8, 0x40, 0x20].into_iter().enumerate() {
        let mut e = NodeEntry::new_at(
            id_with(first, 1),
            ep4("4.4.4.4", 1 + i as u16),
            10,
            true,
            t0,
        );
        e.endpoint = SocketAddr::new(addr4(&format!("{}.4.4.4", i + 4)), 1);
        assert!(t.add_node(e, t0));
    }
    // make the farthest and the closest "never queried"
    let mut never = NodeEntry::new(id_with(0x21, 1), ep4("9.4.4.4", 1), 10, true);
    never.last_queried = Time::ZERO;
    assert!(t.add_node(never, t0));
    let (picked, bucket) = t.next_refresh(t0 + Duration::from_secs(1)).unwrap();
    assert_eq!(picked.id, never.id);
    assert_eq!(bucket, t.num_active_buckets() - 1);
}

/// An unpinged replacement in the last bucket is refreshed too, once.
#[test]
fn test_next_refresh_pings_unpinged_replacements() {
    let s = plain_settings();
    let mut t = v4_table(id_with(0x00, 0), 8, &s);
    let t0 = now();
    t.heard_about(id_with(0x80, 1), ep4("4.4.4.4", 1), t0);
    let (picked, bucket) = t.next_refresh(t0).unwrap();
    assert_eq!((picked.id, bucket), (id_with(0x80, 1), 0));
    // stamped: a second refresh has nothing new, and live nodes there are none
    assert_eq!(t.next_refresh(t0 + Duration::from_secs(1)), None);
}

/// `status` and `status_into` report per-bucket populations; `status_into`
/// keeps the longer of the old and new reports.
#[test]
fn test_status_reports_buckets() {
    let s = plain_settings();
    let mut g = EpGen::new(40);
    let mut t = v4_table(id_with(0x00, 0), 2, &s);
    for i in 0..6u8 {
        let ep = g.ep();
        t.node_seen(id_with(0x80 | i, 5), ep, 10, now());
    }
    let st = t.status();
    assert_eq!(st.len(), t.num_active_buckets());
    assert_eq!(st.iter().map(|b| b.num_nodes).sum::<usize>(), t.size().0);
    assert_eq!(
        st.iter().map(|b| b.num_replacements).sum::<usize>(),
        t.size().1
    );

    let mut longer = vec![st[0]; st.len() + 3];
    t.status_into(&mut longer);
    assert_eq!(
        longer.len(),
        st.len() + 3,
        "a deeper table's report is kept"
    );
    let mut shorter = Vec::new();
    t.status_into(&mut shorter);
    assert_eq!(shorter, st);
}

/// `write_state` prints the sections of libtorrent's `print_state`.
#[test]
fn test_print_state_has_the_expected_sections() {
    let s = plain_settings();
    let mut g = EpGen::new(41);
    let mut t = v4_table(id_with(0x00, 0), 8, &s);
    for i in 0..20u8 {
        let ep = g.ep();
        t.node_seen(id_with(i * 12, 5), ep, 10 + u16::from(i), now());
    }
    t.heard_about(id_with(0xee, 5), g.ep(), now());
    let out = t.print_state(now() + Duration::from_secs(5));
    for needle in [
        "kademlia routing table state",
        "bucket_size: 8",
        "global node count:",
        "number of nodes per bucket:",
        "=== BUCKET == 0 ==",
        "prefix:",
        "node spread per bucket:",
        "[",
    ] {
        assert!(out.contains(needle), "missing {needle:?} in\n{out}");
    }
}

/// Splitting keeps every node in the bucket its ID belongs to and keeps the
/// IP set consistent, under a long random workload with all operations.
#[test]
fn test_random_workload_preserves_invariants() {
    for seed in 0..6u64 {
        let mut g = EpGen::new(100 + seed);
        let s = DhtSettings {
            restrict_routing_ips: seed % 2 == 0,
            extended_routing_table: seed % 3 != 0,
            prefer_verified_node_ids: seed % 4 != 0,
            ..DhtSettings::default()
        };
        let mut t = v4_table(generate_random_id(&mut g.rng), 8, &s);
        let mut known: Vec<(NodeId, SocketAddr)> = Vec::new();
        let mut clock = now();
        for step in 0..3000u32 {
            clock = clock + Duration::from_secs(1);
            let r = g.rng.random(9);
            if r < 3 || known.is_empty() {
                let ep = g.ep();
                let id = if g.rng.random(1) == 0 {
                    generate_id_impl(ep.ip(), g.rng.next_u32(), &mut g.rng)
                } else {
                    generate_random_id(&mut g.rng)
                };
                known.push((id, ep));
                t.node_seen(id, ep, g.rng.random(500) as u16, clock);
            } else {
                let (id, ep) = known[g.rng.random(known.len() as u32 - 1) as usize];
                match r {
                    3 | 4 => {
                        t.node_seen(id, ep, g.rng.random(500) as u16, clock);
                    }
                    5 => t.heard_about(id, ep, clock),
                    6 => t.node_failed(&id, ep),
                    7 => {
                        t.next_refresh(clock);
                    }
                    _ => {
                        let target = generate_random_id(&mut g.rng);
                        let found = t.find_node(&target, FindNodeOptions::INCLUDE_FAILED, 8);
                        assert!(found.len() <= 8);
                    }
                }
            }
            if step % 500 == 499 {
                t.set_id(generate_random_id(&mut g.rng), clock);
            }
            if let Err(e) = t.check_invariants() {
                panic!("seed {seed} step {step}: {e}\n{}", t.print_state(clock));
            }
        }
    }
}

/// Regression for a libtorrent bug found by the `routing_table_ops` fuzz
/// target. `add_node` splits the last bucket and retries; afterwards it
/// erases the new last bucket "if none of the nodes ended up in it" but
/// only looks at its *live* nodes. A new bucket holding only replacements is
/// erased with them, and their addresses stay in the IP set forever (with
/// `restrict_routing_ips` those IPs could then never be added again).
///
/// Sequence: a node that is only a replacement is re-announced behind
/// another entry for the same endpoint; this promotes it, asks for a split,
/// and the retry (with the original, unpinged entry) lands in the new
/// bucket's replacement cache, where the new bucket has no live node.
#[test]
fn test_split_does_not_drop_a_new_bucket_holding_only_replacements() {
    let s = DhtSettings {
        restrict_routing_ips: false,
        ..plain_settings()
    };
    let mut t = v4_table(id_with(0x00, 0), 2, &s);
    // two live nodes on the far side fill the only bucket
    assert!(t.node_seen(id_with(0x80, 1), ep4("1.1.1.1", 1), 10, now()));
    assert!(t.node_seen(id_with(0x90, 2), ep4("2.2.2.2", 1), 10, now()));
    let shared = ep4("3.3.3.3", 1);
    let (x1, x2) = (id_with(0x20, 3), id_with(0x30, 4));
    // two unconfirmed nodes behind one endpoint; x2 is found first by endpoint
    t.heard_about(x2, shared, now());
    t.heard_about(x1, shared, now());
    assert_eq!(t.size(), (2, 2, 2));
    // x1 again: located via x2's entry (another ID, ignored), promoted from
    // the cache, which requests a split
    t.heard_about(x1, shared, now());
    t.check_invariants().unwrap();
    assert_eq!(t.num_active_buckets(), 2, "the new bucket is kept");
    assert_eq!(t.size().0, 2);
    assert!(t.replacement_nodes().any(|e| e.id == x2));
}
