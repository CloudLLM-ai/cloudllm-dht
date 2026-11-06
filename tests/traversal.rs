//! Tests for the traversal algorithm base (`traversal_algorithm.cpp`) and
//! the lookups built on it, including the `test_dht.cpp` cases that drive
//! them (libtorrent RC_2_1, `86d573f2631b0162d3cca5e257217eaf530fdcba`).

mod common;

use std::net::SocketAddr;

use cloudllm_dht::ctx::NodeCtx;
use cloudllm_dht::node_id::{compare_ref, NodeId};
use cloudllm_dht::observer::{ObserverFlags, ObserverId};
use cloudllm_dht::testing::{ep, rand_v4};
use cloudllm_dht::traversal::algorithm::{add_entry, base_done, set_id, Plain, MAX_RESULTS};
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
