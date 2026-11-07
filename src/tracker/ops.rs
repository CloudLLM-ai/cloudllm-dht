//! Bookkeeping of the BEP 44 operations a [`crate::tracker::Dht`] runs
//! across all its nodes.
//!
//! Ports the `get_immutable_item_ctx`, `get_mutable_item_ctx` and
//! `put_item_ctx` structs and their callbacks in
//! `src/kademlia/dht_tracker.cpp` (libtorrent RC_2_1, commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`, BSD-3-Clause, Copyright Arvid
//! Norberg and contributors), extended so that every operation has its own
//! [`OpId`].
//!
//! # Why this is not a straight port
//!
//! libtorrent hands each operation its own `std::function`, so two
//! operations never see each other's results. Here the nodes report through
//! [`Event`]s that carry only the *target*, so operations are told apart by
//! rules instead:
//!
//! * **Gets** of one target are *coalesced*: they would receive the same
//!   answer, so a second get of a target already being fetched joins the
//!   running one (and receives its result as soon as there is one). Every
//!   joined operation gets its own tagged result.
//! * **Puts** of one target run *one at a time, in the order they were
//!   started*: two writers of the same slot must not interleave (the
//!   second one's data callback then sees the first one's item, which is
//!   how compare-and-swap chains).
//! * A get and a put of the same target never interfere: a put's inner
//!   lookup reports nothing.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use crate::bencode::Entry;
use crate::events::{Event, OpId};
use crate::item::Item;
use crate::node_id::NodeId;
use crate::types::PublicKey;

/// What a queued put writes.
pub(crate) enum PutKind {
    Immutable(Entry),
    Mutable {
        pk: PublicKey,
        salt: Vec<u8>,
        cb: Arc<dyn Fn(&mut Item) + Send + Sync>,
    },
}

/// A put waiting for its turn or ready to start.
pub(crate) struct PutJob {
    pub op: OpId,
    pub target: NodeId,
    pub kind: PutKind,
}

struct Running {
    op: OpId,
    active: usize,
    responses: usize,
}

#[derive(Default)]
struct Lane {
    current: Option<Running>,
    waiting: VecDeque<PutJob>,
}

struct ImmutableGet {
    ops: Vec<OpId>,
    active: usize,
    posted: Option<Item>,
}

struct MutableGet {
    ops: Vec<OpId>,
    active: usize,
    best: Item,
}

/// Per-tracker operation state.
#[derive(Default)]
pub(crate) struct Aggregator {
    /// How many nodes an operation fans out to (kept in sync by the
    /// tracker).
    pub nodes: usize,
    next_op: u64,
    immutable_gets: HashMap<NodeId, ImmutableGet>,
    mutable_gets: HashMap<NodeId, MutableGet>,
    lanes: HashMap<NodeId, Lane>,
    /// Puts that became current and must be started on the nodes.
    pub to_start: Vec<PutJob>,
}

fn tagged(op: OpId, result: Event) -> Event {
    Event::Operation {
        op,
        result: Box::new(result),
    }
}

impl Aggregator {
    /// A fresh operation id.
    pub fn new_op(&mut self) -> OpId {
        self.next_op += 1;
        OpId(self.next_op)
    }

    /// Number of operations still waiting for a result.
    pub fn in_flight(&self) -> usize {
        self.immutable_gets
            .values()
            .map(|g| g.ops.len())
            .sum::<usize>()
            + self
                .mutable_gets
                .values()
                .map(|g| g.ops.len())
                .sum::<usize>()
            + self
                .lanes
                .values()
                .map(|l| l.waiting.len() + usize::from(l.current.is_some()))
                .sum::<usize>()
    }

    /// Registers an immutable get; returns `true` when the caller must run
    /// it on the nodes (it did not join a running one).
    pub fn start_immutable_get(
        &mut self,
        op: OpId,
        target: NodeId,
        out: &mut VecDeque<Event>,
    ) -> bool {
        if self.nodes == 0 {
            out.push_back(tagged(op, empty_get(target)));
            return false;
        }
        if let Some(g) = self.immutable_gets.get_mut(&target) {
            match &g.posted {
                Some(item) => out.push_back(tagged(op, found(target, item.clone()))),
                None => g.ops.push(op),
            }
            return false;
        }
        self.immutable_gets.insert(
            target,
            ImmutableGet {
                ops: vec![op],
                active: self.nodes,
                posted: None,
            },
        );
        true
    }

    /// Registers a mutable get; `true` when the caller must run it.
    pub fn start_mutable_get(
        &mut self,
        op: OpId,
        target: NodeId,
        out: &mut VecDeque<Event>,
    ) -> bool {
        if self.nodes == 0 {
            out.push_back(tagged(op, empty_get(target)));
            return false;
        }
        if let Some(g) = self.mutable_gets.get_mut(&target) {
            g.ops.push(op);
            return false;
        }
        self.mutable_gets.insert(
            target,
            MutableGet {
                ops: vec![op],
                active: self.nodes,
                best: Item::new(),
            },
        );
        true
    }

    /// Queues a put; it is added to `to_start` when it is its target's
    /// turn.
    pub fn enqueue_put(&mut self, job: PutJob, out: &mut VecDeque<Event>) {
        if self.nodes == 0 {
            out.push_back(tagged(
                job.op,
                Event::PutDone {
                    target: job.target,
                    item: Item::new(),
                    responses: 0,
                },
            ));
            return;
        }
        let lane = self.lanes.entry(job.target).or_default();
        if lane.current.is_none() {
            lane.current = Some(Running {
                op: job.op,
                active: self.nodes,
                responses: 0,
            });
            self.to_start.push(job);
        } else {
            lane.waiting.push_back(job);
        }
    }

    /// Moves `scratch` (the events one node call produced) to `out`,
    /// folding the BEP 44 events into tagged operation results; every other
    /// event passes through.
    pub fn absorb(&mut self, scratch: &mut Vec<Event>, out: &mut VecDeque<Event>) {
        for ev in scratch.drain(..) {
            match ev {
                Event::GetItemDone {
                    target,
                    item,
                    authoritative,
                } => self.get_done(target, item, authoritative, out),
                Event::PutDone {
                    target,
                    item,
                    responses,
                } => self.put_done(target, item, responses, out),
                other => out.push_back(other),
            }
        }
    }

    fn get_done(
        &mut self,
        target: NodeId,
        item: Item,
        authoritative: bool,
        out: &mut VecDeque<Event>,
    ) {
        if let Some(g) = self.immutable_gets.get_mut(&target) {
            g.active = g.active.saturating_sub(1);
            if g.posted.is_none() && (!item.is_empty() || g.active == 0) {
                for op in g.ops.drain(..) {
                    out.push_back(tagged(op, found(target, item.clone())));
                }
                g.posted = Some(item);
            }
            if g.active == 0 {
                self.immutable_gets.remove(&target);
            }
        } else if let Some(g) = self.mutable_gets.get_mut(&target) {
            if authoritative {
                g.active = g.active.saturating_sub(1);
            }
            let last = authoritative && g.active == 0;
            let better = (g.best.is_empty() && !item.is_empty()) || g.best.seq() < item.seq();
            if better {
                g.best = item;
            }
            // libtorrent passes the last node's item on the final callback;
            // the best one found is what a caller wants there.
            if better || last {
                for op in &g.ops {
                    out.push_back(tagged(
                        *op,
                        Event::GetItemDone {
                            target,
                            item: g.best.clone(),
                            authoritative: last,
                        },
                    ));
                }
            }
            if last {
                self.mutable_gets.remove(&target);
            }
        }
    }

    fn put_done(
        &mut self,
        target: NodeId,
        item: Item,
        responses: usize,
        out: &mut VecDeque<Event>,
    ) {
        let nodes = self.nodes;
        let Some(lane) = self.lanes.get_mut(&target) else {
            return;
        };
        let Some(run) = lane.current.as_mut() else {
            return;
        };
        run.responses += responses;
        run.active = run.active.saturating_sub(1);
        if run.active > 0 {
            return;
        }
        let done = lane.current.take().expect("checked above");
        out.push_back(tagged(
            done.op,
            Event::PutDone {
                target,
                item,
                responses: done.responses,
            },
        ));
        if let Some(next) = lane.waiting.pop_front() {
            lane.current = Some(Running {
                op: next.op,
                active: nodes,
                responses: 0,
            });
            self.to_start.push(next);
        } else {
            self.lanes.remove(&target);
        }
    }

    /// Cancels every operation in flight (shutdown, socket removed).
    pub fn cancel_all(&mut self, out: &mut VecDeque<Event>) {
        let mut ops: Vec<OpId> = Vec::new();
        ops.extend(self.immutable_gets.drain().flat_map(|(_, g)| g.ops));
        ops.extend(self.mutable_gets.drain().flat_map(|(_, g)| g.ops));
        for (_, lane) in self.lanes.drain() {
            ops.extend(lane.current.map(|r| r.op));
            ops.extend(lane.waiting.into_iter().map(|j| j.op));
        }
        self.to_start.clear();
        ops.sort();
        out.extend(ops.into_iter().map(|op| Event::OperationCancelled { op }));
    }
}

fn empty_get(target: NodeId) -> Event {
    found(target, Item::new())
}

fn found(target: NodeId, item: Item) -> Event {
    Event::GetItemDone {
        target,
        item,
        authoritative: true,
    }
}
