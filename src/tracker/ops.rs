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
//! # Operations without a libtorrent counterpart
//!
//! Peer lookups, announces, bootstraps, samples and direct requests are
//! *tasks*: they run on some or all nodes, and the tracker tells the owner
//! when the last of those node-level lookups has ended
//! ([`Event::OperationDone`]). Their results are tagged too; since the nodes
//! report peers by info-hash and samples by endpoint, results are routed by
//! those keys to the operations waiting for them (a peer is delivered once
//! per operation). Direct requests carry the operation id as their token.
//! Samples of one endpoint run one at a time, because replies can arrive in
//! any order and a reply names no request.
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

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
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

#[derive(Default)]
struct SampleLane {
    current: Option<OpId>,
    waiting: VecDeque<(OpId, NodeId)>,
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

/// What a task's results are routed by.
pub(crate) enum TaskKind {
    /// A `get_peers` or `announce` of this info-hash.
    Peers(NodeId),
    /// A `sample_infohashes` to this endpoint.
    Sample(SocketAddr, NodeId),
    /// Bootstrap and direct requests: nothing to route.
    Plain,
}

/// Per-tracker operation state.
#[derive(Default)]
pub(crate) struct Aggregator {
    /// How many nodes an operation fans out to (kept in sync by the
    /// tracker).
    pub nodes: usize,
    next_op: u64,
    /// Running tasks and how many node-level lookups of each are left.
    tasks: HashMap<OpId, usize>,
    /// Peer-lookup operations by info-hash, with the peers already
    /// delivered to each.
    peer_ops: HashMap<NodeId, Vec<(OpId, HashSet<SocketAddr>)>>,
    /// Sample operations by endpoint: the running one and those waiting.
    sample_lanes: HashMap<SocketAddr, SampleLane>,
    /// Samples whose turn has come: (operation, endpoint, target).
    pub samples_to_start: Vec<(OpId, SocketAddr, NodeId)>,
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
        self.tasks.len()
            + self
                .immutable_gets
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
            out.push_back(Event::OperationDone { op });
            return false;
        }
        if let Some(g) = self.immutable_gets.get_mut(&target) {
            match &g.posted {
                Some(item) => {
                    out.push_back(tagged(op, found(target, item.clone())));
                    out.push_back(Event::OperationDone { op });
                }
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
            out.push_back(Event::OperationDone { op });
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
            out.push_back(Event::OperationDone { op: job.op });
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
                Event::GetPeersReply { target, peers } => self.peers_reply(target, peers, out),
                Event::SampleInfohashes {
                    from,
                    nid,
                    interval,
                    num,
                    samples,
                    nodes,
                } => {
                    let ev = Event::SampleInfohashes {
                        from,
                        nid,
                        interval,
                        num,
                        samples,
                        nodes,
                    };
                    match self.sample_lanes.get(&from).and_then(|l| l.current) {
                        Some(op) => out.push_back(tagged(op, ev)),
                        None => out.push_back(ev),
                    }
                }
                Event::DirectResponse { token, from, reply } => {
                    let ev = Event::DirectResponse { token, from, reply };
                    if self.tasks.contains_key(&OpId(token)) {
                        out.push_back(tagged(OpId(token), ev));
                    } else {
                        out.push_back(ev);
                    }
                }
                Event::LookupFinished { tag } => self.lookup_finished(OpId(tag), out),
                other => out.push_back(other),
            }
        }
    }

    /// Registers a task running on `running` nodes. With none it is done at
    /// once.
    pub fn start_task(
        &mut self,
        op: OpId,
        running: usize,
        kind: TaskKind,
        out: &mut VecDeque<Event>,
    ) {
        if running == 0 {
            out.push_back(Event::OperationDone { op });
            return;
        }
        self.tasks.insert(op, running);
        match kind {
            TaskKind::Peers(target) => self
                .peer_ops
                .entry(target)
                .or_default()
                .push((op, HashSet::new())),
            TaskKind::Sample(ep, target) => {
                let lane = self.sample_lanes.entry(ep).or_default();
                if lane.current.is_none() {
                    lane.current = Some(op);
                    self.samples_to_start.push((op, ep, target));
                } else {
                    lane.waiting.push_back((op, target));
                }
            }
            TaskKind::Plain => {}
        }
    }

    fn peers_reply(&mut self, target: NodeId, peers: Vec<SocketAddr>, out: &mut VecDeque<Event>) {
        let Some(ops) = self.peer_ops.get_mut(&target) else {
            out.push_back(Event::GetPeersReply { target, peers });
            return;
        };
        for (op, seen) in ops.iter_mut() {
            let fresh: Vec<SocketAddr> =
                peers.iter().copied().filter(|p| seen.insert(*p)).collect();
            if !fresh.is_empty() {
                out.push_back(tagged(
                    *op,
                    Event::GetPeersReply {
                        target,
                        peers: fresh,
                    },
                ));
            }
        }
    }

    fn lookup_finished(&mut self, op: OpId, out: &mut VecDeque<Event>) {
        let Some(left) = self.tasks.get_mut(&op) else {
            return;
        };
        *left = left.saturating_sub(1);
        if *left > 0 {
            return;
        }
        self.tasks.remove(&op);
        self.peer_ops.retain(|_, v| {
            v.retain(|(o, _)| *o != op);
            !v.is_empty()
        });
        let mut next = Vec::new();
        self.sample_lanes.retain(|ep, lane| {
            lane.waiting.retain(|(o, _)| *o != op);
            if lane.current == Some(op) {
                lane.current = lane.waiting.pop_front().map(|(o, t)| {
                    next.push((o, *ep, t));
                    o
                });
            }
            lane.current.is_some()
        });
        self.samples_to_start.extend(next);
        out.push_back(Event::OperationDone { op });
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
                    out.push_back(Event::OperationDone { op });
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
                    if last {
                        out.push_back(Event::OperationDone { op: *op });
                    }
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
        out.push_back(Event::OperationDone { op: done.op });
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
        let mut ops: Vec<OpId> = self.tasks.drain().map(|(op, _)| op).collect();
        self.peer_ops.clear();
        self.sample_lanes.clear();
        self.samples_to_start.clear();
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
