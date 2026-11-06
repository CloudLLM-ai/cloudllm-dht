//! BEP 44 `get`: look an item up, immutable or mutable.
//!
//! Ports `include/libtorrent/kademlia/get_item.hpp` and
//! `src/kademlia/get_item.cpp` and the `get_item` entry points of
//! `node.cpp` (libtorrent RC_2_1, commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`, BSD-3-Clause, Copyright Arvid
//! Norberg and Alden Torres).
//!
//! # What counts as an answer
//!
//! * **Immutable** (`target` = SHA-1 of the bencoded value): the first
//!   response whose `v` hashes to the target wins at once; there is only one
//!   true item for a target, so the lookup ends without waiting for the rest.
//! * **Mutable** (`target` = SHA-1 of key and salt): a response must carry
//!   `k`, `sig` and `seq` beside `v`; it counts only if the key and salt give
//!   the looked-up target and the signature verifies. The highest sequence
//!   number wins, so the lookup runs to completion and reports each
//!   improvement as it appears (non-authoritative) and the final winner
//!   (authoritative).
//!
//! A response with a `k` and a `sig` but no `seq` is malformed and fails the
//! request.

use std::net::SocketAddr;

use crate::bencode::{Entry, Node};
use crate::ctx::NodeCtx;
use crate::events::Event;
use crate::item::{immutable_item_target_id, item_target_id, Item};
use crate::node_id::NodeId;
use crate::observer::{ObserverId, ObserverKind};
use crate::types::{PublicKey, SequenceNumber, Signature};

use super::algorithm::{observer_timeout, Algorithm};
use super::find_data::{self, FindDataCore, HasFindData, NodesCallback};
use super::put_data::DataCallback;
use super::Traversal;

/// What a [`GetItem`] does with the items it finds (libtorrent's
/// `data_callback`, which `node.cpp` fills in three different ways).
pub enum Report {
    /// Nothing: the lookup only exists to find the nodes for a `put` of an
    /// immutable item (libtorrent passes an empty `data_callback`). Data in
    /// responses is ignored.
    Silent,
    /// Report every item as an [`Event::GetItemDone`] (`node::get_item`).
    Events,
    /// The lookup before a mutable `put`: stay quiet while looking, then,
    /// once the authoritative item is known, let the callback produce the
    /// item to store and hand it to the put (`node.cpp` `put_data_cb`).
    PrepareMutablePut(DataCallback),
}

impl std::fmt::Debug for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Silent => "Report::Silent",
            Self::Events => "Report::Events",
            Self::PrepareMutablePut(_) => "Report::PrepareMutablePut(..)",
        })
    }
}

/// A BEP 44 `get` lookup (libtorrent `get_item`).
#[derive(Debug)]
pub struct GetItem {
    algo: Algorithm,
    fd: FindDataCore,
    report: Report,
    data: Item,
    immutable: bool,
}

impl GetItem {
    /// A lookup for the immutable item stored under `target`.
    #[must_use]
    pub fn new_immutable(
        ctx: &mut NodeCtx<'_>,
        target: NodeId,
        report: Report,
        next: NodesCallback,
    ) -> Self {
        Self {
            algo: Algorithm::new(ctx.new_traversal_id(), target),
            fd: FindDataCore::new(next),
            report,
            data: Item::new(),
            immutable: true,
        }
    }

    /// A lookup for the mutable item of `pk` and `salt`.
    #[must_use]
    pub fn new_mutable(
        ctx: &mut NodeCtx<'_>,
        pk: PublicKey,
        salt: &[u8],
        report: Report,
        next: NodesCallback,
    ) -> Self {
        Self {
            algo: Algorithm::new(ctx.new_traversal_id(), item_target_id(salt, &pk)),
            fd: FindDataCore::new(next),
            report,
            data: Item::for_key(pk, salt),
            immutable: false,
        }
    }

    /// The best item found so far.
    #[must_use]
    pub fn data(&self) -> &Item {
        &self.data
    }

    /// Calls the data callback (libtorrent `m_data_callback(m_data, auth)`).
    fn deliver(&mut self, ctx: &mut NodeCtx<'_>, authoritative: bool) {
        match &mut self.report {
            Report::Silent => {}
            Report::Events => ctx.events.push(Event::GetItemDone {
                target: *self.algo.target(),
                item: self.data.clone(),
                authoritative,
            }),
            Report::PrepareMutablePut(data_cb) => {
                // only the authoritative item is worth asking the caller
                // about
                if authoritative {
                    let mut item = self.data.clone();
                    data_cb(&mut item);
                    if let NodesCallback::Put(put) = &mut self.fd.next {
                        put.set_data(item);
                    }
                }
            }
        }
    }

    /// `get_item::got_data`: a response carried a value.
    fn got_data(
        &mut self,
        ctx: &mut NodeCtx<'_>,
        v: &Node<'_>,
        pk: &PublicKey,
        seq: SequenceNumber,
        sig: &Signature,
    ) {
        // we received data! If nobody listens, we needn't care about it:
        // only an immutable put has no data callback
        if matches!(self.report, Report::Silent) {
            return;
        }
        if self.immutable {
            // the item was already found and reported
            if !self.data.is_empty() {
                return;
            }
            if immutable_item_target_id(v.data_section()) != *self.algo.target() {
                return;
            }
            self.data = Item::immutable_from_node(v);
            // There can only be one true immutable item with a given id.
            // Now that we have it, and the user does not want to do a put,
            // there is no point in asking more nodes.
            self.deliver(ctx, true);
            self.done(ctx);
            return;
        }

        // Mutable data. If it passes the signature check, remember it,
        // keeping the version with the highest sequence number.
        if item_target_id(self.data.salt(), pk) != *self.algo.target() {
            return;
        }
        if self.data.is_empty() || self.data.seq() < seq {
            let Ok(item) = Item::from_signed_node(v, self.data.salt(), seq, pk, sig) else {
                return;
            };
            self.data = item;
            // The caller gets this as soon as it arrives, even though it may
            // not be the last word, rather than after the 15 s a silent
            // node can take to time out. (For a put the callback ignores
            // non-authoritative data.)
            self.deliver(ctx, false);
        }
    }

    /// `get_item_observer::reply`.
    fn reply(&mut self, ctx: &mut NodeCtx<'_>, obs: ObserverId, msg: &Node<'_>) {
        let Some(r) = msg.dict_find_dict(b"r") else {
            observer_timeout(self, ctx, obs);
            return;
        };
        let k = r.dict_find_string(b"k");
        let pk = k
            .and_then(|k| PublicKey::from_slice(k.string_value()))
            .unwrap_or_default();
        let s = r.dict_find_string(b"sig");
        let sig = s
            .and_then(|s| Signature::from_slice(s.string_value()))
            .unwrap_or_default();
        let seq = if let Some(q) = r.dict_find_int(b"seq") {
            SequenceNumber(q.int_value())
        } else if k.is_some() && s.is_some() {
            observer_timeout(self, ctx, obs);
            return;
        } else {
            SequenceNumber(0)
        };
        if let Some(v) = r.dict_find(b"v") {
            self.got_data(ctx, v, &pk, seq, &sig);
        }
        find_data::observer_reply(self, ctx, obs, msg);
    }
}

impl HasFindData for GetItem {
    fn fd(&self) -> &FindDataCore {
        &self.fd
    }

    fn fd_mut(&mut self) -> &mut FindDataCore {
        &mut self.fd
    }
}

impl Traversal for GetItem {
    fn name(&self) -> &'static str {
        "get"
    }

    fn algo(&self) -> &Algorithm {
        &self.algo
    }

    fn algo_mut(&mut self) -> &mut Algorithm {
        &mut self.algo
    }

    fn new_observer(&self) -> ObserverKind {
        ObserverKind::GetItem
    }

    fn start(&mut self, ctx: &mut NodeCtx<'_>) {
        find_data::start(self, ctx);
    }

    fn invoke(&mut self, ctx: &mut NodeCtx<'_>, obs: ObserverId) -> bool {
        if self.fd.is_done() {
            return false;
        }
        let Some(ep) = ctx.rpc.observers.get(obs).map(|o| o.target) else {
            return false;
        };
        let mut a = Entry::dict();
        a.set("target", self.algo.target().0.to_vec());
        let mut e = Entry::dict();
        e.set("q", "get").set("a", a);
        ctx.invoke(e, ep, obs)
    }

    /// `get_item::done`. For a mutable item, or when nothing was found, the
    /// callback gets the last word now: every node has been heard from, so
    /// the highest sequence number among them is the latest version.
    fn done(&mut self, ctx: &mut NodeCtx<'_>) {
        if !matches!(self.report, Report::Silent)
            && (self.data.is_mutable() || self.data.is_empty())
        {
            self.deliver(ctx, true);
        }
        find_data::done(self, ctx);
    }

    fn on_reply(
        &mut self,
        ctx: &mut NodeCtx<'_>,
        obs: ObserverId,
        _from: SocketAddr,
        msg: &Node<'_>,
    ) {
        self.reply(ctx, obs, msg);
    }
}

/// `node::get_item` for an immutable item: a lookup that reports the item
/// as an [`Event::GetItemDone`] (`authoritative` is `true`, and the item is
/// empty if nobody had it).
#[must_use]
pub fn get_immutable(ctx: &mut NodeCtx<'_>, target: NodeId) -> Box<dyn Traversal> {
    Box::new(GetItem::new_immutable(
        ctx,
        target,
        Report::Events,
        NodesCallback::None,
    ))
}

/// `node::get_item` for a mutable item: a lookup that reports each better
/// version as it arrives and the final one at the end, as
/// [`Event::GetItemDone`].
#[must_use]
pub fn get_mutable(ctx: &mut NodeCtx<'_>, pk: PublicKey, salt: &[u8]) -> Box<dyn Traversal> {
    Box::new(GetItem::new_mutable(
        ctx,
        pk,
        salt,
        Report::Events,
        NodesCallback::None,
    ))
}
