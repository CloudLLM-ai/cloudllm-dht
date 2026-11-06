//! An in-flight request: the record the RPC manager keeps per transaction.
//!
//! Ports `include/libtorrent/kademlia/observer.hpp` and the `observer`
//! members defined in `src/kademlia/rpc_manager.cpp` (libtorrent RC_2_1,
//! commit `86d573f2631b0162d3cca5e257217eaf530fdcba`, BSD-3-Clause,
//! Copyright Arvid Norberg, Steven Siloti, Thomas Yuan, Alden Torres).
//!
//! # From `shared_ptr<observer>` to an arena
//!
//! In libtorrent an `observer` is a heap object shared by two owners: the
//! traversal's `m_results` vector and the RPC manager's `m_transactions`
//! multimap, and it points back at its traversal (`shared_ptr`), which in
//! turn points at the node. Rust forbids that cycle, so:
//!
//! * observers live in an [`Observers`] arena owned by the RPC manager;
//! * both holders keep an [`ObserverId`] and a *reference count* in the
//!   arena stands in for the `shared_ptr` count (see [`Observers::acquire`]
//!   and [`Observers::release`]);
//! * an observer names its traversal by [`TraversalId`], and the arena
//!   counts live observers per traversal so the owner can drop a finished
//!   traversal exactly when its last observer is gone, the moment libtorrent's
//!   `shared_ptr<traversal_algorithm>` would hit zero.
//!
//! The virtual `observer::reply` of the C++ class hierarchy becomes a match
//! on [`ObserverKind`] inside the traversal that owns the observer.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::node_id::NodeId;
use crate::time::Time;

/// Identifies a traversal (a lookup, a bootstrap, a single direct request)
/// within one node. Ids are issued once and never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TraversalId(pub u64);

/// A handle to an [`Observer`] in an [`Observers`] arena.
///
/// Handles are generational: using one after its observer was freed is
/// detected (the lookup returns `None`) instead of reaching whatever reused
/// the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObserverId {
    index: u32,
    generation: u32,
}

/// The per-observer flag set (libtorrent `observer_flags_t`).
///
/// A plain bit set rather than a `bitflags!` type so the crate keeps its
/// dependency list short; the constants carry the documentation of the C++
/// `flag_*` members.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::observer::ObserverFlags;
///
/// let f = ObserverFlags::QUERIED | ObserverFlags::ALIVE;
/// assert!(f.contains(ObserverFlags::QUERIED));
/// assert!(!f.contains(ObserverFlags::FAILED));
/// assert_eq!(f & (ObserverFlags::QUERIED | ObserverFlags::FAILED), ObserverFlags::QUERIED);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct ObserverFlags(u8);

impl ObserverFlags {
    /// No flags.
    pub const EMPTY: Self = Self(0);
    /// The request was (or was about to be) sent: it counts in the
    /// traversal's `invoke_count` and must be balanced when a response or
    /// timeout arrives (`flag_queried`).
    pub const QUERIED: Self = Self(1 << 0);
    /// The node came from the routing table or the caller's seed list, not
    /// from another node's response. Such nodes are exempt from the
    /// "one node per /24" search restriction (`flag_initial`).
    pub const INITIAL: Self = Self(1 << 1);
    /// The node's ID was not known when the observer was created (a
    /// bootstrap node); the ID it carries is a random placeholder
    /// (`flag_no_id`).
    pub const NO_ID: Self = Self(1 << 2);
    /// No answer after the short timeout: the traversal opened another
    /// slot but still waits for the full timeout (`flag_short_timeout`).
    pub const SHORT_TIMEOUT: Self = Self(1 << 3);
    /// The request failed: timeout, error, unparsable reply, or never sent
    /// (`flag_failed`).
    pub const FAILED: Self = Self(1 << 4);
    /// A valid response was received from this node (`flag_alive`).
    pub const ALIVE: Self = Self(1 << 5);
    /// The request is finished or cancelled; it must no longer call back
    /// into its traversal (`flag_done`).
    pub const DONE: Self = Self(1 << 6);

    /// `true` if every bit of `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// `true` if any bit of `other` is set in `self` (the C++
    /// `bool(flags & x)` for a single flag).
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// `self` with the bits of `other` cleared.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// `true` if no bit is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for ObserverFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for ObserverFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for ObserverFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

/// Which request an observer belongs to, and therefore how its reply is
/// parsed (the concrete subclass of the C++ `observer`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserverKind {
    /// `null_observer`: ignores the reply content and only marks itself
    /// done. Used by the plain traversal and by tests.
    Null,
    /// `find_data_observer`.
    FindData,
    /// `get_peers_observer`; also what `bootstrap` uses.
    GetPeers,
    /// `obfuscated_get_peers_observer`.
    ObfuscatedGetPeers,
    /// `get_item_observer`.
    GetItem,
    /// `put_data_observer`: carries the write token the `put` must present.
    Put {
        /// The token the node gave in its `get`/`get_peers` response.
        token: Vec<u8>,
    },
    /// `sample_infohashes_observer`.
    SampleInfohashes,
    /// `direct_observer`.
    Direct,
    /// `ping_observer` (in `node.cpp`): learns nodes from the reply. Has no
    /// traversal.
    Ping,
    /// `announce_observer` (in `node.hpp`): ignores the reply. Has no
    /// traversal.
    Announce,
}

/// An outstanding or finished request to one node (libtorrent `observer`).
///
/// Fields are public so traversals and tests can inspect them; the
/// invariants (flag transitions) are maintained by the traversal code, not
/// by this type.
#[derive(Debug, Clone)]
pub struct Observer {
    /// What kind of request this is.
    pub kind: ObserverKind,
    /// The traversal this observer reports to; `None` for the detached
    /// ping and announce observers (libtorrent gives those a dummy
    /// `traversal_algorithm` that never has results).
    pub traversal: Option<TraversalId>,
    /// The node's ID (`m_id`). A random placeholder while
    /// [`ObserverFlags::NO_ID`] is set.
    pub id: NodeId,
    /// Where the request goes (`target_ep()`).
    pub target: SocketAddr,
    /// When the request was created or, once invoked, sent (`m_sent`).
    pub sent: Time,
    /// State flags (`flags`).
    pub flags: ObserverFlags,
}

impl Observer {
    /// Creates an observer; `sent` starts as `now` like libtorrent's
    /// `set_target` in the constructor, and is refreshed when the request
    /// is actually sent.
    #[must_use]
    pub fn new(
        kind: ObserverKind,
        traversal: Option<TraversalId>,
        id: NodeId,
        target: SocketAddr,
        now: Time,
    ) -> Self {
        Self {
            kind,
            traversal,
            id,
            target,
            sent: now,
            flags: ObserverFlags::EMPTY,
        }
    }

    /// `true` after the short timeout fired (`has_short_timeout`).
    #[must_use]
    pub fn has_short_timeout(&self) -> bool {
        self.flags.contains(ObserverFlags::SHORT_TIMEOUT)
    }
}

#[derive(Debug)]
struct Slot {
    generation: u32,
    refs: u32,
    observer: Option<Observer>,
}

/// The arena of live observers, with shared-ownership counting.
///
/// Mirrors what the `shared_ptr<observer>` copies in `m_results` and
/// `m_transactions` did: an observer is freed when its last holder calls
/// [`Observers::release`]. It also replaces libtorrent's `rpc_manager` pool
/// allocator (`num_allocated_observers`).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::observer::{Observer, ObserverKind, Observers, TraversalId};
/// use cloudllm_dht::time::Time;
/// use cloudllm_dht::Sha1Hash;
///
/// let mut arena = Observers::default();
/// let o = Observer::new(
///     ObserverKind::Null,
///     Some(TraversalId(1)),
///     Sha1Hash::MIN,
///     "10.0.0.1:6881".parse().unwrap(),
///     Time::ZERO,
/// );
/// let id = arena.insert(o);          // one reference, held by the creator
/// arena.acquire(id);                 // a second holder
/// assert!(!arena.release(id));       // still alive
/// assert!(arena.release(id));        // last reference: freed
/// assert!(arena.get(id).is_none());
/// ```
#[derive(Debug, Default)]
pub struct Observers {
    slots: Vec<Slot>,
    free: Vec<u32>,
    live: usize,
    per_traversal: HashMap<TraversalId, u32>,
    idle: Vec<TraversalId>,
}

impl Observers {
    /// Stores `observer` with one reference, owned by the caller.
    pub fn insert(&mut self, observer: Observer) -> ObserverId {
        if let Some(t) = observer.traversal {
            *self.per_traversal.entry(t).or_insert(0) += 1;
        }
        self.live += 1;
        if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index as usize];
            slot.refs = 1;
            slot.observer = Some(observer);
            ObserverId {
                index,
                generation: slot.generation,
            }
        } else {
            let index = u32::try_from(self.slots.len()).expect("fewer than 2^32 observers");
            self.slots.push(Slot {
                generation: 0,
                refs: 1,
                observer: Some(observer),
            });
            ObserverId {
                index,
                generation: 0,
            }
        }
    }

    fn slot(&self, id: ObserverId) -> Option<&Slot> {
        self.slots
            .get(id.index as usize)
            .filter(|s| s.generation == id.generation && s.observer.is_some())
    }

    /// The observer, or `None` if it has been freed.
    #[must_use]
    pub fn get(&self, id: ObserverId) -> Option<&Observer> {
        self.slot(id).and_then(|s| s.observer.as_ref())
    }

    /// Mutable access to the observer, or `None` if it has been freed.
    pub fn get_mut(&mut self, id: ObserverId) -> Option<&mut Observer> {
        self.slots
            .get_mut(id.index as usize)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.observer.as_mut())
    }

    /// Adds a holder (a copy of the `shared_ptr`). Does nothing for a stale
    /// handle.
    pub fn acquire(&mut self, id: ObserverId) {
        if let Some(s) = self
            .slots
            .get_mut(id.index as usize)
            .filter(|s| s.generation == id.generation && s.observer.is_some())
        {
            s.refs += 1;
        }
    }

    /// Drops a holder. Returns `true` if that freed the observer. When the
    /// freed observer was the last one of its traversal, the traversal is
    /// queued for [`Observers::take_idle`].
    pub fn release(&mut self, id: ObserverId) -> bool {
        let Some(slot) = self
            .slots
            .get_mut(id.index as usize)
            .filter(|s| s.generation == id.generation && s.observer.is_some())
        else {
            return false;
        };
        slot.refs -= 1;
        if slot.refs > 0 {
            return false;
        }
        let observer = slot.observer.take().expect("checked above");
        slot.generation = slot.generation.wrapping_add(1);
        self.free.push(id.index);
        self.live -= 1;
        if let Some(t) = observer.traversal {
            if let Some(n) = self.per_traversal.get_mut(&t) {
                *n -= 1;
                if *n == 0 {
                    self.per_traversal.remove(&t);
                    self.idle.push(t);
                }
            }
        }
        true
    }

    /// Number of live observers (libtorrent `num_allocated_observers`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.live
    }

    /// `true` if there are no live observers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Number of live observers that report to `t`.
    #[must_use]
    pub fn live_for(&self, t: TraversalId) -> u32 {
        self.per_traversal.get(&t).copied().unwrap_or(0)
    }

    /// Traversals whose last observer was freed since the previous call.
    /// The owner uses this to drop traversals that are finished.
    pub fn take_idle(&mut self) -> Vec<TraversalId> {
        std::mem::take(&mut self.idle)
    }
}
