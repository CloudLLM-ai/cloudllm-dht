//! Answering incoming DHT queries.
//!
//! Provenance: `node::incoming_request`, `node::write_nodes_entries` and
//! the anonymous-namespace `incoming_error` of `src/kademlia/node.cpp`
//! (libtorrent RC_2_1, commit `86d573f2631b0162d3cca5e257217eaf530fdcba`),
//! BSD-3-Clause, Copyright Arvid Norberg and contributors.
//!
//! [`handle_query`] is a pure function of a decoded query, the node's
//! routing table, its storage and its write-token secrets: it returns the
//! datagram to send back and nothing else leaves the function except the
//! [`Event`]s and counters it records. It never touches a socket or a
//! clock, which is what lets `tests/dht_node.rs` port `test_dht.cpp`
//! line for line and lets the fuzz targets feed it arbitrary bytes.
//!
//! # Deviations from libtorrent
//!
//! * An error response carries no `r` dictionary. libtorrent builds the
//!   response first and calls `incoming_error` on it afterwards, so its
//!   errors still contain `r: {id, p}` and any partial results; that only
//!   makes the reply larger (a reflection concern) and nobody reads it.
//! * A `put` that carries a public key `k` but not both `seq` and `sig` is
//!   rejected. libtorrent derives the target from `k` and `salt`, then,
//!   because `mutable_put` is false, stores the value as an *immutable*
//!   item under that mutable target. Anyone holding a write token for a
//!   mutable target (a token is given to every `get` requester) could
//!   thereby shadow the real mutable item: `get` consults the immutable
//!   table first. See `tests/dht_node.rs::test_put_with_key_but_no_signature_is_rejected`.

use std::net::SocketAddr;

use crate::bencode::{Entry, Node, NodeKind};
use crate::events::Event;
use crate::item::{item_target_id, verify_mutable_item};
use crate::msg::{
    error_entry, verify_message, ErrorCode, KeyDesc, KeyFlags, Msg, Query, VerifyError, Want,
};
use crate::net::{write_endpoint, write_nodes_entry, Protocol};
use crate::node::counters::NodeCounters;
use crate::node::tokens::WriteTokens;
use crate::node_entry::NodeEntry;
use crate::node_id::{verify_id, NodeId};
use crate::routing_table::{FindNodeOptions, RoutingTable};
use crate::settings::DhtSettings;
use crate::sha1_hash::Sha1Hash;
use crate::storage::DhtStorage;
use crate::time::Time;
use crate::types::{PublicKey, SequenceNumber, Signature};

/// The largest `v` (value) a `put` may carry, in bencoded bytes (BEP 44).
pub const MAX_ITEM_SIZE: usize = 1000;

/// The longest `salt` a mutable `put` may carry (BEP 44).
pub const MAX_SALT_SIZE: usize = 64;

/// A user hook that may take over the answer to a query (libtorrent
/// `dht_observer::on_dht_request`). It receives the query name, the request
/// and the response built so far (`y`, `t`, `ip`, `r` with `id` and `p`);
/// returning `true` sends that response as is and skips the built-in handler.
pub type RequestHook<'a> = dyn FnMut(&str, &Msg<'_, '_>, &mut Entry) -> bool + 'a;

/// Access to the routing tables of the *other* address family, for BEP 32
/// `want` lists (libtorrent `get_foreign_node_t`).
///
/// A dual-stack tracker runs one node per family; a v4 node asked for
/// `want: ["n6"]` answers with `nodes6` taken from the v6 node's table. The
/// node itself answers for its own family, so implementors only need to
/// serve the others.
pub trait ForeignTables {
    /// The nodes closest to `target` in the table of the node serving
    /// `family`, or `None` when this tracker runs no such node.
    fn find_nodes(&self, family: Protocol, target: &NodeId) -> Option<Vec<NodeEntry>>;
}

/// A [`ForeignTables`] for a tracker that runs a single node: every `want`
/// for the other family is silently dropped, as libtorrent does when
/// `get_foreign_node` returns null.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoForeignTables;

impl ForeignTables for NoForeignTables {
    fn find_nodes(&self, _family: Protocol, _target: &NodeId) -> Option<Vec<NodeEntry>> {
        None
    }
}

/// Everything [`handle_query`] reads or updates.
pub struct QueryEnv<'a> {
    /// The current time (stamps routing-table updates).
    pub now: Time,
    /// Behavioural settings.
    pub settings: &'a DhtSettings,
    /// This node's ID.
    pub id: NodeId,
    /// The family this node serves.
    pub protocol: Protocol,
    /// This node's routing table.
    pub table: &'a mut RoutingTable,
    /// BEP 5/33/44/51 storage, shared by the nodes of a tracker.
    pub storage: &'a mut dyn DhtStorage,
    /// The write-token secrets.
    pub tokens: &'a WriteTokens,
    /// The other family's tables.
    pub foreign: &'a dyn ForeignTables,
    /// Message counters.
    pub counters: &'a mut NodeCounters,
    /// Where notifications for the owner go.
    pub events: &'a mut Vec<Event>,
    /// The optional `on_dht_request` hook.
    pub hook: Option<&'a mut RequestHook<'a>>,
}

/// Top-level keys every query must have: `q`, optional `ro`, `a` with `id`.
const TOP_DESC: [KeyDesc; 4] = [
    KeyDesc::new("q", Some(NodeKind::Str), 0, KeyFlags::NONE),
    KeyDesc::new("ro", Some(NodeKind::Int), 0, KeyFlags::OPTIONAL),
    KeyDesc::new("a", Some(NodeKind::Dict), 0, KeyFlags::PARSE_CHILDREN),
    KeyDesc::new("id", Some(NodeKind::Str), 20, KeyFlags::LAST_CHILD),
];

const GET_PEERS_DESC: [KeyDesc; 4] = [
    KeyDesc::new("info_hash", Some(NodeKind::Str), 20, KeyFlags::NONE),
    KeyDesc::new("noseed", Some(NodeKind::Int), 0, KeyFlags::OPTIONAL),
    KeyDesc::new("scrape", Some(NodeKind::Int), 0, KeyFlags::OPTIONAL),
    KeyDesc::new("want", Some(NodeKind::List), 0, KeyFlags::OPTIONAL),
];

const FIND_NODE_DESC: [KeyDesc; 2] = [
    KeyDesc::new("target", Some(NodeKind::Str), 20, KeyFlags::NONE),
    KeyDesc::new("want", Some(NodeKind::List), 0, KeyFlags::OPTIONAL),
];

const ANNOUNCE_DESC: [KeyDesc; 6] = [
    KeyDesc::new("info_hash", Some(NodeKind::Str), 20, KeyFlags::NONE),
    KeyDesc::new("port", Some(NodeKind::Int), 0, KeyFlags::NONE),
    KeyDesc::new("token", Some(NodeKind::Str), 0, KeyFlags::NONE),
    KeyDesc::new("n", Some(NodeKind::Str), 0, KeyFlags::OPTIONAL),
    KeyDesc::new("seed", Some(NodeKind::Int), 0, KeyFlags::OPTIONAL),
    KeyDesc::new("implied_port", Some(NodeKind::Int), 0, KeyFlags::OPTIONAL),
];

const PUT_DESC: [KeyDesc; 7] = [
    KeyDesc::new("token", Some(NodeKind::Str), 0, KeyFlags::NONE),
    KeyDesc::new("v", None, 0, KeyFlags::NONE),
    KeyDesc::new("seq", Some(NodeKind::Int), 0, KeyFlags::OPTIONAL),
    KeyDesc::new("k", Some(NodeKind::Str), PublicKey::LEN, KeyFlags::OPTIONAL),
    KeyDesc::new(
        "sig",
        Some(NodeKind::Str),
        Signature::LEN,
        KeyFlags::OPTIONAL,
    ),
    KeyDesc::new("cas", Some(NodeKind::Int), 0, KeyFlags::OPTIONAL),
    KeyDesc::new("salt", Some(NodeKind::Str), 0, KeyFlags::OPTIONAL),
];

const GET_DESC: [KeyDesc; 3] = [
    KeyDesc::new("seq", Some(NodeKind::Int), 0, KeyFlags::OPTIONAL),
    KeyDesc::new("target", Some(NodeKind::Str), 20, KeyFlags::NONE),
    KeyDesc::new("want", Some(NodeKind::List), 0, KeyFlags::OPTIONAL),
];

/// A query rejected with a DHT error: the code and text of the reply.
struct Rejection {
    code: ErrorCode,
    text: String,
}

impl Rejection {
    fn new(code: ErrorCode, text: &str) -> Self {
        Self {
            code,
            text: text.to_owned(),
        }
    }

    fn protocol(text: &str) -> Self {
        Self::new(ErrorCode::Protocol, text)
    }
}

impl From<VerifyError> for Rejection {
    fn from(e: VerifyError) -> Self {
        Self::protocol(&e.to_string())
    }
}

/// Builds the response to `m`, a decoded datagram whose `y` is `q`
/// (libtorrent `node::incoming_request`).
///
/// The caller has already established that this node is not read-only,
/// that the message came in on this node's socket and that the send quota
/// allows a response; see [`crate::node::Node::incoming`].
///
/// The result is always a dictionary carrying `t` (copied from the query)
/// and `y`: `"r"` for success, `"e"` plus `e: [code, text]` for a rejected
/// query. A malformed query is answered with a protocol error whose text
/// is libtorrent's (`missing 'q' key`, `invalid value for 'id'`, ...); an
/// invalid BEP 42 node ID is answered with `invalid node ID` when
/// `enforce_node_id` is on.
///
/// Side effects, besides the returned message: the routing table is told
/// about the requester (`heard_about` for every query from a non-read-only
/// node, `node_seen` once a valid write token proves the address is not
/// spoofed), storage is updated by `announce_peer` and `put`, counters
/// advance and notification [`Event`]s are queued.
pub fn handle_query(env: &mut QueryEnv<'_>, m: &Msg<'_, '_>) -> Entry {
    let mut e = Entry::dict();
    e.set("y", "r");
    e.set("t", m.message.dict_find_string_value(b"t", b""));
    match build_reply(env, m, &mut e) {
        Ok(reply) => {
            e.set("r", reply);
        }
        Err(Reject::Answered) => {}
        Err(Reject::Error(r)) => {
            let err = error_entry(r.code, &r.text);
            e.set("y", "e");
            if let Some(list) = err.get("e") {
                e.set("e", list.clone());
            }
        }
    }
    e
}

/// Why [`build_reply`] did not produce a normal `r` dictionary.
enum Reject {
    /// The `on_dht_request` hook wrote the whole response.
    Answered,
    /// Reply with a DHT error.
    Error(Rejection),
}

impl From<Rejection> for Reject {
    fn from(r: Rejection) -> Self {
        Self::Error(r)
    }
}

impl From<VerifyError> for Reject {
    fn from(e: VerifyError) -> Self {
        Self::Error(e.into())
    }
}

fn build_reply(env: &mut QueryEnv<'_>, m: &Msg<'_, '_>, e: &mut Entry) -> Result<Entry, Reject> {
    let top = verify_message(m.message, &TOP_DESC)?;
    let [Some(query), ro, Some(args), Some(id)] = top[..] else {
        return Err(Rejection::protocol("missing 'q' key").into());
    };
    let mut ip = Vec::with_capacity(18);
    write_endpoint(&m.addr, &mut ip);
    e.set("ip", ip);

    let read_only = ro.is_some_and(|n| n.int_value() != 0);
    let id = NodeId::from_slice(id.string_value()).unwrap_or_default();

    // If this node's ID doesn't match its IP, tell it with an error.
    if env.settings.enforce_node_id && !verify_id(&id, m.addr.ip()) {
        return Err(Rejection::protocol("invalid node ID").into());
    }
    if !read_only {
        env.table.heard_about(id, m.addr, env.now);
    }

    let mut reply = Entry::dict();
    reply.set("id", env.id.0);
    // Mirror back the other node's external port.
    reply.set("p", m.addr.port());

    let query = query.string_value();
    if let Some(hook) = env.hook.as_deref_mut() {
        let name = String::from_utf8_lossy(query);
        let mut so_far = e.clone();
        so_far.set("r", reply.clone());
        if hook(&name, m, &mut so_far) {
            *e = so_far;
            return Err(Reject::Answered);
        }
    }

    let known = std::str::from_utf8(query)
        .ok()
        .and_then(|q| q.parse::<Query>().ok());
    match known {
        Some(Query::Ping) => env.counters.ping_in += 1,
        Some(Query::GetPeers) => get_peers(env, m, args, &mut reply)?,
        Some(Query::FindNode) => find_node(env, args, &mut reply)?,
        Some(Query::AnnouncePeer) => announce_peer(env, m, args, &id)?,
        Some(Query::Put) => put(env, m, args, &id)?,
        Some(Query::Get) => get(env, m, args, &mut reply)?,
        Some(Query::SampleInfohashes) => sample_infohashes(env, args, &mut reply)?,
        None => unknown_query(env, args, &mut reply)?,
    }
    Ok(reply)
}

/// `get_peers` (BEP 5, with BEP 33 `scrape` and BEP 32 `want`).
fn get_peers(
    env: &mut QueryEnv<'_>,
    m: &Msg<'_, '_>,
    args: &Node<'_>,
    reply: &mut Entry,
) -> Result<(), Rejection> {
    let keys = verify_message(args, &GET_PEERS_DESC).inspect_err(|_| {
        env.counters.invalid_get_peers += 1;
    })?;
    let info_hash = hash_of(keys[0]);
    env.counters.get_peers_in += 1;

    // Always return nodes as well as peers.
    write_nodes_entries(env, &info_hash, keys[3], reply);

    let noseed = keys[1].is_some_and(|n| n.int_value() != 0);
    let scrape = keys[2].is_some_and(|n| n.int_value() != 0);
    env.events.push(Event::IncomingGetPeers {
        info_hash,
        from: m.addr,
    });
    // If storage is full we withhold the write token so announces spill
    // over to our neighbours, widening the set of nodes that store peers
    // for this torrent.
    let full = env
        .storage
        .get_peers(&info_hash, noseed, scrape, m.addr.ip(), reply);
    if !full {
        reply.set("token", env.tokens.generate(m.addr.ip(), &info_hash));
    }
    Ok(())
}

/// `find_node` (BEP 5 with BEP 32 `want`).
fn find_node(env: &mut QueryEnv<'_>, args: &Node<'_>, reply: &mut Entry) -> Result<(), Rejection> {
    let keys = verify_message(args, &FIND_NODE_DESC).inspect_err(|_| {
        env.counters.invalid_find_node += 1;
    })?;
    env.counters.find_node_in += 1;
    write_nodes_entries(env, &hash_of(keys[0]), keys[1], reply);
    Ok(())
}

/// `announce_peer` (BEP 5): validates the write token, then stores the peer.
fn announce_peer(
    env: &mut QueryEnv<'_>,
    m: &Msg<'_, '_>,
    args: &Node<'_>,
    id: &NodeId,
) -> Result<(), Rejection> {
    let keys = verify_message(args, &ANNOUNCE_DESC).inspect_err(|_| {
        env.counters.invalid_announce += 1;
    })?;
    let mut port = keys[1].map_or(0, Node::int_value);
    // Is the announcer asking us to use the source port of the packet
    // instead of the explicit listen port?
    if keys[5].is_some_and(|n| n.int_value() != 0) {
        port = i64::from(m.addr.port());
    }
    let Ok(port) = u16::try_from(port) else {
        env.counters.invalid_announce += 1;
        return Err(Rejection::protocol("invalid port"));
    };
    let info_hash = hash_of(keys[0]);
    env.events.push(Event::IncomingAnnounce {
        info_hash,
        from: m.addr.ip(),
        port,
    });
    let token = keys[2].map_or(&b""[..], Node::string_value);
    if !env.tokens.verify(token, m.addr.ip(), &info_hash) {
        env.counters.invalid_announce += 1;
        return Err(Rejection::protocol("invalid token"));
    }
    env.counters.announce_peer_in += 1;

    // The token was correct, so this node is not spoofing its address:
    // let the table have a chance to add it.
    env.table.node_seen(*id, m.addr, 0xffff, env.now);

    let name = keys[3].map_or(String::new(), |n| {
        String::from_utf8_lossy(n.string_value()).into_owned()
    });
    let seed = keys[4].is_some_and(|n| n.int_value() != 0);
    env.storage
        .announce_peer(&info_hash, SocketAddr::new(m.addr.ip(), port), &name, seed);
    Ok(())
}

/// `put` (BEP 44): immutable and mutable items.
fn put(
    env: &mut QueryEnv<'_>,
    m: &Msg<'_, '_>,
    args: &Node<'_>,
    id: &NodeId,
) -> Result<(), Rejection> {
    let invalid = |env: &mut QueryEnv<'_>, r: Rejection| {
        env.counters.invalid_put += 1;
        r
    };
    // Put messages contain a signed value, so they must have correct
    // bencoding: otherwise the value would not round-trip and the
    // signature would not match.
    let keys = verify_message(args, &PUT_DESC)
        .map_err(Rejection::from)
        .and_then(|k| match args.has_soft_error() {
            Some(text) => Err(Rejection::protocol(text)),
            None => Ok(k),
        })
        .map_err(|r| invalid(env, r))?;
    env.counters.put_in += 1;

    let value = keys[1].map_or(&b""[..], Node::data_section);
    if value.len() > MAX_ITEM_SIZE || value.is_empty() {
        return Err(invalid(
            env,
            Rejection::new(ErrorCode::MessageTooBig, "message too big"),
        ));
    }
    let salt = keys[6].map_or(&b""[..], Node::string_value);
    if salt.len() > MAX_SALT_SIZE {
        return Err(invalid(
            env,
            Rejection::new(ErrorCode::SaltTooBig, "salt too big"),
        ));
    }
    let pk = keys[3].and_then(|n| PublicKey::from_slice(n.string_value()));
    let sig = keys[4].and_then(|n| Signature::from_slice(n.string_value()));
    let seq = keys[2].map(|n| SequenceNumber(n.int_value()));
    let mutable = match (pk, sig, seq) {
        (Some(pk), Some(sig), Some(seq)) => Some((pk, sig, seq)),
        // A key without the rest is not an immutable put either; see the
        // module documentation.
        (Some(_), _, _) => {
            return Err(invalid(env, Rejection::protocol("incomplete mutable put")));
        }
        _ => None,
    };
    let target = mutable.as_ref().map_or_else(
        || Sha1Hash::of(value),
        |(pk, _, _)| item_target_id(salt, pk),
    );

    // Tokens are only valid for the target the requester did a `get` for.
    let token = keys[0].map_or(&b""[..], Node::string_value);
    if !env.tokens.verify(token, m.addr.ip(), &target) {
        return Err(invalid(env, Rejection::protocol("invalid token")));
    }

    match mutable {
        None => env.storage.put_immutable_item(&target, value, m.addr.ip()),
        Some((pk, sig, seq)) => put_mutable(env, m, &keys, (target, pk, sig, seq), (value, salt))
            .map_err(|r| invalid(env, r))?,
    }
    env.table.node_seen(*id, m.addr, 0xffff, env.now);
    Ok(())
}

/// The signature, sequence and compare-and-swap checks of a mutable `put`.
fn put_mutable(
    env: &mut QueryEnv<'_>,
    m: &Msg<'_, '_>,
    keys: &[Option<&Node<'_>>],
    (target, pk, sig, seq): (Sha1Hash, PublicKey, Signature, SequenceNumber),
    (value, salt): (&[u8], &[u8]),
) -> Result<(), Rejection> {
    if seq < SequenceNumber(0) {
        return Err(Rejection::protocol("invalid (negative) sequence number"));
    }
    if !verify_mutable_item(value, salt, seq, &pk, &sig) {
        return Err(Rejection::new(
            ErrorCode::InvalidSignature,
            "invalid signature",
        ));
    }
    if let Some(current) = env.storage.get_mutable_item_seq(&target) {
        // `cas`, when present, must match the stored sequence number:
        // critical for avoiding races between writers of one slot.
        if keys[5].is_some_and(|cas| current.0 != cas.int_value()) {
            return Err(Rejection::new(ErrorCode::CasMismatch, "CAS mismatch"));
        }
        if current > seq {
            return Err(Rejection::new(
                ErrorCode::SequenceNumberTooLow,
                "old sequence number",
            ));
        }
    }
    env.storage
        .put_mutable_item(&target, value, &sig, seq, &pk, salt, m.addr.ip());
    Ok(())
}

/// `get` (BEP 44): a write token, nodes, and the item if we have it.
fn get(
    env: &mut QueryEnv<'_>,
    m: &Msg<'_, '_>,
    args: &Node<'_>,
    reply: &mut Entry,
) -> Result<(), Rejection> {
    let keys = verify_message(args, &GET_DESC).inspect_err(|_| {
        env.counters.invalid_get += 1;
    })?;
    env.counters.get_in += 1;
    let target = hash_of(keys[1]);

    reply.set("token", env.tokens.generate(m.addr.ip(), &target));
    write_nodes_entries(env, &target, keys[2], reply);

    match keys[0] {
        // With a sequence number it must be a mutable item: don't bother
        // searching the immutable table.
        None => {
            if !env.storage.get_immutable_item(&target, reply) {
                env.storage
                    .get_mutable_item(&target, SequenceNumber(0), true, reply);
            }
        }
        Some(seq) => {
            env.storage
                .get_mutable_item(&target, SequenceNumber(seq.int_value()), false, reply);
        }
    }
    Ok(())
}

/// `sample_infohashes` (BEP 51).
fn sample_infohashes(
    env: &mut QueryEnv<'_>,
    args: &Node<'_>,
    reply: &mut Entry,
) -> Result<(), Rejection> {
    let keys = verify_message(args, &FIND_NODE_DESC).inspect_err(|_| {
        env.counters.invalid_sample_infohashes += 1;
    })?;
    env.counters.sample_infohashes_in += 1;
    let target = hash_of(keys[0]);
    // libtorrent keeps a TODO to pass the returned count as a limit to
    // write_nodes_entries.
    env.storage.get_infohashes_sample(reply);
    write_nodes_entries(env, &target, keys[1], reply);
    Ok(())
}

/// An unrecognised method: if the arguments carry a `target` or
/// `info_hash`, treat it as `find_node` to be forward compatible.
fn unknown_query(
    env: &mut QueryEnv<'_>,
    args: &Node<'_>,
    reply: &mut Entry,
) -> Result<(), Rejection> {
    let twenty = |key: &[u8]| {
        args.dict_find_string(key)
            .filter(|n| n.string_length() == 20)
    };
    let Some(target) = twenty(b"target").or_else(|| twenty(b"info_hash")) else {
        return Err(Rejection::protocol("unknown message"));
    };
    let want = args.dict_find_list(b"want");
    write_nodes_entries(env, &hash_of(Some(target)), want, reply);
    Ok(())
}

/// The 20-byte hash in a node a descriptor table already validated.
fn hash_of(n: Option<&Node<'_>>) -> Sha1Hash {
    n.and_then(|n| Sha1Hash::from_slice(n.string_value()))
        .unwrap_or_default()
}

/// Adds the closest nodes to `target` to `reply` (libtorrent
/// `node::write_nodes_entries`).
///
/// Without a `want` list the node answers for its own family under
/// `nodes`/`nodes6`. With one (BEP 32) it answers for each family named,
/// reaching into the other family's table through [`ForeignTables`];
/// unknown tokens and families this tracker does not run are skipped.
fn write_nodes_entries(
    env: &mut QueryEnv<'_>,
    target: &NodeId,
    want: Option<&Node<'_>>,
    reply: &mut Entry,
) {
    let Some(want) = want.filter(|w| w.kind() == NodeKind::List) else {
        let own = env.table.find_node(target, FindNodeOptions::NONE, 0);
        reply.set(env.protocol.nodes_key(), nodes_entry(&own));
        return;
    };
    for wanted in want.list_iter().filter(|w| w.kind() == NodeKind::Str) {
        let Some(family) = std::str::from_utf8(wanted.string_value())
            .ok()
            .and_then(|s| s.parse::<Want>().ok())
            .map(family_of)
        else {
            continue;
        };
        let nodes = if family == env.protocol {
            Some(env.table.find_node(target, FindNodeOptions::NONE, 0))
        } else {
            env.foreign.find_nodes(family, target)
        };
        if let Some(nodes) = nodes {
            reply.set(family.nodes_key(), nodes_entry(&nodes));
        }
    }
}

fn family_of(w: Want) -> Protocol {
    match w {
        Want::N4 => Protocol::V4,
        Want::N6 => Protocol::V6,
    }
}

/// Packs table entries into a `nodes` string (libtorrent
/// `write_nodes_entry(std::vector<node_entry>)`).
#[must_use]
pub fn nodes_entry(nodes: &[NodeEntry]) -> Entry {
    write_nodes_entry(nodes.iter().map(|n| (&n.id, &n.endpoint)))
}
