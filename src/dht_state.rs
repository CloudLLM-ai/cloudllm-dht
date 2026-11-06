//! Saved node IDs and bootstrap nodes: persistence of the DHT state.
//!
//! Provenance: `include/libtorrent/kademlia/dht_state.hpp` and
//! `src/kademlia/dht_state.cpp` of libtorrent RC_2_1 (commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Alden Torres, Arvid Norberg, Steven Siloti and contributors.
//!
//! The state is a bencoded dictionary:
//!
//! ```text
//! d
//!   7:node-id l <20-byte id><4 or 16-byte address> ... e
//!   5:nodes   l <6-byte compact endpoint> ... e          (omitted when empty)
//!   6:nodes6  l <18-byte compact endpoint> ... e         (omitted when empty)
//! e
//! ```
//!
//! `node-id` always appears (possibly as an empty list). Older libtorrent
//! versions wrote a single 20-byte string there; the loader still accepts it
//! and pairs the id with the unspecified IPv4 address.
//!
//! The file is read from disk or from a settings blob and so is untrusted:
//! [`read_dht_state`] never fails and never panics; anything it does not
//! understand is skipped, like in libtorrent.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::bencode::{decode, DecodeError, Entry, Node, NodeKind};
use crate::net::{read_endpoint_list, write_endpoint};
use crate::node_id::NodeId;
use crate::sha1_hash::HASH_LEN;

/// The node IDs of each listen socket with the address they were generated
/// for (libtorrent `node_ids_t`).
pub type NodeIds = Vec<(IpAddr, NodeId)>;

/// The persistent part of a DHT node (libtorrent `dht::dht_state`).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::dht_state::DhtState;
/// use cloudllm_dht::Sha1Hash;
///
/// let mut s = DhtState::default();
/// s.nids.push(("1.1.1.1".parse().unwrap(), Sha1Hash::MAX));
/// s.nodes.push("2.2.2.2:6881".parse().unwrap());
/// let bytes = s.encode();
/// assert_eq!(DhtState::load(&bytes).unwrap(), s);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DhtState {
    /// The node ID assigned to each listen socket, paired with the local
    /// address it was generated for. IDs are derived per BEP 42 from the
    /// external IP and persisted so the node keeps its place in the DHT
    /// across restarts.
    pub nids: NodeIds,
    /// Bootstrap nodes saved from the IPv4 routing table.
    pub nodes: Vec<SocketAddr>,
    /// Bootstrap nodes saved from the IPv6 routing table.
    pub nodes6: Vec<SocketAddr>,
}

impl DhtState {
    /// Resets to the empty state (libtorrent `dht_state::clear`; the C++
    /// version also releases capacity, which `Vec::clear` does not, so the
    /// vectors are replaced).
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Decodes saved state from bencoded bytes.
    ///
    /// # Errors
    ///
    /// The bencode [`DecodeError`] when `bytes` is not a valid bencoded
    /// document. A *valid* document of the wrong shape is not an error: it
    /// yields the (possibly empty) parts that could be read, as
    /// [`read_dht_state`] does.
    pub fn load(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode(bytes).map(|n| read_dht_state(&n))
    }

    /// Bencodes the state (`save_dht_state` followed by `bencode`).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        save_dht_state(self).encode()
    }
}

/// Reads the `node-id` list (or the old single-string form) under `key`
/// (libtorrent `extract_node_ids`).
///
/// Entries shorter than 20 bytes, or whose length is neither 24 (IPv4) nor
/// 36 (IPv6), are skipped; a non-dictionary `e` gives an empty result.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::bencode::decode;
/// use cloudllm_dht::dht_state::extract_node_ids;
///
/// let old = decode(b"d7:node-id20:aaaaaaaaaaaaaaaaaaaae").unwrap();
/// let ids = extract_node_ids(&old, "node-id");
/// assert_eq!(ids.len(), 1);
/// assert_eq!(ids[0].0.to_string(), "0.0.0.0");
/// ```
#[must_use]
pub fn extract_node_ids(e: &Node<'_>, key: &str) -> NodeIds {
    if e.kind() != NodeKind::Dict {
        return Vec::new();
    }
    let key = key.as_bytes();
    // first look for an old-style nid
    let old = e.dict_find_string_value(key, b"");
    if let Some(id) = NodeId::from_slice(old) {
        return vec![(IpAddr::V4(Ipv4Addr::UNSPECIFIED), id)];
    }
    let Some(list) = e.dict_find_list(key) else {
        return Vec::new();
    };
    list.list_iter()
        .filter(|n| n.kind() == NodeKind::Str)
        .filter_map(|n| parse_node_id_entry(n.string_value()))
        .collect()
}

/// One `node-id` list element: a 20-byte id followed by a 4 or 16 byte
/// address; `None` for any other length.
fn parse_node_id_entry(s: &[u8]) -> Option<(IpAddr, NodeId)> {
    let (id, addr) = s.split_at_checked(HASH_LEN)?;
    let addr = match addr.len() {
        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(addr).ok()?)),
        16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(addr).ok()?)),
        _ => return None,
    };
    Some((addr, NodeId::from_slice(id)?))
}

/// Reads a [`DhtState`] from a decoded dictionary (libtorrent
/// `read_dht_state`). A non-dictionary gives the empty state; missing or
/// malformed parts are left empty.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::bencode::decode;
/// use cloudllm_dht::dht_state::read_dht_state;
///
/// let node = decode(b"le").unwrap();
/// assert_eq!(read_dht_state(&node), Default::default());
/// ```
#[must_use]
pub fn read_dht_state(e: &Node<'_>) -> DhtState {
    if e.kind() != NodeKind::Dict {
        return DhtState::default();
    }
    let endpoints = |key: &[u8]| {
        e.dict_find_list(key)
            .map(read_endpoint_list)
            .unwrap_or_default()
    };
    DhtState {
        nids: extract_node_ids(e, "node-id"),
        nodes: endpoints(b"nodes"),
        nodes6: endpoints(b"nodes6"),
    }
}

fn save_nodes(nodes: &[SocketAddr]) -> Entry {
    Entry::List(
        nodes
            .iter()
            .map(|ep| {
                let mut b = Vec::with_capacity(18);
                write_endpoint(ep, &mut b);
                Entry::Str(b)
            })
            .collect(),
    )
}

/// Builds the bencodable form of `state` (libtorrent `save_dht_state`).
///
/// `node-id` is always written; `nodes` and `nodes6` only when non-empty.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::dht_state::{save_dht_state, DhtState};
///
/// assert_eq!(save_dht_state(&DhtState::default()).encode(), b"d7:node-idlee".to_vec());
/// ```
#[must_use]
pub fn save_dht_state(state: &DhtState) -> Entry {
    let nids = state
        .nids
        .iter()
        .map(|(addr, id)| {
            let mut b = id.0.to_vec();
            match addr {
                IpAddr::V4(a) => b.extend_from_slice(&a.octets()),
                IpAddr::V6(a) => b.extend_from_slice(&a.octets()),
            }
            Entry::Str(b)
        })
        .collect();
    let mut ret = Entry::dict();
    ret.set("node-id", Entry::List(nids));
    if !state.nodes.is_empty() {
        ret.set("nodes", save_nodes(&state.nodes));
    }
    if !state.nodes6.is_empty() {
        ret.set("nodes6", save_nodes(&state.nodes6));
    }
    ret
}
