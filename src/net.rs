//! Addresses and the compact wire encodings of endpoints and nodes.
//!
//! Provenance: `include/libtorrent/aux_/socket_io.hpp`,
//! `src/ip_helpers.cpp`, `include/libtorrent/kademlia/io.hpp` and
//! `write_nodes_entry` in `src/kademlia/node.cpp` of libtorrent RC_2_1
//! (commit `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause,
//! Copyright Arvid Norberg and contributors.
//!
//! The "compact" forms (BEP 5, BEP 32) are: an IPv4 endpoint is 6 bytes
//! (4 address, 2 big-endian port), an IPv6 endpoint 18; a node is its
//! 20-byte ID followed by its endpoint, so 26 or 38 bytes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::bencode::{Entry, Node, NodeKind};
use crate::node_id::NodeId;
use crate::sha1_hash::HASH_LEN;

/// The address family a DHT node (one routing table) serves.
///
/// libtorrent's `udp::v4()`/`udp::v6()` passed around as protocol tags;
/// each DHT node serves exactly one, and a dual-stack tracker runs two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// IPv4: `nodes` in responses, `n4` in `want`.
    V4,
    /// IPv6: `nodes6` in responses, `n6` in `want` (BEP 32).
    V6,
}

impl Protocol {
    /// The protocol of an address.
    #[must_use]
    pub fn of(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }

    /// Bytes of a compact endpoint: 6 or 18.
    #[must_use]
    pub const fn endpoint_len(self) -> usize {
        match self {
            Self::V4 => 6,
            Self::V6 => 18,
        }
    }

    /// Bytes of a compact node (ID plus endpoint): 26 or 38.
    #[must_use]
    pub const fn node_len(self) -> usize {
        HASH_LEN + self.endpoint_len()
    }

    /// The response key carrying nodes of this family (libtorrent
    /// `protocol_nodes_key`).
    #[must_use]
    pub const fn nodes_key(self) -> &'static str {
        match self {
            Self::V4 => "nodes",
            Self::V6 => "nodes6",
        }
    }

    /// The `want` list token for this family (libtorrent `protocol_family_name`).
    #[must_use]
    pub const fn want_key(self) -> &'static str {
        match self {
            Self::V4 => "n4",
            Self::V6 => "n6",
        }
    }
}

/// A node ID with the endpoint it was seen at (libtorrent `node_endpoint`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeEndpoint {
    /// The node's ID.
    pub id: NodeId,
    /// Where it can be reached over UDP.
    pub ep: SocketAddr,
}

/// Appends the compact form of `ep` (address bytes, then big-endian port)
/// to `out` (libtorrent `write_endpoint`).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::net::write_endpoint;
///
/// let mut out = Vec::new();
/// write_endpoint(&"1.2.3.4:6881".parse().unwrap(), &mut out);
/// assert_eq!(out, [1, 2, 3, 4, 0x1a, 0xe1]);
/// ```
pub fn write_endpoint(ep: &SocketAddr, out: &mut Vec<u8>) {
    match ep.ip() {
        IpAddr::V4(a) => out.extend_from_slice(&a.octets()),
        IpAddr::V6(a) => out.extend_from_slice(&a.octets()),
    }
    out.extend_from_slice(&ep.port().to_be_bytes());
}

/// Reads one compact endpoint of the given family from the front of `b`.
/// `None` if `b` is shorter than [`Protocol::endpoint_len`].
#[must_use]
pub fn read_endpoint(protocol: Protocol, b: &[u8]) -> Option<SocketAddr> {
    let b = b.get(..protocol.endpoint_len())?;
    let (addr, port) = b.split_at(b.len() - 2);
    let port = u16::from_be_bytes([port[0], port[1]]);
    let ip = match protocol {
        Protocol::V4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(addr).ok()?)),
        Protocol::V6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(addr).ok()?)),
    };
    Some(SocketAddr::new(ip, port))
}

/// Reads a compact node (ID, then endpoint) from the front of `b`
/// (libtorrent `read_node_endpoint`); `None` if `b` is too short.
#[must_use]
pub fn read_node_endpoint(protocol: Protocol, b: &[u8]) -> Option<NodeEndpoint> {
    let id = NodeId::from_slice(b.get(..HASH_LEN)?)?;
    let ep = read_endpoint(protocol, &b[HASH_LEN..])?;
    Some(NodeEndpoint { id, ep })
}

/// Reads a packed `nodes`/`nodes6` string: consecutive compact nodes.
/// Trailing bytes that do not make a whole node are ignored, as libtorrent
/// does when walking such a string.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::net::{read_nodes, write_nodes, Protocol};
/// use cloudllm_dht::Sha1Hash;
///
/// let id = Sha1Hash::MAX;
/// let ep = "10.0.0.1:1".parse().unwrap();
/// let packed = write_nodes([(&id, &ep)]);
/// assert_eq!(read_nodes(Protocol::V4, &packed).len(), 1);
/// ```
#[must_use]
pub fn read_nodes(protocol: Protocol, b: &[u8]) -> Vec<NodeEndpoint> {
    b.chunks_exact(protocol.node_len())
        .filter_map(|c| read_node_endpoint(protocol, c))
        .collect()
}

/// Packs nodes into a `nodes`/`nodes6` string (libtorrent
/// `write_nodes_entry`, which wraps this in an `entry`).
#[must_use]
pub fn write_nodes<'a>(nodes: impl IntoIterator<Item = (&'a NodeId, &'a SocketAddr)>) -> Vec<u8> {
    let mut out = Vec::new();
    for (id, ep) in nodes {
        out.extend_from_slice(&id.0);
        write_endpoint(ep, &mut out);
    }
    out
}

/// [`write_nodes`] as an [`Entry`] string, ready to insert in a response.
#[must_use]
pub fn write_nodes_entry<'a>(
    nodes: impl IntoIterator<Item = (&'a NodeId, &'a SocketAddr)>,
) -> Entry {
    Entry::Str(write_nodes(nodes))
}

/// Reads a bencoded list of compact endpoints (the `values` of a
/// `get_peers` response, the `nodes` of saved state), skipping strings that
/// are neither 6 nor 18 bytes long (libtorrent `read_endpoint_list`).
///
/// Like libtorrent, a non-string element ends the parse and keeps what was
/// read so far; a non-list yields an empty vector.
#[must_use]
pub fn read_endpoint_list(n: &Node<'_>) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    if n.kind() != NodeKind::List {
        return out;
    }
    for item in n.list_iter() {
        if item.kind() != NodeKind::Str {
            return out;
        }
        let s = item.string_value();
        let parsed = match s.len() {
            6 => read_endpoint(Protocol::V4, s),
            18 => read_endpoint(Protocol::V6, s),
            _ => None,
        };
        out.extend(parsed);
    }
    out
}

/// `true` for loopback, private, link-local and unique-local addresses
/// (libtorrent `aux::is_local`): ranges whose "external IP" a remote node
/// could not have derived a BEP 42 ID from.
#[must_use]
pub fn is_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            let o = a.octets();
            o[0] == 10
                || (o[0] == 172 && (o[1] & 0xf0) == 16)
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
                || a.is_loopback()
        }
        IpAddr::V6(a) => {
            let seg0 = a.segments()[0];
            a.is_loopback()
                || (seg0 & 0xffc0) == 0xfe80 // link local
                || (seg0 & 0xffc0) == 0xfec0 // site local (deprecated)
                || (seg0 & 0xff0f) == 0xff02 // multicast link-local
                || (seg0 & 0xff0f) == 0xff05 // multicast site-local
                || (a.octets()[0] & 0xfe) == 0xfc // unique local
        }
    }
}

/// `true` for link-local addresses only (libtorrent `aux::is_link_local`).
#[must_use]
pub fn is_link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => a.octets()[0] == 169 && a.octets()[1] == 254,
        IpAddr::V6(a) => {
            let seg0 = a.segments()[0];
            (seg0 & 0xffc0) == 0xfe80 || (seg0 & 0xff0f) == 0xff02
        }
    }
}
