//! The outbound edge of the sans-IO core.
//!
//! Provenance: `socket_manager` in `include/libtorrent/kademlia/node.hpp`
//! of libtorrent RC_2_1 (commit `86d573f2631b0162d3cca5e257217eaf530fdcba`),
//! BSD-3-Clause, Copyright Arvid Norberg and contributors.

use std::net::SocketAddr;

use crate::bencode::Entry;

/// Where the DHT core sends the messages it builds.
///
/// libtorrent's `socket_manager` is the DHT's only view of the network: it
/// asks whether the upload budget allows a response, and hands over a
/// message and a destination. Keeping it a trait is what lets the tests
/// port `test_dht.cpp`'s `mock_socket` one to one and lets the real driver
/// be a thin tokio wrapper.
pub trait Transport {
    /// `true` while the node may still send responses (libtorrent
    /// `has_quota`): the upload rate limit has not been exhausted.
    fn has_quota(&mut self) -> bool;

    /// Sends `msg` to `dst`. Returns `false` if it was not sent (libtorrent
    /// `send_packet`). The implementation bencodes the entry; the core
    /// hands over the structured message so tests can inspect it.
    fn send_packet(&mut self, msg: &Entry, dst: SocketAddr) -> bool;
}
