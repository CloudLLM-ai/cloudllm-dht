//! Bencoding: the wire format of every DHT message.
//!
//! * [`decode`] / [`Node`] read a datagram without copying (libtorrent
//!   `bdecode`, `bdecode_node`).
//! * [`Entry`] builds and encodes messages (libtorrent `entry`, `bencode`).
//!
//! See the module docs of [`bdecode`] and [`entry`] for provenance.

pub mod bdecode;
pub mod entry;

pub use bdecode::{
    decode, decode_lenient, decode_with_limits, BdecodeError, DecodeError, Decoded, Node, NodeKind,
    DEFAULT_DEPTH_LIMIT, DEFAULT_TOKEN_LIMIT, MAX_BUFFER_SIZE,
};
pub use entry::Entry;
