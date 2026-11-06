//! `cloudllm_dht`: the BitTorrent Mainline DHT as a sans-IO Rust library,
//! ported from libtorrent's Kademlia implementation (RC_2_1).
//!
//! See `docs/ARCHITECTURE.md` for the design and `docs/PORTING.md` for the
//! module-by-module status against libtorrent.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod announce_flags;
pub mod bencode;
pub mod bloom_filter;
pub mod ctx;
pub mod dht_state;
pub mod dos_blocker;
#[cfg(feature = "tokio-driver")]
pub mod driver;
pub mod ed25519;
pub mod events;
pub mod item;
pub mod msg;
pub mod net;
pub mod node;
pub mod node_entry;
pub mod node_id;
pub mod observer;
pub mod rng;
pub mod routing_table;
pub mod rpc_manager;
pub mod settings;
pub mod sha1_hash;
pub mod storage;
pub mod testing;
pub mod time;
pub mod tracker;
pub mod transport;
pub mod traversal;
pub mod types;

pub use sha1_hash::Sha1Hash;
