//! `cloudllm_dht`: the BitTorrent Mainline DHT as a sans-IO Rust library,
//! ported from libtorrent's Kademlia implementation (RC_2_1).
//!
//! See `docs/ARCHITECTURE.md` for the design and `docs/PORTING.md` for the
//! module-by-module status against libtorrent.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bencode;
