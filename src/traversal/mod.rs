//! The traversal family: iterative lookups over the routing table.
//!
//! **Placeholders, owned by WP2.** See `docs/PORTING.md` for the `Traversal`
//! and `NodeCtx` contract.

pub mod algorithm;
pub mod direct_request;
pub mod find_data;
pub mod get_item;
pub mod get_peers;
pub mod put_data;
pub mod refresh;
pub mod sample_infohashes;
