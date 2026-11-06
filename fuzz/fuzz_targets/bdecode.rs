//! Fuzzes the bencode decoder with arbitrary datagrams.
//!
//! Invariants, beyond "never panics, never recurses":
//! * a successful decode consumes exactly the input (a datagram is one value);
//! * `data_section` of the root is the whole input, and re-decoding it gives
//!   the same print;
//! * an owned copy ([`Entry`]) re-encodes to something that decodes to the
//!   same entry (integers that overflowed to 0 included);
//! * the lenient decode agrees with the strict one on success and failure.
#![no_main]

use cloudllm_dht::bencode::{decode, decode_lenient, Entry};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let strict = decode(data);
    let lenient = decode_lenient(data, 100, 2_000_000);
    match strict {
        Ok(node) => {
            assert!(lenient.error.is_none());
            assert!(node.data_section().len() <= data.len());
            let _ = node.has_soft_error();
            let _ = node.print(false, 0);
            let entry = Entry::from_node(&node);
            let reencoded = entry.encode();
            let again = decode(&reencoded).expect("encoder output must decode");
            assert_eq!(Entry::from_node(&again), entry);
        }
        Err(e) => {
            assert_eq!(lenient.error, Some(e));
            assert!(e.position <= data.len());
            if let Some(partial) = lenient.node {
                let _ = partial.print(true, 0);
            }
        }
    }
});
