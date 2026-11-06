//! The owned bencode value, the counterpart of libtorrent's `entry`.
//!
//! Provenance: `include/libtorrent/entry.hpp`, `src/entry.cpp` and
//! `include/libtorrent/bencode.hpp` of libtorrent RC_2_1
//! (commit `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause,
//! Copyright Arvid Norberg and contributors.
//!
//! [`Entry`] is what the node *builds* (outgoing queries and responses, the
//! saved DHT state); [`crate::bencode::Node`] is what the node *reads*
//! (borrowed views into a received datagram). Keeping the two apart mirrors
//! libtorrent and keeps the receive path free of copies.

use std::collections::BTreeMap;
use std::fmt;

use super::bdecode::{Node, NodeKind};

/// An owned bencoded value.
///
/// Dictionaries are `BTreeMap`s keyed by raw bytes, so [`Entry::encode`]
/// always writes keys in the sorted order BEP 3 requires (libtorrent's
/// `entry::dictionary_type` is a `std::map` for the same reason).
///
/// # Examples
///
/// ```
/// use cloudllm_dht::bencode::Entry;
///
/// let mut e = Entry::dict();
/// e.set("q", "ping");
/// e.set("t", "aa");
/// e.set("y", "q");
/// assert_eq!(e.encode(), b"d1:q4:ping1:t2:aa1:y1:qe".to_vec());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Entry {
    /// An integer (`i42e`).
    Int(i64),
    /// A byte string (`4:spam`). Bencoded strings are bytes, not UTF-8.
    Str(Vec<u8>),
    /// A list (`l...e`).
    List(Vec<Entry>),
    /// A dictionary (`d...e`), keys sorted.
    Dict(BTreeMap<Vec<u8>, Entry>),
    /// libtorrent's `undefined_t`: a default-constructed entry that has not
    /// been given a type yet. It encodes as the empty string `0:`.
    #[default]
    Undefined,
}

impl Entry {
    /// An empty dictionary.
    #[must_use]
    pub fn dict() -> Self {
        Self::Dict(BTreeMap::new())
    }

    /// An empty list.
    #[must_use]
    pub fn list() -> Self {
        Self::List(Vec::new())
    }

    /// Inserts `value` under `key`, turning an [`Entry::Undefined`] into a
    /// dictionary first (libtorrent's `e["key"] = value`).
    ///
    /// # Panics
    ///
    /// Panics if `self` is already a defined non-dictionary value; that is a
    /// programming error (libtorrent asserts and throws the same way).
    pub fn set(&mut self, key: impl AsRef<[u8]>, value: impl Into<Entry>) -> &mut Self {
        if matches!(self, Self::Undefined) {
            *self = Self::dict();
        }
        match self {
            Self::Dict(map) => {
                map.insert(key.as_ref().to_vec(), value.into());
            }
            other => panic!("Entry::set on a non-dictionary: {other:?}"),
        }
        self
    }

    /// Appends `value`, turning an [`Entry::Undefined`] into a list first
    /// (libtorrent's `e.list().push_back(value)`).
    ///
    /// # Panics
    ///
    /// Panics if `self` is already a defined non-list value.
    pub fn push(&mut self, value: impl Into<Entry>) -> &mut Self {
        if matches!(self, Self::Undefined) {
            *self = Self::list();
        }
        match self {
            Self::List(items) => items.push(value.into()),
            other => panic!("Entry::push on a non-list: {other:?}"),
        }
        self
    }

    /// Returns the value under `key` if `self` is a dictionary holding it.
    #[must_use]
    pub fn get(&self, key: impl AsRef<[u8]>) -> Option<&Entry> {
        match self {
            Self::Dict(map) => map.get(key.as_ref()),
            _ => None,
        }
    }

    /// Returns the integer, if this is one (libtorrent `entry::integer()`).
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the string bytes, if this is a string (libtorrent
    /// `entry::string()`).
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Str(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the list items, if this is a list.
    #[must_use]
    pub fn as_list(&self) -> Option<&[Entry]> {
        match self {
            Self::List(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the dictionary, if this is one.
    #[must_use]
    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, Entry>> {
        match self {
            Self::Dict(v) => Some(v),
            _ => None,
        }
    }

    /// Bencodes the value (libtorrent `bencode(out, entry)`).
    ///
    /// # Examples
    ///
    /// ```
    /// use cloudllm_dht::bencode::Entry;
    /// assert_eq!(Entry::Int(-3).encode(), b"i-3e".to_vec());
    /// assert_eq!(Entry::from("spam").encode(), b"4:spam".to_vec());
    /// ```
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// Bencodes the value onto the end of `out`, so callers can reuse one
    /// buffer across messages.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Int(v) => {
                out.push(b'i');
                out.extend_from_slice(v.to_string().as_bytes());
                out.push(b'e');
            }
            Self::Str(s) => encode_str(s, out),
            Self::List(items) => {
                out.push(b'l');
                items.iter().for_each(|i| i.encode_into(out));
                out.push(b'e');
            }
            Self::Dict(map) => {
                out.push(b'd');
                for (k, v) in map {
                    encode_str(k, out);
                    v.encode_into(out);
                }
                out.push(b'e');
            }
            Self::Undefined => out.extend_from_slice(b"0:"),
        }
    }

    /// Copies a decoded [`Node`] into an owned entry (libtorrent builds an
    /// `entry` from a `bdecode_node` the same way when it persists state).
    #[must_use]
    pub fn from_node(node: &Node<'_>) -> Self {
        match node.kind() {
            NodeKind::Int => Self::Int(node.int_value()),
            NodeKind::Str => Self::Str(node.string_value().to_vec()),
            NodeKind::List => Self::List(node.list_iter().map(Self::from_node).collect()),
            NodeKind::Dict => Self::Dict(
                node.dict_iter()
                    .map(|(k, v)| (k.string_value().to_vec(), Self::from_node(v)))
                    .collect(),
            ),
        }
    }
}

fn encode_str(s: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(s.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(s);
}

impl fmt::Display for Entry {
    /// A compact human-readable rendering (libtorrent `entry::to_string`
    /// style), for logs and test failure messages.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(v) => write!(f, "{v}"),
            Self::Str(s) => write!(f, "'{}'", String::from_utf8_lossy(s)),
            Self::List(items) => {
                f.write_str("[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{item}")?;
                }
                f.write_str("]")
            }
            Self::Dict(map) => {
                f.write_str("{")?;
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "'{}': {v}", String::from_utf8_lossy(k))?;
                }
                f.write_str("}")
            }
            Self::Undefined => f.write_str("undefined"),
        }
    }
}

macro_rules! entry_from_int {
    ($($t:ty),*) => {$(
        impl From<$t> for Entry {
            fn from(v: $t) -> Self { Self::Int(i64::from(v)) }
        }
    )*};
}
entry_from_int!(i8, i16, i32, i64, u8, u16, u32);

impl From<bool> for Entry {
    /// `true` is `1` and `false` is `0`, as libtorrent stores booleans.
    fn from(v: bool) -> Self {
        Self::Int(i64::from(v))
    }
}
impl From<&str> for Entry {
    fn from(v: &str) -> Self {
        Self::Str(v.as_bytes().to_vec())
    }
}
impl From<String> for Entry {
    fn from(v: String) -> Self {
        Self::Str(v.into_bytes())
    }
}
impl From<&[u8]> for Entry {
    fn from(v: &[u8]) -> Self {
        Self::Str(v.to_vec())
    }
}
impl From<Vec<u8>> for Entry {
    fn from(v: Vec<u8>) -> Self {
        Self::Str(v)
    }
}
impl<const N: usize> From<[u8; N]> for Entry {
    fn from(v: [u8; N]) -> Self {
        Self::Str(v.to_vec())
    }
}
impl<const N: usize> From<&[u8; N]> for Entry {
    fn from(v: &[u8; N]) -> Self {
        Self::Str(v.to_vec())
    }
}
impl From<Vec<Entry>> for Entry {
    fn from(v: Vec<Entry>) -> Self {
        Self::List(v)
    }
}
