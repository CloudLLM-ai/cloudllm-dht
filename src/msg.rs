//! The DHT message model and the declarative message verifier.
//!
//! Provenance: `include/libtorrent/kademlia/msg.hpp`,
//! `src/kademlia/msg.cpp` and the error/response helpers of
//! `src/kademlia/node.cpp` (libtorrent RC_2_1, commit
//! `86d573f2631b0162d3cca5e257217eaf530fdcba`), BSD-3-Clause, Copyright
//! Arvid Norberg and contributors.
//!
//! # Messages
//!
//! Every datagram is a bencoded dictionary with a transaction id `t`, a
//! type `y` ([`MessageType`]) and, for queries, a method `q` ([`Query`]) and
//! an argument dictionary `a`; responses carry `r`, errors carry `e` =
//! `[code, text]` ([`ErrorCode`]).
//!
//! # The verifier
//!
//! libtorrent validates untrusted messages with a table of [`KeyDesc`]s:
//! "key `id` must be a 20-byte string", "optional dictionary `B` whose
//! children follow, ending at the next `LAST_CHILD`". [`verify_message`]
//! walks such a table and returns the found nodes in table order, or the
//! exact error text libtorrent would put in its reply.

use std::fmt;
use std::net::SocketAddr;
use std::ops::BitOr;
use std::str::FromStr;

use crate::bencode::{Entry, Node, NodeKind};

/// A decoded message with the endpoint it came from or goes to
/// (libtorrent `dht::msg`).
#[derive(Debug, Clone, Copy)]
pub struct Msg<'m, 'a> {
    /// The decoded datagram.
    pub message: &'m Node<'a>,
    /// The remote endpoint.
    pub addr: SocketAddr,
}

/// A string did not name a known protocol token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown {what}: {value:?}")]
pub struct ParseTokenError {
    /// Which kind of token was expected (`"message type"`, `"query"`, ...).
    pub what: &'static str,
    /// The offending text.
    pub value: String,
}

macro_rules! wire_enum {
    ($(#[$m:meta])* $name:ident, $what:literal, { $($(#[$vm:meta])* $var:ident => $s:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name { $($(#[$vm])* $var),+ }

        impl $name {
            /// Every variant, for exhaustive tests.
            pub const ALL: &'static [$name] = &[$($name::$var),+];

            /// The token as it appears on the wire.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $($name::$var => $s),+ }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = ParseTokenError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($s => Ok($name::$var),)+
                    other => Err(ParseTokenError { what: $what, value: other.to_owned() }),
                }
            }
        }
    };
}

wire_enum!(
    /// The wire values of `y`.
    MessageType, "message type", {
    /// `q`
    Query => "q",
    /// `r`
    Response => "r",
    /// `e`
    Error => "e",
});

wire_enum!(
    /// The wire values of `q`: the DHT methods libtorrent serves.
    Query, "query", {
    /// BEP 5 `ping`.
    Ping => "ping",
    /// BEP 5 `find_node`.
    FindNode => "find_node",
    /// BEP 5 `get_peers` (with BEP 33 `scrape`).
    GetPeers => "get_peers",
    /// BEP 5 `announce_peer`.
    AnnouncePeer => "announce_peer",
    /// BEP 44 `get`.
    Get => "get",
    /// BEP 44 `put`.
    Put => "put",
    /// BEP 51 `sample_infohashes`.
    SampleInfohashes => "sample_infohashes",
});

wire_enum!(
    /// The tokens of the BEP 32 `want` list.
    Want, "want token", {
    /// Wants IPv4 nodes.
    N4 => "n4",
    /// Wants IPv6 nodes.
    N6 => "n6",
});

/// DHT error codes (BEP 5 and BEP 44) as libtorrent emits them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ErrorCode {
    /// 201: generic error.
    Generic = 201,
    /// 202: server error.
    Server = 202,
    /// 203: protocol error (malformed packet, invalid arguments, bad
    /// token). libtorrent's default.
    Protocol = 203,
    /// 204: method unknown.
    MethodUnknown = 204,
    /// 205: BEP 44 message (value) too big.
    MessageTooBig = 205,
    /// 206: BEP 44 invalid signature.
    InvalidSignature = 206,
    /// 207: BEP 44 salt too big.
    SaltTooBig = 207,
    /// 301: BEP 44 compare-and-swap mismatch.
    CasMismatch = 301,
    /// 302: BEP 44 sequence number less than current.
    SequenceNumberTooLow = 302,
}

impl ErrorCode {
    /// The numeric code.
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Maps a received code to a known variant.
    #[must_use]
    pub fn from_code(code: i64) -> Option<Self> {
        [
            Self::Generic,
            Self::Server,
            Self::Protocol,
            Self::MethodUnknown,
            Self::MessageTooBig,
            Self::InvalidSignature,
            Self::SaltTooBig,
            Self::CasMismatch,
            Self::SequenceNumberTooLow,
        ]
        .into_iter()
        .find(|c| i64::from(c.code()) == code)
    }
}

/// Builds the response skeleton for an error (libtorrent `incoming_error`):
/// `{"y": "e", "e": [code, text]}`. The caller adds the transaction id.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::msg::{error_entry, ErrorCode};
///
/// let e = error_entry(ErrorCode::Protocol, "invalid token");
/// assert_eq!(e.encode(), b"d1:eli203e13:invalid tokene1:y1:ee".to_vec());
/// ```
#[must_use]
pub fn error_entry(code: ErrorCode, text: &str) -> Entry {
    let mut e = Entry::dict();
    e.set("y", "e");
    e.set(
        "e",
        Entry::List(vec![Entry::Int(i64::from(code.code())), Entry::from(text)]),
    );
    e
}

/// Flags of a [`KeyDesc`] (libtorrent `key_desc_t` flag bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyFlags(u8);

impl KeyFlags {
    /// No flags.
    pub const NONE: Self = Self(0);
    /// The key may be absent without failing the parse.
    pub const OPTIONAL: Self = Self(1);
    /// The key is a dictionary whose children follow in the table, up to and
    /// including the next entry flagged [`KeyFlags::LAST_CHILD`]. Nestable.
    pub const PARSE_CHILDREN: Self = Self(2);
    /// The last entry of a child dictionary.
    pub const LAST_CHILD: Self = Self(4);
    /// `size` means "length must be a multiple of", not "exactly".
    pub const SIZE_DIVISIBLE: Self = Self(8);

    /// The union of two flag sets, usable in `const` contexts.
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// `true` when every bit of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for KeyFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// One row of a verification table (libtorrent `key_desc_t`).
#[derive(Debug, Clone, Copy)]
pub struct KeyDesc {
    /// The dictionary key to look up.
    pub name: &'static str,
    /// Required type; `None` accepts any (libtorrent `none_t`).
    pub kind: Option<NodeKind>,
    /// For strings: required length (or divisor with
    /// [`KeyFlags::SIZE_DIVISIBLE`]); `0` means unchecked.
    pub size: usize,
    /// Behaviour flags.
    pub flags: KeyFlags,
}

impl KeyDesc {
    /// A table row.
    #[must_use]
    pub const fn new(
        name: &'static str,
        kind: Option<NodeKind>,
        size: usize,
        flags: KeyFlags,
    ) -> Self {
        Self {
            name,
            kind,
            size,
            flags,
        }
    }
}

/// Why [`verify_message`] rejected a message. The `Display` text is what
/// libtorrent puts in the DHT error it sends back.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The message is not a dictionary.
    #[error("not a dictionary")]
    NotADictionary,
    /// A required key is missing (or has the wrong type).
    #[error("missing '{0}' key")]
    MissingKey(&'static str),
    /// A string key has an invalid length.
    #[error("invalid value for '{0}'")]
    InvalidValue(&'static str),
    /// The table has more `LAST_CHILD` rows than `PARSE_CHILDREN` rows: a
    /// programming error in the table, not in the message.
    #[error("unbalanced key descriptor table")]
    UnbalancedTable,
}

/// Looks up the keys described by `desc` in `message`, returning one slot
/// per row in table order (libtorrent `verify_message`).
///
/// A slot is `None` for an optional key that is absent, has the wrong type,
/// or (for a string) has an invalid size, and for every child of an absent
/// optional dictionary.
///
/// # Errors
///
/// [`VerifyError`] describing the first required key that is absent or
/// malformed; the `Display` text is the one libtorrent replies with.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::bencode::{decode, NodeKind};
/// use cloudllm_dht::msg::{verify_message, KeyDesc, KeyFlags};
///
/// let desc = [KeyDesc::new("A", Some(NodeKind::Str), 4, KeyFlags::NONE)];
/// let m = decode(b"d1:A4:teste").unwrap();
/// let found = verify_message(&m, &desc).unwrap();
/// assert_eq!(found[0].unwrap().string_value(), b"test");
///
/// let bad = decode(b"d1:A6:foobare").unwrap();
/// assert_eq!(verify_message(&bad, &desc).unwrap_err().to_string(), "invalid value for 'A'");
/// ```
pub fn verify_message<'m, 'a>(
    message: &'m Node<'a>,
    desc: &[KeyDesc],
) -> Result<Vec<Option<&'m Node<'a>>>, VerifyError> {
    if message.kind() != NodeKind::Dict {
        return Err(VerifyError::NotADictionary);
    }
    let mut ret: Vec<Option<&'m Node<'a>>> = vec![None; desc.len()];
    let mut stack: Vec<&'m Node<'a>> = vec![message];
    let mut i = 0;
    while i < desc.len() {
        let k = &desc[i];
        let cur = *stack.last().expect("the stack always holds the root");
        let mut found = cur.dict_find(k.name.as_bytes());
        if let (Some(n), Some(kind)) = (found, k.kind) {
            if n.kind() != kind {
                found = None;
            }
        }
        let optional = k.flags.contains(KeyFlags::OPTIONAL);
        if found.is_none() && !optional {
            return Err(VerifyError::MissingKey(k.name));
        }
        if let Some(n) = found {
            if k.size > 0 && k.kind == Some(NodeKind::Str) {
                let len = n.string_length();
                let invalid = if k.flags.contains(KeyFlags::SIZE_DIVISIBLE) {
                    len % k.size != 0
                } else {
                    len != k.size
                };
                if invalid {
                    found = None;
                    if !optional {
                        return Err(VerifyError::InvalidValue(k.name));
                    }
                }
            }
        }
        ret[i] = found;
        if k.flags.contains(KeyFlags::PARSE_CHILDREN) {
            match found {
                Some(n) => stack.push(n),
                None => {
                    while i < desc.len() && !desc[i].flags.contains(KeyFlags::LAST_CHILD) {
                        i += 1;
                    }
                }
            }
        } else if k.flags.contains(KeyFlags::LAST_CHILD) {
            if stack.len() == 1 {
                return Err(VerifyError::UnbalancedTable);
            }
            stack.pop();
        }
        i += 1;
    }
    Ok(ret)
}
