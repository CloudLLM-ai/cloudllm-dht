//! The bencode decoder, the counterpart of libtorrent's `bdecode_node`.
//!
//! Provenance: `include/libtorrent/bdecode.hpp` and `src/bdecode.cpp` of
//! libtorrent RC_2_1 (commit `86d573f2631b0162d3cca5e257217eaf530fdcba`),
//! BSD-3-Clause, Copyright Arvid Norberg and contributors.
//!
//! # Design
//!
//! libtorrent decodes into a flat token array and hands out cheap views.
//! This port decodes into a small tree of [`Node`]s that borrow the input
//! buffer: every string is a slice of the datagram, nothing is copied, and
//! [`Node::data_section`] still returns the exact source bytes of any
//! sub-value (BEP 44 signs the raw bytes of `v`, so this matters).
//!
//! The decoder is a port of the same state machine, so every limit and every
//! error position matches libtorrent's. The port keeps three properties the
//! DHT relies on:
//!
//! * **Bounded work.** `depth_limit` (default [`DEFAULT_DEPTH_LIMIT`]) and
//!   `token_limit` (default [`DEFAULT_TOKEN_LIMIT`]) cap nesting and the
//!   number of values, and buffers over [`MAX_BUFFER_SIZE`] are refused.
//! * **No recursion.** Nesting is tracked in an explicit stack, so hostile
//!   nesting cannot overflow the call stack. (Dropping a deeply nested
//!   [`Node`] is bounded by the depth limit.)
//! * **Lenient integers, strict structure.** An integer that overflows 64
//!   bits decodes as `0` (libtorrent's "lazy" behaviour), while structural
//!   problems are errors. Cosmetic problems (unsorted or duplicate keys,
//!   leading zeros) are *soft errors*, reported only by
//!   [`Node::has_soft_error`], because real-world peers send them.

use std::cmp::Ordering;
use std::fmt::Write as _;

/// libtorrent's default maximum nesting depth for lists and dictionaries.
pub const DEFAULT_DEPTH_LIMIT: usize = 100;

/// libtorrent's default maximum number of values in one document.
pub const DEFAULT_TOKEN_LIMIT: i64 = 2_000_000;

/// Largest buffer the decoder accepts (`bdecode_token::max_offset`,
/// `2^29 - 1`). Larger inputs fail with [`BdecodeError::LimitExceeded`].
pub const MAX_BUFFER_SIZE: usize = (1 << 29) - 1;

/// Longest string header (`<digits>:`) the decoder accepts
/// (`bdecode_token::long_string_max_header`).
const MAX_STRING_HEADER: usize = 8 + 7 + 2;

/// A bdecode failure, the counterpart of libtorrent's
/// `bdecode_errors::error_code_enum`.
///
/// The `Display` text is libtorrent's `bdecode_category().message()` text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum BdecodeError {
    /// Expected a digit in a bencoded string or integer.
    #[error("expected digit in bencoded string")]
    ExpectedDigit,
    /// Expected a colon after a string length.
    #[error("expected colon in bencoded string")]
    ExpectedColon,
    /// The buffer ended in the middle of a value.
    #[error("unexpected end of file in bencoded string")]
    UnexpectedEof,
    /// Expected a value (list, dictionary, integer or string).
    #[error("expected value (list, dict, int or string) in bencoded string")]
    ExpectedValue,
    /// Nesting exceeded the depth limit.
    #[error("bencoded nesting depth exceeded")]
    DepthExceeded,
    /// The value-count or buffer-size limit was exceeded.
    #[error("bencoded item count limit exceeded")]
    LimitExceeded,
    /// An integer or string length does not fit in 64 bits.
    #[error("integer overflow")]
    Overflow,
}

/// A failed decode: what went wrong and where.
///
/// `position` is the byte offset libtorrent reports through its `error_pos`
/// out-parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{code} at byte {position}")]
pub struct DecodeError {
    /// The failure.
    pub code: BdecodeError,
    /// Byte offset in the input at which decoding stopped.
    pub position: usize,
}

/// The type of a decoded value (libtorrent `bdecode_node::type_t`, minus
/// `none_t`, which Rust expresses as `Option::None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKind {
    /// A dictionary.
    Dict,
    /// A list.
    List,
    /// A byte string.
    Str,
    /// An integer.
    Int,
}

/// One decoded value, borrowing the input buffer.
///
/// All accessors are total: asking a list for its dictionary entries yields
/// nothing rather than panicking, matching how DHT message handlers probe
/// untrusted input.
#[derive(Debug, Clone)]
pub struct Node<'a> {
    buf: &'a [u8],
    start: usize,
    end: usize,
    body: Body<'a>,
}

#[derive(Debug, Clone)]
enum Body<'a> {
    Int(i64),
    /// Offset of the first payload byte (after the `len:` header).
    Str(usize),
    List(Vec<Node<'a>>),
    Dict(Vec<(Node<'a>, Node<'a>)>),
}

/// The result of [`decode_lenient`]: whatever was parsed before an error.
///
/// libtorrent keeps a valid partial tree after a failed parse so that
/// callers can still print it; `print_entry` of such a tree is how the
/// `partial_parse*` tests check it.
#[derive(Debug)]
pub struct Decoded<'a> {
    /// The (possibly partial) tree; `None` only when nothing parsed at all.
    pub node: Option<Node<'a>>,
    /// The error, if the parse did not complete.
    pub error: Option<DecodeError>,
}

/// Decodes `buf` with libtorrent's default limits (`bdecode(buffer, ec)`).
///
/// # Errors
///
/// Returns the first [`DecodeError`] encountered.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::bencode::decode;
///
/// let node = decode(b"d1:ai1e1:b3:fooe").unwrap();
/// assert_eq!(node.dict_find_int_value(b"a", 0), 1);
/// assert_eq!(node.dict_find_string_value(b"b", b""), b"foo");
/// ```
pub fn decode(buf: &[u8]) -> Result<Node<'_>, DecodeError> {
    decode_with_limits(buf, DEFAULT_DEPTH_LIMIT, DEFAULT_TOKEN_LIMIT)
}

/// Decodes `buf` with explicit limits (`bdecode(..., depth_limit,
/// token_limit)`).
///
/// # Errors
///
/// Returns the first [`DecodeError`] encountered.
pub fn decode_with_limits(
    buf: &[u8],
    depth_limit: usize,
    token_limit: i64,
) -> Result<Node<'_>, DecodeError> {
    let d = decode_lenient(buf, depth_limit, token_limit);
    match d.error {
        Some(e) => Err(e),
        None => Ok(d.node.expect("a decode without error always has a root")),
    }
}

/// Decodes `buf` and keeps the partial tree on failure.
///
/// On error the open lists and dictionaries are closed where parsing
/// stopped, and a dictionary key whose value failed to parse gets an empty
/// dictionary as its value, exactly as libtorrent terminates its token tree.
#[must_use]
pub fn decode_lenient(buf: &[u8], depth_limit: usize, token_limit: i64) -> Decoded<'_> {
    Parser::new(buf, depth_limit, token_limit).run()
}

/// An open list or dictionary on the parser's explicit stack.
struct Frame<'a> {
    is_dict: bool,
    start: usize,
    items: Vec<Node<'a>>,
    /// For dictionaries: a key waiting for its value (libtorrent's
    /// `stack_frame::state == 1`).
    pending_key: Option<Node<'a>>,
    pairs: Vec<(Node<'a>, Node<'a>)>,
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
    depth_limit: usize,
    tokens_left: i64,
    stack: Vec<Frame<'a>>,
}

impl<'a> Parser<'a> {
    fn new(buf: &'a [u8], depth_limit: usize, token_limit: i64) -> Self {
        Self {
            buf,
            pos: 0,
            depth_limit,
            tokens_left: token_limit,
            stack: Vec::new(),
        }
    }

    fn fail(&mut self, code: BdecodeError, position: usize) -> Decoded<'a> {
        Decoded {
            node: self.unwind(position),
            error: Some(DecodeError { code, position }),
        }
    }

    fn run(mut self) -> Decoded<'a> {
        if self.buf.len() > MAX_BUFFER_SIZE {
            return self.fail(BdecodeError::LimitExceeded, 0);
        }
        loop {
            match self.step() {
                Step::Continue => {}
                Step::Done(node) => {
                    return Decoded {
                        node: Some(node),
                        error: None,
                    }
                }
                Step::Fail(code, position) => return self.fail(code, position),
            }
        }
    }

    /// Parses one token (libtorrent's main loop body).
    fn step(&mut self) -> Step<'a> {
        let end = self.buf.len();
        if self.pos >= end {
            return Step::Fail(BdecodeError::UnexpectedEof, self.pos);
        }
        if self.stack.len() >= self.depth_limit {
            return Step::Fail(BdecodeError::DepthExceeded, self.pos);
        }
        self.tokens_left -= 1;
        if self.tokens_left < 0 {
            return Step::Fail(BdecodeError::LimitExceeded, self.pos);
        }
        let t = self.buf[self.pos];
        let expecting_key = self
            .stack
            .last()
            .is_some_and(|f| f.is_dict && f.pending_key.is_none());
        if expecting_key && !t.is_ascii_digit() && t != b'e' {
            return Step::Fail(BdecodeError::ExpectedDigit, self.pos);
        }
        match t {
            b'd' | b'l' => {
                self.stack.push(Frame {
                    is_dict: t == b'd',
                    start: self.pos,
                    items: Vec::new(),
                    pending_key: None,
                    pairs: Vec::new(),
                });
                self.pos += 1;
                Step::Continue
            }
            b'i' => self.parse_int(),
            b'e' => self.parse_end(),
            _ => self.parse_string(t),
        }
    }

    fn parse_int(&mut self) -> Step<'a> {
        let int_start = self.pos;
        let (stop, err) = check_integer(self.buf, int_start + 1);
        if let Some(code) = err {
            return Step::Fail(code, stop);
        }
        let value = int_value_at(self.buf, int_start);
        self.pos = stop + 1;
        self.complete(Node {
            buf: self.buf,
            start: int_start,
            end: self.pos,
            body: Body::Int(value),
        })
    }

    fn parse_end(&mut self) -> Step<'a> {
        let Some(frame) = self.stack.pop() else {
            return Step::Fail(BdecodeError::UnexpectedEof, self.pos);
        };
        if frame.is_dict && frame.pending_key.is_some() {
            let pos = self.pos;
            self.stack.push(frame);
            return Step::Fail(BdecodeError::ExpectedValue, pos);
        }
        self.pos += 1;
        let node = frame.close(self.buf, self.pos);
        self.complete(node)
    }

    fn parse_string(&mut self, first: u8) -> Step<'a> {
        let end = self.buf.len();
        if !first.is_ascii_digit() {
            return Step::Fail(BdecodeError::ExpectedValue, self.pos);
        }
        let mut len = i64::from(first - b'0');
        let str_start = self.pos;
        let mut p = self.pos + 1;
        if p >= end {
            self.pos = p;
            return Step::Fail(BdecodeError::UnexpectedEof, p);
        }
        let (stop, err) = parse_int(self.buf, p, end, b':', &mut len);
        p = stop;
        if let Some(code) = err {
            return Step::Fail(code, p);
        }
        if p == end {
            return Step::Fail(BdecodeError::ExpectedColon, p);
        }
        let remaining = i64::try_from(end - p - 1).unwrap_or(i64::MAX);
        if len > remaining {
            return Step::Fail(BdecodeError::UnexpectedEof, p);
        }
        if len < 0 {
            return Step::Fail(BdecodeError::Overflow, p);
        }
        let data_start = p + 1;
        if data_start - str_start > MAX_STRING_HEADER {
            return Step::Fail(BdecodeError::LimitExceeded, data_start);
        }
        let len = usize::try_from(len).expect("len is checked against the buffer size");
        self.pos = data_start + len;
        self.complete(Node {
            buf: self.buf,
            start: str_start,
            end: self.pos,
            body: Body::Str(data_start),
        })
    }

    /// Hands a finished value to its parent, or finishes the document.
    fn complete(&mut self, node: Node<'a>) -> Step<'a> {
        match self.stack.last_mut() {
            None => Step::Done(node),
            Some(f) if f.is_dict => {
                match f.pending_key.take() {
                    None => f.pending_key = Some(node),
                    Some(key) => f.pairs.push((key, node)),
                }
                Step::Continue
            }
            Some(f) => {
                f.items.push(node);
                Step::Continue
            }
        }
    }

    /// Closes every open container at `position` after a failure.
    fn unwind(&mut self, position: usize) -> Option<Node<'a>> {
        let mut last: Option<Node<'a>> = None;
        while let Some(mut frame) = self.stack.pop() {
            if let Some(child) = last.take() {
                // The child was the value of the pending key, or a list item.
                if frame.is_dict {
                    let key = frame.pending_key.take().expect("a child value has a key");
                    frame.pairs.push((key, child));
                } else {
                    frame.items.push(child);
                }
            }
            if let Some(key) = frame.pending_key.take() {
                let empty = Node {
                    buf: self.buf,
                    start: position,
                    end: position,
                    body: Body::Dict(Vec::new()),
                };
                frame.pairs.push((key, empty));
            }
            last = Some(frame.close(self.buf, position));
        }
        last
    }
}

enum Step<'a> {
    Continue,
    Done(Node<'a>),
    Fail(BdecodeError, usize),
}

impl<'a> Frame<'a> {
    fn close(self, buf: &'a [u8], end: usize) -> Node<'a> {
        let body = if self.is_dict {
            Body::Dict(self.pairs)
        } else {
            Body::List(self.items)
        };
        Node {
            buf,
            start: self.start,
            end,
            body,
        }
    }
}

/// Validates the digits of an integer starting after the `i` (libtorrent
/// `check_integer`). Returns the offset where scanning stopped (the closing
/// `e` on success) and the error, if any.
fn check_integer(buf: &[u8], mut p: usize) -> (usize, Option<BdecodeError>) {
    let end = buf.len();
    if p == end {
        return (p, Some(BdecodeError::UnexpectedEof));
    }
    if buf[p] == b'-' {
        p += 1;
        if p == end {
            return (p, Some(BdecodeError::UnexpectedEof));
        }
    }
    let mut digits = 0;
    let mut err = None;
    loop {
        if !buf[p].is_ascii_digit() {
            err = Some(BdecodeError::ExpectedDigit);
            break;
        }
        p += 1;
        digits += 1;
        if p == end {
            err = Some(BdecodeError::UnexpectedEof);
            break;
        }
        if buf[p] == b'e' {
            break;
        }
    }
    if digits > 20 {
        err = Some(BdecodeError::Overflow);
    }
    (p, err)
}

/// Reads decimal digits from `start` up to `delimiter` or `end` into `val`
/// (libtorrent's exported `parse_int`). `val` must be `>= 0` on entry and is
/// the running value, so callers can seed it with a first digit.
///
/// Returns the offset where parsing stopped and the error, if any. Overflow
/// is detected before it happens, so `val` never wraps.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::bencode::bdecode::parse_int;
///
/// let mut v = 0;
/// let (stop, err) = parse_int(b"1234567890e", 0, 11, b'e', &mut v);
/// assert_eq!((v, stop, err), (1_234_567_890, 10, None));
/// ```
pub fn parse_int(
    buf: &[u8],
    mut start: usize,
    end: usize,
    delimiter: u8,
    val: &mut i64,
) -> (usize, Option<BdecodeError>) {
    while start < end && buf[start] != delimiter {
        let c = buf[start];
        if !c.is_ascii_digit() {
            return (start, Some(BdecodeError::ExpectedDigit));
        }
        if *val > i64::MAX / 10 {
            return (start, Some(BdecodeError::Overflow));
        }
        *val *= 10;
        let digit = i64::from(c - b'0');
        if *val > i64::MAX - digit {
            return (start, Some(BdecodeError::Overflow));
        }
        *val += digit;
        start += 1;
    }
    (start, None)
}

/// Parses the validated integer token at `at` (`i...e`); `0` on overflow.
fn int_value_at(buf: &[u8], at: usize) -> i64 {
    let negative = buf[at + 1] == b'-';
    let first = at + 1 + usize::from(negative);
    let mut val = 0;
    let (_, err) = parse_int(buf, first, buf.len(), b'e', &mut val);
    if err.is_some() {
        0
    } else if negative {
        -val
    } else {
        val
    }
}

impl<'a> Node<'a> {
    /// The value's type.
    #[must_use]
    pub fn kind(&self) -> NodeKind {
        match self.body {
            Body::Int(_) => NodeKind::Int,
            Body::Str(_) => NodeKind::Str,
            Body::List(_) => NodeKind::List,
            Body::Dict(_) => NodeKind::Dict,
        }
    }

    /// The integer value, or `0` for non-integers and for integers that do
    /// not fit in 64 bits (libtorrent `int_value()`).
    #[must_use]
    pub fn int_value(&self) -> i64 {
        match self.body {
            Body::Int(v) => v,
            _ => 0,
        }
    }

    /// The string payload, empty for non-strings (libtorrent
    /// `string_value()`). Borrows the input buffer, not the node.
    #[must_use]
    pub fn string_value(&self) -> &'a [u8] {
        match self.body {
            Body::Str(at) => &self.buf[at..self.end],
            _ => &[],
        }
    }

    /// Length of the string payload (libtorrent `string_length()`).
    #[must_use]
    pub fn string_length(&self) -> usize {
        self.string_value().len()
    }

    /// Offset of the string payload in the input (libtorrent
    /// `string_offset()`); `0` for non-strings.
    #[must_use]
    pub fn string_offset(&self) -> usize {
        match self.body {
            Body::Str(at) => at,
            _ => 0,
        }
    }

    /// The exact source bytes of this value, including its header and
    /// terminator (libtorrent `data_section()`). BEP 44 verifies signatures
    /// over the raw bytes of `v`, so re-encoding is not an option.
    #[must_use]
    pub fn data_section(&self) -> &'a [u8] {
        &self.buf[self.start..self.end]
    }

    /// Offset of this value in the input (libtorrent `data_offset()`).
    #[must_use]
    pub fn data_offset(&self) -> usize {
        self.start
    }

    /// Number of list items; `0` for non-lists (libtorrent `list_size()`).
    #[must_use]
    pub fn list_len(&self) -> usize {
        match &self.body {
            Body::List(v) => v.len(),
            _ => 0,
        }
    }

    /// The `i`th list item (libtorrent `list_at(i)`).
    #[must_use]
    pub fn list_at(&self, i: usize) -> Option<&Node<'a>> {
        match &self.body {
            Body::List(v) => v.get(i),
            _ => None,
        }
    }

    /// Iterates list items (empty for non-lists).
    pub fn list_iter(&self) -> impl Iterator<Item = &Node<'a>> {
        match &self.body {
            Body::List(v) => v.as_slice(),
            _ => &[],
        }
        .iter()
    }

    /// Integer at list index `i`, or `default` when absent or not an
    /// integer (libtorrent `list_int_value_at`).
    #[must_use]
    pub fn list_int_value_at(&self, i: usize, default: i64) -> i64 {
        match self.list_at(i) {
            Some(n) if n.kind() == NodeKind::Int => n.int_value(),
            _ => default,
        }
    }

    /// String at list index `i`, or `default` (libtorrent
    /// `list_string_value_at`).
    #[must_use]
    pub fn list_string_value_at<'d>(&self, i: usize, default: &'d [u8]) -> &'d [u8]
    where
        'a: 'd,
    {
        match self.list_at(i) {
            Some(n) if n.kind() == NodeKind::Str => n.string_value(),
            _ => default,
        }
    }

    /// Number of dictionary entries; `0` for non-dictionaries.
    #[must_use]
    pub fn dict_len(&self) -> usize {
        match &self.body {
            Body::Dict(v) => v.len(),
            _ => 0,
        }
    }

    /// The `i`th key and value (libtorrent `dict_at`), in wire order.
    #[must_use]
    pub fn dict_at(&self, i: usize) -> Option<(&'a [u8], &Node<'a>)> {
        self.dict_at_node(i).map(|(k, v)| (k.string_value(), v))
    }

    /// Like [`Node::dict_at`] but returns the key as a node, so callers can
    /// ask for its offsets (libtorrent `dict_at_node`).
    #[must_use]
    pub fn dict_at_node(&self, i: usize) -> Option<(&Node<'a>, &Node<'a>)> {
        match &self.body {
            Body::Dict(v) => v.get(i).map(|(k, v)| (k, v)),
            _ => None,
        }
    }

    /// Iterates `(key node, value node)` pairs in wire order.
    pub fn dict_iter(&self) -> impl Iterator<Item = (&Node<'a>, &Node<'a>)> {
        match &self.body {
            Body::Dict(v) => v.as_slice(),
            _ => &[],
        }
        .iter()
        .map(|(k, v)| (k, v))
    }

    /// The value for `key` (libtorrent `dict_find`). Linear, like
    /// libtorrent: DHT messages have a handful of keys. With duplicate keys
    /// the first one wins.
    #[must_use]
    pub fn dict_find(&self, key: &[u8]) -> Option<&Node<'a>> {
        self.dict_iter()
            .find(|(k, _)| k.string_value() == key)
            .map(|(_, v)| v)
    }

    /// The value for `key` if it is an integer (libtorrent `dict_find_int`).
    #[must_use]
    pub fn dict_find_int(&self, key: &[u8]) -> Option<&Node<'a>> {
        self.dict_find(key).filter(|n| n.kind() == NodeKind::Int)
    }

    /// Integer value for `key`, or `default` (libtorrent
    /// `dict_find_int_value`).
    #[must_use]
    pub fn dict_find_int_value(&self, key: &[u8], default: i64) -> i64 {
        self.dict_find_int(key).map_or(default, Node::int_value)
    }

    /// The value for `key` if it is a string (libtorrent `dict_find_string`).
    #[must_use]
    pub fn dict_find_string(&self, key: &[u8]) -> Option<&Node<'a>> {
        self.dict_find(key).filter(|n| n.kind() == NodeKind::Str)
    }

    /// String value for `key`, or `default` (libtorrent
    /// `dict_find_string_value`).
    #[must_use]
    pub fn dict_find_string_value<'d>(&self, key: &[u8], default: &'d [u8]) -> &'d [u8]
    where
        'a: 'd,
    {
        self.dict_find_string(key)
            .map_or(default, Node::string_value)
    }

    /// The value for `key` if it is a list (libtorrent `dict_find_list`).
    #[must_use]
    pub fn dict_find_list(&self, key: &[u8]) -> Option<&Node<'a>> {
        self.dict_find(key).filter(|n| n.kind() == NodeKind::List)
    }

    /// The value for `key` if it is a dictionary (libtorrent
    /// `dict_find_dict`).
    #[must_use]
    pub fn dict_find_dict(&self, key: &[u8]) -> Option<&Node<'a>> {
        self.dict_find(key).filter(|n| n.kind() == NodeKind::Dict)
    }

    /// Reports the first cosmetic problem in the tree, or `None`
    /// (libtorrent `has_soft_error`).
    ///
    /// The checks, in libtorrent's order of detection, are: a leading zero
    /// in an integer or string length, dictionary keys out of order, and
    /// duplicate dictionary keys. These do not make a message undecodable,
    /// but a node that wants strict BEP 3 behaviour can reject on them.
    ///
    /// # Examples
    ///
    /// ```
    /// use cloudllm_dht::bencode::decode;
    ///
    /// let e = decode(b"d2:bai1e2:aai2ee").unwrap();
    /// assert_eq!(e.has_soft_error(), Some("unsorted dictionary key"));
    /// ```
    #[must_use]
    pub fn has_soft_error(&self) -> Option<&'static str> {
        match &self.body {
            Body::Int(_) => {
                let raw = self.data_section();
                (raw.get(1) == Some(&b'0') && raw.get(2) != Some(&b'e'))
                    .then_some("leading zero in integer")
            }
            Body::Str(_) => {
                let raw = self.data_section();
                (raw.first() == Some(&b'0') && raw.get(1) != Some(&b':'))
                    .then_some("leading zero in string length")
            }
            Body::List(items) => items.iter().find_map(Node::has_soft_error),
            Body::Dict(pairs) => {
                for (k, v) in pairs {
                    if let Some(e) = k.has_soft_error().or_else(|| v.has_soft_error()) {
                        return Some(e);
                    }
                }
                pairs.windows(2).find_map(|w| {
                    match w[0].0.string_value().cmp(w[1].0.string_value()) {
                        Ordering::Greater => Some("unsorted dictionary key"),
                        Ordering::Equal => Some("duplicate dictionary key"),
                        Ordering::Less => None,
                    }
                })
            }
        }
    }

    /// Renders the value like libtorrent's `print_entry(e, single_line,
    /// indent)`: `[ 1, 'foo', { 'x': 1 } ]`.
    #[must_use]
    pub fn print(&self, single_line: bool, indent: usize) -> String {
        let mut out = String::new();
        self.print_into(&mut out, single_line, indent);
        out
    }

    fn print_into(&self, out: &mut String, single_line: bool, indent: usize) {
        match &self.body {
            Body::Int(v) => {
                let _ = write!(out, "{v}");
            }
            Body::Str(_) => print_string(out, self.string_value(), single_line),
            Body::List(items) => {
                let one_liner = single_line || self.line_longer_than(200).is_some();
                let layout = Layout::new(one_liner, indent);
                out.push('[');
                if !(one_liner && items.is_empty()) {
                    out.push_str(&layout.open);
                }
                for (i, item) in items.iter().enumerate() {
                    item.print_into(out, single_line, indent + 2);
                    out.push_str(layout.after(i + 1 == items.len()));
                }
                out.push(']');
            }
            Body::Dict(pairs) => {
                let one_liner = single_line || self.line_longer_than(200).is_some();
                let layout = Layout::new(one_liner, indent);
                out.push('{');
                if !(one_liner && pairs.is_empty()) {
                    out.push_str(&layout.open);
                }
                for (i, (k, v)) in pairs.iter().enumerate() {
                    print_string(out, k.string_value(), true);
                    out.push_str(": ");
                    v.print_into(out, single_line, indent + 2);
                    out.push_str(layout.after(i + 1 == pairs.len()));
                }
                out.push('}');
            }
        }
    }

    /// libtorrent `line_longer_than`: the rendered width if it is within
    /// `limit`, else `None`.
    fn line_longer_than(&self, limit: i64) -> Option<i64> {
        let mut len: i64 = 0;
        match &self.body {
            Body::List(items) => {
                len += 4;
                if len > limit {
                    return None;
                }
                for item in items {
                    len += item.line_longer_than(limit - len)? + 2;
                }
            }
            Body::Dict(pairs) => {
                len += 4;
                if len > limit {
                    return None;
                }
                for (k, v) in pairs {
                    len += 4 + i64::try_from(k.string_length()).unwrap_or(i64::MAX);
                    if len > limit {
                        return None;
                    }
                    len += v.line_longer_than(limit - len)? + 1;
                }
            }
            Body::Str(_) => len += 3 + i64::try_from(self.string_length()).unwrap_or(i64::MAX),
            Body::Int(v) => {
                let mut v = *v;
                while v > 0 {
                    len += 1;
                    v /= 10;
                }
                len += 2;
            }
        }
        (len <= limit).then_some(len)
    }
}

/// The separators `print_entry` puts between elements. libtorrent indents
/// every level's separators by the *enclosing* call's `indent`, a quirk kept
/// for byte-identical output.
struct Layout {
    open: String,
    sep: String,
    close: String,
}

impl Layout {
    fn new(one_liner: bool, indent: usize) -> Self {
        if one_liner {
            Self {
                open: " ".to_owned(),
                sep: ", ".to_owned(),
                close: " ".to_owned(),
            }
        } else {
            let nl = format!("\n{}", " ".repeat(indent));
            Self {
                open: nl.clone(),
                sep: format!(",{nl}"),
                close: nl,
            }
        }
    }

    fn after(&self, last: bool) -> &str {
        if last {
            &self.close
        } else {
            &self.sep
        }
    }
}

fn print_string(out: &mut String, s: &[u8], single_line: bool) {
    let printable = s.iter().all(|c| (32..127).contains(c));
    out.push('\'');
    if printable {
        if single_line && s.len() > 30 {
            out.push_str(&String::from_utf8_lossy(&s[..14]));
            out.push_str("...");
            out.push_str(&String::from_utf8_lossy(&s[s.len() - 14..]));
        } else {
            out.push_str(&String::from_utf8_lossy(s));
        }
    } else if single_line && s.len() > 32 {
        escape(out, &s[..25]);
        out.push_str("...");
        escape(out, &s[s.len() - 4..]);
    } else {
        escape(out, s);
    }
    out.push('\'');
}

/// libtorrent `escape_string`: hex if any byte is non-printable.
fn escape(out: &mut String, s: &[u8]) {
    if s.iter().any(|c| !(32..127).contains(c)) {
        for b in s {
            let _ = write!(out, "{b:02x}");
        }
    } else {
        out.push_str(&String::from_utf8_lossy(s));
    }
}
