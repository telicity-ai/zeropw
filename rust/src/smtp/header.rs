//! CPython 3.12.14's `email` header machinery, as `notify._send` drives it:
//! `EmailMessage.__setitem__` (`EmailPolicy.header_store_parse` and the
//! `headerregistry` `UnstructuredHeader`/`AddressHeader` parse), the parse
//! productions of `email._header_value_parser` those headers use, their fold
//! (`_refold_parse_tree`/`_fold_as_ew`, `_encoded_words`), and the envelope
//! `smtplib.send_message` derives from the parsed headers
//! (`email.utils.getaddresses`/`parseaddr` over the legacy `_parseaddr`
//! parser, and `smtplib.quoteaddr`).
//!
//! This is a direct port, production by production, including the parser's
//! error recovery (`InvalidMailbox`, obsolete local parts, routes, groups,
//! unterminated quoted strings, comments and domain literals) and the places
//! where the email package itself lets a built-in exception escape (for
//! example `_check_for_early_dl_end` appending a defect object to a token
//! list, which later raises `AttributeError`).  Text is held as code points
//! ([`Text`]) rather than `String` because `surrogateescape` decoding of an
//! encoded word produces lone surrogates, which Python carries through to the
//! fold (`unknown-8bit` encoded words) and the decoded header value.

mod cjk;
mod cjk_tables;
#[cfg(test)]
mod codec_tests;
mod codecs;
mod unicode_tables;
mod unicodec;

use crate::pystr;

/// A Python `str`: Unicode code points, including lone surrogates.
pub(super) type Text = Vec<u32>;

/// `str` of a Rust string.
pub(super) fn text(s: &str) -> Text {
    s.chars().map(u32::from).collect()
}

/// A Python exception raised inside the email package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ex {
    /// `email.errors.HeaderParseError`.
    Parse,
    /// `_InvalidEwError`, a `HeaderParseError` subclass.
    InvalidEw,
    /// A built-in exception, by `type(exc).__name__`.
    Builtin(&'static str),
}

type R<T> = Result<T, Ex>;

const ATTR: Ex = Ex::Builtin("AttributeError");
const INDEX: Ex = Ex::Builtin("IndexError");
const UNICODE_ENCODE: Ex = Ex::Builtin("UnicodeEncodeError");
/// `RuntimeError("internal codec error")` from a `_multibytecodec` decoder
/// (`MBERR_INTERNAL`), which `get_encoded_word` does not catch.
const RUNTIME: Ex = Ex::Builtin("RuntimeError");

/// Comment nesting at which CPython's recursion limit (1000 frames) stops
/// the header parse (`message[...] = value`: `get_comment` recursion, then
/// two frames per level in `all_defects`) on the administrator CLI's
/// `incident notify-test` path.  The limit counts the caller's own frames,
/// so other call paths stop a level or two earlier or later (PORTING.md
/// §3.5: `RecursionError` is an uncaught built-in).
const BUILD_RECURSION_NESTING: usize = 487;
/// The same limit in `BytesGenerator.flatten` (`str()`, `as_ew_allowed` and
/// `startswith_fws` recurse two frames per level), one level shallower.
const FOLD_RECURSION_NESTING: usize = 486;

const WSP: &str = " \t";
const CFWS_LEADER: &str = " \t(";
const SPECIALS: &str = "()<>@,:;.\\\"[]";
const ATOM_ENDS: &str = "()<>@,:;.\\\"[] \t";
const DOT_ATOM_ENDS: &str = "()<>@,:;\\\"[] \t";
const PHRASE_ENDS: &str = ")<>@,:;\\[]";
const SPECIALSNL: &str = "()<>@,:;.\\\"[]\n\r";
const NLSET: &str = "\n\r";
const HEXDIGITS: &str = "0123456789abcdefABCDEF";
const MAX_LINE_LENGTH: usize = 78;
const LINESEP: &str = "\r\n";

fn has(set: &str, c: u32) -> bool {
    set.chars().any(|s| u32::from(s) == c)
}

fn first_in(value: &[u32], set: &str) -> bool {
    value.first().is_some_and(|c| has(set, *c))
}

fn starts(value: &[u32], prefix: &str) -> bool {
    prefix
        .chars()
        .enumerate()
        .all(|(index, c)| value.get(index) == Some(&u32::from(c)))
}

fn push(out: &mut Text, s: &str) {
    out.extend(s.chars().map(u32::from));
}

fn is_space(c: u32) -> bool {
    char::from_u32(c).is_some_and(pystr::is_space)
}

fn is_surrogate(c: u32) -> bool {
    (0xD800..=0xDFFF).contains(&c)
}

/// `str.lstrip()`.
fn lstrip(value: &[u32]) -> &[u32] {
    let start = value
        .iter()
        .position(|c| !is_space(*c))
        .unwrap_or(value.len());
    &value[start..]
}

/// `str.rstrip()`.
fn rstrip(value: &[u32]) -> &[u32] {
    let end = value
        .iter()
        .rposition(|c| !is_space(*c))
        .map_or(0, |i| i + 1);
    &value[..end]
}

/// `str.split()`: the whitespace-separated pieces.
fn split_ws(value: &[u32]) -> Vec<&[u32]> {
    value
        .split(|c| is_space(*c))
        .filter(|piece| !piece.is_empty())
        .collect()
}

/// `value.find(needle)`.
fn find(value: &[u32], needle: &str) -> Option<usize> {
    let needle = text(needle);
    if needle.is_empty() {
        return Some(0);
    }
    value.windows(needle.len()).position(|w| w == needle)
}

/// `_wsp_splitter(value, 1)`: the text before the first run of WSP, and
/// `''.join(remainder)` (that run and everything after it).
fn wsp_split(value: &[u32]) -> (&[u32], &[u32]) {
    let end = value
        .iter()
        .position(|c| has(WSP, *c))
        .unwrap_or(value.len());
    value.split_at(end)
}

/// `make_quoted_pairs`.
fn make_quoted_pairs(value: &[u32]) -> Text {
    let mut out = Vec::with_capacity(value.len());
    for &c in value {
        if c == u32::from('\\') || c == u32::from('"') {
            out.push(u32::from('\\'));
        }
        out.push(c);
    }
    out
}

/// `make_parenthesis_pairs`.
fn make_parenthesis_pairs(value: &[u32]) -> Text {
    let mut out = Vec::with_capacity(value.len());
    for &c in value {
        if c == u32::from('\\') || c == u32::from('(') || c == u32::from(')') {
            out.push(u32::from('\\'));
        }
        out.push(c);
    }
    out
}

/// `quote_string`.
fn quote_string(value: &[u32]) -> Text {
    let mut out = text("\"");
    out.extend(make_quoted_pairs(value));
    out.push(u32::from('"'));
    out
}

/// `str.encode('utf-8')`; `None` where it raises (a surrogate).
fn encode_utf8(value: &[u32]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len());
    for &c in value {
        let c = char::from_u32(c)?;
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    Some(out)
}

/// `str.encode(<ascii or utf-8>, 'surrogateescape')`; `None` where it raises.
fn encode_surrogateescape(value: &[u32], utf8: bool) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len());
    for &c in value {
        if (0xDC80..=0xDCFF).contains(&c) {
            out.push((c - 0xDC00) as u8);
        } else if c < 0x80 {
            out.push(c as u8);
        } else if utf8 {
            let c = char::from_u32(c)?;
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        } else {
            return None;
        }
    }
    Some(out)
}

/// `utils._has_surrogates`.
fn has_surrogates(value: &[u32]) -> bool {
    value.iter().any(|c| is_surrogate(*c))
}

/// The Rust string of a surrogate-free `str`.
fn to_string(value: &[u32]) -> Option<String> {
    value.iter().map(|c| char::from_u32(*c)).collect()
}

/// `utils._sanitize` (which `BaseHeader.__new__` applies when the decoded
/// value has surrogates): surrogate-escaped bytes back to UTF-8, invalid
/// sequences as U+FFFD.  `string.encode('utf-8', 'surrogateescape')`
/// raises `UnicodeEncodeError` for any other lone surrogate, which an
/// encoded word in a charset such as `unicode_escape`, `utf-7` or
/// `punycode` can decode to.
fn sanitize(value: &[u32]) -> R<String> {
    let mut bytes = Vec::with_capacity(value.len());
    for &c in value {
        if (0xDC80..=0xDCFF).contains(&c) {
            bytes.push((c - 0xDC00) as u8);
        } else {
            let c = char::from_u32(c).ok_or(UNICODE_ENCODE)?;
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// ------------------------------------------------------------- the tokens

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Defect {
    /// `InvalidHeaderDefect` (or a subclass).
    Invalid,
    /// `UndecodableBytesDefect`.
    Undecodable,
    /// Any other defect.
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TermKind {
    /// `ValueTerminal`.
    Value,
    /// `WhiteSpaceTerminal`.
    Space,
    /// `EWWhiteSpaceTerminal`: `str()` is empty.
    EwSpace,
}

/// The `TokenList` subclass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    TokenList,
    Unstructured,
    Phrase,
    Cfws,
    Atom,
    EncodedWord,
    QuotedString,
    BareQuotedString,
    Comment,
    AddressList,
    Address,
    MailboxList,
    GroupList,
    Group,
    NameAddr,
    AngleAddr,
    ObsRoute,
    Mailbox,
    InvalidMailbox,
    Domain,
    DotAtom,
    DotAtomText,
    AddrSpec,
    ObsLocalPart,
    DisplayName,
    LocalPart,
    DomainLiteral,
    Header,
    HeaderLabel,
}

impl Class {
    fn token_type(self) -> Option<&'static str> {
        Some(match self {
            Class::TokenList => return None,
            Class::Unstructured => "unstructured",
            Class::Phrase => "phrase",
            Class::Cfws => "cfws",
            Class::Atom => "atom",
            Class::EncodedWord => "encoded-word",
            Class::QuotedString => "quoted-string",
            Class::BareQuotedString => "bare-quoted-string",
            Class::Comment => "comment",
            Class::AddressList => "address-list",
            Class::Address => "address",
            Class::MailboxList => "mailbox-list",
            Class::GroupList => "group-list",
            Class::Group => "group",
            Class::NameAddr => "name-addr",
            Class::AngleAddr => "angle-addr",
            Class::ObsRoute => "obs-route",
            Class::Mailbox => "mailbox",
            Class::InvalidMailbox => "invalid-mailbox",
            Class::Domain => "domain",
            Class::DotAtom => "dot-atom",
            Class::DotAtomText => "dot-atom-text",
            Class::AddrSpec => "addr-spec",
            Class::ObsLocalPart => "obs-local-part",
            Class::DisplayName => "display-name",
            Class::LocalPart => "local-part",
            Class::DomainLiteral => "domain-literal",
            Class::Header => "header",
            Class::HeaderLabel => "header-label",
        })
    }
}

#[derive(Clone, Debug)]
struct Term {
    text: Text,
    token_type: &'static str,
    kind: TermKind,
    defects: Vec<Defect>,
    /// `ListSeparator` (`as_ew_allowed = syntactic_break = False`).
    separator: bool,
}

#[derive(Clone, Debug)]
struct List {
    class: Class,
    /// An instance `token_type` assignment (`'invalid-mailbox'`,
    /// `'invalid-obs-local-part'`).
    token_type: Option<&'static str>,
    parts: Vec<Node>,
    defects: Vec<Defect>,
}

#[derive(Clone, Debug)]
enum Node {
    Term(Term),
    List(List),
    /// The `InvalidHeaderDefect` object `_check_for_early_dl_end` appends to a
    /// domain literal's token list: `str()` gives its message, and every
    /// token attribute raises `AttributeError`.
    Stray,
}

const STRAY_MESSAGE: &str = "end of input inside domain-literal";

fn term(text: Text, token_type: &'static str, kind: TermKind) -> Node {
    Node::Term(Term {
        text,
        token_type,
        kind,
        defects: Vec::new(),
        separator: false,
    })
}

/// `ValueTerminal(text, token_type)`.
fn vt(value: &[u32], token_type: &'static str) -> Node {
    term(value.to_vec(), token_type, TermKind::Value)
}

fn vts(value: &str, token_type: &'static str) -> Node {
    term(text(value), token_type, TermKind::Value)
}

/// `WhiteSpaceTerminal(text, token_type)`.
fn wst(value: &[u32], token_type: &'static str) -> Node {
    term(value.to_vec(), token_type, TermKind::Space)
}

/// `DOT`.
fn dot() -> Node {
    vts(".", "dot")
}

/// `ListSeparator`.
fn list_separator() -> Node {
    Node::Term(Term {
        text: text(","),
        token_type: "list-separator",
        kind: TermKind::Value,
        defects: Vec::new(),
        separator: true,
    })
}

fn new_list(class: Class) -> List {
    List {
        class,
        token_type: None,
        parts: Vec::new(),
        defects: Vec::new(),
    }
}

fn list_of(class: Class, parts: Vec<Node>) -> Node {
    Node::List(List {
        class,
        token_type: None,
        parts,
        defects: Vec::new(),
    })
}

impl Node {
    fn token_type(&self) -> R<Option<&'static str>> {
        match self {
            Node::Term(t) => Ok(Some(t.token_type)),
            Node::List(l) => Ok(l.token_type.or_else(|| l.class.token_type())),
            Node::Stray => Err(ATTR),
        }
    }

    fn is(&self, name: &str) -> R<bool> {
        Ok(self.token_type()? == Some(name))
    }

    fn as_list(&self) -> Option<&List> {
        match self {
            Node::List(l) => Some(l),
            _ => None,
        }
    }

    fn parts(&self) -> &[Node] {
        self.as_list().map_or(&[], |l| &l.parts)
    }

    /// `token[:0] = [leader]` on a token list.
    fn prepend(&mut self, leader: Node) {
        if let Node::List(l) = self {
            l.parts.insert(0, leader);
        }
    }

    /// `str(token)`.
    fn str_into(&self, out: &mut Text) {
        match self {
            Node::Term(t) => {
                if t.kind != TermKind::EwSpace {
                    out.extend_from_slice(&t.text);
                }
            }
            Node::Stray => push(out, STRAY_MESSAGE),
            Node::List(l) => match l.class {
                Class::BareQuotedString => {
                    let mut inner = Vec::new();
                    for part in &l.parts {
                        part.str_into(&mut inner);
                    }
                    out.extend(quote_string(&inner));
                }
                Class::Comment => {
                    out.push(u32::from('('));
                    for part in &l.parts {
                        let s = part.to_str();
                        if matches!(part.token_type(), Ok(Some("comment"))) {
                            out.extend(s);
                        } else {
                            out.extend(make_parenthesis_pairs(&s));
                        }
                    }
                    out.push(u32::from(')'));
                }
                _ => {
                    for part in &l.parts {
                        part.str_into(out);
                    }
                }
            },
        }
    }

    fn to_str(&self) -> Text {
        let mut out = Vec::new();
        self.str_into(&mut out);
        out
    }

    /// `token.value`.
    fn value(&self) -> R<Text> {
        match self {
            Node::Term(t) => Ok(match t.kind {
                TermKind::Value => t.text.clone(),
                TermKind::Space => text(" "),
                TermKind::EwSpace => Vec::new(),
            }),
            Node::Stray => Err(ATTR),
            Node::List(l) => match l.class {
                Class::Cfws | Class::Comment => Ok(text(" ")),
                Class::BareQuotedString => {
                    let mut out = Vec::new();
                    for part in &l.parts {
                        part.str_into(&mut out);
                    }
                    Ok(out)
                }
                Class::AddrSpec => {
                    let p0 = l.parts.first().ok_or(INDEX)?;
                    if l.parts.len() < 3 {
                        return p0.value();
                    }
                    let mut out = rstrip(&p0.value()?).to_vec();
                    out.extend(l.parts[1].value()?);
                    out.extend_from_slice(lstrip(&l.parts[2].value()?));
                    Ok(out)
                }
                Class::DisplayName => display_name_value(l),
                Class::LocalPart => {
                    let p0 = l.parts.first().ok_or(INDEX)?;
                    if p0.is("quoted-string")? {
                        quoted_value(p0)
                    } else {
                        p0.value()
                    }
                }
                _ => list_value(&l.parts),
            },
        }
    }

    /// `token.all_defects`.
    fn all_defects(&self, out: &mut Vec<Defect>) -> R<()> {
        match self {
            Node::Term(t) => {
                out.extend_from_slice(&t.defects);
                Ok(())
            }
            Node::Stray => Err(ATTR),
            Node::List(l) => {
                out.extend_from_slice(&l.defects);
                for part in &l.parts {
                    part.all_defects(out)?;
                }
                Ok(())
            }
        }
    }

    fn any_defect(&self, wanted: Defect) -> R<bool> {
        let mut defects = Vec::new();
        self.all_defects(&mut defects)?;
        Ok(defects.contains(&wanted))
    }

    /// `token.startswith_fws()`.
    fn startswith_fws(&self) -> R<bool> {
        match self {
            Node::Term(t) => Ok(t.kind != TermKind::Value && first_in(&t.text, WSP)),
            Node::Stray => Err(ATTR),
            Node::List(l) => l.parts.first().ok_or(INDEX)?.startswith_fws(),
        }
    }

    /// `token.as_ew_allowed`.
    fn as_ew_allowed(&self) -> R<bool> {
        match self {
            Node::Term(t) => Ok(!t.separator),
            Node::Stray => Err(ATTR),
            Node::List(l) => match l.class {
                Class::Domain
                | Class::AddrSpec
                | Class::ObsLocalPart
                | Class::LocalPart
                | Class::DomainLiteral
                | Class::HeaderLabel => Ok(false),
                Class::DotAtomText => Ok(true),
                _ => {
                    for part in &l.parts {
                        if !part.as_ew_allowed()? {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
            },
        }
    }

    /// `token.syntactic_break`.
    fn syntactic_break(&self) -> R<bool> {
        match self {
            Node::Term(t) => Ok(!t.separator),
            Node::List(_) => Ok(true),
            Node::Stray => Err(ATTR),
        }
    }

    /// `token.ew_combine_allowed`.
    fn ew_combine_allowed(&self) -> R<bool> {
        match self {
            Node::Term(_) => Ok(true),
            Node::List(l) => Ok(l.class != Class::DisplayName),
            Node::Stray => Err(ATTR),
        }
    }
}

/// `TokenList.value`.
fn list_value(parts: &[Node]) -> R<Text> {
    let mut out = Vec::new();
    for part in parts {
        out.extend(part.value()?);
    }
    Ok(out)
}

/// `QuotedString.quoted_value`.
fn quoted_value(node: &Node) -> R<Text> {
    let mut out = Vec::new();
    for part in node.parts() {
        if part.is("bare-quoted-string")? {
            part.str_into(&mut out);
        } else {
            out.extend(part.value()?);
        }
    }
    Ok(out)
}

/// `isinstance(token, TokenList) and token[0].token_type == 'cfws'`
/// (`token[-1]` with `last`).
fn list_edge_is_cfws(node: &Node, last: bool) -> R<bool> {
    let Node::List(l) = node else {
        return Ok(false);
    };
    let edge = if last {
        l.parts.last()
    } else {
        l.parts.first()
    };
    edge.ok_or(INDEX)?.is("cfws")
}

/// `DisplayName.value`.
fn display_name_value(l: &List) -> R<Text> {
    let mut quote = !l.defects.is_empty();
    if !quote {
        for part in &l.parts {
            if part.is("quoted-string")? {
                quote = true;
            }
        }
    }
    if !l.parts.is_empty() && quote {
        let first = &l.parts[0];
        let last = &l.parts[l.parts.len() - 1];
        let pre = first.is("cfws")? || list_edge_is_cfws(first, false)?;
        let post = last.is("cfws")? || list_edge_is_cfws(last, true)?;
        let mut out = Vec::new();
        if pre {
            out.push(u32::from(' '));
        }
        out.extend(quote_string(&display_name(l)?));
        if post {
            out.push(u32::from(' '));
        }
        return Ok(out);
    }
    list_value(&l.parts)
}

/// `DisplayName.display_name`.
fn display_name(l: &List) -> R<Text> {
    let mut res: Vec<Node> = l.parts.clone();
    if res.is_empty() {
        return Ok(Vec::new());
    }
    if res[0].is("cfws")? {
        res.remove(0);
    } else if list_edge_is_cfws(&res[0], false)? {
        let rest = res[0].parts()[1..].to_vec();
        res[0] = list_of(Class::TokenList, rest);
    }
    let last = res.last().ok_or(INDEX)?;
    if last.is("cfws")? {
        res.pop();
    } else if list_edge_is_cfws(last, true)? {
        let parts = last.parts();
        let rest = parts[..parts.len() - 1].to_vec();
        let index = res.len() - 1;
        res[index] = list_of(Class::TokenList, rest);
    }
    list_value(&res)
}

/// `LocalPart.local_part`: whitespace stripped from the ends and around dots.
fn local_part(l: &List) -> R<Text> {
    let p0 = l.parts.first().ok_or(INDEX)?;
    let mut tokens: Vec<Node> = p0.parts().to_vec();
    tokens.push(dot());
    let mut res: Vec<Node> = vec![dot()];
    let mut last_is_tl = false;
    for tok in tokens {
        if tok.is("cfws")? {
            continue;
        }
        let last = res.last().ok_or(INDEX)?;
        if last_is_tl && tok.is("dot")? && last.parts().last().ok_or(INDEX)?.is("cfws")? {
            let parts = last.parts();
            let rest = parts[..parts.len() - 1].to_vec();
            let index = res.len() - 1;
            res[index] = list_of(Class::TokenList, rest);
        }
        let last = res.last().ok_or(INDEX)?;
        let is_tl = tok.as_list().is_some();
        if is_tl && last.is("dot")? && tok.parts().first().ok_or(INDEX)?.is("cfws")? {
            let rest = tok.parts()[1..].to_vec();
            res.push(list_of(Class::TokenList, rest));
        } else {
            res.push(tok);
        }
        last_is_tl = is_tl;
    }
    let inner = &res[1..res.len() - 1];
    list_value(inner)
}

/// `Domain.domain` / `DomainLiteral.domain`: the value without whitespace.
fn domain_text(l: &List) -> R<Text> {
    let value = list_value(&l.parts)?;
    Ok(split_ws(&value).concat())
}

// --------------------------------------------------------- mailbox access

fn index_first(node: &Node) -> R<&Node> {
    node.parts().first().ok_or(INDEX)
}

fn index_last(node: &Node) -> R<&Node> {
    node.parts().last().ok_or(INDEX)
}

/// `.display_name` of a mailbox-like token.
fn prop_display_name(node: &Node) -> R<Option<Text>> {
    let Node::List(l) = node else {
        return Err(ATTR);
    };
    match l.class {
        Class::Mailbox => {
            let p0 = index_first(node)?;
            if p0.is("name-addr")? {
                prop_display_name(p0)
            } else {
                Ok(None)
            }
        }
        Class::NameAddr => {
            if l.parts.len() == 1 {
                Ok(None)
            } else {
                prop_display_name(index_first(node)?)
            }
        }
        Class::Group => prop_display_name(index_first(node)?),
        Class::Address => {
            let p0 = index_first(node)?;
            if p0.is("group")? {
                prop_display_name(p0)
            } else {
                Ok(None)
            }
        }
        Class::DisplayName => Ok(Some(display_name(l)?)),
        Class::InvalidMailbox => Ok(None),
        _ => Err(ATTR),
    }
}

/// `.local_part` of a mailbox-like token.
fn prop_local_part(node: &Node) -> R<Option<Text>> {
    let Node::List(l) = node else {
        return Err(ATTR);
    };
    match l.class {
        Class::Mailbox | Class::AddrSpec => prop_local_part(index_first(node)?),
        Class::NameAddr => prop_local_part(index_last(node)?),
        Class::AngleAddr => {
            for part in &l.parts {
                if part.is("addr-spec")? {
                    return prop_local_part(part);
                }
            }
            Ok(None)
        }
        Class::LocalPart => Ok(Some(local_part(l)?)),
        Class::InvalidMailbox => Ok(None),
        _ => Err(ATTR),
    }
}

/// `.domain` of a mailbox-like token.
fn prop_domain(node: &Node) -> R<Option<Text>> {
    let Node::List(l) = node else {
        return Err(ATTR);
    };
    match l.class {
        Class::Mailbox => prop_domain(index_first(node)?),
        Class::NameAddr => prop_domain(index_last(node)?),
        Class::AngleAddr => {
            for part in &l.parts {
                if part.is("addr-spec")? {
                    return prop_domain(part);
                }
            }
            Ok(None)
        }
        Class::AddrSpec => {
            if l.parts.len() < 3 {
                Ok(None)
            } else {
                prop_domain(index_last(node)?)
            }
        }
        Class::Domain | Class::DomainLiteral => Ok(Some(domain_text(l)?)),
        Class::InvalidMailbox => Ok(None),
        _ => Err(ATTR),
    }
}

/// `.all_mailboxes` of an address-like token.
fn all_mailboxes(node: &Node) -> R<Vec<&Node>> {
    let Node::List(l) = node else {
        return Err(ATTR);
    };
    match l.class {
        Class::Address => {
            let p0 = index_first(node)?;
            if p0.is("mailbox")? || p0.is("invalid-mailbox")? {
                Ok(vec![p0])
            } else {
                all_mailboxes(p0)
            }
        }
        Class::Group => {
            let p2 = l.parts.get(2).ok_or(INDEX)?;
            if !p2.is("group-list")? {
                return Ok(Vec::new());
            }
            all_mailboxes(p2)
        }
        Class::GroupList => match l.parts.first() {
            Some(p0) if p0.is("mailbox-list")? => all_mailboxes(p0),
            _ => Ok(Vec::new()),
        },
        Class::MailboxList => {
            let mut out = Vec::new();
            for part in &l.parts {
                if part.is("mailbox")? || part.is("invalid-mailbox")? {
                    out.push(part);
                }
            }
            Ok(out)
        }
        Class::AddressList => {
            let mut out = Vec::new();
            for part in &l.parts {
                if part.is("address")? {
                    out.extend(all_mailboxes(part)?);
                }
            }
            Ok(out)
        }
        _ => Err(ATTR),
    }
}

// ------------------------------------------------------------- the parser

/// The unparsed rest of a header value.  Productions return a suffix of their
/// input, except `get_local_part`'s obsolete-syntax path, which re-parses
/// `str(local_part) + value` and returns a suffix of that new string.
#[derive(Clone)]
struct S {
    buf: std::rc::Rc<[u32]>,
    start: usize,
}

impl std::ops::Deref for S {
    type Target = [u32];
    fn deref(&self) -> &[u32] {
        self.buf.get(self.start..).unwrap_or_default()
    }
}

impl S {
    fn new(value: &[u32]) -> S {
        S {
            buf: value.into(),
            start: 0,
        }
    }

    /// `value[n:]`.
    fn skip(&self, n: usize) -> S {
        S {
            buf: self.buf.clone(),
            start: (self.start + n).min(self.buf.len()),
        }
    }

    /// The suffix of this value that is `rest_len` long.
    fn suffix(&self, rest_len: usize) -> S {
        self.skip(self.len().saturating_sub(rest_len))
    }
}

fn validate_xtext(node: &mut Node) {
    if let Node::Term(t) = node {
        if t.text.iter().any(|c| *c <= 0x20 || *c == 0x7F) {
            t.defects.push(Defect::Other);
        }
        if has_surrogates(&t.text) {
            t.defects.push(Defect::Undecodable);
        }
    }
}

type P = R<(Node, S)>;

/// `_get_ptext_to_endchars(value, endchars)`.
fn get_ptext_to_endchars(value: &S, endchars: &str) -> R<(Text, S, bool)> {
    let (fragment, _) = wsp_split(value);
    if fragment.is_empty() {
        // The `for ... else` reads `pos` without the loop ever binding it.
        return Err(Ex::Builtin("UnboundLocalError"));
    }
    let mut vchars = Vec::new();
    let mut escape = false;
    let mut had_qp = false;
    let mut stop = fragment.len();
    for (pos, &c) in fragment.iter().enumerate() {
        if c == u32::from('\\') {
            if escape {
                escape = false;
                had_qp = true;
            } else {
                escape = true;
                continue;
            }
        }
        if escape {
            escape = false;
        } else if has(endchars, c) {
            stop = pos;
            break;
        }
        vchars.push(c);
    }
    Ok((vchars, value.skip(stop), had_qp))
}

/// `get_fws`.
fn get_fws(value: &S) -> (Node, S) {
    let rest = lstrip(value).len();
    let consumed = value.len() - rest;
    (wst(&value[..consumed], "fws"), value.skip(consumed))
}

/// `get_encoded_word(value, terminal_type)`.
fn get_encoded_word(value: &S, terminal_type: &'static str) -> P {
    let mut ew = new_list(Class::EncodedWord);
    if !starts(value, "=?") {
        return Err(Ex::Parse);
    }
    let body = value.skip(2);
    let Some(end) = find(&body, "?=") else {
        return Err(Ex::Parse);
    };
    let mut tok: Text = body[..end].to_vec();
    let mut remainder = body.skip(end + 2);
    if remainder.len() > 1
        && has(HEXDIGITS, remainder[0])
        && has(HEXDIGITS, remainder[1])
        && tok.iter().filter(|c| **c == u32::from('?')).count() < 2
    {
        let (rest, after) = match find(&remainder, "?=") {
            Some(i) => (remainder[..i].to_vec(), remainder.skip(i + 2)),
            None => (remainder.to_vec(), remainder.skip(remainder.len())),
        };
        push(&mut tok, "?=");
        tok.extend(rest);
        remainder = after;
    }
    if split_ws(&tok).len() > 1 {
        ew.defects.push(Defect::Invalid);
    }
    let value = remainder;
    let (decoded, defects) = ew_decode(&tok)?;
    ew.defects.extend(defects);
    let mut rest = S::new(&decoded);
    while !rest.is_empty() {
        if first_in(&rest, WSP) {
            let (token, after) = get_fws(&rest);
            ew.parts.push(token);
            rest = after;
            continue;
        }
        let (chars, after) = wsp_split(&rest);
        let mut vtext = vt(chars, terminal_type);
        validate_xtext(&mut vtext);
        ew.parts.push(vtext);
        rest = rest.suffix(after.len());
    }
    if !value.is_empty() && !first_in(&value, WSP) {
        ew.defects.push(Defect::Invalid);
    }
    Ok((Node::List(ew), value))
}

/// `rfc2047_matcher.search(value)`:
/// `=\?[^?]*\?[qQbB]\?.*?\?=` (`.` does not match a newline).
fn rfc2047_search(value: &[u32]) -> bool {
    let q = u32::from('?');
    for start in 0..value.len() {
        if !starts(&value[start..], "=?") {
            continue;
        }
        let Some(offset) = value[start + 2..].iter().position(|c| *c == q) else {
            continue;
        };
        let cte = start + 2 + offset + 1;
        if !value.get(cte).is_some_and(|c| has("qQbB", *c)) || value.get(cte + 1) != Some(&q) {
            continue;
        }
        for index in cte + 2..value.len() {
            if starts(&value[index..], "?=") {
                return true;
            }
            if value[index] == u32::from('\n') {
                break;
            }
        }
    }
    false
}

/// `get_unstructured(value)`.
fn get_unstructured(value: &[u32]) -> R<Node> {
    let mut value = S::new(value);
    let mut unstructured = new_list(Class::Unstructured);
    while !value.is_empty() {
        if first_in(&value, WSP) {
            let (token, rest) = get_fws(&value);
            unstructured.parts.push(token);
            value = rest;
            continue;
        }
        let mut valid_ew = true;
        if starts(&value, "=?") {
            match get_encoded_word(&value, "utext") {
                Ok((token, rest)) => {
                    let mut have_ws = true;
                    if let Some(last) = unstructured.parts.last()
                        && !last.is("fws")?
                    {
                        unstructured.defects.push(Defect::Invalid);
                        have_ws = false;
                    }
                    let len = unstructured.parts.len();
                    if have_ws
                        && len > 1
                        && unstructured.parts[len - 2].is("encoded-word")?
                        && let Node::Term(t) = &mut unstructured.parts[len - 1]
                    {
                        t.kind = TermKind::EwSpace;
                    }
                    unstructured.parts.push(token);
                    value = rest;
                    continue;
                }
                Err(Ex::InvalidEw) => valid_ew = false,
                Err(Ex::Parse) => {}
                Err(error) => return Err(error),
            }
        }
        let (mut tok, rest) = wsp_split(&value);
        let mut rest_len = rest.len();
        if valid_ew && rfc2047_search(tok) {
            let at = find(&value, "=?").unwrap_or(value.len());
            tok = &value[..at];
            rest_len = value.len() - at;
            if tok.is_empty() {
                // Unreachable in CPython (the word was a valid or an invalid
                // encoded word, never neither): no progress would be made.
                return Err(Ex::Parse);
            }
        }
        let mut vtext = vt(tok, "utext");
        validate_xtext(&mut vtext);
        unstructured.parts.push(vtext);
        value = value.suffix(rest_len);
    }
    Ok(Node::List(unstructured))
}

/// `get_qp_ctext`.
fn get_qp_ctext(value: &S) -> P {
    let (ptext, rest, _) = get_ptext_to_endchars(value, "()")?;
    let mut token = wst(&ptext, "ptext");
    validate_xtext(&mut token);
    Ok((token, rest))
}

/// `get_qcontent`.
fn get_qcontent(value: &S) -> P {
    let (ptext, rest, _) = get_ptext_to_endchars(value, "\"")?;
    let mut token = vt(&ptext, "ptext");
    validate_xtext(&mut token);
    Ok((token, rest))
}

/// `get_atext`.
fn get_atext(value: &S) -> P {
    let end = value
        .iter()
        .position(|c| has(ATOM_ENDS, *c))
        .unwrap_or(value.len());
    if end == 0 {
        return Err(Ex::Parse);
    }
    let mut atext = vt(&value[..end], "atext");
    validate_xtext(&mut atext);
    Ok((atext, value.skip(end)))
}

/// `get_bare_quoted_string`.
fn get_bare_quoted_string(value: &S) -> P {
    if value.first() != Some(&u32::from('"')) {
        return Err(Ex::Parse);
    }
    let mut bqs = new_list(Class::BareQuotedString);
    let mut value = value.skip(1);
    if value.first() == Some(&u32::from('"')) {
        let (token, rest) = get_qcontent(&value)?;
        bqs.parts.push(token);
        value = rest;
    }
    while value.first().is_some_and(|c| *c != u32::from('"')) {
        let (token, rest) = if first_in(&value, WSP) {
            get_fws(&value)
        } else if starts(&value, "=?") {
            let mut valid_ew = false;
            let parsed = match get_encoded_word(&value, "vtext") {
                Ok(parsed) => {
                    bqs.defects.push(Defect::Invalid);
                    valid_ew = true;
                    parsed
                }
                Err(Ex::Parse | Ex::InvalidEw) => get_qcontent(&value)?,
                Err(error) => return Err(error),
            };
            let len = bqs.parts.len();
            if valid_ew
                && len > 1
                && bqs.parts[len - 1].is("fws")?
                && bqs.parts[len - 2].is("encoded-word")?
                && let Node::Term(t) = &mut bqs.parts[len - 1]
            {
                t.kind = TermKind::EwSpace;
            }
            parsed
        } else {
            get_qcontent(&value)?
        };
        bqs.parts.push(token);
        value = rest;
    }
    if value.is_empty() {
        bqs.defects.push(Defect::Invalid);
        return Ok((Node::List(bqs), value));
    }
    Ok((Node::List(bqs), value.skip(1)))
}

/// `get_comment`.
fn get_comment(value: &S, depth: usize) -> P {
    if depth + 1 >= BUILD_RECURSION_NESTING {
        return Err(Ex::Builtin("RecursionError"));
    }
    if value.first().is_some_and(|c| *c != u32::from('(')) {
        return Err(Ex::Parse);
    }
    let mut comment = new_list(Class::Comment);
    let mut value = value.skip(1);
    while value.first().is_some_and(|c| *c != u32::from(')')) {
        let (token, rest) = if first_in(&value, WSP) {
            get_fws(&value)
        } else if value.first() == Some(&u32::from('(')) {
            get_comment(&value, depth + 1)?
        } else {
            get_qp_ctext(&value)?
        };
        comment.parts.push(token);
        value = rest;
    }
    if value.is_empty() {
        comment.defects.push(Defect::Invalid);
        return Ok((Node::List(comment), value));
    }
    Ok((Node::List(comment), value.skip(1)))
}

/// `get_cfws`.
fn get_cfws(value: &S) -> P {
    let mut value = value.clone();
    let mut cfws = new_list(Class::Cfws);
    while first_in(&value, CFWS_LEADER) {
        let (token, rest) = if first_in(&value, WSP) {
            get_fws(&value)
        } else {
            get_comment(&value, 0)?
        };
        cfws.parts.push(token);
        value = rest;
    }
    Ok((Node::List(cfws), value))
}

/// `get_quoted_string`.
fn get_quoted_string(value: &S) -> P {
    let mut value = value.clone();
    let mut qs = new_list(Class::QuotedString);
    if first_in(&value, CFWS_LEADER) {
        let (token, rest) = get_cfws(&value)?;
        qs.parts.push(token);
        value = rest;
    }
    let (token, rest) = get_bare_quoted_string(&value)?;
    qs.parts.push(token);
    value = rest;
    if first_in(&value, CFWS_LEADER) {
        let (token, rest) = get_cfws(&value)?;
        qs.parts.push(token);
        value = rest;
    }
    Ok((Node::List(qs), value))
}

/// `get_atom`.
fn get_atom(value: &S) -> P {
    let mut value = value.clone();
    let mut atom = new_list(Class::Atom);
    if first_in(&value, CFWS_LEADER) {
        let (token, rest) = get_cfws(&value)?;
        atom.parts.push(token);
        value = rest;
    }
    if first_in(&value, ATOM_ENDS) {
        return Err(Ex::Parse);
    }
    let (token, rest) = if starts(&value, "=?") {
        match get_encoded_word(&value, "vtext") {
            Ok(parsed) => parsed,
            Err(Ex::Parse | Ex::InvalidEw) => get_atext(&value)?,
            Err(error) => return Err(error),
        }
    } else {
        get_atext(&value)?
    };
    atom.parts.push(token);
    value = rest;
    if first_in(&value, CFWS_LEADER) {
        let (token, rest) = get_cfws(&value)?;
        atom.parts.push(token);
        value = rest;
    }
    Ok((Node::List(atom), value))
}

/// `get_dot_atom_text`.
fn get_dot_atom_text(value: &S) -> P {
    let mut value = value.clone();
    let mut dat = new_list(Class::DotAtomText);
    if value.is_empty() || first_in(&value, ATOM_ENDS) {
        return Err(Ex::Parse);
    }
    while !value.is_empty() && !first_in(&value, ATOM_ENDS) {
        let (token, rest) = get_atext(&value)?;
        dat.parts.push(token);
        value = rest;
        if value.first() == Some(&u32::from('.')) {
            dat.parts.push(dot());
            value = value.skip(1);
        }
    }
    if dat.parts.last().ok_or(INDEX)?.is("dot")? {
        return Err(Ex::Parse);
    }
    Ok((Node::List(dat), value))
}

/// `get_dot_atom`.
fn get_dot_atom(value: &S) -> P {
    let mut value = value.clone();
    let mut da = new_list(Class::DotAtom);
    if has(CFWS_LEADER, *value.first().ok_or(INDEX)?) {
        let (token, rest) = get_cfws(&value)?;
        da.parts.push(token);
        value = rest;
    }
    let (token, rest) = if starts(&value, "=?") {
        match get_encoded_word(&value, "vtext") {
            Ok(parsed) => parsed,
            Err(Ex::Parse | Ex::InvalidEw) => get_dot_atom_text(&value)?,
            Err(error) => return Err(error),
        }
    } else {
        get_dot_atom_text(&value)?
    };
    da.parts.push(token);
    value = rest;
    if first_in(&value, CFWS_LEADER) {
        let (token, rest) = get_cfws(&value)?;
        da.parts.push(token);
        value = rest;
    }
    Ok((Node::List(da), value))
}

/// `get_word`.
fn get_word(value: &S) -> P {
    let mut value = value.clone();
    let mut leader = None;
    if has(CFWS_LEADER, *value.first().ok_or(INDEX)?) {
        let (token, rest) = get_cfws(&value)?;
        leader = Some(token);
        value = rest;
    }
    let Some(&c) = value.first() else {
        return Err(Ex::Parse);
    };
    let (mut token, rest) = if c == u32::from('"') {
        get_quoted_string(&value)?
    } else if has(SPECIALS, c) {
        return Err(Ex::Parse);
    } else {
        get_atom(&value)?
    };
    if let Some(leader) = leader {
        token.prepend(leader);
    }
    Ok((token, rest))
}

/// `get_phrase`.
fn get_phrase(value: &S) -> R<(List, S)> {
    let mut value = value.clone();
    let mut phrase = new_list(Class::Phrase);
    match get_word(&value) {
        Ok((token, rest)) => {
            phrase.parts.push(token);
            value = rest;
        }
        Err(Ex::Parse | Ex::InvalidEw) => phrase.defects.push(Defect::Invalid),
        Err(error) => return Err(error),
    }
    while !value.is_empty() && !first_in(&value, PHRASE_ENDS) {
        if value[0] == u32::from('.') {
            phrase.parts.push(dot());
            phrase.defects.push(Defect::Other);
            value = value.skip(1);
            continue;
        }
        let (token, rest) = match get_word(&value) {
            Ok(parsed) => parsed,
            Err(Ex::Parse | Ex::InvalidEw) if first_in(&value, CFWS_LEADER) => {
                let parsed = get_cfws(&value)?;
                phrase.defects.push(Defect::Other);
                parsed
            }
            Err(error) => return Err(error),
        };
        phrase.parts.push(token);
        value = rest;
    }
    Ok((phrase, value))
}

/// `get_local_part`.
fn get_local_part(value: &S) -> P {
    let mut value = value.clone();
    let mut lp = new_list(Class::LocalPart);
    let mut leader = None;
    if first_in(&value, CFWS_LEADER) {
        let (token, rest) = get_cfws(&value)?;
        leader = Some(token);
        value = rest;
    }
    if value.is_empty() {
        return Err(Ex::Parse);
    }
    let (mut token, rest) = match get_dot_atom(&value) {
        Ok(parsed) => parsed,
        Err(Ex::Parse | Ex::InvalidEw) => match get_word(&value) {
            Ok(parsed) => parsed,
            Err(error @ (Ex::Parse | Ex::InvalidEw)) => {
                let c = value[0];
                if c != u32::from('\\') && has(PHRASE_ENDS, c) {
                    return Err(error);
                }
                (list_of(Class::TokenList, Vec::new()), value.clone())
            }
            Err(error) => return Err(error),
        },
        Err(error) => return Err(error),
    };
    value = rest;
    if let Some(leader) = leader {
        token.prepend(leader);
    }
    lp.parts.push(token);
    if let Some(&c) = value.first()
        && (c == u32::from('\\') || !has(PHRASE_ENDS, c))
    {
        let mut obs_input = Node::List(lp.clone()).to_str();
        obs_input.extend_from_slice(&value);
        let (obs, rest) = get_obs_local_part(&S::new(&obs_input))?;
        if obs.is("invalid-obs-local-part")? {
            lp.defects.push(Defect::Invalid);
        } else {
            lp.defects.push(Defect::Other);
        }
        lp.parts[0] = obs;
        value = rest;
    }
    Ok((Node::List(lp), value))
}

/// `get_obs_local_part`.
fn get_obs_local_part(value: &S) -> P {
    let mut value = value.clone();
    let mut obs = new_list(Class::ObsLocalPart);
    let mut last_non_ws_was_dot = false;
    while let Some(&c) = value.first() {
        if !(c == u32::from('\\') || !has(PHRASE_ENDS, c)) {
            break;
        }
        if c == u32::from('.') {
            if last_non_ws_was_dot {
                obs.defects.push(Defect::Invalid);
            }
            obs.parts.push(dot());
            last_non_ws_was_dot = true;
            value = value.skip(1);
            continue;
        } else if c == u32::from('\\') {
            obs.parts.push(vt(&value[..1], "misplaced-special"));
            value = value.skip(1);
            obs.defects.push(Defect::Invalid);
            last_non_ws_was_dot = false;
            continue;
        }
        if let Some(last) = obs.parts.last()
            && !last.is("dot")?
        {
            obs.defects.push(Defect::Invalid);
        }
        let (token, rest) = match get_word(&value) {
            Ok(parsed) => {
                last_non_ws_was_dot = false;
                parsed
            }
            Err(Ex::Parse | Ex::InvalidEw) if first_in(&value, CFWS_LEADER) => get_cfws(&value)?,
            Err(error) => return Err(error),
        };
        obs.parts.push(token);
        value = rest;
    }
    if obs.parts.is_empty() {
        return Err(Ex::Parse);
    }
    let n = obs.parts.len();
    if obs.parts[0].is("dot")? || (obs.parts[0].is("cfws")? && n > 1 && obs.parts[1].is("dot")?) {
        obs.defects.push(Defect::Invalid);
    }
    if obs.parts[n - 1].is("dot")?
        || (obs.parts[n - 1].is("cfws")? && n > 1 && obs.parts[n - 2].is("dot")?)
    {
        obs.defects.push(Defect::Invalid);
    }
    if !obs.defects.is_empty() {
        obs.token_type = Some("invalid-obs-local-part");
    }
    Ok((Node::List(obs), value))
}

/// `get_dtext`.
fn get_dtext(value: &S) -> P {
    let (ptext, rest, had_qp) = get_ptext_to_endchars(value, "[]")?;
    let mut token = vt(&ptext, "ptext");
    if had_qp && let Node::Term(t) = &mut token {
        t.defects.push(Defect::Other);
    }
    validate_xtext(&mut token);
    Ok((token, rest))
}

/// `_check_for_early_dl_end`.
fn early_dl_end(value: &S, dl: &mut List) -> bool {
    if !value.is_empty() {
        return false;
    }
    dl.parts.push(Node::Stray);
    dl.parts.push(vts("]", "domain-literal-end"));
    true
}

/// `get_domain_literal`.
fn get_domain_literal(value: &S) -> P {
    let mut value = value.clone();
    let mut dl = new_list(Class::DomainLiteral);
    if has(CFWS_LEADER, *value.first().ok_or(INDEX)?) {
        let (token, rest) = get_cfws(&value)?;
        dl.parts.push(token);
        value = rest;
    }
    if value.is_empty() || value[0] != u32::from('[') {
        return Err(Ex::Parse);
    }
    value = value.skip(1);
    if early_dl_end(&value, &mut dl) {
        return Ok((Node::List(dl), value));
    }
    dl.parts.push(vts("[", "domain-literal-start"));
    if first_in(&value, WSP) {
        let (token, rest) = get_fws(&value);
        dl.parts.push(token);
        value = rest;
    }
    let (token, rest) = get_dtext(&value)?;
    dl.parts.push(token);
    value = rest;
    if early_dl_end(&value, &mut dl) {
        return Ok((Node::List(dl), value));
    }
    if first_in(&value, WSP) {
        let (token, rest) = get_fws(&value);
        dl.parts.push(token);
        value = rest;
    }
    if early_dl_end(&value, &mut dl) {
        return Ok((Node::List(dl), value));
    }
    if value[0] != u32::from(']') {
        return Err(Ex::Parse);
    }
    dl.parts.push(vts("]", "domain-literal-end"));
    value = value.skip(1);
    if first_in(&value, CFWS_LEADER) {
        let (token, rest) = get_cfws(&value)?;
        dl.parts.push(token);
        value = rest;
    }
    Ok((Node::List(dl), value))
}

/// `get_domain`.
fn get_domain(value: &S) -> P {
    let mut value = value.clone();
    let mut domain = new_list(Class::Domain);
    let mut leader = None;
    if first_in(&value, CFWS_LEADER) {
        let (token, rest) = get_cfws(&value)?;
        leader = Some(token);
        value = rest;
    }
    if value.is_empty() {
        return Err(Ex::Parse);
    }
    if value[0] == u32::from('[') {
        let (mut token, rest) = get_domain_literal(&value)?;
        if let Some(leader) = leader {
            token.prepend(leader);
        }
        domain.parts.push(token);
        return Ok((Node::List(domain), rest));
    }
    let (mut token, rest) = match get_dot_atom(&value) {
        Ok(parsed) => parsed,
        Err(Ex::Parse | Ex::InvalidEw) => get_atom(&value)?,
        Err(error) => return Err(error),
    };
    value = rest;
    if value.first() == Some(&u32::from('@')) {
        return Err(Ex::Parse);
    }
    if let Some(leader) = leader {
        token.prepend(leader);
    }
    domain.parts.push(token);
    if value.first() == Some(&u32::from('.')) {
        domain.defects.push(Defect::Other);
        if domain.parts[0].is("dot-atom")? {
            let inner = domain.parts[0].parts().to_vec();
            domain.parts = inner;
        }
        while value.first() == Some(&u32::from('.')) {
            domain.parts.push(dot());
            let (token, rest) = get_atom(&value.skip(1))?;
            domain.parts.push(token);
            value = rest;
        }
    }
    Ok((Node::List(domain), value))
}

/// `get_addr_spec`.
fn get_addr_spec(value: &S) -> P {
    let mut addr_spec = new_list(Class::AddrSpec);
    let (token, value) = get_local_part(value)?;
    addr_spec.parts.push(token);
    if value.first() != Some(&u32::from('@')) {
        addr_spec.defects.push(Defect::Invalid);
        return Ok((Node::List(addr_spec), value));
    }
    addr_spec.parts.push(vts("@", "address-at-symbol"));
    let (token, value) = get_domain(&value.skip(1))?;
    addr_spec.parts.push(token);
    Ok((Node::List(addr_spec), value))
}

/// `get_obs_route`.
fn get_obs_route(value: &S) -> P {
    let mut value = value.clone();
    let mut route = new_list(Class::ObsRoute);
    while let Some(&c) = value.first() {
        if has(CFWS_LEADER, c) {
            let (token, rest) = get_cfws(&value)?;
            route.parts.push(token);
            value = rest;
        } else if c == u32::from(',') {
            route.parts.push(list_separator());
            value = value.skip(1);
        } else {
            break;
        }
    }
    if value.first() != Some(&u32::from('@')) {
        return Err(Ex::Parse);
    }
    route.parts.push(vts("@", "route-component-marker"));
    let (token, rest) = get_domain(&value.skip(1))?;
    route.parts.push(token);
    value = rest;
    while value.first() == Some(&u32::from(',')) {
        route.parts.push(list_separator());
        value = value.skip(1);
        if value.is_empty() {
            break;
        }
        if first_in(&value, CFWS_LEADER) {
            let (token, rest) = get_cfws(&value)?;
            route.parts.push(token);
            value = rest;
        }
        if value.is_empty() {
            break;
        }
        if value[0] == u32::from('@') {
            route.parts.push(vts("@", "route-component-marker"));
            let (token, rest) = get_domain(&value.skip(1))?;
            route.parts.push(token);
            value = rest;
        }
    }
    if value.is_empty() || value[0] != u32::from(':') {
        return Err(Ex::Parse);
    }
    route.parts.push(vts(":", "end-of-obs-route-marker"));
    Ok((Node::List(route), value.skip(1)))
}

/// `get_angle_addr`.
fn get_angle_addr(value: &S) -> P {
    let mut value = value.clone();
    let mut angle = new_list(Class::AngleAddr);
    if first_in(&value, CFWS_LEADER) {
        let (token, rest) = get_cfws(&value)?;
        angle.parts.push(token);
        value = rest;
    }
    if value.first() != Some(&u32::from('<')) {
        return Err(Ex::Parse);
    }
    angle.parts.push(vts("<", "angle-addr-start"));
    value = value.skip(1);
    if value.first() == Some(&u32::from('>')) {
        angle.parts.push(vts(">", "angle-addr-end"));
        angle.defects.push(Defect::Invalid);
        return Ok((Node::List(angle), value.skip(1)));
    }
    let (token, rest) = match get_addr_spec(&value) {
        Ok(parsed) => parsed,
        Err(Ex::Parse | Ex::InvalidEw) => {
            let (route, rest) = match get_obs_route(&value) {
                Ok(parsed) => parsed,
                Err(Ex::Parse | Ex::InvalidEw) => return Err(Ex::Parse),
                Err(error) => return Err(error),
            };
            angle.defects.push(Defect::Other);
            angle.parts.push(route);
            get_addr_spec(&rest)?
        }
        Err(error) => return Err(error),
    };
    angle.parts.push(token);
    value = rest;
    if value.first() == Some(&u32::from('>')) {
        value = value.skip(1);
    } else {
        angle.defects.push(Defect::Invalid);
    }
    angle.parts.push(vts(">", "angle-addr-end"));
    if first_in(&value, CFWS_LEADER) {
        let (token, rest) = get_cfws(&value)?;
        angle.parts.push(token);
        value = rest;
    }
    Ok((Node::List(angle), value))
}

/// `get_display_name`.
fn get_display_name(value: &S) -> R<(List, S)> {
    let (phrase, rest) = get_phrase(value)?;
    Ok((
        List {
            class: Class::DisplayName,
            token_type: None,
            parts: phrase.parts,
            defects: phrase.defects,
        },
        rest,
    ))
}

/// `get_name_addr`.
fn get_name_addr(value: &S) -> P {
    let mut value = value.clone();
    let mut name_addr = new_list(Class::NameAddr);
    let mut leader = None;
    if value.is_empty() {
        return Err(Ex::Parse);
    }
    if first_in(&value, CFWS_LEADER) {
        let (token, rest) = get_cfws(&value)?;
        leader = Some(token);
        value = rest;
        if value.is_empty() {
            return Err(Ex::Parse);
        }
    }
    if value[0] != u32::from('<') {
        if has(PHRASE_ENDS, value[0]) {
            return Err(Ex::Parse);
        }
        let (mut token, rest) = get_display_name(&value)?;
        value = rest;
        if value.is_empty() {
            return Err(Ex::Parse);
        }
        if let Some(leader) = leader.take() {
            let first = token.parts.first_mut().ok_or(INDEX)?;
            if let Node::List(inner) = first {
                inner.parts.insert(0, leader);
            } else {
                token.parts.insert(0, leader);
            }
        }
        name_addr.parts.push(Node::List(token));
    }
    let (mut token, rest) = get_angle_addr(&value)?;
    if let Some(leader) = leader {
        token.prepend(leader);
    }
    name_addr.parts.push(token);
    Ok((Node::List(name_addr), rest))
}

/// `get_mailbox`.
fn get_mailbox(value: &S) -> P {
    let mut mailbox = new_list(Class::Mailbox);
    let (token, rest) = match get_name_addr(value) {
        Ok(parsed) => parsed,
        Err(Ex::Parse | Ex::InvalidEw) => match get_addr_spec(value) {
            Ok(parsed) => parsed,
            Err(Ex::Parse | Ex::InvalidEw) => return Err(Ex::Parse),
            Err(error) => return Err(error),
        },
        Err(error) => return Err(error),
    };
    if token.any_defect(Defect::Invalid)? {
        mailbox.token_type = Some("invalid-mailbox");
    }
    mailbox.parts.push(token);
    Ok((Node::List(mailbox), rest))
}

/// `get_invalid_mailbox(value, endchars)`.
fn get_invalid_mailbox(value: &S, endchars: &str) -> R<(List, S)> {
    let mut value = value.clone();
    let mut invalid = new_list(Class::InvalidMailbox);
    while let Some(&c) = value.first() {
        if has(endchars, c) {
            break;
        }
        if has(PHRASE_ENDS, c) {
            invalid.parts.push(vt(&value[..1], "misplaced-special"));
            value = value.skip(1);
        } else {
            let (phrase, rest) = get_phrase(&value)?;
            invalid.parts.push(Node::List(phrase));
            value = rest;
        }
    }
    Ok((invalid, value))
}

/// `mailbox.token_type = 'invalid-mailbox'; mailbox.extend(token)`.
fn absorb_invalid(target: &mut Node, invalid: List) -> R<()> {
    match target {
        Node::List(l) => {
            l.token_type = Some("invalid-mailbox");
            l.parts.extend(invalid.parts);
            Ok(())
        }
        // A terminal takes the attribute but has no `extend`.
        _ => Err(ATTR),
    }
}

/// `get_mailbox_list`.
fn get_mailbox_list(value: &S) -> R<(List, S)> {
    let mut value = value.clone();
    let mut list = new_list(Class::MailboxList);
    while value.first().is_some_and(|c| *c != u32::from(';')) {
        match get_mailbox(&value) {
            Ok((token, rest)) => {
                list.parts.push(token);
                value = rest;
            }
            Err(Ex::Parse | Ex::InvalidEw) => {
                if first_in(&value, CFWS_LEADER) {
                    let (leader, rest) = get_cfws(&value)?;
                    value = rest;
                    if value.is_empty() || first_in(&value, ",;") {
                        list.parts.push(leader);
                        list.defects.push(Defect::Other);
                    } else {
                        let (mut token, rest) = get_invalid_mailbox(&value, ",;")?;
                        value = rest;
                        token.parts.insert(0, leader);
                        list.parts.push(Node::List(token));
                        list.defects.push(Defect::Invalid);
                    }
                } else if value[0] == u32::from(',') {
                    list.defects.push(Defect::Other);
                } else {
                    let (token, rest) = get_invalid_mailbox(&value, ",;")?;
                    value = rest;
                    list.parts.push(Node::List(token));
                    list.defects.push(Defect::Invalid);
                }
            }
            Err(error) => return Err(error),
        }
        if !value.is_empty() && !first_in(&value, ",;") {
            let (token, rest) = get_invalid_mailbox(&value, ",;")?;
            value = rest;
            absorb_invalid(list.parts.last_mut().ok_or(INDEX)?, token)?;
            list.defects.push(Defect::Invalid);
        }
        if value.first() == Some(&u32::from(',')) {
            list.parts.push(list_separator());
            value = value.skip(1);
        }
    }
    Ok((list, value))
}

/// `get_group_list`.
fn get_group_list(value: &S) -> P {
    let mut value = value.clone();
    let mut group_list = new_list(Class::GroupList);
    if value.is_empty() {
        group_list.defects.push(Defect::Invalid);
        return Ok((Node::List(group_list), value));
    }
    let mut leader = None;
    if first_in(&value, CFWS_LEADER) {
        let (token, rest) = get_cfws(&value)?;
        value = rest;
        if value.is_empty() {
            group_list.defects.push(Defect::Invalid);
            group_list.parts.push(token);
            return Ok((Node::List(group_list), value));
        }
        if value[0] == u32::from(';') {
            group_list.parts.push(token);
            return Ok((Node::List(group_list), value));
        }
        leader = Some(token);
    }
    let (mut token, rest) = get_mailbox_list(&value)?;
    value = rest;
    let mailboxes = all_mailboxes(&Node::List(token.clone()))?.len();
    if mailboxes == 0 {
        if let Some(leader) = leader {
            group_list.parts.push(leader);
        }
        group_list.parts.extend(token.parts);
        group_list.defects.push(Defect::Other);
        return Ok((Node::List(group_list), value));
    }
    if let Some(leader) = leader {
        token.parts.insert(0, leader);
    }
    group_list.parts.push(Node::List(token));
    Ok((Node::List(group_list), value))
}

/// `get_group`.
fn get_group(value: &S) -> P {
    let mut group = new_list(Class::Group);
    let (token, mut value) = get_display_name(value)?;
    if value.first() != Some(&u32::from(':')) {
        return Err(Ex::Parse);
    }
    group.parts.push(Node::List(token));
    group.parts.push(vts(":", "group-display-name-terminator"));
    value = value.skip(1);
    if value.first() == Some(&u32::from(';')) {
        group.parts.push(vts(";", "group-terminator"));
        return Ok((Node::List(group), value.skip(1)));
    }
    let (token, rest) = get_group_list(&value)?;
    group.parts.push(token);
    value = rest;
    if value.is_empty() {
        group.defects.push(Defect::Invalid);
    } else if value[0] != u32::from(';') {
        return Err(Ex::Parse);
    }
    group.parts.push(vts(";", "group-terminator"));
    value = value.skip(1);
    if first_in(&value, CFWS_LEADER) {
        let (token, rest) = get_cfws(&value)?;
        group.parts.push(token);
        value = rest;
    }
    Ok((Node::List(group), value))
}

/// `get_address`.
fn get_address(value: &S) -> P {
    let (token, rest) = match get_group(value) {
        Ok(parsed) => parsed,
        Err(Ex::Parse | Ex::InvalidEw) => match get_mailbox(value) {
            Ok(parsed) => parsed,
            Err(Ex::Parse | Ex::InvalidEw) => return Err(Ex::Parse),
            Err(error) => return Err(error),
        },
        Err(error) => return Err(error),
    };
    Ok((list_of(Class::Address, vec![token]), rest))
}

/// `get_address_list`.
fn get_address_list(value: &[u32]) -> R<Node> {
    let mut value = S::new(value);
    let mut list = new_list(Class::AddressList);
    while !value.is_empty() {
        match get_address(&value) {
            Ok((token, rest)) => {
                list.parts.push(token);
                value = rest;
            }
            Err(Ex::Parse | Ex::InvalidEw) => {
                if first_in(&value, CFWS_LEADER) {
                    let (leader, rest) = get_cfws(&value)?;
                    value = rest;
                    if value.is_empty() || value[0] == u32::from(',') {
                        list.parts.push(leader);
                        list.defects.push(Defect::Other);
                    } else {
                        let (mut token, rest) = get_invalid_mailbox(&value, ",")?;
                        value = rest;
                        token.parts.insert(0, leader);
                        list.parts
                            .push(list_of(Class::Address, vec![Node::List(token)]));
                        list.defects.push(Defect::Invalid);
                    }
                } else if value[0] == u32::from(',') {
                    list.defects.push(Defect::Other);
                } else {
                    let (token, rest) = get_invalid_mailbox(&value, ",")?;
                    value = rest;
                    list.parts
                        .push(list_of(Class::Address, vec![Node::List(token)]));
                    list.defects.push(Defect::Invalid);
                }
            }
            Err(error) => return Err(error),
        }
        if !value.is_empty() && value[0] != u32::from(',') {
            let (token, rest) = get_invalid_mailbox(&value, ",")?;
            value = rest;
            // `address_list[-1][0]`.
            let target = match list.parts.last_mut().ok_or(INDEX)? {
                Node::List(address) => address.parts.first_mut().ok_or(INDEX)?,
                _ => return Err(ATTR),
            };
            absorb_invalid(target, token)?;
            list.defects.push(Defect::Invalid);
        }
        if !value.is_empty() {
            list.parts.push(list_separator());
            value = value.skip(1);
        }
    }
    Ok(Node::List(list))
}

// ------------------------------------------------- _encoded_words.decode

/// How `bytes.decode(charset)` decodes, per CPython's codec registry.
#[derive(Clone, Copy, Debug)]
enum Codec {
    Utf8,
    Utf8Sig,
    Ascii,
    Latin1,
    /// Index into `codecs::CHARMAPS`.
    Charmap(usize),
    /// `encodings.undefined`: always raises `UnicodeError`.
    Undefined,
    /// A bytes-to-bytes codec: `bytes.decode` raises `LookupError`.
    NonText,
    /// A `_multibytecodec` CJK codec (`cjk.rs`).
    Cjk(cjk::Cjk),
    Utf16(unicodec::Endian),
    Utf32(unicodec::Endian),
    Utf7,
    UnicodeEscape,
    RawUnicodeEscape,
    Punycode,
    Idna,
}

/// The `errors` argument `_encoded_words.decode` passes to `bytes.decode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Errors {
    Strict,
    SurrogateEscape,
}

/// Why a `bytes.decode` call raised.
#[derive(Debug, PartialEq, Eq)]
enum DecodeFail {
    /// `UnicodeDecodeError`.
    Decode,
    /// Another `ValueError`: the `UnicodeError` a Python codec raises.
    Value,
    /// `RuntimeError("internal codec error")`.
    Runtime,
}

/// The error handler for a `UnicodeDecodeError` over `input[start..end]`
/// (`unicode_decode_call_errorhandler_writer`, `multibytecodec_decerror`):
/// `strict` raises it; `surrogateescape` (`PyCodec_SurrogateEscapeErrors`)
/// writes U+DC80..U+DCFF for up to four leading non-ASCII bytes of the
/// range and resumes after them, or re-raises when the range starts with
/// an ASCII byte.  Returns the position decoding resumes at.
fn decode_error(
    errors: Errors,
    input: &[u8],
    start: usize,
    end: usize,
    out: &mut Text,
) -> Result<usize, DecodeFail> {
    if errors == Errors::Strict {
        return Err(DecodeFail::Decode);
    }
    let mut consumed = 0;
    while consumed < 4 && start + consumed < end {
        match input.get(start + consumed) {
            Some(&byte) if byte >= 0x80 => {
                out.push(surrogate_byte(byte));
                consumed += 1;
            }
            _ => break,
        }
    }
    if consumed == 0 {
        // codec complained about ASCII byte.
        return Err(DecodeFail::Decode);
    }
    Ok(start + consumed)
}

/// `codecs.lookup(name)` for `bytes.decode`: `None` is `LookupError`.
fn lookup_codec(name: &[u32]) -> Option<Codec> {
    // `_Py_normalize_encoding` over the UTF-8 bytes: ASCII alphanumerics and
    // `.` are kept (lower-cased); every other run, non-ASCII included,
    // becomes one `_` between kept characters.
    let mut norm = String::new();
    let mut punct = false;
    for &c in name {
        let ascii = char::from_u32(c).filter(char::is_ascii);
        match ascii {
            Some(ch) if ch.is_ascii_alphanumeric() || ch == '.' => {
                if punct && !norm.is_empty() {
                    norm.push('_');
                }
                punct = false;
                norm.push(ch.to_ascii_lowercase());
            }
            _ => punct = true,
        }
    }
    // `encodings.search_function`.
    let alias = |key: &str| {
        codecs::ALIASES
            .binary_search_by(|(k, _)| (*k).cmp(key))
            .ok()
            .map(|i| codecs::ALIASES[i].1)
    };
    let aliased = alias(&norm).or_else(|| alias(&norm.replace('.', "_")));
    let mut candidates = Vec::new();
    if let Some(aliased) = aliased {
        candidates.push(aliased.to_owned());
    }
    candidates.push(norm.clone());
    for module in candidates {
        if module.is_empty() || module.contains('.') {
            continue;
        }
        if module == "aliases" {
            // Importable, but not a codec module.
            return None;
        }
        if let Some((_, codec)) = codecs::MODULES.iter().find(|(m, _)| *m == module) {
            return match codec {
                Codec::NonText => None,
                other => Some(*other),
            };
        }
    }
    None
}

/// The outcome of `bytes.decode(charset[, errors])`.
enum Decoded {
    Ok(Text),
    /// `UnicodeDecodeError` (strict).
    DecodeError,
}

fn surrogate_byte(b: u8) -> u32 {
    0xDC00 + u32::from(b)
}

fn decode_utf8(bytes: &[u8], escape: bool) -> Decoded {
    let mut out = Vec::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.extend(chunk.valid().chars().map(u32::from));
        if !chunk.invalid().is_empty() {
            if !escape {
                return Decoded::DecodeError;
            }
            out.extend(chunk.invalid().iter().map(|b| surrogate_byte(*b)));
        }
    }
    Decoded::Ok(out)
}

/// `bytes.decode(codec, 'strict' | 'surrogateescape')`.
fn decode_with(codec: Codec, bytes: &[u8], escape: bool) -> R<Decoded> {
    Ok(match codec {
        Codec::Utf8 => decode_utf8(bytes, escape),
        Codec::Utf8Sig => decode_utf8(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes), escape),
        Codec::Ascii => {
            let mut out = Vec::with_capacity(bytes.len());
            for &b in bytes {
                if b < 0x80 {
                    out.push(u32::from(b));
                } else if escape {
                    out.push(surrogate_byte(b));
                } else {
                    return Ok(Decoded::DecodeError);
                }
            }
            Decoded::Ok(out)
        }
        Codec::Latin1 => Decoded::Ok(bytes.iter().map(|b| u32::from(*b)).collect()),
        Codec::Charmap(index) => {
            let table = codecs::CHARMAPS.get(index).ok_or(Ex::InvalidEw)?;
            let mut out = Vec::with_capacity(bytes.len());
            for &b in bytes {
                let c = table[usize::from(b)];
                if c != 0xFFFE {
                    out.push(u32::from(c));
                } else if escape && b >= 0x80 {
                    out.push(surrogate_byte(b));
                } else {
                    // surrogateescape cannot represent a byte below 0x80 and
                    // re-raises the `UnicodeDecodeError`.
                    return Ok(Decoded::DecodeError);
                }
            }
            Decoded::Ok(out)
        }
        // `UnicodeError("undefined encoding")`: a `ValueError`.
        Codec::Undefined => return Err(Ex::InvalidEw),
        // `lookup_codec` never returns a non-text codec.
        Codec::NonText => return Err(Ex::InvalidEw),
        Codec::Cjk(..)
        | Codec::Utf16(..)
        | Codec::Utf32(..)
        | Codec::Utf7
        | Codec::UnicodeEscape
        | Codec::RawUnicodeEscape
        | Codec::Punycode
        | Codec::Idna => {
            let errors = if escape {
                Errors::SurrogateEscape
            } else {
                Errors::Strict
            };
            let decoded = match codec {
                Codec::Cjk(cjk) => cjk::decode(cjk, bytes, errors),
                Codec::Utf16(endian) => unicodec::decode_utf16(bytes, endian, errors),
                Codec::Utf32(endian) => unicodec::decode_utf32(bytes, endian, errors),
                Codec::Utf7 => unicodec::decode_utf7(bytes, errors),
                Codec::UnicodeEscape => unicodec::decode_unicode_escape(bytes, errors),
                Codec::RawUnicodeEscape => unicodec::decode_raw_unicode_escape(bytes, errors),
                Codec::Punycode => unicodec::decode_punycode(bytes, errors),
                _ => unicodec::decode_idna(bytes, errors),
            };
            match decoded {
                Ok(text) => Decoded::Ok(text),
                Err(DecodeFail::Decode) => Decoded::DecodeError,
                // `ValueError`: `get_encoded_word` turns it into
                // `_InvalidEwError`.
                Err(DecodeFail::Value) => return Err(Ex::InvalidEw),
                Err(DecodeFail::Runtime) => return Err(RUNTIME),
            }
        }
    })
}

/// `_encoded_words.decode('=?' + tok + '?=')` as `get_encoded_word` calls
/// it: `ValueError`/`KeyError` are `_InvalidEwError`.  Returns the text and
/// its defects.
fn ew_decode(tok: &[u32]) -> R<(Text, Vec<Defect>)> {
    let q = u32::from('?');
    let fields: Vec<&[u32]> = tok.split(|c| *c == q).collect();
    let [charset, cte, cte_string] = fields[..] else {
        return Err(Ex::InvalidEw);
    };
    let star = charset
        .iter()
        .position(|c| *c == u32::from('*'))
        .unwrap_or(charset.len());
    let charset = &charset[..star];
    let cte_is = |c: char| {
        cte.len() == 1 && (cte[0] == u32::from(c) || cte[0] == u32::from(c.to_ascii_uppercase()))
    };
    // `cte_string.encode('ascii', 'surrogateescape')`.
    let mut raw = Vec::with_capacity(cte_string.len());
    for &c in cte_string {
        if c < 0x80 {
            raw.push(c as u8);
        } else if (0xDC80..=0xDCFF).contains(&c) {
            raw.push((c - 0xDC00) as u8);
        } else {
            return Err(Ex::InvalidEw);
        }
    }
    let mut defects = Vec::new();
    let bytes = if cte_is('q') {
        decode_q(&raw)
    } else if cte_is('b') {
        decode_b(&raw, &mut defects)
    } else {
        return Err(Ex::InvalidEw);
    };
    if charset.contains(&0) {
        // `bytes.decode`: "embedded null character" (`ValueError`).
        return Err(Ex::InvalidEw);
    }
    // `bytes.decode(charset)`: the `encoding` argument is converted to a C
    // string first (a lone surrogate raises `UnicodeEncodeError`, handled
    // like `LookupError`), then empty bytes decode to '' without a codec
    // lookup (`PyUnicode_FromEncodedObject`).
    let codec = if charset.iter().any(|c| is_surrogate(*c)) {
        None
    } else if bytes.is_empty() {
        return Ok((Text::new(), defects));
    } else {
        lookup_codec(charset)
    };
    let text = match codec {
        None => {
            // `LookupError`: ASCII with surrogateescape.
            let lower: Option<String> = to_string(charset).map(|s| s.to_lowercase());
            if lower.as_deref() != Some("unknown-8bit") {
                defects.push(Defect::Other);
            }
            match decode_with(Codec::Ascii, &bytes, true)? {
                Decoded::Ok(text) => text,
                Decoded::DecodeError => return Err(Ex::InvalidEw),
            }
        }
        Some(codec) => match decode_with(codec, &bytes, false)? {
            Decoded::Ok(text) => text,
            Decoded::DecodeError => {
                defects.push(Defect::Undecodable);
                match decode_with(codec, &bytes, true)? {
                    Decoded::Ok(text) => text,
                    Decoded::DecodeError => return Err(Ex::InvalidEw),
                }
            }
        },
    };
    Ok((text, defects))
}

/// `_encoded_words.decode_q`.
fn decode_q(raw: &[u8]) -> Vec<u8> {
    let raw: Vec<u8> = raw
        .iter()
        .map(|b| if *b == b'_' { b' ' } else { *b })
        .collect();
    let mut out = Vec::with_capacity(raw.len());
    let mut index = 0;
    while let Some(&byte) = raw.get(index) {
        let pair = raw
            .get(index + 1..index + 3)
            .filter(|p| p.iter().all(u8::is_ascii_hexdigit));
        match (byte, pair) {
            (b'=', Some(pair)) => {
                let hex = std::str::from_utf8(pair).unwrap_or_default();
                out.push(u8::from_str_radix(hex, 16).unwrap_or_default());
                index += 3;
            }
            _ => {
                out.push(byte);
                index += 1;
            }
        }
    }
    out
}

/// `_encoded_words.decode_b`.
fn decode_b(raw: &[u8], defects: &mut Vec<Defect>) -> Vec<u8> {
    let pad_err = raw.len() % 4;
    let missing: &[u8] = if pad_err == 0 {
        b""
    } else {
        &b"==="[..4 - pad_err]
    };
    let mut padded = raw.to_vec();
    padded.extend_from_slice(missing);
    let strict = std::str::from_utf8(&padded)
        .ok()
        .and_then(|s| crate::pybase64::b64decode_strict(s).ok());
    if let Some(decoded) = strict {
        if pad_err != 0 {
            defects.push(Defect::Other);
        }
        return decoded;
    }
    if let Ok(decoded) = crate::pybase64::b64decode_bytes(raw) {
        defects.push(Defect::Other);
        return decoded;
    }
    let mut extra = raw.to_vec();
    extra.extend_from_slice(b"==");
    if let Ok(decoded) = crate::pybase64::b64decode_bytes(&extra) {
        defects.push(Defect::Other);
        defects.push(Defect::Other);
        return decoded;
    }
    defects.push(Defect::Other);
    raw.to_vec()
}

/// `_encoded_words.encode(string, charset)`.
fn ew_encode(value: &[u32], charset: &str) -> R<Text> {
    let bytes = if charset == "unknown-8bit" {
        encode_surrogateescape(value, false).ok_or(UNICODE_ENCODE)?
    } else {
        encode_utf8(value).ok_or(UNICODE_ENCODE)?
    };
    let q_safe = |b: u8| b.is_ascii_alphanumeric() || b"-!*+/".contains(&b);
    let qlen: usize = bytes
        .iter()
        .map(|&b| if q_safe(b) || b == b' ' { 1 } else { 3 })
        .sum();
    let blen = bytes.len() / 3 * 4 + if bytes.len() % 3 == 0 { 0 } else { 4 };
    let mut out = format!("=?{charset}?");
    if (qlen as isize) - (blen as isize) < 5 {
        out.push_str("q?");
        for &b in &bytes {
            match b {
                b' ' => out.push('_'),
                b if q_safe(b) => out.push(char::from(b)),
                b => out.push_str(&format!("={b:02X}")),
            }
        }
    } else {
        out.push_str("b?");
        out.push_str(&crate::pybase64::b64encode(&bytes));
    }
    out.push_str("?=");
    Ok(text(&out))
}

// ----------------------------------------------------------------- folding

enum Item {
    Node(Node),
    /// `end_ew_not_allowed`.
    EndBlocked,
}

fn line_len(lines: &[Text]) -> usize {
    lines.last().map_or(0, Vec::len)
}

/// `_steal_trailing_WSP_if_exists`.
fn steal_trailing_wsp(lines: &mut [Text]) -> Text {
    match lines.last_mut() {
        Some(last) if last.last().is_some_and(|c| has(WSP, *c)) => {
            last.pop().map(|c| vec![c]).unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

fn last_line(lines: &mut [Text]) -> R<&mut Text> {
    lines.last_mut().ok_or(INDEX)
}

/// `_refold_parse_tree(parse_tree, policy=...)` with `max_line_length` 78
/// and `linesep` CRLF.
fn refold(parse_tree: &Node, utf8: bool) -> R<Text> {
    let maxlen = MAX_LINE_LENGTH;
    let encoding = if utf8 { "utf-8" } else { "us-ascii" };
    let mut lines: Vec<Text> = vec![Vec::new()];
    let mut leading_whitespace: Text = Vec::new();
    let mut last_ew: Option<usize> = None;
    let mut last_charset: Option<&'static str> = None;
    let mut wrap_as_ew_blocked = 0usize;
    let mut want_encoding = false;
    let mut parts: std::collections::VecDeque<Item> =
        parse_tree.parts().iter().cloned().map(Item::Node).collect();
    while let Some(item) = parts.pop_front() {
        let part = match item {
            Item::EndBlocked => {
                wrap_as_ew_blocked = wrap_as_ew_blocked.saturating_sub(1);
                continue;
            }
            Item::Node(part) => part,
        };
        let tstr = part.to_str();
        if !want_encoding {
            let token_type = part.token_type()?;
            want_encoding = if matches!(token_type, Some("ptext" | "vtext")) {
                tstr.iter().any(|c| has(SPECIALSNL, *c))
            } else {
                tstr.iter().any(|c| has(NLSET, *c))
            };
        }
        let encodable = if utf8 {
            !has_surrogates(&tstr)
        } else {
            tstr.iter().all(|c| *c < 0x80)
        };
        let charset: &'static str = if encodable {
            encoding
        } else {
            want_encoding = true;
            if part.any_defect(Defect::Undecodable)? {
                "unknown-8bit"
            } else {
                "utf-8"
            }
        };
        // `part.token_type == 'mime-parameters'`.
        part.token_type()?;

        if want_encoding && wrap_as_ew_blocked == 0 {
            if !part.as_ew_allowed()? {
                want_encoding = false;
                last_ew = None;
                if part.syntactic_break()? {
                    let folded = refold(&part, utf8)?;
                    let encoded = &folded[..folded.len().saturating_sub(LINESEP.len())];
                    if find(encoded, LINESEP).is_none() {
                        if encoded.len() as isize > maxlen as isize - line_len(&lines) as isize {
                            let newline = steal_trailing_wsp(&mut lines);
                            lines.push(newline);
                        }
                        last_line(&mut lines)?.extend_from_slice(encoded);
                        continue;
                    }
                }
            }
            match &part {
                Node::List(l) => {
                    for child in l.parts.iter().rev() {
                        parts.push_front(Item::Node(child.clone()));
                    }
                    want_encoding = false;
                    continue;
                }
                // `list(defect)`.
                Node::Stray => return Err(Ex::Builtin("TypeError")),
                Node::Term(_) if part.as_ew_allowed()? => {
                    if last_ew.is_some()
                        && Some(charset) != last_charset
                        && (last_charset == Some("unknown-8bit")
                            || last_charset == Some("utf-8") && charset != "us-ascii")
                    {
                        last_ew = None;
                    }
                    last_ew = fold_as_ew(
                        &tstr,
                        &mut lines,
                        last_ew,
                        part.ew_combine_allowed()?,
                        charset,
                        &leading_whitespace,
                    )?;
                    leading_whitespace.clear();
                    last_charset = Some(charset);
                    want_encoding = false;
                    continue;
                }
                Node::Term(_) => {
                    last_ew = None;
                    want_encoding = false;
                }
            }
        }
        if tstr.len() as isize <= maxlen as isize - line_len(&lines) as isize {
            last_line(&mut lines)?.extend(tstr);
            continue;
        }
        leading_whitespace.clear();
        if part.syntactic_break()? && tstr.len() < maxlen {
            let newline = steal_trailing_wsp(&mut lines);
            if !newline.is_empty() || part.startswith_fws()? {
                let mut line = newline;
                line.extend(tstr);
                leading_whitespace = line.iter().take_while(|c| has(WSP, **c)).copied().collect();
                lines.push(line);
                last_ew = None;
                continue;
            }
        }
        if let Node::List(l) = &part {
            let class_type = part.token_type()?;
            let mut newparts: Vec<Item> = l.parts.iter().cloned().map(Item::Node).collect();
            if class_type == Some("bare-quoted-string") {
                let mut quoted = vec![Item::Node(vts("\"", "ptext"))];
                for p in &l.parts {
                    quoted.push(Item::Node(vt(&make_quoted_pairs(&p.to_str()), "ptext")));
                }
                quoted.push(Item::Node(vts("\"", "ptext")));
                newparts = quoted;
            }
            if class_type == Some("comment") {
                let mut wrapped = vec![Item::Node(vts("(", "ptext"))];
                for p in &l.parts {
                    if p.is("ptext")? {
                        wrapped.push(Item::Node(vt(
                            &make_parenthesis_pairs(&p.to_str()),
                            "ptext",
                        )));
                    } else {
                        wrapped.push(Item::Node(p.clone()));
                    }
                }
                wrapped.push(Item::Node(vts(")", "ptext")));
                newparts = wrapped;
            }
            if !part.as_ew_allowed()? {
                wrap_as_ew_blocked += 1;
                newparts.push(Item::EndBlocked);
            }
            for item in newparts.into_iter().rev() {
                parts.push_front(item);
            }
            continue;
        }
        if part.as_ew_allowed()? && wrap_as_ew_blocked == 0 {
            parts.push_front(Item::Node(part));
            want_encoding = true;
            continue;
        }
        let newline = steal_trailing_wsp(&mut lines);
        if !newline.is_empty() || part.startswith_fws()? {
            let mut line = newline;
            line.extend(tstr);
            lines.push(line);
        } else {
            last_line(&mut lines)?.extend(tstr);
        }
    }
    let mut out = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            push(&mut out, LINESEP);
        }
        out.extend_from_slice(line);
    }
    push(&mut out, LINESEP);
    Ok(out)
}

/// `_fold_as_ew`.
fn fold_as_ew(
    to_encode: &[u32],
    lines: &mut Vec<Text>,
    last_ew: Option<usize>,
    ew_combine_allowed: bool,
    charset: &'static str,
    leading_whitespace: &[u32],
) -> R<Option<usize>> {
    let maxlen = MAX_LINE_LENGTH;
    let mut to_encode: Text = to_encode.to_vec();
    let mut leading_whitespace: Text = leading_whitespace.to_vec();
    match last_ew {
        Some(position) if ew_combine_allowed => {
            let last = last_line(lines)?;
            let mut combined = last.get(position..).unwrap_or_default().to_vec();
            combined.extend_from_slice(&to_encode);
            to_encode = get_unstructured(&combined)?.to_str();
            last.truncate(position.min(last.len()));
        }
        _ => {
            let lead = *to_encode.first().ok_or(INDEX)?;
            if has(WSP, lead) {
                to_encode.remove(0);
                if line_len(lines) == maxlen {
                    let newline = steal_trailing_wsp(lines);
                    lines.push(newline);
                }
                last_line(lines)?.push(lead);
            }
        }
    }
    let mut trailing = None;
    let tail = *to_encode.last().ok_or(INDEX)?;
    if has(WSP, tail) {
        trailing = to_encode.pop();
    }
    let mut new_last_ew = last_ew.unwrap_or_else(|| line_len(lines));
    let encode_as = if charset == "us-ascii" {
        "utf-8"
    } else {
        charset
    };
    let chrome_len = encode_as.len() + 7;
    while !to_encode.is_empty() {
        let remaining_space = maxlen as isize - line_len(lines) as isize;
        let text_space = remaining_space - chrome_len as isize - leading_whitespace.len() as isize;
        if text_space <= 0 {
            lines.push(text(" "));
            continue;
        }
        if lines.len() > 1 && line_len(lines) == 1 && !leading_whitespace.is_empty() {
            let word = ew_encode(&leading_whitespace, encode_as)?;
            last_line(lines)?.extend(word);
            leading_whitespace.clear();
        }
        let mut take = to_encode.len().min(text_space as usize);
        let mut encoded = ew_encode(&to_encode[..take], encode_as)?;
        while encoded.len() as isize - remaining_space > 0 && take > 0 {
            take -= 1;
            encoded = ew_encode(&to_encode[..take], encode_as)?;
        }
        last_line(lines)?.extend(encoded);
        to_encode.drain(..take);
        leading_whitespace.clear();
        if !to_encode.is_empty() {
            lines.push(text(" "));
            new_last_ew = line_len(lines);
        }
    }
    if let Some(trailing) = trailing {
        last_line(lines)?.push(trailing);
    }
    Ok(ew_combine_allowed.then_some(new_last_ew))
}

// ------------------------------------------------------------ the headers

/// The deepest nesting of comments in a parse tree.
fn comment_nesting(node: &Node) -> usize {
    let inner = node.parts().iter().map(comment_nesting).max().unwrap_or(0);
    match node {
        Node::List(l) if l.class == Class::Comment => inner + 1,
        _ => inner,
    }
}

/// A header object as `EmailMessage.__setitem__` stores it.
pub(super) struct Header {
    name: &'static str,
    parse_tree: Node,
    /// `str(header)`: the (sanitized) `decoded` value.
    pub(super) decoded: String,
}

/// `UnstructuredHeader` (`Subject`).
pub(super) fn unstructured_header(name: &'static str, value: &str) -> R<Header> {
    let parse_tree = get_unstructured(&text(value))?;
    let decoded = sanitize(&parse_tree.to_str())?;
    Ok(Header {
        name,
        parse_tree,
        decoded,
    })
}

/// `headerregistry.Address.__str__` over `(display_name, username, domain)`.
fn address_str(display_name: &[u32], username: &[u32], domain: &[u32]) -> Text {
    let mut lp = username.to_vec();
    if lp.iter().any(|c| has(DOT_ATOM_ENDS, *c)) {
        lp = quote_string(&lp);
    }
    let addr_spec = if !domain.is_empty() {
        let mut out = lp;
        out.push(u32::from('@'));
        out.extend_from_slice(domain);
        out
    } else if lp.is_empty() {
        text("<>")
    } else {
        lp
    };
    let mut disp = display_name.to_vec();
    if disp.iter().any(|c| has(SPECIALS, *c)) {
        disp = quote_string(&disp);
    }
    if disp.is_empty() {
        return addr_spec;
    }
    let mut out = disp;
    push(&mut out, " <");
    if addr_spec != text("<>") {
        out.extend(addr_spec);
    }
    out.push(u32::from('>'));
    out
}

/// `AddressHeader` (`From`/`To`): `get_address_list`, then the
/// `Group`/`Address` objects and the `decoded` string they produce.
pub(super) fn address_header(name: &'static str, value: &str) -> R<Header> {
    let parse_tree = get_address_list(&text(value))?;
    let mut groups: Vec<Text> = Vec::new();
    for addr in parse_tree.parts() {
        if !addr.is("address")? {
            continue;
        }
        let group_name = prop_display_name(addr)?;
        let mut addresses: Vec<Text> = Vec::new();
        for mb in all_mailboxes(addr)? {
            let display_name = prop_display_name(mb)?.unwrap_or_default();
            let username = prop_local_part(mb)?.unwrap_or_default();
            let domain = prop_domain(mb)?.unwrap_or_default();
            let joined = [&display_name, &username, &domain];
            if joined.iter().any(|t| {
                t.iter()
                    .any(|c| *c == u32::from('\r') || *c == u32::from('\n'))
            }) {
                return Err(Ex::Builtin("ValueError"));
            }
            addresses.push(address_str(&display_name, &username, &domain));
        }
        // `Group.__str__`.
        groups.push(match group_name {
            None if addresses.len() == 1 => addresses.remove(0),
            group_name => {
                let mut out = match group_name {
                    Some(disp) if disp.iter().any(|c| has(SPECIALS, *c)) => quote_string(&disp),
                    Some(disp) => disp,
                    None => text("None"),
                };
                out.push(u32::from(':'));
                if !addresses.is_empty() {
                    out.push(u32::from(' '));
                    for (index, address) in addresses.iter().enumerate() {
                        if index > 0 {
                            push(&mut out, ", ");
                        }
                        out.extend_from_slice(address);
                    }
                }
                out.push(u32::from(';'));
                out
            }
        });
    }
    // `list(address_list.all_defects)`.
    parse_tree.any_defect(Defect::Invalid)?;
    let mut decoded = Vec::new();
    for (index, group) in groups.iter().enumerate() {
        if index > 0 {
            push(&mut decoded, ", ");
        }
        decoded.extend_from_slice(group);
    }
    Ok(Header {
        name,
        parse_tree,
        decoded: sanitize(&decoded)?,
    })
}

impl Header {
    /// `policy.fold_binary(name, header)` (`BaseHeader.fold` through
    /// `_refold_parse_tree`, then `encode(<utf8|ascii>, 'surrogateescape')`).
    pub(super) fn fold_binary(&self, utf8: bool) -> R<Vec<u8>> {
        if comment_nesting(&self.parse_tree) >= FOLD_RECURSION_NESTING {
            return Err(Ex::Builtin("RecursionError"));
        }
        let label = list_of(
            Class::HeaderLabel,
            vec![vts(self.name, "header-name"), vts(":", "header-sep")],
        );
        let mut parts = vec![label];
        if !self.parse_tree.parts().is_empty() {
            parts.push(list_of(Class::Cfws, vec![wst(&text(" "), "fws")]));
        }
        parts.push(self.parse_tree.clone());
        let folded = refold(&list_of(Class::Header, parts), utf8)?;
        encode_surrogateescape(&folded, utf8).ok_or(UNICODE_ENCODE)
    }
}

// ------------------------------------------------- the legacy address parser

/// `email._parseaddr.AddrlistClass`.
struct AddrList {
    field: Vec<char>,
    pos: usize,
    commentlist: Vec<String>,
    depth: usize,
}

const LEGACY_SPECIALS: &str = "()<>@,:;.\"[]";
const LEGACY_LWS: &str = " \t";
const LEGACY_FWS: &str = " \t\r\n";
const LEGACY_ATOMENDS: &str = "()<>@,:;.\"[] \t\r\n";
const LEGACY_PHRASEENDS: &str = "()<>@,:;\"[] \t\r\n";

/// `_parseaddr.quote`.
fn legacy_quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

impl AddrList {
    fn new(field: &str) -> Self {
        AddrList {
            field: field.chars().collect(),
            pos: 0,
            commentlist: Vec::new(),
            depth: 0,
        }
    }

    fn at(&self) -> Option<char> {
        self.field.get(self.pos).copied()
    }

    fn gotonext(&mut self) -> R<String> {
        let mut wslist = String::new();
        while let Some(c) = self.at() {
            if LEGACY_FWS.contains(c) {
                if !"\n\r".contains(c) {
                    wslist.push(c);
                }
                self.pos += 1;
            } else if c == '(' {
                let comment = self.getcomment()?;
                self.commentlist.push(comment);
            } else {
                break;
            }
        }
        Ok(wslist)
    }

    fn getaddrlist(&mut self) -> R<Vec<(String, String)>> {
        let mut result = Vec::new();
        while self.pos < self.field.len() {
            let ad = self.getaddress()?;
            if ad.is_empty() {
                result.push((String::new(), String::new()));
            } else {
                result.extend(ad);
            }
        }
        Ok(result)
    }

    fn getaddress(&mut self) -> R<Vec<(String, String)>> {
        self.depth += 1;
        if self.depth >= BUILD_RECURSION_NESTING {
            return Err(Ex::Builtin("RecursionError"));
        }
        let result = self.getaddress_inner();
        self.depth -= 1;
        result
    }

    fn getaddress_inner(&mut self) -> R<Vec<(String, String)>> {
        self.commentlist = Vec::new();
        self.gotonext()?;
        let oldpos = self.pos;
        let oldcl = self.commentlist.clone();
        let plist = self.getphraselist()?;
        self.gotonext()?;
        let mut returnlist = Vec::new();
        match self.at() {
            None => {
                if let Some(first) = plist.first() {
                    returnlist = vec![(self.commentlist.join(" "), first.clone())];
                }
            }
            Some('.' | '@') => {
                self.pos = oldpos;
                self.commentlist = oldcl;
                let addrspec = self.getaddrspec()?;
                returnlist = vec![(self.commentlist.join(" "), addrspec)];
            }
            Some(':') => {
                let fieldlen = self.field.len();
                self.pos += 1;
                while self.pos < self.field.len() {
                    self.gotonext()?;
                    if self.pos < fieldlen && self.field[self.pos] == ';' {
                        self.pos += 1;
                        break;
                    }
                    returnlist.extend(self.getaddress()?);
                }
            }
            Some('<') => {
                let routeaddr = self.getrouteaddr()?;
                if self.commentlist.is_empty() {
                    returnlist = vec![(plist.join(" "), routeaddr)];
                } else {
                    returnlist = vec![(
                        format!("{} ({})", plist.join(" "), self.commentlist.join(" ")),
                        routeaddr,
                    )];
                }
            }
            Some(c) => {
                if let Some(first) = plist.first() {
                    returnlist = vec![(self.commentlist.join(" "), first.clone())];
                } else if LEGACY_SPECIALS.contains(c) {
                    self.pos += 1;
                }
            }
        }
        self.gotonext()?;
        if self.at() == Some(',') {
            self.pos += 1;
        }
        Ok(returnlist)
    }

    fn getrouteaddr(&mut self) -> R<String> {
        if self.at() != Some('<') {
            return Ok(String::new());
        }
        let mut expectroute = false;
        self.pos += 1;
        self.gotonext()?;
        let mut adlist = String::new();
        while let Some(c) = self.at() {
            if expectroute {
                self.getdomain()?;
                expectroute = false;
            } else if c == '>' {
                self.pos += 1;
                break;
            } else if c == '@' {
                self.pos += 1;
                expectroute = true;
            } else if c == ':' {
                self.pos += 1;
            } else {
                adlist = self.getaddrspec()?;
                self.pos += 1;
                break;
            }
            self.gotonext()?;
        }
        Ok(adlist)
    }

    fn getaddrspec(&mut self) -> R<String> {
        let mut aslist: Vec<String> = Vec::new();
        self.gotonext()?;
        while let Some(c) = self.at() {
            let mut preserve_ws = true;
            if c == '.' {
                if aslist.last().is_some_and(|l| py_strip(l).is_empty()) {
                    aslist.pop();
                }
                aslist.push(".".into());
                self.pos += 1;
                preserve_ws = false;
            } else if c == '"' {
                let quoted = self.getquote()?;
                aslist.push(format!("\"{}\"", legacy_quote(&quoted)));
            } else if LEGACY_ATOMENDS.contains(c) {
                if aslist.last().is_some_and(|l| py_strip(l).is_empty()) {
                    aslist.pop();
                }
                break;
            } else {
                aslist.push(self.getatom(LEGACY_ATOMENDS));
            }
            let ws = self.gotonext()?;
            if preserve_ws && !ws.is_empty() {
                aslist.push(ws);
            }
        }
        if self.at() != Some('@') {
            return Ok(aslist.concat());
        }
        aslist.push("@".into());
        self.pos += 1;
        self.gotonext()?;
        let domain = self.getdomain()?;
        if domain.is_empty() {
            return Ok(String::new());
        }
        Ok(aslist.concat() + &domain)
    }

    fn getdomain(&mut self) -> R<String> {
        let mut sdlist = String::new();
        while let Some(c) = self.at() {
            if LEGACY_LWS.contains(c) {
                self.pos += 1;
            } else if c == '(' {
                let comment = self.getcomment()?;
                self.commentlist.push(comment);
            } else if c == '[' {
                sdlist.push_str(&self.getdomainliteral()?);
            } else if c == '.' {
                self.pos += 1;
                sdlist.push('.');
            } else if c == '@' {
                return Ok(String::new());
            } else if LEGACY_ATOMENDS.contains(c) {
                break;
            } else {
                sdlist.push_str(&self.getatom(LEGACY_ATOMENDS));
            }
        }
        Ok(sdlist)
    }

    fn getdelimited(&mut self, beginchar: char, endchars: &str, allowcomments: bool) -> R<String> {
        if self.at() != Some(beginchar) {
            return Ok(String::new());
        }
        self.depth += 1;
        if self.depth >= BUILD_RECURSION_NESTING {
            return Err(Ex::Builtin("RecursionError"));
        }
        let mut slist = String::new();
        let mut quote = false;
        self.pos += 1;
        while let Some(c) = self.at() {
            if quote {
                slist.push(c);
                quote = false;
            } else if endchars.contains(c) {
                self.pos += 1;
                break;
            } else if allowcomments && c == '(' {
                slist.push_str(&self.getcomment()?);
                continue;
            } else if c == '\\' {
                quote = true;
            } else {
                slist.push(c);
            }
            self.pos += 1;
        }
        self.depth -= 1;
        Ok(slist)
    }

    fn getquote(&mut self) -> R<String> {
        self.getdelimited('"', "\"\r", false)
    }

    fn getcomment(&mut self) -> R<String> {
        self.getdelimited('(', ")\r", true)
    }

    fn getdomainliteral(&mut self) -> R<String> {
        Ok(format!("[{}]", self.getdelimited('[', "]\r", false)?))
    }

    fn getatom(&mut self, atomends: &str) -> String {
        let mut atom = String::new();
        while let Some(c) = self.at() {
            if atomends.contains(c) {
                break;
            }
            atom.push(c);
            self.pos += 1;
        }
        atom
    }

    fn getphraselist(&mut self) -> R<Vec<String>> {
        let mut plist = Vec::new();
        while let Some(c) = self.at() {
            if LEGACY_FWS.contains(c) {
                self.pos += 1;
            } else if c == '"' {
                plist.push(self.getquote()?);
            } else if c == '(' {
                let comment = self.getcomment()?;
                self.commentlist.push(comment);
            } else if LEGACY_PHRASEENDS.contains(c) {
                break;
            } else {
                plist.push(self.getatom(LEGACY_PHRASEENDS));
            }
        }
        Ok(plist)
    }
}

/// `str.strip()`.
fn py_strip(value: &str) -> &str {
    value.trim_matches(pystr::is_space)
}

/// `_parseaddr.AddressList(field).addresslist`.
fn legacy_addresslist(field: &str) -> R<Vec<(String, String)>> {
    if field.is_empty() {
        return Ok(Vec::new());
    }
    AddrList::new(field).getaddrlist()
}

/// `utils._iter_escaped_chars` then `_strip_quoted_realnames`.
fn strip_quoted_realnames(addr: &str) -> String {
    if !addr.contains('"') {
        return addr.to_owned();
    }
    let chars: Vec<char> = addr.chars().collect();
    let mut escaped: Vec<(usize, String)> = Vec::new();
    let mut escape = false;
    let mut last = 0;
    for (pos, &ch) in chars.iter().enumerate() {
        last = pos;
        if escape {
            escaped.push((pos, format!("\\{ch}")));
            escape = false;
        } else if ch == '\\' {
            escape = true;
        } else {
            escaped.push((pos, ch.to_string()));
        }
    }
    if escape {
        escaped.push((last, "\\".into()));
    }
    let mut start = 0;
    let mut open_pos: Option<usize> = None;
    let mut result = String::new();
    for (pos, ch) in escaped {
        if ch == "\"" {
            match open_pos {
                None => open_pos = Some(pos),
                Some(open) => {
                    if start != open {
                        result.extend(&chars[start..open]);
                    }
                    start = pos + 1;
                    open_pos = None;
                }
            }
        }
    }
    if start < chars.len() {
        result.extend(&chars[start..]);
    }
    result
}

/// `utils._check_parenthesis`.
fn check_parenthesis(addr: &str) -> bool {
    let addr = strip_quoted_realnames(addr);
    let mut opens: i64 = 0;
    let mut escape = false;
    for ch in addr.chars() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
        } else if ch == '(' {
            opens += 1;
        } else if ch == ')' {
            opens -= 1;
            if opens < 0 {
                return false;
            }
        }
    }
    opens == 0
}

/// `utils._pre_parse_validation` for one field.
fn pre_parse(value: &str) -> String {
    if check_parenthesis(value) {
        value.to_owned()
    } else {
        "('', '')".to_owned()
    }
}

/// `utils._post_parse_validation`.
fn post_parse(parsed: Vec<(String, String)>) -> Vec<(String, String)> {
    parsed
        .into_iter()
        .map(|v| {
            if v.1.contains('[') {
                (String::new(), String::new())
            } else {
                v
            }
        })
        .collect()
}

/// `email.utils.getaddresses([field])` (strict): the address of each pair.
pub(super) fn getaddresses(field: &str) -> R<Vec<String>> {
    let field = pre_parse(field);
    let result = post_parse(legacy_addresslist(&field)?);
    let n = 1 + strip_quoted_realnames(&field).matches(',').count();
    if result.len() != n {
        return Ok(vec![String::new()]);
    }
    Ok(result.into_iter().map(|(_, addr)| addr).collect())
}

/// `email.utils.parseaddr(addr)` (strict).
fn parseaddr(addr: &str) -> R<(String, String)> {
    let addr = pre_parse(addr);
    let addrs = post_parse(legacy_addresslist(&addr)?);
    if addrs.len() != 1 {
        return Ok((String::new(), String::new()));
    }
    Ok(addrs.into_iter().next().unwrap_or_default())
}

/// `smtplib.quoteaddr(addrstring)`.
pub(super) fn quoteaddr(addrstring: &str) -> R<String> {
    let (displayname, addr) = parseaddr(addrstring)?;
    if displayname.is_empty() && addr.is_empty() {
        if py_strip(addrstring).starts_with('<') {
            return Ok(addrstring.to_owned());
        }
        return Ok(format!("<{addrstring}>"));
    }
    Ok(format!("<{addr}>"))
}
