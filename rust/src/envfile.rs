//! `.env` import (docs/env-import.md §3–§5): read an environment file as data,
//! never execute it, keep only the forms on which `dotenv` (Node),
//! `python-dotenv` and Docker Compose agree, and decide per entry whether it
//! looks like a secret.
//!
//! Errors name a line and a reason code only. They never repeat the line's
//! text, and a variable name appears in output only for an entry that parsed
//! and has a value, so a token pasted without `=` cannot reach an error.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::errors::Error;
use crate::runs::MIN_PATTERN_LENGTH;
use crate::vault::MAX_SECRET_BYTES;

/// The largest file `secret import` reads.
pub const MAX_ENV_FILE_BYTES: usize = MAX_SECRET_BYTES;
/// The most assignments one file may hold, empty ones included.
pub const MAX_ENV_ENTRIES: usize = 200;
/// How many `line:reason` pairs an `env_file_invalid` error lists.
pub const MAX_REPORTED_ERRORS: usize = 50;
/// Kinds `secret import` may give a new key (no SSH keys).
pub const IMPORT_KINDS: &[&str] = &["env_var", "api_key", "password"];

/// Name pieces (split on `_`, compared upper-case) that mark a secret.
const SECRET_NAME_PARTS: &[&str] = &[
    "KEY",
    "APIKEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PWD",
    "PASS",
    "PASSPHRASE",
    "CREDENTIAL",
    "CREDENTIALS",
    "AUTH",
    "PRIVATE",
    "DSN",
    "SIGNING",
    "SALT",
    "COOKIE",
    "SESSION",
    "WEBHOOK",
];

const PLAIN_WORDS: &[&str] = &["true", "false", "yes", "no", "on", "off"];

/// One assignment with a value.
pub struct Entry {
    /// The 1-based line the assignment starts on.
    pub line: usize,
    pub name: String,
    /// The key ID: the prefix plus the name in lower case.
    pub id: String,
    pub value: Zeroizing<Vec<u8>>,
}

pub struct Parsed {
    pub entries: Vec<Entry>,
    /// Lines of assignments with an empty value (`NAME=`, `NAME=""`).
    pub empty_lines: Vec<usize>,
}

/// Whether an entry is selected by default, and why (§4).
pub fn classify(name: &str, value: &[u8]) -> (bool, &'static str) {
    if is_plain(value) {
        return (false, "plain_value");
    }
    if value.len() < MIN_PATTERN_LENGTH {
        return (false, "short_value");
    }
    if name
        .split('_')
        .any(|part| SECRET_NAME_PARTS.contains(&part.to_ascii_uppercase().as_str()))
    {
        return (true, "secret_name");
    }
    if url_with_password(value) {
        return (true, "url_password");
    }
    (false, "no_hint")
}

/// A value that a default selection never takes: rules 1 and 2 of §4.
pub fn is_short_or_plain(value: &[u8]) -> bool {
    is_plain(value) || value.len() < MIN_PATTERN_LENGTH
}

fn is_plain(value: &[u8]) -> bool {
    if !value.is_empty()
        && value
            .iter()
            .all(|b| b.is_ascii_digit() || *b == b'.' || *b == b'-')
    {
        return true;
    }
    PLAIN_WORDS
        .iter()
        .any(|word| value.eq_ignore_ascii_case(word.as_bytes()))
}

/// `scheme://[user]:password@host…`.
fn url_with_password(value: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(value) else {
        return false;
    };
    let Some((scheme, rest)) = text.split_once("://") else {
        return false;
    };
    let mut chars = scheme.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        || !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let Some((userinfo, host)) = authority.rsplit_once('@') else {
        return false;
    };
    !host.is_empty()
        && userinfo
            .split_once(':')
            .is_some_and(|(_, password)| !password.is_empty())
}

/// Checks `prefix` for `--id-prefix`: it starts a key ID, so the ID rules
/// apply, with room left for a name.
pub fn validate_prefix(prefix: &str) -> Result<(), Error> {
    if prefix.is_empty() {
        return Ok(());
    }
    let bytes = prefix.as_bytes();
    let head = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if bytes.len() >= 64
        || !head(bytes[0])
        || !bytes[1..]
            .iter()
            .all(|&b| head(b) || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(Error::invalid_input("invalid_id_prefix"));
    }
    Ok(())
}

fn key_id(prefix: &str, name: &str) -> Result<String, &'static str> {
    let id = format!("{prefix}{}", name.to_ascii_lowercase());
    if id.len() > 64 {
        return Err("name_too_long");
    }
    crate::projects::validate_name(&id, "secret_id").map_err(|_| "invalid_name")
}

fn is_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn line_of(text: &[u8], at: usize) -> usize {
    1 + text[..at].iter().filter(|&&b| b == b'\n').count()
}

fn invalid(errors: &[(usize, &'static str)]) -> Error {
    let detail = errors
        .iter()
        .take(MAX_REPORTED_ERRORS)
        .map(|(line, reason)| format!("{line}:{reason}"))
        .collect::<Vec<_>>()
        .join(",");
    Error::invalid_input("env_file_invalid").with_detail(detail)
}

/// Parse `input` and give every entry with a value its key ID. All problems
/// of one kind are reported together: file-level ones first
/// (`env_file_too_large`, `env_file_not_utf8`, `nul_byte` and lone carriage
/// returns), then every line error at once, then `id_collision`.
pub fn parse(input: &[u8], id_prefix: &str) -> Result<Parsed, Error> {
    if input.len() > MAX_ENV_FILE_BYTES {
        return Err(Error::invalid_input("env_file_too_large"));
    }
    let input = input.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(input);
    if std::str::from_utf8(input).is_err() {
        return Err(Error::invalid_input("env_file_not_utf8"));
    }
    // A NUL or a carriage return outside `\r\n` is read differently by each
    // tool (or not at all): stop before anything else.
    let mut file_errors: Vec<(usize, &'static str)> = Vec::new();
    for (at, &b) in input.iter().enumerate() {
        let reason = match b {
            0 => "nul_byte",
            b'\r' if input.get(at + 1) != Some(&b'\n') => "lone_carriage_return",
            _ => continue,
        };
        let line = line_of(input, at);
        if file_errors.last() != Some(&(line, reason)) {
            file_errors.push((line, reason));
        }
    }
    if !file_errors.is_empty() {
        return Err(invalid(&file_errors));
    }
    // `\r\n` becomes `\n`, as all three tools read it. Sized up front so the
    // copy never reallocates (and leaves) a part of the file.
    let mut text = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut at = 0;
    while at < input.len() {
        if input[at] == b'\r' {
            at += 1;
            continue;
        }
        text.push(input[at]);
        at += 1;
    }
    Parser::new(&text).run(id_prefix)
}

struct Parser<'a> {
    text: &'a [u8],
    at: usize,
    errors: Vec<(usize, &'static str)>,
}

enum Value {
    Empty,
    Bytes(Zeroizing<Vec<u8>>),
    /// The line is already reported.
    Bad,
}

impl<'a> Parser<'a> {
    fn new(text: &'a [u8]) -> Self {
        Self {
            text,
            at: 0,
            errors: Vec::new(),
        }
    }

    fn line(&self, at: usize) -> usize {
        line_of(self.text, at)
    }

    fn end_of_line(&self, from: usize) -> usize {
        self.text[from..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(self.text.len(), |n| from + n)
    }

    /// Past the end of the line `from` is on.
    fn skip_line(&mut self, from: usize) {
        self.at = (self.end_of_line(from) + 1).min(self.text.len());
    }

    fn report(&mut self, at: usize, reason: &'static str) {
        let line = self.line(at);
        self.errors.push((line, reason));
    }

    fn run(mut self, id_prefix: &str) -> Result<Parsed, Error> {
        let mut entries = Vec::new();
        let mut empty_lines = Vec::new();
        let mut names: BTreeSet<String> = BTreeSet::new();
        let mut assignments = 0usize;
        while self.at < self.text.len() {
            let start = self.at;
            let eol = self.end_of_line(start);
            let raw = &self.text[start..eol];
            let first = raw.iter().position(|&b| !is_blank(b));
            let Some(first) = first else {
                self.skip_line(start);
                continue;
            };
            if raw[first] == b'#' {
                self.skip_line(start);
                continue;
            }
            let Some(eq) = raw.iter().position(|&b| b == b'=') else {
                self.report(start, "not_assignment");
                self.skip_line(start);
                continue;
            };
            assignments += 1;
            if assignments > MAX_ENV_ENTRIES {
                return Err(Error::invalid_input("env_file_too_many_entries"));
            }
            let lhs = trim(&raw[..eq]);
            let lhs = match lhs.strip_prefix(b"export") {
                Some(rest) if rest.first().is_some_and(|&b| is_blank(b)) => trim(rest),
                _ => lhs,
            };
            let name = std::str::from_utf8(lhs).unwrap_or("");
            if !is_name(name) {
                self.report(start, "invalid_name");
                self.skip_line(start);
                continue;
            }
            let name = name.to_owned();
            let mut value_at = start + eq + 1;
            while value_at < eol && is_blank(self.text[value_at]) {
                value_at += 1;
            }
            let value = match self.text.get(value_at) {
                None | Some(b'\n') => {
                    self.skip_line(start);
                    Value::Empty
                }
                Some(b'\'') => self.single_quoted(value_at),
                Some(b'"') => self.double_quoted(value_at),
                Some(b'`') => {
                    // Skip the whole value so its other lines are not
                    // reported on their own.
                    match self.closing(value_at + 1, b'`') {
                        Some(close) => {
                            self.report(start, "backtick_quote");
                            self.skip_line(close);
                        }
                        None => {
                            self.report(start, "unterminated_quote");
                            self.at = self.text.len();
                        }
                    }
                    Value::Bad
                }
                Some(_) => self.unquoted(start, value_at, eol),
            };
            if !names.insert(name.clone()) {
                self.report(start, "duplicate_name");
                continue;
            }
            let line = self.line(start);
            match value {
                Value::Bad => {}
                Value::Empty => empty_lines.push(line),
                Value::Bytes(value) if value.is_empty() => empty_lines.push(line),
                Value::Bytes(value) => match key_id(id_prefix, &name) {
                    Ok(id) => entries.push(Entry {
                        line,
                        name,
                        id,
                        value,
                    }),
                    Err(reason) => self.errors.push((line, reason)),
                },
            }
        }
        if !self.errors.is_empty() {
            self.errors.sort();
            return Err(invalid(&self.errors));
        }
        let mut by_id: BTreeMap<&str, usize> = BTreeMap::new();
        let mut collisions: BTreeSet<&str> = BTreeSet::new();
        for entry in &entries {
            if by_id.insert(&entry.id, entry.line).is_some() {
                collisions.insert(&entry.id);
            }
        }
        if !collisions.is_empty() {
            let detail = collisions.into_iter().collect::<Vec<_>>().join(",");
            return Err(Error::invalid_input("id_collision").with_detail(detail));
        }
        Ok(Parsed {
            entries,
            empty_lines,
        })
    }

    /// The index of the next `quote` from `from`, across lines.
    fn closing(&self, from: usize, quote: u8) -> Option<usize> {
        self.text[from..]
            .iter()
            .position(|&b| b == quote)
            .map(|n| from + n)
    }

    /// After a closing quote at `close`: only blanks and an optional comment
    /// may follow on that line. Moves past the line either way.
    fn after_quote(&mut self, start: usize, close: usize) -> bool {
        let eol = self.end_of_line(close);
        let rest = &self.text[close + 1..eol];
        let ok = match rest.iter().position(|&b| !is_blank(b)) {
            None => true,
            Some(n) => rest[n] == b'#',
        };
        if !ok {
            self.report(start, "trailing_text");
        }
        self.skip_line(close);
        ok
    }

    fn single_quoted(&mut self, open: usize) -> Value {
        let start = self.line_start(open);
        let Some(close) = self.closing(open + 1, b'\'') else {
            self.report(start, "unterminated_quote");
            self.at = self.text.len();
            return Value::Bad;
        };
        let content = &self.text[open + 1..close];
        let backslash = content.contains(&b'\\');
        if backslash {
            self.report(start, "backslash_in_single_quotes");
        }
        if !self.after_quote(start, close) || backslash {
            return Value::Bad;
        }
        let mut value = Zeroizing::new(Vec::with_capacity(content.len()));
        value.extend_from_slice(content);
        Value::Bytes(value)
    }

    fn double_quoted(&mut self, open: usize) -> Value {
        let start = self.line_start(open);
        let mut value = Zeroizing::new(Vec::with_capacity(self.text.len() - open));
        let mut bad = false;
        let mut at = open + 1;
        let close = loop {
            match self.text.get(at) {
                None => {
                    self.report(start, "unterminated_quote");
                    self.at = self.text.len();
                    return Value::Bad;
                }
                Some(b'"') => break at,
                Some(b'\\') => {
                    match self.text.get(at + 1) {
                        Some(b'n') => value.push(b'\n'),
                        Some(b'r') => value.push(b'\r'),
                        _ => {
                            if !bad {
                                self.report(start, "unsupported_escape");
                            }
                            bad = true;
                        }
                    }
                    // `\"` does not close the value in any of the tools.
                    at += 2;
                }
                Some(b'$') => {
                    if !bad {
                        self.report(start, "dollar_needs_single_quotes");
                    }
                    bad = true;
                    at += 1;
                }
                Some(&b) => {
                    value.push(b);
                    at += 1;
                }
            }
        };
        if !self.after_quote(start, close) || bad {
            return Value::Bad;
        }
        Value::Bytes(value)
    }

    fn unquoted(&mut self, start: usize, value_at: usize, eol: usize) -> Value {
        self.skip_line(start);
        let rest = &self.text[value_at..eol];
        // `NAME=#x` and `NAME= #x`: Node reads an empty value, python-dotenv
        // `#x`.
        let mut end = rest.len();
        for (n, &b) in rest.iter().enumerate() {
            if b == b'#' {
                if n > 0 && is_blank(rest[n - 1]) {
                    end = n;
                    break;
                }
                self.report(start, "unquoted_hash");
                return Value::Bad;
            }
        }
        let content = trim(&rest[..end]);
        if content.contains(&b'$') {
            self.report(start, "dollar_needs_single_quotes");
            return Value::Bad;
        }
        let mut value = Zeroizing::new(Vec::with_capacity(content.len()));
        value.extend_from_slice(content);
        Value::Bytes(value)
    }

    fn line_start(&self, at: usize) -> usize {
        self.text[..at]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |n| n + 1)
    }
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| !is_blank(b))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&b| !is_blank(b))
        .map_or(start, |n| n + 1);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> Parsed {
        match parse(text.as_bytes(), "") {
            Ok(parsed) => parsed,
            Err(error) => panic!("{}: {}", error.reason, error.detail),
        }
    }

    fn values(text: &str) -> Vec<(String, String)> {
        ok(text)
            .entries
            .into_iter()
            .map(|e| (e.name, String::from_utf8(e.value.to_vec()).unwrap()))
            .collect()
    }

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    fn error(text: &str) -> (String, String) {
        match parse(text.as_bytes(), "") {
            Ok(_) => panic!("parsed: {text:?}"),
            Err(error) => (error.reason.to_string(), error.detail),
        }
    }

    #[test]
    fn reads_the_forms_the_tools_agree_on() {
        let text = "\u{feff}# comment\n\n  # indented comment\nexport OPENAI_API_KEY=sk-synthetic-0001\r\nPLAIN = some value  # note\nSQ='a b $c #d'\nDQ=\"line1\\nline2\\r\" # trailing comment\nMULTI='first\nsecond'\nDQM=\"x\ny\"\nHASH=abc #comment\nQ=\"v\"#c\n";
        assert_eq!(
            values(text),
            vec![
                pair("OPENAI_API_KEY", "sk-synthetic-0001"),
                pair("PLAIN", "some value"),
                pair("SQ", "a b $c #d"),
                pair("DQ", "line1\nline2\r"),
                pair("MULTI", "first\nsecond"),
                pair("DQM", "x\ny"),
                pair("HASH", "abc"),
                pair("Q", "v"),
            ]
        );
        let parsed = ok("A=x\nB='a'\r\nC=\nD=\"\"\nE=''\n");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.empty_lines, vec![3, 4, 5]);
        assert_eq!(parsed.entries[1].line, 2);
    }

    #[test]
    fn ambiguous_lines_stop_with_line_numbers_only() {
        let text = "TOKEN_ONLY_WITHOUT_EQUALS_synthetic\nA=abc#def\nB=$HOME\nC=\"a\\tb\"\nD='a\\b'\nE=`x`\nF=\"ok\"tail\n1BAD=x\nG=x\nG=y\nH= #x\nI=\"${X}\"\n";
        let (reason, detail) = error(text);
        assert_eq!(reason, "env_file_invalid");
        assert_eq!(
            detail,
            "1:not_assignment,2:unquoted_hash,3:dollar_needs_single_quotes,4:unsupported_escape,5:backslash_in_single_quotes,6:backtick_quote,7:trailing_text,8:invalid_name,10:duplicate_name,11:unquoted_hash,12:dollar_needs_single_quotes"
        );
        assert!(!detail.contains("synthetic"));
        assert_eq!(error("A='open\nB=x\n").1, "1:unterminated_quote");
        assert_eq!(
            error("A=\"open\\\"\n").1,
            "1:unsupported_escape,1:unterminated_quote"
        );
        assert_eq!(error("A=`x\ny`\nB=c\n").1, "1:backtick_quote");
        // a later error is still reported after a multi-line value
        assert_eq!(error("A='x\ny'\nB=a#b\n").1, "3:unquoted_hash");
    }

    #[test]
    fn file_level_limits() {
        assert_eq!(error("A=x\0y\nB=z\0\n").1, "1:nul_byte,2:nul_byte");
        assert_eq!(error("A=x\rB=y\n").1, "1:lone_carriage_return");
        assert_eq!(
            parse(b"A=\xff\xfe", "").err().unwrap().reason,
            "env_file_not_utf8"
        );
        let big = vec![b'#'; MAX_ENV_FILE_BYTES + 1];
        assert_eq!(parse(&big, "").err().unwrap().reason, "env_file_too_large");
        let many: String = (0..=MAX_ENV_ENTRIES).map(|n| format!("V{n}=\n")).collect();
        assert_eq!(
            parse(many.as_bytes(), "").err().unwrap().reason,
            "env_file_too_many_entries"
        );
        let most: String = (0..MAX_ENV_ENTRIES).map(|n| format!("V{n}=\n")).collect();
        assert_eq!(ok(&most).empty_lines.len(), MAX_ENV_ENTRIES);
        let errors: String = (0..80).map(|n| format!("bad line {n}\n")).collect();
        assert_eq!(error(&errors).1.split(',').count(), MAX_REPORTED_ERRORS);
    }

    #[test]
    fn key_ids_follow_the_id_rules() {
        let parsed = parse(b"OPENAI_API_KEY=sk-synthetic-0002\n", "prod.").unwrap();
        assert_eq!(parsed.entries[0].id, "prod.openai_api_key");
        assert_eq!(error("_PRIVATE=abcdefgh\n").1, "1:invalid_name");
        let long = format!("{}=abcdefgh\n", "A".repeat(65));
        assert_eq!(error(&long).1, "1:name_too_long");
        // an empty value makes no key, so its name is not checked
        assert!(ok("_EMPTY=\n").entries.is_empty());
        let (reason, detail) = error("Token=abcdefgh1\nTOKEN=abcdefgh2\n");
        assert_eq!(
            (reason.as_str(), detail.as_str()),
            ("id_collision", "token")
        );
        assert!(validate_prefix("dev-").is_ok());
        assert!(validate_prefix("Dev").is_err());
        assert!(validate_prefix("-x").is_err());
        assert!(validate_prefix(&"a".repeat(64)).is_err());
    }

    #[test]
    fn shell_syntax_is_never_run() {
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join("ran");
        let text = format!(
            "A='$(touch {m})'\nB=$(touch {m})\nC=`touch {m}`\nD=\"$(touch {m})\"\n",
            m = marker.display()
        );
        assert_eq!(error(&text).0, "env_file_invalid");
        let parsed = ok(&format!("A='$(touch {})'\n", marker.display()));
        assert_eq!(parsed.entries.len(), 1);
        assert!(!marker.exists());
    }

    #[test]
    fn default_selection() {
        let cases = [
            ("OPENAI_API_KEY", "sk-synthetic-0003", true, "secret_name"),
            ("AUTH_ENABLED", "true", false, "plain_value"),
            ("TOKEN_TTL", "3600", false, "plain_value"),
            ("VERSION", "1.2.3-4", false, "plain_value"),
            ("DB_PASSWORD", "short", false, "short_value"),
            ("stripeApiKey", "sk-synthetic-0004", false, "no_hint"),
            ("APIKEY", "sk-synthetic-0004", true, "secret_name"),
            (
                "SENTRY_DSN",
                "https://synthetic@sentry.example/1",
                true,
                "secret_name",
            ),
            (
                "DATABASE_URL",
                "postgres://app:synthetic-pw@db.example:5432/app",
                true,
                "url_password",
            ),
            (
                "REDIS_URL",
                "redis://:synthetic-pw@cache.example:6379",
                true,
                "url_password",
            ),
            (
                "PUBLIC_URL",
                "https://user@example.com/path",
                false,
                "no_hint",
            ),
            ("HOME_URL", "https://example.com/a:b@c", false, "no_hint"),
            ("NODE_ENV", "production", false, "no_hint"),
            ("KEYBOARD_LAYOUT", "dvorak-programmer", false, "no_hint"),
        ];
        for (name, value, selected, why) in cases {
            assert_eq!(classify(name, value.as_bytes()), (selected, why), "{name}");
        }
        assert!(is_short_or_plain(b"off"));
        assert!(!is_short_or_plain(b"sk-synthetic-0005"));
    }
}
