//! [`AppError`]: the single error shape that crosses IPC (`{error, reason, detail?}`, see
//! desktop/src/ipc/contract.ts). Errors from `zeropw-admin` are rebuilt from its stderr JSON;
//! the core never puts an input value into an error, and drops a CLI `detail` that contains any
//! secret the call handed over.

use std::fmt;
use std::io;

use serde::{Deserialize, Serialize};

const MAX_DETAIL_CHARS: usize = 300;
const MAX_CODE_CHARS: usize = 64;

/// `{error, reason, detail?}`: error class, stable reason code, value-free detail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppError {
    pub error: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AppError {
    pub fn new(error: &str, reason: &str) -> Self {
        Self {
            error: error.to_owned(),
            reason: reason.to_owned(),
            detail: None,
        }
    }

    /// Attach a value-free detail (a flag name, a count, an exit status; never an input value).
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn invalid_input(reason: &str) -> Self {
        Self::new("InvalidInput", reason)
    }

    pub fn not_found(reason: &str) -> Self {
        Self::new("NotFound", reason)
    }

    pub fn auth_failed(reason: &str) -> Self {
        Self::new("AuthFailed", reason)
    }

    pub fn unavailable(reason: &str) -> Self {
        Self::new("Unavailable", reason)
    }

    pub fn timeout(reason: &str) -> Self {
        Self::new("Timeout", reason)
    }

    pub fn internal(reason: &str) -> Self {
        Self::new("InternalError", reason)
    }

    pub fn state(reason: &str) -> Self {
        Self::new("StateError", reason)
    }

    /// An I/O failure, described by its kind only (no path, no OS message with a path in it).
    pub fn io(reason: &str, error: &io::Error) -> Self {
        Self::new("IoError", reason).with_detail(format!("{:?}", error.kind()))
    }

    /// Rebuild the error `zeropw-admin` printed on stderr. The CLI prints argparse usage text
    /// before its JSON line on usage errors, so the last line that is a JSON object with string
    /// `error` and `reason` codes wins; everything else on stderr is discarded. A `detail` is
    /// kept only when it is a string that contains none of `secrets`.
    pub fn from_admin_stderr(stderr: &[u8], secrets: &[&str]) -> Option<Self> {
        let text = String::from_utf8_lossy(stderr);
        text.lines().rev().find_map(|line| {
            let line = line.trim();
            if !line.starts_with('{') {
                return None;
            }
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            let object = value.as_object()?;
            let error = object.get("error")?.as_str()?;
            let reason = object.get("reason")?.as_str()?;
            if !is_code(error) || !is_code(reason) {
                return None;
            }
            let mut out = Self::new(error, reason);
            match object.get("detail") {
                Some(serde_json::Value::String(detail)) => {
                    out.detail = sanitize_detail(detail, secrets);
                }
                Some(serde_json::Value::Object(fields)) => out.detail = fingerprint_detail(fields),
                _ => {}
            }
            Some(out)
        })
    }
}

/// An object `detail` keeps only its `*_fingerprint` fields with device fingerprint values
/// (`team join` failing with `join_pending_approval` carries `self_fingerprint` and
/// `inviter_fingerprint`, docs/remote-sync.md §3.2), as compact JSON with sorted keys. Those are
/// public identifiers the user compares on both screens; any other field is dropped.
fn fingerprint_detail(fields: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    let kept: std::collections::BTreeMap<&str, &str> = fields
        .iter()
        .filter(|(key, _)| key.ends_with("_fingerprint") && key.len() <= MAX_CODE_CHARS)
        .filter_map(|(key, value)| Some((key.as_str(), value.as_str()?)))
        .filter(|(_, value)| is_fingerprint(value))
        .collect();
    if kept.is_empty() {
        return None;
    }
    serde_json::to_string(&kept).ok()
}

/// A team device fingerprint: 26 characters of lowercase unpadded base32
/// (rust/src/team/identity.rs `fingerprint`).
pub fn is_fingerprint(text: &str) -> bool {
    text.len() == 26 && text.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

/// Error classes and reason codes are short identifiers; anything else is not a CLI error line.
pub(crate) fn is_code(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_CODE_CHARS
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Control characters become spaces, the text is bounded, and a detail that contains any of
/// the call's secrets is dropped entirely (the error class and reason still reach the UI).
pub(crate) fn sanitize_detail(detail: &str, secrets: &[&str]) -> Option<String> {
    if detail.is_empty() {
        return None;
    }
    if secrets
        .iter()
        .any(|secret| !secret.is_empty() && detail.contains(secret))
    {
        return None;
    }
    let cleaned: String = detail
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_DETAIL_CHARS)
        .collect();
    let cleaned = cleaned.trim().to_owned();
    (!cleaned.is_empty()).then_some(cleaned)
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error, self.reason)?;
        if let Some(detail) = &self.detail {
            write!(f, " ({detail})")?;
        }
        Ok(())
    }
}

impl std::error::Error for AppError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_last_json_line_after_usage_text() {
        let stderr = b"usage: zeropw-admin [-h] --state-dir DIR COMMAND ...\n{\"detail\":\"unrecognized arguments: 1; values are not echoed\",\"error\":\"UsageError\",\"reason\":\"usage\"}\n";
        let e = AppError::from_admin_stderr(stderr, &[]).unwrap();
        assert_eq!(e.error, "UsageError");
        assert_eq!(e.reason, "usage");
        assert_eq!(
            e.detail.as_deref(),
            Some("unrecognized arguments: 1; values are not echoed")
        );
    }

    #[test]
    fn drops_detail_that_contains_a_secret() {
        let stderr = br#"{"error":"AuthFailed","reason":"bad_passphrase","detail":"got synthetic-pass-123"}"#;
        let e = AppError::from_admin_stderr(stderr, &["synthetic-pass-123"]).unwrap();
        assert_eq!(e.reason, "bad_passphrase");
        assert_eq!(e.detail, None);
        assert!(!e.to_string().contains("synthetic-pass-123"));
    }

    #[test]
    fn rejects_lines_that_are_not_cli_errors() {
        assert!(AppError::from_admin_stderr(b"plain text\n", &[]).is_none());
        assert!(AppError::from_admin_stderr(br#"{"error":1,"reason":"x"}"#, &[]).is_none());
        assert!(AppError::from_admin_stderr(br#"{"error":"A B","reason":"x"}"#, &[]).is_none());
        assert!(AppError::from_admin_stderr(br#"{"error":"A"}"#, &[]).is_none());
        assert!(AppError::from_admin_stderr(b"", &[]).is_none());
    }

    #[test]
    fn an_object_detail_keeps_only_fingerprints() {
        let stderr = br#"{"error":"StateError","reason":"join_pending_approval","detail":{"self_fingerprint":"abcdefghijklmnopqrstuvwxyz","inviter_fingerprint":"zyxwvutsrqponmlkjihgfedcba","invite":"synthetic-invite-secret","note_fingerprint":"not a fingerprint"}}"#;
        let e = AppError::from_admin_stderr(stderr, &[]).unwrap();
        assert_eq!(e.reason, "join_pending_approval");
        assert_eq!(
            e.detail.as_deref(),
            Some(
                r#"{"inviter_fingerprint":"zyxwvutsrqponmlkjihgfedcba","self_fingerprint":"abcdefghijklmnopqrstuvwxyz"}"#
            )
        );
        assert!(!e.to_string().contains("synthetic-invite-secret"));
        let only_other = br#"{"error":"X","reason":"y","detail":{"invite":"synthetic"}}"#;
        assert_eq!(
            AppError::from_admin_stderr(only_other, &[]).unwrap().detail,
            None
        );
        let upper = br#"{"error":"X","reason":"y","detail":{"self_fingerprint":"ABCDEFGHIJKLMNOPQRSTUVWXYZ"}}"#;
        assert_eq!(
            AppError::from_admin_stderr(upper, &[]).unwrap().detail,
            None
        );
    }

    #[test]
    fn detail_is_bounded_and_control_free() {
        let long = "x".repeat(1000);
        assert_eq!(sanitize_detail(&long, &[]).unwrap().len(), MAX_DETAIL_CHARS);
        assert_eq!(sanitize_detail("a\nb\u{1b}c", &[]).unwrap(), "a b c");
        assert_eq!(sanitize_detail("   ", &[]), None);
        assert_eq!(sanitize_detail("ok", &[""]).as_deref(), Some("ok"));
    }

    #[test]
    fn serializes_without_empty_detail() {
        let v = serde_json::to_value(AppError::invalid_input("invalid_name")).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"error":"InvalidInput","reason":"invalid_name"})
        );
        let v = serde_json::to_value(AppError::not_found("x").with_detail("--id")).unwrap();
        assert_eq!(v["detail"], "--id");
    }
}
