//! Port of `zeropw/errors.py`.
//!
//! Python models errors as a class hierarchy; callers `except StateError` to
//! catch subclasses such as `KmsError`. Rust keeps that as two fields:
//! [`ErrorClass`] is what a caller matches on (the Python base class it would
//! catch), and `name` is `type(self).__name__`, which `to_dict` exposes.
//! Every error carries a value-free `reason` code and an optional `detail`
//! built only from fixed strings and identifiers — never secret material.

use std::borrow::Cow;
use std::fmt;

use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorClass {
    ZeroPW,
    InvalidInput,
    NotFound,
    AuthFailed,
    PolicyDenied,
    Unsupported,
    AuditUnavailable,
    StateError,
}

impl ErrorClass {
    /// The Python class name for this class.
    pub fn class_name(self) -> &'static str {
        match self {
            ErrorClass::ZeroPW => "ZeroPWError",
            ErrorClass::InvalidInput => "InvalidInput",
            ErrorClass::NotFound => "NotFound",
            ErrorClass::AuthFailed => "AuthFailed",
            ErrorClass::PolicyDenied => "PolicyDenied",
            ErrorClass::Unsupported => "Unsupported",
            ErrorClass::AuditUnavailable => "AuditUnavailable",
            ErrorClass::StateError => "StateError",
        }
    }

    /// The class-level default `reason` used when none is given.
    pub fn default_reason(self) -> &'static str {
        match self {
            ErrorClass::ZeroPW => "zeropw_error",
            ErrorClass::InvalidInput => "invalid_input",
            ErrorClass::NotFound => "not_found",
            ErrorClass::AuthFailed => "auth_failed",
            ErrorClass::PolicyDenied => "policy_denied",
            ErrorClass::Unsupported => "unsupported",
            ErrorClass::AuditUnavailable => "audit_unavailable",
            ErrorClass::StateError => "state_error",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Error {
    pub class: ErrorClass,
    /// `type(self).__name__` — equals `class.class_name()` except for
    /// subclasses such as `KmsError`.
    pub name: Cow<'static, str>,
    pub reason: Cow<'static, str>,
    pub detail: String,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// `Class(reason, detail)`; an empty `reason` falls back to the class default,
    /// exactly like Python's `if reason: self.reason = reason`.
    pub fn new(class: ErrorClass, reason: impl Into<Cow<'static, str>>, detail: impl Into<String>) -> Self {
        let reason = reason.into();
        let reason = if reason.is_empty() { Cow::Borrowed(class.default_reason()) } else { reason };
        Error { class, name: Cow::Borrowed(class.class_name()), reason, detail: detail.into() }
    }

    /// A subclass instance: `name` differs from the base class name.
    pub fn subclass(
        class: ErrorClass,
        name: &'static str,
        reason: impl Into<Cow<'static, str>>,
        detail: impl Into<String>,
    ) -> Self {
        let mut err = Error::new(class, reason, detail);
        err.name = Cow::Borrowed(name);
        err
    }

    pub fn invalid_input(reason: impl Into<Cow<'static, str>>) -> Self {
        Error::new(ErrorClass::InvalidInput, reason, "")
    }
    pub fn not_found(reason: impl Into<Cow<'static, str>>) -> Self {
        Error::new(ErrorClass::NotFound, reason, "")
    }
    pub fn auth_failed(reason: impl Into<Cow<'static, str>>) -> Self {
        Error::new(ErrorClass::AuthFailed, reason, "")
    }
    pub fn policy_denied(reason: impl Into<Cow<'static, str>>) -> Self {
        Error::new(ErrorClass::PolicyDenied, reason, "")
    }
    pub fn unsupported(reason: impl Into<Cow<'static, str>>) -> Self {
        Error::new(ErrorClass::Unsupported, reason, "")
    }
    pub fn audit_unavailable(reason: impl Into<Cow<'static, str>>) -> Self {
        Error::new(ErrorClass::AuditUnavailable, reason, "")
    }
    pub fn state(reason: impl Into<Cow<'static, str>>) -> Self {
        Error::new(ErrorClass::StateError, reason, "")
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn is(&self, class: ErrorClass) -> bool {
        self.class == class
    }

    /// `str(exc)`: `reason` or `reason: detail`.
    pub fn message(&self) -> String {
        if self.detail.is_empty() { self.reason.to_string() } else { format!("{}: {}", self.reason, self.detail) }
    }

    /// `ZeroPWError.to_dict()`.
    pub fn to_dict(&self) -> Value {
        let mut payload = Map::new();
        payload.insert("error".into(), Value::String(self.name.to_string()));
        payload.insert("reason".into(), Value::String(self.reason.to_string()));
        if !self.detail.is_empty() {
            payload.insert("detail".into(), Value::String(self.detail.clone()));
        }
        Value::Object(payload)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.name, self.message())
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_reason_and_message() {
        let err = Error::new(ErrorClass::NotFound, "", "");
        assert_eq!(err.reason, "not_found");
        assert_eq!(err.message(), "not_found");
        let err = Error::new(ErrorClass::StateError, "state_missing", "/tmp/x");
        assert_eq!(err.message(), "state_missing: /tmp/x");
        assert_eq!(err.to_dict()["detail"], "/tmp/x");
    }

    #[test]
    fn subclass_keeps_base_class_for_matching() {
        let err = Error::subclass(ErrorClass::StateError, "KmsError", "kms_missing", "");
        assert!(err.is(ErrorClass::StateError));
        assert_eq!(err.to_dict()["error"], "KmsError");
        assert!(err.to_dict().get("detail").is_none());
    }
}
