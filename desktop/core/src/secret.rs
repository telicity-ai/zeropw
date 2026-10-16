//! [`SecretString`]: the only type the core uses for passphrases, tokens, invite links and
//! revealed values. It is zeroized on drop and deliberately implements none of `Debug`,
//! `Display`, `Clone` or `Serialize`, so a secret cannot reach a log line, an error, an event
//! payload or an IPC response by accident. Reading it takes an explicit [`SecretString::expose`].

use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

/// A zeroize-on-drop string with no formatting or serialization.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wrap an owned string. The string's buffer is wiped when the value is dropped.
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The secret text. Call sites are the places a secret leaves the core.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// An explicit second copy (also zeroized on drop). `Clone` is not implemented on purpose.
    pub fn duplicate(&self) -> Self {
        Self::new(self.0.as_str().to_owned())
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

/// Inputs (IPC payloads, CLI stdout) deserialize straight into a `SecretString`; there is no
/// `Serialize`, so it can never be written back out.
impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Zeroizing::<String>::deserialize(deserializer).map(Self)
    }
}

/// Compile-time proof that a type does NOT implement a trait (the ambiguity trick used by
/// `static_assertions::assert_not_impl_any!`): if the type implemented the trait, the two
/// blanket impls would both apply and `some_item` would be ambiguous.
#[macro_export]
#[doc(hidden)]
macro_rules! assert_not_impl {
    ($ty:ty: $($tr:path),+ $(,)?) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            $(
                {
                    #[allow(dead_code)]
                    struct Invalid;
                    impl<T: ?Sized + $tr> AmbiguousIfImpl<Invalid> for T {}
                }
            )+
            let _ = <$ty as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

assert_not_impl!(SecretString: std::fmt::Debug);
assert_not_impl!(SecretString: std::fmt::Display);
assert_not_impl!(SecretString: Clone);
assert_not_impl!(SecretString: serde::Serialize);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_from_json_and_exposes_only_explicitly() {
        let s: SecretString = serde_json::from_str("\"synthetic-pass-1\"").unwrap();
        assert_eq!(s.expose(), "synthetic-pass-1");
        assert_eq!(s.len(), 16);
        assert!(!s.is_empty());
        let d = s.duplicate();
        drop(s);
        assert_eq!(d.expose(), "synthetic-pass-1");
    }

    #[test]
    fn rejects_non_string_json() {
        assert!(serde_json::from_str::<SecretString>("12").is_err());
        assert!(serde_json::from_str::<SecretString>("null").is_err());
    }
}
