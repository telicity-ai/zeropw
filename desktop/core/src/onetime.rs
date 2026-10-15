//! [`OneTimeStore`] (docs/desktop-app.md §4.3): recovery codes, caller tokens, invite links,
//! pasted invites and revealed secret values are held briefly in wiped buffers and handed out
//! by random 128-bit references. Showing a value removes it. Revealed secrets live 60 s,
//! everything else 10 minutes. Entries have a kind, so a reference minted for one purpose
//! (a revealed value) can never be redeemed for another (a terminal token).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::error::AppError;
use crate::secret::SecretString;

pub const SECRET_TTL: Duration = Duration::from_secs(60);
pub const DEFAULT_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_ENTRIES: usize = 256;

/// What a stored value is, which fixes its lifetime and who may redeem it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OneTimeKind {
    /// A generated recovery code, redeemed by `vault_init`.
    RecoveryCode,
    /// A principal's caller token, shown once and injected into the in-app terminal.
    CallerToken,
    /// A `zeropw://join#…` link created by this device.
    InviteLink,
    /// An invite pasted or deep-linked on the joining side; redeemed only by `team_join`.
    InviteText,
    /// One secret version revealed after re-authentication.
    RevealedSecret,
}

impl OneTimeKind {
    pub fn ttl(self) -> Duration {
        match self {
            OneTimeKind::RevealedSecret => SECRET_TTL,
            _ => DEFAULT_TTL,
        }
    }

    /// Kinds `onetime_show`/`onetime_copy` may hand to the webview. A pasted invite stays in
    /// Rust: the webview already had it, and only `team_join` needs it again.
    pub fn showable(self) -> bool {
        !matches!(self, OneTimeKind::InviteText)
    }
}

struct Entry {
    kind: OneTimeKind,
    value: SecretString,
    expires_at: Instant,
}

type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// Short-lived single-use values keyed by unguessable references. No `Debug` or `Serialize`
/// on the values; the store's own `Debug` prints only a count.
pub struct OneTimeStore {
    entries: Mutex<HashMap<String, Entry>>,
    now: Clock,
}

impl Default for OneTimeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for OneTimeStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneTimeStore")
            .field("entries", &self.lock().len())
            .finish()
    }
}

impl OneTimeStore {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(Instant::now))
    }

    /// A store with an injected clock (tests advance it to check expiry).
    pub fn with_clock(now: Clock) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            now,
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn locked_live(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        let now = (self.now)();
        let mut entries = self.lock();
        entries.retain(|_, entry| entry.expires_at > now);
        entries
    }

    /// Store `value` and return its reference (32 hex characters, 128 random bits).
    pub fn put(&self, kind: OneTimeKind, value: SecretString) -> Result<String, AppError> {
        let reference = random_ref()?;
        let expires_at = (self.now)() + kind.ttl();
        let mut entries = self.locked_live();
        if entries.len() >= MAX_ENTRIES {
            return Err(AppError::unavailable("onetime_store_full"));
        }
        entries.insert(
            reference.clone(),
            Entry {
                kind,
                value,
                expires_at,
            },
        );
        Ok(reference)
    }

    /// `onetime_show`: remove and return a showable value. Unknown, expired, already shown and
    /// non-showable references all fail the same way.
    pub fn take_showable(&self, reference: &str) -> Result<(OneTimeKind, SecretString), AppError> {
        check_ref(reference)?;
        let mut entries = self.locked_live();
        match entries.get(reference) {
            Some(entry) if entry.kind.showable() => {}
            _ => return Err(unknown()),
        }
        let entry = entries.remove(reference).ok_or_else(unknown)?;
        Ok((entry.kind, entry.value))
    }

    /// A copy of a showable value, leaving it in place (`onetime_copy` removes it only after
    /// the clipboard write succeeded).
    pub fn peek_showable(&self, reference: &str) -> Result<SecretString, AppError> {
        check_ref(reference)?;
        let entries = self.locked_live();
        match entries.get(reference) {
            Some(entry) if entry.kind.showable() => Ok(entry.value.duplicate()),
            _ => Err(unknown()),
        }
    }

    /// Remove and return a value of `kind`. A reference of another kind is left untouched.
    pub fn take_kind(&self, reference: &str, kind: OneTimeKind) -> Result<SecretString, AppError> {
        check_ref(reference)?;
        let mut entries = self.locked_live();
        match entries.get(reference) {
            Some(entry) if entry.kind == kind => {}
            _ => return Err(unknown()),
        }
        entries
            .remove(reference)
            .map(|entry| entry.value)
            .ok_or_else(unknown)
    }

    /// A copy of a value of `kind` for use inside Rust, leaving the entry in place (a terminal
    /// using a token that the user may still want to copy; a recovery code whose `init` might
    /// fail and be retried).
    pub fn peek_kind(&self, reference: &str, kind: OneTimeKind) -> Result<SecretString, AppError> {
        check_ref(reference)?;
        let entries = self.locked_live();
        match entries.get(reference) {
            Some(entry) if entry.kind == kind => Ok(entry.value.duplicate()),
            _ => Err(unknown()),
        }
    }

    /// `onetime_discard`: forget a value. Idempotent.
    pub fn discard(&self, reference: &str) {
        self.lock().remove(reference);
    }

    /// Live entries.
    pub fn len(&self) -> usize {
        self.locked_live().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop everything (app shutdown, vault lock).
    pub fn clear(&self) {
        self.lock().clear();
    }
}

fn unknown() -> AppError {
    AppError::not_found("onetime_ref_unknown")
}

fn check_ref(reference: &str) -> Result<(), AppError> {
    if reference.len() == 32
        && reference
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(AppError::invalid_input("onetime_ref_invalid"))
    }
}

/// 128 bits from the OS CSPRNG as lowercase hex.
pub(crate) fn random_ref() -> Result<String, AppError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| AppError::unavailable("csprng_unavailable"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

crate::assert_not_impl!(Entry: std::fmt::Debug);
crate::assert_not_impl!(Entry: serde::Serialize);

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn store_with_clock() -> (OneTimeStore, Arc<AtomicU64>) {
        let base = Instant::now();
        let offset = Arc::new(AtomicU64::new(0));
        let o = offset.clone();
        let store = OneTimeStore::with_clock(Arc::new(move || {
            base + Duration::from_secs(o.load(Ordering::SeqCst))
        }));
        (store, offset)
    }

    #[test]
    fn values_are_single_use() {
        let store = OneTimeStore::new();
        let r = store
            .put(OneTimeKind::CallerToken, "zpw_synthetic".into())
            .unwrap();
        assert_eq!(r.len(), 32);
        let (kind, value) = store.take_showable(&r).unwrap();
        assert_eq!(kind, OneTimeKind::CallerToken);
        assert_eq!(value.expose(), "zpw_synthetic");
        assert_eq!(
            store.take_showable(&r).err().unwrap().reason,
            "onetime_ref_unknown"
        );
        assert!(store.is_empty());
    }

    #[test]
    fn refs_are_random_and_validated() {
        let store = OneTimeStore::new();
        let a = store.put(OneTimeKind::InviteLink, "a".into()).unwrap();
        let b = store.put(OneTimeKind::InviteLink, "b".into()).unwrap();
        assert_ne!(a, b);
        for bad in ["", "zz", &"A".repeat(32), &"0".repeat(31), &"0".repeat(33)] {
            assert_eq!(
                store.take_showable(bad).err().unwrap().reason,
                "onetime_ref_invalid"
            );
        }
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn revealed_secrets_expire_after_60s_others_after_10min() {
        let (store, clock) = store_with_clock();
        let secret = store
            .put(OneTimeKind::RevealedSecret, "synthetic-v".into())
            .unwrap();
        let token = store
            .put(OneTimeKind::CallerToken, "zpw_synthetic".into())
            .unwrap();
        clock.store(59, Ordering::SeqCst);
        assert_eq!(store.len(), 2);
        clock.store(60, Ordering::SeqCst);
        assert!(store.take_showable(&secret).is_err());
        assert_eq!(store.len(), 1);
        clock.store(599, Ordering::SeqCst);
        assert!(store.peek_kind(&token, OneTimeKind::CallerToken).is_ok());
        clock.store(600, Ordering::SeqCst);
        assert!(store.take_showable(&token).is_err());
        assert!(store.is_empty());
    }

    #[test]
    fn kinds_cannot_be_crossed() {
        let store = OneTimeStore::new();
        let revealed = store
            .put(OneTimeKind::RevealedSecret, "synthetic-v".into())
            .unwrap();
        assert!(
            store
                .peek_kind(&revealed, OneTimeKind::CallerToken)
                .is_err()
        );
        assert!(store.take_kind(&revealed, OneTimeKind::InviteText).is_err());
        // The failed redemptions did not consume it.
        assert_eq!(
            store
                .take_kind(&revealed, OneTimeKind::RevealedSecret)
                .unwrap()
                .expose(),
            "synthetic-v"
        );

        let pasted = store
            .put(OneTimeKind::InviteText, "zeropw://join#X".into())
            .unwrap();
        assert!(store.take_showable(&pasted).is_err());
        assert!(store.peek_kind(&pasted, OneTimeKind::InviteText).is_ok());
    }

    #[test]
    fn peek_keeps_and_discard_removes() {
        let store = OneTimeStore::new();
        let r = store
            .put(OneTimeKind::RecoveryCode, "AAAA-BBBB".into())
            .unwrap();
        assert_eq!(
            store
                .peek_kind(&r, OneTimeKind::RecoveryCode)
                .unwrap()
                .expose(),
            "AAAA-BBBB"
        );
        assert_eq!(store.len(), 1);
        store.discard(&r);
        store.discard(&r);
        assert!(store.is_empty());
        assert_eq!(format!("{store:?}"), "OneTimeStore { entries: 0 }");
    }

    #[test]
    fn store_is_bounded() {
        let store = OneTimeStore::new();
        for _ in 0..MAX_ENTRIES {
            store.put(OneTimeKind::InviteLink, "x".into()).unwrap();
        }
        assert_eq!(
            store
                .put(OneTimeKind::InviteLink, "x".into())
                .unwrap_err()
                .reason,
            "onetime_store_full"
        );
    }
}
