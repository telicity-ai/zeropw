//! [`OneTimeStore`] (docs/desktop-app.md §4.3): recovery codes, caller tokens, invite links,
//! pasted invites and revealed secret values are held briefly in wiped buffers and handed out
//! by random 128-bit references. Showing a value removes it. Revealed secrets live 60 s,
//! pasted and deep-linked invites 60 minutes (an invitee previews the link first, then makes a
//! vault, then joins), everything else 10 minutes. Entries have a kind, so a reference minted
//! for one purpose (a revealed value) can never be redeemed for another (a terminal token).
//!
//! Capacity: at most [`MAX_ENTRIES`] values the app made (codes, tokens, links, revealed
//! values), counting [`Reservation`]s. A command whose CLI call changes state and prints a
//! value only once (a caller token, an invite link, a revealed value with its audit record)
//! reserves its slot before it runs the CLI, so a full store refuses it before anything
//! happens instead of losing the value afterwards. Pasted and deep-linked invites have their
//! own pool of [`MAX_INVITE_TEXTS`]; the oldest is dropped for a new one, so links opened from
//! outside the app can never take the room the app's own values need. A joined invite is
//! removed at once (`team_join`).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::error::AppError;
use crate::secret::SecretString;

pub const SECRET_TTL: Duration = Duration::from_secs(60);
/// A pasted or deep-linked invite: long enough to preview it, make a vault and then join.
pub const INVITE_TEXT_TTL: Duration = Duration::from_secs(60 * 60);
pub const DEFAULT_TTL: Duration = Duration::from_secs(10 * 60);
/// Values the app made, live or reserved.
pub const MAX_ENTRIES: usize = 256;
/// Pasted or deep-linked invites kept for `team_join`; the oldest goes first.
pub const MAX_INVITE_TEXTS: usize = 16;

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
            OneTimeKind::InviteText => INVITE_TEXT_TTL,
            _ => DEFAULT_TTL,
        }
    }

    /// Kinds `onetime_show`/`onetime_copy` may hand to the webview. A pasted invite stays in
    /// Rust: the webview already had it, and only `team_join` needs it again. A recovery code
    /// also stays: `recovery_generate` already returned its groups, once, and only
    /// `vault_init` reads it again.
    pub fn showable(self) -> bool {
        !matches!(self, OneTimeKind::InviteText | OneTimeKind::RecoveryCode)
    }
}

struct Entry {
    kind: OneTimeKind,
    value: SecretString,
    /// A value-free note about the entry (the principal a caller token belongs to).
    label: Option<String>,
    expires_at: Instant,
    /// Insertion order (which invite is the oldest).
    seq: u64,
}

type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

#[derive(Default)]
struct Entries {
    map: HashMap<String, Entry>,
    /// Slots held by live [`Reservation`]s.
    reserved: usize,
}

impl Entries {
    /// Room for one more value the app made (anything but an `InviteText`).
    fn has_room(&self) -> bool {
        let made = self
            .map
            .values()
            .filter(|e| e.kind != OneTimeKind::InviteText)
            .count();
        made + self.reserved < MAX_ENTRIES
    }

    /// Drop the oldest invites until one more fits in their pool.
    fn make_room_for_invite(&mut self) {
        loop {
            let invites = self
                .map
                .iter()
                .filter(|(_, e)| e.kind == OneTimeKind::InviteText);
            if invites.clone().count() < MAX_INVITE_TEXTS {
                return;
            }
            let oldest = invites
                .min_by_key(|(_, e)| (e.expires_at, e.seq))
                .map(|(reference, _)| reference.clone());
            match oldest {
                Some(reference) => {
                    self.map.remove(&reference);
                }
                None => return,
            }
        }
    }
}

/// Short-lived single-use values keyed by unguessable references. No `Debug` or `Serialize`
/// on the values; the store's own `Debug` prints only a count.
pub struct OneTimeStore {
    entries: Mutex<Entries>,
    now: Clock,
    next_seq: std::sync::atomic::AtomicU64,
}

/// A slot held in the store for a value that does not exist yet (see the module docs). Fill
/// it with [`Reservation::fill`]; dropping it unfilled gives the slot back.
pub struct Reservation<'a> {
    store: &'a OneTimeStore,
    kind: OneTimeKind,
    /// Counted in `Entries::reserved`. Never for an invite, which has its own evicting pool.
    held: bool,
}

impl Reservation<'_> {
    /// Store the value in the reserved slot and return its reference.
    pub fn fill(self, value: SecretString) -> Result<String, AppError> {
        self.fill_with(value, None)
    }

    /// [`Self::fill`] with a value-free label (see [`OneTimeStore::put_labeled`]).
    pub fn fill_labeled(self, value: SecretString, label: &str) -> Result<String, AppError> {
        self.fill_with(value, Some(label.to_owned()))
    }

    fn fill_with(mut self, value: SecretString, label: Option<String>) -> Result<String, AppError> {
        let reference = random_ref()?;
        let expires_at = (self.store.now)() + self.kind.ttl();
        let seq = self.store.seq();
        let mut entries = self.store.locked_live();
        if self.held {
            entries.reserved = entries.reserved.saturating_sub(1);
            self.held = false;
        } else {
            entries.make_room_for_invite();
        }
        entries.map.insert(
            reference.clone(),
            Entry {
                kind: self.kind,
                value,
                label,
                expires_at,
                seq,
            },
        );
        Ok(reference)
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.held {
            let mut entries = self.store.lock();
            entries.reserved = entries.reserved.saturating_sub(1);
        }
    }
}

impl Default for OneTimeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for OneTimeStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneTimeStore")
            .field("entries", &self.lock().map.len())
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
            entries: Mutex::new(Entries::default()),
            now,
            next_seq: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Entries> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn locked_live(&self) -> MutexGuard<'_, Entries> {
        let now = (self.now)();
        let mut entries = self.lock();
        entries.map.retain(|_, entry| entry.expires_at > now);
        entries
    }

    fn seq(&self) -> u64 {
        self.next_seq
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Hold a slot for a value of `kind` that a CLI call is about to print (module docs).
    /// Fails with `onetime_store_full` while the store is full, before anything has run.
    pub fn reserve(&self, kind: OneTimeKind) -> Result<Reservation<'_>, AppError> {
        let mut entries = self.locked_live();
        if kind != OneTimeKind::InviteText {
            if !entries.has_room() {
                return Err(full());
            }
            entries.reserved += 1;
        }
        Ok(Reservation {
            store: self,
            kind,
            held: kind != OneTimeKind::InviteText,
        })
    }

    /// Store `value` and return its reference (32 hex characters, 128 random bits).
    pub fn put(&self, kind: OneTimeKind, value: SecretString) -> Result<String, AppError> {
        self.insert(kind, value, None)
    }

    /// [`Self::put`] with a value-free label kept next to the value (a caller token remembers
    /// its principal, so a terminal opened with it can say whose it is).
    pub fn put_labeled(
        &self,
        kind: OneTimeKind,
        value: SecretString,
        label: &str,
    ) -> Result<String, AppError> {
        self.insert(kind, value, Some(label.to_owned()))
    }

    fn insert(
        &self,
        kind: OneTimeKind,
        value: SecretString,
        label: Option<String>,
    ) -> Result<String, AppError> {
        let reference = random_ref()?;
        let expires_at = (self.now)() + kind.ttl();
        let seq = self.seq();
        let mut entries = self.locked_live();
        if kind == OneTimeKind::InviteText {
            entries.make_room_for_invite();
        } else if !entries.has_room() {
            return Err(full());
        }
        entries.map.insert(
            reference.clone(),
            Entry {
                kind,
                value,
                label,
                expires_at,
                seq,
            },
        );
        Ok(reference)
    }

    /// `onetime_show`: remove and return a showable value. Unknown, expired, already shown and
    /// non-showable references all fail the same way.
    pub fn take_showable(&self, reference: &str) -> Result<(OneTimeKind, SecretString), AppError> {
        check_ref(reference)?;
        let mut entries = self.locked_live();
        match entries.map.get(reference) {
            Some(entry) if entry.kind.showable() => {}
            _ => return Err(unknown()),
        }
        let entry = entries.map.remove(reference).ok_or_else(unknown)?;
        Ok((entry.kind, entry.value))
    }

    /// A copy of a showable value, leaving it in place (`onetime_copy` removes it only after
    /// the clipboard write succeeded).
    pub fn peek_showable(&self, reference: &str) -> Result<SecretString, AppError> {
        check_ref(reference)?;
        let entries = self.locked_live();
        match entries.map.get(reference) {
            Some(entry) if entry.kind.showable() => Ok(entry.value.duplicate()),
            _ => Err(unknown()),
        }
    }

    /// Remove and return a value of `kind`. A reference of another kind is left untouched.
    pub fn take_kind(&self, reference: &str, kind: OneTimeKind) -> Result<SecretString, AppError> {
        check_ref(reference)?;
        let mut entries = self.locked_live();
        match entries.map.get(reference) {
            Some(entry) if entry.kind == kind => {}
            _ => return Err(unknown()),
        }
        entries
            .map
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
        match entries.map.get(reference) {
            Some(entry) if entry.kind == kind => Ok(entry.value.duplicate()),
            _ => Err(unknown()),
        }
    }

    /// [`Self::peek_kind`] plus the entry's label.
    pub fn peek_kind_labeled(
        &self,
        reference: &str,
        kind: OneTimeKind,
    ) -> Result<(SecretString, Option<String>), AppError> {
        check_ref(reference)?;
        let entries = self.locked_live();
        match entries.map.get(reference) {
            Some(entry) if entry.kind == kind => Ok((entry.value.duplicate(), entry.label.clone())),
            _ => Err(unknown()),
        }
    }

    /// Whether `reference` still holds a live value of `kind` (nothing is copied or consumed).
    pub fn contains_kind(&self, reference: &str, kind: OneTimeKind) -> bool {
        check_ref(reference).is_ok()
            && self
                .locked_live()
                .map
                .get(reference)
                .is_some_and(|entry| entry.kind == kind)
    }

    /// `onetime_discard`: forget a value. Idempotent.
    pub fn discard(&self, reference: &str) {
        self.lock().map.remove(reference);
    }

    /// Live entries.
    pub fn len(&self) -> usize {
        self.locked_live().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop everything (app shutdown, vault lock).
    pub fn clear(&self) {
        self.lock().map.clear();
    }
}

fn unknown() -> AppError {
    AppError::not_found("onetime_ref_unknown")
}

fn full() -> AppError {
    AppError::unavailable("onetime_store_full")
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
    fn revealed_secrets_expire_after_60s_invites_after_60min_others_after_10min() {
        let (store, clock) = store_with_clock();
        let secret = store
            .put(OneTimeKind::RevealedSecret, "synthetic-v".into())
            .unwrap();
        let token = store
            .put(OneTimeKind::CallerToken, "zpw_synthetic".into())
            .unwrap();
        let invite = store
            .put(OneTimeKind::InviteText, "zeropw://join#X".into())
            .unwrap();
        clock.store(59, Ordering::SeqCst);
        assert_eq!(store.len(), 3);
        clock.store(60, Ordering::SeqCst);
        assert!(store.take_showable(&secret).is_err());
        assert_eq!(store.len(), 2);
        clock.store(599, Ordering::SeqCst);
        assert!(store.peek_kind(&token, OneTimeKind::CallerToken).is_ok());
        clock.store(600, Ordering::SeqCst);
        assert!(store.take_showable(&token).is_err());
        assert_eq!(store.len(), 1);
        // A previewed invite outlives the 10 minutes: onboarding comes between it and joining.
        clock.store(3599, Ordering::SeqCst);
        assert!(store.contains_kind(&invite, OneTimeKind::InviteText));
        clock.store(3600, Ordering::SeqCst);
        assert!(!store.contains_kind(&invite, OneTimeKind::InviteText));
        assert!(store.peek_kind(&invite, OneTimeKind::InviteText).is_err());
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
    fn recovery_codes_are_never_shown_again() {
        // recovery_generate already returned the groups; only vault_init reads the code.
        let store = OneTimeStore::new();
        let r = store
            .put(OneTimeKind::RecoveryCode, "AAAA-BBBB".into())
            .unwrap();
        assert_eq!(
            store.take_showable(&r).err().unwrap().reason,
            "onetime_ref_unknown"
        );
        assert!(store.peek_showable(&r).is_err());
        assert!(store.peek_kind(&r, OneTimeKind::RecoveryCode).is_ok());
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
    fn labels_travel_with_the_value() {
        let store = OneTimeStore::new();
        let r = store
            .put_labeled(OneTimeKind::CallerToken, "zpw_synthetic".into(), "agent-1")
            .unwrap();
        let (value, label) = store
            .peek_kind_labeled(&r, OneTimeKind::CallerToken)
            .unwrap();
        assert_eq!(value.expose(), "zpw_synthetic");
        assert_eq!(label.as_deref(), Some("agent-1"));
        assert!(store.contains_kind(&r, OneTimeKind::CallerToken));
        assert!(!store.contains_kind(&r, OneTimeKind::InviteText));
        assert!(!store.contains_kind("not-a-ref", OneTimeKind::CallerToken));
        let plain = store.put(OneTimeKind::CallerToken, "x".into()).unwrap();
        assert_eq!(
            store
                .peek_kind_labeled(&plain, OneTimeKind::CallerToken)
                .unwrap()
                .1,
            None
        );
        assert!(
            store
                .peek_kind_labeled(&r, OneTimeKind::RevealedSecret)
                .is_err()
        );
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
        assert_eq!(
            store
                .reserve(OneTimeKind::CallerToken)
                .err()
                .unwrap()
                .reason,
            "onetime_store_full"
        );
    }

    #[test]
    fn reservations_hold_their_slot_until_filled_or_dropped() {
        let store = OneTimeStore::new();
        let held: Vec<Reservation<'_>> = (0..MAX_ENTRIES)
            .map(|_| store.reserve(OneTimeKind::CallerToken).unwrap())
            .collect();
        assert!(store.is_empty());
        assert!(store.reserve(OneTimeKind::RevealedSecret).is_err());
        assert!(store.put(OneTimeKind::RecoveryCode, "x".into()).is_err());
        let mut held = held.into_iter();
        // A reserved slot always takes its value, even with the store otherwise full.
        let first = held.next().unwrap();
        let r = first
            .fill_labeled("zpw_synthetic".into(), "agent-1")
            .unwrap();
        assert_eq!(
            store
                .peek_kind_labeled(&r, OneTimeKind::CallerToken)
                .unwrap()
                .1
                .as_deref(),
            Some("agent-1")
        );
        assert!(store.reserve(OneTimeKind::CallerToken).is_err());
        // Dropping unfilled reservations gives the slots back.
        drop(held);
        assert_eq!(store.len(), 1);
        let again = store.reserve(OneTimeKind::InviteLink).unwrap();
        let link = again.fill("zeropw://join#X".into()).unwrap();
        assert_eq!(
            store.take_showable(&link).unwrap().1.expose(),
            "zeropw://join#X"
        );
    }

    #[test]
    fn pasted_invites_have_their_own_pool_and_cannot_fill_the_store() {
        let store = OneTimeStore::new();
        let first: Vec<String> = (0..MAX_INVITE_TEXTS)
            .map(|i| {
                store
                    .put(OneTimeKind::InviteText, format!("zeropw://join#{i}").into())
                    .unwrap()
            })
            .collect();
        // Many more (deep links opened from outside): the oldest give way, never an error.
        let mut last = String::new();
        for i in 0..(MAX_ENTRIES * 2) {
            last = store
                .put(
                    OneTimeKind::InviteText,
                    format!("zeropw://join#n{i}").into(),
                )
                .unwrap();
        }
        assert_eq!(store.len(), MAX_INVITE_TEXTS);
        assert!(
            first
                .iter()
                .all(|r| !store.contains_kind(r, OneTimeKind::InviteText))
        );
        assert!(store.contains_kind(&last, OneTimeKind::InviteText));
        // The app's own values still have all their room.
        let held: Vec<Reservation<'_>> = (0..MAX_ENTRIES)
            .map(|_| store.reserve(OneTimeKind::CallerToken).unwrap())
            .collect();
        assert_eq!(held.len(), MAX_ENTRIES);
        // And an invite still fits next to a full store.
        assert!(
            store
                .put(OneTimeKind::InviteText, "zeropw://join#late".into())
                .is_ok()
        );
    }
}
