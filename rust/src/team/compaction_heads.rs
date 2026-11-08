//! Local original-signature evidence for the latest compaction cut only.
//! This cache is never a live vector, authority, receipt or import capability.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::commit::{self, Commit, CommitStore, Hlc};
use super::fold::FoldResult;
use super::identity::DeviceRecord;
use crate::errors::{Error, Result};
use crate::pyint::PyInt;
use crate::pyjson::{self, DumpOptions};
use crate::store::StateDir;

const FORMAT: &str = "zeropw-team-compaction-heads-v1";
const MAX_HEADS: usize = 256;
const MAX_BYTES: usize = 16_777_216;

fn invalid() -> Error {
    Error::state("team_compaction_head_invalid")
}
fn unavailable() -> Error {
    Error::state("team_compaction_head_unavailable")
}
fn limit() -> Error {
    Error::state("team_compaction_head_limit_exceeded")
}
fn persist_failed() -> Error {
    Error::state("team_compaction_head_persist_failed")
}
fn layout_unsupported() -> Error {
    Error::state("team_compaction_layout_unsupported")
}
fn require_lock(state: &StateDir) -> Result<()> {
    if !state.locked_by_current_thread() {
        return Err(Error::state("team_compaction_lock_required"));
    }
    Ok(())
}
fn cache_path(env_id: &str) -> String {
    format!("team/{env_id}/compaction_heads.json")
}
fn fingerprint(value: &str) -> bool {
    value.len() == 26
        && value
            .bytes()
            .all(|b: u8| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}
fn object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>> {
    let map = value.as_object().ok_or_else(invalid)?;
    if map.len() != keys.len() || keys.iter().any(|key| !map.contains_key(*key)) {
        return Err(invalid());
    }
    Ok(map)
}
fn canonical(value: &Value) -> Result<Vec<u8>> {
    pyjson::dumps(value, DumpOptions::compact_sorted())
        .map(String::into_bytes)
        .map_err(|_| invalid())
}
fn pretty(value: &Value) -> Result<Vec<u8>> {
    pyjson::dumps(value, DumpOptions::pretty_sorted())
        .map(String::into_bytes)
        .map_err(|_| invalid())
}
fn positive(value: &Value) -> Result<PyInt> {
    let seq = PyInt::from_json_integer(value).ok_or_else(invalid)?;
    if seq <= 0 {
        return Err(invalid());
    }
    Ok(seq)
}
fn vector(value: &Value) -> Result<BTreeMap<String, PyInt>> {
    let map = value.as_object().ok_or_else(invalid)?;
    if map.len() > MAX_HEADS {
        return Err(limit());
    }
    map.iter()
        .map(|(author, seq)| {
            if !fingerprint(author) {
                return Err(invalid());
            }
            Ok((author.clone(), positive(seq)?))
        })
        .collect()
}
fn vector_value(vector: &BTreeMap<String, PyInt>) -> Value {
    Value::Object(
        vector
            .iter()
            .map(|(author, seq)| (author.clone(), seq.value()))
            .collect(),
    )
}
fn record(value: &Value, author: &str) -> Result<DeviceRecord> {
    object(value, &["sign_pub", "agree_pub", "sig"])?;
    let record = DeviceRecord::from_dict(value).map_err(|_| invalid())?;
    if !record.verify()
        || record.fingerprint() != author
        || canonical(value)? != canonical(&record.to_dict())?
    {
        return Err(invalid());
    }
    Ok(record)
}

struct Head {
    commit: Commit,
    device: DeviceRecord,
}
impl Head {
    fn checked(commit: Commit, device: DeviceRecord, env_id: &str) -> Result<Self> {
        if commit.env_id != env_id
            || !fingerprint(&commit.author)
            || commit.author_seq <= 0
            || commit
                .seen
                .iter()
                .any(|(fp, seq)| !fingerprint(fp) || *seq < 0)
            || !device.verify()
            || !commit::verify_commit(&commit, &device)
        {
            return Err(invalid());
        }
        Ok(Self { commit, device })
    }
    fn value(&self) -> Result<Value> {
        Ok(json!({
            "author": self.commit.author,
            "author_seq": self.commit.author_seq.value(),
            "hlc": self.commit.hlc,
            "commit_hash": self.commit.hash().map_err(|_| invalid())?,
            "device": self.device.to_dict(),
            "commit": self.commit.to_dict(),
        }))
    }
    fn same_original(&self, other: &Self) -> Result<bool> {
        Ok(self.commit.canonical_json(false).map_err(|_| invalid())?
            == other.commit.canonical_json(false).map_err(|_| invalid())?
            && self.commit.canonical_json(true).map_err(|_| invalid())?
                == other.commit.canonical_json(true).map_err(|_| invalid())?
            && self.device == other.device)
    }
}
struct Image {
    vector: BTreeMap<String, PyInt>,
    heads: BTreeMap<String, Head>,
}

// Equality to the *entire* persisted spelling also rejects duplicate keys,
// trailing whitespace/data and legacy reserved-key normalization. This does
// not change the permissive legacy JSON loader or introduce a second parser.
fn decode(bytes: &[u8], env_id: &str) -> Result<Image> {
    if bytes.len() > MAX_BYTES {
        return Err(limit());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let value = pyjson::loads(text).map_err(|_| invalid())?;
    if pretty(&value)? != bytes {
        return Err(invalid());
    }
    let root = object(&value, &["format", "env_id", "vector", "heads"])?;
    if root.get("format").and_then(Value::as_str) != Some(FORMAT)
        || root.get("env_id").and_then(Value::as_str) != Some(env_id)
        || !commit::valid_env_id(env_id)
    {
        return Err(invalid());
    }
    let vector = vector(&value["vector"])?;
    let entries = value["heads"].as_array().ok_or_else(invalid)?;
    if entries.len() > MAX_HEADS {
        return Err(limit());
    }
    if entries.len() != vector.len() {
        return Err(invalid());
    }
    let mut heads = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for entry in entries {
        object(
            entry,
            &[
                "author",
                "author_seq",
                "hlc",
                "commit_hash",
                "device",
                "commit",
            ],
        )?;
        let author = entry["author"].as_str().ok_or_else(invalid)?;
        if previous.is_some_and(|fp| fp >= author) {
            return Err(invalid());
        }
        previous = Some(author);
        let seq = positive(&entry["author_seq"])?;
        if vector.get(author) != Some(&seq) {
            return Err(invalid());
        }
        let device = record(&entry["device"], author)?;
        let commit = Commit::from_dict(&entry["commit"]).map_err(|_| invalid())?;
        let hash = commit.hash().map_err(|_| invalid())?;
        if commit.author != author
            || commit.author_seq != seq
            || entry["hlc"].as_str() != Some(commit.hlc.as_str())
            || entry["commit_hash"].as_str() != Some(hash.as_str())
            || canonical(&entry["commit"])? != commit.canonical_json(true).map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        heads.insert(author.to_owned(), Head::checked(commit, device, env_id)?);
    }
    Ok(Image { vector, heads })
}

fn load(state: &StateDir, env_id: &str) -> Result<Option<(Vec<u8>, Image)>> {
    let path = state.path.join(cache_path(env_id));
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid()),
        Ok(metadata) if !metadata.file_type().is_file() => return Err(invalid()),
        Ok(metadata) if metadata.len() > MAX_BYTES as u64 => return Err(limit()),
        Ok(_) => {}
    }
    let file = File::open(path).map_err(|_| invalid())?;
    if !file.metadata().map_err(|_| invalid())?.is_file() {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let image = decode(&bytes, env_id)?;
    Ok(Some((bytes, image)))
}

/// An I/O plan, constructed only from checked originals under the real lock.
/// No Debug/Clone/serialization or evidence getter is provided.
pub(super) struct PreparedHeads {
    state_path: PathBuf,
    env_id: String,
    total: PyInt,
    image: Value,
    bytes: Vec<u8>,
    snapshot_sha256: [u8; 32],
    vector: BTreeMap<String, PyInt>,
}

pub(super) fn prepare(
    state: &StateDir,
    env_id: &str,
    snapshot: &FoldResult,
    live: &[Commit],
    records: &HashMap<String, DeviceRecord>,
) -> Result<PreparedHeads> {
    require_lock(state)?;
    if !commit::valid_env_id(env_id)
        || snapshot.document.get("env_id").and_then(Value::as_str) != Some(env_id)
    {
        return Err(invalid());
    }
    let mut required = BTreeMap::new();
    for (author, seq) in &snapshot.vector {
        if !fingerprint(author) || *seq < 0 {
            return Err(invalid());
        }
        if *seq > 0 {
            required.insert(author.clone(), seq.clone());
        }
    }
    if required.len() > MAX_HEADS {
        return Err(limit());
    }
    let old = load(state, env_id)?.map(|(_, image)| image);
    let local_record = |author: &str| -> Result<DeviceRecord> {
        let device = records.get(author).ok_or_else(unavailable)?;
        if !device.verify() || device.fingerprint() != author {
            return Err(invalid());
        }
        Ok(device.clone())
    };
    if let Some(old) = &old {
        for (author, seq) in &old.vector {
            if required.get(author).is_none_or(|next| next < seq) {
                return Err(invalid());
            }
            let head = old.heads.get(author).ok_or_else(invalid)?;
            if local_record(author)? != head.device {
                return Err(invalid());
            }
        }
    }
    // Index only exact selected slots, never 1..a peer-controlled sequence.
    let mut selected = BTreeMap::<String, Head>::new();
    for entry in live {
        if required.get(&entry.author) != Some(&entry.author_seq) {
            continue;
        }
        let head = Head::checked(entry.clone(), local_record(&entry.author)?, env_id)?;
        if let Some(previous) = selected.get(&entry.author)
            && !previous.same_original(&head)?
        {
            return Err(invalid());
        }
        selected.insert(entry.author.clone(), head);
    }
    let mut heads = Vec::with_capacity(required.len());
    for (author, seq) in &required {
        let cached = old.as_ref().and_then(|old| old.heads.get(author));
        let live = selected.get(author);
        match (cached, live) {
            (Some(cached), Some(live)) if cached.commit.author_seq == *seq => {
                if !cached.same_original(live)? {
                    return Err(invalid());
                }
            }
            (Some(cached), Some(live))
                if Hlc::parse(&live.commit.hlc).map_err(|_| invalid())?
                    <= Hlc::parse(&cached.commit.hlc).map_err(|_| invalid())? =>
            {
                return Err(invalid());
            }
            _ => {}
        }
        let exact = live
            .or_else(|| cached.filter(|head| head.commit.author_seq == *seq))
            .ok_or_else(unavailable)?;
        heads.push(exact.value()?);
    }
    let image = json!({"format":FORMAT,"env_id":env_id,
        "vector":vector_value(&required),"heads":heads});
    if pyjson::value_depth_within(&image, pyjson::MAX_JSON_DEPTH).is_none() {
        return Err(limit());
    }
    let bytes = pretty(&image)?;
    if bytes.len() > MAX_BYTES {
        return Err(limit());
    }
    // Prospective images use exactly the same loader as existing/readback images.
    // A legacy opaque value that changes on parsing is refused, never normalized.
    let decoded = decode(&bytes, env_id)?;
    if decoded.vector != required {
        return Err(invalid());
    }
    let snapshot_image = json!({"document":snapshot.document,
        "version_order":snapshot.version_order,"vector":vector_value(&snapshot.vector)});
    let snapshot_sha256 = Sha256::digest(pretty(&snapshot_image)?).into();
    let total = snapshot
        .vector
        .values()
        .fold(PyInt::zero(), |sum, seq| PyInt(sum.0 + &seq.0));
    Ok(PreparedHeads {
        state_path: state.path.clone(),
        env_id: env_id.to_owned(),
        total,
        image,
        bytes,
        snapshot_sha256,
        vector: required,
    })
}

// Public signature material follows receipt's first-record rule, including
// fold-skipped and removed authors. It conveys no membership or wrap authority.
// This private image never crosses a helper's lock epoch.
fn checked_cache(store: &CommitStore<'_>, live: Option<&[Commit]>) -> Result<Option<Image>> {
    require_lock(store.state)?;
    let Some((_, image)) = load(store.state, &store.env_id)? else {
        return Ok(None);
    };
    if !commit::valid_env_id(&store.env_id) || store.root != format!("team/{}", store.env_id) {
        return Err(invalid());
    }
    let records = match live {
        Some(live) => commit::device_registry(live),
        None => store.retained_device_registry().map_err(|_| invalid())?,
    };
    let floor = store.snapshot_floor().map_err(|_| invalid())?;
    let vector = store.vector().map_err(|_| invalid())?;
    for (author, seq) in &image.vector {
        if floor.get(author).is_none_or(|covered| covered < seq)
            || vector.get(author).is_none_or(|covered| covered < seq)
        {
            return Err(invalid());
        }
        let head = image.heads.get(author).ok_or_else(invalid)?;
        let device = records.get(author).ok_or_else(unavailable)?;
        if device != &head.device {
            return Err(invalid());
        }
        Hlc::parse(&head.commit.hlc).map_err(|_| invalid())?;
        // One exact lookup per cached author, never a cache-derived range.
        if let Some(original) = store.get(author, seq).map_err(|_| invalid())? {
            let original = Head::checked(original, device.clone(), &store.env_id)?;
            if !head.same_original(&original)? {
                return Err(invalid());
            }
        }
    }
    if let Some(live) = live {
        for entry in live {
            if image.vector.get(&entry.author) != Some(&entry.author_seq) {
                continue;
            }
            let head = image.heads.get(&entry.author).ok_or_else(invalid)?;
            let original = Head::checked(entry.clone(), head.device.clone(), &store.env_id)?;
            if !head.same_original(&original)? {
                return Err(invalid());
            }
        }
    }
    Ok(Some(image))
}

pub(super) fn cached_hlc_not_above_previous(
    store: &CommitStore<'_>,
    candidate: &Commit,
    live: Option<&[Commit]>,
) -> Result<bool> {
    require_lock(store.state)?;
    if candidate.author_seq <= 1 || candidate.author_seq != &store.last_seq(&candidate.author)? + 1
    {
        return Ok(false);
    }
    let image = checked_cache(store, live)?;
    let previous_seq = &candidate.author_seq - 1;
    // Absent cache preserves the legacy live-predecessor-only behavior.
    let Some(image) = image else {
        return Ok(match store.get(&candidate.author, previous_seq)? {
            Some(previous) => Hlc::parse(&candidate.hlc)? <= Hlc::parse(&previous.hlc)?,
            None => false,
        });
    };
    if candidate.env_id != store.env_id {
        return Err(invalid());
    }
    let previous = store
        .get(&candidate.author, &previous_seq)
        .map_err(|_| invalid())?;
    let cached = image.heads.get(&candidate.author);
    if previous.is_none() && cached.is_none_or(|head| head.commit.author_seq != previous_seq) {
        return Err(unavailable());
    }
    let candidate_hlc = Hlc::parse(&candidate.hlc)?;
    let live_failure = match previous {
        Some(previous) => candidate_hlc <= Hlc::parse(&previous.hlc).map_err(|_| invalid())?,
        None => false,
    };
    let cached_failure = match cached {
        Some(head) => candidate_hlc <= Hlc::parse(&head.commit.hlc).map_err(|_| invalid())?,
        None => false,
    };
    Ok(live_failure || cached_failure)
}

pub(super) fn observe_cached_hlcs(
    store: &CommitStore<'_>,
    live: &[Commit],
    clock: &mut Hlc,
) -> Result<()> {
    let Some(image) = checked_cache(store, Some(live))? else {
        return Ok(());
    };
    let vector = store.vector().map_err(|_| invalid())?;
    let live_slots: std::collections::BTreeSet<_> = live
        .iter()
        .map(|entry| (&entry.author, &entry.author_seq))
        .collect();
    for (author, seq) in &vector {
        if *seq > 0 && !live_slots.contains(&(author, seq)) && image.vector.get(author) != Some(seq)
        {
            return Err(unavailable());
        }
    }
    // Validate everything before touching the caller's remembered clock.
    let mut observed = clock.clone();
    for head in image.heads.values() {
        observed.observe(&head.commit.hlc).map_err(|_| invalid())?;
    }
    *clock = observed;
    Ok(())
}

// Only descendants generated here are inspected. Trusted ancestors above the
// configured root retain their normal resolution (including a platform /tmp
// alias). Components remove a final slash/dot so a linked root cannot disguise
// its own type as `state-link/` or `state-link/.`.
pub(super) fn preflight_layout(state: &StateDir, env_id: &str, total: &PyInt) -> Result<()> {
    require_lock(state)?;
    if !commit::valid_env_id(env_id) || *total < 0 {
        return Err(layout_unsupported());
    }
    let root: PathBuf = state.path.components().collect();
    if !fs::symlink_metadata(&root)
        .map_err(|_| persist_failed())?
        .file_type()
        .is_dir()
    {
        return Err(layout_unsupported());
    }
    let file = format!("{total}.json");
    for (directories, destination) in [
        (vec!["team", env_id, "snapshots"], file.as_str()),
        (vec!["team", env_id, "snapshot_records"], file.as_str()),
        (vec!["team", env_id], "compaction_heads.json"),
    ] {
        let mut path = root.clone();
        let mut missing_parent = false;
        for component in directories {
            let mut components = Path::new(component).components();
            if !matches!(components.next(), Some(Component::Normal(_)))
                || components.next().is_some()
            {
                return Err(layout_unsupported());
            }
            path.push(component);
            if !path.starts_with(&root) {
                return Err(layout_unsupported());
            }
            if missing_parent {
                continue;
            }
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_dir() => {}
                Ok(_) => return Err(layout_unsupported()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing_parent = true;
                }
                Err(_) => return Err(persist_failed()),
            }
        }
        if missing_parent {
            continue;
        }
        path.push(destination);
        if !path.starts_with(&root) {
            return Err(layout_unsupported());
        }
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => return Err(layout_unsupported()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(persist_failed()),
        }
    }
    Ok(())
}

fn check_snapshot(state: &StateDir, env_id: &str, prepared: &PreparedHeads) -> Result<()> {
    let path = format!("team/{env_id}/snapshots/{}.json", prepared.total);
    if !fs::symlink_metadata(state.path.join(&path))
        .map_err(|_| persist_failed())?
        .file_type()
        .is_file()
    {
        return Err(persist_failed());
    }
    let value = state
        .read_json(&path, Value::Null)
        .map_err(|_| persist_failed())?;
    let digest: [u8; 32] = Sha256::digest(pretty(&value).map_err(|_| persist_failed())?).into();
    if digest != prepared.snapshot_sha256 {
        return Err(persist_failed());
    }
    let covered = value
        .get("vector")
        .and_then(Value::as_object)
        .ok_or_else(persist_failed)?;
    let mut nonzero = BTreeMap::new();
    for (author, seq) in covered {
        let seq = PyInt::from_json_integer(seq).ok_or_else(persist_failed)?;
        if seq < 0 {
            return Err(persist_failed());
        }
        if seq > 0 {
            nonzero.insert(author.clone(), seq);
        }
    }
    if nonzero != prepared.vector {
        return Err(persist_failed());
    }
    Ok(())
}

// Child first, then every relevant ancestor through and including StateDir.
// Safe File APIs only; unsupported directory fsync is an error, never a fallback.
fn sync_directories(state: &StateDir, directory: &Path) -> Result<()> {
    let mut current = directory;
    loop {
        if !current.starts_with(&state.path)
            || !fs::symlink_metadata(current)
                .map_err(|_| persist_failed())?
                .file_type()
                .is_dir()
        {
            return Err(persist_failed());
        }
        #[cfg(test)]
        testing::hit(testing::Boundary::DirectorySync)?;
        File::open(current)
            .and_then(|file| file.sync_all())
            .map_err(|_| persist_failed())?;
        if current == state.path {
            return Ok(());
        }
        current = current.parent().ok_or_else(persist_failed)?;
    }
}

fn read_record(state: &StateDir, env_id: &str, total: &PyInt) -> Result<Vec<u8>> {
    let path = format!("team/{env_id}/snapshot_records/{total}.json");
    if !fs::symlink_metadata(state.path.join(&path))
        .map_err(|_| persist_failed())?
        .file_type()
        .is_file()
    {
        return Err(persist_failed());
    }
    let value = state
        .read_json(&path, Value::Null)
        .map_err(|_| persist_failed())?;
    if !value.is_object() {
        return Err(persist_failed());
    }
    canonical(&value).map_err(|_| persist_failed())
}

pub(super) fn persist_before_prune(
    state: &StateDir,
    env_id: &str,
    total: &PyInt,
    prepared: PreparedHeads,
) -> Result<()> {
    require_lock(state)?;
    if prepared.state_path != state.path || prepared.env_id != env_id || prepared.total != *total {
        return Err(persist_failed());
    }
    check_snapshot(state, env_id, &prepared)?;
    // The caller compared this record to unchanged snapshot_record(facts, live).
    // Bind that exact readback across the durability barrier as well.
    let record = read_record(state, env_id, total)?;
    sync_directories(state, &state.path.join(format!("team/{env_id}/snapshots")))?;
    #[cfg(test)]
    testing::hit(testing::Boundary::SnapshotDurable)?;
    sync_directories(
        state,
        &state.path.join(format!("team/{env_id}/snapshot_records")),
    )?;
    #[cfg(test)]
    testing::hit(testing::Boundary::RecordDurable)?;
    #[cfg(test)]
    testing::hit(testing::Boundary::BeforeCacheWrite)?;
    state
        .write_json(&cache_path(env_id), &prepared.image)
        .map_err(|_| persist_failed())?;
    #[cfg(test)]
    testing::hit(testing::Boundary::AfterCacheWrite)?;
    sync_directories(state, &state.path.join(format!("team/{env_id}")))?;
    #[cfg(test)]
    testing::hit(testing::Boundary::CacheDurable)?;
    #[cfg(test)]
    testing::hit(testing::Boundary::BeforeReadback)?;
    let (bytes, image) = load(state, env_id)
        .map_err(|_| persist_failed())?
        .ok_or_else(persist_failed)?;
    if bytes != prepared.bytes || image.vector != prepared.vector {
        return Err(persist_failed());
    }
    check_snapshot(state, env_id, &prepared)?;
    if read_record(state, env_id, total)? != record {
        return Err(persist_failed());
    }
    #[cfg(test)]
    testing::hit(testing::Boundary::BarrierComplete)?;
    Ok(())
}

#[cfg(test)]
pub(super) mod testing {
    use std::cell::RefCell;

    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum Boundary {
        BeforeLayout,
        BeforeSnapshot,
        AfterSnapshot,
        BeforeRecord,
        AfterRecord,
        DirectorySync,
        SnapshotDurable,
        RecordDurable,
        BeforeCacheWrite,
        AfterCacheWrite,
        CacheDurable,
        BeforeReadback,
        BarrierComplete,
        BeforeUnlink,
        AfterFirstUnlink,
    }
    type Pause = (
        Boundary,
        std::sync::mpsc::SyncSender<()>,
        std::sync::mpsc::Receiver<()>,
    );
    pub(crate) enum SnapshotReplacement {
        Missing,
        Directory,
        #[cfg(unix)]
        IdenticalSymlink(PathBuf),
    }
    struct SnapshotMutation {
        at: Boundary,
        scope: PathBuf,
        path: PathBuf,
        replacement: SnapshotReplacement,
    }
    #[derive(Default)]
    struct Trace {
        fail: Option<Boundary>,
        events: Vec<Boundary>,
        action: Option<(Boundary, PathBuf, Option<Vec<u8>>)>,
        pause: Option<Pause>,
        snapshot_mutation: Option<SnapshotMutation>,
    }
    thread_local! {
        static TRACE: RefCell<Trace> = RefCell::new(Trace::default());
        static AUTHOR_WALL: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
    }
    pub(crate) fn author_wall() -> Option<i64> {
        AUTHOR_WALL.with(std::cell::Cell::get)
    }
    pub(crate) fn set_author_wall(wall: Option<i64>) {
        AUTHOR_WALL.with(|value| value.set(wall));
    }
    pub(crate) fn reset(fail: Option<Boundary>) {
        TRACE.with(|trace| {
            *trace.borrow_mut() = Trace {
                fail,
                ..Trace::default()
            }
        });
    }
    pub(crate) fn action(boundary: Boundary, path: PathBuf, bytes: Option<Vec<u8>>) {
        TRACE.with(|trace| trace.borrow_mut().action = Some((boundary, path, bytes)));
    }
    pub(crate) fn pause(
        boundary: Boundary,
        entered: std::sync::mpsc::SyncSender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    ) {
        TRACE.with(|trace| trace.borrow_mut().pause = Some((boundary, entered, resume)));
    }
    pub(crate) fn events() -> Vec<Boundary> {
        TRACE.with(|trace| trace.borrow().events.clone())
    }
    pub(crate) fn replace_snapshot(
        at: Boundary,
        scope: PathBuf,
        path: PathBuf,
        replacement: SnapshotReplacement,
    ) {
        TRACE.with(|trace| {
            trace.borrow_mut().snapshot_mutation = Some(SnapshotMutation {
                at,
                scope,
                path,
                replacement,
            });
        });
    }
    pub(crate) fn hit(boundary: Boundary) -> Result<()> {
        TRACE.with(|trace| {
            let mut trace = trace.borrow_mut();
            trace.events.push(boundary);
            if trace
                .snapshot_mutation
                .as_ref()
                .is_some_and(|mutation| mutation.at == boundary)
            {
                let mutation = trace.snapshot_mutation.take().ok_or_else(persist_failed)?;
                let owned = |path: &Path| {
                    path.starts_with(&mutation.scope)
                        && !path.components().any(|part| part == Component::ParentDir)
                };
                if !owned(&mutation.path) {
                    return Err(persist_failed());
                }
                match mutation.replacement {
                    SnapshotReplacement::Missing => {
                        fs::remove_file(mutation.path).map_err(|_| persist_failed())?;
                    }
                    SnapshotReplacement::Directory => {
                        fs::remove_file(&mutation.path).map_err(|_| persist_failed())?;
                        fs::create_dir(mutation.path).map_err(|_| persist_failed())?;
                    }
                    #[cfg(unix)]
                    SnapshotReplacement::IdenticalSymlink(target) => {
                        if !owned(&target) {
                            return Err(persist_failed());
                        }
                        let bytes = fs::read(&mutation.path).map_err(|_| persist_failed())?;
                        fs::write(&target, bytes).map_err(|_| persist_failed())?;
                        fs::remove_file(&mutation.path).map_err(|_| persist_failed())?;
                        std::os::unix::fs::symlink(target, mutation.path)
                            .map_err(|_| persist_failed())?;
                    }
                }
            }
            if trace
                .action
                .as_ref()
                .is_some_and(|(at, _, _)| *at == boundary)
            {
                let (_, path, bytes) = trace.action.take().ok_or_else(persist_failed)?;
                match bytes {
                    Some(bytes) => fs::write(path, bytes),
                    None => fs::create_dir(path),
                }
                .map_err(|_| persist_failed())?;
            }
            if trace
                .pause
                .as_ref()
                .is_some_and(|(at, _, _)| *at == boundary)
            {
                let (_, entered, resume) = trace.pause.take().ok_or_else(persist_failed)?;
                entered.send(()).map_err(|_| persist_failed())?;
                resume
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .map_err(|_| persist_failed())?;
            }
            if trace.fail == Some(boundary) {
                return Err(persist_failed());
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretBytes;
    use crate::team::fold;
    use crate::team::identity::DeviceKey;
    use tempfile::TempDir;

    fn key(seed: u8) -> DeviceKey {
        DeviceKey {
            sign_seed: SecretBytes::new(vec![seed; 32]),
            agree_private: SecretBytes::new(vec![seed.wrapping_add(1); 32]),
        }
    }
    fn signed(key: &DeviceKey, env: &str, seq: PyInt, hlc: &str, opaque: Value) -> Commit {
        commit::sign_commit(
            key,
            env,
            seq,
            hlc,
            &BTreeMap::new(),
            vec![json!({"op":"settings.update","sync_interval_seconds":17,"opaque":opaque})],
        )
        .unwrap()
    }
    fn identity(keys: &[DeviceKey]) -> HashMap<String, DeviceRecord> {
        keys.iter()
            .map(|key| (key.fingerprint().unwrap(), key.record().unwrap()))
            .collect()
    }
    fn snapshot(env: &str, live: &[Commit]) -> FoldResult {
        fold::fold(env, live.to_vec(), None, None, None, None).unwrap()
    }
    fn env(key: &DeviceKey) -> String {
        format!(
            "{}-0123456789abcdef0123456789abcdef",
            key.fingerprint().unwrap()
        )
    }

    #[test]
    fn compaction_heads_layout_requires_lock_and_creates_no_prospective_paths() {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let env = env(&key(1));
        assert_eq!(
            preflight_layout(&state, &env, &1.into())
                .unwrap_err()
                .reason,
            "team_compaction_lock_required"
        );
        let _lock = state.lock().unwrap();
        preflight_layout(&state, &env, &1.into()).unwrap();
        assert!(!state.path.join("team").exists());
        for (env, total) in [("../outside", 1.into()), (env.as_str(), (-1).into())] {
            let error = preflight_layout(&state, env, &total).unwrap_err();
            assert_eq!(error.reason, "team_compaction_layout_unsupported");
            assert!(error.detail.is_empty());
        }
        let retained = tmp.path().join("retained-state");
        fs::rename(&state.path, &retained).unwrap();
        let error = preflight_layout(&state, &env, &1.into()).unwrap_err();
        fs::rename(retained, &state.path).unwrap();
        assert_eq!(error.reason, "team_compaction_head_persist_failed");
        assert!(error.detail.is_empty());
    }

    #[test]
    fn compaction_heads_layout_refuses_non_directory_and_nonregular_destinations() {
        let env = env(&key(2));
        for relative in [
            "team".to_owned(),
            format!("team/{env}"),
            format!("team/{env}/snapshots"),
            format!("team/{env}/snapshot_records"),
            format!("team/{env}/snapshots/1.json"),
            format!("team/{env}/snapshot_records/1.json"),
            format!("team/{env}/compaction_heads.json"),
        ] {
            let tmp = TempDir::new().unwrap();
            let state = StateDir::new(tmp.path().join("state"));
            state.create().unwrap();
            let path = state.path.join(&relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            if relative.ends_with(".json") {
                fs::create_dir(&path).unwrap();
            } else {
                fs::write(&path, b"synthetic-layout-file").unwrap();
            }
            let _lock = state.lock().unwrap();
            let error = preflight_layout(&state, &env, &1.into()).unwrap_err();
            assert_eq!(error.reason, "team_compaction_layout_unsupported");
            assert!(error.detail.is_empty());
            assert_eq!(path.is_file(), !relative.ends_with(".json"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn compaction_heads_layout_rejects_dangling_links_but_allows_trusted_parent_alias() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("real-parent");
        fs::create_dir(&parent).unwrap();
        let alias = tmp.path().join("parent-alias");
        std::os::unix::fs::symlink(&parent, &alias).unwrap();
        let state = StateDir::new(alias.join("state"));
        state.create().unwrap();
        let env = env(&key(3));
        let _lock = state.lock().unwrap();
        preflight_layout(&state, &env, &1.into()).unwrap();
        let directory = state.path.join(format!("team/{env}"));
        fs::create_dir_all(&directory).unwrap();
        for name in ["snapshots", "snapshot_records", "compaction_heads.json"] {
            let path = directory.join(name);
            std::os::unix::fs::symlink(tmp.path().join("missing-target"), &path).unwrap();
            let error = preflight_layout(&state, &env, &1.into()).unwrap_err();
            fs::remove_file(path).unwrap();
            assert_eq!(error.reason, "team_compaction_layout_unsupported");
            assert!(error.detail.is_empty());
        }
        for name in ["snapshots", "snapshot_records"] {
            let folder = directory.join(name);
            fs::create_dir(&folder).unwrap();
            let path = folder.join("1.json");
            std::os::unix::fs::symlink(tmp.path().join("missing-target"), &path).unwrap();
            let error = preflight_layout(&state, &env, &1.into()).unwrap_err();
            fs::remove_file(&path).unwrap();
            assert_eq!(error.reason, "team_compaction_layout_unsupported");
            assert!(error.detail.is_empty());
            fs::write(folder.join("1.json"), b"synthetic-regular-file").unwrap();
        }
        fs::write(directory.join("compaction_heads.json"), b"synthetic-cache").unwrap();
        preflight_layout(&state, &env, &1.into()).unwrap();
        assert_eq!(
            fs::read(directory.join("snapshots/1.json"))
                .unwrap()
                .as_slice(),
            b"synthetic-regular-file"
        );
    }

    #[test]
    fn compaction_heads_helpers_require_real_lock_and_bind_snapshot_plan() {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let key = key(1);
        let env = env(&key);
        let live = vec![signed(&key, &env, 1.into(), "1000-0007", Value::Null)];
        let snapshot = snapshot(&env, &live);
        let identity = identity(&[key]);
        assert_eq!(
            prepare(&state, &env, &snapshot, &live, &identity)
                .err()
                .unwrap()
                .reason,
            "team_compaction_lock_required"
        );
        let prepared = {
            let _lock = state.lock().unwrap();
            prepare(&state, &env, &snapshot, &live, &identity).unwrap()
        };
        assert_eq!(
            persist_before_prune(&state, &env, &1.into(), prepared)
                .unwrap_err()
                .reason,
            "team_compaction_lock_required"
        );
        let _lock = state.lock().unwrap();
        let prepared = prepare(&state, &env, &snapshot, &live, &identity).unwrap();
        let mut wrong = snapshot.clone();
        wrong.vector.values_mut().for_each(|seq| *seq = 2.into());
        fold::save_snapshot(&state, &env, &1.into(), &wrong).unwrap();
        assert_eq!(
            persist_before_prune(&state, &env, &1.into(), prepared)
                .unwrap_err()
                .reason,
            "team_compaction_head_persist_failed"
        );
        assert!(load(&state, &env).unwrap().is_none());
    }

    #[test]
    fn compaction_heads_exact_huge_pyint_slots_hlc_monotonicity_and_vector_regression() {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let _lock = state.lock().unwrap();
        let key = key(2);
        let env = env(&key);
        let fp = key.fingerprint().unwrap();
        let identity = identity(std::slice::from_ref(&key));
        let huge = PyInt::from_json_integer(
            &pyjson::loads("1844674407370955161600000000000000000001").unwrap(),
        )
        .unwrap();
        let live = vec![signed(
            &key,
            &env,
            huge.clone(),
            "184467440737095516160000-000007",
            Value::Null,
        )];
        let original = snapshot(&env, &live);
        let prepared = prepare(&state, &env, &original, &live, &identity).unwrap();
        assert_eq!(prepared.image["vector"][&fp], huge.value());
        assert_eq!(
            prepared.image["heads"][0]["hlc"],
            "184467440737095516160000-000007"
        );
        state
            .write_json(&cache_path(&env), &prepared.image)
            .unwrap();
        assert!(prepare(&state, &env, &original, &[], &identity).is_ok());
        let mut regression = original.clone();
        regression.vector.insert(fp.clone(), &huge - 1);
        assert_eq!(
            prepare(&state, &env, &regression, &live, &identity)
                .err()
                .unwrap()
                .reason,
            "team_compaction_head_invalid"
        );
        regression.vector.clear();
        assert_eq!(
            prepare(&state, &env, &regression, &[], &identity)
                .err()
                .unwrap()
                .reason,
            "team_compaction_head_invalid"
        );
        for hlc in [
            "184467440737095516160000-000007",
            "184467440737095516159999-999999",
        ] {
            let next = vec![signed(&key, &env, &huge + 1, hlc, Value::Null)];
            assert_eq!(
                prepare(&state, &env, &snapshot(&env, &next), &next, &identity)
                    .err()
                    .unwrap()
                    .reason,
                "team_compaction_head_invalid"
            );
        }
        let next = vec![signed(
            &key,
            &env,
            &huge + 1,
            "184467440737095516160000-000008",
            Value::Null,
        )];
        let advanced = prepare(&state, &env, &snapshot(&env, &next), &next, &identity).unwrap();
        assert_eq!(
            advanced.image["heads"][0]["author_seq"],
            (&huge + 1).value()
        );
        assert!(!state.path.join(format!("team/{env}/snapshots")).exists());
    }

    #[test]
    fn compaction_heads_at_256_and_over_256_are_exact_without_sequence_enumeration() {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let _lock = state.lock().unwrap();
        let keys: Vec<_> = (0..=255).map(key).collect();
        let env = env(&keys[0]);
        let live: Vec<_> = keys
            .iter()
            .map(|key| signed(key, &env, 1.into(), "1000-0000", Value::Null))
            .collect();
        let mut snapshot = snapshot(&env, &live);
        let prepared = prepare(&state, &env, &snapshot, &live, &identity(&keys)).unwrap();
        assert_eq!(prepared.image["heads"].as_array().unwrap().len(), 256);
        let authors: Vec<_> = prepared.image["heads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|head| head["author"].as_str().unwrap())
            .collect();
        assert!(authors.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(snapshot.vector.values().all(|seq| *seq == 1));
        let extra = (b'a'..=b'z')
            .map(|b| String::from_utf8(vec![b; 26]).unwrap())
            .find(|fp| !snapshot.vector.contains_key(fp))
            .unwrap();
        snapshot.vector.insert(extra, 1.into());
        assert_eq!(
            prepare(&state, &env, &snapshot, &live, &identity(&keys))
                .err()
                .unwrap()
                .reason,
            "team_compaction_head_limit_exceeded"
        );
    }

    #[test]
    fn compaction_heads_serialized_16_mib_boundary_and_bounded_disk_read() {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let _lock = state.lock().unwrap();
        let key = key(3);
        let env = env(&key);
        let identity = identity(std::slice::from_ref(&key));
        let empty = vec![signed(&key, &env, 1.into(), "1000-0000", json!(""))];
        let overhead = prepare(&state, &env, &snapshot(&env, &empty), &empty, &identity)
            .unwrap()
            .bytes
            .len();
        let at = vec![signed(
            &key,
            &env,
            1.into(),
            "1000-0000",
            json!("x".repeat(MAX_BYTES - overhead)),
        )];
        let prepared = prepare(&state, &env, &snapshot(&env, &at), &at, &identity).unwrap();
        assert_eq!(prepared.bytes.len(), 16_777_216);
        state
            .write_json(&cache_path(&env), &prepared.image)
            .unwrap();
        assert_eq!(load(&state, &env).unwrap().unwrap().0.len(), 16_777_216);
        fs::remove_file(state.path.join(cache_path(&env))).unwrap();
        let over = vec![signed(
            &key,
            &env,
            1.into(),
            "1000-0000",
            json!("x".repeat(MAX_BYTES - overhead + 1)),
        )];
        assert_eq!(
            prepare(&state, &env, &snapshot(&env, &over), &over, &identity)
                .err()
                .unwrap()
                .reason,
            "team_compaction_head_limit_exceeded"
        );
        let file = File::create(state.path.join(cache_path(&env))).unwrap();
        file.set_len(MAX_BYTES as u64 + 1).unwrap();
        assert_eq!(
            load(&state, &env).err().unwrap().reason,
            "team_compaction_head_limit_exceeded"
        );
        assert_eq!(
            decode(&vec![b' '; MAX_BYTES + 1], &env)
                .err()
                .unwrap()
                .reason,
            "team_compaction_head_limit_exceeded"
        );
        fs::remove_file(state.path.join(cache_path(&env))).unwrap();
        fs::create_dir(state.path.join(cache_path(&env))).unwrap();
        assert_eq!(
            load(&state, &env).err().unwrap().reason,
            "team_compaction_head_invalid"
        );
    }

    #[test]
    fn compaction_heads_clock_helpers_lock_absence_and_atomic_observation() {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let key = key(31);
        let env = env(&key);
        let fp = key.fingerprint().unwrap();
        let store = CommitStore::new(&state, &env);
        let candidate = signed(&key, &env, 3.into(), "1000001-0007", Value::Null);
        let mut clock = Hlc::default();
        assert_eq!(
            observe_cached_hlcs(&store, &[], &mut clock)
                .unwrap_err()
                .reason,
            "team_compaction_lock_required"
        );
        assert_eq!(
            cached_hlc_not_above_previous(&store, &candidate, None)
                .unwrap_err()
                .reason,
            "team_compaction_lock_required"
        );
        let _lock = state.lock().unwrap();
        let legacy = CommitStore::new(&state, "legacy-not-a-new-env-id");
        observe_cached_hlcs(&legacy, &[], &mut clock).unwrap();
        assert_eq!(clock, Hlc::default());
        let init = commit::sign_commit(&key, &env, 1, "1000000-0000", &BTreeMap::new(), vec![json!({
            "op":"env.init","owner_device":key.record().unwrap().to_dict(),"owner_name":"synthetic-owner",
            "generation_id":"0123456789abcdef","wraps":{}})]).unwrap();
        let head = signed(&key, &env, 2.into(), "1000001-0007", Value::Null);
        store.append(&init).unwrap();
        store.append(&head).unwrap();
        let live = store.all_commits().unwrap();
        let snapshot = snapshot(&env, &live);
        let prepared = prepare(
            &state,
            &env,
            &snapshot,
            &live,
            &commit::device_registry(&live),
        )
        .unwrap();
        fold::save_snapshot(&state, &env, &2.into(), &snapshot).unwrap();
        state
            .write_json(&cache_path(&env), &prepared.image)
            .unwrap();
        fs::remove_file(state.path.join(format!("team/{env}/commits/{fp}/2.json"))).unwrap();
        let retained = store.all_commits().unwrap();
        assert!(cached_hlc_not_above_previous(&store, &candidate, Some(&retained)).unwrap());
        assert!(cached_hlc_not_above_previous(&store, &candidate, None).unwrap());
        observe_cached_hlcs(&store, &retained, &mut clock).unwrap();
        assert_eq!(clock.render(), "1000001-0007");
        let initial = Hlc::new(7, 8);
        for failure in ["missing_head", "record", "coverage", "json"] {
            state
                .write_json(&cache_path(&env), &prepared.image)
                .unwrap();
            fold::save_snapshot(&state, &env, &2.into(), &snapshot).unwrap();
            let mut current = initial.clone();
            match failure {
                "missing_head" => {
                    let mut later = snapshot.clone();
                    later.vector.insert(fp.clone(), 3.into());
                    fold::save_snapshot(&state, &env, &2.into(), &later).unwrap();
                }
                "record" => {
                    let alternative = DeviceKey {
                        sign_seed: key.sign_seed.clone(),
                        agree_private: SecretBytes::new(vec![99; 32]),
                    };
                    let mut image = prepared.image.clone();
                    image["heads"][0]["device"] = alternative.record().unwrap().to_dict();
                    state.write_json(&cache_path(&env), &image).unwrap();
                }
                "coverage" => {
                    let mut lower = snapshot.clone();
                    lower.vector.insert(fp.clone(), 1.into());
                    fold::save_snapshot(&state, &env, &2.into(), &lower).unwrap();
                }
                "json" => fs::write(state.path.join(cache_path(&env)), b"{invalid").unwrap(),
                _ => unreachable!(),
            }
            let error = observe_cached_hlcs(&store, &retained, &mut current).unwrap_err();
            assert_eq!(
                error.reason,
                if failure == "missing_head" {
                    "team_compaction_head_unavailable"
                } else {
                    "team_compaction_head_invalid"
                }
            );
            assert!(error.detail.is_empty());
            assert_eq!(current, initial);
        }
        state
            .write_json(&cache_path(&env), &prepared.image)
            .unwrap();
        fold::save_snapshot(&state, &env, &2.into(), &snapshot).unwrap();
        fs::remove_file(state.path.join(format!("team/{env}/commits/{fp}/1.json"))).unwrap();
        let error = observe_cached_hlcs(&store, &[], &mut clock).unwrap_err();
        assert_eq!(error.reason, "team_compaction_head_unavailable");
        assert!(error.detail.is_empty());
    }

    #[test]
    fn compaction_heads_reserved_number_normalization_refuses_before_publication() {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let _lock = state.lock().unwrap();
        let key = key(4);
        let env = env(&key);
        // Construct the literal object directly, never through legacy loads.
        let live = vec![signed(
            &key,
            &env,
            1.into(),
            "1000-0000",
            json!({"$serde_json::private::Number":"123"}),
        )];
        assert_eq!(
            prepare(
                &state,
                &env,
                &snapshot(&env, &live),
                &live,
                &identity(&[key])
            )
            .err()
            .unwrap()
            .reason,
            "team_compaction_head_invalid"
        );
        assert!(load(&state, &env).unwrap().is_none());
        assert!(!state.path.join(format!("team/{env}/snapshots")).exists());
    }
}
