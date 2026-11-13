//! Durable import primitives. New records have their own strict private paths;
//! legacy StateDir byte formats and single-file writer behavior are unchanged.
use crate::{
    errors::{Error, Result},
    pyjson::{self, DumpOptions},
    store::StateDir,
};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path},
};

pub(crate) const INDEX: &str = "vault/personal_imports.json";
pub(crate) const BACKUP: &str = "vault/personal_bootstrap_backup.json";
pub(crate) const LOCAL_REMOVAL_DENIAL: &str = "local-removal-denial.json";

type ImportPathEntries = std::collections::BTreeMap<(std::path::PathBuf, bool), (u64, [u64; 11])>;
pub(crate) struct ImportPathCache {
    entries: std::cell::RefCell<ImportPathEntries>,
}
#[derive(PartialEq, Eq)]
pub(crate) struct ImportRootObservation {
    root: [u64; 11],
    lock: [u64; 11],
}
impl ImportRootObservation {
    pub(crate) fn visit_words(&self, mut visit: impl FnMut(u64)) {
        for word in self.root.iter().chain(self.lock.iter()) {
            visit(*word);
        }
    }
}
impl ImportPathCache {
    pub(crate) fn empty() -> Self {
        Self {
            entries: Default::default(),
        }
    }
}

/// A borrowed operation, never ambient StateDir authority. A selected parent
/// retains its original counters/start/generation; a credential entry without
/// one gets a finite guard beginning at its first actual lock.
pub(crate) struct ImportIo<'g, 'a> {
    state: &'a StateDir,
    history: Option<&'g crate::team::commit::HistorySession<'a>>,
    _lock: Option<crate::store::StateLock<'a>>,
    root: File,
    root_id: (u64, u64),
    root_stamp: std::cell::Cell<[u64; 11]>,
    lock_stamp: std::cell::Cell<[u64; 11]>,
    lock_id: (u64, u64),
    identity: Option<crate::team::identity::DeviceRecord>,
    key_hash: Option<[u8; 32]>,
    work: std::cell::Cell<u64>,
    charged: std::cell::Cell<u64>,
    failure: std::cell::RefCell<Option<Error>>,
    generation: std::rc::Rc<std::cell::Cell<u64>>,
    budget: std::rc::Rc<crate::team::commit::ImportHistoryBudget>,
    paths: std::rc::Rc<ImportPathCache>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl<'a> ImportIo<'a, 'a> {
    pub(crate) fn open(state: &'a StateDir) -> Result<Self> {
        let lock = state.lock()?;
        #[cfg(test)]
        opus_cost::metric(state, "standalone_guards", 1);
        let budget = std::rc::Rc::new(crate::team::commit::ImportHistoryBudget::new_guard());
        Self::capture(state, None, Some(lock), budget)
    }
    pub(crate) fn bootstrap(
        state: &'a StateDir,
        budget: std::rc::Rc<crate::team::commit::ImportHistoryBudget>,
    ) -> Result<Self> {
        let lock = state.lock()?;
        Self::capture(state, None, Some(lock), budget)
    }
    pub(crate) fn shared_generation(&self) -> std::rc::Rc<std::cell::Cell<u64>> {
        self.generation.clone()
    }
    pub(crate) fn shared_paths(&self) -> std::rc::Rc<ImportPathCache> {
        self.paths.clone()
    }
    pub(crate) fn open_routed(state: &'a StateDir, witness: &ImportWitness) -> Result<Self> {
        let io = Self::open(state)?;
        io.charge(witness.work, witness.bytes)?;
        Ok(io)
    }
}
impl<'g, 'a> ImportIo<'g, 'a> {
    pub(crate) fn with_history(
        history: &'g crate::team::commit::HistorySession<'a>,
    ) -> Result<Self> {
        history.check()?;
        #[cfg(test)]
        opus_cost::metric(history.state(), "parented_io", 1);
        history.charge_import(
            128 + 8 * history.state().path.as_os_str().len() as u64,
            1024 + 8 * history.state().path.as_os_str().len() as u64,
        )?;
        Self::capture(
            history.state(),
            Some(history),
            None,
            history.import_budget(),
        )
    }
    fn capture(
        state: &'a StateDir,
        history: Option<&'g crate::team::commit::HistorySession<'a>>,
        lock: Option<crate::store::StateLock<'a>>,
        budget: std::rc::Rc<crate::team::commit::ImportHistoryBudget>,
    ) -> Result<Self> {
        use rustix::fs::{Mode, OFlags, open};
        budget.charge(
            1024 + 16 * state.path.as_os_str().len() as u64,
            4096 + 16 * state.path.as_os_str().len() as u64,
        )?;
        if history.is_none() {
            private(&state.path, true)?;
            private(&state.path.join(".lock"), false)?;
        }
        let root = File::from(
            open(
                &state.path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| failed())?,
        );
        let metadata = root.metadata().map_err(|_| failed())?;
        let result = Self {
            state,
            history,
            _lock: lock,
            root,
            root_id: (metadata.dev(), metadata.ino()),
            root_stamp: std::cell::Cell::new(io_stamp(&metadata)),
            lock_stamp: std::cell::Cell::new(io_stamp(
                &fs::symlink_metadata(state.path.join(".lock")).map_err(|_| failed())?,
            )),
            lock_id: state.import_lock_identity()?,
            identity: state.import_identity().cloned(),
            key_hash: state.import_key_hash()?,
            work: std::cell::Cell::new(0),
            charged: std::cell::Cell::new(0),
            failure: std::cell::RefCell::new(None),
            generation: std::rc::Rc::new(std::cell::Cell::new(0)),
            budget,
            paths: history.map_or_else(
                || std::rc::Rc::new(ImportPathCache::empty()),
                |history| history.import_paths(),
            ),
            _thread: std::marker::PhantomData,
        };
        result.charge(1, 256)?;
        result.boundary()?;
        Ok(result)
    }
    pub(crate) fn state(&self) -> &'a StateDir {
        self.state
    }
    pub(crate) fn check(&self) -> Result<()> {
        if let Some(error) = self.failure.borrow().as_ref() {
            return Err(error.clone());
        }
        if let Some(history) = self.history {
            history.check_import_deadline()?;
        } else {
            self.budget.check()?;
        }
        if !self.state.locked_by_current_thread() {
            return Err(Error::state("team_bootstrap_local_state_changed"));
        }
        Ok(())
    }
    pub(crate) fn boundary(&self) -> Result<()> {
        self.charge(
            128 + 8 * self.state.path.as_os_str().len() as u64,
            1024 + 8 * self.state.path.as_os_str().len() as u64,
        )?;
        let root = fs::symlink_metadata(&self.state.path).map_err(|_| failed())?;
        let held = self.root.metadata().map_err(|_| failed())?;
        let root_stamp = io_stamp(&root);
        let lock_stamp =
            io_stamp(&fs::symlink_metadata(self.state.path.join(".lock")).map_err(|_| failed())?);
        if !root.is_dir()
            || (root.dev(), root.ino()) != self.root_id
            || (held.dev(), held.ino()) != self.root_id
            || root_stamp[..5] != self.root_stamp.get()[..5]
            || lock_stamp[..6] != self.lock_stamp.get()[..6]
            || io_stamp(&held) != root_stamp
            || self.state.import_lock_identity()? != self.lock_id
            || self.state.import_identity() != self.identity.as_ref()
            || self.state.import_key_hash()? != self.key_hash
        {
            return Err(Error::state("team_bootstrap_local_state_changed"));
        }
        if root_stamp != self.root_stamp.get() || lock_stamp != self.lock_stamp.get() {
            self.private_path(&self.state.path, true)?;
            self.private_path(&self.state.path.join(".lock"), false)?;
            self.root_stamp.set(root_stamp);
            self.lock_stamp.set(lock_stamp);
        }
        Ok(())
    }
    pub(crate) fn anchor_revision(&self) -> Result<ImportRootObservation> {
        self.boundary()?;
        Ok(ImportRootObservation {
            root: self.root_stamp.get(),
            lock: self.lock_stamp.get(),
        })
    }
    fn refuse<T>(&self, error: Error) -> Result<T> {
        *self.failure.borrow_mut() = Some(error.clone());
        Err(error)
    }
    pub(crate) fn charge(&self, work: u64, bytes: u64) -> Result<()> {
        self.check()?;
        if let Some(history) = self.history {
            history.charge_import(work, bytes)?;
        } else {
            self.budget.charge(work, bytes)?;
        }
        let Some(work) = self
            .work
            .get()
            .checked_add(work)
            .filter(|n| *n <= 67_108_864)
        else {
            return self.refuse(Error::state("team_bootstrap_limit_exceeded"));
        };
        let Some(bytes) = self.charged.get().checked_add(bytes) else {
            return self.refuse(Error::state("team_bootstrap_limit_exceeded"));
        };
        self.work.set(work);
        self.charged.set(bytes);
        Ok(())
    }
    pub(crate) fn generation(&self) -> Result<u64> {
        self.check()?;
        self.history
            .map_or_else(|| Ok(self.generation.get()), |h| h.mutation_generation())
    }
    pub(crate) fn invalidate(&self) -> Result<()> {
        if let Some(history) = self.history {
            history.invalidate()?;
        } else {
            self.generation
                .set(self.generation.get().checked_add(1).ok_or_else(failed)?);
        }
        self.check()
    }
    fn private_path(&self, path: &Path, directory: bool) -> Result<()> {
        self.charge(1 + path.as_os_str().len() as u64, 256)?;
        let before = fs::symlink_metadata(path).map_err(|_| failed())?;
        let generation = self.generation()?;
        let key = (path.to_path_buf(), directory);
        let stamp = io_stamp(&before);
        if self.paths.entries.borrow().get(&key) == Some(&(generation, stamp)) {
            return Ok(());
        }
        private(path, directory)?;
        self.charge(1, 256)?;
        if io_stamp(&fs::symlink_metadata(path).map_err(|_| failed())?) != stamp {
            return Err(failed());
        }
        if self.paths.entries.borrow().len() >= 65_536 {
            return Err(failed());
        }
        self.paths
            .entries
            .borrow_mut()
            .insert(key, (generation, stamp));
        self.check()
    }
    pub(crate) fn validate_relative(&self, name: &str, directory: bool) -> Result<()> {
        self.private_path(&self.state.path, true)?;
        let parts = Path::new(name).components().collect::<Vec<_>>();
        let mut path = self.state.path.clone();
        for (index, part) in parts.iter().enumerate() {
            let Component::Normal(part) = part else {
                return Err(failed());
            };
            path.push(part);
            self.private_path(&path, index + 1 < parts.len() || directory)?;
        }
        self.check()
    }
    pub(crate) fn read(&self, name: &str, cap: u64) -> Result<Option<Vec<u8>>> {
        use rustix::fs::{Mode, OFlags, openat};
        use std::io::Read;
        self.boundary()?;
        self.charge(1 + name.len() as u64, name.len() as u64)?;
        let relative = Path::new(name);
        let parts = relative.components().collect::<Vec<_>>();
        if parts.is_empty() || parts.iter().any(|c| !matches!(c, Component::Normal(_))) {
            return Err(failed());
        }
        let mut parent = self.root.try_clone().map_err(|_| failed())?;
        let mut current = self.state.path.clone();
        for (index, part) in parts.iter().enumerate() {
            let Component::Normal(part) = part else {
                return Err(failed());
            };
            self.charge(1 + part.len() as u64, 256 + part.len() as u64)?;
            current.push(part);
            let directory = index + 1 < parts.len();
            let flags = OFlags::RDONLY
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | if directory {
                    OFlags::DIRECTORY
                } else {
                    OFlags::NONBLOCK
                };
            let descriptor = match openat(&parent, *part, flags, Mode::empty()) {
                Ok(fd) => File::from(fd),
                Err(error) if error == rustix::io::Errno::NOENT => {
                    self.boundary()?;
                    return Ok(None);
                }
                Err(_) => return Err(failed()),
            };
            #[cfg(test)]
            if !directory {
                opus_cost::metric(self.state, "raw_opens", 1);
            }
            self.private_path(&current, directory)?;
            let before = descriptor.metadata().map_err(|_| failed())?;
            let path = fs::symlink_metadata(&current).map_err(|_| failed())?;
            if io_stamp(&before) != io_stamp(&path) {
                return Err(failed());
            }
            if directory {
                parent = descriptor;
                continue;
            }
            if before.len() > cap {
                return self.refuse(Error::state("team_bootstrap_limit_exceeded"));
            }
            let bound = before.len().checked_add(1).ok_or_else(failed)?;
            self.charge(bound, bound.checked_mul(4).ok_or_else(failed)?)?;
            let mut raw = Vec::new();
            let read = (&descriptor).take(bound).read_to_end(&mut raw);
            #[cfg(test)]
            {
                opus_cost::metric(self.state, "raw_bytes", raw.len() as u64);
                if name.ends_with("/provenance/install-journal.json") {
                    opus_cost::metric(self.state, "cold_body_bytes", raw.len() as u64);
                }
                if name.ends_with("/provenance/payload.json") {
                    opus_cost::metric(self.state, "payload_materialized_bytes", raw.len() as u64);
                }
            }
            read.map_err(|_| failed())?;
            if raw.len() as u64 != before.len()
                || io_stamp(&before) != io_stamp(&descriptor.metadata().map_err(|_| failed())?)
                || io_stamp(&before)
                    != io_stamp(&fs::symlink_metadata(&current).map_err(|_| failed())?)
            {
                return Err(failed());
            }
            self.boundary()?;
            return Ok(Some(raw));
        }
        Err(failed())
    }
    pub(crate) fn parse(&self, raw: &[u8], cap: u64) -> Result<Value> {
        self.parse_document(raw, cap, 64, 65_536, true)
    }
    pub(crate) fn business_json(&self, name: &str, raw: &[u8]) -> Result<Value> {
        self.parse_document(
            raw,
            67_108_864,
            crate::pyjson::MAX_JSON_DEPTH as u64,
            1_048_576,
            false,
        )
        .map_err(|error| {
            if matches!(
                error.reason.as_ref(),
                "team_bootstrap_limit_exceeded"
                    | "team_bootstrap_timeout"
                    | "team_bootstrap_local_state_changed"
            ) {
                error
            } else {
                Error::state("state_corrupt").with_detail(name)
            }
        })
    }
    fn parse_document(
        &self,
        raw: &[u8],
        cap: u64,
        maximum_depth: u64,
        maximum_nodes: u64,
        strict: bool,
    ) -> Result<Value> {
        if raw.len() as u64 > cap {
            return self.refuse(Error::state("team_bootstrap_limit_exceeded"));
        }
        let n = raw.len() as u64;
        #[cfg(test)]
        {
            opus_cost::metric(self.state, "parse_calls", 1);
            opus_cost::metric(self.state, "parse_bytes", n);
        }
        self.charge(n, n.checked_mul(4).ok_or_else(failed)?)?;
        let (mut depth, mut nodes, mut quoted, mut escaped, mut scalar) =
            (0u64, 0u64, false, false, false);
        for byte in raw {
            if quoted {
                if escaped {
                    escaped = false;
                } else if *byte == b'\\' {
                    escaped = true;
                } else if *byte == b'"' {
                    quoted = false;
                }
                continue;
            }
            match *byte {
                b'"' => {
                    quoted = true;
                    scalar = false;
                    nodes += 1;
                }
                b'{' | b'[' => {
                    depth += 1;
                    nodes += 1;
                    scalar = false;
                }
                b'}' | b']' => {
                    depth = depth.checked_sub(1).ok_or_else(failed)?;
                    scalar = false;
                }
                b' ' | b'\n' | b'\r' | b'\t' | b',' | b':' => scalar = false,
                _ => {
                    if !scalar {
                        nodes += 1;
                    }
                    scalar = true;
                }
            }
            if depth > maximum_depth || nodes > maximum_nodes {
                return self.refuse(Error::state("team_bootstrap_limit_exceeded"));
            }
        }
        self.charge(
            n.checked_mul(4)
                .and_then(|v| v.checked_add(nodes))
                .ok_or_else(failed)?,
            n.checked_mul(32)
                .and_then(|v| v.checked_add(nodes.checked_mul(64)?))
                .ok_or_else(failed)?,
        )?;
        #[cfg(test)]
        opus_cost::metric(self.state, "screen_nodes", nodes);
        let value = if strict {
            crate::team::commit::retained_import_json(raw)?
        } else {
            pyjson::loads(std::str::from_utf8(raw).map_err(|_| failed())?).map_err(|_| failed())?
        };
        self.check()?;
        Ok(value)
    }
    pub(crate) fn json(&self, name: &str, cap: u64) -> Result<Option<Value>> {
        self.read(name, cap)?
            .map(|raw| self.parse(&raw, cap))
            .transpose()
    }
    pub(crate) fn list(&self, name: &str) -> Result<Vec<String>> {
        use rustix::fs::{Dir, Mode, OFlags, openat};
        self.boundary()?;
        let mut parent = self.root.try_clone().map_err(|_| failed())?;
        let mut current = self.state.path.clone();
        for part in Path::new(name).components() {
            let Component::Normal(part) = part else {
                return Err(failed());
            };
            self.charge(1 + part.len() as u64, 256 + part.len() as u64)?;
            let child = match openat(
                &parent,
                part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => File::from(fd),
                Err(error) if error == rustix::io::Errno::NOENT => return Ok(Vec::new()),
                Err(_) => return Err(failed()),
            };
            current.push(part);
            self.private_path(&current, true)?;
            if io_stamp(&child.metadata().map_err(|_| failed())?)
                != io_stamp(&fs::symlink_metadata(&current).map_err(|_| failed())?)
            {
                return Err(failed());
            }
            parent = child;
        }
        let before = parent.metadata().map_err(|_| failed())?;
        self.charge(1, 256)?;
        let mut directory = Dir::read_from(&parent).map_err(|_| failed())?;
        let mut names = Vec::new();
        loop {
            self.charge(1, 256)?;
            let Some(entry) = directory.read() else {
                break;
            };
            let entry = entry.map_err(|_| failed())?;
            let name = entry.file_name().to_str().map_err(|_| failed())?;
            if matches!(name, "." | "..") {
                continue;
            }
            if names.len() >= 65_536 {
                return Err(failed());
            }
            self.charge(name.len() as u64, name.len() as u64)?;
            names.push(name.to_owned());
        }
        if io_stamp(&before) != io_stamp(&parent.metadata().map_err(|_| failed())?)
            || io_stamp(&before) != io_stamp(&fs::symlink_metadata(current).map_err(|_| failed())?)
        {
            return Err(failed());
        }
        self.boundary()?;
        Ok(names)
    }
    pub(crate) fn hash(&self, raw: &[u8]) -> Result<String> {
        use sha2::{Digest, Sha256};
        self.charge(raw.len() as u64, raw.len() as u64)?;
        #[cfg(test)]
        opus_cost::metric(self.state, "sha_bytes", raw.len() as u64);
        let digest = hex::encode(Sha256::digest(raw));
        self.check()?;
        Ok(digest)
    }
    fn verify(
        &self,
        value: &Value,
        signer: &crate::team::identity::DeviceRecord,
        domain: &str,
        env: &str,
        size: u64,
    ) -> Result<()> {
        self.charge(
            size.checked_mul(12)
                .and_then(|v| v.checked_add(4096))
                .ok_or_else(failed)?,
            size.checked_mul(16).ok_or_else(failed)?,
        )?;
        let mut unsigned = value.clone();
        let signature = unsigned
            .as_object_mut()
            .ok_or_else(failed)?
            .remove("sig")
            .ok_or_else(failed)?;
        let signature = crate::pybase64::b64decode_strict(signature.as_str().ok_or_else(failed)?)
            .map_err(|_| failed())?;
        #[cfg(test)]
        opus_cost::metric(self.state, "signature_checks", 1);
        if value["domain"] != domain
            || value["env_id"] != env
            || !crate::crypto::ed25519::verify(
                &signer.sign_pub,
                &crate::team::bootstrap::bytes(&unsigned)?,
                &signature,
            )
        {
            return Err(failed());
        }
        self.check()
    }
    fn digest(&self, value: &Value, bound: u64) -> Result<String> {
        self.charge(
            bound.checked_mul(5).ok_or_else(failed)?,
            bound.checked_mul(8).ok_or_else(failed)?,
        )?;
        let result = crate::team::bootstrap::digest(value)?;
        self.check()?;
        Ok(result)
    }
}
fn io_stamp(m: &fs::Metadata) -> [u64; 11] {
    [
        m.dev(),
        m.ino(),
        m.mode() as u64,
        m.uid() as u64,
        m.gid() as u64,
        m.nlink(),
        m.len(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ]
}

struct Observation {
    raw: Option<Vec<u8>>,
    stamp: Option<[u64; 11]>,
    cap: u64,
}
/// Immediate-use view of signed import metadata under one actual lock and
/// mutation generation. The cold journal is a structural witness here only.
pub(crate) struct VisibilityEpoch<'e, 'g, 'a> {
    io: &'e ImportIo<'g, 'a>,
    generation: u64,
    root: ImportRootObservation,
    observations: std::collections::BTreeMap<String, Observation>,
    records: Value,
    manifests: std::collections::BTreeMap<String, Value>,
    payloads: std::cell::RefCell<std::collections::BTreeSet<String>>,
    discovery: Vec<(String, [u64; 11])>,
    small_bytes: u64,
    restore_pending: bool,
    business: std::collections::BTreeMap<String, Value>,
}
impl<'e, 'g, 'a> VisibilityEpoch<'e, 'g, 'a> {
    pub(crate) fn state(&self) -> &'a StateDir {
        self.io.state()
    }
    pub(crate) fn capture(io: &'e ImportIo<'g, 'a>) -> Result<Self> {
        let mut view = Self {
            io,
            generation: io.generation()?,
            root: io.anchor_revision()?,
            observations: Default::default(),
            records: serde_json::json!({}),
            manifests: Default::default(),
            payloads: Default::default(),
            discovery: Vec::new(),
            small_bytes: 0,
            restore_pending: false,
            business: Default::default(),
        };
        if io.identity.is_some() {
            let raw = view
                .observe(crate::team::identity::DEVICE_KEY_FILE, 65_536)?
                .ok_or_else(failed)?;
            let hash = io.hash(&raw)?;
            if io
                .key_hash
                .is_none_or(|expected| hex::encode(expected) != hash)
            {
                return Err(failed());
            }
        }
        let index = view.observe(INDEX, 1_048_576);
        let mut damaged = index.as_ref().is_err();
        if let Ok(Some(raw)) = index {
            match io.parse(&raw, 1_048_576) {
                Ok(value) if value.is_object() => view.records = value,
                _ => {
                    io.check()?;
                    damaged = true;
                }
            }
        }
        if let Some(raw) = view.observe(crate::policy::CONTROL, 65_536)? {
            let control = io.parse(&raw, 65_536)?;
            view.restore_pending = control["restore_pending"] == true;
            view.business.insert(crate::policy::CONTROL.into(), control);
        }
        let envs = view.discover()?;
        if damaged && envs.is_empty() {
            return Err(failed());
        }
        for (env, record) in view.records.as_object().into_iter().flatten() {
            io.charge(env.len() as u64 + 1, env.len() as u64)?;
            if !crate::team::commit::valid_env_id(env) || !record.is_object() {
                return Err(failed());
            }
        }
        for env in envs {
            if view.records.get(&env).is_none() {
                view.records[&env] = serde_json::json!({"state":"recovery_required"});
            }
        }
        let names = view
            .records
            .as_object()
            .ok_or_else(failed)?
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for env in names {
            let valid = !damaged && view.authenticate(&env).is_ok();
            io.check()?;
            if !valid {
                view.records[&env]["state"] = serde_json::json!("recovery_required");
            }
            for (leaf, reason) in [
                (
                    "history-required.json",
                    Some("team_checkpoint_history_required"),
                ),
                ("member-removed.json", None),
                (LOCAL_REMOVAL_DENIAL, None),
            ] {
                let name = crate::team::bootstrap::path(&env, leaf)?;
                io.charge(1 + name.len() as u64, 256)?;
                let present = !matches!(fs::symlink_metadata(io.state.path.join(&name)), Err(e) if e.kind() == std::io::ErrorKind::NotFound);
                if present {
                    if let Some(reason) = reason {
                        view.records[&env]["state"] = serde_json::json!("recovery_required");
                        view.records[&env]["reason"] = serde_json::json!(reason);
                    } else {
                        view.records[&env]["local_member_removed"] = serde_json::json!(true);
                    }
                }
                // A witness's presence, including corrupt or ambiguous metadata,
                // denies. Its raw bytes are not needed to exercise that denial.
            }
        }
        io.check()?;
        Ok(view)
    }
    fn observe(&mut self, name: &str, cap: u64) -> Result<Option<Vec<u8>>> {
        if self.observations.contains_key(name) {
            return Err(failed());
        }
        let raw = self.io.read(name, cap)?;
        self.small_bytes = self
            .small_bytes
            .checked_add(raw.as_ref().map_or(0, |v| v.len() as u64))
            .filter(|n| *n <= 1_048_576)
            .ok_or_else(failed)?;
        self.io.charge(
            raw.as_ref().map_or(0, |v| v.len() as u64),
            raw.as_ref().map_or(0, |v| v.len() as u64),
        )?;
        self.io.charge(1, 256)?;
        let stamp = match fs::symlink_metadata(self.io.state.path.join(name)) {
            Ok(m) => Some(io_stamp(&m)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(failed()),
        };
        self.observations.insert(
            name.into(),
            Observation {
                raw: raw.clone(),
                stamp,
                cap,
            },
        );
        Ok(raw)
    }
    fn discover(&mut self) -> Result<Vec<String>> {
        self.io.charge(1, 256)?;
        let directory = match fs::read_dir(self.io.state.path.join("team")) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(failed()),
        };
        let mut names = Vec::new();
        for entry in directory {
            self.io.charge(1, 256)?;
            if names.len() >= 65_536 {
                return Err(failed());
            }
            let name = entry
                .map_err(|_| failed())?
                .file_name()
                .into_string()
                .map_err(|_| failed())?;
            self.io.charge(name.len() as u64, name.len() as u64)?;
            names.push(name);
        }
        let width = names.iter().map(String::len).max().unwrap_or(1) as u64;
        self.io.charge(
            (names.len() as u64)
                .checked_mul(names.len() as u64)
                .and_then(|n| n.checked_mul(width))
                .ok_or_else(failed)?,
            0,
        )?;
        names.sort();
        let mut witnessed = Vec::new();
        for env in names
            .into_iter()
            .filter(|n| crate::team::commit::valid_env_id(n))
        {
            self.io.charge(1 + env.len() as u64, 256)?;
            let name = format!("team/{env}/bootstrap");
            match fs::symlink_metadata(self.io.state.path.join(&name)) {
                Ok(m) => {
                    self.discovery.push((name.clone(), io_stamp(&m)));
                    let mut evidence = false;
                    for leaf in [
                        "journal.json",
                        "receipt.json",
                        "provenance",
                        "history-required.json",
                        "member-removed.json",
                        LOCAL_REMOVAL_DENIAL,
                    ] {
                        self.io
                            .charge(1 + name.len() as u64 + leaf.len() as u64, 256)?;
                        match fs::symlink_metadata(self.io.state.path.join(&name).join(leaf)) {
                            Ok(metadata) => {
                                evidence = true;
                                self.discovery
                                    .push((format!("{name}/{leaf}"), io_stamp(&metadata)));
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(_) => {
                                evidence = true;
                            }
                        }
                    }
                    if evidence {
                        witnessed.push(env);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(failed()),
            }
            if witnessed.len() > 256 {
                return Err(failed());
            }
        }
        Ok(witnessed)
    }
    fn authenticate(&mut self, env: &str) -> Result<()> {
        let record = self.records[env].clone();
        let identity = self.io.identity.as_ref().ok_or_else(failed)?;
        let index_size = self
            .observations
            .get(INDEX)
            .and_then(|o| o.raw.as_ref())
            .map_or(0, |v| v.len() as u64);
        self.io.verify(
            &record,
            identity,
            "zeropw-personal-import-visibility-v1",
            env,
            index_size,
        )?;
        // A fault at this observation must remain fatal across capture's
        // per-environment blocked classification, before any later write.
        #[cfg(test)]
        testing::hit(self.io.state, env, "visibility-index-authenticated")
            .or_else(|error| self.io.refuse(error))?;
        if record["state"] != "committed" {
            return Err(failed());
        }
        let compact_raw = self
            .observe(
                &crate::team::bootstrap::path(env, "journal.json")?,
                1_048_576,
            )?
            .ok_or_else(failed)?;
        let compact = self.io.parse(&compact_raw, 1_048_576)?;
        self.io.verify(
            &compact,
            identity,
            "zeropw-personal-import-journal-v1",
            env,
            compact_raw.len() as u64,
        )?;
        let fields = [
            "domain",
            "v",
            "layout",
            "state",
            "env_id",
            "epoch",
            "manifest_hash",
            "ready",
            "receipt",
            "visibility",
            "signer_record",
            "recipient_record",
            "genesis_hash",
            "admission_hash",
            "manifest_raw_sha256",
            "payload_sha256",
            "payload_length",
            "cold_journal_sha256",
            "cold_journal_length",
            "sig",
        ];
        if compact.as_object().is_none_or(|m| {
            m.len() != fields.len() || fields.iter().any(|key| !m.contains_key(*key))
        }) || compact["v"] != 1
            || compact["layout"] != "compact_committed_v1"
            || compact["state"] != "COMMITTED"
            || compact["epoch"] != record["epoch"]
            || compact["manifest_hash"] != record["manifest_hash"]
            || compact["recipient_record"] != identity.to_dict()
            || record["commit_journal_sha256"] != self.io.hash(&compact_raw)?
        {
            return Err(failed());
        }
        let owner = crate::team::identity::DeviceRecord::from_dict(&compact["signer_record"])?;
        #[cfg(test)]
        testing::hit(self.io.state, env, "visibility-compact-authenticated")
            .or_else(|error| self.io.refuse(error))?;
        if !owner.verify_uncached()
            || crate::team::commit::env_owner_fingerprint(env)? != owner.fingerprint()
        {
            return Err(failed());
        }
        let receipt_raw = self
            .observe(&crate::team::bootstrap::path(env, "receipt.json")?, 65_536)?
            .ok_or_else(failed)?;
        let receipt = self.io.parse(&receipt_raw, 65_536)?;
        self.io.verify(
            &receipt,
            identity,
            "zeropw-team-bootstrap-receipt-v1",
            env,
            receipt_raw.len() as u64,
        )?;
        let manifest_raw = self
            .observe(
                &crate::team::bootstrap::path(env, "provenance/manifest.json")?,
                65_536,
            )?
            .ok_or_else(failed)?;
        let manifest = self.io.parse(&manifest_raw, 65_536)?;
        self.io.verify(
            &manifest,
            &owner,
            "zeropw-team-bootstrap-v1",
            env,
            manifest_raw.len() as u64,
        )?;
        self.io.verify(
            &compact["ready"],
            &owner,
            "zeropw-team-bootstrap-ready-v1",
            env,
            compact_raw.len() as u64,
        )?;
        let mut expected = compact["visibility"].clone();
        self.io.verify(
            &expected,
            identity,
            "zeropw-personal-import-visibility-v1",
            env,
            compact_raw.len() as u64,
        )?;
        #[cfg(test)]
        testing::hit(self.io.state, env, "visibility-signatures-authenticated")
            .or_else(|error| self.io.refuse(error))?;
        expected["state"] = serde_json::json!("committed");
        expected["receipt_sha256"] = record["receipt_sha256"].clone();
        expected["commit_journal_sha256"] = record["commit_journal_sha256"].clone();
        expected["sig"] = record["sig"].clone();
        if expected != record
            || receipt != compact["receipt"]
            || receipt["epoch"] != compact["epoch"]
            || receipt["signer"] != owner.fingerprint()
            || receipt["recipient"] != identity.fingerprint()
            || self.io.digest(&receipt, receipt_raw.len() as u64)? != record["receipt_sha256"]
            || self.io.digest(&manifest, manifest_raw.len() as u64)? != record["manifest_hash"]
            || compact["manifest_raw_sha256"] != self.io.hash(&manifest_raw)?
            || compact["payload_sha256"] != manifest["payload"]["sha256"]
            || compact["payload_length"] != manifest["payload"]["byte_length"]
            || compact["admission_hash"] != manifest["recipient_admission_commit_hash"]
            || receipt["ready_sha256"]
                != self
                    .io
                    .digest(&compact["ready"], compact_raw.len() as u64)?
            || compact["ready"]["manifest_hash"] != record["manifest_hash"]
        {
            return Err(failed());
        }
        #[cfg(test)]
        testing::hit(self.io.state, env, "visibility-bindings-authenticated")
            .or_else(|error| self.io.refuse(error))?;
        for (leaf, length, cap) in [
            (
                "provenance/install-journal.json",
                &compact["cold_journal_length"],
                67_108_864u64,
            ),
            (
                "provenance/payload.json",
                &compact["payload_length"],
                16_777_216u64,
            ),
        ] {
            let name = crate::team::bootstrap::path(env, leaf)?;
            self.io.charge(1 + name.len() as u64, 256)?;
            private_relative(self.io.state, &name)?;
            let metadata =
                fs::symlink_metadata(self.io.state.path.join(name)).map_err(|_| failed())?;
            if !metadata.is_file()
                || length
                    .as_u64()
                    .is_none_or(|n| n > cap || n != metadata.len())
            {
                return Err(failed());
            }
        }
        self.manifests.insert(env.into(), manifest);
        Ok(())
    }
    pub(crate) fn records(&self) -> &Value {
        &self.records
    }
    fn business_document(&mut self, name: &str, default: Value) -> Result<Value> {
        if !self.business.contains_key(name) {
            let raw = self.io.read(name, 67_108_864)?;
            let value = raw
                .as_ref()
                .map(|raw| self.io.business_json(name, raw))
                .transpose()?
                .unwrap_or(default);
            self.io.charge(1 + name.len() as u64, 256)?;
            let stamp = match fs::symlink_metadata(self.io.state.path.join(name)) {
                Ok(m) => Some(io_stamp(&m)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(_) => return Err(failed()),
            };
            self.observations.insert(
                name.into(),
                Observation {
                    raw,
                    stamp,
                    cap: 67_108_864,
                },
            );
            self.business.insert(name.into(), value);
        }
        let n = self
            .observations
            .get(name)
            .and_then(|o| o.raw.as_ref())
            .map_or(0, |raw| raw.len() as u64);
        self.io.charge(
            n.checked_mul(2).ok_or_else(failed)?,
            n.checked_mul(64).ok_or_else(failed)?,
        )?;
        Ok(self.business.get(name).ok_or_else(failed)?.clone())
    }
    // Explicit forwarding seam retained for deferred MEDIUM02 integration.
    #[allow(dead_code)]
    pub(crate) fn read_json(&mut self, name: &str, default: Value) -> Result<Value> {
        let value = self.business_document(name, default)?;
        self.filter(name, value)
    }
    pub(crate) fn raw_json(&mut self, name: &str, default: Value) -> Result<Value> {
        self.business_document(name, default)
    }
    pub(crate) fn require_path(&self, name: &str) -> Result<()> {
        let mut parts = name.split('/');
        if parts.next() == Some("team")
            && let Some(env) = parts.next()
            && crate::team::commit::valid_env_id(env)
            && parts.next() != Some("bootstrap")
        {
            self.require_env(env)?;
        }
        Ok(())
    }
    pub(crate) fn filter(&self, name: &str, value: Value) -> Result<Value> {
        if name == crate::team::identity::DEVICE_KEY_FILE {
            return Ok(value);
        }
        for (env, record) in self.records.as_object().into_iter().flatten() {
            if record["state"] == "committed"
                && record["local_member_removed"] != true
                && !self.restore_pending
            {
                self.require_env(env)?;
            }
        }
        visible_records(&self.records, self.restore_pending, name, value)
    }
    pub(crate) fn require_secret(&mut self, id: &str) -> Result<()> {
        self.require_id(id, true)
    }
    pub(crate) fn require_connection(&mut self, id: &str) -> Result<()> {
        self.require_id(id, false)
    }
    fn require_id(&mut self, id: &str, secret: bool) -> Result<()> {
        let name = if secret {
            crate::vault::VAULT_DOC
        } else {
            crate::policy::CONNECTIONS
        };
        let doc = self.business_document(name, Value::Null)?;
        let entry = if secret {
            &doc["secrets"][id]
        } else {
            &doc[id]
        };
        for (env, record) in self.records.as_object().into_iter().flatten() {
            let ids = if secret {
                &record["secret_ids"]
            } else {
                &record["connection_ids"]
            };
            self.io.charge(1 + id.len() as u64 + env.len() as u64, 0)?;
            if entry["shared_env"] == *env
                || ids
                    .as_array()
                    .is_some_and(|ids| ids.iter().any(|v| v.as_str() == Some(id)))
            {
                self.require_credential_env(env)?;
            }
        }
        Ok(())
    }
    pub(crate) fn require_credential_env(&self, env: &str) -> Result<()> {
        self.require_env(env)?;
        if let Some(record) = self.records.get(env) {
            if record["local_member_removed"] == true {
                return Err(Error::policy_denied("team_member_removed"));
            }
            if self.restore_pending {
                return Err(Error::policy_denied("restore_pending"));
            }
        }
        self.io.check()
    }
    pub(crate) fn projection_denied(&self, env: &str) -> Result<bool> {
        if let Some(record) = self.records.get(env) {
            if record["state"] != "committed" {
                return Err(Error::state("team_bootstrap_recovery_required"));
            }
            if record["local_member_removed"] == true || self.restore_pending {
                return Ok(true);
            }
            self.require_env(env)?;
        }
        Ok(false)
    }
    pub(crate) fn personal_manifest(&self, env: &str) -> Result<Option<Value>> {
        self.require_env(env)?;
        if let Some(manifest) = self.manifests.get(env) {
            self.io.charge(65_536, 65_536 * 64)?;
            return Ok(Some(manifest.clone()));
        }
        Ok(None)
    }
    pub(crate) fn require_env(&self, env: &str) -> Result<()> {
        if let Some(record) = self.records.get(env) {
            if record["state"] != "committed" {
                return Err(Error::state(
                    if record["reason"] == "team_checkpoint_history_required" {
                        "team_checkpoint_history_required"
                    } else {
                        "team_bootstrap_recovery_required"
                    },
                ));
            }
            self.payloads.borrow_mut().insert(env.into());
        }
        self.io.check()
    }
    pub(crate) fn finish(self) -> Result<()> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        if self.generation != self.io.generation()? {
            return Err(Error::state("team_bootstrap_local_state_changed"));
        }
        let mut payload_total = 0u64;
        for env in self.payloads.borrow().iter() {
            let manifest = self.manifests.get(env).ok_or_else(failed)?;
            let length = manifest["payload"]["byte_length"]
                .as_u64()
                .ok_or_else(failed)?;
            payload_total = payload_total
                .checked_add(length)
                .filter(|n| *n <= 16_777_216)
                .ok_or_else(failed)?;
            let name = crate::team::bootstrap::path(env, "provenance/payload.json")?;
            // Streaming keeps the original ciphertext opaque and the buffer
            // <=64KiB. Charge the read/hash passes before opening it.
            self.io.charge(
                length
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(failed)?,
                length.checked_mul(5).ok_or_else(failed)?,
            )?;
            private_relative(self.io.state, &name)?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(self.io.state.path.join(&name))
                .map_err(|_| failed())?;
            let before = file.metadata().map_err(|_| failed())?;
            if !before.is_file() || before.len() != length {
                return Err(failed());
            }
            let mut reader = (&file).take(length.checked_add(1).ok_or_else(failed)?);
            let mut hash = Sha256::new();
            let mut buffer = [0u8; 65_536];
            let mut count = 0u64;
            loop {
                self.io.check()?;
                let n = reader.read(&mut buffer).map_err(|_| failed())?;
                if n == 0 {
                    break;
                }
                count = count.checked_add(n as u64).ok_or_else(failed)?;
                hash.update(&buffer[..n]);
            }
            if count != length
                || hex::encode(hash.finalize()) != manifest["payload"]["sha256"]
                || io_stamp(&before) != io_stamp(&file.metadata().map_err(|_| failed())?)
                || io_stamp(&before)
                    != io_stamp(
                        &fs::symlink_metadata(self.io.state.path.join(name))
                            .map_err(|_| failed())?,
                    )
            {
                return Err(failed());
            }
        }
        for (name, observation) in &self.observations {
            if self.io.read(name, observation.cap)? != observation.raw {
                return Err(Error::state("team_bootstrap_local_state_changed"));
            }
            self.io.charge(1, 256)?;
            let stamp = match fs::symlink_metadata(self.io.state.path.join(name)) {
                Ok(m) => Some(io_stamp(&m)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(_) => return Err(failed()),
            };
            if stamp != observation.stamp {
                return Err(Error::state("team_bootstrap_local_state_changed"));
            }
        }
        let mut recheck = Self {
            io: self.io,
            generation: self.generation,
            root: self.io.anchor_revision()?,
            observations: Default::default(),
            records: Value::Null,
            manifests: Default::default(),
            payloads: Default::default(),
            discovery: Vec::new(),
            small_bytes: 0,
            restore_pending: false,
            business: Default::default(),
        };
        recheck.discover()?;
        if recheck.discovery != self.discovery {
            return Err(Error::state("team_bootstrap_local_state_changed"));
        }
        if self.io.anchor_revision()? != self.root {
            return Err(Error::state("team_bootstrap_local_state_changed"));
        }
        self.io.boundary()
    }
}

/// Lock-free routing DATA for the legacy deferred observer. This can select
/// locked validation; its digest never authorizes an import.
pub(crate) struct ImportWitness {
    digest: [u8; 32],
    present: bool,
    began: std::time::Instant,
    work: u64,
    bytes: u64,
}
impl ImportWitness {
    pub(crate) fn present(&self) -> bool {
        self.present
    }
    pub(crate) fn unchanged(&self, other: &Self) -> bool {
        self.digest == other.digest && self.present == other.present
    }
}
pub(crate) fn routing_witness(state: &StateDir) -> Result<ImportWitness> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut result = ImportWitness {
        digest: [0; 32],
        present: false,
        began: std::time::Instant::now(),
        work: 0,
        bytes: 0,
    };
    let mut charge = |work: u64, bytes: u64| -> Result<()> {
        if result.began.elapsed() >= std::time::Duration::from_secs(5) {
            return Err(Error::state("team_bootstrap_timeout"));
        }
        result.work = result
            .work
            .checked_add(work)
            .filter(|n| *n <= 67_108_864)
            .ok_or_else(|| Error::state("team_bootstrap_limit_exceeded"))?;
        result.bytes = result
            .bytes
            .checked_add(bytes)
            .filter(|n| *n <= 268_435_456)
            .ok_or_else(|| Error::state("team_bootstrap_limit_exceeded"))?;
        Ok(())
    };
    let mut hash = Sha256::new();
    charge(1 + INDEX.len() as u64, 256)?;
    match fs::symlink_metadata(state.path.join(INDEX)) {
        Ok(metadata) => {
            result.present = true;
            for word in io_stamp(&metadata) {
                hash.update(word.to_be_bytes());
            }
            if metadata.is_file() && metadata.len() <= 1_048_576 {
                let bound = metadata.len() + 1;
                charge(2 * bound + 3, 5 * bound)?;
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(state.path.join(INDEX))
                    .map_err(|_| failed())?;
                let mut bytes = Vec::new();
                (&file)
                    .take(bound)
                    .read_to_end(&mut bytes)
                    .map_err(|_| failed())?;
                if bytes.len() as u64 != metadata.len()
                    || io_stamp(&file.metadata().map_err(|_| failed())?) != io_stamp(&metadata)
                    || io_stamp(
                        &fs::symlink_metadata(state.path.join(INDEX)).map_err(|_| failed())?,
                    ) != io_stamp(&metadata)
                {
                    return Err(Error::state("team_bootstrap_local_state_changed"));
                }
                hash.update(bytes);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            hash.update([0]);
        }
        Err(_) => {
            result.present = true;
            hash.update([1]);
        }
    }
    charge(1, 256)?;
    let directory = match fs::read_dir(state.path.join("team")) {
        Ok(directory) => Some(directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(failed()),
    };
    let mut names = Vec::new();
    let mut visited = 0usize;
    for entry in directory.into_iter().flatten() {
        charge(1, 256)?;
        visited = visited
            .checked_add(1)
            .filter(|n| *n <= 65_536)
            .ok_or_else(failed)?;
        let name = entry
            .map_err(|_| failed())?
            .file_name()
            .into_string()
            .map_err(|_| failed())?;
        charge(name.len() as u64, name.len() as u64)?;
        if crate::team::commit::valid_env_id(&name) {
            names.push(name);
        }
    }
    let count = names.len() as u64;
    let width = names.iter().map(String::len).max().unwrap_or(1) as u64;
    charge(
        count
            .checked_mul(count)
            .and_then(|n| n.checked_mul(width))
            .ok_or_else(failed)?,
        0,
    )?;
    names.sort();
    for env in names {
        for leaf in [
            "journal.json",
            "receipt.json",
            "provenance",
            "history-required.json",
            "member-removed.json",
            LOCAL_REMOVAL_DENIAL,
        ] {
            let name = crate::team::bootstrap::path(&env, leaf)?;
            charge(1 + 2 * name.len() as u64, 256 + name.len() as u64)?;
            match fs::symlink_metadata(state.path.join(&name)) {
                Ok(metadata) => {
                    result.present = true;
                    hash.update(name.as_bytes());
                    for word in io_stamp(&metadata) {
                        hash.update(word.to_be_bytes());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    result.present = true;
                    hash.update(name.as_bytes());
                    hash.update([1]);
                }
            }
        }
    }
    charge(1, 0)?;
    result.digest = hash.finalize().into();
    Ok(result)
}

pub(crate) fn coherent_path(name: &str) -> bool {
    name.starts_with("team/")
        || [
            crate::vault::VAULT_DOC,
            crate::policy::CONNECTIONS,
            crate::projects::DOC,
            crate::tombstone::PATH,
        ]
        .contains(&name)
}
pub(crate) fn require_path(state: &StateDir, name: &str) -> Result<()> {
    let mut parts = name.split('/');
    if parts.next() == Some("team")
        && let Some(env) = parts.next()
        && crate::team::commit::valid_env_id(env)
        && parts.next() != Some("bootstrap")
    {
        require_env(state, env)?;
    }
    Ok(())
}

pub(crate) fn index(state: &StateDir) -> Result<Value> {
    let io = ImportIo::open(state)?;
    index_in(&io)
}
pub(crate) fn index_in(io: &ImportIo<'_, '_>) -> Result<Value> {
    let view = VisibilityEpoch::capture(io)?;
    for (env, record) in view.records().as_object().into_iter().flatten() {
        if record["state"] == "committed" && record["local_member_removed"] != true {
            view.require_env(env)?;
        }
    }
    io.charge(view.small_bytes, view.small_bytes)?;
    let records = view.records().clone();
    view.finish()?;
    Ok(records)
}

// Cold transaction DATA, never a public visibility decision. Callers must
// authenticate its exact per-epoch records under Context/Slot before writing.
pub(crate) fn raw_index_in(io: &ImportIo<'_, '_>) -> Result<Value> {
    let value = io
        .json(INDEX, 1_048_576)?
        .unwrap_or_else(|| serde_json::json!({}));
    if !value.is_object() {
        return Err(failed());
    }
    Ok(value)
}

pub(crate) fn require_env(state: &StateDir, env: &str) -> Result<()> {
    let io = ImportIo::open(state)?;
    let view = VisibilityEpoch::capture(&io)?;
    view.require_env(env)?;
    view.finish()
}
pub(crate) fn credential_projection_denied(state: &StateDir, env: &str) -> Result<bool> {
    if !state.locked_by_current_thread() {
        return Err(failed());
    }
    let io = ImportIo::open(state)?;
    let view = VisibilityEpoch::capture(&io)?;
    let denied = view.projection_denied(env)?;
    view.finish()?;
    Ok(denied)
}
// Private forwarding facade retained with the deferred MEDIUM02 work.
#[allow(dead_code)]
pub(crate) fn visible(state: &StateDir, name: &str, value: Value) -> Result<Value> {
    if name == crate::team::identity::DEVICE_KEY_FILE {
        return Ok(value);
    }
    let io = ImportIo::open(state)?;
    let view = VisibilityEpoch::capture(&io)?;
    let value = view.filter(name, value)?;
    view.finish()?;
    Ok(value)
}
fn visible_records(
    all: &Value,
    restore_pending: bool,
    name: &str,
    mut value: Value,
) -> Result<Value> {
    for (env, record) in all.as_object().into_iter().flatten() {
        if record["state"] == "committed"
            && record["local_member_removed"] != true
            && !restore_pending
        {
            continue;
        }
        if record["state"] == "committed"
            && ![crate::vault::VAULT_DOC, crate::policy::CONNECTIONS].contains(&name)
        {
            continue;
        }
        if name.starts_with(&format!("team/{env}/"))
            && !name.starts_with(&format!("team/{env}/bootstrap/"))
        {
            return Err(Error::state("team_bootstrap_recovery_required"));
        }
        if name == crate::vault::VAULT_DOC {
            if let Some(map) = value.get_mut("secrets").and_then(Value::as_object_mut) {
                map.retain(|id, entry| {
                    entry["shared_env"] != *env
                        && !record["secret_ids"]
                            .as_array()
                            .is_some_and(|ids| ids.contains(&serde_json::json!(id)))
                });
            }
        } else if name == crate::policy::CONNECTIONS {
            if let Some(map) = value.as_object_mut() {
                map.retain(|id, entry| {
                    entry["shared_env"] != *env
                        && !record["connection_ids"]
                            .as_array()
                            .is_some_and(|ids| ids.contains(&serde_json::json!(id)))
                });
            }
        } else if name == "team/envs.json" {
            if let Some(map) = value.as_object_mut() {
                map.remove(env);
            }
        } else if name == crate::projects::DOC
            && let (Some(project), Some(environment)) =
                (record["project"].as_str(), record["environment"].as_str())
            && let Some(entries) = value
                .get_mut(project)
                .and_then(|v| v.get_mut("environments"))
                .and_then(Value::as_array_mut)
        {
            entries.retain(|v| v != environment);
        }
    }
    Ok(value)
}

pub(crate) fn require_secret(state: &StateDir, id: &str) -> Result<()> {
    let io = ImportIo::open(state)?;
    let mut view = VisibilityEpoch::capture(&io)?;
    view.require_secret(id)?;
    view.finish()
}
pub(crate) fn require_connection(state: &StateDir, id: &str) -> Result<()> {
    let io = ImportIo::open(state)?;
    let mut view = VisibilityEpoch::capture(&io)?;
    view.require_connection(id)?;
    view.finish()
}

/// Called only after the existing fact-authority decision. This durable
/// deny-only witness prevents a cached imported credential from surviving
/// this receiver's removal, even if subsequent derivation needs history.
pub(crate) fn admitted_fact(state: &StateDir, fact: &crate::team::sync::Fact) -> Result<()> {
    if fact.kind == "member_removed"
        && state
            .import_identity()
            .is_some_and(|r| fact.target["fingerprint"] == r.fingerprint())
        && index(state)?.get(&fact.env_id).is_some()
    {
        let _lock = state.lock()?;
        json(
            state,
            &crate::team::bootstrap::path(&fact.env_id, "member-removed.json")?,
            &fact.to_dict(),
        )?;
    }
    Ok(())
}

// Private forwarding facade retained with the deferred MEDIUM02 work.
#[allow(dead_code)]
pub(crate) fn immutable(state: &StateDir, env: &str, record: &Value) -> Result<()> {
    let io = ImportIo::open(state)?;
    let view = VisibilityEpoch::capture(&io)?;
    if view.records().get(env) != Some(record) {
        return Err(Error::state("team_bootstrap_recovery_required"));
    }
    view.require_env(env)?;
    view.finish()
}
pub(crate) fn personal_manifest(state: &StateDir, env: &str) -> Result<Option<Value>> {
    let io = ImportIo::open(state)?;
    let view = VisibilityEpoch::capture(&io)?;
    let manifest = view.personal_manifest(env)?;
    view.finish()?;
    Ok(manifest)
}

pub(crate) fn history_required(state: &StateDir, env: &str, evidence: &Value) -> Result<Error> {
    let _lock = state.lock()?;
    let hash = crate::team::bootstrap::digest(evidence)?;
    json(
        state,
        &crate::team::bootstrap::path(env, &format!("history-required/{hash}.json"))?,
        evidence,
    )?;
    json(
        state,
        &crate::team::bootstrap::path(env, "history-required.json")?,
        &serde_json::json!({"reason":"team_checkpoint_history_required","evidence_sha256":hash}),
    )?;
    Ok(Error::state("team_checkpoint_history_required"))
}

pub(crate) fn backup_provenance(state: &StateDir) -> Result<Value> {
    let io = ImportIo::open(state)?;
    let view = VisibilityEpoch::capture(&io)?;
    let mut environments = serde_json::Map::new();
    for (env, record) in view.records().as_object().into_iter().flatten() {
        view.require_env(env)?;
        let mut compact = Value::Null;
        let mut files = serde_json::Map::new();
        let mut total_bytes = 0u64;
        for leaf in [
            "journal.json",
            "provenance/install-journal.json",
            "provenance/manifest.json",
            "provenance/payload.json",
            "provenance/basis.json",
            "receipt.json",
            "member-removed.json",
            LOCAL_REMOVAL_DENIAL,
        ] {
            let name = crate::team::bootstrap::path(env, leaf)?;
            let cap = match leaf {
                "journal.json" => 1_048_576,
                "provenance/install-journal.json" => 67_108_864,
                "provenance/manifest.json" | "receipt.json" => 65_536,
                _ => 16_777_216,
            };
            let Some(data) = io.read(&name, cap)? else {
                if matches!(leaf, "member-removed.json" | LOCAL_REMOVAL_DENIAL) {
                    continue;
                }
                return Err(failed());
            };
            total_bytes = total_bytes
                .checked_add(data.len() as u64)
                .filter(|n| *n <= 67_108_864)
                .ok_or_else(failed)?;
            if leaf == "journal.json" {
                compact = io.parse(&data, cap)?;
            }
            if leaf == "provenance/install-journal.json"
                && (compact["cold_journal_length"] != data.len() as u64
                    || compact["cold_journal_sha256"] != io.hash(&data)?)
            {
                return Err(failed());
            }
            let size = (data.len() as u64)
                .checked_add(2)
                .and_then(|n| n.checked_div(3))
                .and_then(|n| n.checked_mul(4))
                .ok_or_else(failed)?;
            io.charge(
                size.checked_mul(2).ok_or_else(failed)?,
                size.checked_mul(4).ok_or_else(failed)?,
            )?;
            files.insert(
                leaf.into(),
                serde_json::json!(crate::pybase64::b64encode(&data)),
            );
        }
        environments.insert(
            env.clone(),
            serde_json::json!({"visibility":record,"original_files_b64":files}),
        );
    }
    view.finish()?;
    if environments.is_empty() {
        return Ok(Value::Null);
    }
    Ok(
        serde_json::json!({"v":1,"local_record":state.import_identity().ok_or_else(failed)?.to_dict(),"environments":environments}),
    )
}

/// A backup preserves the attestation as original bytes. It confers no
/// replacement-device or repair authority: restore can only retain an intact
/// same-device epoch already present locally, never install a copied receipt.
pub(crate) fn check_restore_provenance(state: &StateDir, archived: &Value) -> Result<()> {
    if archived.is_null() {
        return Ok(());
    }
    let current = backup_provenance(state)?;
    if archived["v"] != 1
        || archived["local_record"] != current["local_record"]
        || archived["environments"]
            .as_object()
            .is_none_or(|m| m.is_empty())
    {
        return Err(Error::state("team_bootstrap_existing_state_unsupported"));
    }
    for (env, record) in current["environments"].as_object().into_iter().flatten() {
        if record["visibility"]["local_member_removed"] == true
            && archived["environments"].get(env).is_none()
        {
            return Err(Error::state("team_bootstrap_recovery_required"));
        }
    }
    for (env, value) in archived["environments"].as_object().into_iter().flatten() {
        if current["environments"].get(env) != Some(value) {
            return Err(Error::state("team_bootstrap_recovery_required"));
        }
    }
    Ok(())
}

/// Ordinary read/modify/write callers see a filtered view. Preserve reserved
/// unpublished entries when they save an unrelated edit, and refuse attempts
/// to write a reserved identity rather than overwriting the import projection.
pub(crate) fn preserve_hidden(state: &StateDir, name: &str, value: &Value) -> Result<Value> {
    if ![
        crate::vault::VAULT_DOC,
        crate::policy::CONNECTIONS,
        "team/envs.json",
        crate::projects::DOC,
    ]
    .contains(&name)
    {
        // These are the only documents with an imported projection to
        // preserve. Unrelated StateDir files keep their ordinary semantics.
        return Ok(value.clone());
    }
    let all = index(state)?;
    let mut result = value.clone();
    if !all
        .as_object()
        .into_iter()
        .flatten()
        .any(|(_, v)| v["state"] != "committed" || v["local_member_removed"] == true)
    {
        return Ok(result);
    }
    let target = state.path.join(name);
    let raw = if target.exists() {
        let b = fs::read(target).map_err(|_| failed())?;
        pyjson::loads(std::str::from_utf8(&b).map_err(|_| failed())?).map_err(|_| failed())?
    } else {
        Value::Null
    };
    for (env, rec) in all.as_object().into_iter().flatten() {
        if rec["state"] == "committed" && rec["local_member_removed"] != true {
            continue;
        }
        if name == "team/envs.json" {
            if result.get(env).is_some_and(|v| raw.get(env) != Some(v)) {
                return Err(Error::state("team_bootstrap_recovery_required"));
            }
            if let Some(v) = raw.get(env) {
                result
                    .as_object_mut()
                    .ok_or_else(failed)?
                    .insert(env.clone(), v.clone());
            }
            continue;
        }
        if name == crate::projects::DOC {
            let (Some(project), Some(environment)) =
                (rec["project"].as_str(), rec["environment"].as_str())
            else {
                continue;
            };
            if result[project]["environments"]
                .as_array()
                .is_some_and(|e| e.contains(&serde_json::json!(environment)))
                && !raw[project]["environments"]
                    .as_array()
                    .is_some_and(|e| e.contains(&serde_json::json!(environment)))
            {
                return Err(Error::state("team_bootstrap_recovery_required"));
            }
            if let Some(p) = raw.get(project)
                && p["environments"]
                    .as_array()
                    .is_some_and(|e| e.contains(&serde_json::json!(environment)))
            {
                let target = result
                    .as_object_mut()
                    .ok_or_else(failed)?
                    .entry(project)
                    .or_insert_with(|| p.clone());
                let entries = target
                    .get_mut("environments")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(failed)?;
                if !entries.contains(&serde_json::json!(environment)) {
                    entries.push(serde_json::json!(environment));
                }
            }
            continue;
        }
        let (ids, nested) = if name == crate::vault::VAULT_DOC {
            (&rec["secret_ids"], true)
        } else {
            (&rec["connection_ids"], false)
        };
        let source = if nested { &raw["secrets"] } else { &raw };
        let destination = if nested {
            result.get_mut("secrets")
        } else {
            Some(&mut result)
        }
        .and_then(Value::as_object_mut)
        .ok_or_else(failed)?;
        for id in ids
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if destination
                .get(id)
                .is_some_and(|v| source.get(id) != Some(v))
            {
                return Err(Error::state("team_bootstrap_recovery_required"));
            }
            if let Some(v) = source.get(id) {
                destination.insert(id.to_owned(), v.clone());
            }
        }
    }
    Ok(result)
}

fn failed() -> Error {
    Error::state("team_bootstrap_storage_failed")
}
macro_rules! fault_edge {
    ($state:expr,$name:expr,$point:literal) => {{
        #[cfg(test)]
        {
            testing::hit($state, $name, $point)?;
        }
    }};
}
fn private(path: &Path, dir: bool) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(|_| failed())?;
    if (if dir { !m.is_dir() } else { !m.is_file() })
        || m.uid() != nix::unistd::geteuid().as_raw()
        || m.permissions().mode() & 0o777 != if dir { 0o700 } else { 0o600 }
        || (!dir && m.nlink() != 1)
    {
        return Err(failed());
    }
    #[cfg(target_os = "macos")]
    {
        // Refuse extended ACLs, including inherited ACLs. The trusted system
        // utility is fixed; no peer data selects a program or shell command.
        let out = std::process::Command::new("/bin/ls")
            .args(["-lde", "--"])
            .arg(path)
            .output()
            .map_err(|_| failed())?;
        if !out.status.success()
            || out
                .stdout
                .split(|b| *b == b'\n')
                .skip(1)
                .any(|line| !line.is_empty())
        {
            return Err(failed());
        }
    }
    Ok(())
}

pub(crate) fn private_relative(state: &StateDir, name: &str) -> Result<()> {
    let relative = Path::new(name);
    if relative
        .components()
        .any(|p| !matches!(p, Component::Normal(_)))
    {
        return Err(failed());
    }
    private(&state.path, true)?;
    let mut current = state.path.clone();
    let parts = relative.components().collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(_) => private(&current, index + 1 < parts.len())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(failed()),
        }
    }
    Ok(())
}

pub(crate) fn write(state: &StateDir, name: &str, data: &[u8]) -> Result<()> {
    if !state.locked_by_current_thread() {
        return Err(failed());
    }
    let relative = Path::new(name);
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(failed());
    }
    private(&state.path, true)?;
    let parent = relative.parent().ok_or_else(failed)?;
    let mut current = state.path.clone();
    for component in parent.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(_) => private(&current, true)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fault_edge!(state, name, "directory-create-before");
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&current)
                    .map_err(|_| failed())?;
                fault_edge!(state, name, "directory-create-after");
                private(&current, true)?;
                fault_edge!(state, name, "ancestor-fsync-before");
                File::open(current.parent().ok_or_else(failed)?)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| failed())?;
                fault_edge!(state, name, "ancestor-fsync-after");
            }
            Err(_) => return Err(failed()),
        }
    }
    let target = state.path.join(relative);
    match fs::symlink_metadata(&target) {
        Ok(_) => private(&target, false)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(failed()),
    }
    let temp = current.join(format!(".pvboot-{}", super::team::bootstrap::random(16)));
    let result = (|| {
        fault_edge!(state, name, "file-open-before");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|_| failed())?;
        fault_edge!(state, name, "file-open-after");
        fault_edge!(state, name, "file-write-before");
        f.write_all(data).map_err(|_| failed())?;
        fault_edge!(state, name, "file-write-after");
        fault_edge!(state, name, "file-fsync-before");
        f.sync_all().map_err(|_| failed())?;
        fault_edge!(state, name, "file-fsync-after");
        private(&temp, false)?;
        fault_edge!(state, name, "readback-before");
        if fs::read(&temp).map_err(|_| failed())? != data {
            return Err(failed());
        }
        fault_edge!(state, name, "readback-after");
        fault_edge!(state, name, "rename-before");
        fs::rename(&temp, &target).map_err(|_| failed())?;
        fault_edge!(state, name, "rename-after");
        fault_edge!(state, name, "parent-fsync-before");
        File::open(&current)
            .and_then(|f| f.sync_all())
            .map_err(|_| failed())?;
        fault_edge!(state, name, "parent-fsync-after");
        private(&target, false)?;
        fault_edge!(state, name, "final-readback-before");
        if fs::read(&target).map_err(|_| failed())? != data {
            return Err(failed());
        }
        fault_edge!(state, name, "final-readback-after");
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Exact-owned-state, in-process fault control. No environment variable,
/// IPC route, or non-test implementation exists.
// Selected publication uses descriptor-anchored parents and the same legacy
// pretty-sorted image. The original writer above remains unchanged.
pub(crate) fn write_with_history(
    history: &crate::team::commit::HistorySession<'_>,
    name: &str,
    data: &[u8],
) -> Result<()> {
    use rustix::fs::{
        AtFlags, Mode, OFlags, RenameFlags, fsync, mkdirat, open, openat, renameat_with, unlinkat,
    };
    use std::io::Read;
    let state = history.state();
    history.reserve_writer(name, data.len() as u64)?;
    let path = Path::new(name);
    let parts = path.components().collect::<Vec<_>>();
    if parts.is_empty()
        || parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(failed());
    }
    let root = File::from(
        open(
            &state.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failed())?,
    );
    state.check_import_root_descriptor(&root)?;
    let mut directory: rustix::fd::OwnedFd = root.into();
    let mut current = state.path.clone();
    for part in &parts[..parts.len() - 1] {
        let Component::Normal(part) = part else {
            return Err(failed());
        };
        writer_edge(history, name, "directory-open-before")?;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let child = match openat(&directory, *part, flags, Mode::empty()) {
            Ok(child) => child,
            Err(error) if error == rustix::io::Errno::NOENT => {
                writer_edge(history, name, "directory-create-before")?;
                history.invalidate()?;
                mkdirat(&directory, *part, Mode::from_raw_mode(0o700)).map_err(|_| failed())?;
                writer_edge(history, name, "directory-create-after")?;
                writer_edge(history, name, "ancestor-fsync-before")?;
                history.invalidate()?;
                fsync(&directory).map_err(|_| failed())?;
                writer_edge(history, name, "ancestor-fsync-after")?;
                openat(&directory, *part, flags, Mode::empty()).map_err(|_| failed())?
            }
            Err(_) => return Err(failed()),
        };
        current.push(part);
        private(&current, true)?;
        let opened = File::from(child);
        let metadata = opened.metadata().map_err(|_| failed())?;
        let named = fs::symlink_metadata(&current).map_err(|_| failed())?;
        if metadata.dev() != named.dev() || metadata.ino() != named.ino() {
            return Err(failed());
        }
        directory = opened.into();
        writer_edge(history, name, "directory-open-after")?;
    }
    let Component::Normal(leaf) = parts[parts.len() - 1] else {
        return Err(failed());
    };
    // NOREPLACE is supported by the pinned rustix on both Linux and Apple.
    // Existing records are handled by the independently validating guard.
    let temp = format!(".pvboot-{}", crate::team::bootstrap::random(16));
    let result = (|| {
        writer_edge(history, name, "file-open-before")?;
        history.invalidate()?;
        let mut file = File::from(
            openat(
                &directory,
                temp.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| failed())?,
        );
        writer_edge(history, name, "file-open-after")?;
        writer_edge(history, name, "file-write-before")?;
        history.invalidate()?;
        file.write_all(data).map_err(|_| failed())?;
        writer_edge(history, name, "file-write-after")?;
        writer_edge(history, name, "file-fsync-before")?;
        history.invalidate()?;
        file.sync_all().map_err(|_| failed())?;
        writer_edge(history, name, "file-fsync-after")?;
        let identity = file.metadata().map_err(|_| failed())?;
        let readback = |leaf: &std::ffi::OsStr| -> Result<()> {
            let opened = File::from(
                openat(
                    &directory,
                    leaf,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| failed())?,
            );
            let metadata = opened.metadata().map_err(|_| failed())?;
            if !metadata.is_file()
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1
                || metadata.dev() != identity.dev()
                || metadata.ino() != identity.ino()
                || metadata.len() != data.len() as u64
            {
                return Err(failed());
            }
            let mut bytes = Vec::new();
            (&opened)
                .take((data.len() as u64).checked_add(1).ok_or_else(failed)?)
                .read_to_end(&mut bytes)
                .map_err(|_| failed())?;
            if bytes != data {
                return Err(failed());
            }
            Ok(())
        };
        writer_edge(history, name, "readback-before")?;
        readback(std::ffi::OsStr::new(&temp))?;
        writer_edge(history, name, "readback-after")?;
        writer_edge(history, name, "rename-before")?;
        history.invalidate()?;
        renameat_with(
            &directory,
            temp.as_str(),
            &directory,
            leaf,
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| failed())?;
        writer_edge(history, name, "rename-after")?;
        writer_edge(history, name, "parent-fsync-before")?;
        history.invalidate()?;
        fsync(&directory).map_err(|_| failed())?;
        writer_edge(history, name, "parent-fsync-after")?;
        writer_edge(history, name, "final-readback-before")?;
        readback(leaf)?;
        writer_edge(history, name, "final-readback-after")?;
        private(&current.join(leaf), false)?;
        history.check()
    })();
    if result.is_err() {
        let _ = history.invalidate();
        let _ = unlinkat(&directory, temp.as_str(), AtFlags::empty());
    }
    result
}

/// Only compact journal/index metadata may replace an exact captured image.
/// Denial and commit publication continue using the NOREPLACE writer above.
pub(crate) fn replace_import_metadata(
    history: &crate::team::commit::HistorySession<'_>,
    name: &str,
    expected: &[u8],
    data: &[u8],
) -> Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags, fsync, open, openat, renameat, unlinkat};
    use std::io::Read;
    let state = history.state();
    if name != INDEX && name != crate::team::bootstrap::path(history.env(), "journal.json")? {
        return Err(failed());
    }
    history.reserve_writer(name, data.len() as u64)?;
    let io = history.import_io()?;
    if io.read(name, 67_108_864)?.as_deref() != Some(expected) {
        return Err(Error::state("team_bootstrap_local_state_changed"));
    }
    let root = File::from(
        open(
            &state.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failed())?,
    );
    state.check_import_root_descriptor(&root)?;
    let relative = Path::new(name);
    let parts = relative.components().collect::<Vec<_>>();
    if parts.is_empty() || parts.iter().any(|p| !matches!(p, Component::Normal(_))) {
        return Err(failed());
    }
    let mut parent = root;
    let mut current = state.path.clone();
    for part in &parts[..parts.len() - 1] {
        let Component::Normal(part) = part else {
            return Err(failed());
        };
        history.charge(1 + part.len() as u64, 256)?;
        let child = File::from(
            openat(
                &parent,
                *part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| failed())?,
        );
        current.push(part);
        private(&current, true)?;
        if io_stamp(&child.metadata().map_err(|_| failed())?)
            != io_stamp(&fs::symlink_metadata(&current).map_err(|_| failed())?)
        {
            return Err(failed());
        }
        parent = child;
    }
    let Component::Normal(leaf) = parts[parts.len() - 1] else {
        return Err(failed());
    };
    let temp = format!(".pvboot-{}", crate::team::bootstrap::random(16));
    let result = (|| {
        writer_edge(history, name, "replace-open-before")?;
        history.invalidate()?;
        let mut file = File::from(
            openat(
                &parent,
                temp.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| failed())?,
        );
        writer_edge(history, name, "replace-open-after")?;
        writer_edge(history, name, "replace-write-before")?;
        history.invalidate()?;
        file.write_all(data).map_err(|_| failed())?;
        writer_edge(history, name, "replace-write-after")?;
        writer_edge(history, name, "replace-fsync-before")?;
        history.invalidate()?;
        file.sync_all().map_err(|_| failed())?;
        writer_edge(history, name, "replace-fsync-after")?;
        let identity = file.metadata().map_err(|_| failed())?;
        let readback = |leaf: &std::ffi::OsStr| -> Result<()> {
            let file = File::from(
                openat(
                    &parent,
                    leaf,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| failed())?,
            );
            let meta = file.metadata().map_err(|_| failed())?;
            if !meta.is_file()
                || meta.uid() != nix::unistd::geteuid().as_raw()
                || meta.mode() & 0o777 != 0o600
                || meta.nlink() != 1
                || meta.dev() != identity.dev()
                || meta.ino() != identity.ino()
                || meta.len() != data.len() as u64
            {
                return Err(failed());
            }
            let mut raw = Vec::new();
            (&file)
                .take(data.len() as u64 + 1)
                .read_to_end(&mut raw)
                .map_err(|_| failed())?;
            if raw != data {
                return Err(failed());
            }
            Ok(())
        };
        writer_edge(history, name, "replace-readback-before")?;
        readback(std::ffi::OsStr::new(&temp))?;
        writer_edge(history, name, "replace-readback-after")?;
        // A reentrant edit and same-size replacement are both observable.
        if io.read(name, 67_108_864)?.as_deref() != Some(expected) {
            return Err(Error::state("team_bootstrap_local_state_changed"));
        }
        writer_edge(history, name, "replace-rename-before")?;
        history.invalidate()?;
        renameat(&parent, temp.as_str(), &parent, leaf).map_err(|_| failed())?;
        writer_edge(history, name, "replace-rename-after")?;
        writer_edge(history, name, "replace-parent-fsync-before")?;
        history.invalidate()?;
        fsync(&parent).map_err(|_| failed())?;
        writer_edge(history, name, "replace-parent-fsync-after")?;
        writer_edge(history, name, "replace-final-readback-before")?;
        readback(leaf)?;
        writer_edge(history, name, "replace-final-readback-after")?;
        state.checked_import_root()?;
        history.check()
    })();
    if result.is_err() {
        let _ = history.invalidate();
        let _ = unlinkat(&parent, temp.as_str(), AtFlags::empty());
    }
    result
}
pub(crate) fn confirm_denial_durable(
    history: &crate::team::commit::HistorySession<'_>,
    name: &str,
) -> Result<()> {
    use rustix::fs::{Mode, OFlags, fsync, open, openat};
    use std::io::Read;
    let state = history.state();
    private_relative(state, name)?;
    let root = File::from(
        open(
            &state.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failed())?,
    );
    state.check_import_root_descriptor(&root)?;
    let mut directory: rustix::fd::OwnedFd = root.into();
    let parts = Path::new(name).components().collect::<Vec<_>>();
    if parts.is_empty()
        || parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(failed());
    }
    for part in &parts[..parts.len() - 1] {
        let Component::Normal(part) = part else {
            return Err(failed());
        };
        history.check()?;
        directory = openat(
            &directory,
            *part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failed())?;
    }
    let Component::Normal(leaf) = parts[parts.len() - 1] else {
        return Err(failed());
    };
    let file = File::from(
        openat(
            &directory,
            leaf,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failed())?,
    );
    let metadata = file.metadata().map_err(|_| failed())?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > 16_777_216 {
        return Err(failed());
    }
    history.reserve_writer(name, metadata.len())?;
    let mut before = Vec::new();
    (&file)
        .take(metadata.len().checked_add(1).ok_or_else(failed)?)
        .read_to_end(&mut before)
        .map_err(|_| failed())?;
    writer_edge(history, name, "existing-file-fsync-before")?;
    history.invalidate()?;
    history.invalidate()?;
    file.sync_all().map_err(|_| failed())?;
    writer_edge(history, name, "existing-file-fsync-after")?;
    writer_edge(history, name, "existing-parent-fsync-before")?;
    history.invalidate()?;
    fsync(&directory).map_err(|_| failed())?;
    writer_edge(history, name, "existing-parent-fsync-after")?;
    let again = File::from(
        openat(
            &directory,
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| failed())?,
    );
    let actual = again.metadata().map_err(|_| failed())?;
    if actual.dev() != metadata.dev()
        || actual.ino() != metadata.ino()
        || actual.len() != metadata.len()
    {
        return Err(failed());
    }
    let mut after = Vec::new();
    (&again)
        .take(metadata.len().checked_add(1).ok_or_else(failed)?)
        .read_to_end(&mut after)
        .map_err(|_| failed())?;
    if before != after || before.len() as u64 != metadata.len() {
        return Err(failed());
    }
    history.check()
}
fn writer_edge(
    history: &crate::team::commit::HistorySession<'_>,
    name: &str,
    point: &str,
) -> Result<()> {
    history.check()?;
    history.charge(1, 0)?;
    #[cfg(test)]
    testing::hit(history.state(), name, point)?;
    #[cfg(not(test))]
    let _ = (name, point);
    history.check()
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        sync::{Arc, Condvar, LazyLock, Mutex},
        time::Duration,
    };
    struct Spec {
        at: Option<usize>,
        named: Option<(String, String, usize)>,
        hits: Vec<(String, String)>,
        fired: bool,
        crash: bool,
        pause: Option<Arc<Pause>>,
    }
    pub(crate) struct Pause {
        state: Mutex<(bool, bool)>,
        changed: Condvar,
    }
    impl Pause {
        pub(crate) fn wait(&self) {
            let guard = self.state.lock().unwrap();
            let (guard, result) = self
                .changed
                .wait_timeout_while(guard, Duration::from_secs(10), |s| !s.0)
                .unwrap();
            assert!(
                guard.0 && !result.timed_out(),
                "owned reader did not reach pause"
            );
        }
        pub(crate) fn release(&self) {
            self.state.lock().unwrap().1 = true;
            self.changed.notify_all();
        }
    }
    static SPECS: LazyLock<Mutex<BTreeMap<PathBuf, Spec>>> =
        LazyLock::new(|| Mutex::new(BTreeMap::new()));
    pub(crate) struct Scope {
        root: PathBuf,
    }
    impl Scope {
        pub(crate) fn track(state: &StateDir, at: Option<usize>) -> Self {
            let root = state.path.clone();
            assert!(state.path.is_dir());
            assert!(
                SPECS
                    .lock()
                    .unwrap()
                    .insert(
                        root.clone(),
                        Spec {
                            at,
                            named: None,
                            hits: Vec::new(),
                            fired: false,
                            crash: false,
                            pause: None
                        }
                    )
                    .is_none()
            );
            Self { root }
        }
        pub(crate) fn pause(state: &StateDir, suffix: &str, point: &str) -> (Self, Arc<Pause>) {
            let scope = Self::named(state, suffix, point, 1);
            let pause = Arc::new(Pause {
                state: Mutex::new((false, false)),
                changed: Condvar::new(),
            });
            SPECS.lock().unwrap().get_mut(&scope.root).unwrap().pause = Some(pause.clone());
            (scope, pause)
        }
        pub(crate) fn crash(state: &StateDir, at: usize) -> Self {
            let scope = Self::track(state, Some(at));
            SPECS.lock().unwrap().get_mut(&scope.root).unwrap().crash = true;
            scope
        }
        pub(crate) fn named(state: &StateDir, suffix: &str, point: &str, nth: usize) -> Self {
            let value = Self::track(state, None);
            SPECS.lock().unwrap().get_mut(&value.root).unwrap().named =
                Some((suffix.into(), point.into(), nth));
            value
        }
        pub(crate) fn hits(&self) -> Vec<(String, String)> {
            SPECS.lock().unwrap()[&self.root].hits.clone()
        }
        pub(crate) fn fired(&self) -> bool {
            SPECS.lock().unwrap()[&self.root].fired
        }
    }
    impl Drop for Scope {
        fn drop(&mut self) {
            SPECS.lock().unwrap().remove(&self.root);
        }
    }
    pub(crate) fn reader_hit(state: &StateDir, name: &str, point: &str) -> Result<()> {
        let enabled = SPECS
            .lock()
            .unwrap()
            .get(&state.path)
            .is_some_and(|s| s.pause.is_some());
        if enabled {
            hit(state, name, point)
        } else {
            Ok(())
        }
    }
    pub(crate) fn hit(state: &StateDir, name: &str, point: &str) -> Result<()> {
        let mut specs = SPECS.lock().unwrap();
        let Some(spec) = specs.get_mut(&state.path) else {
            return Ok(());
        };
        let index = spec.hits.len();
        spec.hits.push((name.into(), point.into()));
        let named = spec.named.as_ref().is_some_and(|(suffix, p, nth)| {
            name.ends_with(suffix)
                && point == p
                && spec
                    .hits
                    .iter()
                    .filter(|(n, p)| n.ends_with(suffix) && p == point)
                    .count()
                    == *nth
        });
        if !spec.fired && (spec.at == Some(index) || named) {
            spec.fired = true;
            if spec.crash {
                std::process::exit(86);
            }
            if let Some(pause) = spec.pause.clone() {
                drop(specs);
                let mut guard = pause.state.lock().unwrap();
                guard.0 = true;
                pause.changed.notify_all();
                let (guard, result) = pause
                    .changed
                    .wait_timeout_while(guard, Duration::from_secs(10), |s| !s.1)
                    .unwrap();
                return if guard.1 && !result.timed_out() {
                    Ok(())
                } else {
                    Err(failed())
                };
            }
            return Err(failed());
        }
        Ok(())
    }
}

pub(crate) fn json(state: &StateDir, name: &str, value: &Value) -> Result<()> {
    encoded_len(value)?;
    write(
        state,
        name,
        pyjson::dumps(value, DumpOptions::pretty_sorted())?.as_bytes(),
    )
}

/// Count before allocating a pretty JSON image. All new import documents
/// use ASCII escaping, two-space indentation, and at most 64 containers.
pub(crate) fn encoded_len(value: &Value) -> Result<usize> {
    const CAP: usize = 64 * 1024 * 1024;
    fn add(a: usize, b: usize) -> Result<usize> {
        a.checked_add(b)
            .filter(|n| *n <= CAP)
            .ok_or_else(|| Error::state("team_bootstrap_limit_exceeded"))
    }
    fn string(s: &str) -> Result<usize> {
        let mut n = 2;
        for c in s.chars() {
            n = add(
                n,
                match c {
                    '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
                    ' '..='~' => 1,
                    c if (c as u32) <= 0xffff => 6,
                    _ => 12,
                },
            )?;
        }
        Ok(n)
    }
    fn count(v: &Value, depth: usize) -> Result<usize> {
        if depth > 64 {
            return Err(Error::state("team_bootstrap_limit_exceeded"));
        }
        match v {
            Value::Null => Ok(4),
            Value::Bool(b) => Ok(if *b { 4 } else { 5 }),
            Value::String(s) => string(s),
            Value::Number(_) => Ok(pyjson::dumps(v, DumpOptions::compact_sorted())?.len()),
            Value::Array(items) => {
                if items.is_empty() {
                    return Ok(2);
                }
                let mut n = add(3, 2 * depth)?;
                for item in items {
                    n = add(n, add(2 + 2 * (depth + 1), count(item, depth + 1)?)?)?;
                }
                Ok(n)
            }
            Value::Object(items) => {
                if items.is_empty() {
                    return Ok(2);
                }
                let mut n = add(3, 2 * depth)?;
                for (key, item) in items {
                    n = add(
                        n,
                        add(
                            4 + 2 * (depth + 1),
                            add(string(key)?, count(item, depth + 1)?)?,
                        )?,
                    )?;
                }
                Ok(n)
            }
        }
    }
    count(value, 0)
}

pub(crate) fn transfer_lease(state: &StateDir, env: &str) -> Result<File> {
    let _lock = state.lock()?;
    let marker = crate::team::bootstrap::path(env, "lease-marker")?;
    if !state.exists(&marker) {
        write(state, &marker, b"personal-bootstrap-lease-v1\n")?;
    }
    let name = crate::team::bootstrap::path(env, "transfer.lock")?;
    let p = state.path.join(&name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)
        .map_err(|_| failed())?;
    private(&p, false)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| Error::state("team_bootstrap_busy"))?;
    Ok(file)
}

pub(crate) fn validate_environment_tree(state: &StateDir, env: &str) -> Result<()> {
    if !crate::team::commit::valid_env_id(env) {
        return Err(failed());
    }
    private(&state.path, true)?;
    let team = state.path.join("team");
    private(&team, true)?;
    let root = team.join(env);
    if !root.exists() {
        return Ok(());
    }
    let mut directories = vec![root];
    let mut total = 0u64;
    let mut count = 0usize;
    while let Some(dir) = directories.pop() {
        private(&dir, true)?;
        for entry in fs::read_dir(dir).map_err(|_| failed())? {
            let entry = entry.map_err(|_| failed())?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|_| failed())?;
            count = count.checked_add(1).ok_or_else(failed)?;
            if count > 65_536 {
                return Err(Error::state("team_bootstrap_limit_exceeded"));
            }
            if metadata.is_dir() {
                directories.push(entry.path());
            } else {
                private(&entry.path(), false)?;
                total = total.checked_add(metadata.len()).ok_or_else(failed)?;
                if total > 64 * 1024 * 1024 {
                    return Err(Error::state("team_bootstrap_limit_exceeded"));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_inventory(state: &StateDir, env: &str) -> Result<()> {
    let mut total = 0u64;
    for name in [
        crate::vault::VAULT_DOC,
        crate::policy::CONNECTIONS,
        crate::projects::DOC,
        crate::tombstone::PATH,
        crate::team::sync::ENVS_MAP_PATH,
        crate::policy::CONTROL,
        &crate::team::bootstrap::path(env, "known-facts.json")?,
    ] {
        private_relative(state, name)?;
        match fs::symlink_metadata(state.path.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(failed()),
            Ok(m) => {
                total = total.checked_add(m.len()).ok_or_else(failed)?;
                if total > 64 * 1024 * 1024 {
                    return Err(Error::state("team_bootstrap_limit_exceeded"));
                }
            }
        }
    }
    Ok(())
}

/// Fixed private staging trees only. Inspect types, modes and ownership
/// before any file is opened, synced or removed; no archive or peer path.
fn staging_entries(state: &StateDir, env: &str) -> Result<Vec<(std::path::PathBuf, bool)>> {
    let root = state
        .path
        .join(crate::team::bootstrap::path(env, "staging")?);
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut pending = vec![root];
    let mut entries = Vec::new();
    let mut bytes = 0u64;
    while let Some(path) = pending.pop() {
        private(&path, true)?;
        entries.push((path.clone(), true));
        for entry in fs::read_dir(path).map_err(|_| failed())? {
            let path = entry.map_err(|_| failed())?.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| failed())?;
            if metadata.is_dir() {
                pending.push(path);
            } else {
                private(&path, false)?;
                bytes = bytes.checked_add(metadata.len()).ok_or_else(failed)?;
                entries.push((path, false));
            }
            if entries
                .len()
                .checked_add(pending.len())
                .is_none_or(|n| n > 65_536)
                || bytes > 64 * 1024 * 1024
            {
                return Err(Error::state("team_bootstrap_limit_exceeded"));
            }
        }
    }
    Ok(entries)
}
pub(crate) fn sync_staging(state: &StateDir, env: &str) -> Result<usize> {
    if !state.locked_by_current_thread() {
        return Err(failed());
    }
    let entries = staging_entries(state, env)?;
    let mut total = 0usize;
    for (path, dir) in entries.iter().rev() {
        let _name = path
            .strip_prefix(&state.path)
            .map_err(|_| failed())?
            .to_str()
            .ok_or_else(failed)?;
        if !dir {
            total = total
                .checked_add(
                    usize::try_from(fs::metadata(path).map_err(|_| failed())?.len())
                        .map_err(|_| failed())?,
                )
                .ok_or_else(failed)?;
        }
        fault_edge!(state, _name, "staging-fsync-before");
        File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|_| failed())?;
        fault_edge!(state, _name, "staging-fsync-after");
    }
    Ok(total)
}
pub(crate) fn discard_staging(state: &StateDir, env: &str) -> Result<()> {
    if !state.locked_by_current_thread() {
        return Err(failed());
    }
    for (path, dir) in staging_entries(state, env)?.into_iter().rev() {
        let _name = path
            .strip_prefix(&state.path)
            .map_err(|_| failed())?
            .to_str()
            .ok_or_else(failed)?;
        fault_edge!(state, _name, "staging-unlink-before");
        if dir {
            fs::remove_dir(&path)
        } else {
            fs::remove_file(&path)
        }
        .map_err(|_| failed())?;
        fault_edge!(state, _name, "staging-unlink-after");
        fault_edge!(state, _name, "staging-unlink-parent-fsync-before");
        File::open(path.parent().ok_or_else(failed)?)
            .and_then(|f| f.sync_all())
            .map_err(|_| failed())?;
        fault_edge!(state, _name, "staging-unlink-parent-fsync-after");
    }
    Ok(())
}

#[cfg(test)]
mod personal_reader_tests {
    use super::*;
    use crate::{
        context::Context,
        gateway,
        policy::{Connection, HttpAuth, HttpScope, HttpTarget},
        sshwire,
    };
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::net::UnixStream,
        process::{Child, Command, Stdio},
        sync::{Arc, mpsc},
        thread,
        time::Duration,
    };
    struct Writer(Option<Child>);
    impl Writer {
        fn join(&mut self) {
            assert!(self.0.take().unwrap().wait().unwrap().success());
        }
    }
    impl Drop for Writer {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    fn writer(
        state: &StateDir,
        env: &str,
    ) -> (Writer, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "import_barrier::personal_reader_tests::personal_bootstrap_guard_writer_child",
                "--nocapture",
            ])
            .env("PVBOOT_OWN_WRITER_STATE", &state.path)
            .env("PVBOOT_OWN_WRITER_ENV", env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if line.starts_with("PVBOOT_WRITER_") {
                    let _ = tx.send(line);
                }
            }
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            "PVBOOT_WRITER_WAITING"
        );
        (Writer(Some(child)), rx, reader)
    }
    #[test]
    fn personal_bootstrap_guard_writer_child() {
        let Some(root) = std::env::var_os("PVBOOT_OWN_WRITER_STATE") else {
            return;
        };
        let env = std::env::var("PVBOOT_OWN_WRITER_ENV").unwrap();
        let state = StateDir::new(root);
        println!("\nPVBOOT_WRITER_WAITING");
        std::io::stdout().flush().unwrap();
        {
            let _lock = state.lock().unwrap();
            let name = crate::team::bootstrap::path(&env, "receipt.json").unwrap();
            fs::write(state.path.join(name), b"{}").unwrap();
        }
        println!("PVBOOT_WRITER_DONE");
        std::io::stdout().flush().unwrap();
    }
    fn ssh_client(path: &Path) -> sshwire::AgentConnection<UnixStream> {
        let socket = UnixStream::connect(path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut client = sshwire::AgentConnection::new(socket);
        let host =
            sshwire::Ed25519PrivateKey::from_seed(&[9; 32], "synthetic-personal-host").unwrap();
        let signature = sshwire::encode_ssh_signature(&host.sign(&[3; 32])).unwrap();
        assert_eq!(
            client
                .request(&sshwire::build_session_bind(
                    &host.public.blob(),
                    &[3; 32],
                    &signature,
                    false
                ))
                .unwrap(),
            sshwire::build_success()
        );
        client
    }
    fn ssh_sign(mut client: sshwire::AgentConnection<UnixStream>) -> bool {
        let key =
            sshwire::Ed25519PrivateKey::from_seed(&[8; 32], "synthetic-personal-user").unwrap();
        let data = sshwire::build_userauth_request(
            &[3; 32],
            "deploy",
            "ssh-ed25519",
            &key.public.blob(),
            sshwire::SSH_CONNECTION_SERVICE,
            None,
        );
        client
            .request(&sshwire::build_sign_request(&key.public.blob(), &data, 0))
            .unwrap()
            .first()
            == Some(&sshwire::SSH_AGENT_SIGN_RESPONSE)
    }
    #[test]
    fn personal_bootstrap_paused_readers_gateway_and_signer_serialize_with_independent_writer() {
        let fixture = crate::team::bootstrap::install::tests::installed();
        let ctx = fixture.b.clone();
        let env = &fixture.env;
        let receipt_path = ctx
            .state
            .path
            .join(crate::team::bootstrap::path(env, "receipt.json").unwrap());
        let original = fs::read(&receipt_path).unwrap();
        let fake = crate::fake_upstream::FakeUpstream::new("synthetic-install-fault-value").start();
        ctx.policy
            .create_principal("epoch-reader", "synthetic")
            .unwrap();
        ctx.policy
            .create_connection(
                Connection::new(
                    "epoch-http",
                    "personal",
                    "vault",
                    "synthetic",
                    "http",
                    "alpha",
                    None,
                    "",
                    Some(
                        HttpTarget::new(fake.scheme(), fake.host(), fake.port() as i64, None, true)
                            .unwrap(),
                    ),
                    Some(HttpAuth::bearer()),
                    Some(
                        HttpScope::new(
                            Some(vec!["GET".into()]),
                            Some(vec!["/data".into()]),
                            vec![],
                        )
                        .unwrap(),
                    ),
                    None,
                    None,
                    0,
                    "active",
                    "",
                    "",
                )
                .unwrap(),
            )
            .unwrap();
        let grant = ctx
            .policy
            .create_grant("epoch-reader", "epoch-http", Some(3600), None)
            .unwrap();
        let http = ctx
            .handles
            .issue(
                "epoch-reader",
                "epoch-http",
                &grant.id,
                grant.policy_version,
                3600,
                None,
            )
            .unwrap();
        let grant = ctx
            .policy
            .create_grant("epoch-reader", "ssh", Some(3600), None)
            .unwrap();
        let manager = crate::signer::install(ctx.clone(), None).unwrap();
        let binding = manager.bind("epoch-reader", "ssh", &grant.id).unwrap();
        for (kind, name, point, held) in [
            (
                "vault",
                crate::vault::VAULT_DOC,
                "reader-check-before-read",
                true,
            ),
            (
                "vault",
                crate::vault::VAULT_DOC,
                "reader-file-read-before-view",
                true,
            ),
            (
                "policy",
                crate::policy::CONNECTIONS,
                "reader-file-read-before-view",
                true,
            ),
            ("http", "epoch-http", "gateway-consume-before", false),
            ("http", "epoch-http", "gateway-consume-before-decrypt", true),
            ("ssh", "ssh", "signer-consume-before", false),
            ("ssh", "ssh", "signer-consume-before-decrypt", true),
        ] {
            let client = (kind == "ssh").then(|| ssh_client(&binding.socket_path));
            let (scope, pause) = testing::Scope::pause(ctx.state, name, point);
            let reader_ctx = Arc::clone(&ctx);
            let handle = http.clone();
            let reader = thread::spawn(move || match kind {
                "vault" => reader_ctx
                    .vault
                    .list_secrets(None, None)
                    .unwrap()
                    .iter()
                    .any(|s| s.id == "alpha"),
                "policy" => reader_ctx.policy.get_connection("ssh").is_ok(),
                "http" => gateway::relay(
                    &reader_ctx,
                    &handle,
                    "GET",
                    "/data",
                    &gateway::Headers::new(),
                    b"",
                    None,
                )
                .relayed(),
                "ssh" => ssh_sign(client.unwrap()),
                _ => unreachable!(),
            });
            pause.wait();
            let (mut child, done, drain) = writer(ctx.state, env);
            if held {
                assert!(
                    matches!(
                        done.recv_timeout(Duration::from_millis(150)),
                        Err(mpsc::RecvTimeoutError::Timeout)
                    ),
                    "writer crossed a held epoch guard"
                );
                pause.release();
                assert!(
                    reader.join().unwrap(),
                    "coherent operation failed before writer started"
                );
                assert_eq!(
                    done.recv_timeout(Duration::from_secs(5)).unwrap(),
                    "PVBOOT_WRITER_DONE"
                );
            } else {
                assert_eq!(
                    done.recv_timeout(Duration::from_secs(5)).unwrap(),
                    "PVBOOT_WRITER_DONE"
                );
                pause.release();
                assert!(
                    !reader.join().unwrap(),
                    "cached operation crossed changed import epoch"
                );
            }
            child.join();
            drain.join().unwrap();
            drop(scope);
            assert!(ctx.vault.secret_for_trusted_use("alpha", None).is_err());
            assert!(ctx.vault.secret_for_trusted_use("unrelated", None).is_ok());
            {
                let _lock = ctx.state.lock().unwrap();
                fs::write(&receipt_path, &original).unwrap();
            }
            assert!(ctx.vault.secret_for_trusted_use("alpha", None).is_ok());
        }
        manager.shutdown();
        println!("PVBOOT_PAUSED_CROSS_PROCESS_READER_CASES=7");
    }
    fn removal_writer(
        state: &StateDir,
        env: &str,
    ) -> (Writer, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "import_barrier::personal_reader_tests::personal_bootstrap_removal_writer_child",
                "--nocapture",
            ])
            .env("PVBOOT_OWN_REMOVAL_STATE", &state.path)
            .env("PVBOOT_OWN_REMOVAL_ENV", env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if line.starts_with("PVBOOT_WRITER_") {
                    let _ = tx.send(line);
                }
            }
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            "PVBOOT_WRITER_WAITING"
        );
        (Writer(Some(child)), rx, reader)
    }
    #[test]
    fn personal_bootstrap_removal_writer_child() {
        let Some(root) = std::env::var_os("PVBOOT_OWN_REMOVAL_STATE") else {
            return;
        };
        let env = std::env::var("PVBOOT_OWN_REMOVAL_ENV").unwrap();
        println!("\nPVBOOT_WRITER_WAITING");
        std::io::stdout().flush().unwrap();
        let ctx = Context::open(
            root,
            crate::context::Config::default(),
            crate::clock::system(),
        )
        .unwrap();
        let key = crate::team::identity::DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let fp = key.fingerprint().unwrap();
        crate::team::membership::author_commit(
            &ctx,
            None,
            &env,
            vec![serde_json::json!({"op":"member.remove","fingerprint":fp})],
        )
        .unwrap();
        assert!(
            ctx.state
                .exists(&crate::team::bootstrap::path(&env, LOCAL_REMOVAL_DENIAL).unwrap())
        );
        assert!(
            !ctx.state
                .exists(&crate::team::bootstrap::path(&env, "member-removed.json").unwrap())
        );
        println!("PVBOOT_WRITER_DONE");
        std::io::stdout().flush().unwrap();
    }
    #[test]
    fn personal_bootstrap_real_removal_serializes_all_reader_lock_orders() {
        fn copy(source: &Path, target: &Path) {
            let metadata = fs::symlink_metadata(source).unwrap();
            assert!(metadata.is_dir());
            fs::DirBuilder::new()
                .mode(metadata.permissions().mode() & 0o777)
                .create(target)
                .unwrap();
            for entry in fs::read_dir(source).unwrap() {
                let entry = entry.unwrap();
                let metadata = fs::symlink_metadata(entry.path()).unwrap();
                let target = target.join(entry.file_name());
                if metadata.is_dir() {
                    copy(&entry.path(), &target);
                } else {
                    assert!(metadata.is_file());
                    fs::copy(entry.path(), &target).unwrap();
                    fs::set_permissions(target, metadata.permissions()).unwrap();
                }
            }
        }
        let fixture = crate::team::bootstrap::install::tests::installed();
        let env = &fixture.env;
        let fake = crate::fake_upstream::FakeUpstream::new("synthetic-install-fault-value").start();
        for (kind, name, point, held) in [
            (
                "vault",
                crate::vault::VAULT_DOC,
                "reader-check-before-read",
                true,
            ),
            (
                "vault",
                crate::vault::VAULT_DOC,
                "reader-file-read-before-view",
                true,
            ),
            (
                "trusted",
                crate::vault::VAULT_DOC,
                "reader-file-read-before-view",
                true,
            ),
            (
                "policy",
                crate::policy::CONNECTIONS,
                "reader-file-read-before-view",
                true,
            ),
            ("http", "epoch-http", "gateway-consume-before", false),
            ("http", "epoch-http", "gateway-consume-before-decrypt", true),
            ("ssh", "ssh", "signer-consume-before", false),
            ("ssh", "ssh", "signer-consume-before-decrypt", true),
        ] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("b");
            copy(&fixture.b.state.path, &path);
            let ctx = Arc::new(
                Context::open(
                    path,
                    crate::context::Config::default(),
                    crate::clock::system(),
                )
                .unwrap(),
            );
            ctx.policy
                .create_principal("epoch-reader", "synthetic")
                .unwrap();
            ctx.policy
                .create_connection(
                    Connection::new(
                        "epoch-http",
                        "personal",
                        "vault",
                        "synthetic",
                        "http",
                        "alpha",
                        None,
                        "",
                        Some(
                            HttpTarget::new(
                                fake.scheme(),
                                fake.host(),
                                fake.port() as i64,
                                None,
                                true,
                            )
                            .unwrap(),
                        ),
                        Some(HttpAuth::bearer()),
                        Some(
                            HttpScope::new(
                                Some(vec!["GET".into()]),
                                Some(vec!["/data".into()]),
                                vec![],
                            )
                            .unwrap(),
                        ),
                        None,
                        None,
                        0,
                        "active",
                        "",
                        "",
                    )
                    .unwrap(),
                )
                .unwrap();
            let grant = ctx
                .policy
                .create_grant("epoch-reader", "epoch-http", Some(3600), None)
                .unwrap();
            let http = ctx
                .handles
                .issue(
                    "epoch-reader",
                    "epoch-http",
                    &grant.id,
                    grant.policy_version,
                    3600,
                    None,
                )
                .unwrap();
            let grant = ctx
                .policy
                .create_grant("epoch-reader", "ssh", Some(3600), None)
                .unwrap();
            let manager = crate::signer::install(ctx.clone(), None).unwrap();
            let binding = manager.bind("epoch-reader", "ssh", &grant.id).unwrap();
            let client = (kind == "ssh").then(|| ssh_client(&binding.socket_path));
            let (scope, pause) = testing::Scope::pause(ctx.state, name, point);
            let reader_ctx = ctx.clone();
            let reader = thread::spawn(move || match kind {
                "vault" => reader_ctx
                    .vault
                    .list_secrets(None, None)
                    .unwrap()
                    .iter()
                    .any(|entry| entry.id == "alpha"),
                "trusted" => reader_ctx
                    .vault
                    .secret_for_trusted_use("alpha", None)
                    .is_ok(),
                "policy" => reader_ctx.policy.get_connection("ssh").is_ok(),
                "http" => gateway::relay(
                    &reader_ctx,
                    &http,
                    "GET",
                    "/data",
                    &gateway::Headers::new(),
                    b"",
                    None,
                )
                .relayed(),
                "ssh" => ssh_sign(client.unwrap()),
                _ => unreachable!(),
            });
            pause.wait();
            let (mut child, done, drain) = removal_writer(ctx.state, env);
            if held {
                assert!(matches!(
                    done.recv_timeout(Duration::from_millis(150)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ));
                pause.release();
                assert!(reader.join().unwrap(), "already linearized reader {kind}");
                assert_eq!(
                    done.recv_timeout(Duration::from_secs(5)).unwrap(),
                    "PVBOOT_WRITER_DONE"
                );
            } else {
                assert_eq!(
                    done.recv_timeout(Duration::from_secs(5)).unwrap(),
                    "PVBOOT_WRITER_DONE"
                );
                pause.release();
                assert!(!reader.join().unwrap(), "late reader {kind}");
            }
            child.join();
            drain.join().unwrap();
            drop(scope);
            assert!(ctx.vault.secret_for_trusted_use("alpha", None).is_err());
            assert!(ctx.vault.secret_for_trusted_use("unrelated", None).is_ok());
            if let Ok(grant) =
                ctx.policy
                    .create_grant("epoch-reader", "epoch-http", Some(3600), None)
            {
                let handle = ctx
                    .handles
                    .issue(
                        "epoch-reader",
                        "epoch-http",
                        &grant.id,
                        grant.policy_version,
                        3600,
                        None,
                    )
                    .unwrap();
                assert!(
                    !gateway::relay(
                        &ctx,
                        &handle,
                        "GET",
                        "/data",
                        &gateway::Headers::new(),
                        b"",
                        None
                    )
                    .relayed()
                );
            }
            if let Ok(binding) = manager.bind("epoch-reader", "ssh", &grant.id) {
                assert!(!ssh_sign(ssh_client(&binding.socket_path)));
            }
            manager.shutdown();
        }
        println!("PVBOOT_REAL_REMOVAL_READER_LOCK_ORDERS=8");
    }
}

#[cfg(test)]
pub(crate) mod opus_cost {
    use super::*;
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        sync::{LazyLock, Mutex},
    };
    struct Spec {
        address: usize,
        env: String,
        notes: Vec<String>,
        metrics: BTreeMap<&'static str, u64>,
        protocol_trace: bool,
    }
    static SPECS: LazyLock<Mutex<BTreeMap<PathBuf, Spec>>> =
        LazyLock::new(|| Mutex::new(BTreeMap::new()));
    pub(crate) struct Scope {
        root: PathBuf,
    }
    impl Scope {
        pub(crate) fn begin(state: &StateDir, env: &str) -> Self {
            assert!(crate::team::commit::valid_env_id(env));
            let root = state.path.clone();
            assert!(
                SPECS
                    .lock()
                    .unwrap()
                    .insert(
                        root.clone(),
                        Spec {
                            address: state as *const StateDir as usize,
                            env: env.into(),
                            notes: Vec::new(),
                            metrics: BTreeMap::new(),
                            protocol_trace: false,
                        }
                    )
                    .is_none()
            );
            Self { root }
        }
        pub(crate) fn protocol_trace(state: &StateDir, env: &str) -> Self {
            let scope = Self::begin(state, env);
            SPECS
                .lock()
                .unwrap()
                .get_mut(&scope.root)
                .unwrap()
                .protocol_trace = true;
            scope
        }
        pub(crate) fn notes(&self) -> Vec<String> {
            SPECS.lock().unwrap()[&self.root].notes.clone()
        }
        pub(crate) fn metrics(&self) -> BTreeMap<&'static str, u64> {
            SPECS.lock().unwrap()[&self.root].metrics.clone()
        }
    }
    impl Drop for Scope {
        fn drop(&mut self) {
            SPECS.lock().unwrap().remove(&self.root);
        }
    }
    pub(crate) fn note(state: &StateDir, env: &str, label: &str) {
        let mut specs = SPECS.lock().unwrap();
        if let Some(spec) = specs.get_mut(&state.path)
            && spec.address == state as *const StateDir as usize
            && spec.env == env
        {
            if spec.protocol_trace {
                return;
            }
            assert!(spec.notes.len() < 1024);
            assert!(label.len() <= 256);
            spec.notes.push(label.into());
        }
    }
    pub(crate) fn note_hash(state: &StateDir, env: &str, label: &str, value: &Value) {
        let enabled = SPECS.lock().unwrap().get(&state.path).is_some_and(|spec| {
            spec.address == state as *const StateDir as usize && spec.env == env
        });
        if enabled {
            note(
                state,
                env,
                &format!("{label}:{}", crate::team::bootstrap::digest(value).unwrap()),
            );
        }
    }
    pub(crate) fn protocol_event(state: &StateDir, env: &str, label: &'static str) {
        let mut specs = SPECS.lock().unwrap();
        if let Some(spec) = specs.get_mut(&state.path)
            && spec.address == state as *const StateDir as usize
            && spec.env == env
            && spec.protocol_trace
        {
            let count = spec.metrics.entry(label).or_default();
            *count += 1;
            if *count <= 8 {
                eprintln!("PVBOOT_OPUS_PROTOCOL_EVENT kind={label} count={count}");
            }
        }
    }
    pub(crate) fn protocol_error(state: &StateDir, env: &str, reason: &str) {
        let mut specs = SPECS.lock().unwrap();
        if let Some(spec) = specs.get_mut(&state.path)
            && spec.address == state as *const StateDir as usize
            && spec.env == env
            && spec.protocol_trace
        {
            let count = spec.metrics.entry("protocol_errors").or_default();
            *count += 1;
            if *count <= 8
                && reason.len() <= 96
                && reason
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_' || byte.is_ascii_digit())
            {
                eprintln!("PVBOOT_OPUS_PROTOCOL_ERROR reason={reason}");
            }
        }
    }
    pub(crate) fn protocol_members(state: &StateDir, env: &str, document: &Value) {
        let mut specs = SPECS.lock().unwrap();
        if let Some(spec) = specs.get_mut(&state.path)
            && spec.address == state as *const StateDir as usize
            && spec.env == env
            && spec.protocol_trace
        {
            let count = spec.metrics.entry("membership_projections").or_default();
            *count += 1;
            if *count <= 8 {
                let members = document["members"].as_object().into_iter().flatten().take(2).map(|(fp, member)| (fp.clone(), serde_json::json!({"status":member["status"],"role":member["role"],"record_present":member["device"].is_object()}))).collect::<serde_json::Map<_,_>>();
                eprintln!(
                    "PVBOOT_OPUS_MEMBERSHIP_PROJECTION {}",
                    Value::Object(members)
                );
            }
        }
    }
    pub(crate) fn metric(state: &StateDir, label: &'static str, amount: u64) {
        if let Some(spec) = SPECS.lock().unwrap().get_mut(&state.path)
            && spec.address == state as *const StateDir as usize
        {
            let counter = spec.metrics.entry(label).or_default();
            *counter = counter
                .checked_add(amount)
                .expect("bounded actual I/O counter");
        }
    }
}
