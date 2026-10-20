//! Team replication and monotone facts, port of `zeropw/team/sync.py`.
#![allow(clippy::collapsible_if)]
#![allow(clippy::type_complexity)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::commit::{self, Commit, CommitStore, Hlc};
use super::fold::{self, Facts, FoldResult};
use super::identity::{DeviceKey, DeviceRecord};
use super::transport::{InviteCheck, MembershipCheck, OnSession, Session, Transport};
use crate::audit::RecordArgs;
use crate::context::Context;
use crate::errors::{Error, Result};
use crate::pybase64;
use crate::pyint::{PyInt, PyNumber};
use crate::pyjson::{self, DumpOptions};
use crate::store::{StateDir, iso};

pub const FACT_FORMAT: &str = "zeropw-team-fact-v1";
pub const FACT_KINDS: [&str; 4] = [
    "connection_disabled",
    "secret_version_revoked",
    "member_removed",
    "incident",
];
// Replay advances over at most this many persisted lines per VECTOR, including
// malformed lines. A full pass restarts so a rejected/out-of-order frame is
// retried after later commit catch-up, while receiver hashes deduplicate it.
const FACT_REPLAY_LINES_PER_VECTOR: usize = 64;
/// `sync._SEEN_CAPACITY`: bound of the rebroadcast-dedup set.
const SEEN_CAPACITY: usize = 4096;
/// Commits from one peer that may wait for their history at once; one past
/// this bound is quarantined at once (issue #28).
const EARLY_COMMITS_PER_PEER: usize = 256;
/// An early commit asks its sender for the missing range at most this often
/// per peer...
const EARLY_VECTOR_INTERVAL: Duration = Duration::from_secs(1);
/// ...and only once no commit has been accepted for this long, so a catch-up
/// still streaming in is not requested again from every relaying peer.
const EARLY_QUIET: Duration = Duration::from_millis(250);
/// COMMIT/FACT frames withheld from one joining device until its history has
/// been sent; past this, the rest reach it with a later VECTOR.
const HELD_FRAMES_MAX: usize = 256;
/// `thread.join(timeout=5)` in `TeamSync.stop`.
const THREAD_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
pub const ENVS_MAP_PATH: &str = "team/envs.json";
pub const SNAPSHOT_INTERVAL_COMMITS: i128 = 1000;
pub const COMPACT_MIN_AGE_MS: i64 = 30 * 24 * 3600 * 1000;
pub const MAX_INCIDENT_STR_LENGTH: usize = 200;
pub const MAX_INCIDENT_LIST_ITEMS: usize = 100;
pub const MAX_INCIDENT_UNIT: i64 = 2_147_483_647;

fn canon(value: &Value) -> Result<Vec<u8>> {
    Ok(pyjson::dumps(value, DumpOptions::compact_sorted())?.into_bytes())
}

/// Remove `fp`'s dial mark if it names `session` (issue #14).
fn take_dial_mark(env: &mut EnvState, fp: &str, session: &Arc<dyn Session>) -> bool {
    let ours = env
        .dial_pending
        .get(fp)
        .and_then(Weak::upgrade)
        .is_some_and(|marked| Arc::ptr_eq(&marked, session));
    if ours {
        env.dial_pending.remove(fp);
    }
    ours
}

/// Withhold `frame` from a joining device until its history has been sent
/// (issue #28); past [`HELD_FRAMES_MAX`] it waits for a later VECTOR.
fn hold_frame(
    held: &mut HashMap<String, std::collections::VecDeque<Value>>,
    fp: &str,
    frame: &Value,
) {
    let frames = held.entry(fp.to_owned()).or_default();
    if frames.len() < HELD_FRAMES_MAX {
        frames.push_back(frame.clone());
    }
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use crate::context::Config;
    use crate::team::transport::{
        HandshakeFailedHook, InviteCheck, InviteProof, MembershipCheck, OnSession, SessionClosed,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use tempfile::TempDir;

    struct StubSession {
        peer: DeviceRecord,
        closed: AtomicBool,
        created: Instant,
    }
    impl Session for StubSession {
        fn peer(&self) -> DeviceRecord {
            self.peer.clone()
        }
        fn env_id(&self) -> &str {
            "retry-env"
        }
        fn send(&self, _: &Value) -> Result<()> {
            Ok(())
        }
        fn recv(&self, _: Duration) -> std::result::Result<Option<Value>, SessionClosed> {
            Err(SessionClosed("peer_closed"))
        }
        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
        fn created_at(&self) -> Instant {
            self.created
        }
    }
    struct StubTransport {
        session: Arc<dyn Session>,
    }
    impl Transport for StubTransport {
        fn set_membership(&self, _: MembershipCheck) {}
        fn set_invite_check(&self, _: Option<InviteCheck>) {}
        fn set_handshake_failed(&self, _: Option<HandshakeFailedHook>) {}
        fn listen(&self, _: &str, _: OnSession) -> Result<()> {
            Ok(())
        }
        fn dial(
            &self,
            _: &str,
            _: &str,
            _: Option<InviteProof>,
        ) -> std::result::Result<Arc<dyn Session>, SessionClosed> {
            Ok(self.session.clone())
        }
        fn close(&self) {}
    }

    /// Hands out the queued sessions in order, counting every dial.
    struct QueueTransport {
        queue: Mutex<Vec<Arc<dyn Session>>>,
        dials: std::sync::atomic::AtomicUsize,
    }
    impl QueueTransport {
        fn new(queue: Vec<Arc<dyn Session>>) -> Arc<Self> {
            Arc::new(QueueTransport {
                queue: Mutex::new(queue),
                dials: Default::default(),
            })
        }
        fn dials(&self) -> usize {
            self.dials.load(Ordering::SeqCst)
        }
    }
    impl Transport for QueueTransport {
        fn set_membership(&self, _: MembershipCheck) {}
        fn set_invite_check(&self, _: Option<InviteCheck>) {}
        fn set_handshake_failed(&self, _: Option<HandshakeFailedHook>) {}
        fn listen(&self, _: &str, _: OnSession) -> Result<()> {
            Ok(())
        }
        fn dial(
            &self,
            _: &str,
            _: &str,
            _: Option<InviteProof>,
        ) -> std::result::Result<Arc<dyn Session>, SessionClosed> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            let mut queue = self.queue.lock().unwrap();
            if queue.is_empty() {
                return Err(SessionClosed("synthetic_no_session"));
            }
            Ok(queue.remove(0))
        }
        fn close(&self) {}
    }

    struct RecordingSession {
        peer: DeviceRecord,
        env_id: String,
        sent: Mutex<Vec<Value>>,
        on_first_send: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
        closed: AtomicBool,
        created: Instant,
    }
    impl Session for RecordingSession {
        fn peer(&self) -> DeviceRecord {
            self.peer.clone()
        }
        fn env_id(&self) -> &str {
            &self.env_id
        }
        fn send(&self, message: &Value) -> Result<()> {
            let first = {
                let mut sent = self.sent.lock().unwrap();
                sent.push(message.clone());
                sent.len() == 1
            };
            if first && let Some(callback) = self.on_first_send.lock().unwrap().take() {
                callback();
            }
            Ok(())
        }
        fn recv(&self, _: Duration) -> std::result::Result<Option<Value>, SessionClosed> {
            Err(SessionClosed("peer_closed"))
        }
        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
        fn created_at(&self) -> Instant {
            self.created
        }
    }

    #[test]
    fn fact_replay_stops_on_session_replacement_and_receive_only_drain() {
        let root = TempDir::new().unwrap();
        let ctx = Arc::new(
            Context::initialize(
                root.path().join("state"),
                "synthetic-admin",
                "synthetic-recovery",
                Config::default(),
                crate::clock::system(),
            )
            .unwrap(),
        );
        let mine = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let peer_key = DeviceKey::generate();
        let peer = peer_key.record().unwrap();
        let mine_fp = mine.fingerprint().unwrap();
        let fp = peer.fingerprint();
        let env_id = commit::new_env_id(&mine_fp).unwrap();
        let generation = "0000000000000000";
        let wrap = crate::team::envelope::wrap_dek(
            &[7u8; 32],
            &env_id,
            generation,
            &mine.record().unwrap(),
        )
        .unwrap();
        let init = commit::sign_commit(
            &mine,
            &env_id,
            1,
            "1000-0000",
            &BTreeMap::new(),
            vec![json!({"op":"env.init","owner_device":mine.record().unwrap().to_dict(),"owner_name":"alice","generation_id":generation,"wraps":{mine_fp:wrap}})],
        )
        .unwrap();
        let add = commit::sign_commit(
            &mine,
            &env_id,
            2,
            "2000-0000",
            &BTreeMap::new(),
            vec![json!({"op":"member.add","device":peer.to_dict(),"name":"bob","role":"admin"})],
        )
        .unwrap();
        let store = CommitStore::new(ctx.state, &env_id);
        store.append(&init).unwrap();
        store.append(&add).unwrap();
        let make_recorder = || {
            Arc::new(RecordingSession {
                peer: peer.clone(),
                env_id: env_id.clone(),
                sent: Mutex::new(Vec::new()),
                on_first_send: Mutex::new(None),
                closed: AtomicBool::new(false),
                created: Instant::now(),
            })
        };
        let recorder = make_recorder();
        let session: Arc<dyn Session> = recorder.clone();
        let team = TeamSync::new(
            ctx.clone(),
            Arc::new(StubTransport {
                session: session.clone(),
            }),
            mine.clone(),
        );
        team.register_env(&env_id).unwrap();
        assert!(team.accept_session(&env_id, session.clone(), true));
        let foreign_env = commit::new_env_id(&mine.fingerprint().unwrap()).unwrap();
        // First and 65th lines are valid. Invalid, signed INCIDENT,
        // cross-environment, malformed-target and bad-signature rows between
        // them must never be sent.
        // Replacement during the first send reaches the old batch's cursor
        // update at line 64, which must not overwrite the new session's zero.
        for i in 0..=64 {
            let line = if i == 0 || i == 64 {
                sign_fact(
                    &mine,
                    &env_id,
                    "connection_disabled",
                    json!({"connection_id":"gh"}),
                    &format!("{}-0000", 3000 + i),
                )
                .unwrap()
                .to_dict()
                .to_string()
            } else {
                match i % 5 {
                    0 => "not-json".to_owned(),
                    1 => sign_fact(
                        &mine,
                        &env_id,
                        "incident",
                        json!({"incident_id":"0123456789abcdef"}),
                        &format!("{}-0000", 3000 + i),
                    )
                    .unwrap()
                    .to_dict()
                    .to_string(),
                    2 => sign_fact(
                        &mine,
                        &foreign_env,
                        "connection_disabled",
                        json!({"connection_id":"gh"}),
                        &format!("{}-0000", 3000 + i),
                    )
                    .unwrap()
                    .to_dict()
                    .to_string(),
                    3 => {
                        let mut tampered = sign_fact(
                            &mine,
                            &env_id,
                            "connection_disabled",
                            json!({"connection_id":"gh"}),
                            &format!("{}-0000", 3000 + i),
                        )
                        .unwrap()
                        .to_dict();
                        tampered["target"]["credential"] = json!("synthetic-do-not-send");
                        tampered.to_string()
                    }
                    _ => {
                        let mut tampered = sign_fact(
                            &mine,
                            &env_id,
                            "connection_disabled",
                            json!({"connection_id":"gh"}),
                            &format!("{}-0000", 3000 + i),
                        )
                        .unwrap()
                        .to_dict();
                        tampered["target"]["connection_id"] = json!("bad-signature");
                        tampered.to_string()
                    }
                }
            };
            ctx.state
                .append_line(&format!("team/{env_id}/facts.jsonl"), &line)
                .unwrap();
        }
        let replacement = make_recorder();
        let replacement_session: Arc<dyn Session> = replacement.clone();
        let keep_new_inbound = mine.fingerprint().unwrap() > fp;
        let weak = Arc::downgrade(&team);
        let callback_env = env_id.clone();
        *recorder.on_first_send.lock().unwrap() = Some(Box::new(move || {
            assert!(weak.upgrade().unwrap().accept_session(
                &callback_env,
                replacement_session.clone(),
                keep_new_inbound
            ));
        }));
        team.send_fact_catchup(&env_id, &session).unwrap();
        assert_eq!(recorder.sent.lock().unwrap().len(), 1);
        assert_eq!(
            team.envs.lock().unwrap()[&env_id].fact_replay_cursor[&fp],
            0
        );
        let replacement_session: Arc<dyn Session> = replacement.clone();
        team.send_fact_catchup(&env_id, &replacement_session)
            .unwrap();
        assert_eq!(replacement.sent.lock().unwrap().len(), 1);
        team.send_fact_catchup(&env_id, &replacement_session)
            .unwrap();
        assert_eq!(replacement.sent.lock().unwrap().len(), 2);
        let frames = replacement.sent.lock().unwrap().clone();
        assert!(frames.iter().all(|v| v["type"] == "FACT"));
        assert!(
            frames
                .iter()
                .all(|v| v["fact"]["kind"] == "connection_disabled")
        );
        assert!(
            frames
                .iter()
                .all(|v| v["fact"]["target"] == json!({"connection_id":"gh"}))
        );
        assert!(!json!(frames).to_string().contains("synthetic-do-not-send"));
        let appended = sign_fact(
            &mine,
            &env_id,
            "secret_version_revoked",
            json!({"secret_id":"key","version_id":"0011223344556677"}),
            "4000-0000",
        )
        .unwrap();
        ctx.state
            .append_line(
                &format!("team/{env_id}/facts.jsonl"),
                &appended.to_dict().to_string(),
            )
            .unwrap();
        // Same live session, after EOF had reset to zero: a later line still
        // arrives on the next bounded cycle. Earlier frames may repeat and
        // are deduplicated by the real receiving path.
        team.send_fact_catchup(&env_id, &replacement_session)
            .unwrap();
        team.send_fact_catchup(&env_id, &replacement_session)
            .unwrap();
        let frames = replacement.sent.lock().unwrap();
        assert_eq!(frames.len(), 5);
        assert_eq!(frames.last().unwrap()["fact"], appended.to_dict());
        drop(frames);

        let draining = make_recorder();
        let draining_session: Arc<dyn Session> = draining.clone();
        assert!(team.accept_session(&env_id, draining_session.clone(), keep_new_inbound));
        let weak = Arc::downgrade(&team);
        let callback_env = env_id.clone();
        let callback_fp = fp.clone();
        *draining.on_first_send.lock().unwrap() = Some(Box::new(move || {
            weak.upgrade()
                .unwrap()
                .drain_removed(&callback_env, &callback_fp);
        }));
        team.send_fact_catchup(&env_id, &draining_session).unwrap();
        // The next batch would reach valid line 64 if a drained session were
        // still eligible for outbound replay.
        team.send_fact_catchup(&env_id, &draining_session).unwrap();
        assert_eq!(draining.sent.lock().unwrap().len(), 1);
        assert!(
            team.envs.lock().unwrap()[&env_id]
                .draining
                .contains_key(&fp)
        );
    }

    #[test]
    fn concurrent_store_fact_has_exactly_one_insert_winner() {
        use std::sync::Barrier;

        let root = TempDir::new().unwrap();
        let ctx = Arc::new(
            Context::initialize(
                root.path().join("state"),
                "synthetic-admin",
                "synthetic-recovery",
                Config::default(),
                crate::clock::system(),
            )
            .unwrap(),
        );
        let mine = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let peer = DeviceKey::generate().record().unwrap();
        let session: Arc<dyn Session> = Arc::new(StubSession {
            peer,
            closed: AtomicBool::new(false),
            created: Instant::now(),
        });
        let team = TeamSync::new(
            ctx.clone(),
            Arc::new(StubTransport { session }),
            mine.clone(),
        );
        let env_id = commit::new_env_id(&mine.fingerprint().unwrap()).unwrap();
        team.envs.lock().unwrap().insert(
            env_id.clone(),
            EnvState::new(Facts::default(), HashSet::new(), HashMap::new()),
        );
        let fact = sign_fact(
            &mine,
            &env_id,
            "connection_disabled",
            json!({"connection_id":"synthetic-connection"}),
            "3000-0000",
        )
        .unwrap();
        let barrier = Barrier::new(2);
        let inserted = thread::scope(|scope| {
            let first = scope.spawn(|| {
                barrier.wait();
                team.store_fact(&env_id, &fact).unwrap()
            });
            let second = scope.spawn(|| {
                barrier.wait();
                team.store_fact(&env_id, &fact).unwrap()
            });
            usize::from(first.join().unwrap()) + usize::from(second.join().unwrap())
        });
        assert_eq!(inserted, 1);
        assert_eq!(team.envs.lock().unwrap()[&env_id].fact_hashes.len(), 1);
        assert_eq!(
            ctx.state
                .read_lines(&format!("team/{env_id}/facts.jsonl"), None)
                .unwrap()
                .len(),
            1
        );
    }

    /// An owner node with a shared environment, a `TeamSync` and one admin
    /// peer, plus a recording session for that peer (driven through
    /// `handle_message` directly).
    struct OwnerWithAdminPeer {
        _root: TempDir,
        ctx: Arc<Context>,
        env_id: String,
        peer_key: DeviceKey,
        recorder: Arc<RecordingSession>,
        session: Arc<dyn Session>,
        team: Arc<TeamSync>,
    }
    fn owner_with_admin_peer() -> OwnerWithAdminPeer {
        owner_with_admin_peer_configured(Config::default())
    }
    fn owner_with_admin_peer_configured(config: Config) -> OwnerWithAdminPeer {
        let root = TempDir::new().unwrap();
        let ctx = Arc::new(
            Context::initialize(
                root.path().join("a"),
                "synthetic-admin",
                "synthetic-recovery",
                config,
                crate::clock::system(),
            )
            .unwrap(),
        );
        ctx.projects.create("demo", &["dev"]).unwrap();
        let env_id = crate::team::membership::share_environment(
            &ctx,
            None,
            "demo",
            "dev",
            "owner",
            "synthetic-admin",
        )
        .unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let mine = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let peer_key = DeviceKey::generate();
        let peer = peer_key.record().unwrap();
        let recorder = Arc::new(RecordingSession {
            peer: peer.clone(),
            env_id: env_id.clone(),
            sent: Mutex::new(Vec::new()),
            on_first_send: Mutex::new(None),
            closed: AtomicBool::new(false),
            created: Instant::now(),
        });
        let session: Arc<dyn Session> = recorder.clone();
        let team = TeamSync::new(
            ctx.clone(),
            Arc::new(StubTransport {
                session: session.clone(),
            }),
            mine,
        );
        team.register_env(&env_id).unwrap();
        crate::team::membership::author_commit(
            &ctx,
            Some(&team),
            &env_id,
            vec![json!({"op":"member.add","device":peer.to_dict(),"name":"bob","role":"admin"})],
        )
        .unwrap();
        OwnerWithAdminPeer {
            _root: root,
            ctx,
            env_id,
            peer_key,
            recorder,
            session,
            team,
        }
    }

    fn settings_commit(key: &DeviceKey, env_id: &str, seq: i64, wall: i64) -> Commit {
        commit::sign_commit(
            key,
            env_id,
            seq,
            &format!("{wall}-0000"),
            &BTreeMap::new(),
            vec![json!({"op":"settings.update","sync_interval_seconds":30})],
        )
        .unwrap()
    }
    fn sent_of_type(recorder: &RecordingSession, kind: &str) -> Vec<Value> {
        recorder
            .sent
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m["type"] == kind)
            .cloned()
            .collect()
    }
    fn recording_session(peer: DeviceRecord, env_id: &str) -> Arc<RecordingSession> {
        Arc::new(RecordingSession {
            peer,
            env_id: env_id.to_owned(),
            sent: Mutex::new(Vec::new()),
            on_first_send: Mutex::new(None),
            closed: AtomicBool::new(false),
            created: Instant::now(),
        })
    }
    /// A second shared environment on `f`'s node, `name/dev`, known to `f.team`
    /// only when `register` is set.
    fn another_environment(f: &OwnerWithAdminPeer, name: &str, register: bool) -> String {
        f.ctx.projects.create(name, &["dev"]).unwrap();
        let env_id = crate::team::membership::share_environment(
            &f.ctx,
            None,
            name,
            "dev",
            "owner",
            "synthetic-admin",
        )
        .unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
        if register {
            f.team.register_env(&env_id).unwrap();
        }
        env_id
    }
    fn quarantined(ctx: &Context, env_id: &str) -> Vec<String> {
        std::fs::read_dir(ctx.state.path.join(format!("team/{env_id}/rejected")))
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Issue #35: a refold that passes over a stale snapshot stores a new
    /// one with the facts it was folded with and drops the stale one, so
    /// the next refold builds on the new one.
    #[test]
    fn a_refold_replaces_a_stale_snapshot() {
        let f = owner_with_admin_peer();
        f.team
            .publish_fact(
                &f.env_id,
                "connection_disabled",
                json!({"connection_id": "synthetic-off"}),
            )
            .unwrap();
        // Folded without that fact, as an earlier refold could have stored it.
        let commits = CommitStore::new(f.ctx.state, &f.env_id)
            .all_commits()
            .unwrap();
        let stale_commits = commits.clone();
        let stale = fold::fold_for_refold(&f.env_id, commits, f.ctx.state, None, None).unwrap();
        fold::save_snapshot(f.ctx.state, &f.env_id, &PyInt::from(0), &stale.snapshot).unwrap();
        let record = fold::snapshot_record(None, &stale_commits);
        fold::save_snapshot_record(f.ctx.state, &f.env_id, &PyInt::from(0), &record).unwrap();
        f.team.refold(&f.env_id).unwrap();
        let names: Vec<String> = std::fs::read_dir(
            f.ctx
                .state
                .path
                .join(format!("team/{}/snapshots", f.env_id)),
        )
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        assert_ne!(names[0], "0.json");
        let commits = CommitStore::new(f.ctx.state, &f.env_id)
            .all_commits()
            .unwrap();
        let (facts, _, _) = load_facts(&f.ctx, &f.env_id).unwrap();
        let next =
            fold::fold_for_refold(&f.env_id, commits, f.ctx.state, Some(&facts), None).unwrap();
        assert!(next.stale_snapshots.is_empty());
    }

    /// A snapshot without a record that matches the fold of the commits it
    /// covers is built on, and the refold records it (issue #35).
    #[test]
    fn a_refold_records_an_unrecorded_snapshot() {
        let f = owner_with_admin_peer();
        let commits = CommitStore::new(f.ctx.state, &f.env_id)
            .all_commits()
            .unwrap();
        let (facts, _, _) = load_facts(&f.ctx, &f.env_id).unwrap();
        let built =
            fold::fold_for_refold(&f.env_id, commits.clone(), f.ctx.state, Some(&facts), None)
                .unwrap();
        fold::save_snapshot(f.ctx.state, &f.env_id, &PyInt::from(1), &built.snapshot).unwrap();
        f.team.refold(&f.env_id).unwrap();
        let recorded = f
            .ctx
            .state
            .read_json(
                &format!("team/{}/snapshot_records/1.json", f.env_id),
                Value::Null,
            )
            .unwrap();
        assert_eq!(recorded, fold::snapshot_record(Some(&facts), &commits));
    }

    /// ...also when the same refold stores a new snapshot in place of a
    /// newer one that went stale.
    #[test]
    fn a_refold_records_an_unrecorded_snapshot_while_replacing_a_stale_one() {
        let f = owner_with_admin_peer();
        let commits = CommitStore::new(f.ctx.state, &f.env_id)
            .all_commits()
            .unwrap();
        let (facts, _, _) = load_facts(&f.ctx, &f.env_id).unwrap();
        let built =
            fold::fold_for_refold(&f.env_id, commits.clone(), f.ctx.state, Some(&facts), None)
                .unwrap();
        let (unrecorded, stale) = (PyInt::from(0), PyInt::from(1));
        fold::save_snapshot(f.ctx.state, &f.env_id, &unrecorded, &built.snapshot).unwrap();
        fold::save_snapshot(f.ctx.state, &f.env_id, &stale, &built.snapshot).unwrap();
        fold::save_snapshot_record(
            f.ctx.state,
            &f.env_id,
            &stale,
            &json!({"facts": ["synthetic-stale"]}),
        )
        .unwrap();
        f.team.refold(&f.env_id).unwrap();
        let read = |path: String| f.ctx.state.read_json(&path, Value::Null).unwrap();
        assert_eq!(
            read(format!("team/{}/snapshot_records/0.json", f.env_id)),
            fold::snapshot_record(Some(&facts), &commits)
        );
        assert!(
            read(format!("team/{}/snapshots/1.json", f.env_id)).is_null(),
            "the stale snapshot is dropped"
        );
    }

    /// Issue #28: a joiner's session gets no live COMMIT, FACT or INCIDENT
    /// until its first VECTOR is answered, and the answer is in total order
    /// across authors, so an admitted author's commits never precede its
    /// admission even when its fingerprint sorts first.
    #[test]
    fn joiner_gets_history_in_total_order_before_live_traffic() {
        let f = owner_with_admin_peer();
        let owner = f.team.device.fingerprint().unwrap();
        let second_admin = loop {
            let key = DeviceKey::generate();
            if key.fingerprint().unwrap() < owner {
                break key;
            }
        };
        crate::team::membership::author_commit(
            &f.ctx,
            Some(&f.team),
            &f.env_id,
            vec![json!({"op":"member.add","device":second_admin.record().unwrap().to_dict(),"name":"carol","role":"admin"})],
        )
        .unwrap();
        let store = CommitStore::new(f.ctx.state, &f.env_id);
        let by_second = settings_commit(&second_admin, &f.env_id, 1, commit::now_ms() + 1);
        assert_eq!(
            commit::receive_commit(&store, &by_second, commit::now_ms(), None).unwrap(),
            "accepted"
        );
        let peer = f.peer_key.fingerprint().unwrap();
        f.team
            .envs
            .lock()
            .unwrap()
            .get_mut(&f.env_id)
            .unwrap()
            .pending_invites
            .insert(peer.clone(), ("admin".into(), "bob".into()));
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        let incident = sign_fact(
            &f.team.device,
            &f.env_id,
            "incident",
            json!({"incident_id":"0123456789abcdef"}),
            "10000-0000",
        )
        .unwrap();
        f.team
            .envs
            .lock()
            .unwrap()
            .get_mut(&f.env_id)
            .unwrap()
            .incident_outbox
            .insert(incident.hash().unwrap(), incident.clone());
        let live = json!({"type":"COMMIT","commit":by_second.to_dict()});
        let fact = sign_fact(
            &f.team.device,
            &f.env_id,
            "connection_disabled",
            json!({"connection_id":"gh"}),
            "10001-0000",
        )
        .unwrap();
        let live_fact = json!({"type":"FACT","fact":fact.to_dict()});
        f.team.broadcast(&f.env_id, &live, None);
        f.team.broadcast(&f.env_id, &live_fact, None);
        assert_eq!(f.team.deliver_incident(&f.env_id, &incident), 0);
        f.team.retry_pending_incidents_to(&f.env_id, &f.session);
        assert!(f.recorder.sent.lock().unwrap().is_empty());

        f.team
            .handle_vector(&f.env_id, &f.session, &json!({"type":"VECTOR","vector":{}}))
            .unwrap();
        let hashes = |commits: Vec<Commit>| -> Vec<String> {
            commits.iter().map(|c| c.hash().unwrap()).collect()
        };
        let sent = f.recorder.sent.lock().unwrap().clone();
        let answered: Vec<Commit> = sent[..4]
            .iter()
            .map(|m| Commit::from_dict(&m["commit"]).unwrap())
            .collect();
        assert_eq!(hashes(answered), hashes(store.all_commits().unwrap()));
        // Then what was held, in order, then the incident.
        assert_eq!(sent[4], live);
        assert_eq!(sent[5], live_fact);
        assert_eq!(sent[6]["type"], "INCIDENT");
        assert_eq!(sent.len(), 7);
        // Released: live traffic flows again.
        f.team.broadcast(&f.env_id, &live, None);
        assert_eq!(f.recorder.sent.lock().unwrap()[7], live);
        let env = &f.team.envs.lock().unwrap()[&f.env_id];
        assert!(env.catching_up.is_empty() && env.held.is_empty());
    }

    /// A joiner removed while its catch-up is held gets its removal notice
    /// at once and nothing else: neither the held frames nor the history a
    /// VECTOR answer already under way would send (section 4.4).
    #[test]
    fn a_joiner_removed_while_held_gets_only_its_removal_notice() {
        // Its VECTOR asks for the whole history, or for none of it.
        for full in [false, true] {
            let f = owner_with_admin_peer();
            let peer = f.peer_key.fingerprint().unwrap();
            f.team
                .envs
                .lock()
                .unwrap()
                .get_mut(&f.env_id)
                .unwrap()
                .pending_invites
                .insert(peer.clone(), ("admin".into(), "bob".into()));
            assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
            let live = settings_commit(&f.team.device, &f.env_id, 99, commit::now_ms() + 1);
            f.team.broadcast(
                &f.env_id,
                &json!({"type":"COMMIT","commit":live.to_dict()}),
                None,
            );
            assert!(f.recorder.sent.lock().unwrap().is_empty());
            let removal = sign_fact(
                &f.team.device,
                &f.env_id,
                "member_removed",
                json!({"fingerprint": peer}),
                "10002-0000",
            )
            .unwrap();
            f.team.drain_removed(&f.env_id, &peer);
            f.team.send_removal_notice(&f.env_id, &removal, None);
            let vector = if full {
                json!(CommitStore::new(f.ctx.state, &f.env_id).vector().unwrap())
            } else {
                json!({})
            };
            f.team
                .handle_vector(
                    &f.env_id,
                    &f.session,
                    &json!({"type":"VECTOR","vector":vector}),
                )
                .unwrap();
            let sent = f.recorder.sent.lock().unwrap().clone();
            assert_eq!(sent, [json!({"type":"FACT","fact":removal.to_dict()})]);
            let env = &f.team.envs.lock().unwrap()[&f.env_id];
            assert!(env.catching_up.is_empty() && env.held.is_empty());
        }
    }

    /// An unreadable `deferred/` entry -- one released or corrupted while it
    /// is read -- keeps an early commit waiting; it does not end the session.
    #[test]
    fn an_unreadable_deferred_entry_keeps_an_early_commit_waiting() {
        let f = owner_with_admin_peer();
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        let deferred = f.ctx.state.path.join(format!("team/{}/deferred", f.env_id));
        std::fs::create_dir_all(&deferred).unwrap();
        std::fs::write(deferred.join("synthetic.json"), b"{not json").unwrap();
        let early = settings_commit(&f.peer_key, &f.env_id, 2, commit::now_ms() + 1);
        f.team
            .handle_commit(
                &f.env_id,
                &f.session,
                &json!({"type":"COMMIT","commit":early.to_dict()}),
            )
            .unwrap();
        assert!(quarantined(&f.ctx, &f.env_id).is_empty());
        let peer = f.peer_key.fingerprint().unwrap();
        let env = &f.team.envs.lock().unwrap()[&f.env_id];
        assert!(env.sessions.contains_key(&peer));
        assert!(
            env.vector_due.contains(&peer),
            "the sender is marked due for the range"
        );
    }

    /// Section 6.4: an environment whose poll fails -- on an unreadable
    /// `deferred/` entry here -- holds up no environment polled after it.
    #[test]
    fn a_failing_environment_holds_up_no_other_environment() {
        let f = owner_with_admin_peer();
        let second = another_environment(&f, "other", true);
        let (broken, healthy) = if f.env_id < second {
            (f.env_id.clone(), second)
        } else {
            (second, f.env_id.clone())
        };
        let deferred = f.ctx.state.path.join(format!("team/{broken}/deferred"));
        std::fs::create_dir_all(&deferred).unwrap();
        std::fs::write(deferred.join("synthetic.json"), b"{not json").unwrap();
        let recorder = recording_session(f.peer_key.record().unwrap(), &healthy);
        assert!(f.team.accept_session(&healthy, recorder.clone(), true));
        assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        assert_eq!(sent_of_type(&recorder, "VECTOR").len(), 1);
        // Audited for the failing environment only (issue #49).
        assert_eq!(sync_poll_audits(&f, &broken), 1);
        assert_eq!(sync_poll_audits(&f, &healthy), 0);
    }

    /// `team_sync_poll` records for `env_id`.
    fn sync_poll_audits(f: &OwnerWithAdminPeer, env_id: &str) -> usize {
        f.ctx
            .audit
            .iter_records()
            .unwrap()
            .iter()
            .filter(|record| record["event"] == "team_sync_poll" && record["env_id"] == env_id)
            .count()
    }

    /// Issue #49: once an environment that could not be loaded loads, its
    /// next failure is audited, although for the same reason as the load.
    #[test]
    fn a_failure_after_a_load_failure_is_audited() {
        let f = owner_with_admin_peer();
        let late = another_environment(&f, "late", false);
        let peers = f.ctx.state.path.join(format!("team/{late}/peers.json"));
        std::fs::write(&peers, b"[1]").unwrap();
        assert_eq!(f.team.discover().unwrap_err().reason, "state_corrupt");
        assert!(!f.team.known_envs().contains(&late));
        assert_eq!(sync_poll_audits(&f, &late), 1);
        std::fs::remove_file(&peers).unwrap();
        let deferred = f.ctx.state.path.join(format!("team/{late}/deferred"));
        std::fs::create_dir_all(&deferred).unwrap();
        std::fs::write(deferred.join("synthetic.json"), b"{not json").unwrap();
        *f.team.last_discovery.lock().unwrap() = Instant::now() - Duration::from_secs(2);
        assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        assert!(f.team.known_envs().contains(&late));
        assert_eq!(sync_poll_audits(&f, &late), 2);
    }

    /// Issue #49: an environment whose first refold fails is loaded as well,
    /// so that failure is audited although for the same reason as its load
    /// failure, and the polls retrying the refold are not.
    #[test]
    fn a_refold_failing_at_registration_after_a_load_failure_is_audited() {
        let f = owner_with_admin_peer();
        let late = another_environment(&f, "late", false);
        let peers = f.ctx.state.path.join(format!("team/{late}/peers.json"));
        std::fs::write(&peers, b"[1]").unwrap();
        assert_eq!(f.team.discover().unwrap_err().reason, "state_corrupt");
        assert_eq!(sync_poll_audits(&f, &late), 1);
        std::fs::remove_file(&peers).unwrap();
        let restore = fail_refolds(&f);
        assert_eq!(f.team.discover().unwrap_err().reason, "state_corrupt");
        assert!(f.team.known_envs().contains(&late));
        assert_eq!(sync_poll_audits(&f, &late), 2);
        for _ in 0..3 {
            *f.team.last_discovery.lock().unwrap() = Instant::now() - Duration::from_secs(2);
            assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        }
        assert_eq!(sync_poll_audits(&f, &late), 2);
        restore();
    }

    /// Section 6.4: while its poll fails, an environment still closes its due
    /// sessions, so a drained device's window stays bounded (section 4.4),
    /// but asks no peer for anything. Once `deferred/` reads again, the peer
    /// an early commit asked for meanwhile gets one VECTOR, not one more for
    /// the periodic exchange that also fell due.
    #[test]
    fn a_failing_environment_closes_due_sessions_and_asks_nothing() {
        let f = owner_with_admin_peer();
        let peer = f.peer_key.fingerprint().unwrap();
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        let drained_key = DeviceKey::generate();
        let drained = recording_session(drained_key.record().unwrap(), &f.env_id);
        assert!(f.team.accept_session(&f.env_id, drained.clone(), true));
        let gone = drained_key.fingerprint().unwrap();
        f.team
            .envs
            .lock()
            .unwrap()
            .get_mut(&f.env_id)
            .unwrap()
            .draining
            .insert(gone.clone(), Instant::now());
        let ended_key = DeviceKey::generate();
        let ended = recording_session(ended_key.record().unwrap(), &f.env_id);
        assert!(f.team.accept_session(&f.env_id, ended.clone(), true));
        ended.close();
        let entry = f
            .ctx
            .state
            .path
            .join(format!("team/{}/deferred/synthetic.json", f.env_id));
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::fs::write(&entry, b"[1]").unwrap();
        let early = settings_commit(&f.peer_key, &f.env_id, 2, commit::now_ms() + 1);
        f.team
            .handle_commit(
                &f.env_id,
                &f.session,
                &json!({"type":"COMMIT","commit":early.to_dict()}),
            )
            .unwrap();
        assert!(
            f.team.envs.lock().unwrap()[&f.env_id]
                .vector_due
                .contains(&peer)
        );
        assert_eq!(f.team.poll().unwrap_err().reason, "commit_malformed");
        assert!(drained.is_closed());
        {
            let envs = f.team.envs.lock().unwrap();
            let sessions = &envs[&f.env_id].sessions;
            assert!(!sessions.contains_key(&gone));
            assert!(!sessions.contains_key(&ended_key.fingerprint().unwrap()));
        }
        assert!(sent_of_type(&f.recorder, "VECTOR").is_empty());
        std::fs::remove_file(&entry).unwrap();
        f.team.poll().unwrap();
        assert_eq!(sent_of_type(&f.recorder, "VECTOR").len(), 1);
    }

    /// Section 6.4: an environment that cannot be loaded when it is
    /// discovered holds up neither the discovery of another new environment
    /// nor the poll of the known ones.
    #[test]
    fn an_environment_that_cannot_load_holds_up_no_other() {
        let f = owner_with_admin_peer();
        let first = another_environment(&f, "first", false);
        let second = another_environment(&f, "second", false);
        let (broken, healthy) = if first < second {
            (first, second)
        } else {
            (second, first)
        };
        std::fs::write(
            f.ctx.state.path.join(format!("team/{broken}/peers.json")),
            b"[1]",
        )
        .unwrap();
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        let known = f.team.known_envs();
        assert!(known.contains(&healthy) && !known.contains(&broken));
        assert_eq!(sent_of_type(&f.recorder, "VECTOR").len(), 1);
    }

    /// Section 6.4: a failing environment's poll dials no one, and dials as
    /// soon as it succeeds again.
    #[test]
    fn a_failing_environment_dials_no_one() {
        let f = owner_with_admin_peer();
        let peer = f.peer_key.fingerprint().unwrap();
        let (session, _tx) = scripted(f.peer_key.record().unwrap());
        let session: Arc<dyn Session> = session;
        let transport = QueueTransport::new(vec![session]);
        let team = TeamSync::new(f.ctx.clone(), transport.clone(), f.team.device.clone());
        team.register_env(&f.env_id).unwrap();
        team.set_peer_address(&f.env_id, &peer, "synthetic-address")
            .unwrap();
        let entry = f
            .ctx
            .state
            .path
            .join(format!("team/{}/deferred/synthetic.json", f.env_id));
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::fs::write(&entry, b"{not json").unwrap();
        for _ in 0..3 {
            assert_eq!(team.poll().unwrap_err().reason, "state_corrupt");
        }
        assert_eq!(transport.dials(), 0);
        std::fs::remove_file(&entry).unwrap();
        team.poll().unwrap();
        assert_eq!(transport.dials(), 1);
        team.stop();
    }

    /// Section 6.4: a failing environment still closes sessions past the
    /// session age limit.
    #[test]
    fn a_failing_environment_closes_expired_sessions() {
        let f = owner_with_admin_peer_configured(Config {
            team_session_max_age_seconds: 0.0,
            ..Config::default()
        });
        let peer = f.peer_key.fingerprint().unwrap();
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        let entry = f
            .ctx
            .state
            .path
            .join(format!("team/{}/deferred/synthetic.json", f.env_id));
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::fs::write(&entry, b"{not json").unwrap();
        assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        assert!(f.recorder.is_closed());
        assert!(
            !f.team.envs.lock().unwrap()[&f.env_id]
                .sessions
                .contains_key(&peer)
        );
    }

    /// Issue #14: a dialed session that reads closed before its receiver has
    /// noticed is dropped by the poll but not redialed in the same tick, so
    /// its receiver counts the refused dial and the next dial backs off.
    #[test]
    fn a_session_the_poll_closes_is_redialed_from_the_next_tick() {
        let f = owner_with_admin_peer();
        let peer = f.peer_key.fingerprint().unwrap();
        let delay = Duration::from_millis(1500);
        let (first, _first_tx) = scripted_with(f.peer_key.record().unwrap(), false, delay);
        let (second, _second_tx) = scripted_with(f.peer_key.record().unwrap(), false, delay);
        let queued: Vec<Arc<dyn Session>> = vec![first.clone(), second];
        let transport = QueueTransport::new(queued);
        let team = TeamSync::new(f.ctx.clone(), transport.clone(), f.team.device.clone());
        team.register_env(&f.env_id).unwrap();
        team.set_peer_address(&f.env_id, &peer, "synthetic-address")
            .unwrap();
        team.poll().unwrap();
        assert_eq!(transport.dials(), 1);
        first.close();
        team.poll().unwrap();
        assert_eq!(transport.dials(), 1);
        let (min, _) = Config::default().team_dial_backoff;
        wait_for(|| {
            team.envs.lock().unwrap()[&f.env_id]
                .backoff
                .contains_key(&peer)
        });
        {
            let envs = team.envs.lock().unwrap();
            let env = &envs[&f.env_id];
            assert_eq!(env.backoff[&peer], Duration::from_secs_f64(min));
            assert!(env.next_attempt.contains_key(&peer));
        }
        team.stop();
    }

    /// Section 6.4: a persistent poll failure is audited once per reason,
    /// not on every tick, and again when it starts anew.
    #[test]
    fn a_failing_environment_is_audited_once_per_failure() {
        let f = owner_with_admin_peer();
        let entry = f
            .ctx
            .state
            .path
            .join(format!("team/{}/deferred/synthetic.json", f.env_id));
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        // A commit whose HLC does not parse: `deferred/` reads, and only the
        // release fails.
        let mut malformed = settings_commit(&f.peer_key, &f.env_id, 1, 1000).to_dict();
        malformed["hlc"] = json!("synthetic");
        std::fs::write(&entry, malformed.to_string()).unwrap();
        let audited = || {
            f.ctx
                .state
                .read_lines(crate::audit::AUDIT_FILE, None)
                .unwrap()
                .iter()
                .filter_map(|line| pyjson::loads(line).ok())
                .filter(|record| record["event"] == "team_sync_poll")
                .collect::<Vec<_>>()
        };
        for _ in 0..3 {
            // Each poll also runs discovery, which leaves a known
            // environment's record alone (issue #49).
            *f.team.last_discovery.lock().unwrap() = Instant::now() - Duration::from_secs(2);
            assert_eq!(f.team.poll().unwrap_err().reason, "hlc_malformed");
        }
        let records = audited();
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0]["result"], "failed");
        assert_eq!(records[0]["reason"], "hlc_malformed");
        assert_eq!(records[0]["env_id"], json!(f.env_id));
        std::fs::write(&entry, b"[1]").unwrap();
        assert_eq!(f.team.poll().unwrap_err().reason, "commit_malformed");
        assert_eq!(audited().len(), 2);
        std::fs::remove_file(&entry).unwrap();
        f.team.poll().unwrap();
        std::fs::write(&entry, b"[1]").unwrap();
        assert_eq!(f.team.poll().unwrap_err().reason, "commit_malformed");
        assert_eq!(audited().len(), 3);
    }

    /// Both failing environments are polled and audited; the poll returns the
    /// first one's error.
    #[test]
    fn a_poll_returns_the_first_failure() {
        let f = owner_with_admin_peer();
        let second = another_environment(&f, "other", true);
        let (first, later) = if f.env_id < second {
            (f.env_id.clone(), second)
        } else {
            (second, f.env_id.clone())
        };
        for (env_id, body) in [(&first, &b"[1]"[..]), (&later, &b"{not json"[..])] {
            let deferred = f.ctx.state.path.join(format!("team/{env_id}/deferred"));
            std::fs::create_dir_all(&deferred).unwrap();
            std::fs::write(deferred.join("synthetic.json"), body).unwrap();
        }
        assert_eq!(f.team.poll().unwrap_err().reason, "commit_malformed");
        let audited: Vec<Value> = f
            .ctx
            .state
            .read_lines(crate::audit::AUDIT_FILE, None)
            .unwrap()
            .iter()
            .filter_map(|line| pyjson::loads(line).ok())
            .filter(|record| record["event"] == "team_sync_poll")
            .collect();
        assert_eq!(audited.len(), 2, "{audited:?}");
    }

    /// Discovery registers what it can, audits what it cannot load, and
    /// returns the first such error; `start` still refuses to run then.
    #[test]
    fn discovery_returns_the_first_failure_and_start_refuses() {
        let f = owner_with_admin_peer();
        let one = another_environment(&f, "one", false);
        let two = another_environment(&f, "two", false);
        for env_id in [&one, &two] {
            std::fs::write(
                f.ctx.state.path.join(format!("team/{env_id}/peers.json")),
                b"[1]",
            )
            .unwrap();
        }
        let first = std::cmp::min(&one, &two);
        let error = f.team.discover().unwrap_err();
        assert_eq!(error.reason, "state_corrupt");
        assert!(error.detail.contains(first.as_str()), "{}", error.detail);
        let audited = f
            .ctx
            .state
            .read_lines(crate::audit::AUDIT_FILE, None)
            .unwrap()
            .iter()
            .filter(|line| line.contains("team_sync_poll"))
            .count();
        assert_eq!(audited, 2);
        let fresh = TeamSync::new(
            f.ctx.clone(),
            QueueTransport::new(Vec::new()),
            f.team.device.clone(),
        );
        assert_eq!(fresh.start(None).unwrap_err().reason, "state_corrupt");
        fresh.stop();
    }

    /// Every refold of `f`'s node fails, as with an unreadable local vault,
    /// until the returned closure restores the vault.
    fn fail_refolds(f: &OwnerWithAdminPeer) -> impl FnOnce() {
        let path = f.ctx.state.path.join(crate::vault::VAULT_DOC);
        let saved = std::fs::read(&path).unwrap();
        std::fs::write(&path, b"[1]").unwrap();
        move || std::fs::write(&path, saved).unwrap()
    }
    fn retrying_refolds_at_once() -> OwnerWithAdminPeer {
        owner_with_admin_peer_configured(Config {
            team_refold_retry_backoff: (0.0, 0.0),
            ..Config::default()
        })
    }
    fn sync_interval(f: &OwnerWithAdminPeer) -> Value {
        f.team.document(&f.env_id).unwrap()["settings"]["sync_interval_seconds"].clone()
    }
    fn fact_audits(f: &OwnerWithAdminPeer, event: &str) -> usize {
        f.ctx
            .audit
            .iter_records()
            .unwrap()
            .iter()
            .filter(|record| record["event"] == event)
            .count()
    }

    /// Issue #51: a refold that fails while picking up a local commit is
    /// retried by every poll until it succeeds. Meanwhile each poll reports
    /// the failure, audited once, and the commit waits: it is not broadcast.
    /// Then it is folded and broadcast, once.
    #[test]
    fn a_failed_pickup_refold_is_retried_until_it_succeeds() {
        let f = retrying_refolds_at_once();
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        f.team.poll().unwrap();
        crate::team::membership::author_commit(
            &f.ctx,
            None,
            &f.env_id,
            vec![json!({"op":"settings.update","sync_interval_seconds":31})],
        )
        .unwrap();
        let restore = fail_refolds(&f);
        let commits = || sent_of_type(&f.recorder, "COMMIT");
        let before = commits().len();
        for _ in 0..3 {
            assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        }
        assert_ne!(sync_interval(&f), 31);
        assert_eq!(commits().len(), before);
        let audited = f
            .ctx
            .state
            .read_lines(crate::audit::AUDIT_FILE, None)
            .unwrap()
            .iter()
            .filter(|line| line.contains("team_sync_poll"))
            .count();
        assert_eq!(audited, 1);
        restore();
        f.team.poll().unwrap();
        assert_eq!(sync_interval(&f), 31);
        let sent = commits();
        assert_eq!(sent.len(), before + 1);
        assert_eq!(
            sent[before]["commit"]["ops"][0]["sync_interval_seconds"],
            31
        );
        f.team.poll().unwrap();
        assert_eq!(commits().len(), before + 1);
    }

    /// Issue #51: a refold that fails after a fact arrives -- here a member's
    /// removal -- is retried by the poll as well, so the removal reaches the
    /// document once a refold succeeds instead of waiting for the next commit.
    /// The fact is audited as applied when it arrives all the same.
    #[test]
    fn a_failed_refold_after_a_removal_fact_is_retried() {
        let f = retrying_refolds_at_once();
        let peer = f.peer_key.fingerprint().unwrap();
        f.team.poll().unwrap();
        let active = || f.team.is_active_member(&f.env_id, &peer);
        assert!(active());
        let fact = sign_fact(
            &f.peer_key,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":peer}),
            "10000-0000",
        )
        .unwrap();
        let restore = fail_refolds(&f);
        let received = f.team.handle_fact(
            &f.env_id,
            &f.session,
            &json!({"type":"FACT","fact":fact.to_dict()}),
        );
        assert_eq!(received.unwrap_err().reason, "state_corrupt");
        assert_eq!(fact_audits(&f, "team_fact_apply"), 1);
        for _ in 0..3 {
            assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        }
        assert!(active());
        restore();
        f.team.poll().unwrap();
        assert!(!active());
        assert_eq!(fact_audits(&f, "team_fact_apply"), 1);
    }

    /// While the refold after a removal fails, the document still lists the
    /// removed device as active, but its stored removal fact refuses it all
    /// the same: no handshake with it is accepted, a PEERS message does not
    /// make it a dial candidate again, and the poll does not dial it.
    #[test]
    fn a_removal_fact_refuses_the_device_while_its_refold_fails() {
        let f = retrying_refolds_at_once();
        let peer = f.peer_key.fingerprint().unwrap();
        f.team.poll().unwrap();
        assert!(f.team.membership(&f.env_id, &peer).is_some());
        let restore = fail_refolds(&f);
        let fact = sign_fact(
            &f.peer_key,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":peer}),
            "10000-0000",
        )
        .unwrap();
        let received = f.team.handle_fact(
            &f.env_id,
            &f.session,
            &json!({"type":"FACT","fact":fact.to_dict()}),
        );
        assert_eq!(received.unwrap_err().reason, "state_corrupt");
        assert_eq!(
            f.team.document(&f.env_id).unwrap()["members"][&peer]["status"],
            "active"
        );
        assert!(f.team.membership(&f.env_id, &peer).is_none());
        // What the document lists, as `team join` and callers expect.
        assert!(f.team.is_active_member(&f.env_id, &peer));
        let address = "127.0.0.1:9";
        let mut peers = Map::new();
        peers.insert(peer.clone(), json!([address]));
        f.team
            .handle_peers(&f.env_id, &json!({"type":"PEERS","peers":peers}));
        let candidates = |f: &OwnerWithAdminPeer| {
            f.team.envs.lock().unwrap()[&f.env_id]
                .candidate_addresses
                .get(&peer)
                .cloned()
        };
        assert_eq!(candidates(&f), None);
        // As if it had been learned before the removal.
        f.team
            .envs
            .lock()
            .unwrap()
            .get_mut(&f.env_id)
            .unwrap()
            .candidate_addresses
            .entry(peer.clone())
            .or_default()
            .insert(address.into());
        let sent = f.recorder.sent.lock().unwrap().len();
        assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        assert_eq!(f.recorder.sent.lock().unwrap().len(), sent);
        {
            // Not dialed at all: a dial would get the peer's session from
            // the stub transport, store the address and close the session
            // it may not accept.
            let envs = f.team.envs.lock().unwrap();
            let env = &envs[&f.env_id];
            assert!(!env.sessions.contains_key(&peer));
            assert!(!env.dial_pending.contains_key(&peer));
            assert!(!env.next_attempt.contains_key(&peer));
        }
        assert!(!f.session.is_closed());
        let persisted = f
            .ctx
            .state
            .read_json(&format!("team/{}/peers.json", f.env_id), json!({}))
            .unwrap();
        assert!(persisted.get(&peer).is_none(), "{persisted}");
        restore();
        f.team.poll().unwrap();
        assert!(f.team.membership(&f.env_id, &peer).is_none());
    }

    /// A handshake that passed the membership check before the device's
    /// removal fact was stored is not accepted as a session afterwards.
    #[test]
    fn a_session_whose_handshake_preceded_a_removal_fact_is_refused() {
        let f = owner_with_admin_peer();
        let peer = f.peer_key.fingerprint().unwrap();
        f.team.poll().unwrap();
        assert!(f.team.membership(&f.env_id, &peer).is_some());
        let fact = sign_fact(
            &f.peer_key,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":peer}),
            "10000-0000",
        )
        .unwrap();
        f.team
            .handle_fact(
                &f.env_id,
                &f.session,
                &json!({"type":"FACT","fact":fact.to_dict()}),
            )
            .unwrap();
        // As if it had also consumed a fresh invitation.
        f.team
            .envs
            .lock()
            .unwrap()
            .get_mut(&f.env_id)
            .unwrap()
            .pending_invites
            .insert(peer.clone(), ("user".into(), "bob".into()));
        let late = recording_session(f.peer_key.record().unwrap(), &f.env_id);
        assert!(!f.team.accept_session(&f.env_id, late.clone(), true));
        assert!(late.is_closed());
        {
            let envs = f.team.envs.lock().unwrap();
            let env = &envs[&f.env_id];
            assert!(!env.sessions.contains_key(&peer));
            assert!(!env.pending_invites.contains_key(&peer));
        }
        let refused: Vec<Value> = f
            .ctx
            .audit
            .iter_records()
            .unwrap()
            .into_iter()
            .filter(|r| r["event"] == "team_handshake_failed")
            .collect();
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(refused[0]["reason"], "not_member");
        assert_eq!(refused[0]["fingerprint"], json!(peer));
    }

    /// Issue #51: an environment whose first refold fails as it is
    /// registered is retried by the poll, which fails until a refold
    /// succeeds instead of reporting success with an empty document.
    #[test]
    fn an_environment_whose_first_refold_fails_is_retried() {
        let f = retrying_refolds_at_once();
        let late = another_environment(&f, "late", false);
        let restore = fail_refolds(&f);
        assert_eq!(f.team.discover().unwrap_err().reason, "state_corrupt");
        assert!(f.team.known_envs().contains(&late));
        assert!(f.team.document(&late).unwrap().is_null());
        for _ in 0..3 {
            assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        }
        restore();
        f.team.poll().unwrap();
        assert!(f.team.document(&late).unwrap()["members"].is_object());
    }

    /// Issue #51: after its first retry a refold that keeps failing is
    /// retried only as `team_refold_retry_backoff` allows, the wait doubling
    /// up to the maximum; until then the poll reports the failure, and its
    /// pickups and releases do not refold.
    #[test]
    fn a_failing_refold_is_retried_with_backoff() {
        let f = owner_with_admin_peer_configured(Config {
            team_refold_retry_backoff: (1000.0, 4000.0),
            ..Config::default()
        });
        f.team.poll().unwrap();
        crate::team::membership::author_commit(
            &f.ctx,
            None,
            &f.env_id,
            vec![json!({"op":"settings.update","sync_interval_seconds":31})],
        )
        .unwrap();
        let restore = fail_refolds(&f);
        let backoff = || {
            let mut envs = f.team.envs.lock().unwrap();
            let failure = envs
                .get_mut(&f.env_id)
                .unwrap()
                .refold_failure
                .as_mut()
                .unwrap();
            let backoff = failure.backoff;
            // As if the wait were over.
            failure.retry_at = failure.retry_at.map(|_| Instant::now());
            backoff
        };
        // The pickup's refold fails; the first retry is the next tick.
        assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        let mut waits = Vec::new();
        for _ in 0..3 {
            waits.push(backoff().as_secs());
            assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        }
        assert_eq!(waits, [1000, 2000, 4000]);
        assert_eq!(backoff().as_secs(), 4000);
        // Due again, but the retry now waits 4000 seconds.
        assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        restore();
        // Not yet due: nothing refolds, not even for a released commit.
        let store = CommitStore::new(f.ctx.state, &f.env_id);
        store
            .defer(&settings_commit(
                &f.peer_key,
                &f.env_id,
                1,
                commit::now_ms() - 2000,
            ))
            .unwrap();
        let refolds = f.team.refolds_run.load(Ordering::SeqCst);
        assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        assert_eq!(f.team.refolds_run.load(Ordering::SeqCst), refolds);
        assert!(store.deferred_commits().unwrap().is_empty());
        assert_ne!(sync_interval(&f), 31);
        backoff();
        f.team.poll().unwrap();
        assert_eq!(sync_interval(&f), 31);
        assert!(
            f.team.envs.lock().unwrap()[&f.env_id]
                .refold_failure
                .is_none()
        );
    }

    /// Issue #52: the poll releases deferred commits with receipt's checks,
    /// audited in this node's log.
    #[test]
    fn the_poll_rejects_a_released_commit_out_of_its_authors_hlc_order() {
        let f = owner_with_admin_peer();
        f.team.poll().unwrap();
        let peer = f.peer_key.fingerprint().unwrap();
        let store = CommitStore::new(f.ctx.state, &f.env_id);
        let now = commit::now_ms();
        store
            .defer(&settings_commit(&f.peer_key, &f.env_id, 1, now - 2000))
            .unwrap();
        store
            .defer(&settings_commit(&f.peer_key, &f.env_id, 2, now - 3000))
            .unwrap();
        f.team.poll().unwrap();
        assert_eq!(store.last_seq(&peer).unwrap(), PyInt::from(1));
        assert!(store.deferred_commits().unwrap().is_empty());
        let rejected: Vec<Value> = f
            .ctx
            .audit
            .iter_records()
            .unwrap()
            .into_iter()
            .filter(|record| record["event"] == "team_commit_rejected")
            .collect();
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0]["reason"], "team_hlc_not_monotone");
        assert_eq!(rejected[0]["fingerprint"], peer);
    }

    /// Issue #51: a refold that keeps failing -- as a stored commit that no
    /// refold can derive makes it -- holds up no other step of the poll, nor
    /// its sync. Each poll reports the failure, and still sends its VECTOR,
    /// delivers the queued incident and releases the deferred commit that is
    /// due; only the local commit picked up meanwhile waits for a refold that
    /// succeeds.
    #[test]
    fn a_failing_refold_holds_up_no_other_step_or_the_sync() {
        let f = owner_with_admin_peer_configured(Config {
            team_refold_retry_backoff: (0.0, 0.0),
            team_sync_interval_seconds: Some(0.0),
            ..Config::default()
        });
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        f.team.poll().unwrap();
        let incident = sign_fact(
            &f.team.device,
            &f.env_id,
            "incident",
            json!({"incident_id":"0123456789abcdef"}),
            "10000-0000",
        )
        .unwrap();
        f.team
            .envs
            .lock()
            .unwrap()
            .get_mut(&f.env_id)
            .unwrap()
            .incident_outbox
            .insert(incident.hash().unwrap(), incident);
        crate::team::membership::author_commit(
            &f.ctx,
            None,
            &f.env_id,
            vec![json!({"op":"settings.update","sync_interval_seconds":31})],
        )
        .unwrap();
        let store = CommitStore::new(f.ctx.state, &f.env_id);
        store
            .defer(&settings_commit(
                &f.peer_key,
                &f.env_id,
                1,
                commit::now_ms() - 2000,
            ))
            .unwrap();
        let restore = fail_refolds(&f);
        let sent = |kind: &str| sent_of_type(&f.recorder, kind).len();
        let (vectors, commits) = (sent("VECTOR"), sent("COMMIT"));
        for _ in 0..3 {
            assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        }
        assert_eq!(sent("VECTOR"), vectors + 3);
        assert_eq!(sent("INCIDENT"), 1);
        assert!(store.deferred_commits().unwrap().is_empty());
        let peer = f.peer_key.fingerprint().unwrap();
        assert_eq!(store.last_seq(&peer).unwrap(), PyInt::from(1));
        assert_eq!(sent("COMMIT"), commits);
        restore();
        f.team.poll().unwrap();
        assert_eq!(sync_interval(&f), 31);
        // The local commit and the released one.
        assert_eq!(sent("COMMIT"), commits + 2);
    }

    /// Issue #51: a fact is announced -- audited as applied, relayed and, for
    /// a removal, sent to the removed device -- as it is stored, also when
    /// that refold fails; the poll's retry folds it in. Here both local
    /// paths: a fact this node publishes, and one another process wrote.
    #[test]
    fn a_fact_is_announced_although_its_refold_failed() {
        let f = retrying_refolds_at_once();
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        f.team.poll().unwrap();
        let announced = || {
            (
                fact_audits(&f, "team_fact_apply"),
                sent_of_type(&f.recorder, "FACT").len(),
            )
        };
        let restore = fail_refolds(&f);
        let published = f.team.publish_fact(
            &f.env_id,
            "connection_disabled",
            json!({"connection_id":"synthetic-one"}),
        );
        assert_eq!(published.unwrap_err().reason, "state_corrupt");
        assert_eq!(announced(), (1, 1));
        restore();
        f.team.poll().unwrap();
        let restore = fail_refolds(&f);
        let written = f
            .team
            .sign_authorized_fact(
                &f.env_id,
                "connection_disabled",
                json!({"connection_id":"synthetic-two"}),
            )
            .unwrap();
        f.ctx
            .state
            .append_line(
                &format!("team/{}/facts.jsonl", f.env_id),
                &pyjson::dumps(&written.to_dict(), DumpOptions::compact_sorted()).unwrap(),
            )
            .unwrap();
        assert_eq!(f.team.poll().unwrap_err().reason, "state_corrupt");
        assert_eq!(announced(), (2, 2));
        restore();
        f.team.poll().unwrap();
        assert_eq!(announced(), (2, 2));
    }

    /// A VECTOR answer the peer's removal interrupts stops there and still
    /// audits the commits it sent.
    #[test]
    fn an_interrupted_answer_audits_what_it_sent() {
        let f = owner_with_admin_peer();
        let peer = f.peer_key.fingerprint().unwrap();
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        let stored = CommitStore::new(f.ctx.state, &f.env_id)
            .all_commits()
            .unwrap()
            .len();
        assert!(stored > 1, "the answer needs more than one commit");
        let team = f.team.clone();
        let (env_id, removed) = (f.env_id.clone(), peer.clone());
        *f.recorder.on_first_send.lock().unwrap() =
            Some(Box::new(move || team.drain_removed(&env_id, &removed)));
        f.team
            .handle_vector(&f.env_id, &f.session, &json!({"type":"VECTOR","vector":{}}))
            .unwrap();
        assert_eq!(f.recorder.sent.lock().unwrap().len(), 1);
        let audited: Vec<Value> = f
            .ctx
            .audit
            .tail(50)
            .unwrap()
            .into_iter()
            .filter(|r| r["event"] == "team_sync_vector")
            .collect();
        assert_eq!(audited.len(), 1, "{audited:?}");
        assert_eq!(audited[0]["commits"], json!(1));
    }

    /// Incidents queued for an admin stop as soon as it drains.
    #[test]
    fn incident_retry_stops_once_the_admin_drains() {
        let f = owner_with_admin_peer();
        let peer = f.peer_key.fingerprint().unwrap();
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        for n in 0..2 {
            let incident = sign_fact(
                &f.team.device,
                &f.env_id,
                "incident",
                json!({"incident_id": format!("0123456789abcde{n}")}),
                &format!("1000{n}-0000"),
            )
            .unwrap();
            f.team
                .envs
                .lock()
                .unwrap()
                .get_mut(&f.env_id)
                .unwrap()
                .incident_outbox
                .insert(incident.hash().unwrap(), incident);
        }
        let team = f.team.clone();
        let (env_id, removed) = (f.env_id.clone(), peer.clone());
        *f.recorder.on_first_send.lock().unwrap() =
            Some(Box::new(move || team.drain_removed(&env_id, &removed)));
        f.team.retry_pending_incidents_to(&f.env_id, &f.session);
        assert_eq!(sent_of_type(&f.recorder, "INCIDENT").len(), 1);
    }

    /// A joiner removed while its held frames are being sent gets none of
    /// the rest.
    #[test]
    fn a_joiner_removed_mid_batch_gets_none_of_the_rest() {
        let f = owner_with_admin_peer();
        let peer = f.peer_key.fingerprint().unwrap();
        f.team
            .envs
            .lock()
            .unwrap()
            .get_mut(&f.env_id)
            .unwrap()
            .pending_invites
            .insert(peer.clone(), ("admin".into(), "bob".into()));
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        for seq in 0..3 {
            let live = settings_commit(&f.team.device, &f.env_id, 90 + seq, commit::now_ms() + 1);
            f.team.broadcast(
                &f.env_id,
                &json!({"type":"COMMIT","commit":live.to_dict()}),
                None,
            );
        }
        let vector = json!(CommitStore::new(f.ctx.state, &f.env_id).vector().unwrap());
        let team = f.team.clone();
        let (env_id, removed) = (f.env_id.clone(), peer.clone());
        *f.recorder.on_first_send.lock().unwrap() =
            Some(Box::new(move || team.drain_removed(&env_id, &removed)));
        f.team
            .handle_vector(
                &f.env_id,
                &f.session,
                &json!({"type":"VECTOR","vector":vector}),
            )
            .unwrap();
        assert_eq!(f.recorder.sent.lock().unwrap().len(), 1);
        let env = &f.team.envs.lock().unwrap()[&f.env_id];
        assert!(env.catching_up.is_empty() && env.held.is_empty());
    }

    /// Issue #28: a commit whose author's admission is deferred here (its
    /// HLC is too far ahead) waits for the deferral instead of being
    /// quarantined once its sender has been asked again.
    #[test]
    fn early_commits_wait_for_a_deferred_admission() {
        let f = owner_with_admin_peer();
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        let store = CommitStore::new(f.ctx.state, &f.env_id);
        let owner = f.team.device.fingerprint().unwrap();
        let newcomer = DeviceKey::generate();
        let ahead = commit::now_ms() + 3_600_000;
        let add = commit::sign_commit(
            &f.team.device,
            &f.env_id,
            &store.last_seq(&owner).unwrap() + 1,
            &format!("{ahead}-0000"),
            &BTreeMap::new(),
            vec![json!({"op":"member.add","device":newcomer.record().unwrap().to_dict(),"name":"dan","role":"admin"})],
        )
        .unwrap();
        assert_eq!(
            commit::receive_commit(&store, &add, commit::now_ms(), None).unwrap(),
            "deferred"
        );
        let theirs = settings_commit(&newcomer, &f.env_id, 1, ahead + 1);
        let deliver = || {
            f.team
                .handle_commit(
                    &f.env_id,
                    &f.session,
                    &json!({"type":"COMMIT","commit":theirs.to_dict()}),
                )
                .unwrap()
        };
        deliver();
        f.team
            .send_due_vectors(&f.env_id, Instant::now() + Duration::from_secs(2));
        assert!(
            sent_of_type(&f.recorder, "VECTOR").is_empty(),
            "what waits on deferred/ is not asked for"
        );
        // A periodic VECTOR goes out meanwhile: the repeat still waits.
        f.team.send_vector(&f.env_id, &f.session);
        deliver();
        assert!(quarantined(&f.ctx, &f.env_id).is_empty());
        assert!(
            f.team.envs.lock().unwrap()[&f.env_id].early_commits
                [&f.peer_key.fingerprint().unwrap()]
                .contains_key(&theirs.hash().unwrap())
        );
    }

    /// A joiner's hold ends with its session: a replacement session starts
    /// from its own VECTOR exchange, and nothing held is sent on it.
    #[test]
    fn a_replaced_or_dropped_session_takes_its_hold_along() {
        let f = owner_with_admin_peer();
        let peer = f.peer_key.fingerprint().unwrap();
        let hold = |team: &TeamSync| {
            let mut envs = team.envs.lock().unwrap();
            let env = envs.get_mut(&f.env_id).unwrap();
            env.pending_invites
                .insert(peer.clone(), ("admin".into(), "bob".into()));
        };
        hold(&f.team);
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        f.team
            .broadcast(&f.env_id, &json!({"type":"COMMIT","commit":{}}), None);
        assert_eq!(f.team.envs.lock().unwrap()[&f.env_id].held[&peer].len(), 1);
        let replacement = Arc::new(RecordingSession {
            peer: f.peer_key.record().unwrap(),
            env_id: f.env_id.clone(),
            sent: Mutex::new(Vec::new()),
            on_first_send: Mutex::new(None),
            closed: AtomicBool::new(false),
            created: Instant::now(),
        });
        let replacement_session: Arc<dyn Session> = replacement.clone();
        let inbound = f.team.device.fingerprint().unwrap() > peer;
        f.team
            .envs
            .lock()
            .unwrap()
            .get_mut(&f.env_id)
            .unwrap()
            .pending_invites
            .clear();
        assert!(
            f.team
                .accept_session(&f.env_id, replacement_session.clone(), inbound)
        );
        {
            let env = &f.team.envs.lock().unwrap()[&f.env_id];
            assert!(env.catching_up.is_empty() && env.held.is_empty());
        }
        f.team
            .handle_vector(
                &f.env_id,
                &replacement_session,
                &json!({"type":"VECTOR","vector":{}}),
            )
            .unwrap();
        assert!(
            sent_of_type(&replacement, "COMMIT")
                .iter()
                .all(|m| m["commit"] != json!({}))
        );

        hold(&f.team);
        f.team.drop_session(&f.env_id, &peer, None);
        let third: Arc<dyn Session> = Arc::new(RecordingSession {
            peer: f.peer_key.record().unwrap(),
            env_id: f.env_id.clone(),
            sent: Mutex::new(Vec::new()),
            on_first_send: Mutex::new(None),
            closed: AtomicBool::new(false),
            created: Instant::now(),
        });
        assert!(f.team.accept_session(&f.env_id, third, true));
        f.team
            .broadcast(&f.env_id, &json!({"type":"COMMIT","commit":{}}), None);
        f.team.drop_session(&f.env_id, &peer, None);
        let env = &f.team.envs.lock().unwrap()[&f.env_id];
        assert!(env.catching_up.is_empty() && env.held.is_empty());
    }

    /// Issue #28: a commit that arrives ahead of its history is not
    /// quarantined; the poll loop asks the sender for the range (at most once
    /// a second, and only once no commit is being accepted), and the commit is
    /// accepted once it arrives in order. Sent early again after that request
    /// -- the sender no longer has the history -- it is quarantined as before.
    #[test]
    fn early_live_commits_wait_for_their_history() {
        let f = owner_with_admin_peer();
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        let peer = f.peer_key.fingerprint().unwrap();
        let wall = commit::now_ms();
        let first = settings_commit(&f.peer_key, &f.env_id, 1, wall + 1);
        let second = settings_commit(&f.peer_key, &f.env_id, 2, wall + 2);
        let deliver = |c: &Commit| {
            f.team
                .handle_commit(
                    &f.env_id,
                    &f.session,
                    &json!({"type":"COMMIT","commit":c.to_dict()}),
                )
                .unwrap()
        };
        let vectors = || sent_of_type(&f.recorder, "VECTOR").len();
        // The due VECTOR goes out on a poll tick, unless one went to this
        // peer less than a second ago or a commit was just accepted.
        let tick = |after: Duration| f.team.send_due_vectors(&f.env_id, Instant::now() + after);
        deliver(&second);
        assert!(quarantined(&f.ctx, &f.env_id).is_empty());
        assert_eq!(vectors(), 0);
        f.team
            .envs
            .lock()
            .unwrap()
            .get_mut(&f.env_id)
            .unwrap()
            .last_accepted = Some(Instant::now());
        tick(Duration::ZERO);
        assert_eq!(vectors(), 0);
        tick(Duration::from_secs(2));
        assert_eq!(vectors(), 1);
        tick(Duration::from_secs(2));
        assert_eq!(vectors(), 1);
        deliver(&first);
        deliver(&second);
        let store = CommitStore::new(f.ctx.state, &f.env_id);
        assert_eq!(
            store.last_seq(&f.peer_key.fingerprint().unwrap()).unwrap(),
            PyInt::from(2)
        );
        assert!(quarantined(&f.ctx, &f.env_id).is_empty());
        assert!(
            f.team.envs.lock().unwrap()[&f.env_id]
                .early_commits
                .is_empty()
        );

        // An author this store has never admitted: within a second of the
        // last request nothing more is asked, and a repeat before any new
        // request still waits.
        let stranger = DeviceKey::generate();
        let unknown = settings_commit(&stranger, &f.env_id, 1, wall + 3);
        deliver(&unknown);
        deliver(&unknown);
        {
            // Quiet, and asked just now: only the one-second limit holds the
            // request back, however long the deliveries above took.
            let mut envs = f.team.envs.lock().unwrap();
            let env = envs.get_mut(&f.env_id).unwrap();
            env.last_accepted = None;
            env.last_vector_sent.insert(peer.clone(), Instant::now());
        }
        tick(Duration::ZERO);
        assert_eq!(vectors(), 1);
        assert!(quarantined(&f.ctx, &f.env_id).is_empty());

        // Asked again, the peer still sends a commit whose predecessor it no
        // longer has (compacted): quarantined as a sequence gap.
        let fourth = settings_commit(&f.peer_key, &f.env_id, 4, wall + 4);
        deliver(&fourth);
        tick(Duration::from_secs(2));
        assert_eq!(vectors(), 2);
        assert!(quarantined(&f.ctx, &f.env_id).is_empty());
        deliver(&fourth);
        let rejected = quarantined(&f.ctx, &f.env_id);
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert!(rejected[0].contains("-0000000004-"), "{rejected:?}");
        assert!(
            f.ctx
                .audit
                .tail(50)
                .unwrap()
                .iter()
                .any(|r| { r["event"] == "team_commit_rejected" && r["reason"] == "team_seq_gap" })
        );
        // The stranger's commit was asked for too: now it is quarantined.
        deliver(&unknown);
        assert_eq!(quarantined(&f.ctx, &f.env_id).len(), 2);
        assert!(
            f.team.envs.lock().unwrap()[&f.env_id]
                .early_commits
                .is_empty()
        );

        // One peer may keep only so many commits waiting; past that, an early
        // commit from it is quarantined at once.
        {
            let mut envs = f.team.envs.lock().unwrap();
            let waiting = envs
                .get_mut(&f.env_id)
                .unwrap()
                .early_commits
                .entry(peer.clone())
                .or_default();
            for n in 0..EARLY_COMMITS_PER_PEER {
                waiting.insert(format!("{n:064}"), Instant::now());
            }
        }
        let sixth = settings_commit(&f.peer_key, &f.env_id, 6, wall + 6);
        deliver(&sixth);
        assert_eq!(quarantined(&f.ctx, &f.env_id).len(), 3);
        // Dropping the session forgets what its peer left waiting.
        f.team.drop_session(&f.env_id, &peer, None);
        let env = &f.team.envs.lock().unwrap()[&f.env_id];
        assert!(env.early_commits.is_empty() && env.vector_due.is_empty());
    }

    #[test]
    fn retained_admin_role_does_not_authorize_a_removed_author() {
        let doc = json!({"owner":"owner","members":{"admin":{"role":"admin","status":"removed"}}});
        assert!(!fact_role_ok(
            &doc,
            "member_removed",
            "admin",
            &json!({"fingerprint":"third"})
        ));
        let mut active = doc.clone();
        active["members"]["admin"]["status"] = json!("active");
        assert!(fact_role_ok(
            &active,
            "member_removed",
            "admin",
            &json!({"fingerprint":"third"})
        ));
    }

    #[test]
    fn removed_admin_cannot_remove_unrelated_member_on_receive_replay_or_publish() {
        let f = owner_with_admin_peer();
        let peer = f.peer_key.fingerprint().unwrap();
        let third = DeviceKey::generate().record().unwrap();
        crate::team::membership::author_commit(
            &f.ctx,
            Some(&f.team),
            &f.env_id,
            vec![json!({"op":"member.add","device":third.to_dict(),"name":"third","role":"user"})],
        )
        .unwrap();
        f.team
            .publish_fact(&f.env_id, "member_removed", json!({"fingerprint":peer}))
            .unwrap();
        let bad = sign_fact(
            &f.peer_key,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":third.fingerprint()}),
            "10000-0000",
        )
        .unwrap();
        assert!(!f.team.validate_incoming_fact(&f.env_id, &bad).unwrap());
        f.ctx
            .state
            .append_line(
                &format!("team/{}/facts.jsonl", f.env_id),
                &crate::pyjson::dumps(&bad.to_dict(), crate::pyjson::DumpOptions::compact_sorted())
                    .unwrap(),
            )
            .unwrap();
        f.team.pick_up_local_facts(&f.env_id, false).unwrap();
        assert_eq!(
            f.team.document(&f.env_id).unwrap()["members"][third.fingerprint()]["status"],
            "active"
        );
        assert!(
            crate::team::membership::load_environment(&f.ctx, &f.env_id)
                .unwrap()
                .document["members"][third.fingerprint()]["status"]
                == "active"
        );
        assert!(
            !f.ctx
                .state
                .read_lines(&format!("team/{}/rejected_facts.jsonl", f.env_id), None)
                .unwrap()
                .is_empty()
        );
        let peer_team = TeamSync::new(
            f.ctx.clone(),
            Arc::new(StubTransport {
                session: f.session.clone(),
            }),
            f.peer_key,
        );
        peer_team.register_env(&f.env_id).unwrap();
        assert_eq!(
            peer_team.document(&f.env_id).unwrap()["members"][third.fingerprint()]["status"],
            "active"
        );
        assert!(
            peer_team
                .publish_fact(
                    &f.env_id,
                    "member_removed",
                    json!({"fingerprint":third.fingerprint()})
                )
                .is_err()
        );
    }

    #[test]
    fn idle_fact_pickup_skips_admission_and_concurrent_cli_appends_survive() {
        let f = owner_with_admin_peer();
        let ctx = f.ctx.clone();
        let env = f.env_id.clone();
        let writer = std::thread::spawn(move || {
            for i in 0..12 {
                crate::team::membership::author_fact(
                    &ctx,
                    None,
                    &env,
                    "connection_disabled",
                    json!({"connection_id":format!("gh{i}")}),
                )
                .unwrap();
            }
        });
        for _ in 0..12 {
            f.team.pick_up_local_facts(&f.env_id, false).unwrap();
        }
        writer.join().unwrap();
        f.team.pick_up_local_facts(&f.env_id, false).unwrap();
        assert_eq!(load_facts(&f.ctx, &f.env_id).unwrap().1.len(), 12);
        assert_eq!(
            f.team.envs.lock().unwrap()[&f.env_id]
                .facts
                .disabled_connections
                .len(),
            12
        );
        let loads = f.team.fact_pickup_loads.load(Ordering::SeqCst);
        for _ in 0..12 {
            f.team.pick_up_local_facts(&f.env_id, false).unwrap();
        }
        assert_eq!(f.team.fact_pickup_loads.load(Ordering::SeqCst), loads);
    }

    #[test]
    fn admission_observes_future_commits_and_send_waits_for_unlock() {
        let f = owner_with_admin_peer();
        assert!(f.team.accept_session(&f.env_id, f.session.clone(), true));
        let store = CommitStore::new(f.ctx.state, &f.env_id);
        let future = commit::sign_commit(
            &f.peer_key,
            &f.env_id,
            1,
            &format!("{}-0000", commit::now_ms() + 240_000),
            &store.vector().unwrap(),
            vec![json!({"op":"settings.update","sync_interval_seconds":42})],
        )
        .unwrap();
        assert_eq!(
            f.team.submit_commit(&f.env_id, &future).unwrap(),
            "accepted"
        );
        crate::team::membership::author_commit(
            &f.ctx,
            Some(&f.team),
            &f.env_id,
            vec![json!({"op":"settings.update","sync_interval_seconds":43})],
        )
        .unwrap();
        f.recorder.sent.lock().unwrap().clear();
        let before = 0;
        let joined = DeviceKey::generate().record().unwrap();
        let lock = f.ctx.state.lock().unwrap();
        f.team
            .admit_member(&f.env_id, &joined, "user", "invited")
            .unwrap();
        assert_eq!(f.recorder.sent.lock().unwrap().len(), before);
        assert_eq!(
            f.team.document(&f.env_id).unwrap()["members"][joined.fingerprint()]["status"],
            "active"
        );
        let owner = DeviceKey::load_or_create(f.ctx.state, f.ctx.kms)
            .unwrap()
            .fingerprint()
            .unwrap();
        let latest = store
            .all_commits()
            .unwrap()
            .into_iter()
            .filter(|c| c.author == owner)
            .max_by_key(|c| c.author_seq.clone())
            .unwrap();
        assert!(Hlc::parse(&latest.hlc).unwrap() > Hlc::parse(&future.hlc).unwrap());
        let state = f.ctx.state;
        *f.recorder.on_first_send.lock().unwrap() =
            Some(Box::new(move || assert!(!state.locked_by_current_thread())));
        drop(lock);
        f.team.flush_deferred_sends();
        assert!(f.recorder.sent.lock().unwrap().len() > before);
    }

    #[test]
    fn live_pickup_preserves_receipted_revocation_after_role_change() {
        let f = owner_with_admin_peer();
        let owner = DeviceKey::load_or_create(f.ctx.state, f.ctx.kms).unwrap();
        let peer = f.peer_key.fingerprint().unwrap();
        crate::team::membership::author_commit(
            &f.ctx,
            Some(&f.team),
            &f.env_id,
            vec![json!({"op":"owner.transfer","fingerprint":peer})],
        )
        .unwrap();
        let disable = Fact::from_dict(
            &crate::team::membership::author_fact(
                &f.ctx,
                None,
                &f.env_id,
                "connection_disabled",
                json!({"connection_id":"gh"}),
            )
            .unwrap(),
        )
        .unwrap();
        let store = CommitStore::new(f.ctx.state, &f.env_id);
        let demotion=commit::sign_commit(&f.peer_key,&f.env_id,1,&Hlc::new(0,0).tick(None),&store.vector().unwrap(),
            vec![json!({"op":"member.set_role","fingerprint":owner.fingerprint().unwrap(),"role":"user"})]).unwrap();
        assert_eq!(
            f.team.submit_commit(&f.env_id, &demotion).unwrap(),
            "accepted"
        );
        assert!(
            f.team.envs.lock().unwrap()[&f.env_id]
                .facts
                .disabled_connections
                .contains("gh")
        );
        f.team.pick_up_local_facts(&f.env_id, false).unwrap();
        assert!(
            f.team.envs.lock().unwrap()[&f.env_id]
                .facts
                .disabled_connections
                .contains("gh")
        );
        assert!(
            load_facts(&f.ctx, &f.env_id)
                .unwrap()
                .1
                .contains(&disable.hash().unwrap())
        );
    }

    #[test]
    fn historical_revocations_survive_unreceipted_author_role_changes() {
        for op in ["member.set_role", "member.remove"] {
            let f = owner_with_admin_peer();
            let fp = f.peer_key.fingerprint().unwrap();
            let disable = sign_fact(
                &f.peer_key,
                &f.env_id,
                "connection_disabled",
                json!({"connection_id":"gh"}),
                "10000-0000",
            )
            .unwrap();
            let revoke = sign_fact(
                &f.peer_key,
                &f.env_id,
                "secret_version_revoked",
                json!({"secret_id":"synthetic", "version_id":"11111111111111111111111111111111"}),
                "10001-0000",
            )
            .unwrap();
            for fact in [&disable, &revoke] {
                f.ctx
                    .state
                    .append_line(
                        &format!("team/{}/facts.jsonl", f.env_id),
                        &pyjson::dumps(&fact.to_dict(), DumpOptions::compact_sorted()).unwrap(),
                    )
                    .unwrap();
            }
            // Sign the role-change commit directly to model a legacy store
            // without causing a new-version loader to create admission receipts.
            let owner = DeviceKey::load_or_create(f.ctx.state, f.ctx.kms).unwrap();
            let store = CommitStore::new(f.ctx.state, &f.env_id);
            let mut change = json!({"op":op,"fingerprint":fp});
            if op == "member.set_role" {
                change["role"] = json!("user");
            }
            let commit = commit::sign_commit(
                &owner,
                &f.env_id,
                &store.last_seq(&owner.fingerprint().unwrap()).unwrap() + 1,
                &Hlc::new(0, 0).tick(None),
                &store.vector().unwrap(),
                vec![change],
            )
            .unwrap();
            assert_eq!(
                commit::receive_commit(&store, &commit, commit::now_ms(), None).unwrap(),
                "accepted"
            );
            let (facts, hashes, _) = load_facts(&f.ctx, &f.env_id).unwrap();
            assert!(hashes.contains(&disable.hash().unwrap()));
            assert!(hashes.contains(&revoke.hash().unwrap()));
            assert!(facts.disabled_connections.contains("gh"));
            assert_eq!(load_facts(&f.ctx, &f.env_id).unwrap().1, hashes);
        }
    }

    #[test]
    fn removal_repair_sorts_after_a_received_future_rotation() {
        let f = owner_with_admin_peer();
        let owner = DeviceKey::load_or_create(f.ctx.state, f.ctx.kms).unwrap();
        let generation = "44444444444444444444444444444444";
        let mut wraps = Map::new();
        for record in [owner.record().unwrap(), f.peer_key.record().unwrap()] {
            wraps.insert(
                record.fingerprint(),
                crate::team::envelope::wrap_dek(&[9u8; 32], &f.env_id, generation, &record)
                    .unwrap(),
            );
        }
        let store = CommitStore::new(f.ctx.state, &f.env_id);
        let future = commit::sign_commit(
            &f.peer_key,
            &f.env_id,
            1,
            &format!("{}-0000", commit::now_ms() + 240_000),
            &store.vector().unwrap(),
            vec![json!({"op":"dek.rotate","generation_id":generation,"wraps":wraps})],
        )
        .unwrap();
        assert_eq!(
            f.team.submit_commit(&f.env_id, &future).unwrap(),
            "accepted"
        );
        let stale = valid_secret_version(&f, &json!(generation), b"synthetic-future-clock");
        let removal = sign_fact(
            &f.peer_key,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":f.peer_key.fingerprint().unwrap()}),
            "10000-0000",
        )
        .unwrap();
        f.team
            .handle_fact(
                &f.env_id,
                &f.session,
                &json!({"type":"FACT","fact":removal.to_dict()}),
            )
            .unwrap();
        assert_eq!(
            crate::team::membership::author_commit(&f.ctx, Some(&f.team), &f.env_id, vec![stale])
                .unwrap_err()
                .reason,
            "team_rekey_pending"
        );
        assert_ne!(
            f.team.document(&f.env_id).unwrap()["dek"]["current"],
            generation
        );
        let latest = store
            .all_commits()
            .unwrap()
            .into_iter()
            .filter(|c| c.author == owner.fingerprint().unwrap())
            .max_by_key(|c| c.author_seq.clone())
            .unwrap();
        assert!(Hlc::parse(&latest.hlc).unwrap() > Hlc::parse(&future.hlc).unwrap());
    }

    #[test]
    fn commit_removal_blocks_writes_under_old_wrapped_generation() {
        let f = owner_with_admin_peer();
        let owner = DeviceKey::load_or_create(f.ctx.state, f.ctx.kms).unwrap();
        let generation = "55555555555555555555555555555555";
        let mut wraps = Map::new();
        for record in [owner.record().unwrap(), f.peer_key.record().unwrap()] {
            wraps.insert(
                record.fingerprint(),
                crate::team::envelope::wrap_dek(&[10u8; 32], &f.env_id, generation, &record)
                    .unwrap(),
            );
        }
        crate::team::membership::author_commit(
            &f.ctx,
            Some(&f.team),
            &f.env_id,
            vec![json!({"op":"dek.rotate","generation_id":generation,"wraps":wraps})],
        )
        .unwrap();
        let current = f.team.document(&f.env_id).unwrap()["dek"]["current"].clone();
        let stale = valid_secret_version(&f, &current, b"synthetic-commit-removal");
        crate::team::membership::author_commit(
            &f.ctx,
            Some(&f.team),
            &f.env_id,
            vec![json!({"op":"member.remove","fingerprint":f.peer_key.fingerprint().unwrap()})],
        )
        .unwrap();
        assert_eq!(
            crate::team::membership::author_commit(&f.ctx, Some(&f.team), &f.env_id, vec![stale])
                .unwrap_err()
                .reason,
            "team_rekey_pending"
        );
    }

    #[test]
    fn stale_live_process_cannot_admit_after_standalone_removal() {
        let f = owner_with_admin_peer();
        let third = DeviceKey::generate().record().unwrap();
        crate::team::membership::author_commit(
            &f.ctx,
            Some(&f.team),
            &f.env_id,
            vec![json!({"op":"member.add","device":third.to_dict(),"name":"third","role":"user"})],
        )
        .unwrap();
        crate::team::membership::author_fact(
            &f.ctx,
            None,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":f.peer_key.fingerprint().unwrap()}),
        )
        .unwrap();
        let fact = sign_fact(
            &f.peer_key,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":third.fingerprint()}),
            "10000-0000",
        )
        .unwrap();
        f.team
            .handle_fact(
                &f.env_id,
                &f.session,
                &json!({"type":"FACT","fact":fact.to_dict()}),
            )
            .unwrap();
        assert!(
            !load_facts(&f.ctx, &f.env_id)
                .unwrap()
                .1
                .contains(&fact.hash().unwrap())
        );
        assert_eq!(
            crate::team::membership::load_environment(&f.ctx, &f.env_id)
                .unwrap()
                .document["members"][third.fingerprint()]["status"],
            "active"
        );
    }

    #[test]
    fn cold_loader_rejects_unadmitted_removed_admin_fact() {
        let f = owner_with_admin_peer();
        let third = DeviceKey::generate().record().unwrap();
        crate::team::membership::author_commit(
            &f.ctx,
            Some(&f.team),
            &f.env_id,
            vec![json!({"op":"member.add","device":third.to_dict(),"name":"third","role":"user"})],
        )
        .unwrap();
        f.team
            .publish_fact(
                &f.env_id,
                "member_removed",
                json!({"fingerprint":f.peer_key.fingerprint().unwrap()}),
            )
            .unwrap();
        let bad = sign_fact(
            &f.peer_key,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":third.fingerprint()}),
            "10000-0000",
        )
        .unwrap();
        f.ctx
            .state
            .append_line(
                &format!("team/{}/facts.jsonl", f.env_id),
                &pyjson::dumps(&bad.to_dict(), DumpOptions::compact_sorted()).unwrap(),
            )
            .unwrap();
        // No poll or pickup: standalone loading is the first observer.
        assert_eq!(
            crate::team::membership::load_environment(&f.ctx, &f.env_id)
                .unwrap()
                .document["members"][third.fingerprint()]["status"],
            "active"
        );
        let fresh = TeamSync::new(
            f.ctx.clone(),
            Arc::new(StubTransport {
                session: f.session.clone(),
            }),
            DeviceKey::load_or_create(f.ctx.state, f.ctx.kms).unwrap(),
        );
        fresh.register_env(&f.env_id).unwrap();
        assert_eq!(
            fresh.document(&f.env_id).unwrap()["members"][third.fingerprint()]["status"],
            "active"
        );
        assert!(
            !load_facts(&f.ctx, &f.env_id)
                .unwrap()
                .1
                .contains(&bad.hash().unwrap())
        );
    }

    #[test]
    fn concurrent_rotations_cannot_leave_removed_device_in_current_wraps() {
        let f = owner_with_admin_peer();
        let v = DeviceKey::generate().record().unwrap();
        let w = DeviceKey::generate().record().unwrap();
        crate::team::membership::author_commit(
            &f.ctx,
            Some(&f.team),
            &f.env_id,
            vec![
                json!({"op":"member.add","device":v.to_dict(),"name":"v","role":"user"}),
                json!({"op":"member.add","device":w.to_dict(),"name":"w","role":"user"}),
            ],
        )
        .unwrap();
        let owner = DeviceKey::load_or_create(f.ctx.state, f.ctx.kms).unwrap();
        let fv = sign_fact(
            &owner,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":v.fingerprint()}),
            "10000-0000",
        )
        .unwrap();
        let fw = sign_fact(
            &f.peer_key,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":w.fingerprint()}),
            "10001-0000",
        )
        .unwrap();
        // Two independently authored rotations, each missing the other removal.
        // Deliver rotations first: fact and COMMIT transport order is independent.
        for (generation, fact, excluded) in [
            ("11111111111111111111111111111111", &fw, w.fingerprint()),
            ("22222222222222222222222222222222", &fv, v.fingerprint()),
        ] {
            let dek = [7u8; 32];
            let mut wraps = Map::new();
            for record in [
                owner.record().unwrap(),
                f.peer_key.record().unwrap(),
                v.clone(),
                w.clone(),
            ] {
                if record.fingerprint() != excluded {
                    wraps.insert(
                        record.fingerprint(),
                        crate::team::envelope::wrap_dek(&dek, &f.env_id, generation, &record)
                            .unwrap(),
                    );
                }
            }
            crate::team::membership::author_commit(&f.ctx, Some(&f.team), &f.env_id,
                vec![json!({"op":"dek.rotate","generation_id":generation,"wraps":wraps,"removal_fact_hash":fact.hash().unwrap()})]).unwrap();
        }
        for fact in [&fv, &fw] {
            f.team
                .handle_fact(
                    &f.env_id,
                    &f.session,
                    &json!({"type":"FACT","fact":fact.to_dict()}),
                )
                .unwrap();
        }
        let before = f.team.document(&f.env_id).unwrap()["dek"]["current"].clone();
        crate::team::membership::ensure_removal_rotations(&f.ctx, Some(&f.team), &f.env_id)
            .unwrap();
        let doc = f.team.document(&f.env_id).unwrap();
        assert_ne!(doc["dek"]["current"], before);
        let current = doc["dek"]["current"].as_str().unwrap();
        assert!(
            doc["dek"]["generations"][current]["wraps"]
                .get(v.fingerprint())
                .is_none()
        );
        assert!(
            doc["dek"]["generations"][current]["wraps"]
                .get(w.fingerprint())
                .is_none()
        );
        // A delayed rotation can arrive after both facts and their repairs.
        let generation = "33333333333333333333333333333333";
        let mut wraps = Map::new();
        for record in [
            owner.record().unwrap(),
            f.peer_key.record().unwrap(),
            w.clone(),
        ] {
            wraps.insert(
                record.fingerprint(),
                crate::team::envelope::wrap_dek(&[8u8; 32], &f.env_id, generation, &record)
                    .unwrap(),
            );
        }
        crate::team::membership::author_commit(&f.ctx, Some(&f.team), &f.env_id,
            vec![json!({"op":"dek.rotate","generation_id":generation,"wraps":wraps,"removal_fact_hash":fv.hash().unwrap()})]).unwrap();
        let unsafe_write = valid_secret_version(&f, &json!(generation), b"synthetic-late-rotation");
        assert_eq!(
            crate::team::membership::author_commit(
                &f.ctx,
                Some(&f.team),
                &f.env_id,
                vec![unsafe_write]
            )
            .unwrap_err()
            .reason,
            "team_rekey_pending"
        );
        let doc = f.team.document(&f.env_id).unwrap();
        let current = doc["dek"]["current"].as_str().unwrap();
        assert!(
            doc["dek"]["generations"][current]["wraps"]
                .get(w.fingerprint())
                .is_none()
        );
    }

    #[test]
    fn draining_admin_cannot_send_a_non_reciprocal_removal() {
        let f = owner_with_admin_peer();
        let peer = f.peer_key.fingerprint().unwrap();
        let third = DeviceKey::generate().record().unwrap();
        crate::team::membership::author_commit(
            &f.ctx,
            Some(&f.team),
            &f.env_id,
            vec![json!({"op":"member.add","device":third.to_dict(),"name":"third","role":"user"})],
        )
        .unwrap();
        let bad = sign_fact(
            &f.peer_key,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":third.fingerprint()}),
            "10000-0000",
        )
        .unwrap();
        assert!(f.team.validate_incoming_fact(&f.env_id, &bad).unwrap());
        {
            let mut envs = f.team.envs.lock().unwrap();
            let env = envs.get_mut(&f.env_id).unwrap();
            env.draining.insert(peer.clone(), Instant::now());
            env.removal_authors
                .insert(peer, HashSet::from([f.team.device.fingerprint().unwrap()]));
        }
        f.team
            .handle_message(
                &f.env_id,
                &f.session,
                &json!({"type":"FACT","fact":bad.to_dict()}),
            )
            .unwrap();
        assert!(
            !f.team.envs.lock().unwrap()[&f.env_id]
                .fact_hashes
                .contains(&bad.hash().unwrap())
        );
        assert_eq!(
            f.team.document(&f.env_id).unwrap()["members"][third.fingerprint()]["status"],
            "active"
        );
    }

    fn valid_secret_version(f: &OwnerWithAdminPeer, generation: &Value, value: &[u8]) -> Value {
        let doc = f.team.document(&f.env_id).unwrap();
        let device = DeviceKey::load_or_create(f.ctx.state, f.ctx.kms).unwrap();
        let gid = generation.as_str().unwrap();
        let wrap = &doc["dek"]["generations"][gid]["wraps"][device.fingerprint().unwrap()];
        let dek = crate::team::envelope::unwrap_dek(wrap, &f.env_id, gid, &device).unwrap();
        let ciphertext = crate::team::envelope::encrypt_secret(
            &dek,
            &f.env_id,
            "rekey-boundary",
            "0123456789abcdef",
            value,
        )
        .unwrap();
        json!({"op":"secret.put_version","secret_id":"rekey-boundary","kind":"api_key", "generation_id":generation,
            "version_id":"0123456789abcdef","ciphertext":ciphertext,"public":{}})
    }

    #[test]
    fn self_removal_rekeys_on_receipt_and_after_restart_without_repeat_rotation() {
        for receive in [true, false] {
            let f = owner_with_admin_peer();
            let peer = f.peer_key.fingerprint().unwrap();
            let before = f.team.document(&f.env_id).unwrap()["dek"]["current"].clone();
            let old_write = valid_secret_version(&f, &before, b"synthetic-old-generation");
            let fact = sign_fact(
                &f.peer_key,
                &f.env_id,
                "member_removed",
                json!({"fingerprint":peer}),
                "10000-0000",
            )
            .unwrap();
            if receive {
                f.team
                    .handle_fact(
                        &f.env_id,
                        &f.session,
                        &json!({"type":"FACT","fact":fact.to_dict()}),
                    )
                    .unwrap();
                let pending = crate::team::membership::author_commit(
                    &f.ctx,
                    Some(&f.team),
                    &f.env_id,
                    vec![old_write.clone()],
                );
                assert_eq!(pending.unwrap_err().reason, "team_rekey_pending");
            } else {
                assert!(f.team.validate_incoming_fact(&f.env_id, &fact).unwrap());
                f.team.store_fact(&f.env_id, &fact).unwrap();
                f.team.refold(&f.env_id).unwrap();
                let pending = crate::team::membership::author_commit(
                    &f.ctx,
                    None,
                    &f.env_id,
                    vec![old_write.clone()],
                );
                assert_eq!(pending.unwrap_err().reason, "team_rekey_pending");
                f.team.pick_up_local_commits(&f.env_id, false).unwrap();
            }
            let doc = f.team.document(&f.env_id).unwrap();
            let generation = doc["dek"]["current"].clone();
            assert_ne!(generation, before);
            let gid = generation.as_str().unwrap();
            assert_eq!(
                doc["dek"]["generations"][gid]["removal_fact_hash"],
                fact.hash().unwrap()
            );
            assert!(doc["dek"]["generations"][gid]["wraps"].get(&peer).is_none());
            let vector = CommitStore::new(f.ctx.state, &f.env_id).vector().unwrap();
            f.team.repair_member_removals(&f.env_id).unwrap();
            assert_eq!(
                CommitStore::new(f.ctx.state, &f.env_id).vector().unwrap(),
                vector
            );
            let result = crate::team::membership::author_commit(
                &f.ctx,
                Some(&f.team),
                &f.env_id,
                vec![old_write],
            );
            assert_eq!(result.unwrap_err().reason, "team_rekey_pending");
            let fresh = valid_secret_version(&f, &generation, b"synthetic-new-generation");
            crate::team::membership::author_commit(&f.ctx, Some(&f.team), &f.env_id, vec![fresh])
                .unwrap();
            assert_eq!(
                f.team.document(&f.env_id).unwrap()["secrets"]["rekey-boundary"]["versions"]["0123456789abcdef"]
                    ["generation"],
                generation
            );
        }
    }

    #[test]
    fn ordinary_admin_removal_also_blocks_stale_generation_writes() {
        let f = owner_with_admin_peer();
        let before = f.team.document(&f.env_id).unwrap()["dek"]["current"].clone();
        let stale = valid_secret_version(&f, &before, b"synthetic-pre-removal");
        crate::team::membership::remove_member(
            &f.ctx,
            Some(&f.team),
            &f.env_id,
            &f.peer_key.fingerprint().unwrap(),
        )
        .unwrap();
        let result =
            crate::team::membership::author_commit(&f.ctx, Some(&f.team), &f.env_id, vec![stale]);
        assert_eq!(result.unwrap_err().reason, "team_rekey_pending");
        let after = f.team.document(&f.env_id).unwrap()["dek"]["current"].clone();
        let fresh = valid_secret_version(&f, &after, b"synthetic-post-removal");
        crate::team::membership::author_commit(&f.ctx, Some(&f.team), &f.env_id, vec![fresh])
            .unwrap();
    }

    #[test]
    fn persistent_rekey_failure_does_not_stop_another_environment() {
        let f = owner_with_admin_peer();
        f.ctx.projects.create("other", &["dev"]).unwrap();
        let second = crate::team::membership::share_environment(
            &f.ctx,
            None,
            "other",
            "dev",
            "owner",
            "synthetic-admin",
        )
        .unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
        f.team.register_env(&second).unwrap();
        let peer = f.peer_key.fingerprint().unwrap();
        let fact = sign_fact(
            &f.peer_key,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":peer}),
            "10000-0000",
        )
        .unwrap();
        std::fs::create_dir(
            f.ctx
                .state
                .path
                .join(format!("team/{}/rotation_flags.json", f.env_id)),
        )
        .unwrap();
        f.team
            .handle_fact(
                &f.env_id,
                &f.session,
                &json!({"type":"FACT","fact":fact.to_dict()}),
            )
            .unwrap();
        crate::team::membership::author_commit(
            &f.ctx,
            None,
            &second,
            vec![json!({"op":"settings.update","sync_interval_seconds":42})],
        )
        .unwrap();
        f.team.poll().unwrap();
        assert_eq!(
            f.team.document(&second).unwrap()["settings"]["sync_interval_seconds"],
            42
        );
        assert!(
            !f.team.envs.lock().unwrap()[&f.env_id]
                .pending_removal_repairs
                .is_empty()
        );
        let events = f
            .ctx
            .state
            .read_lines(crate::audit::AUDIT_FILE, None)
            .unwrap();
        assert!(
            events
                .iter()
                .filter_map(|line| pyjson::loads(line).ok())
                .any(|event| event["event"] == "team_dek_rotate"
                    && event["reason"] == "team_rekey_repair_failed")
        );
    }

    #[test]
    fn received_ordinary_removal_rekeys_and_duplicate_confirmation_does_not_repeat_it() {
        let f = owner_with_admin_peer();
        let third_key = DeviceKey::generate();
        let third = third_key.record().unwrap();
        crate::team::membership::author_commit(
            &f.ctx,
            Some(&f.team),
            &f.env_id,
            vec![json!({"op":"member.add","device":third.to_dict(),"name":"third","role":"user"})],
        )
        .unwrap();
        let before = f.team.document(&f.env_id).unwrap()["dek"]["current"].clone();
        let stale = valid_secret_version(&f, &before, b"synthetic-pre-removal");
        let removal = sign_fact(
            &f.peer_key,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":third.fingerprint()}),
            "10000-0000",
        )
        .unwrap();
        f.team
            .handle_fact(
                &f.env_id,
                &f.session,
                &json!({"type":"FACT","fact":removal.to_dict()}),
            )
            .unwrap();

        let result =
            crate::team::membership::author_commit(&f.ctx, Some(&f.team), &f.env_id, vec![stale]);
        assert_eq!(result.unwrap_err().reason, "team_rekey_pending");
        assert_ne!(
            f.team.document(&f.env_id).unwrap()["dek"]["current"],
            before
        );
        let vector = CommitStore::new(f.ctx.state, &f.env_id).vector().unwrap();
        let confirmation = sign_fact(
            &third_key,
            &f.env_id,
            "member_removed",
            json!({"fingerprint":third.fingerprint()}),
            "10001-0000",
        )
        .unwrap();
        f.team
            .handle_fact(
                &f.env_id,
                &f.session,
                &json!({"type":"FACT","fact":confirmation.to_dict()}),
            )
            .unwrap();
        f.team.repair_member_removals(&f.env_id).unwrap();
        assert_eq!(
            CommitStore::new(f.ctx.state, &f.env_id).vector().unwrap(),
            vector
        );
    }

    /// Gap 1: `_relaxed_document` is cached by the store vector and cleared
    /// only by `_refold`, so a removed member's device record is resolved
    /// without re-folding the whole log per FACT/INCIDENT -- and the
    /// Rust-only offline fact replay folds at most once per pass, not once
    /// per replayed line.
    #[test]
    fn relaxed_document_is_cached_by_store_vector() {
        let OwnerWithAdminPeer {
            _root,
            ctx,
            env_id,
            peer_key,
            recorder,
            session,
            team,
        } = owner_with_admin_peer();
        let folds = || team.relaxed_folds.load(Ordering::SeqCst);
        assert_eq!(folds(), 0);
        let bad_fact = |i: u64| {
            let mut fact = sign_fact(
                &peer_key,
                &env_id,
                "connection_disabled",
                json!({"connection_id":format!("c{i}")}),
                &format!("{}-0000", 5000 + i),
            )
            .unwrap()
            .to_dict();
            fact["target"]["connection_id"] = json!("tampered");
            json!({"type":"FACT","fact":fact})
        };
        let incident = |i: u64| {
            let fact = sign_fact(
                &peer_key,
                &env_id,
                "incident",
                json!({"incident_id":format!("{i:016x}")}),
                &format!("{}-0000", 6000 + i),
            )
            .unwrap();
            json!({"type":"INCIDENT","fact":fact.to_dict()})
        };
        let mut counts = Vec::new();
        for i in 0..5 {
            team.handle_message(&env_id, &session, &bad_fact(i))
                .unwrap();
        }
        counts.push(folds());
        for i in 0..3 {
            team.handle_message(&env_id, &session, &incident(i))
                .unwrap();
        }
        counts.push(folds());
        // Another process's commit moves the store vector: a cache miss.
        crate::team::membership::author_commit(
            &ctx,
            None,
            &env_id,
            vec![json!({"op":"settings.update","sync_interval_seconds":7})],
        )
        .unwrap();
        team.handle_message(&env_id, &session, &bad_fact(10))
            .unwrap();
        counts.push(folds());
        team.handle_message(&env_id, &session, &bad_fact(11))
            .unwrap();
        counts.push(folds());
        // The pickup refolds, which clears the cache even at the same vector.
        team.poll().unwrap();
        team.handle_message(&env_id, &session, &bad_fact(12))
            .unwrap();
        counts.push(folds());
        let sent = recorder.sent.lock().unwrap().clone();
        let acks = sent.iter().filter(|m| m["type"] == "INCIDENT_ACK").count();
        let rejected = ctx
            .audit
            .tail(500)
            .unwrap()
            .iter()
            .filter(|r| r["event"] == "team_fact_rejected")
            .count();
        // The counts the Python prototype's `_relaxed_document` produced for
        // the same traffic.
        assert_eq!(
            json!({"counts":counts,"acks":acks,"rejected":rejected}),
            json!({"counts": [1, 1, 2, 2, 3], "acks": 3, "rejected": 8})
        );

        // Rust-only offline fact replay (DEVIATIONS.md): 64 lines, each
        // needing the author's device record.
        for i in 0..64u64 {
            let line = sign_fact(
                &peer_key,
                &env_id,
                "connection_disabled",
                json!({"connection_id":format!("r{i}")}),
                &format!("{}-0000", 7000 + i),
            )
            .unwrap()
            .to_dict()
            .to_string();
            ctx.state
                .append_line(&format!("team/{env_id}/facts.jsonl"), &line)
                .unwrap();
        }
        assert!(team.accept_session(&env_id, session.clone(), true));
        recorder.sent.lock().unwrap().clear();
        let warm = folds();
        team.send_fact_catchup(&env_id, &session).unwrap();
        let replayed = recorder.sent.lock().unwrap().len();
        assert!(replayed >= 60, "only {replayed} facts replayed");
        assert_eq!(folds(), warm, "a warm cache must not fold again");
        team.refold(&env_id).unwrap();
        team.send_fact_catchup(&env_id, &session).unwrap();
        assert!(recorder.sent.lock().unwrap().len() > replayed);
        assert_eq!(folds(), warm + 1, "one fold per replay pass, not per line");
    }

    /// A truthy non-dict `rotation_flags.json` (or a non-dict entry that a
    /// recommended id reads) raises in Python inside `_handle_incident`,
    /// after the incident record is written and before the ACK; Rust returns
    /// `state_corrupt` from the same step (so the receive loop drops the
    /// session exactly as Python's escaping exception does) instead of
    /// panicking on `Value` index assignment.
    #[test]
    fn corrupt_rotation_flags_fail_the_incident() {
        let fixture = owner_with_admin_peer();
        let (ctx, env_id, team) = (&fixture.ctx, &fixture.env_id, &fixture.team);
        let path = format!("team/{env_id}/rotation_flags.json");
        let cases = [
            (json!(["x"]), json!({"secret_ids_mandatory":["s1"]})),
            (json!(["x"]), json!({})),
            (
                json!({"s2":"bad"}),
                json!({"secret_ids_recommended":["s2"]}),
            ),
            (json!({"s2":"bad"}), json!({"secret_ids_mandatory":["s2"]})),
            (json!({"s2":null}), json!({"secret_ids_recommended":["s2"]})),
            (json!(0), json!({"secret_ids_recommended":["s3"]})),
            (
                json!({"s4":{"reason":"rotation_required","flagged_at":"T0"}}),
                json!({"secret_ids_recommended":["s4","s5"],"secret_ids_mandatory":["s6"]}),
            ),
        ];
        let peer_fp = fixture.peer_key.fingerprint().unwrap();
        let mut out = Vec::new();
        for (i, (flags, extra)) in cases.into_iter().enumerate() {
            ctx.state.write_json(&path, &flags).unwrap();
            let before = fixture.recorder.sent.lock().unwrap().len();
            let mut target = extra;
            target["incident_id"] = json!(format!("{i:016x}"));
            let fact = sign_fact(
                &fixture.peer_key,
                env_id,
                "incident",
                target,
                &format!("{}-0000", 6000 + i),
            )
            .unwrap();
            let result = team.handle_message(
                env_id,
                &fixture.session,
                &json!({"type":"INCIDENT","fact":fact.to_dict()}),
            );
            if let Err(error) = &result {
                assert_eq!(error.reason, "state_corrupt");
            }
            let mut after = ctx.state.read_json(&path, Value::Null).unwrap();
            if let Some(map) = after.as_object_mut() {
                for entry in map.values_mut() {
                    if entry.is_object() && entry["flagged_at"] != "T0" {
                        entry["flagged_at"] = json!("T");
                    }
                }
            }
            out.push(json!({
                "raised": result.is_err(),
                "flags": after,
                "acked": fixture.recorder.sent.lock().unwrap().len() - before,
                "record": ctx.state.exists(&format!("team/{env_id}/incidents/{peer_fp}-{i:016x}.json")),
            }));
        }
        let received = ctx
            .audit
            .tail(500)
            .unwrap()
            .iter()
            .filter(|r| r["event"] == "team_incident_received")
            .count();
        // The outcomes the Python prototype's `_handle_incident` produced
        // (`raised` there is an escaping exception, here `state_corrupt`).
        assert_eq!(
            json!({"cases":out,"received":received}),
            json!({"cases": [
                {"raised": true, "flags": ["x"], "acked": 0, "record": true},
                {"raised": false, "flags": ["x"], "acked": 1, "record": true},
                {"raised": true, "flags": {"s2": "bad"}, "acked": 0, "record": true},
                {"raised": false, "flags": {"s2": {"flagged_at": "T", "reason": "rotation_required"}},
                 "acked": 1, "record": true},
                {"raised": true, "flags": {"s2": null}, "acked": 0, "record": true},
                {"raised": false, "flags": {"s3": {"flagged_at": "T", "reason": "rotation_recommended"}},
                 "acked": 1, "record": true},
                {"raised": false, "flags": {
                    "s4": {"flagged_at": "T0", "reason": "rotation_required"},
                    "s5": {"flagged_at": "T", "reason": "rotation_recommended"},
                    "s6": {"flagged_at": "T", "reason": "rotation_required"}},
                 "acked": 1, "record": true},
            ], "received": 4})
        );
    }

    /// `register_env` over every JSON shape of the two peer-state documents:
    /// a truthy non-dict `peer_vectors.json` raises `AttributeError` and a
    /// truthy non-iterable `overridden_alerted.json` raises `TypeError` in
    /// Python (`state_corrupt` here, §3.5); a falsy document is empty; any
    /// other iterable is iterated like Python; peer-vector ints are exact.
    #[test]
    fn peer_state_documents_load() {
        let fps: Vec<String> = (0..3)
            .map(|_| DeviceKey::generate().record().unwrap().fingerprint())
            .collect();
        let big = "100000000000000000000000000000000000000000";
        let vectors_doc: Value = serde_json::from_str(&format!(
            r#"{{"{a}": {{"a": 1, "b": true, "c": 1.5, "d": -3, "e": {big}, "e2": -{big}, "f": "7",
                "g": null, "h": [1], "i": 1e2, "j": 0, "k": -0}},
               "not-a-fingerprint": {{"a": 1}}, "{b}": [1, 2], "{c}": {{}}}}"#,
            a = fps[0],
            b = fps[1],
            c = fps[2],
        ))
        .unwrap();
        let mut cases = vec![json!([vectors_doc, ["o1", 1, null, "o2", ["o3"], {"o4": 1}]])];
        let falsy = [
            json!([]),
            json!(0),
            json!(""),
            json!(null),
            json!(false),
            json!({}),
        ];
        let odd = [json!(["x"]), json!("x"), json!(5), json!(true), json!(1.5)];
        for doc in falsy.iter().chain(odd.iter()) {
            cases.push(json!([doc, ["o1"]]));
        }
        let alerted = [
            json!({"k1": 1, "k2": [2]}),
            json!("xyz"),
            json!([["a"], {"b": 1}, "c", "c"]),
            json!(5),
            json!(true),
            json!(1.5),
        ];
        for doc in falsy.iter().chain(alerted.iter()) {
            cases.push(json!([{}, doc]));
        }
        // `None`: the load fails closed (`state_corrupt`; the Python
        // prototype raised `AttributeError`/`TypeError`). Otherwise the
        // loaded state, as the Python prototype loaded it.
        let loaded = |alerted: Value| Some(json!({"peer_vectors": {}, "alerted": alerted}));
        let mut expected: Vec<Option<Value>> = vec![Some(json!({
            "peer_vectors": {
                (fps[0].clone()): {"a": 1, "d": -3, "e": serde_json::from_str::<Value>(big).unwrap(),
                    "e2": serde_json::from_str::<Value>(&format!("-{big}")).unwrap(), "j": 0, "k": 0},
                (fps[2].clone()): {},
            },
            "alerted": ["o1", "o2"],
        }))];
        expected.extend(falsy.iter().map(|_| loaded(json!(["o1"]))));
        expected.extend(odd.iter().map(|_| None));
        expected.extend(falsy.iter().map(|_| loaded(json!([]))));
        expected.extend([
            loaded(json!(["k1", "k2"])),
            loaded(json!(["x", "y", "z"])),
            loaded(json!(["c"])),
            None,
            None,
            None,
        ]);
        assert_eq!(expected.len(), cases.len());

        let root = TempDir::new().unwrap();
        let ctx = Arc::new(
            Context::initialize(
                root.path().join("a"),
                "synthetic-admin",
                "synthetic-recovery",
                Config::default(),
                crate::clock::system(),
            )
            .unwrap(),
        );
        ctx.projects.create("demo", &["dev"]).unwrap();
        let env_id = crate::team::membership::share_environment(
            &ctx,
            None,
            "demo",
            "dev",
            "owner",
            "synthetic-admin",
        )
        .unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let mine = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let session: Arc<dyn Session> = Arc::new(StubSession {
            peer: DeviceKey::generate().record().unwrap(),
            closed: AtomicBool::new(false),
            created: Instant::now(),
        });
        for (case, expected) in cases.iter().zip(&expected) {
            ctx.state
                .write_json(&format!("team/{env_id}/peer_vectors.json"), &case[0])
                .unwrap();
            ctx.state
                .write_json(&format!("team/{env_id}/overridden_alerted.json"), &case[1])
                .unwrap();
            let team = TeamSync::new(
                ctx.clone(),
                Arc::new(StubTransport {
                    session: session.clone(),
                }),
                mine.clone(),
            );
            match team.register_env(&env_id) {
                Err(error) => {
                    assert_eq!(error.reason, "state_corrupt", "{case}");
                    assert!(expected.is_none(), "{case}: failed, expected {expected:?}");
                }
                Ok(()) => {
                    let envs = team.envs.lock().unwrap();
                    let env = &envs[&env_id];
                    let mut alerted: Vec<&String> = env.alerted_overrides.iter().collect();
                    alerted.sort();
                    assert_eq!(
                        Some(json!({"peer_vectors": env.peer_vectors, "alerted": alerted})),
                        *expected,
                        "{case}"
                    );
                }
            }
        }
    }

    /// `handle_vector` with integer edge values from a peer: the stored
    /// and persisted vector keeps every non-negative int exactly, and the
    /// catch-up range treats a claim past the local sequence (at any
    /// magnitude) as "nothing to send", a negative/bool/float as 0.
    #[test]
    fn peer_vector_ints_are_exact() {
        let fixture = owner_with_admin_peer();
        let own = fixture.team.device.fingerprint().unwrap();
        let peer_fp = fixture.peer_key.fingerprint().unwrap();
        let big = "1000000000000000000000000000000";
        let huge = "10000000000000000000000000000000000000000";
        let vectors = [
            format!(r#"{{"a": {huge}, "b": -1, "c": true, "d": 1.5, "e": 5, "{own}": {huge}}}"#),
            format!(r#"{{"{own}": {big}}}"#),
            format!(r#"{{"{own}": -5}}"#),
            format!(r#"{{"{own}": true}}"#),
            format!(r#"{{"{own}": 1.0}}"#),
            format!(r#"{{"{own}": 1}}"#),
            "{}".to_owned(),
        ];
        let mut out = Vec::new();
        for vector in vectors {
            let vector: Value = serde_json::from_str(&vector).unwrap();
            fixture.recorder.sent.lock().unwrap().clear();
            fixture
                .team
                .handle_message(
                    &fixture.env_id,
                    &fixture.session,
                    &json!({"type":"VECTOR","vector":vector}),
                )
                .unwrap();
            let commits = fixture
                .recorder
                .sent
                .lock()
                .unwrap()
                .iter()
                .filter(|m| m["type"] == "COMMIT")
                .count();
            let stored = fixture
                .ctx
                .state
                .read_json(
                    &format!("team/{}/peer_vectors.json", fixture.env_id),
                    Value::Null,
                )
                .unwrap()[&peer_fp]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| {
                    (
                        if *k == own {
                            "OWN".to_owned()
                        } else {
                            k.clone()
                        },
                        v.clone(),
                    )
                })
                .collect::<Map<String, Value>>();
            out.push(json!({"commits": commits, "stored": stored}));
        }
        // A huge claim sends nothing; an invalid one is treated as 0. (The
        // outcomes the Python prototype's `_handle_vector` produced.)
        let huge_value: Value = serde_json::from_str(huge).unwrap();
        assert_eq!(
            json!(out),
            json!([
                {"commits": 0, "stored": {"a": huge_value, "e": 5, "OWN": huge_value}},
                {"commits": 0, "stored": {"OWN": serde_json::from_str::<Value>(big).unwrap()}},
                {"commits": 2, "stored": {}},
                {"commits": 2, "stored": {}},
                {"commits": 2, "stored": {}},
                {"commits": 1, "stored": {"OWN": 1}},
                {"commits": 2, "stored": {}},
            ])
        );
    }

    /// `stop()`'s ordering, observed through a transport whose `dial` is
    /// slow: the poll thread is joined (so the in-flight dial returns)
    /// before the transport is closed.
    struct SlowDialTransport {
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    impl Transport for SlowDialTransport {
        fn set_membership(&self, _: MembershipCheck) {}
        fn set_invite_check(&self, _: Option<InviteCheck>) {}
        fn set_handshake_failed(&self, _: Option<HandshakeFailedHook>) {}
        fn listen(&self, _: &str, _: OnSession) -> Result<()> {
            Ok(())
        }
        fn dial(
            &self,
            _: &str,
            _: &str,
            _: Option<InviteProof>,
        ) -> std::result::Result<Arc<dyn Session>, SessionClosed> {
            self.events.lock().unwrap().push("dial_start");
            thread::sleep(Duration::from_millis(300));
            self.events.lock().unwrap().push("dial_end");
            Err(SessionClosed("synthetic_refused"))
        }
        fn close(&self) {
            self.events.lock().unwrap().push("close");
        }
    }

    #[test]
    fn stop_joins_the_poll_thread_before_closing_the_transport() {
        let fixture = owner_with_admin_peer();
        let events = Arc::new(Mutex::new(Vec::new()));
        let slow = TeamSync::new(
            fixture.ctx.clone(),
            Arc::new(SlowDialTransport {
                events: events.clone(),
            }),
            fixture.team.device.clone(),
        );
        slow.register_env(&fixture.env_id).unwrap();
        slow.set_peer_address(
            &fixture.env_id,
            &fixture.peer_key.fingerprint().unwrap(),
            "synthetic-slow-address",
        )
        .unwrap();
        slow.start(None).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !events.lock().unwrap().contains(&"dial_start") {
            assert!(Instant::now() < deadline, "the poll thread never dialed");
            thread::sleep(Duration::from_millis(5));
        }
        slow.stop();
        let events = events.lock().unwrap().clone();
        assert_eq!(events, ["dial_start", "dial_end", "close"]);
    }

    /// Gap 7: `_drop_member_sessions` forgets a removed peer's addresses and
    /// its dial backoff/next-attempt state, not only its addresses.
    #[test]
    fn member_removal_forgets_dial_backoff_state() {
        let root = TempDir::new().unwrap();
        let ctx = Arc::new(
            Context::initialize(
                root.path().join("a"),
                "synthetic-admin",
                "synthetic-recovery",
                Config::default(),
                crate::clock::system(),
            )
            .unwrap(),
        );
        ctx.projects.create("demo", &["dev"]).unwrap();
        let env_id = crate::team::membership::share_environment(
            &ctx,
            None,
            "demo",
            "dev",
            "owner",
            "synthetic-admin",
        )
        .unwrap()["env_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let mine = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let peer = DeviceKey::generate().record().unwrap();
        let fp = peer.fingerprint();
        let other = DeviceKey::generate().record().unwrap();
        let other_fp = other.fingerprint();
        let session: Arc<dyn Session> = Arc::new(StubSession {
            peer: peer.clone(),
            closed: AtomicBool::new(false),
            created: Instant::now(),
        });
        let team = TeamSync::new(ctx.clone(), Arc::new(StubTransport { session }), mine);
        team.register_env(&env_id).unwrap();
        for record in [&peer, &other] {
            crate::team::membership::author_commit(
                &ctx,
                Some(&team),
                &env_id,
                vec![json!({"op":"member.add","device":record.to_dict(),"name":"m","role":"user"})],
            )
            .unwrap();
        }
        {
            let mut envs = team.envs.lock().unwrap();
            let env = envs.get_mut(&env_id).unwrap();
            for key in [&fp, &other_fp] {
                env.candidate_addresses
                    .insert(key.clone(), BTreeSet::from(["unreachable".to_owned()]));
                env.backoff.insert(key.clone(), Duration::from_secs(8));
                env.next_attempt
                    .insert(key.clone(), Instant::now() + Duration::from_secs(8));
            }
        }
        team.publish_fact(&env_id, "member_removed", json!({"fingerprint":fp}))
            .unwrap();
        let envs = team.envs.lock().unwrap();
        let env = &envs[&env_id];
        assert!(!env.candidate_addresses.contains_key(&fp));
        assert!(!env.backoff.contains_key(&fp));
        assert!(!env.next_attempt.contains_key(&fp));
        // No live session to drain, and an unrelated member is untouched.
        assert!(!env.draining.contains_key(&fp));
        assert!(env.candidate_addresses.contains_key(&other_fp));
        assert!(env.backoff.contains_key(&other_fp));
        assert!(env.next_attempt.contains_key(&other_fp));
    }

    /// Gap 2: the rebroadcast seen-set is an LRU set like `sync._LruSet` (a
    /// hit refreshes recency, overflow evicts the least recent), compared
    /// call by call with a straightforward reference model.
    #[test]
    fn lru_seen_set_refreshes_on_hit_and_evicts_least_recent() {
        let mut state = 0x2545_f491_u64;
        let keys: Vec<String> = (0..400)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                format!("k{}", state % 9)
            })
            .collect();
        let mut model: Vec<&str> = Vec::new(); // least recent first
        let mut expected = Vec::new();
        for key in &keys {
            if let Some(index) = model.iter().position(|k| k == key) {
                let hit = model.remove(index);
                model.push(hit);
                expected.push(false);
            } else {
                model.push(key);
                if model.len() > 4 {
                    model.remove(0);
                }
                expected.push(true);
            }
        }
        let mut seen = LruSet::new(4);
        let rust: Vec<bool> = keys.iter().map(|k| seen.add_if_new(k)).collect();
        assert_eq!(rust, expected);
        assert!(
            rust.iter().filter(|new| **new).count() > 9,
            "no eviction exercised"
        );
        assert_eq!(SEEN_CAPACITY, 4096);
    }

    /// A peer session that speaks only when the test sends it a frame, and
    /// hangs up when the test drops the sender.
    struct ScriptedSession {
        peer: DeviceRecord,
        frames: Mutex<mpsc::Receiver<Value>>,
        closed: AtomicBool,
        created: Instant,
        sends_fail: bool,
        /// How long `recv` takes to notice anything, closing included.
        recv_delay: Duration,
    }
    impl Session for ScriptedSession {
        fn peer(&self) -> DeviceRecord {
            self.peer.clone()
        }
        fn env_id(&self) -> &str {
            "retry-env"
        }
        fn send(&self, _: &Value) -> Result<()> {
            if self.sends_fail {
                return Err(Error::state("synthetic_send_failure"));
            }
            Ok(())
        }
        fn recv(&self, timeout: Duration) -> std::result::Result<Option<Value>, SessionClosed> {
            thread::sleep(self.recv_delay);
            if self.closed.load(Ordering::SeqCst) {
                return Err(SessionClosed("closed"));
            }
            match self
                .frames
                .lock()
                .unwrap()
                .recv_timeout(timeout.min(Duration::from_millis(20)))
            {
                Ok(frame) => Ok(Some(frame)),
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
                Err(mpsc::RecvTimeoutError::Disconnected) => Err(SessionClosed("peer_closed")),
            }
        }
        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
        fn created_at(&self) -> Instant {
            self.created
        }
    }

    /// A team on an empty `retry-env` whose transport dials `session`, with
    /// `fp` an address and the given standing backoff.
    fn dialing_team(
        root: &TempDir,
        session: Arc<dyn Session>,
        backoff: Option<Duration>,
    ) -> (Arc<TeamSync>, String) {
        let ctx = Arc::new(
            Context::initialize(
                root.path().join("state"),
                "admin-passphrase",
                "recovery-passphrase",
                Config::default(),
                crate::clock::system(),
            )
            .unwrap(),
        );
        let mine = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
        let fp = session.peer().fingerprint();
        let team = TeamSync::new(ctx, Arc::new(StubTransport { session }), mine);
        let mut state = EnvState::new(Facts::default(), HashSet::new(), HashMap::new());
        state
            .candidate_addresses
            .insert(fp.clone(), BTreeSet::from(["retry-address".to_owned()]));
        if let Some(backoff) = backoff {
            state.backoff.insert(fp.clone(), backoff);
            state
                .next_attempt
                .insert(fp.clone(), Instant::now() + backoff);
        }
        team.envs.lock().unwrap().insert("retry-env".into(), state);
        (team, fp)
    }

    fn wait_for(mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "condition not reached");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn scripted(peer: DeviceRecord) -> (Arc<ScriptedSession>, mpsc::Sender<Value>) {
        scripted_with(peer, false, Duration::ZERO)
    }

    fn scripted_with(
        peer: DeviceRecord,
        sends_fail: bool,
        recv_delay: Duration,
    ) -> (Arc<ScriptedSession>, mpsc::Sender<Value>) {
        let (tx, rx) = mpsc::channel();
        let session = Arc::new(ScriptedSession {
            peer,
            frames: Mutex::new(rx),
            closed: AtomicBool::new(false),
            created: Instant::now(),
            sends_fail,
            recv_delay,
        });
        (session, tx)
    }

    /// Issue #14: the initiator's handshake completes before the responder
    /// accepts it, so a dial resets the backoff only once the peer's first
    /// frame has been handled; a disconnect after that keeps the reset.
    #[test]
    fn successful_retry_resets_backoff_before_next_disconnect() {
        let root = TempDir::new().unwrap();
        let (session, tx) = scripted(DeviceKey::generate().record().unwrap());
        let (team, fp) = dialing_team(&root, session.clone(), Some(Duration::from_secs(8)));
        team.dial_attempt("retry-env", &fp);
        {
            let guard = team.envs.lock().unwrap();
            let state = guard.get("retry-env").unwrap();
            assert_eq!(state.backoff.get(&fp), Some(&Duration::from_secs(8)));
            assert!(state.dial_pending.contains_key(&fp));
        }
        tx.send(json!({"type":"PEERS","peers":{}})).unwrap();
        wait_for(|| {
            !team.envs.lock().unwrap()["retry-env"]
                .backoff
                .contains_key(&fp)
        });
        drop(tx);
        wait_for(|| {
            !team.envs.lock().unwrap()["retry-env"]
                .sessions
                .contains_key(&fp)
        });
        let guard = team.envs.lock().unwrap();
        let state = guard.get("retry-env").unwrap();
        assert!(!state.backoff.contains_key(&fp));
        assert!(!state.next_attempt.contains_key(&fp));
        assert!(state.dial_pending.is_empty());
    }

    /// Issue #14: a dial the peer refuses after the handshake -- it closes
    /// before sending anything -- backs off, doubling on every refusal, so a
    /// removed device no longer redials its remover on every poll tick.
    #[test]
    fn refused_dials_back_off() {
        let root = TempDir::new().unwrap();
        let (session, tx) = scripted(DeviceKey::generate().record().unwrap());
        drop(tx);
        let (team, fp) = dialing_team(&root, session, None);
        let (min, _) = Config::default().team_dial_backoff;
        for expected in [min, min * 2.0] {
            team.dial_attempt("retry-env", &fp);
            wait_for(|| {
                team.envs.lock().unwrap()["retry-env"].backoff.get(&fp)
                    == Some(&Duration::from_secs_f64(expected))
            });
            wait_for(|| {
                !team.envs.lock().unwrap()["retry-env"]
                    .sessions
                    .contains_key(&fp)
            });
            let guard = team.envs.lock().unwrap();
            let state = guard.get("retry-env").unwrap();
            assert!(state.next_attempt[&fp] > Instant::now());
            assert!(state.dial_pending.is_empty());
        }
    }

    /// A dial that loses the tie-break to the peer's own session is neither
    /// a success nor a refusal: its mark goes, the backoff stays as it was.
    #[test]
    fn a_dial_that_loses_the_tie_break_leaves_no_mark() {
        // The outbound session loses when this node's fingerprint sorts
        // after the peer's (`keep_new = mine < fp` for an outbound one).
        let (_root, team, peer_key) = loop {
            let root = TempDir::new().unwrap();
            let key = DeviceKey::generate();
            let (session, _tx) = scripted(key.record().unwrap());
            let (team, fp) = dialing_team(&root, session, None);
            if team.device.fingerprint().unwrap() > fp {
                break (root, team, key);
            }
        };
        let fp = peer_key.fingerprint().unwrap();
        let inbound: Arc<dyn Session> = Arc::new(StubSession {
            peer: peer_key.record().unwrap(),
            closed: AtomicBool::new(false),
            created: Instant::now(),
        });
        assert!(team.accept_session("retry-env", inbound.clone(), true));
        team.dial_attempt("retry-env", &fp);
        let guard = team.envs.lock().unwrap();
        let state = guard.get("retry-env").unwrap();
        assert!(Arc::ptr_eq(&state.sessions[&fp], &inbound));
        assert!(state.dial_pending.is_empty());
        assert!(!state.backoff.contains_key(&fp));
    }

    /// A session the peer opened resets the backoff once its first frame
    /// is handled, like a dial of ours would: the tie-break loser and a
    /// member its peers did not know yet stop backing off once they are
    /// heard from.
    #[test]
    fn an_inbound_session_resets_the_backoff() {
        let root = TempDir::new().unwrap();
        let key = DeviceKey::generate();
        let (unused, _) = scripted(key.record().unwrap());
        let (team, fp) = dialing_team(&root, unused, Some(Duration::from_secs(160)));
        let (inbound, tx) = scripted(key.record().unwrap());
        let inbound: Arc<dyn Session> = inbound;
        assert!(team.accept_session("retry-env", inbound.clone(), true));
        team.start_receiver("retry-env".into(), inbound);
        tx.send(json!({"type":"PEERS","peers":{}})).unwrap();
        wait_for(|| {
            let guard = team.envs.lock().unwrap();
            let state = &guard["retry-env"];
            !state.backoff.contains_key(&fp) && !state.next_attempt.contains_key(&fp)
        });
    }

    /// A dial whose session is accepted but dropped by a failed send before
    /// the peer is heard from is a refused dial, not a lost tie-break: it
    /// backs off, even when the dialing thread looks before the session's
    /// receiver has noticed.
    #[test]
    fn an_accepted_dial_dropped_by_a_failed_send_backs_off() {
        let root = TempDir::new().unwrap();
        let (session, _tx) = scripted_with(
            DeviceKey::generate().record().unwrap(),
            true,
            Duration::from_millis(300),
        );
        let (team, fp) = dialing_team(&root, session, None);
        let (min, _) = Config::default().team_dial_backoff;
        team.dial_attempt("retry-env", &fp);
        // Counted as the dial returns, before a poll tick could redial.
        let backoff = || {
            team.envs.lock().unwrap()["retry-env"]
                .backoff
                .get(&fp)
                .copied()
        };
        assert_eq!(backoff(), Some(Duration::from_secs_f64(min)));
        // The receiver, noticing later, does not count it again.
        assert!(!team.receivers.lock().unwrap().is_empty());
        wait_for(|| {
            team.receivers
                .lock()
                .unwrap()
                .iter()
                .all(|t| t.handle.is_finished())
        });
        assert_eq!(backoff(), Some(Duration::from_secs_f64(min)));
        let guard = team.envs.lock().unwrap();
        let state = guard.get("retry-env").unwrap();
        assert!(!state.sessions.contains_key(&fp));
        assert!(state.dial_pending.is_empty());
    }
}
fn valid_id(s: &str, limit: usize) -> bool {
    !s.is_empty()
        && s.chars().count() <= limit
        && !s.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
}
fn valid_token(s: &str) -> bool {
    (16..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_fp(s: &str) -> bool {
    s.len() == 26
        && s.bytes()
            .all(|b: u8| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}
fn valid_incident_str(v: &Value) -> bool {
    v.as_str()
        .is_some_and(|s| valid_id(s, MAX_INCIDENT_STR_LENGTH))
}
fn valid_incident_int(v: &Value) -> bool {
    !v.is_boolean()
        && v.as_i64()
            .is_some_and(|n| (0..=MAX_INCIDENT_UNIT).contains(&n))
}
fn valid_incident_list(v: &Value) -> bool {
    v.as_array().is_some_and(|a| {
        a.len() <= MAX_INCIDENT_LIST_ITEMS
            && a.iter()
                .all(|v| v.as_str().is_some_and(|s| valid_id(s, 64)))
    })
}

pub fn sanitize_incident_summary(summary: &Value) -> Result<Value> {
    let source = summary
        .as_object()
        .ok_or_else(|| Error::invalid_input("team_incident_summary_invalid"))?;
    let id = source
        .get("incident_id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid_input("team_incident_summary_invalid"))?;
    if !valid_token(id) {
        return Err(Error::invalid_input("team_incident_summary_invalid"));
    }
    let mut clean = Map::new();
    clean.insert("incident_id".into(), json!(id));
    for (key, value) in source {
        if key == "incident_id" {
            continue;
        }
        if (["ts", "scope", "rule", "first_used_at", "last_used_at"].contains(&key.as_str())
            && valid_incident_str(value))
            || (key == "uses" && valid_incident_int(value))
        {
            clean.insert(key.clone(), value.clone());
        } else if [
            "secret_ids_mandatory",
            "secret_ids_recommended",
            "connection_ids",
        ]
        .contains(&key.as_str())
            && valid_incident_list(value)
        {
            let values: BTreeSet<&str> = value
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            if !values.is_empty() {
                clean.insert(key.clone(), json!(values));
            }
        }
    }
    Ok(Value::Object(clean))
}

pub(crate) fn validate_fact_target(kind: &str, target: &Value) -> Result<()> {
    let bad = || Error::invalid_input("team_fact_target_invalid");
    let obj = target.as_object().ok_or_else(bad)?;
    match kind {
        "connection_disabled"
            if obj.len() == 1
                && obj
                    .get("connection_id")
                    .and_then(Value::as_str)
                    .is_some_and(|s| valid_id(s, 64)) =>
        {
            Ok(())
        }
        "secret_version_revoked"
            if obj.len() == 2
                && obj
                    .get("secret_id")
                    .and_then(Value::as_str)
                    .is_some_and(|s| valid_id(s, 64))
                && obj
                    .get("version_id")
                    .and_then(Value::as_str)
                    .is_some_and(valid_token) =>
        {
            Ok(())
        }
        "member_removed"
            if obj.len() == 1
                && obj
                    .get("fingerprint")
                    .and_then(Value::as_str)
                    .is_some_and(valid_fp) =>
        {
            Ok(())
        }
        "incident" => {
            if !obj
                .get("incident_id")
                .and_then(Value::as_str)
                .is_some_and(valid_token)
            {
                return Err(bad());
            }
            for (key, value) in obj {
                let valid = match key.as_str() {
                    "incident_id" | "ts" | "scope" | "rule" | "first_used_at" | "last_used_at" => {
                        valid_incident_str(value)
                    }
                    "uses" => valid_incident_int(value),
                    "secret_ids_mandatory" | "secret_ids_recommended" | "connection_ids" => {
                        valid_incident_list(value)
                    }
                    _ => false,
                };
                if !valid {
                    return Err(bad());
                }
            }
            Ok(())
        }
        "connection_disabled" | "secret_version_revoked" | "member_removed" => Err(bad()),
        _ => Err(Error::invalid_input("team_fact_kind_unknown")),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fact {
    pub format: String,
    pub env_id: String,
    pub kind: String,
    pub target: Value,
    pub author: String,
    pub hlc: String,
    pub sig: String,
}
impl Fact {
    pub fn canonical_json(&self, include_sig: bool) -> Result<Vec<u8>> {
        canon(&self.canonical(include_sig))
    }
    fn canonical(&self, include_sig: bool) -> Value {
        let mut value = json!({"format":self.format,"env_id":self.env_id,"kind":self.kind,"target":self.target,"author":self.author,"hlc":self.hlc});
        if include_sig {
            value["sig"] = json!(self.sig);
        }
        value
    }
    pub fn hash(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(self.canonical_json(true)?)))
    }
    pub fn to_dict(&self) -> Value {
        self.canonical(true)
    }
    pub fn from_dict(data: &Value) -> Result<Self> {
        let bad = || Error::invalid_input("team_fact_malformed");
        let obj = data.as_object().ok_or_else(bad)?;
        let field = |key| obj.get(key).map(commit::python_str_coerce).ok_or_else(bad);
        // Python applies dict(target) before stringifying its keys. Reuse the
        // commit parser's sequence-of-pairs conversion and key equivalence.
        let pairs =
            commit::python_dict_pairs(obj.get("target").ok_or_else(bad)?).ok_or_else(bad)?;
        let mut merged: Vec<(Value, Value)> = Vec::new();
        for (key, value) in pairs {
            if !commit::dict_key_is_hashable(&key) {
                return Err(bad());
            }
            if let Some((_, prior_value)) = merged
                .iter_mut()
                .find(|(prior, _)| commit::dict_keys_equal(prior, &key))
            {
                *prior_value = value;
            } else {
                merged.push((key, value));
            }
        }
        let mut target = Map::new();
        for (key, value) in merged {
            target.insert(commit::python_str_coerce(&key), value);
        }
        Ok(Self {
            format: field("format")?,
            env_id: field("env_id")?,
            kind: field("kind")?,
            target: Value::Object(target),
            author: field("author")?,
            hlc: field("hlc")?,
            sig: field("sig")?,
        })
    }
}
pub fn sign_fact(
    device: &DeviceKey,
    env_id: &str,
    kind: &str,
    target: Value,
    hlc: &str,
) -> Result<Fact> {
    validate_fact_target(kind, &target)?;
    let mut fact = Fact {
        format: FACT_FORMAT.into(),
        env_id: env_id.into(),
        kind: kind.into(),
        target,
        author: device.fingerprint()?,
        hlc: hlc.into(),
        sig: String::new(),
    };
    fact.sig = pybase64::b64encode(&device.sign(&fact.canonical_json(false)?)?);
    Ok(fact)
}
pub fn verify_fact(fact: &Fact, author: &DeviceRecord) -> bool {
    if fact.format != FACT_FORMAT
        || fact.author != author.fingerprint()
        || !FACT_KINDS.contains(&fact.kind.as_str())
        || validate_fact_target(&fact.kind, &fact.target).is_err()
        || Hlc::parse(&fact.hlc).is_err()
    {
        return false;
    }
    let Ok(sig) = pybase64::b64decode_strict(&fact.sig) else {
        return false;
    };
    fact.canonical_json(false)
        .is_ok_and(|bytes| super::verify_signature(&author.sign_pub, &bytes, &sig))
}
fn apply_fact(facts: &mut Facts, fact: &Fact) {
    match fact.kind.as_str() {
        "connection_disabled" => {
            if let Some(id) = fact.target["connection_id"].as_str() {
                facts.disabled_connections.insert(id.into());
            }
        }
        "secret_version_revoked" => {
            if let (Some(sid), Some(vid)) = (
                fact.target["secret_id"].as_str(),
                fact.target["version_id"].as_str(),
            ) {
                facts.revoked_versions.insert((sid.into(), vid.into()));
            }
        }
        "member_removed" => {
            if let Some(fp) = fact.target["fingerprint"].as_str() {
                facts.removed_members.insert(fp.into());
                if let Ok(hash) = fact.hash() {
                    facts.removal_facts.insert(
                        hash,
                        fold::RemovalFact {
                            author: fact.author.clone(),
                            target: fp.into(),
                            hlc: fact.hlc.clone(),
                        },
                    );
                }
            }
        }
        "incident" => facts.incidents.push(fact.target.clone()),
        _ => {}
    }
}
pub fn is_admin(doc: &Value, fp: &str) -> bool {
    let member = &doc["members"][fp];
    member["status"] == "active" && (doc["owner"] == fp || member["role"] == "admin")
}
pub fn fact_role_ok(doc: &Value, kind: &str, author: &str, target: &Value) -> bool {
    if kind == "member_removed" {
        let target_fp = target["fingerprint"].as_str().unwrap_or("");
        if doc["owner"] == target_fp {
            return false;
        }
        // `is_admin` covers an active owner; a removed owner keeps no
        // authority.
        return is_admin(doc, author) || author == target_fp;
    }
    if kind == "incident" {
        return doc["members"][author]["status"] == "active";
    }
    is_admin(doc, author)
}
/// Admission receipts authenticate the local authorization decision. They are
/// local only: peers must perform their own signature and authority checks.
pub(crate) fn receipt_fact(ctx: &Context, fact: &Fact) -> Result<()> {
    let _lock = ctx.state.lock()?;
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms)?;
    let hash = fact.hash()?;
    let message = canon(
        &json!({"domain":"zeropw-local-fact-admission-v1","env_id":fact.env_id,"hash":hash}),
    )?;
    ctx.state.append_line(
        &format!("team/{}/fact_admissions.jsonl", fact.env_id),
        &pyjson::dumps(
            &json!({"hash":hash,"sig":pybase64::b64encode(&device.sign(&message)?)}),
            DumpOptions::compact_sorted(),
        )?,
    )
}

pub fn load_facts(
    ctx: &Context,
    env_id: &str,
) -> Result<(Facts, HashSet<String>, HashMap<String, HashSet<String>>)> {
    let _lock = ctx.state.lock()?;
    let state = ctx.state;
    let path = format!("team/{env_id}/facts.jsonl");
    let lines = state.read_lines(&path, None)?;
    let mut facts = Facts::default();
    let mut hashes = HashSet::new();
    let mut authors: HashMap<String, HashSet<String>> = HashMap::new();
    if lines.is_empty() {
        return Ok((facts, hashes, authors));
    }
    let local = DeviceKey::load_or_create(state, ctx.kms)?.record()?;
    let mut receipts =
        state.read_json(&format!("team/{env_id}/fact_admissions.json"), json!({}))?;
    for line in state.read_lines(&format!("team/{env_id}/fact_admissions.jsonl"), None)? {
        if let Ok(entry) = pyjson::loads(&line)
            && let (Some(hash), Some(sig)) = (entry["hash"].as_str(), entry["sig"].as_str())
        {
            if let Some(map) = receipts.as_object_mut() {
                map.insert(hash.into(), json!(sig));
            }
        }
    }
    let commits = CommitStore::new(state, env_id).all_commits()?;
    let identity = fold::fold(env_id, commits.clone(), None, None, None, None)?.document;
    // Irreversible historical revocations survive later role changes. A
    // signed history prefix proves the author once had the required role.
    let mut historical_admins = HashSet::new();
    let mut historical_members = HashSet::new();
    let needs_history = lines
        .iter()
        .filter_map(|line| pyjson::loads(line).ok())
        .filter_map(|value| Fact::from_dict(&value).ok())
        .any(|fact| {
            if fact.kind == "member_removed" {
                return false;
            }
            let Ok(hash) = fact.hash() else {
                return false;
            };
            let Ok(message) = canon(
                &json!({"domain":"zeropw-local-fact-admission-v1","env_id":env_id,"hash":hash}),
            ) else {
                return false;
            };
            !receipts[&hash]
                .as_str()
                .and_then(|sig| pybase64::b64decode_strict(sig).ok())
                .is_some_and(|sig| super::verify_signature(&local.sign_pub, &message, &sig))
        });
    if needs_history {
        let mut ordered = commits.clone();
        ordered.sort_by(|a, b| {
            Hlc::parse(&a.hlc)
                .unwrap_or_else(|_| (0.into(), 0.into()))
                .cmp(&Hlc::parse(&b.hlc).unwrap_or_else(|_| (0.into(), 0.into())))
                .then(a.author.cmp(&b.author))
                .then(a.author_seq.cmp(&b.author_seq))
        });
        for count in 1..=ordered.len() {
            let doc =
                fold::fold(env_id, ordered[..count].to_vec(), None, None, None, None)?.document;
            if let Some(members) = doc["members"].as_object() {
                for (fp, member) in members {
                    if member["status"] == "active" {
                        historical_members.insert(fp.clone());
                        if member["role"] == "admin" {
                            historical_admins.insert(fp.clone());
                        }
                    }
                }
            }
        }
    }
    let mut retained = Vec::new();
    for line in &lines {
        let candidate = pyjson::loads(line)
            .ok()
            .and_then(|v| Fact::from_dict(&v).ok());
        let mut accepted = false;
        if let Some(fact) = candidate.filter(|f| f.env_id == env_id) {
            let hash = fact.hash()?;
            if hashes.contains(&hash) {
                retained.push(line.as_str());
                continue;
            }
            if member_device_record(&identity, &fact.author)
                .is_some_and(|record| verify_fact(&fact, &record))
            {
                let message = canon(
                    &json!({"domain":"zeropw-local-fact-admission-v1","env_id":env_id,"hash":hash}),
                )?;
                let admitted = receipts[&hash]
                    .as_str()
                    .and_then(|s| pybase64::b64decode_strict(s).ok())
                    .is_some_and(|sig| super::verify_signature(&local.sign_pub, &message, &sig));
                let historical = match fact.kind.as_str() {
                    "connection_disabled" | "secret_version_revoked" => {
                        historical_admins.contains(&fact.author)
                    }
                    "incident" => historical_members.contains(&fact.author),
                    _ => false,
                };
                let authorized = if admitted || historical {
                    true
                } else {
                    let mut prefix = facts.clone();
                    let target = fact.target["fingerprint"].as_str().unwrap_or("");
                    if fact.kind == "member_removed"
                        && authors
                            .get(&fact.author)
                            .is_some_and(|set| set.len() == 1 && set.contains(target))
                    {
                        prefix.removed_members.remove(&fact.author);
                    }
                    let doc = fold::fold(env_id, commits.clone(), Some(&prefix), None, None, None)?
                        .document;
                    fact_role_ok(&doc, &fact.kind, &fact.author, &fact.target)
                };
                if authorized {
                    if !admitted {
                        receipt_fact(ctx, &fact)?;
                    }
                    hashes.insert(hash);
                    apply_fact(&mut facts, &fact);
                    if fact.kind == "member_removed"
                        && let Some(fp) = fact.target["fingerprint"].as_str()
                    {
                        authors.entry(fp.into()).or_default().insert(fact.author);
                    }
                    accepted = true;
                }
            }
        }
        if accepted {
            retained.push(line.as_str());
        } else {
            state.append_line(
                &format!("team/{env_id}/rejected_facts.jsonl"),
                &pyjson::dumps(
                    &json!({"line":line,"reason":"team_fact_startup_rejected"}),
                    DumpOptions::compact_sorted(),
                )?,
            )?;
        }
    }
    if retained.len() != lines.len() {
        let mut text = retained.join("\n");
        if !text.is_empty() {
            text.push('\n');
        }
        state.write_bytes(&path, text.as_bytes())?;
    }
    Ok((facts, hashes, authors))
}
pub fn read_env_mapping(state: &StateDir) -> Result<Value> {
    let doc = state.read_json(ENVS_MAP_PATH, json!({}))?;
    Ok(if doc.is_object() { doc } else { json!({}) })
}
pub fn write_env_mapping(
    state: &StateDir,
    env_id: &str,
    project: &str,
    environment: &str,
) -> Result<()> {
    let _lock = state.lock()?;
    let mut doc = read_env_mapping(state)?;
    doc[env_id] = json!({"project":project,"environment":environment});
    state.write_json(ENVS_MAP_PATH, &doc)
}
pub fn env_project_environment(
    state: &StateDir,
    env_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let doc = read_env_mapping(state)?;
    let entry = &doc[env_id];
    Ok((
        entry["project"].as_str().map(str::to_owned),
        entry["environment"].as_str().map(str::to_owned),
    ))
}
pub fn resolve_env_id(
    state: &StateDir,
    project: &str,
    environment: &str,
) -> Result<Option<String>> {
    let doc = read_env_mapping(state)?;
    Ok(doc.as_object().and_then(|m| {
        m.iter()
            .find(|(_, entry)| entry["project"] == project && entry["environment"] == environment)
            .map(|(id, _)| id.clone())
    }))
}
pub fn discover_envs(state: &StateDir) -> Result<Vec<String>> {
    let root = state.path.join("team");
    if !root.is_dir() {
        return Ok(vec![]);
    }
    let mut found = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|_| Error::state("state_corrupt"))? {
        let entry = entry.map_err(|_| Error::state("state_corrupt"))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        if path.is_dir()
            && commit::valid_env_id(&name)
            && (path.join("commits").is_dir()
                || path.join("snapshots").is_dir()
                || path.join("facts.jsonl").exists())
        {
            found.push(name);
        }
    }
    found.sort();
    Ok(found)
}

/// Python `list(x)` / `for a in x` over a `json.load`ed value: a list yields
/// its elements, a str its characters, a dict its keys. `None`/`bool`/numbers
/// are not iterable (`TypeError` in Python), returned as `None` here.
pub(crate) fn python_list(value: &Value) -> Option<Vec<Value>> {
    match value {
        Value::Array(items) => Some(items.clone()),
        Value::String(s) => Some(s.chars().map(|c| Value::String(c.to_string())).collect()),
        Value::Object(map) => Some(map.keys().map(|k| Value::String(k.clone())).collect()),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
}

/// The device record of `members[fp]` in a folded document, if it parses and
/// really is `fp`'s (`_known_device_record` after its `_relaxed_document`).
fn member_device_record(doc: &Value, fp: &str) -> Option<DeviceRecord> {
    let record = DeviceRecord::from_dict(&doc["members"][fp]["device"]).ok()?;
    (record.fingerprint() == fp).then_some(record)
}

/// `StateDir.read_json(path, {}) or {}` for a document Python then uses as a
/// `dict`: a falsy document becomes `{}`, and a truthy non-dict (on which
/// Python's `.get`/`.items`/item assignment raises an uncaught
/// `AttributeError`/`TypeError`) is `state_corrupt` (PORTING.md §3.5).
fn read_dict_or_empty(state: &StateDir, path: &str) -> Result<Map<String, Value>> {
    match state.read_json(path, json!({}))? {
        Value::Object(map) => Ok(map),
        other if super::json_falsy(&other) => Ok(Map::new()),
        _ => Err(Error::state("state_corrupt").with_detail(path)),
    }
}

/// Port of `sync._LruSet`: a bounded set deduplicating rebroadcast of
/// already-seen commit hashes. A hit refreshes the key's recency
/// (`move_to_end`); an insert past capacity evicts the least recent key.
struct LruSet {
    capacity: usize,
    tick: u64,
    by_key: HashMap<String, u64>,
    by_tick: BTreeMap<u64, String>,
}
impl LruSet {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            tick: 0,
            by_key: HashMap::new(),
            by_tick: BTreeMap::new(),
        }
    }
    fn add_if_new(&mut self, key: &str) -> bool {
        self.tick += 1;
        if let Some(previous) = self.by_key.get_mut(key) {
            self.by_tick.remove(previous);
            *previous = self.tick;
            self.by_tick.insert(self.tick, key.to_owned());
            return false;
        }
        self.by_key.insert(key.to_owned(), self.tick);
        self.by_tick.insert(self.tick, key.to_owned());
        if self.by_key.len() > self.capacity
            && let Some((_, oldest)) = self.by_tick.pop_first()
        {
            self.by_key.remove(&oldest);
        }
        true
    }
}

/// A spawned thread plus a channel that disconnects when its closure ends,
/// so `stop` can wait for it with Python's `join(timeout=5)` bound.
struct BoundedThread {
    handle: thread::JoinHandle<()>,
    done: mpsc::Receiver<()>,
}
impl BoundedThread {
    fn spawn(body: impl FnOnce() + Send + 'static) -> Self {
        let (done_tx, done) = mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            // Dropped when the closure returns (or unwinds): disconnects `done`.
            let _done = done_tx;
            body();
        });
        Self { handle, done }
    }
    /// `thread.join(timeout=5)`: a thread still running after the bound is
    /// left detached, exactly like a timed-out Python join.
    fn join_bounded(self, timeout: Duration) {
        if self.handle.thread().id() == thread::current().id() {
            return;
        }
        match self.done.recv_timeout(timeout) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = self.handle.join();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

struct EnvState {
    document: Value,
    facts: Facts,
    fact_hashes: HashSet<String>,
    removal_authors: HashMap<String, HashSet<String>>,
    sessions: HashMap<String, Arc<dyn Session>>,
    fact_replay_cursor: HashMap<String, usize>,
    candidate_addresses: HashMap<String, BTreeSet<String>>,
    draining: HashMap<String, Instant>,
    /// `_EnvState.peer_vectors`: Python ints, so exact at any magnitude.
    peer_vectors: HashMap<String, BTreeMap<String, PyInt>>,
    backoff: HashMap<String, Duration>,
    next_attempt: HashMap<String, Instant>,
    /// A dialed session whose peer has not yet sent a frame we handled.
    /// The initiator's handshake completes before the responder accepts it
    /// (a remover refuses a removed device only at message 3), so the dial
    /// counts as a success only then (issue #14).
    dial_pending: HashMap<String, Weak<dyn Session>>,
    hlc: Hlc,
    last_known_vector: BTreeMap<String, PyInt>,
    known_fact_lines: usize,
    fact_file_stamp: Option<(u64, u64, i64, i64)>,
    /// `_EnvState.last_snapshot_total`: a Python number -- the exact `int`
    /// sum of a saved snapshot's vector, or whatever `sum()` of a loaded
    /// snapshot's raw vector values produced (a `float` when it held one).
    last_snapshot_total: PyNumber,
    last_vector_sent: HashMap<String, Instant>,
    synced_at: Option<f64>,
    incident_outbox: HashMap<String, Fact>,
    incident_backoff: HashMap<String, Duration>,
    incident_next_attempt: HashMap<String, Instant>,
    pending_invites: HashMap<String, (String, String)>,
    /// Sessions of devices that just joined through an invitation. They have
    /// no history yet, so live COMMIT/FACT frames for them are held (and
    /// INCIDENTs not sent) until their first VECTOR has been answered with
    /// the whole history in order; otherwise the joiner quarantines the
    /// inviter's `member.add` as `team_author_unknown` (issue #28).
    catching_up: HashSet<String>,
    /// Frames withheld from `catching_up` sessions, in order.
    held: HashMap<String, std::collections::VecDeque<Value>>,
    /// Commits that arrived before the history they build on: by sending
    /// peer, the commit hash and when that peer first sent it.
    early_commits: HashMap<String, HashMap<String, Instant>>,
    /// Peers an early commit asks for a VECTOR, sent by the poll loop as
    /// [`EARLY_VECTOR_INTERVAL`] and [`EARLY_QUIET`] allow.
    vector_due: HashSet<String>,
    /// When this node last accepted a commit a peer sent.
    last_accepted: Option<Instant>,
    alerted_overrides: HashSet<String>,
    /// `_EnvState.relaxed_cache`: (store vector, relaxed document).
    relaxed_cache: Option<(BTreeMap<String, PyInt>, Arc<Value>)>,
    /// Bumped wherever Python clears `relaxed_cache` (`_refold`), so a fold
    /// computed concurrently with that invalidation is never cached.
    relaxed_generation: u64,
    pending_removal_repairs: HashSet<String>,
    next_removal_repair: Instant,
    /// The last refold failed, wherever it ran: the poll retries it until
    /// one succeeds (section 6.4, issue #51).
    refold_failure: Option<RefoldFailure>,
}
/// A failed refold the poll retries: its error, and when after the first
/// retry ([`crate::context::Config::team_refold_retry_backoff`]).
struct RefoldFailure {
    error: Error,
    backoff: Duration,
    retry_at: Option<Instant>,
}
impl EnvState {
    fn new(
        facts: Facts,
        hashes: HashSet<String>,
        authors: HashMap<String, HashSet<String>>,
    ) -> Self {
        Self {
            document: Value::Null,
            facts,
            fact_hashes: hashes,
            removal_authors: authors,
            sessions: HashMap::new(),
            fact_replay_cursor: HashMap::new(),
            candidate_addresses: HashMap::new(),
            draining: HashMap::new(),
            peer_vectors: HashMap::new(),
            backoff: HashMap::new(),
            next_attempt: HashMap::new(),
            dial_pending: HashMap::new(),
            hlc: Hlc::new(0, 0),
            last_known_vector: BTreeMap::new(),
            known_fact_lines: 0,
            fact_file_stamp: None,
            last_snapshot_total: PyNumber::Int(0.into()),
            last_vector_sent: HashMap::new(),
            synced_at: None,
            incident_outbox: HashMap::new(),
            incident_backoff: HashMap::new(),
            incident_next_attempt: HashMap::new(),
            pending_invites: HashMap::new(),
            catching_up: HashSet::new(),
            held: HashMap::new(),
            early_commits: HashMap::new(),
            vector_due: HashSet::new(),
            last_accepted: None,
            alerted_overrides: HashSet::new(),
            relaxed_cache: None,
            relaxed_generation: 0,
            pending_removal_repairs: HashSet::new(),
            next_removal_repair: Instant::now(),
            refold_failure: None,
        }
    }
    /// `fp`'s member entry while the device is a member to talk to: active
    /// in the document, with no stored removal fact. A refold that failed
    /// leaves the document behind the facts, so the fact alone refuses the
    /// device until a refold marks it removed.
    fn active_member(&self, fp: &str) -> Option<&Value> {
        let member = &self.document["members"][fp];
        (member["status"] == "active" && !self.facts.removed_members.contains(fp)).then_some(member)
    }
}

pub struct TeamSync {
    pub ctx: Arc<Context>,
    pub transport: Arc<dyn Transport>,
    pub device: DeviceKey,
    envs: Mutex<HashMap<String, EnvState>>,
    stop: AtomicBool,
    poll_thread: Mutex<Option<BoundedThread>>,
    last_discovery: Mutex<Instant>,
    /// This instance, for the receive threads it starts (Python's `self`).
    this: Weak<TeamSync>,
    /// `TeamSync._commit_seen`.
    commit_seen: Mutex<LruSet>,
    /// `TeamSync._session_threads`.
    receivers: Mutex<Vec<BoundedThread>>,
    deferred_sends: Mutex<std::collections::VecDeque<(String, Value, Option<String>, bool)>>,
    /// The reason each failing environment's poll or load last failed with,
    /// so a failure the poll thread retries every tick is audited once.
    poll_failures: Mutex<HashMap<String, String>>,
    /// Test observability: how many relaxed-document folds actually ran.
    #[cfg(test)]
    relaxed_folds: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    fact_pickup_loads: std::sync::atomic::AtomicUsize,
    /// Test observability: how many refolds ran.
    #[cfg(test)]
    refolds_run: std::sync::atomic::AtomicUsize,
}
pub fn attached(ctx: &Context) -> Option<Arc<TeamSync>> {
    let guard = ctx.team.lock().ok()?;
    guard.as_ref()?.downcast_ref::<Weak<TeamSync>>()?.upgrade()
}
impl TeamSync {
    pub fn new(ctx: Arc<Context>, transport: Arc<dyn Transport>, device: DeviceKey) -> Arc<Self> {
        let this = Arc::new_cyclic(|this| Self {
            ctx,
            transport,
            device,
            envs: Mutex::new(HashMap::new()),
            stop: AtomicBool::new(false),
            poll_thread: Mutex::new(None),
            last_discovery: Mutex::new(Instant::now() - Duration::from_secs(2)),
            this: this.clone(),
            commit_seen: Mutex::new(LruSet::new(SEEN_CAPACITY)),
            receivers: Mutex::new(Vec::new()),
            deferred_sends: Mutex::new(std::collections::VecDeque::new()),
            poll_failures: Mutex::new(HashMap::new()),
            #[cfg(test)]
            relaxed_folds: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fact_pickup_loads: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            refolds_run: std::sync::atomic::AtomicUsize::new(0),
        });
        let weak = Arc::downgrade(&this);
        let membership: MembershipCheck =
            Arc::new(move |env, fp| weak.upgrade().and_then(|s| s.membership(env, fp)));
        this.transport.set_membership(membership);
        let weak = Arc::downgrade(&this);
        let invite: InviteCheck = Arc::new(move |env, record, hash, proof| {
            weak.upgrade()
                .is_some_and(|s| s.invite_check(env, record, hash, proof))
        });
        this.transport.set_invite_check(Some(invite));
        let weak = Arc::downgrade(&this);
        this.transport
            .set_handshake_failed(Some(Arc::new(move |reason, fp| {
                if let Some(s) = weak.upgrade() {
                    s.audit_handshake_failed(reason, fp);
                }
            })));
        *this.ctx.team.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Box::new(Arc::downgrade(&this)));
        this
    }
    pub fn start(self: &Arc<Self>, listen_address: Option<&str>) -> Result<()> {
        self.discover()?;
        if let Some(address) = listen_address {
            let weak = Arc::downgrade(self);
            let callback: OnSession = Arc::new(move |session| {
                if let Some(s) = weak.upgrade() {
                    s.on_inbound_session(session);
                } else {
                    session.close();
                }
            });
            self.transport.listen(address, callback)?;
        }
        self.stop.store(false, Ordering::SeqCst);
        let weak = Arc::downgrade(self);
        *self.poll_thread.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(BoundedThread::spawn(move || {
                while let Some(s) = weak.upgrade() {
                    if s.stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let _ = s.poll();
                    thread::sleep(Duration::from_millis(50));
                }
            }));
        Ok(())
    }
    /// `TeamSync.stop`: signal, join the poll thread (bounded), and only then
    /// close the transport -- an in-flight poll tick (e.g. a dial) finishes
    /// against a live transport, as in Python -- then close every session
    /// and join the receive threads.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let poll_thread = self
            .poll_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(t) = poll_thread {
            t.join_bounded(THREAD_JOIN_TIMEOUT);
        }
        self.transport.close();
        let sessions = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let mut all = Vec::new();
            for env in envs.values_mut() {
                all.extend(env.sessions.drain().map(|(_, session)| session));
                env.fact_replay_cursor.clear();
                env.catching_up.clear();
                env.held.clear();
                env.early_commits.clear();
                env.vector_due.clear();
                env.dial_pending.clear();
            }
            all
        };
        for session in sessions {
            session.close();
        }
        // Python: `threads, self._session_threads = self._session_threads, []`
        // then `t.join(timeout=5)` each, outside every lock (a receive
        // thread's own exit path takes `envs` via `drop_session`).
        let receivers =
            std::mem::take(&mut *self.receivers.lock().unwrap_or_else(|e| e.into_inner()));
        for t in receivers {
            t.join_bounded(THREAD_JOIN_TIMEOUT);
        }
    }
    pub fn known_envs(&self) -> Vec<String> {
        let mut ids: Vec<_> = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        ids.sort();
        ids
    }
    /// Register every environment found on disk. One that cannot be loaded
    /// holds up no other (section 6.4); the first such error is returned.
    pub fn discover(&self) -> Result<()> {
        let mut failed = None;
        for id in discover_envs(self.ctx.state)? {
            let known = self
                .envs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&id);
            let registered = self.register_env(&id);
            // Loaded now, even if its first refold failed: a load failure
            // noted before cannot hide the next failure, whatever its reason
            // (issue #49). One already loaded keeps what its polls noted.
            if !known
                && self
                    .envs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains_key(&id)
            {
                self.note_poll_failure(&id, None);
            }
            if let Err(error) = registered {
                self.note_poll_failure(&id, Some(&error));
                failed.get_or_insert(error);
            }
        }
        failed.map_or(Ok(()), Err)
    }
    /// Audit `env_id`'s poll or load failing (section 6.4) when it starts
    /// failing or fails for another reason; `None` once it succeeds.
    fn note_poll_failure(&self, env_id: &str, error: Option<&Error>) {
        let mut failures = self.poll_failures.lock().unwrap_or_else(|e| e.into_inner());
        let Some(error) = error else {
            failures.remove(env_id);
            return;
        };
        if failures.get(env_id).map(String::as_str) == Some(error.reason.as_ref()) {
            return;
        }
        failures.insert(env_id.to_owned(), error.reason.to_string());
        drop(failures);
        let _ = self.ctx.audit.record(
            "team_sync_poll",
            RecordArgs {
                result: Some("failed"),
                reason: Some(&error.reason),
                extra: vec![("env_id", json!(env_id))],
                ..Default::default()
            },
        );
    }
    pub fn register_env(&self, env_id: &str) -> Result<()> {
        if self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(env_id)
        {
            return Ok(());
        }
        let (facts, hashes, authors) = load_facts(&self.ctx, env_id)?;
        let mut env = EnvState::new(facts, hashes, authors);
        // `self._read_peers(env_id).items()`: a truthy non-dict document
        // raises in Python before the environment is loaded (§3.5).
        let peers = read_dict_or_empty(self.ctx.state, &format!("team/{env_id}/peers.json"))?;
        for (fp, addrs) in &peers {
            if valid_fp(fp) {
                if let Some(addrs) = addrs.as_array() {
                    env.candidate_addresses.insert(
                        fp.clone(),
                        addrs
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect(),
                    );
                }
            }
        }
        // `(read_json(...) or {}).items()`: a truthy non-dict raises (§3.5);
        // each dict-valued entry keeps `{str(k): int(v) ... if isinstance(v,
        // int) and not isinstance(v, bool)}` -- any magnitude, any sign.
        let peer_vectors =
            read_dict_or_empty(self.ctx.state, &format!("team/{env_id}/peer_vectors.json"))?;
        for (fp, vector) in &peer_vectors {
            if !valid_fp(fp) {
                continue;
            }
            if let Some(vector) = vector.as_object() {
                env.peer_vectors.insert(
                    fp.clone(),
                    vector
                        .iter()
                        .filter_map(|(author, seq)| {
                            PyInt::from_json_integer(seq).map(|n| (author.clone(), n))
                        })
                        .collect(),
                );
            }
        }
        let persisted_lines = self
            .ctx
            .state
            .read_lines(&format!("team/{env_id}/facts.jsonl"), None)?;
        env.known_fact_lines = persisted_lines.len();
        for line in persisted_lines {
            if let Ok(value) = pyjson::loads(&line)
                && let Ok(fact) = Fact::from_dict(&value)
                && fact.kind == "member_removed"
            {
                env.pending_removal_repairs.insert(fact.hash()?);
            }
        }
        // `snapshot = F.load_latest_snapshot(...)`; `if snapshot is not
        // None: env.last_snapshot_total = sum((snapshot.get("vector") or
        // {}).values())`. A non-dict snapshot (even a falsy one) or a truthy
        // non-dict vector has no `.get`/`.values` (`AttributeError`), and
        // `sum()` raises for a non-number value (`TypeError`) or an int too
        // large for a float it must be added to (`OverflowError`); all are
        // `state_corrupt` from this step (§3.5).
        if let Some(snapshot) = fold::load_latest_snapshot(self.ctx.state, env_id)?
            && !snapshot.is_null()
        {
            let corrupt = || Error::state("state_corrupt").with_detail("team_snapshot");
            let vector = snapshot.as_object().ok_or_else(corrupt)?.get("vector");
            env.last_snapshot_total = match vector {
                None => PyNumber::Int(0.into()),
                Some(v) if super::json_falsy(v) => PyNumber::Int(0.into()),
                Some(Value::Object(v)) => {
                    crate::pyint::python_sum(v.values()).ok_or_else(corrupt)?
                }
                Some(_) => return Err(corrupt()),
            };
        }
        for line in self
            .ctx
            .state
            .read_lines(&format!("team/{env_id}/incident_outbox.jsonl"), None)?
        {
            if let Ok(value) = pyjson::loads(&line) {
                if let Ok(fact) = Fact::from_dict(&value) {
                    if fact.env_id == env_id && fact.kind == "incident" {
                        if let Ok(hash) = fact.hash() {
                            env.incident_outbox.insert(hash, fact);
                        }
                    }
                }
            }
        }
        // `{s for s in (read_json(...) or []) if isinstance(s, str)}`: any
        // iterable (a dict's keys, a string's characters); a truthy number or
        // `true` is not iterable (`TypeError`, §3.5).
        let alerted_path = format!("team/{env_id}/overridden_alerted.json");
        let alerted = self.ctx.state.read_json(&alerted_path, json!([]))?;
        if !super::json_falsy(&alerted) {
            env.alerted_overrides = python_list(&alerted)
                .ok_or_else(|| Error::state("state_corrupt").with_detail(&alerted_path))?
                .into_iter()
                .filter_map(|value| match value {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .collect();
        }
        self.envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(env_id.into(), env);
        self.refold(env_id)?;
        // `env.last_known_vector = dict(env.store.vector())` runs after
        // `_refold`, so a failing refold leaves the registered environment
        // with the empty baseline.
        let vector = CommitStore::new(self.ctx.state, env_id).vector()?;
        if let Some(env) = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(env_id)
        {
            env.last_known_vector = vector;
        }
        Ok(())
    }
    /// Refold `env_id`, noting whether it failed: the poll retries a failed
    /// refold until one succeeds (section 6.4, issue #51). Noted under the
    /// state lock, so in the order concurrent refolds ran.
    fn refold(&self, env_id: &str) -> Result<FoldResult> {
        let lock = self.ctx.state.lock();
        let folded = match &lock {
            Ok(_) => self.fold_env(env_id),
            Err(error) => Err(error.clone()),
        };
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id) {
            match (&folded, &mut env.refold_failure) {
                (Ok(_), failure) => *failure = None,
                (Err(error), Some(failure)) => failure.error = error.clone(),
                (Err(error), failure) => {
                    *failure = Some(RefoldFailure {
                        error: error.clone(),
                        backoff: Duration::ZERO,
                        retry_at: None,
                    })
                }
            }
        }
        folded
    }
    /// Retry `env_id`'s failed refold when it is due: on the tick after it
    /// failed, then backing off as
    /// [`crate::context::Config::team_refold_retry_backoff`] says. Until one
    /// succeeds this fails with the refold's error (section 6.4, issue #51).
    fn retry_failed_refold(&self, env_id: &str, now: Instant) -> Result<()> {
        {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            match envs.get(env_id).and_then(|e| e.refold_failure.as_ref()) {
                None => return Ok(()),
                Some(failure) if failure.retry_at.is_some_and(|at| now < at) => {
                    return Err(failure.error.clone());
                }
                Some(_) => {}
            }
        }
        let Err(error) = self.refold(env_id) else {
            return Ok(());
        };
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(failure) = envs.get_mut(env_id).and_then(|e| e.refold_failure.as_mut()) {
            let (min, max) = self.ctx.config.team_refold_retry_backoff;
            let next = if failure.backoff.is_zero() {
                min
            } else {
                (failure.backoff.as_secs_f64() * 2.0).min(max)
            };
            failure.backoff = Duration::from_secs_f64(next);
            failure.retry_at = Some(now + failure.backoff);
        }
        Err(error)
    }
    fn fold_env(&self, env_id: &str) -> Result<FoldResult> {
        #[cfg(test)]
        self.refolds_run.fetch_add(1, Ordering::SeqCst);
        let _lock = self.ctx.state.lock()?;
        let (facts, _, _) = load_facts(&self.ctx, env_id)?;
        let commits = CommitStore::new(self.ctx.state, env_id).all_commits()?;
        let fold::Refold {
            result,
            snapshot,
            record,
            stale_snapshots,
            unrecorded_snapshot,
        } = fold::fold_for_refold(
            env_id,
            commits,
            self.ctx.state,
            Some(&facts),
            Some(self.ctx.audit),
        )?;
        let (project, environment) = env_project_environment(self.ctx.state, env_id)?;
        fold::derive_local(
            &result,
            self.ctx.state,
            &self.ctx.policy,
            Some(self.ctx.audit),
            Some(&self.device),
            Some(self.ctx.kms),
            project.as_deref(),
            environment.as_deref(),
        )?;
        // `total = sum(result.vector.values())`: exact Python ints.
        let total = result
            .vector
            .values()
            .fold(PyInt::zero(), |acc, v| PyInt(acc.0 + &v.0));
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let env = envs
            .get_mut(env_id)
            .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
        env.facts = facts;
        env.document = result.document.clone();
        env.relaxed_cache = None;
        env.relaxed_generation = env.relaxed_generation.wrapping_add(1);
        // `total - env.last_snapshot_total >= SNAPSHOT_INTERVAL_COMMITS`,
        // with Python's int/float arithmetic (an `OverflowError` converting
        // a huge int for a float operand escapes `_refold`).
        let due = PyNumber::Int(total.0.clone())
            .sub(&env.last_snapshot_total)
            .ok_or_else(|| Error::state("state_corrupt").with_detail("team_snapshot"))?
            .ge_int(&SNAPSHOT_INTERVAL_COMMITS.into());
        // Stale snapshots are replaced at once, so the next refold does not
        // pass them over again (issue #35).
        if due || !stale_snapshots.is_empty() {
            fold::save_snapshot(self.ctx.state, env_id, &total, &snapshot)?;
            fold::save_snapshot_record(self.ctx.state, env_id, &total, &record)?;
            for number in stale_snapshots.iter().filter(|number| **number != total) {
                fold::remove_snapshot(self.ctx.state, env_id, number);
            }
            env.last_snapshot_total = PyNumber::Int(total.0);
        }
        // Only spares the next fold a check: a record not written is checked
        // again.
        if let Some(number) = unrecorded_snapshot {
            let _ = fold::save_snapshot_record(self.ctx.state, env_id, &number, &record);
        }
        drop(envs);
        self.record_overrides(env_id, &result.overridden)?;
        Ok(result)
    }
    fn record_overrides(&self, env_id: &str, overridden: &[Value]) -> Result<()> {
        let mine = self.device.fingerprint()?;
        let mut new = Vec::new();
        let mut snapshot = None;
        {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let Some(env) = envs.get_mut(env_id) else {
                return Ok(());
            };
            for entry in overridden {
                if entry["author"] != mine {
                    continue;
                }
                let signature = format!(
                    "{}:{}",
                    entry["hash"].as_str().unwrap_or(""),
                    entry["by_hash"].as_str().unwrap_or("")
                );
                if env.alerted_overrides.insert(signature) {
                    new.push(entry.clone());
                }
            }
            if !new.is_empty() {
                let mut values: Vec<_> = env.alerted_overrides.iter().cloned().collect();
                values.sort();
                snapshot = Some(values);
            }
        }
        let Some(snapshot) = snapshot else {
            return Ok(());
        };
        self.ctx.state.write_json(
            &format!("team/{env_id}/overridden_alerted.json"),
            &json!(snapshot),
        )?;
        for entry in new {
            let kind = entry["target_kind"].as_str().unwrap_or("");
            let target = entry["target_id"].as_str();
            let mut extra = vec![
                ("env_id", json!(env_id)),
                ("author_seq", entry["author_seq"].clone()),
                ("fingerprint", entry["by_author"].clone()),
            ];
            if kind == "secret_active" {
                extra.push(("secret_id", entry["target_id"].clone()));
            }
            let _ = self.ctx.audit.record(
                "team_op_overridden",
                RecordArgs {
                    result: Some("ok"),
                    connection: if kind == "connection" { target } else { None },
                    extra,
                    ..Default::default()
                },
            );
        }
        Ok(())
    }
    fn membership(&self, env_id: &str, fp: &str) -> Option<DeviceRecord> {
        let envs = self.envs.lock().ok()?;
        let env = envs.get(env_id)?;
        env.active_member(fp)?;
        member_device_record(&env.document, fp)
    }
    fn audit_handshake_failed(&self, reason: &str, fp: Option<&str>) {
        let _ = self.ctx.audit.record(
            "team_handshake_failed",
            RecordArgs {
                result: Some("denied"),
                reason: Some(reason),
                extra: fp.map_or_else(Vec::new, |v| vec![("fingerprint", json!(v))]),
                ..Default::default()
            },
        );
    }
    fn invite_check(&self, env_id: &str, record: &DeviceRecord, hash: &[u8], proof: &[u8]) -> bool {
        let joiner = record.fingerprint();
        let Ok(info) =
            super::membership::consume_invite_by(&self.ctx, env_id, hash, proof, Some(&joiner))
        else {
            return false;
        };
        let Some((role, name)) = info else {
            return false;
        };
        if let Ok(mut envs) = self.envs.lock() {
            if let Some(env) = envs.get_mut(env_id) {
                env.pending_invites.insert(joiner, (role, name));
                return true;
            }
        }
        false
    }
    pub fn document(&self, env_id: &str) -> Result<Value> {
        self.envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(env_id)
            .map(|e| e.document.clone())
            .ok_or_else(|| Error::not_found("team_env_unknown"))
    }
    /// `fp` is an active member as the document lists it. Sessions also
    /// refuse a device whose removal fact no refold has folded in yet
    /// ([`EnvState::active_member`]).
    pub fn is_active_member(&self, env_id: &str, fp: &str) -> bool {
        let Ok(envs) = self.envs.lock() else {
            return false;
        };
        envs.get(env_id).is_some_and(|env| {
            env.document["members"][fp]["status"] == "active"
                && member_device_record(&env.document, fp).is_some()
        })
    }
    pub fn set_peer_address(&self, env_id: &str, fp: &str, address: &str) -> Result<()> {
        if !valid_fp(fp) || address.is_empty() {
            return Err(Error::invalid_input("team_invalid_peer_address"));
        }
        {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let env = envs
                .get_mut(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
            env.candidate_addresses
                .entry(fp.into())
                .or_default()
                .insert(address.into());
        }
        self.persist_peer_address(env_id, fp, address)
    }
    /// `_persist_peer_address`: `doc = read_json(...) or {}`,
    /// `addrs = list(doc.get(fp, []))`, append if absent, write back. A truthy
    /// non-dict document (or a non-iterable entry) raises in Python; here it
    /// is `state_corrupt` and the file is left untouched (PORTING.md §3.5).
    fn persist_peer_address(&self, env_id: &str, fp: &str, address: &str) -> Result<()> {
        let _lock = self.ctx.state.lock()?;
        let path = format!("team/{env_id}/peers.json");
        let mut peers = read_dict_or_empty(self.ctx.state, &path)?;
        let mut addrs = match peers.get(fp) {
            None => Vec::new(),
            Some(value) => python_list(value)
                .ok_or_else(|| Error::state("state_corrupt").with_detail(&path))?,
        };
        if !addrs.iter().any(|v| v == address) {
            addrs.push(json!(address));
        }
        peers.insert(fp.to_owned(), Value::Array(addrs));
        self.ctx.state.write_json(&path, &Value::Object(peers))
    }
    /// `self._commit_seen.add_if_new(commit.hash)`.
    fn commit_first_seen(&self, commit: &Commit) -> bool {
        // A commit that cannot be hashed cannot be deduplicated; keep the
        // broadcast rather than silently dropping it (unreachable for a
        // commit `receive_commit`/`CommitStore` already accepted).
        let Ok(hash) = commit.hash() else {
            return true;
        };
        self.commit_seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .add_if_new(&hash)
    }
    pub fn submit_commit(&self, env_id: &str, commit: &Commit) -> Result<&'static str> {
        if !self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(env_id)
        {
            return Err(Error::invalid_input("team_env_unknown"));
        }
        let result = {
            let _lock = self.ctx.state.lock()?;
            commit::receive_commit(
                &CommitStore::new(self.ctx.state, env_id),
                commit,
                commit::now_ms(),
                Some(self.ctx.audit),
            )?
        };
        if result == "accepted" {
            // The local-commit pickup baseline is moved only by
            // `pick_up_local_commits`, as in Python: resetting it here would
            // swallow a commit another process wrote meanwhile. The seen-set
            // keeps that pickup from broadcasting this commit a second time.
            self.refold(env_id)?;
            if self.commit_first_seen(commit) {
                self.broadcast(
                    env_id,
                    &json!({"type":"COMMIT","commit":commit.to_dict()}),
                    None,
                );
            }
        }
        Ok(result)
    }
    pub fn publish_fact(&self, env_id: &str, kind: &str, target: Value) -> Result<Value> {
        let _lock = self.ctx.state.lock()?;
        let fact = self.sign_authorized_fact(env_id, kind, target)?;
        let stored = self.store_and_apply_fact(env_id, &fact)?;
        drop(_lock);
        if let Some(folded) = stored {
            self.announce_fact(env_id, &fact);
            folded?;
        }
        Ok(fact.to_dict())
    }
    /// Check that this device may author the fact, and sign it without
    /// storing it yet.
    pub(crate) fn sign_authorized_fact(
        &self,
        env_id: &str,
        kind: &str,
        target: Value,
    ) -> Result<Fact> {
        let _lock = self.ctx.state.lock()?;
        validate_fact_target(kind, &target)?;
        let fp = self.device.fingerprint()?;
        let doc = if kind == "member_removed" {
            self.role_document_for_removal(
                env_id,
                &fp,
                target["fingerprint"].as_str().unwrap_or(""),
            )?
        } else {
            crate::team::membership::load_environment(&self.ctx, env_id)?.document
        };
        if !fact_role_ok(&doc, kind, &fp, &target) {
            return Err(Error::policy_denied("team_fact_not_authorized"));
        }
        let observed = CommitStore::new(self.ctx.state, env_id).all_commits()?;
        let hlc = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let env = envs
                .get_mut(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
            for commit in observed {
                env.hlc.observe(&commit.hlc)?;
            }
            env.hlc.tick(None)
        };
        sign_fact(&self.device, env_id, kind, target, &hlc)
    }
    /// Store, apply and broadcast a fact [`Self::sign_authorized_fact`]
    /// signed.
    pub(crate) fn publish_signed_fact(&self, env_id: &str, fact: Fact) -> Result<Value> {
        let _lock = self.ctx.state.lock()?;
        let stored = self.store_and_apply_fact(env_id, &fact)?;
        drop(_lock);
        if let Some(folded) = stored {
            self.announce_fact(env_id, &fact);
            folded?;
        }
        Ok(fact.to_dict())
    }
    /// Store and apply `fact`: `None` if it was stored already, else the
    /// refold's outcome. A fact is announced even when that refold failed:
    /// it is stored, and the poll's retry folds it in (issue #51).
    fn store_and_apply_fact(&self, env_id: &str, fact: &Fact) -> Result<Option<Result<()>>> {
        if !self.store_fact(env_id, fact)? {
            return Ok(None);
        }
        if fact.kind == "member_removed"
            && let Some(fp) = fact.target["fingerprint"].as_str()
        {
            self.drain_removed(env_id, fp);
        }
        Ok(Some(self.refold(env_id).map(|_| ())))
    }
    fn announce_fact(&self, env_id: &str, fact: &Fact) {
        self.audit_fact_apply(env_id, fact);
        self.broadcast(env_id, &json!({"type":"FACT","fact":fact.to_dict()}), None);
        if fact.kind == "member_removed" && fact.target["fingerprint"].as_str().is_some() {
            self.send_removal_notice(env_id, fact, None);
        }
    }
    fn store_fact(&self, env_id: &str, fact: &Fact) -> Result<bool> {
        let hash = fact.hash()?;
        let _lock = self.ctx.state.lock()?;
        {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let env = envs
                .get(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
            if env.fact_hashes.contains(&hash) {
                return Ok(false);
            }
        }
        receipt_fact(&self.ctx, fact)?;
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let env = envs
            .get_mut(env_id)
            .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
        if env.fact_hashes.contains(&hash) {
            return Ok(false);
        }
        let line = pyjson::dumps(&fact.to_dict(), DumpOptions::compact_sorted())?;
        self.ctx
            .state
            .append_line(&format!("team/{env_id}/facts.jsonl"), &line)?;
        env.fact_hashes.insert(hash.clone());
        apply_fact(&mut env.facts, fact);
        if fact.kind == "member_removed" {
            env.pending_removal_repairs.insert(hash.clone());
            env.next_removal_repair = Instant::now();
        }
        env.known_fact_lines += 1;
        if fact.kind == "member_removed" {
            if let Some(fp) = fact.target["fingerprint"].as_str() {
                env.removal_authors
                    .entry(fp.into())
                    .or_default()
                    .insert(fact.author.clone());
            }
        }
        Ok(true)
    }
    fn defer_send(&self, env_id: &str, message: Value, exclude: Option<&str>, notice: bool) {
        let mut queue = self
            .deferred_sends
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Sends are best effort; durable commit/fact logs support catch-up.
        if queue.len() == 64 {
            queue.pop_front();
        }
        queue.push_back((env_id.into(), message, exclude.map(str::to_owned), notice));
    }
    pub(crate) fn flush_deferred_sends(&self) {
        if self.ctx.state.locked_by_current_thread() {
            return;
        }
        let queued = std::mem::take(
            &mut *self
                .deferred_sends
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        for (env, message, exclude, notice) in queued {
            if notice {
                if let Ok(fact) = Fact::from_dict(&message) {
                    self.send_removal_notice(&env, &fact, exclude.as_deref());
                }
            } else {
                self.broadcast(&env, &message, exclude.as_deref());
            }
        }
    }
    fn broadcast(&self, env_id: &str, message: &Value, exclude: Option<&str>) {
        if self.ctx.state.locked_by_current_thread() {
            self.defer_send(env_id, message.clone(), exclude, false);
            return;
        }
        let sessions = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let Some(e) = envs.get_mut(env_id) else {
                return;
            };
            let mut targets = Vec::new();
            for (fp, session) in &e.sessions {
                if Some(fp.as_str()) == exclude || e.draining.contains_key(fp) {
                    continue;
                }
                if e.catching_up.contains(fp) {
                    hold_frame(&mut e.held, fp, message);
                    continue;
                }
                targets.push((fp.clone(), session.clone()));
            }
            targets
        };
        // `_broadcast`: a failed send drops that session at once
        // (`_drop_session`: unregister, close, `team_session_close` audit).
        for (fp, session) in sessions {
            if session.send(message).is_err() {
                self.drop_session(env_id, &fp, Some(&session));
            }
        }
    }
    fn send_removal_notice(&self, env_id: &str, fact: &Fact, exclude: Option<&str>) {
        if self.ctx.state.locked_by_current_thread() {
            self.defer_send(env_id, fact.to_dict(), exclude, true);
            return;
        }
        let Some(target) = fact.target["fingerprint"].as_str() else {
            return;
        };
        if exclude == Some(target) {
            return;
        }
        // Never withheld: the target is draining, and a held frame would
        // only go out with an answer to a VECTOR a draining session no
        // longer gets.
        let notice = json!({"type":"FACT","fact":fact.to_dict()});
        let session = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(env_id)
            .and_then(|env| env.sessions.get(target))
            .cloned();
        if let Some(session) = session
            && session.send(&notice).is_err()
        {
            self.drop_session(env_id, target, Some(&session));
        }
    }

    fn drain_removed(&self, env_id: &str, fp: &str) {
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id) {
            // `_drop_member_sessions`: forget the removed peer as a dial
            // candidate entirely -- addresses and retry/backoff state.
            env.candidate_addresses.remove(fp);
            env.backoff.remove(fp);
            env.next_attempt.remove(fp);
            env.dial_pending.remove(fp);
            if env.sessions.contains_key(fp) {
                env.draining.entry(fp.into()).or_insert_with(|| {
                    Instant::now()
                        + Duration::from_secs_f64(self.ctx.config.team_removed_drain_seconds)
                });
            }
        }
    }
    pub fn synced_at(&self, env_id: &str) -> Option<String> {
        self.envs
            .lock()
            .ok()?
            .get(env_id)?
            .synced_at
            .map(|ts| iso(Some(ts)))
    }

    fn accept_session(&self, env_id: &str, session: Arc<dyn Session>, inbound: bool) -> bool {
        let fp = session.peer().fingerprint();
        let mine = self.device.fingerprint().unwrap_or_default();
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(env) = envs.get_mut(env_id) else {
            session.close();
            return false;
        };
        // A handshake that passed the membership check before the device's
        // removal fact was stored ends here: `drain_removed` drains only the
        // sessions already accepted.
        if env.facts.removed_members.contains(&fp) {
            env.pending_invites.remove(&fp);
            drop(envs);
            session.close();
            // As that membership check now would; audited once the envs lock
            // is released, as audit writes take the state lock.
            self.audit_handshake_failed("not_member", Some(&fp));
            return false;
        }
        if let Some(current) = env.sessions.get(&fp) {
            if Arc::ptr_eq(current, &session) {
                return true;
            }
            let keep_new = if mine < fp { !inbound } else { inbound };
            if !keep_new {
                session.close();
                return false;
            }
            // Replaced by a session that reached the peer: not a refused dial.
            let replaced = current.clone();
            take_dial_mark(env, &fp, &replaced);
            replaced.close();
            // The new session starts with its own VECTOR exchange.
            env.catching_up.remove(&fp);
            env.held.remove(&fp);
            env.early_commits.remove(&fp);
            env.vector_due.remove(&fp);
        }
        env.fact_replay_cursor.insert(fp.clone(), 0);
        // A device joining through an invitation has no history yet: hold
        // live broadcasts from the moment its session is visible to them.
        if inbound && env.pending_invites.contains_key(&fp) {
            env.catching_up.insert(fp.clone());
        }
        env.sessions.insert(fp, session);
        true
    }
    fn on_inbound_session(self: &Arc<Self>, session: Arc<dyn Session>) {
        let env_id = session.env_id().to_owned();
        let fp = session.peer().fingerprint();
        if !self.accept_session(&env_id, session.clone(), true) {
            return;
        }
        let pending = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get_mut(&env_id)
                .and_then(|env| env.pending_invites.remove(&fp))
        };
        if let Some((role, name)) = pending {
            if self
                .admit_member(&env_id, &session.peer(), &role, &name)
                .is_err()
            {
                let _ = self.ctx.audit.record(
                    "team_member_add",
                    RecordArgs {
                        result: Some("failed"),
                        reason: Some("team_member_admission_failed"),
                        extra: vec![("env_id", json!(env_id)), ("fingerprint", json!(fp))],
                        ..Default::default()
                    },
                );
                self.drop_session(&env_id, &fp, Some(&session));
                return;
            }
        }
        self.audit_event("team_session_open", &env_id, Some(&fp), None, None);
        self.start_receiver(env_id.clone(), session.clone());
        self.send_vector(&env_id, &session);
        // Python lets `_send_peers`'s exception (corrupt/non-dict peers.json)
        // escape `_on_inbound_session`, skipping the remaining step.
        if self.send_peers(&env_id, &session).is_err() {
            return;
        }
        self.retry_pending_incidents_to(&env_id, &session);
    }
    fn admit_member(
        &self,
        env_id: &str,
        record: &DeviceRecord,
        role: &str,
        name: &str,
    ) -> Result<()> {
        use crate::kms::WrappedKey;
        let _lock = self.ctx.state.lock()?;
        let doc = crate::team::membership::load_environment(&self.ctx, env_id)?.document;
        let mut wraps = Map::new();
        if let Some(gens) = doc["dek"]["generations"].as_object() {
            for gen_id in gens.keys() {
                let value = self
                    .ctx
                    .state
                    .read_json(&format!("team/{env_id}/dek/{gen_id}.json"), Value::Null)?;
                if value.is_null() {
                    continue;
                }
                let Ok(wrapped) = WrappedKey::from_dict(&value) else {
                    continue;
                };
                let Ok(dek) = self.ctx.kms.unwrap(&wrapped) else {
                    continue;
                };
                wraps.insert(
                    gen_id.clone(),
                    super::envelope::wrap_dek(dek.expose(), env_id, gen_id, record)?,
                );
            }
        }
        let mut op = json!({"op":"member.add","device":record.to_dict(),"name":name,"role":role});
        if !wraps.is_empty() {
            op["wraps"] = Value::Object(wraps);
        }
        crate::team::membership::author_commit(&self.ctx, Some(self), env_id, vec![op])?;
        // Python: extra={"env_id", "fingerprint", "role"} (the role is not a
        // fact/op `kind`).
        let _ = self.ctx.audit.record(
            "team_member_add",
            RecordArgs {
                result: Some("ok"),
                extra: vec![
                    ("env_id", json!(env_id)),
                    ("fingerprint", json!(record.fingerprint())),
                    ("role", json!(role)),
                ],
                ..Default::default()
            },
        );
        drop(_lock);
        self.flush_deferred_sends();
        Ok(())
    }
    /// `_start_receiver`: always a receive thread of THIS instance (Python's
    /// `self`), registered for `stop`'s bounded join.
    fn start_receiver(&self, env_id: String, session: Arc<dyn Session>) {
        let weak: Weak<Self> = self.this.clone();
        let thread = BoundedThread::spawn(move || {
            let mut heard = false;
            loop {
                let Some(this) = weak.upgrade() else {
                    break;
                };
                if this.stop.load(Ordering::SeqCst) {
                    break;
                }
                match session.recv(Duration::from_secs(1)) {
                    Ok(Some(message)) => {
                        if this.handle_message(&env_id, &session, &message).is_err() {
                            break;
                        }
                        if !heard {
                            heard = true;
                            this.confirm_dial(&env_id, &session);
                        }
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
            if let Some(this) = weak.upgrade() {
                // Before the session is dropped, so the poll loop cannot
                // redial in between (issue #14).
                this.fail_unconfirmed_dial(&env_id, &session);
                this.drop_session(&env_id, &session.peer().fingerprint(), Some(&session));
            }
        });
        let mut receivers = self.receivers.lock().unwrap_or_else(|e| e.into_inner());
        // Joining an already-finished thread is immediate in Python; pruning
        // them here only bounds this list's growth.
        receivers.retain(|t| !t.handle.is_finished());
        receivers.push(thread);
    }
    fn drop_session(&self, env_id: &str, fp: &str, expected: Option<&Arc<dyn Session>>) {
        let removed = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let Some(env) = envs.get_mut(env_id) else {
                return;
            };
            if expected.is_some_and(|wanted| {
                env.sessions
                    .get(fp)
                    .is_none_or(|current| !Arc::ptr_eq(current, wanted))
            }) {
                return;
            }
            env.draining.remove(fp);
            env.fact_replay_cursor.remove(fp);
            env.catching_up.remove(fp);
            env.held.remove(fp);
            env.early_commits.remove(fp);
            env.vector_due.remove(fp);
            env.sessions.remove(fp)
        };
        if let Some(session) = removed {
            session.close();
            self.audit_event("team_session_close", env_id, Some(fp), None, None);
        }
    }
    fn send_vector(&self, env_id: &str, session: &Arc<dyn Session>) {
        let fp = session.peer().fingerprint();
        {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if envs
                .get(env_id)
                .is_none_or(|e| e.draining.contains_key(&fp))
            {
                return;
            }
        }
        let Ok(vector) = CommitStore::new(self.ctx.state, env_id).vector() else {
            return;
        };
        if session
            .send(&json!({"type":"VECTOR","vector":vector}))
            .is_err()
        {
            self.drop_session(env_id, &fp, Some(session));
            return;
        }
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id) {
            env.vector_due.remove(&fp);
            env.last_vector_sent.insert(fp, Instant::now());
            env.synced_at = Some((self.ctx.clock)());
        }
    }
    /// The VECTORs early commits asked for (issue #28), once the peer was not
    /// asked within [`EARLY_VECTOR_INTERVAL`] and no commit was accepted
    /// within [`EARLY_QUIET`].
    fn send_due_vectors(&self, env_id: &str, now: Instant) {
        let due = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let Some(env) = envs.get(env_id) else {
                return;
            };
            if env
                .last_accepted
                .is_some_and(|at| now.saturating_duration_since(at) < EARLY_QUIET)
            {
                return;
            }
            env.vector_due
                .iter()
                .filter(|fp| {
                    env.last_vector_sent.get(*fp).is_none_or(|at| {
                        now.saturating_duration_since(*at) >= EARLY_VECTOR_INTERVAL
                    })
                })
                .filter_map(|fp| env.sessions.get(fp).cloned())
                .collect::<Vec<_>>()
        };
        for session in due {
            self.send_vector(env_id, &session);
        }
    }
    /// `_send_peers`: only list-valued entries, each reduced to its sorted
    /// string addresses. A corrupt or non-dict `peers.json` is an error the
    /// caller stops on, as Python's escaping exception does.
    fn send_peers(&self, env_id: &str, session: &Arc<dyn Session>) -> Result<()> {
        let fp = session.peer().fingerprint();
        {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if envs
                .get(env_id)
                .is_some_and(|e| e.draining.contains_key(&fp))
            {
                return Ok(());
            }
        }
        let peers_doc = read_dict_or_empty(self.ctx.state, &format!("team/{env_id}/peers.json"))?;
        let mut payload = Map::new();
        for (peer_fp, addrs) in peers_doc {
            let Value::Array(addrs) = addrs else {
                continue;
            };
            let mut strings: Vec<String> = addrs
                .into_iter()
                .filter_map(|a| match a {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .collect();
            // Python's `sorted()` on str orders by code point, which is
            // exactly UTF-8 byte order.
            strings.sort();
            payload.insert(peer_fp, json!(strings));
        }
        if session
            .send(&json!({"type":"PEERS","peers":payload}))
            .is_err()
        {
            self.drop_session(env_id, &fp, Some(session));
        }
        Ok(())
    }
    fn handle_message(
        &self,
        env_id: &str,
        session: &Arc<dyn Session>,
        message: &Value,
    ) -> Result<()> {
        let mtype = message["type"].as_str().unwrap_or("");
        let fp = session.peer().fingerprint();
        let draining = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .is_some_and(|e| e.draining.contains_key(&fp))
        };
        if draining {
            let reciprocal = {
                let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
                let target = message["fact"]["target"]["fingerprint"]
                    .as_str()
                    .unwrap_or("");
                message["fact"]["author"] == fp
                    && (target == fp
                        || envs
                            .get(env_id)
                            .and_then(|e| e.removal_authors.get(&fp))
                            .is_some_and(|authors| authors.contains(target)))
            };
            if mtype == "FACT" && message["fact"]["kind"] == "member_removed" && reciprocal {
                self.handle_fact(env_id, session, message)?;
            } else if mtype == "FACT"
                && let Ok(fact) = Fact::from_dict(&message["fact"])
            {
                self.audit_fact_rejected(env_id, &fact, "team_fact_not_authorized");
            }
            return Ok(());
        }
        match mtype {
            "VECTOR" => self.handle_vector(env_id, session, message)?,
            "COMMIT" => self.handle_commit(env_id, session, message)?,
            "FACT" => self.handle_fact(env_id, session, message)?,
            "PEERS" => self.handle_peers(env_id, message),
            "INCIDENT" => self.handle_incident(env_id, session, message)?,
            "INCIDENT_ACK" => self.handle_incident_ack(env_id, message)?,
            _ => {}
        }
        Ok(())
    }
    fn handle_vector(
        &self,
        env_id: &str,
        session: &Arc<dyn Session>,
        message: &Value,
    ) -> Result<()> {
        let Some(vector) = message["vector"].as_object() else {
            return Ok(());
        };
        let fp = session.peer().fingerprint();
        // `isinstance(v, int) and not isinstance(v, bool) and v >= 0`, exact.
        let clean: BTreeMap<String, PyInt> = vector
            .iter()
            .filter_map(|(k, v)| {
                PyInt::from_json_integer(v)
                    .filter(|n| n.0.sign() != num_bigint::Sign::Minus)
                    .map(|n| (k.clone(), n))
            })
            .collect();
        {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(env) = envs.get_mut(env_id) {
                env.peer_vectors.insert(fp.clone(), clean);
            }
        }
        self.persist_peer_vectors(env_id)?;
        let store = CommitStore::new(self.ctx.state, env_id);
        let local = store.vector()?;
        let mut missing = Vec::new();
        for (author, last) in local {
            // `their_seq = peer_vector.get(fp, 0)`, reset to 0 unless a
            // non-negative non-bool int; `range(their_seq + 1, last_seq + 1)`
            // is empty for any claim at or past `last_seq`, however large.
            let their = vector
                .get(&author)
                .and_then(PyInt::from_json_integer)
                .filter(|n| n.0.sign() != num_bigint::Sign::Minus);
            let mut seq = match their {
                None => PyInt::from(1),
                Some(n) => &n + 1,
            };
            while seq <= last {
                if let Some(commit) = store.get(&author, &seq)? {
                    missing.push(commit);
                }
                seq = &seq + 1;
            }
        }
        // In total order across authors, so the peer learns each member's
        // admission before that member's own commits (issue #28).
        let mut sent = 0;
        for commit in commit::sort_total_order(missing)? {
            // A device removed meanwhile gets nothing more (section 4.4).
            if self.draining(env_id, &fp) {
                self.end_hold(env_id, &fp);
                break;
            }
            if session
                .send(&json!({"type":"COMMIT","commit":commit.to_dict()}))
                .is_err()
            {
                self.drop_session(env_id, &fp, Some(session));
                return Ok(());
            }
            sent += 1;
        }
        if sent > 0 {
            self.audit_event("team_sync_vector", env_id, Some(&fp), None, Some(sent));
        }
        if self.draining(env_id, &fp) {
            self.end_hold(env_id, &fp);
            return Ok(());
        }
        // Ordinary facts have no sequence in the commit vector. Replay a
        // bounded slice after missing commits on this authenticated session;
        // otherwise an offline disable/revoke can be lost permanently.
        self.send_fact_catchup(env_id, session)?;
        if let Some(env) = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(env_id)
        {
            env.synced_at = Some((self.ctx.clock)());
        }
        // A joiner now holds the history in order. Send what was held for it
        // meanwhile, in order, and release it only once nothing is left, so
        // no live frame overtakes a held one.
        loop {
            let frames = {
                let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
                let Some(env) = envs.get_mut(env_id) else {
                    return Ok(());
                };
                if !env.catching_up.contains(&fp)
                    || env
                        .sessions
                        .get(&fp)
                        .is_none_or(|current| !Arc::ptr_eq(current, session))
                {
                    return Ok(());
                }
                // Removed meanwhile: none of what was held goes out.
                if env.draining.contains_key(&fp) {
                    env.catching_up.remove(&fp);
                    env.held.remove(&fp);
                    return Ok(());
                }
                match env.held.remove(&fp) {
                    Some(frames) if !frames.is_empty() => frames,
                    _ => {
                        env.catching_up.remove(&fp);
                        break;
                    }
                }
            };
            for frame in frames {
                if self.draining(env_id, &fp) {
                    self.end_hold(env_id, &fp);
                    return Ok(());
                }
                if session.send(&frame).is_err() {
                    self.drop_session(env_id, &fp, Some(session));
                    return Ok(());
                }
            }
        }
        self.retry_pending_incidents_to(env_id, session);
        Ok(())
    }
    /// Forget what was held for `fp`: a removed device gets none of it.
    fn end_hold(&self, env_id: &str, fp: &str) {
        if let Some(env) = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(env_id)
        {
            env.catching_up.remove(fp);
            env.held.remove(fp);
        }
    }
    fn draining(&self, env_id: &str, fp: &str) -> bool {
        self.envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(env_id)
            .is_some_and(|env| env.draining.contains_key(fp))
    }
    fn current_fact_session(&self, env_id: &str, fp: &str, session: &Arc<dyn Session>) -> bool {
        let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        envs.get(env_id).is_some_and(|env| {
            !env.draining.contains_key(fp)
                && env.document["members"][fp]["status"] == "active"
                && env
                    .sessions
                    .get(fp)
                    .is_some_and(|current| Arc::ptr_eq(current, session))
        })
    }
    fn send_fact_catchup(&self, env_id: &str, session: &Arc<dyn Session>) -> Result<()> {
        let fp = session.peer().fingerprint();
        if !self.current_fact_session(env_id, &fp, session) {
            return Ok(());
        }
        let lines = self
            .ctx
            .state
            .read_lines(&format!("team/{env_id}/facts.jsonl"), None)?;
        let start = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .and_then(|env| env.fact_replay_cursor.get(&fp))
                .copied()
                .unwrap_or(0)
                .min(lines.len())
        };
        let end = start
            .saturating_add(FACT_REPLAY_LINES_PER_VECTOR)
            .min(lines.len());
        let mut relaxed: Option<Option<Arc<Value>>> = None;
        for line in lines.get(start..end).unwrap_or_default() {
            let Ok(value) = pyjson::loads(line) else {
                continue;
            };
            let Ok(fact) = Fact::from_dict(&value) else {
                continue;
            };
            if fact.env_id != env_id || fact.kind == "incident" {
                continue;
            }
            // One relaxed-document lookup per replay pass (not per line):
            // resolved lazily, so a pass with nothing to verify folds nothing.
            let relaxed = relaxed.get_or_insert_with(|| self.relaxed_document(env_id).ok());
            let Some(author) = relaxed
                .as_deref()
                .and_then(|doc| member_device_record(doc, &fact.author))
            else {
                continue;
            };
            if !verify_fact(&fact, &author) {
                continue;
            }
            if !self.current_fact_session(env_id, &fp, session) {
                return Ok(());
            }
            if session
                .send(&json!({"type":"FACT","fact":fact.to_dict()}))
                .is_err()
            {
                self.drop_session(env_id, &fp, Some(session));
                return Ok(());
            }
        }
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id)
            && env
                .sessions
                .get(&fp)
                .is_some_and(|current| Arc::ptr_eq(current, session))
        {
            env.fact_replay_cursor
                .insert(fp, if end == lines.len() { 0 } else { end });
        }
        Ok(())
    }
    fn persist_peer_vectors(&self, env_id: &str) -> Result<()> {
        let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(env) = envs.get(env_id) else {
            return Ok(());
        };
        self.ctx.state.write_json(
            &format!("team/{env_id}/peer_vectors.json"),
            &json!(env.peer_vectors),
        )
    }
    fn handle_commit(
        &self,
        env_id: &str,
        session: &Arc<dyn Session>,
        message: &Value,
    ) -> Result<()> {
        let commit = match Commit::from_dict(&message["commit"]) {
            Ok(commit) => commit,
            Err(error) if error.is(crate::errors::ErrorClass::InvalidInput) => return Ok(()),
            Err(error) => {
                // A built-in exception escaping `Commit.from_dict` (an
                // infinite `author_seq`/`seen` value) ends the receive loop
                // at once. For an op with a non-string key, Python's
                // `from_dict` succeeded: another environment's commit is
                // ignored, and for this one `receive_commit` raises while
                // hashing or verifying it -- before any rejected record or
                // audit -- which ends the receive loop.
                if commit::raises_only_when_canonicalized(&error)
                    && commit::python_str_coerce(&message["commit"]["env_id"]) != env_id
                {
                    return Ok(());
                }
                return Err(error);
            }
        };
        if commit.env_id != env_id {
            return Ok(());
        }
        let receive = |live: bool| -> Result<&'static str> {
            let _lock = self.ctx.state.lock()?;
            let store = CommitStore::new(self.ctx.state, env_id);
            if live {
                commit::receive_live_commit(&store, &commit, commit::now_ms(), Some(self.ctx.audit))
            } else {
                commit::receive_commit(&store, &commit, commit::now_ms(), Some(self.ctx.audit))
            }
        };
        let mut outcome = receive(true)?;
        if outcome == "early" {
            if !self.early_commit_quarantined(env_id, session, &commit)? {
                return Ok(());
            }
            outcome = receive(false)?;
        }
        self.after_receipt(env_id, &commit, outcome)?;
        if outcome == "accepted" {
            // As in `submit_commit`: the pickup baseline is left alone and the
            // seen-set gates the (single) rebroadcast.
            self.refold(env_id)?;
            if self.commit_first_seen(&commit) {
                self.broadcast(
                    env_id,
                    &json!({"type":"COMMIT","commit":commit.to_dict()}),
                    Some(&session.peer().fingerprint()),
                );
            }
        }
        Ok(())
    }
    /// Whether a commit that arrived before its history (issue #28) is
    /// quarantined after all. The first time a peer sends it, the poll loop
    /// asks that peer for the missing range ([`TeamSync::send_due_vectors`]),
    /// which it sends again in total order. Sent early again after that
    /// request, the history is gone from that peer -- compacted (section 7.3)
    /// -- and the commit is quarantined as before, unless what it waits for
    /// sits in `deferred/` here; so is one beyond [`EARLY_COMMITS_PER_PEER`]
    /// commits waiting from that peer.
    fn early_commit_quarantined(
        &self,
        env_id: &str,
        session: &Arc<dyn Session>,
        commit: &Commit,
    ) -> Result<bool> {
        let fp = session.peer().fingerprint();
        let hash = commit.hash()?;
        // A deferred/ entry released or corrupted while this reads it is no
        // reason to drop the session: the commit keeps waiting, and the
        // sender is marked due, to be asked for the range once deferred/
        // reads again (section 5.4).
        let (deferred, ask) =
            match commit::waits_on_deferred(&CommitStore::new(self.ctx.state, env_id), commit) {
                Ok(deferred) => (deferred, !deferred),
                Err(_) => (true, true),
            };
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(env) = envs.get_mut(env_id) else {
            return Ok(false);
        };
        let asked = env.last_vector_sent.get(&fp).copied();
        let waiting = env.early_commits.entry(fp.clone()).or_default();
        match waiting.get(&hash) {
            Some(first) if !deferred && asked.is_some_and(|at| at > *first) => {
                waiting.remove(&hash);
                return Ok(true);
            }
            Some(_) => {}
            None if waiting.len() >= EARLY_COMMITS_PER_PEER => return Ok(true),
            None => {
                waiting.insert(hash, Instant::now());
            }
        }
        if ask {
            env.vector_due.insert(fp);
        }
        Ok(false)
    }
    /// A received commit that is no longer early: forget it, and note an
    /// acceptance for [`EARLY_QUIET`].
    fn after_receipt(&self, env_id: &str, commit: &Commit, outcome: &str) -> Result<()> {
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(env) = envs.get_mut(env_id) else {
            return Ok(());
        };
        if outcome == "accepted" {
            env.last_accepted = Some(Instant::now());
        }
        if !env.early_commits.is_empty() {
            let hash = commit.hash()?;
            for waiting in env.early_commits.values_mut() {
                waiting.remove(&hash);
            }
            env.early_commits.retain(|_, waiting| !waiting.is_empty());
        }
        Ok(())
    }
    /// `_relaxed_document`, including its store-vector-keyed cache: while no
    /// commit has changed the vector and no `_refold` has run since, the
    /// previous fold is reused instead of re-folding the whole commit log
    /// (one lookup per replayed/received fact and per incident).
    fn relaxed_document(&self, env_id: &str) -> Result<Arc<Value>> {
        let vector_key = CommitStore::new(self.ctx.state, env_id).vector()?;
        let (mut facts, generation) = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let env = envs
                .get(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
            if let Some((cached_key, cached)) = &env.relaxed_cache
                && *cached_key == vector_key
            {
                return Ok(cached.clone());
            }
            (env.facts.clone(), env.relaxed_generation)
        };
        facts.removed_members.clear();
        #[cfg(test)]
        self.relaxed_folds.fetch_add(1, Ordering::SeqCst);
        let document = Arc::new(
            fold::fold(
                env_id,
                CommitStore::new(self.ctx.state, env_id).all_commits()?,
                Some(&facts),
                None,
                None,
                None,
            )?
            .document,
        );
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id)
            && env.relaxed_generation == generation
        {
            env.relaxed_cache = Some((vector_key, document.clone()));
        }
        Ok(document)
    }
    /// `_known_device_record`.
    fn known_record(&self, env_id: &str, fp: &str) -> Option<DeviceRecord> {
        member_device_record(self.relaxed_document(env_id).ok()?.as_ref(), fp)
    }
    fn role_document_for_removal(&self, env_id: &str, author: &str, target: &str) -> Result<Value> {
        let (mut facts, _, authors) = load_facts(&self.ctx, env_id)?;
        if facts.removed_members.contains(author)
            && authors
                .get(author)
                .is_some_and(|set| set.len() == 1 && set.contains(target))
        {
            facts.removed_members.remove(author);
        }
        Ok(fold::fold(
            env_id,
            CommitStore::new(self.ctx.state, env_id).all_commits()?,
            Some(&facts),
            None,
            None,
            None,
        )?
        .document)
    }
    fn validate_incoming_fact(&self, env_id: &str, fact: &Fact) -> Result<bool> {
        let hash = fact.hash()?;
        {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if envs
                .get(env_id)
                .is_none_or(|e| e.fact_hashes.contains(&hash))
            {
                return Ok(false);
            }
        }
        if validate_fact_target(&fact.kind, &fact.target).is_err() {
            self.audit_fact_rejected(env_id, fact, "team_fact_target_invalid");
            return Ok(false);
        }
        let Some(record) = self.known_record(env_id, &fact.author) else {
            self.audit_fact_rejected(env_id, fact, "team_fact_signature_invalid");
            return Ok(false);
        };
        if !verify_fact(fact, &record) {
            self.audit_fact_rejected(env_id, fact, "team_fact_signature_invalid");
            return Ok(false);
        }
        let doc = if fact.kind == "member_removed" {
            self.role_document_for_removal(
                env_id,
                &fact.author,
                fact.target["fingerprint"].as_str().unwrap_or(""),
            )?
        } else {
            crate::team::membership::load_environment(&self.ctx, env_id)?.document
        };
        if !fact_role_ok(&doc, &fact.kind, &fact.author, &fact.target) {
            self.audit_fact_rejected(env_id, fact, "team_fact_not_authorized");
            return Ok(false);
        }
        Ok(true)
    }
    fn repair_member_removals(&self, env_id: &str) -> Result<()> {
        let pending = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let Some(env) = envs.get(env_id) else {
                return Ok(());
            };
            let current = env.document["dek"]["current"].as_str().unwrap_or("");
            let unsafe_current = env.document["dek"]["generations"][current]["wraps"]
                .as_object()
                .is_some_and(|wraps| {
                    env.document["members"].as_object().is_some_and(|members| {
                        members.iter().any(|(fp, member)| {
                            member["status"] != "active" && wraps.contains_key(fp)
                        })
                    })
                });
            if (env.pending_removal_repairs.is_empty() && !unsafe_current)
                || Instant::now() < env.next_removal_repair
            {
                return Ok(());
            }
            env.pending_removal_repairs.clone()
        };
        let doc = self.document(env_id)?;
        if !is_admin(&doc, &self.device.fingerprint()?) {
            return Ok(());
        }
        let result =
            crate::team::membership::ensure_removal_rotations(&self.ctx, Some(self), env_id);
        {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(env) = envs.get_mut(env_id) {
                if result.is_ok() {
                    env.pending_removal_repairs
                        .retain(|hash| !pending.contains(hash));
                } else {
                    env.next_removal_repair = Instant::now() + Duration::from_secs(1);
                }
            }
        }
        if result.is_err() {
            let _ = self.ctx.audit.record(
                "team_dek_rotate",
                RecordArgs {
                    result: Some("failed"),
                    reason: Some("team_rekey_repair_failed"),
                    extra: vec![("env_id", json!(env_id))],
                    ..Default::default()
                },
            );
        }
        Ok(())
    }
    fn handle_fact(&self, env_id: &str, session: &Arc<dyn Session>, message: &Value) -> Result<()> {
        let _lock = self.ctx.state.lock()?;
        let Ok(fact) = Fact::from_dict(&message["fact"]) else {
            return Ok(());
        };
        if fact.env_id != env_id
            || fact.kind == "incident"
            || !FACT_KINDS.contains(&fact.kind.as_str())
        {
            return Ok(());
        }
        if self.validate_incoming_fact(env_id, &fact)? && self.store_fact(env_id, &fact)? {
            if fact.kind == "member_removed"
                && let Some(fp) = fact.target["fingerprint"].as_str()
            {
                self.drain_removed(env_id, fp);
            }
            let folded = self.refold(env_id);
            drop(_lock);
            // Even when that refold failed: the fact is stored, and the
            // poll's retry folds it in (issue #51).
            self.audit_fact_apply(env_id, &fact);
            self.broadcast(
                env_id,
                &json!({"type":"FACT","fact":fact.to_dict()}),
                Some(&session.peer().fingerprint()),
            );
            if fact.kind == "member_removed" {
                if fact.target["fingerprint"].as_str().is_some() {
                    self.send_removal_notice(env_id, &fact, Some(&session.peer().fingerprint()));
                }
            }
            folded?;
        }
        Ok(())
    }
    fn handle_peers(&self, env_id: &str, message: &Value) {
        let Some(peers) = message["peers"].as_object() else {
            return;
        };
        let mine = self.device.fingerprint().unwrap_or_default();
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(env) = envs.get_mut(env_id) else {
            return;
        };
        for (fp, addrs) in peers {
            if fp == &mine || env.active_member(fp).is_none() {
                continue;
            }
            if let Some(addrs) = addrs.as_array() {
                let bucket = env.candidate_addresses.entry(fp.clone()).or_default();
                for addr in addrs {
                    if let Some(s) = addr.as_str() {
                        if !s.is_empty() && s.len() <= 128 {
                            bucket.insert(s.into());
                        }
                    }
                }
            }
        }
    }
    fn audit_event(
        &self,
        event: &str,
        env_id: &str,
        fp: Option<&str>,
        kind: Option<&str>,
        count: Option<usize>,
    ) {
        let mut extra = vec![("env_id", json!(env_id))];
        if let Some(fp) = fp {
            extra.push(("fingerprint", json!(fp)));
        }
        if let Some(kind) = kind {
            extra.push(("kind", json!(kind)));
        }
        if let Some(count) = count {
            extra.push(("commits", json!(count)));
        }
        let _ = self.ctx.audit.record(
            event,
            RecordArgs {
                result: Some("ok"),
                extra,
                ..Default::default()
            },
        );
    }
    fn audit_fact_apply(&self, env_id: &str, fact: &Fact) {
        self.audit_event(
            "team_fact_apply",
            env_id,
            Some(&fact.author),
            Some(&fact.kind),
            None,
        );
    }
    fn record_removal_conflict(&self, env_id: &str, fact: &Fact) -> Result<()> {
        if validate_fact_target(&fact.kind, &fact.target).is_err() {
            return Ok(());
        }
        let Some(record) = self.known_record(env_id, &fact.author) else {
            return Ok(());
        };
        if !verify_fact(fact, &record) {
            return Ok(());
        }
        let target = fact.target["fingerprint"].as_str().unwrap_or("");
        if self.known_record(env_id, target).is_none() {
            return Ok(());
        }
        let _lock = self.ctx.state.lock()?;
        let path = format!("team/{env_id}/removal_conflicts.json");
        let mut values = self.ctx.state.read_json(&path, json!({}))?;
        let map = values
            .as_object_mut()
            .ok_or_else(|| Error::state("state_corrupt"))?;
        map.insert(
            target.into(),
            json!({"target":target,"author":fact.author,"hash":fact.hash()?}),
        );
        self.ctx.state.write_json(&path, &values)
    }

    fn audit_fact_rejected(&self, env_id: &str, fact: &Fact, reason: &str) {
        if reason == "team_fact_not_authorized" && fact.kind == "member_removed" {
            let _ = self.record_removal_conflict(env_id, fact);
        }
        let _ = self.ctx.audit.record(
            "team_fact_rejected",
            RecordArgs {
                result: Some("denied"),
                reason: Some(reason),
                extra: vec![
                    ("env_id", json!(env_id)),
                    ("kind", json!(fact.kind)),
                    ("fingerprint", json!(fact.author)),
                ],
                ..Default::default()
            },
        );
    }

    fn handle_incident(
        &self,
        env_id: &str,
        session: &Arc<dyn Session>,
        message: &Value,
    ) -> Result<()> {
        let Ok(fact) = Fact::from_dict(&message["fact"]) else {
            return Ok(());
        };
        if fact.env_id != env_id
            || fact.kind != "incident"
            || fact.author != session.peer().fingerprint()
        {
            return Ok(());
        }
        // `author_record is None or not verify_fact(...)`: an unknown author is
        // audited exactly like a bad signature.
        if !self
            .known_record(env_id, &fact.author)
            .is_some_and(|record| verify_fact(&fact, &record))
        {
            self.audit_fact_rejected(env_id, &fact, "team_fact_signature_invalid");
            return Ok(());
        }
        let doc = self.document(env_id)?;
        if !fact_role_ok(&doc, "incident", &fact.author, &fact.target) {
            self.audit_fact_rejected(env_id, &fact, "team_fact_not_authorized");
            return Ok(());
        }
        if !is_admin(&doc, &self.device.fingerprint()?) {
            return Ok(());
        }
        let id = fact.target["incident_id"].as_str().unwrap_or("");
        if !valid_token(id) {
            return Ok(());
        }
        let path = format!("team/{env_id}/incidents/{}-{id}.json", fact.author);
        if !self.ctx.state.exists(&path) {
            // A retry must reconstruct a missing incident record even when a
            // prior attempt already persisted the fact before failing here.
            let _newly_stored = self.store_fact(env_id, &fact)?;
            let mut rec = fact.target.clone();
            rec["received_from"] = json!(fact.author);
            rec["received_at"] = json!(iso(Some((self.ctx.clock)())));
            self.ctx.state.write_json(&path, &rec)?;
            self.apply_incident_rotation_flags(env_id, &fact.target)?;
            self.audit_event(
                "team_incident_received",
                env_id,
                Some(&fact.author),
                None,
                None,
            );
        }
        if session
            .send(&json!({"type":"INCIDENT_ACK","hash":fact.hash()?}))
            .is_err()
        {
            self.drop_session(env_id, &session.peer().fingerprint(), Some(session));
        }
        Ok(())
    }
    fn apply_incident_rotation_flags(&self, env_id: &str, target: &Value) -> Result<()> {
        let mandatory: Vec<&str> = target["secret_ids_mandatory"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let recommended: Vec<&str> = target["secret_ids_recommended"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let _lock = self.ctx.state.lock()?;
        let path = format!("team/{env_id}/rotation_flags.json");
        let corrupt = || Error::state("state_corrupt").with_detail(&path);
        // `flags = read_json(...) or {}`. On a truthy non-dict Python's item
        // assignment / `.get` raises uncaught (§3.5: `state_corrupt`), but
        // only once there is a secret id to flag; with none it writes the
        // document back unchanged.
        let mut flags = match self.ctx.state.read_json(&path, json!({}))? {
            Value::Object(map) => map,
            other if super::json_falsy(&other) => Map::new(),
            other if mandatory.is_empty() && recommended.is_empty() => {
                return self.ctx.state.write_json(&path, &other);
            }
            _ => return Err(corrupt()),
        };
        let now = iso(Some((self.ctx.clock)()));
        for id in mandatory {
            flags.insert(
                id.to_owned(),
                json!({"reason":"rotation_required","flagged_at":now}),
            );
        }
        for id in recommended {
            // `flags.get(id, {}).get("reason")`: a present non-dict entry
            // raises in Python.
            let required = match flags.get(id) {
                None => false,
                Some(Value::Object(entry)) => entry
                    .get("reason")
                    .is_some_and(|reason| reason == "rotation_required"),
                Some(_) => return Err(corrupt()),
            };
            if !required {
                flags.insert(
                    id.to_owned(),
                    json!({"reason":"rotation_recommended","flagged_at":now}),
                );
            }
        }
        self.ctx.state.write_json(&path, &Value::Object(flags))
    }
    fn handle_incident_ack(&self, env_id: &str, message: &Value) -> Result<()> {
        let Some(hash) = message["hash"].as_str() else {
            return Ok(());
        };
        let found = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(env) = envs.get_mut(env_id) {
                env.incident_backoff.remove(hash);
                env.incident_next_attempt.remove(hash);
                env.incident_outbox.remove(hash).is_some()
            } else {
                false
            }
        };
        if found {
            self.persist_incident_outbox(env_id)?;
        }
        Ok(())
    }
    fn persist_incident_outbox(&self, env_id: &str) -> Result<()> {
        let facts = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .map(|e| e.incident_outbox.values().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        };
        let mut lines = Vec::new();
        for fact in facts {
            lines.push(pyjson::dumps(
                &fact.to_dict(),
                DumpOptions::compact_sorted(),
            )?);
        }
        let blob = if lines.is_empty() {
            String::new()
        } else {
            lines.join("\n") + "\n"
        };
        self.ctx.state.write_bytes(
            &format!("team/{env_id}/incident_outbox.jsonl"),
            blob.as_bytes(),
        )
    }
    fn deliver_incident(&self, env_id: &str, fact: &Fact) -> usize {
        let mine = self.device.fingerprint().unwrap_or_default();
        let sessions = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .map(|e| {
                    e.sessions
                        .iter()
                        .filter(|(fp, _)| {
                            *fp != &mine
                                && !e.draining.contains_key(*fp)
                                && !e.catching_up.contains(*fp)
                                && is_admin(&e.document, fp)
                        })
                        .map(|(_, s)| s.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        let mut sent = 0;
        for session in sessions {
            if session
                .send(&json!({"type":"INCIDENT","fact":fact.to_dict()}))
                .is_ok()
            {
                sent += 1;
            } else {
                self.drop_session(env_id, &session.peer().fingerprint(), Some(&session));
            }
        }
        sent
    }
    pub fn send_incident(&self, env_id: &str, summary: &Value) -> Result<Value> {
        let clean = sanitize_incident_summary(summary)?;
        let doc = self.document(env_id)?;
        if !fact_role_ok(&doc, "incident", &self.device.fingerprint()?, &clean) {
            return Err(Error::policy_denied("team_fact_not_authorized"));
        }
        let hlc = {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get_mut(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?
                .hlc
                .tick(None)
        };
        let fact = sign_fact(&self.device, env_id, "incident", clean, &hlc)?;
        // An outbox entry still needs delivery/retry even if this signed fact
        // was already persisted by an earlier attempt.
        let _newly_stored = self.store_fact(env_id, &fact)?;
        let hash = fact.hash()?;
        {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let env = envs
                .get_mut(env_id)
                .ok_or_else(|| Error::invalid_input("team_env_unknown"))?;
            env.incident_outbox.insert(hash.clone(), fact.clone());
            env.incident_backoff.remove(&hash);
            env.incident_next_attempt.remove(&hash);
        }
        self.persist_incident_outbox(env_id)?;
        self.deliver_incident(env_id, &fact);
        let mut result = fact.to_dict();
        result["hash"] = json!(hash);
        Ok(result)
    }
    pub fn send_incident_for_all_envs(&self, summaries: &Value) -> Value {
        let mut result = Map::new();
        if let Some(entries) = summaries.as_object() {
            for (env, summary) in entries {
                let status = match self.send_incident(env, summary) {
                    Ok(_) => "queued".into(),
                    Err(e) => format!("error:{}", e.reason),
                };
                result.insert(env.clone(), json!(status));
            }
        }
        Value::Object(result)
    }
    pub fn on_incident_open(&self, summaries: &Value) -> Value {
        self.send_incident_for_all_envs(summaries)
    }
    fn retry_pending_incidents_to(&self, env_id: &str, session: &Arc<dyn Session>) {
        let fp = session.peer().fingerprint();
        let pending = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .filter(|e| {
                    !e.draining.contains_key(&fp)
                        && !e.catching_up.contains(&fp)
                        && is_admin(&e.document, &fp)
                })
                .map(|e| e.incident_outbox.values().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        };
        for fact in pending {
            if self.draining(env_id, &fp) {
                break;
            }
            if session
                .send(&json!({"type":"INCIDENT","fact":fact.to_dict()}))
                .is_err()
            {
                self.drop_session(env_id, &fp, Some(session));
                break;
            }
        }
    }
    fn poll_incident_outbox(&self, env_id: &str, now: Instant) {
        let due = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .map(|e| {
                    e.incident_outbox
                        .iter()
                        .filter(|(h, _)| {
                            e.incident_next_attempt.get(*h).is_none_or(|at| now >= *at)
                        })
                        .map(|(h, f)| (h.clone(), f.clone()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        for (hash, fact) in due {
            self.deliver_incident(env_id, &fact);
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(env) = envs.get_mut(env_id) {
                if !env.incident_outbox.contains_key(&hash) {
                    continue;
                }
                let (min, max) = self.ctx.config.team_incident_retry_backoff;
                let next = env
                    .incident_backoff
                    .get(&hash)
                    .map_or(min, |d| (d.as_secs_f64() * 2.0).min(max));
                let dur = Duration::from_secs_f64(next);
                env.incident_backoff.insert(hash.clone(), dur);
                env.incident_next_attempt.insert(hash, now + dur);
            }
        }
    }

    /// One poll tick. An environment that fails holds up no other (section
    /// 6.4): each is polled, and the first error is returned.
    pub fn poll(&self) -> Result<()> {
        self.flush_deferred_sends();
        let now = Instant::now();
        let mut failed = None;
        {
            let mut last = self
                .last_discovery
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if now.duration_since(*last) > Duration::from_secs(1) {
                *last = now;
                drop(last);
                failed = self.discover().err();
            }
        }
        for id in self.known_envs() {
            let polled = self.poll_env(&id, now);
            self.note_poll_failure(&id, polled.as_ref().err());
            if let Err(error) = polled {
                failed.get_or_insert(error);
            }
        }
        self.flush_deferred_sends();
        failed.map_or(Ok(()), Err)
    }
    fn poll_env(&self, env_id: &str, now: Instant) -> Result<()> {
        let advanced = self.advance_env(env_id, now);
        let (close, had_session) = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let Some(env) = envs.get(env_id) else {
                return advanced.and_then(|owed| owed.map_or(Ok(()), Err));
            };
            let max_age = Duration::from_secs_f64(self.ctx.config.team_session_max_age_seconds);
            let close = env
                .sessions
                .iter()
                .filter(|(fp, s)| {
                    s.is_closed()
                        || env
                            .draining
                            .get(*fp)
                            .is_some_and(|deadline| now >= *deadline)
                        || now.duration_since(s.created_at()) >= max_age
                })
                .map(|(fp, _)| fp.clone())
                .collect::<Vec<_>>();
            (close, env.sessions.keys().cloned().collect::<HashSet<_>>())
        };
        for fp in close {
            self.drop_session(env_id, &fp, None);
        }
        // Until a failed step succeeds, this poll dials no one and sends no
        // VECTOR (section 6.4), but its due sessions are closed above all the
        // same, so a drained device's window stays bounded (section 4.4).
        let owed = advanced?;
        // Before the periodic VECTORs are picked, so a peer due both ways
        // gets one.
        self.send_due_vectors(env_id, now);
        let (dial, send) = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let Some(env) = envs.get(env_id) else {
                return owed.map_or(Ok(()), Err);
            };
            let mine = self.device.fingerprint()?;
            let dial = env.document["members"]
                .as_object()
                .into_iter()
                .flat_map(|m| m.iter())
                .filter(|(fp, _)| {
                    *fp != &mine
                        && env.active_member(fp).is_some()
                        // Nor one whose session closed above: it is redialed
                        // from the next tick, once that session's receiver has
                        // counted a refused dial (issue #14).
                        && !had_session.contains(*fp)
                        && !env.sessions.contains_key(*fp)
                        && env
                            .candidate_addresses
                            .get(*fp)
                            .is_some_and(|a| !a.is_empty())
                        && env.next_attempt.get(*fp).is_none_or(|at| now >= *at)
                })
                .map(|(fp, _)| fp.clone())
                .collect::<Vec<_>>();
            let interval = self
                .ctx
                .config
                .team_sync_interval_seconds
                .unwrap_or_else(|| {
                    env.document["settings"]["sync_interval_seconds"]
                        .as_f64()
                        .filter(|v| *v > 0.0)
                        .unwrap_or(fold::DEFAULT_SYNC_INTERVAL_SECONDS as f64)
                });
            let send = env
                .sessions
                .iter()
                .filter(|(fp, _)| {
                    env.last_vector_sent
                        .get(*fp)
                        .is_none_or(|at| now.duration_since(*at).as_secs_f64() >= interval)
                })
                .map(|(_, s)| s.clone())
                .collect::<Vec<_>>();
            (dial, send)
        };
        for fp in dial {
            self.dial_attempt(env_id, &fp);
        }
        for session in send {
            self.send_vector(env_id, &session);
        }
        // A refold still owed held up none of the above; the poll reports it
        // until one succeeds (section 6.4, issue #51).
        owed.map_or(Ok(()), Err)
    }
    /// The steps of a poll tick that read and change an environment's state:
    /// a failed refold's retry, local commits and facts, removal repair, the
    /// incident outbox, and the deferred commits whose time has come. A
    /// failed refold is no failed step: the steps run on the last document a
    /// refold produced, and a refold still owed after them is returned
    /// (section 6.4, issue #51).
    fn advance_env(&self, env_id: &str, now: Instant) -> Result<Option<Error>> {
        let owed = self.retry_failed_refold(env_id, now).is_err();
        self.pick_up_local_commits(env_id, owed)?;
        self.pick_up_local_facts(env_id, owed)?;
        self.repair_member_removals(env_id)?;
        self.poll_incident_outbox(env_id, now);
        let store = CommitStore::new(self.ctx.state, env_id);
        let released = store.release_deferred(commit::now_ms(), Some(self.ctx.audit))?;
        // While a refold is owed, or when this one fails, these are left to
        // the pickup, which broadcasts them once a refold succeeds.
        if !released.is_empty() && !owed && self.refold(env_id).is_ok() {
            for commit in released {
                // The next pickup tick sees these as new store commits too;
                // the seen-set keeps that from broadcasting them again.
                if self.commit_first_seen(&commit) {
                    self.broadcast(
                        env_id,
                        &json!({"type":"COMMIT","commit":commit.to_dict()}),
                        None,
                    );
                }
            }
        }
        Ok(self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(env_id)
            .and_then(|e| e.refold_failure.as_ref())
            .map(|failure| failure.error.clone()))
    }
    /// `owed`: a failed refold is still owed, so new commits are left for
    /// the pickup after a refold succeeds.
    fn pick_up_local_commits(&self, env_id: &str, owed: bool) -> Result<()> {
        let store = CommitStore::new(self.ctx.state, env_id);
        let current = store.vector()?;
        let baseline = {
            self.envs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(env_id)
                .map(|e| e.last_known_vector.clone())
                .unwrap_or_default()
        };
        let mut added = Vec::new();
        for (fp, hi) in &current {
            // `seq_lo = baseline.get(fp, 0)`; `range(seq_lo + 1, seq_hi + 1)`.
            let mut seq = match baseline.get(fp) {
                Some(lo) => lo + 1,
                None => PyInt::from(1),
            };
            while seq <= *hi {
                if let Some(commit) = store.get(fp, &seq)? {
                    added.push(commit);
                }
                seq = &seq + 1;
            }
        }
        // The baseline moves only once a refold succeeds: while one is owed,
        // or when this one fails (noted and retried by the poll), the pickup
        // after a refold succeeds folds and broadcasts these (issue #51).
        if !added.is_empty() && (owed || self.refold(env_id).is_err()) {
            return Ok(());
        }
        if let Some(env) = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(env_id)
        {
            env.last_known_vector = current;
        }
        if !added.is_empty() {
            for commit in added {
                if self.commit_first_seen(&commit) {
                    self.broadcast(
                        env_id,
                        &json!({"type":"COMMIT","commit":commit.to_dict()}),
                        None,
                    );
                }
            }
        }
        Ok(())
    }
    fn quarantine_local_fact(&self, env_id: &str, rejected: &str, reason: &str) -> Result<()> {
        let _lock = self.ctx.state.lock()?;
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let env = envs
            .get_mut(env_id)
            .ok_or_else(|| Error::not_found("team_env_unknown"))?;
        if let Ok(value) = pyjson::loads(rejected)
            && let Ok(fact) = Fact::from_dict(&value)
            && env.fact_hashes.contains(&fact.hash()?)
        {
            return Ok(());
        }
        let path = format!("team/{env_id}/facts.jsonl");
        let lines = self.ctx.state.read_lines(&path, None)?;
        let retained: Vec<_> = lines
            .iter()
            .filter(|line| line.as_str() != rejected)
            .collect();
        if retained.len() == lines.len() {
            return Ok(());
        }
        self.ctx.state.append_line(
            &format!("team/{env_id}/rejected_facts.jsonl"),
            &pyjson::dumps(
                &json!({"line":rejected,"reason":reason}),
                DumpOptions::compact_sorted(),
            )?,
        )?;
        let mut text = retained
            .iter()
            .map(|line| line.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if !text.is_empty() {
            text.push('\n');
        }
        self.ctx.state.write_bytes(&path, text.as_bytes())?;
        env.known_fact_lines = retained.len();
        Ok(())
    }

    fn fact_file_stamp(&self, env_id: &str) -> Result<Option<(u64, u64, i64, i64)>> {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(
            self.ctx
                .state
                .path
                .join(format!("team/{env_id}/facts.jsonl")),
        ) {
            Ok(m) => Ok(Some((m.ino(), m.len(), m.mtime(), m.mtime_nsec()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::state("team_fact_stat_failed")),
        }
    }
    /// `owed`: a failed refold is still owed, so the poll's retry rather than
    /// a refold here folds the facts picked up.
    fn pick_up_local_facts(&self, env_id: &str, owed: bool) -> Result<()> {
        let _lock = self.ctx.state.lock()?;
        let stamp = self.fact_file_stamp(env_id)?;
        if self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(env_id)
            .is_some_and(|env| env.fact_file_stamp == stamp)
        {
            return Ok(());
        }
        #[cfg(test)]
        self.fact_pickup_loads.fetch_add(1, Ordering::SeqCst);

        let (_, admitted, _) = load_facts(&self.ctx, env_id)?;
        let lines = self
            .ctx
            .state
            .read_lines(&format!("team/{env_id}/facts.jsonl"), None)?;
        let mut refolding = !owed;
        // Scan by accepted fact hash, not a prefix count: another process may
        // append an unvalidated line before an already accepted remote fact.
        for line in &lines {
            let Ok(value) = pyjson::loads(line) else {
                self.quarantine_local_fact(env_id, line, "team_fact_malformed")?;
                continue;
            };
            let Ok(fact) = Fact::from_dict(&value) else {
                self.quarantine_local_fact(env_id, line, "team_fact_malformed")?;
                continue;
            };
            let hash = fact.hash()?;
            if self
                .envs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(env_id)
                .is_some_and(|env| env.fact_hashes.contains(&hash))
            {
                continue;
            }
            if fact.kind == "incident" {
                continue;
            }
            if fact.env_id != env_id
                || !FACT_KINDS.contains(&fact.kind.as_str())
                || !admitted.contains(&hash)
            {
                self.quarantine_local_fact(env_id, line, "team_fact_rejected")?;
                continue;
            }
            receipt_fact(&self.ctx, &fact)?;
            let inserted = {
                let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(env) = envs.get_mut(env_id) {
                    if env.fact_hashes.insert(fact.hash()?) {
                        apply_fact(&mut env.facts, &fact);
                        if fact.kind == "member_removed" {
                            env.pending_removal_repairs.insert(fact.hash()?);
                            env.next_removal_repair = Instant::now();
                        }
                        if fact.kind == "member_removed" {
                            if let Some(fp) = fact.target["fingerprint"].as_str() {
                                env.removal_authors
                                    .entry(fp.into())
                                    .or_default()
                                    .insert(fact.author.clone());
                            }
                        }
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };
            if !inserted {
                continue;
            }
            if fact.kind == "member_removed"
                && let Some(fp) = fact.target["fingerprint"].as_str()
            {
                self.drain_removed(env_id, fp);
            }
            // A refold that fails is noted, and the poll's retry folds in this
            // fact and the rest; they are announced all the same (issue #51).
            if refolding && self.refold(env_id).is_err() {
                refolding = false;
            }
            self.audit_fact_apply(env_id, &fact);
            self.broadcast(env_id, &json!({"type":"FACT","fact":fact.to_dict()}), None);
            if fact.kind == "member_removed" {
                if fact.target["fingerprint"].as_str().is_some() {
                    self.send_removal_notice(env_id, &fact, None);
                }
            }
        }
        let stamp = self.fact_file_stamp(env_id)?;
        if let Some(env) = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(env_id)
        {
            env.fact_file_stamp = stamp;
        }
        Ok(())
    }
    fn dial_attempt(&self, env_id: &str, fp: &str) {
        let address = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            envs.get(env_id)
                .and_then(|e| e.candidate_addresses.get(fp))
                .and_then(|a| a.iter().next().cloned())
        };
        let Some(address) = address else {
            return;
        };
        let Ok(session) = self.transport.dial(&address, env_id, None) else {
            self.record_dial_failure(env_id, fp);
            return;
        };
        if session.peer().fingerprint() != fp {
            session.close();
            self.record_dial_failure(env_id, fp);
            return;
        }
        // The backoff resets only once the peer's first frame has been
        // handled (`confirm_dial`); a refused dial backs off (issue #14).
        if let Some(env) = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(env_id)
        {
            env.dial_pending.insert(fp.into(), Arc::downgrade(&session));
        }
        // Python lets this escape `poll()` (the poll loop swallows it); the
        // failure is confined to this one dial here.
        let wired = self.wire_dialed_session(env_id, fp, &address, session.clone());
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id) {
            match wired {
                Err(_) => {
                    if take_dial_mark(env, fp, &session) {
                        self.note_dial_failure(env, fp);
                    }
                }
                // Lost the tie-break to the peer's own session, which stands.
                Ok(false) => {
                    take_dial_mark(env, fp, &session);
                }
                // Already dropped (a failed send) before its receiver ran: a
                // refused dial, counted now so a poll tick cannot redial and
                // overwrite the mark first.
                Ok(true) => {
                    if env
                        .sessions
                        .get(fp)
                        .is_none_or(|current| !Arc::ptr_eq(current, &session))
                        && take_dial_mark(env, fp, &session)
                    {
                        self.note_dial_failure(env, fp);
                    }
                }
            }
        }
    }
    fn record_dial_failure(&self, env_id: &str, fp: &str) {
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id) {
            self.note_dial_failure(env, fp);
        }
    }
    fn note_dial_failure(&self, env: &mut EnvState, fp: &str) {
        let (min, max) = self.ctx.config.team_dial_backoff;
        let next = env
            .backoff
            .get(fp)
            .map_or(min, |d| (d.as_secs_f64() * 2.0).min(max));
        let dur = Duration::from_secs_f64(next);
        env.backoff.insert(fp.into(), dur);
        env.next_attempt.insert(fp.into(), Instant::now() + dur);
    }
    /// The peer's first frame on this session was handled: the peer
    /// accepts us, so the next dial need not wait. This holds for a session
    /// it opened too, or a tie-break loser and a member its peers did not
    /// know yet would keep backing off towards five minutes.
    fn confirm_dial(&self, env_id: &str, session: &Arc<dyn Session>) {
        let fp = session.peer().fingerprint();
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id) {
            take_dial_mark(env, &fp, session);
            env.backoff.remove(&fp);
            env.next_attempt.remove(&fp);
        }
    }
    /// A dialed session ended before its peer sent a frame we handled -- a
    /// refused handshake: back off before dialing again.
    fn fail_unconfirmed_dial(&self, env_id: &str, session: &Arc<dyn Session>) {
        let fp = session.peer().fingerprint();
        let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(env) = envs.get_mut(env_id)
            && take_dial_mark(env, &fp, session)
        {
            self.note_dial_failure(env, &fp);
        }
    }
    /// `_wire_dialed_session`. Python persists the dialed address first and an
    /// exception there (a corrupt `peers.json`) escapes before the session is
    /// accepted, so it is never wired: here it is returned (`state_corrupt`)
    /// and the session is closed rather than leaked. A later `_send_peers`
    /// failure likewise stops before the incident retry.
    ///
    /// Returns whether `accept_session` kept the session.
    fn wire_dialed_session(
        &self,
        env_id: &str,
        fp: &str,
        address: &str,
        session: Arc<dyn Session>,
    ) -> Result<bool> {
        // A successful dial also becomes a redial candidate (as through
        // `set_peer_address`); only the persisted address is Python's step.
        if valid_fp(fp) && !address.is_empty() {
            let mut envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(env) = envs.get_mut(env_id) {
                env.candidate_addresses
                    .entry(fp.into())
                    .or_default()
                    .insert(address.into());
            }
        }
        if let Err(error) = self.persist_peer_address(env_id, fp, address) {
            session.close();
            return Err(error);
        }
        if !self.accept_session(env_id, session.clone(), false) {
            return Ok(false);
        }
        self.audit_event("team_session_open", env_id, Some(fp), None, None);
        self.start_receiver(env_id.into(), session.clone());
        self.send_vector(env_id, &session);
        self.send_peers(env_id, &session)?;
        self.retry_pending_incidents_to(env_id, &session);
        Ok(true)
    }
    /// `adopt_outbound_session`: hand a session the caller dialed itself
    /// (`membership::join`) to the gossip machinery.
    pub fn adopt_outbound_session(&self, env_id: &str, session: Arc<dyn Session>, address: &str) {
        let _ = self.adopt_outbound_session_checked(env_id, session, address);
    }
    /// [`Self::adopt_outbound_session`] reporting what Python's version would
    /// raise, for `join` to fail with it instead of waiting out its timeout.
    pub(crate) fn adopt_outbound_session_checked(
        &self,
        env_id: &str,
        session: Arc<dyn Session>,
        address: &str,
    ) -> Result<()> {
        let fp = session.peer().fingerprint();
        self.wire_dialed_session(env_id, &fp, address, session)
            .map(|_| ())
    }
    pub fn status(&self, env_id: &str) -> Result<Value> {
        let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
        let env = envs
            .get(env_id)
            .ok_or_else(|| Error::not_found("team_env_unknown"))?;
        let mut sessions: Vec<_> = env.sessions.keys().cloned().collect();
        sessions.sort();
        let conflicts = self
            .ctx
            .state
            .read_json(&format!("team/{env_id}/removal_conflicts.json"), json!({}))?;
        if conflicts.as_object().is_none_or(|values| {
            values.values().any(|value| {
                !value["target"].as_str().is_some_and(valid_fp)
                    || !value["author"].as_str().is_some_and(valid_fp)
                    || !value["hash"].as_str().is_some_and(|hash| {
                        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
                    })
            })
        }) {
            return Err(Error::state("state_corrupt").with_detail("team_removal_conflicts"));
        }
        let rejected_removals: Vec<_> = conflicts
            .as_object()
            .ok_or_else(|| Error::state("state_corrupt"))?
            .values()
            .filter(|value| {
                value["target"].as_str().is_some_and(|target| {
                    valid_fp(target) && !env.facts.removed_members.contains(target)
                })
            })
            .map(|value| {
                json!({"target":value["target"],"author":value["author"],"hash":value["hash"],
                "reason":"team_fact_not_authorized"})
            })
            .collect();
        Ok(
            json!({"env_id":env_id,"vector":CommitStore::new(self.ctx.state,env_id).vector()?,"sessions":sessions,"synced_at":env.synced_at.map(|ts|iso(Some(ts))),"pending_deferred":CommitStore::new(self.ctx.state,env_id).deferred_commits()?.len(),"rejected_removals":rejected_removals}),
        )
    }

    pub fn compact(&self, env_id: &str) -> Result<Value> {
        let (facts, peer_vectors, members) = {
            let envs = self.envs.lock().unwrap_or_else(|e| e.into_inner());
            let env = envs
                .get(env_id)
                .ok_or_else(|| Error::not_found("team_env_unknown"))?;
            (
                env.facts.clone(),
                env.peer_vectors.clone(),
                env.document["members"].clone(),
            )
        };
        let store = CommitStore::new(self.ctx.state, env_id);
        let commits = store.all_commits()?;
        if commits.is_empty() {
            return Ok(json!({"env_id":env_id,"removed":0,"blocked_by":[]}));
        }
        let now = PyInt::from(commit::now_ms());
        let mut cutoff = None;
        for (i, entry) in commits.iter().enumerate() {
            let (wall, _) = Hlc::parse(&entry.hlc)?;
            if PyInt(&now.0 - wall.0) < COMPACT_MIN_AGE_MS {
                break;
            }
            cutoff = Some(i);
        }
        let Some(cutoff) = cutoff else {
            return Ok(
                json!({"env_id":env_id,"removed":0,"blocked_by":[],"reason":"no_commit_old_enough"}),
            );
        };
        // `candidate_vector[author] = max(candidate_vector.get(author, 0),
        // author_seq)`.
        let mut candidate = BTreeMap::<String, PyInt>::new();
        for entry in &commits[..=cutoff] {
            let seq = candidate
                .entry(entry.author.clone())
                .or_insert_with(PyInt::zero);
            if entry.author_seq > *seq {
                *seq = entry.author_seq.clone();
            }
        }
        let mine = self.device.fingerprint()?;
        let mut blocked = Vec::new();
        if let Some(members) = members.as_object() {
            for (fp, member) in members {
                if fp == &mine || member["status"] != "active" {
                    continue;
                }
                if candidate.iter().any(|(author, seq)| {
                    peer_vectors
                        .get(fp)
                        .and_then(|v| v.get(author))
                        .map_or(*seq > 0, |known| known < seq)
                }) {
                    blocked.push(fp.clone());
                }
            }
        }
        blocked.sort();
        if !blocked.is_empty() {
            return Ok(json!({"env_id":env_id,"removed":0,"blocked_by":blocked}));
        }
        let snapshot = fold::snapshot_of_prefix(
            env_id,
            commits[..=cutoff].to_vec(),
            self.ctx.state,
            Some(&facts),
            &commits,
            Some(self.ctx.audit),
        )?;
        // Numbered by what it covers, an earlier compaction's commits
        // included (issue #50).
        let total = snapshot
            .vector
            .values()
            .fold(PyInt::zero(), |acc, v| PyInt(acc.0 + &v.0));
        fold::save_snapshot(self.ctx.state, env_id, &total, &snapshot)?;
        fold::save_snapshot_record(
            self.ctx.state,
            env_id,
            &total,
            &fold::snapshot_record(Some(&facts), &commits),
        )?;
        let mut removed = 0;
        {
            let _lock = self.ctx.state.lock()?;
            for entry in &commits[..=cutoff] {
                if entry.ops.iter().any(|op| {
                    [
                        "env.init",
                        "member.add",
                        "member.set_role",
                        "member.remove",
                        "owner.transfer",
                        "dek.rotate",
                    ]
                    .contains(&op["op"].as_str().unwrap_or(""))
                }) {
                    continue;
                }
                let path = self.ctx.state.path.join(format!(
                    "team/{env_id}/commits/{}/{}.json",
                    entry.author, entry.author_seq
                ));
                if std::fs::remove_file(path).is_ok() {
                    removed += 1;
                }
            }
        }
        if let Some(env) = self
            .envs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(env_id)
        {
            env.last_snapshot_total = PyNumber::Int(total.0);
        }
        self.refold(env_id)?;
        let _ = self.ctx.audit.record(
            "team_compact",
            RecordArgs {
                result: Some("ok"),
                extra: vec![("env_id", json!(env_id)), ("count", json!(removed))],
                ..Default::default()
            },
        );
        Ok(json!({"env_id":env_id,"removed":removed,"blocked_by":[]}))
    }
}
