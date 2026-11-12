//! Independent process death, offline continuation, monotone restrictions and
//! unavailable-prefix refusal after the actual encrypted onboarding fixture.
#[path = "team_personal_bootstrap_runtime.rs"]
mod runtime;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
};
use zeropw::{
    clock,
    context::{Config, Context},
    pyjson::{self, DumpOptions},
    team::{
        commit::{self, Commit, CommitStore},
        envelope, fold,
        identity::DeviceKey,
        membership, sync,
    },
    vault::Vault,
};

fn deliver(ctx: &Context, env: &str, c: &Commit) {
    assert!(matches!(
        commit::receive_commit(
            &CommitStore::new(ctx.state, env),
            c,
            commit::now_ms(),
            Some(ctx.audit)
        )
        .unwrap(),
        "accepted" | "duplicate"
    ));
}
fn derive(ctx: &Context, env: &str) {
    let folded = membership::load_environment(ctx, env).unwrap();
    let key = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    fold::derive_local(
        &folded,
        ctx.state,
        &ctx.policy,
        Some(ctx.audit),
        Some(&key),
        Some(ctx.kms),
        Some("personal"),
        Some("vault"),
    )
    .unwrap();
}
fn receive_fact_original(ctx: &Context, env: &str, fact: &Value) {
    ctx.state
        .append_line(
            &format!("team/{env}/facts.jsonl"),
            &pyjson::dumps(fact, DumpOptions::compact_sorted()).unwrap(),
        )
        .unwrap();
    sync::load_facts(ctx, env).unwrap();
}

#[test]
fn personal_bootstrap_crash_author_child() {
    let Some(path) = std::env::var_os("PVBOOT_CRASH_OWN_STATE") else {
        return;
    };
    let env = std::env::var("PVBOOT_CRASH_OWN_ENV").unwrap();
    let ctx = Context::open(path, Config::default(), clock::system()).unwrap();
    let commit = membership::author_commit(
        &ctx,
        None,
        &env,
        vec![json!({"op":"settings.update","sync_interval_seconds":19})],
    )
    .unwrap();
    assert_eq!(commit.author_seq, 2);
    println!("\nPVBOOT_DURABLE_AUTHOR {}", commit.hash().unwrap());
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

#[test]
fn personal_bootstrap_crash_process_death_preserves_one_epoch_and_next_sequence() {
    let f = runtime::installed(true);
    for team in f.teams.iter().rev() {
        team.stop();
    }
    let receipt_path =
        f.b.state
            .path
            .join(format!("team/{}/bootstrap/receipt.json", f.env));
    let receipt = std::fs::read(&receipt_path).unwrap();
    struct OwnedCrashChild(std::process::Child);
    impl Drop for OwnedCrashChild {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }
    let mut child = OwnedCrashChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "personal_bootstrap_crash_author_child",
                "--nocapture",
            ])
            .env("PVBOOT_CRASH_OWN_STATE", &f.b.state.path)
            .env("PVBOOT_CRASH_OWN_ENV", &f.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let output = child.0.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            let line = line.unwrap();
            if let Some(hash) = line.strip_prefix("PVBOOT_DURABLE_AUTHOR ") {
                let _ = tx.send(hash.trim().to_owned());
            }
        }
    });
    let boundary = rx.recv_timeout(std::time::Duration::from_secs(10));
    let _ = child.0.kill();
    let status = child.0.wait().unwrap();
    reader.join().unwrap();
    let hash = boundary
        .unwrap_or_else(|_| panic!("owned child did not report its durable boundary: {status}"));
    assert_eq!(hash.len(), 64);
    assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let reopened = Context::open(&f.b.state.path, Config::default(), clock::system()).unwrap();
    let fp = DeviceKey::load_or_create(reopened.state, reopened.kms)
        .unwrap()
        .fingerprint()
        .unwrap();
    let store = CommitStore::new(reopened.state, &f.env);
    assert_eq!(store.get(&fp, 2).unwrap().unwrap().hash().unwrap(), hash);
    let next = membership::author_commit(
        &reopened,
        None,
        &f.env,
        vec![json!({"op":"settings.update","sync_interval_seconds":20})],
    )
    .unwrap();
    assert_eq!(next.author_seq, 3);
    assert_eq!(std::fs::read(receipt_path).unwrap(), receipt);
    assert_eq!(
        store
            .all_commits()
            .unwrap()
            .iter()
            .filter(|c| c.author == fp && c.author_seq == 2)
            .count(),
        1
    );
}

#[test]
fn personal_bootstrap_crash_offline_conflicts_delete_put_and_backup_rollback() {
    let f = runtime::installed(false);
    for team in f.teams.iter().rev() {
        team.stop();
    }
    deliver(&f.a, &f.env, f.history.last().unwrap());
    let operations = |version: &str, value: &[u8]| {
        let cipher = envelope::encrypt_secret(&[7; 32], &f.env, "alpha", version, value).unwrap();
        vec![
            json!({"op":"secret.put_version","secret_id":"alpha","version_id":version,"generation_id":runtime::GENERATION,"kind":"api_key","ciphertext":cipher,"public":{}}),
            json!({"op":"secret.activate","secret_id":"alpha","version_id":version}),
        ]
    };
    let a = membership::author_commit(
        &f.a,
        None,
        &f.env,
        operations("7777777777777777", b"synthetic-offline-a"),
    )
    .unwrap();
    let b = membership::author_commit(
        &f.b,
        None,
        &f.env,
        operations("8888888888888888", b"synthetic-offline-b"),
    )
    .unwrap();
    assert_eq!(b.author_seq, 2);
    deliver(&f.a, &f.env, &b);
    deliver(&f.b, &f.env, &a);
    derive(&f.a, &f.env);
    derive(&f.b, &f.env);
    let left = membership::load_environment(&f.a, &f.env).unwrap();
    let right = membership::load_environment(&f.b, &f.env).unwrap();
    assert_eq!(left.document, right.document);
    assert_eq!(left.version_order, right.version_order);
    assert_eq!(right.version_order["alpha"].as_array().unwrap().len(), 6);
    for version in ["7777777777777777", "8888888888888888"] {
        assert!(
            right.document["secrets"]["alpha"]["versions"]
                .get(version)
                .is_some()
        );
    }
    let backup = f.root.path().join("pre-delete-backup.json");
    f.b.vault.backup(&backup).unwrap();
    let deletion = membership::author_fact(
        &f.b,
        None,
        &f.env,
        "secret_deleted",
        json!({"secret_id":"alpha"}),
    )
    .unwrap();
    let late = membership::author_commit(
        &f.a,
        None,
        &f.env,
        operations("9999999999999999", b"synthetic-deleted-put"),
    )
    .unwrap();
    deliver(&f.b, &f.env, &late);
    derive(&f.b, &f.env);
    receive_fact_original(&f.a, &f.env, &deletion);
    derive(&f.a, &f.env);
    assert!(f.a.vault.secret_for_trusted_use("alpha", None).is_err());
    assert!(f.b.vault.secret_for_trusted_use("alpha", None).is_err());
    let receipt = std::fs::read(
        f.b.state
            .path
            .join(format!("team/{}/bootstrap/receipt.json", f.env)),
    )
    .unwrap();
    Vault::restore(f.b.state, &backup, f.b.audit, Some(f.b.kms)).unwrap();
    assert!(f.b.policy.restore_pending().unwrap());
    assert!(f.b.vault.secret_for_trusted_use("alpha", None).is_err());
    assert_eq!(
        std::fs::read(
            f.b.state
                .path
                .join(format!("team/{}/bootstrap/receipt.json", f.env))
        )
        .unwrap(),
        receipt
    );
}

#[test]
fn personal_bootstrap_crash_late_authenticated_prefix_is_preserved_and_blocks_only_target() {
    let f = runtime::installed(false);
    for team in f.teams.iter().rev() {
        team.stop();
    }
    let old = &f.history[1];
    assert_eq!(old.author_seq, 2);
    assert!(
        CommitStore::new(f.b.state, &f.env)
            .get(&old.author, 2)
            .unwrap()
            .is_none()
    );
    let error = commit::receive_commit(
        &CommitStore::new(f.b.state, &f.env),
        old,
        commit::now_ms(),
        Some(f.b.audit),
    )
    .unwrap_err();
    assert_eq!(error.reason, "team_checkpoint_history_required");
    assert!(
        f.b.state
            .path
            .join(format!(
                "team/{}/bootstrap/history-required/{}.json",
                f.env,
                old.hash().unwrap()
            ))
            .is_file()
    );
    assert!(f.b.vault.secret_for_trusted_use("alpha", None).is_err());
    assert!(f.b.projects.require_environment("unrelated", "dev").is_ok());
    assert!(f.a.vault.secret_for_trusted_use("alpha", None).is_ok());
}

#[test]
fn personal_bootstrap_crash_postcut_b_removal_and_rotation_enforce_cached_credential_denial() {
    let f = runtime::installed(false);
    for team in f.teams.iter().rev() {
        team.stop();
    }
    deliver(&f.a, &f.env, f.history.last().unwrap());
    let key = DeviceKey::load_or_create(f.b.state, f.b.kms).unwrap();
    let bfp = key.fingerprint().unwrap();
    let before = CommitStore::new(f.b.state, &f.env).vector().unwrap();
    let removal = membership::remove_member(&f.a, None, &f.env, &bfp).unwrap();
    assert_eq!(removal["dek_rotated"], true);
    for c in CommitStore::new(f.a.state, &f.env).all_commits().unwrap() {
        if before.get(&c.author).is_none_or(|n| &c.author_seq > n) {
            deliver(&f.b, &f.env, &c);
        }
    }
    receive_fact_original(&f.b, &f.env, &removal["fact"]);
    let document = membership::load_environment(&f.b, &f.env).unwrap().document;
    assert_eq!(document["members"][&bfp]["status"], "removed");
    assert!(
        document["dek"]["generations"][document["dek"]["current"].as_str().unwrap()]["wraps"]
            .get(&bfp)
            .is_none()
    );
    assert!(f.b.vault.secret_for_trusted_use("alpha", None).is_err());
    assert!(f.b.policy.get_connection("live").is_err());
    assert!(
        membership::author_commit(
            &f.b,
            None,
            &f.env,
            vec![json!({"op":"settings.update","sync_interval_seconds":21})]
        )
        .is_err()
    );
    assert!(f.b.projects.require_environment("unrelated", "dev").is_ok());
}

// Complete positive-compaction case relocated to cfg(test)
// team::sync::personal_bootstrap_restart_age_tests; the grant keeps the age seam
// absent from the non-test library linked by this integration target.

#[derive(Default)]
struct RestartTrace {
    events: std::sync::Mutex<std::collections::BTreeMap<String, Value>>,
}
impl RestartTrace {
    fn frame(&self, side: &str, session: usize, direction: &str, message: &Value) {
        let kind = message["type"].as_str().unwrap_or("");
        if !matches!(
            kind,
            "VECTOR" | "FACT" | "COMMIT" | "SYNC_CAPS" | "TOMBSTONE_STATE" | "TOMBSTONE_ACK"
        ) && !kind.starts_with("BOOTSTRAP_")
        {
            return;
        }
        let key = format!("{side}:{session}:{direction}:{kind}");
        let mut events = self.events.lock().unwrap();
        if events.len() >= 64 && !events.contains_key(&key) {
            return;
        }
        let value = events.entry(key).or_insert_with(|| json!({"count":0}));
        value["count"] = json!(value["count"].as_u64().unwrap() + 1);
        if kind == "VECTOR" {
            assert!(message["vector"].as_object().unwrap().len() <= 2);
            value["vector"] = message["vector"].clone();
        }
    }
    fn snapshot(&self) -> Value {
        json!(*self.events.lock().unwrap())
    }
    fn processed(&self, side: &str, session: usize, kind: &str, elapsed: std::time::Duration) {
        let key = format!("{side}:{session}:processing:{kind}");
        let mut events = self.events.lock().unwrap();
        if events.len() >= 64 && !events.contains_key(&key) {
            return;
        }
        let value = events
            .entry(key)
            .or_insert_with(|| json!({"count":0,"total_us":0,"max_us":0}));
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        value["count"] = json!(value["count"].as_u64().unwrap() + 1);
        value["total_us"] = json!(value["total_us"].as_u64().unwrap().saturating_add(micros));
        value["max_us"] = json!(value["max_us"].as_u64().unwrap().max(micros));
    }
}
enum RestartDial {
    InboundOnly,
    PersonalOnly,
}
struct RestartTransport {
    inner: std::sync::Arc<zeropw::team::transport::TcpTransport>,
    side: &'static str,
    trace: std::sync::Arc<RestartTrace>,
    dial: RestartDial,
}
struct RestartSession {
    inner: std::sync::Arc<dyn zeropw::team::transport::Session>,
    side: &'static str,
    id: usize,
    trace: std::sync::Arc<RestartTrace>,
    processing: std::sync::Mutex<Option<(std::time::Instant, String)>>,
}
impl RestartSession {
    fn wrap(
        inner: std::sync::Arc<dyn zeropw::team::transport::Session>,
        side: &'static str,
        trace: std::sync::Arc<RestartTrace>,
    ) -> std::sync::Arc<dyn zeropw::team::transport::Session> {
        static IDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        std::sync::Arc::new(Self {
            inner,
            side,
            trace,
            id: IDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            processing: std::sync::Mutex::new(None),
        })
    }
}
impl zeropw::team::transport::Session for RestartSession {
    fn peer(&self) -> zeropw::team::identity::DeviceRecord {
        self.inner.peer()
    }
    fn env_id(&self) -> &str {
        self.inner.env_id()
    }
    fn send(&self, v: &Value) -> zeropw::errors::Result<()> {
        self.trace.frame(self.side, self.id, "send", v);
        self.inner.send(v)
    }
    fn recv(
        &self,
        t: std::time::Duration,
    ) -> Result<Option<Value>, zeropw::team::transport::SessionClosed> {
        if let Some((start, kind)) = self.processing.lock().unwrap().take() {
            self.trace
                .processed(self.side, self.id, &kind, start.elapsed());
        }
        let v = self.inner.recv(t)?;
        if let Some(v) = &v {
            self.trace.frame(self.side, self.id, "recv", v);
            let kind = v["type"].as_str().unwrap_or("");
            if matches!(
                kind,
                "VECTOR" | "FACT" | "COMMIT" | "SYNC_CAPS" | "TOMBSTONE_STATE" | "TOMBSTONE_ACK"
            ) {
                *self.processing.lock().unwrap() = Some((std::time::Instant::now(), kind.into()));
            }
        }
        Ok(v)
    }
    fn recv_original(
        &self,
        t: std::time::Duration,
    ) -> Result<Option<Vec<u8>>, zeropw::team::transport::SessionClosed> {
        let raw = self.inner.recv_original(t)?;
        if let Some(raw) = &raw
            && let Ok(v) = pyjson::loads(std::str::from_utf8(raw).unwrap_or(""))
        {
            self.trace.frame(self.side, self.id, "raw_recv", &v);
        }
        Ok(raw)
    }
    fn close(&self) {
        self.inner.close()
    }
    fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }
    fn created_at(&self) -> std::time::Instant {
        self.inner.created_at()
    }
    fn transport_kind(&self) -> Option<&'static str> {
        self.inner.transport_kind()
    }
}
impl zeropw::team::transport::Transport for RestartTransport {
    fn set_membership(&self, cb: zeropw::team::transport::MembershipCheck) {
        self.inner.set_membership(cb)
    }
    fn set_invite_check(&self, cb: Option<zeropw::team::transport::InviteCheck>) {
        self.inner.set_invite_check(cb)
    }
    fn set_handshake_failed(&self, cb: Option<zeropw::team::transport::HandshakeFailedHook>) {
        self.inner.set_handshake_failed(cb)
    }
    fn listen(
        &self,
        address: &str,
        cb: zeropw::team::transport::OnSession,
    ) -> zeropw::errors::Result<()> {
        let side = self.side;
        let trace = self.trace.clone();
        self.inner.listen_arc(
            address,
            std::sync::Arc::new(move |s| cb(RestartSession::wrap(s, side, trace.clone()))),
        )
    }
    fn dial(
        &self,
        address: &str,
        env: &str,
        proof: Option<zeropw::team::transport::InviteProof>,
    ) -> Result<
        std::sync::Arc<dyn zeropw::team::transport::Session>,
        zeropw::team::transport::SessionClosed,
    > {
        if matches!(self.dial, RestartDial::InboundOnly)
            || matches!(self.dial, RestartDial::PersonalOnly) && proof.is_none()
        {
            return Err(zeropw::team::transport::SessionClosed(
                "synthetic_dial_disabled",
            ));
        }
        self.inner
            .dial_session(address, env, proof)
            .map(|s| RestartSession::wrap(s, self.side, self.trace.clone()))
    }
    fn close(&self) {
        self.inner.shutdown()
    }
}

#[test]
fn personal_bootstrap_crash_activated_owner_committed_receiver_restart_at_current_endpoint() {
    activated_owner_current_endpoint(true);
}

#[test]
fn personal_bootstrap_crash_activated_owner_current_endpoint_with_tombstones() {
    activated_owner_current_endpoint(false);
}

fn activated_owner_current_endpoint(empty: bool) {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };
    use zeropw::team::{sync::TeamSync, transport::TcpTransport};
    struct Stop(Vec<Arc<TeamSync>>);
    impl Drop for Stop {
        fn drop(&mut self) {
            for team in self.0.iter().rev() {
                team.stop();
            }
        }
    }
    let f = runtime::installed(empty);
    for team in f.teams.iter().rev() {
        team.stop();
    }
    let ak = DeviceKey::load_or_create(f.a.state, f.a.kms).unwrap();
    let bk = DeviceKey::load_or_create(f.b.state, f.b.kms).unwrap();
    let afp = ak.fingerprint().unwrap();
    let bfp = bk.fingerprint().unwrap();
    let auth =
        f.a.state
            .read_json(
                &format!("team/{}/bootstrap/authorizations/{bfp}.json", f.env),
                Value::Null,
            )
            .unwrap();
    assert_eq!(auth["activated"], true);
    let receipt_path =
        f.b.state
            .path
            .join(format!("team/{}/bootstrap/receipt.json", f.env));
    let receipt = std::fs::read(&receipt_path).unwrap();
    let journal_path =
        f.b.state
            .path
            .join(format!("team/{}/bootstrap/journal.json", f.env));
    let journal = std::fs::read(&journal_path).unwrap();
    let trace = Arc::new(RestartTrace::default());
    let at = TcpTransport::new(ak.clone(), Arc::new(|_, _| None), 64);
    let bt = TcpTransport::new(bk.clone(), Arc::new(|_, _| None), 64);
    // Keep A inbound-only and B's background ordinary fallback disabled so
    // success must use the real committed-receiver reconnect path itself.
    let ta = TeamSync::new(
        f.a.clone(),
        Arc::new(RestartTransport {
            inner: at.clone(),
            side: "a",
            trace: trace.clone(),
            dial: RestartDial::InboundOnly,
        }),
        ak,
    );
    let tb = TeamSync::new(
        f.b.clone(),
        Arc::new(RestartTransport {
            inner: bt,
            side: "b",
            trace: trace.clone(),
            dial: RestartDial::PersonalOnly,
        }),
        bk,
    );
    let _stop = Stop(vec![ta.clone(), tb.clone()]);
    ta.enable_sync_state();
    tb.enable_sync_state();
    ta.start(Some("127.0.0.1:0")).unwrap();
    tb.register_env(&f.env).unwrap();
    tb.set_peer_address(&f.env, &afp, &at.bound_address().unwrap())
        .unwrap();
    assert!(ta.synced_at(&f.env).is_none());
    assert!(tb.synced_at(&f.env).is_none());
    tb.start(None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(35);
    loop {
        let a_ready = ta.synced_at(&f.env).is_some();
        let b_ready = tb.synced_at(&f.env).is_some();
        if a_ready && b_ready {
            break;
        }
        if Instant::now() >= deadline {
            println!(
                "PVBOOT_CURRENT_ENDPOINT_METADATA {}",
                json!({"predicates":{"a_ready":a_ready,"b_ready":b_ready},"a":restart_metadata(&f.a,&f.env,&bfp),"b":restart_metadata(&f.b,&f.env,&afp),"wire":trace.snapshot()})
            );
            panic!("activated owner and committed receiver did not reach fresh ordinary agreement");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let wire = trace.snapshot();
    assert!(
        wire.as_object()
            .unwrap()
            .keys()
            .all(|key| !key.contains("BOOTSTRAP_")),
        "activated-owner restart must not replay bootstrap controls"
    );
    assert!(
        wire.as_object()
            .unwrap()
            .keys()
            .any(|key| key.starts_with("b:") && key.ends_with(":recv:VECTOR"))
    );
    assert_eq!(std::fs::read(receipt_path).unwrap(), receipt);
    assert_eq!(std::fs::read(journal_path).unwrap(), journal);
    let commits = CommitStore::new(f.a.state, &f.env).all_commits().unwrap();
    assert_eq!(
        commits
            .iter()
            .flat_map(|c| &c.ops)
            .filter(|op| op["op"] == "member.add")
            .count(),
        1
    );
    println!(
        "PVBOOT_CURRENT_ENDPOINT_FRESH_AGREEMENT {}",
        json!({"receipt_unchanged":true,"journal_unchanged":true,"member_add_count":1,"wire":wire})
    );
}

fn restart_metadata(ctx: &Context, env: &str, peer: &str) -> Value {
    let state = ctx
        .state
        .read_json(&format!("team/{env}/sync_state.json"), Value::Null)
        .unwrap();
    let attempt = ctx
        .state
        .read_json(&format!("team/{env}/bootstrap/attempt.json"), Value::Null)
        .unwrap();
    let auth = ctx
        .state
        .read_json(
            &format!("team/{env}/bootstrap/authorizations/{peer}.json"),
            Value::Null,
        )
        .unwrap();
    let closed = |value: &Value| {
        value
            .as_str()
            .filter(|s| {
                s.len() <= 64
                    && s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            })
            .map(|s| json!(s))
            .unwrap_or(Value::Null)
    };
    let reasons = ctx
        .state
        .read_lines("audit/audit.jsonl", Some(24))
        .unwrap()
        .iter()
        .filter_map(|line| pyjson::loads(line).ok())
        .filter(|row| {
            matches!(
                row["event"].as_str(),
                Some("team_sync_poll" | "team_handshake_failed")
            )
        })
        .map(|row| json!({"event":closed(&row["event"]),"reason":closed(&row["reason"])}))
        .take(8)
        .collect::<Vec<_>>();
    let p = &state["peers"][peer];
    json!({"vector":CommitStore::new(ctx.state,env).vector().unwrap(),"peer":{"session":p["session"],"peer_vector":p["peer_vector"],"vector_received_at":p["vector_received_at"],"transport":p["transport"],"dial_failures":p["dial_failures"],"last_error":closed(&p["last_error"]),"tombstone_agreement":p["tombstone_agreement"]},"closed_reasons":reasons,"authorization_activated":auth["activated"],"attempt_state":closed(&attempt["state"]),"attempt_reason":closed(&attempt["reason"])})
}

#[test]
fn personal_bootstrap_crash_signed_self_removal_commit_denies_imported_readers() {
    let f = runtime::installed(false);
    for team in f.teams.iter().rev() {
        team.stop();
    }
    let bfp = DeviceKey::load_or_create(f.b.state, f.b.kms)
        .unwrap()
        .fingerprint()
        .unwrap();
    assert!(f.b.vault.secret_for_trusted_use("alpha", None).is_ok());
    let removed = membership::author_commit(
        &f.b,
        None,
        &f.env,
        vec![json!({"op":"member.remove","fingerprint":bfp})],
    )
    .unwrap();
    let document = membership::load_environment(&f.b, &f.env).unwrap().document;
    assert_eq!(document["members"][&bfp]["status"], "removed");
    let trusted_open = f.b.vault.secret_for_trusted_use("alpha", None).is_ok();
    let listed = f.b.vault.list_secrets(None, None).unwrap();
    let listed_alpha = listed.iter().any(|v| v.id == "alpha");
    println!(
        "PVBOOT_SELF_REMOVAL_READERS {}",
        json!({"accepted_sequence":removed.author_seq,"document_member_removed":true,"trusted_reader_open":trusted_open,"listed_imported_secret":listed_alpha})
    );
    assert!(
        !trusted_open && !listed_alpha,
        "accepted signed self-removal must deny imported credential readers"
    );
}

#[test]
fn personal_bootstrap_crash_signed_admin_removal_before_fact_denies_imported_readers() {
    let f = runtime::installed(false);
    for team in f.teams.iter().rev() {
        team.stop();
    }
    let bfp = DeviceKey::load_or_create(f.b.state, f.b.kms)
        .unwrap()
        .fingerprint()
        .unwrap();
    assert!(f.b.vault.secret_for_trusted_use("alpha", None).is_ok());
    let removed = membership::author_commit(
        &f.a,
        None,
        &f.env,
        vec![json!({"op":"member.remove","fingerprint":bfp})],
    )
    .unwrap();
    assert_eq!(
        commit::receive_commit(
            &CommitStore::new(f.b.state, &f.env),
            &removed,
            commit::now_ms(),
            Some(f.b.audit),
        )
        .unwrap(),
        "accepted"
    );
    let document = membership::load_environment(&f.b, &f.env).unwrap().document;
    assert_eq!(document["members"][&bfp]["status"], "removed");
    let trusted_open = f.b.vault.secret_for_trusted_use("alpha", None).is_ok();
    let listed_alpha =
        f.b.vault
            .list_secrets(None, None)
            .unwrap()
            .iter()
            .any(|v| v.id == "alpha");
    println!(
        "PVBOOT_ADMIN_REMOVAL_BEFORE_FACT_READERS {}",
        json!({
            "accepted_sequence":removed.author_seq, "document_member_removed":true,
            "trusted_reader_open":trusted_open, "listed_imported_secret":listed_alpha,
        })
    );
    assert!(
        !trusted_open && !listed_alpha,
        "accepted effective admin removal must deny imported credential readers before FACT"
    );
}

#[test]
fn personal_bootstrap_crash_self_remove_completes_real_fact_and_committed_recovery_without_reactivation()
 {
    let f = runtime::installed(false);
    for team in f.teams.iter().rev() {
        team.stop();
    }
    let bfp = DeviceKey::load_or_create(f.b.state, f.b.kms)
        .unwrap()
        .fingerprint()
        .unwrap();
    let before =
        f.b.state
            .read_bytes(&format!("team/{}/bootstrap/receipt.json", f.env))
            .unwrap();
    let outcome = membership::remove_member(&f.b, None, &f.env, &bfp).unwrap();
    assert_eq!(outcome["fact"]["kind"], "member_removed");
    assert_eq!(outcome["fact"]["target"]["fingerprint"], bfp);
    assert!(
        f.b.state
            .exists(&format!("team/{}/bootstrap/member-removed.json", f.env))
    );
    let deny_path = format!("team/{}/bootstrap/local-removal-denial.json", f.env);
    let denial = f.b.state.read_bytes(&deny_path).unwrap();
    assert!(!denial.is_empty());
    assert!(f.b.vault.secret_for_trusted_use("alpha", None).is_err());
    assert!(
        f.b.vault
            .list_secrets(None, None)
            .unwrap()
            .iter()
            .all(|secret| secret.id != "alpha")
    );
    let reopened = std::sync::Arc::new(
        Context::open(&f.b.state.path, Config::default(), clock::system()).unwrap(),
    );
    let key = DeviceKey::load_or_create(reopened.state, reopened.kms).unwrap();
    let membership_check: zeropw::team::transport::MembershipCheck =
        std::sync::Arc::new(|_, _| None);
    let transport = zeropw::team::transport::TcpTransport::new(key.clone(), membership_check, 8);
    let team = sync::TeamSync::new(reopened.clone(), std::sync::Arc::new(transport), key);
    team.register_env(&f.env).unwrap();
    assert_eq!(reopened.state.read_bytes(&deny_path).unwrap(), denial);
    assert_eq!(
        reopened
            .state
            .read_bytes(&format!("team/{}/bootstrap/receipt.json", f.env))
            .unwrap(),
        before
    );
    assert!(
        reopened
            .vault
            .secret_for_trusted_use("alpha", None)
            .is_err()
    );
    let document = membership::load_environment(&reopened, &f.env)
        .unwrap()
        .document;
    assert_eq!(document["members"][&bfp]["status"], "removed");
    let store = CommitStore::new(reopened.state, &f.env);
    assert_eq!(store.vector().unwrap()[&bfp], 2);
    assert_eq!(
        store
            .all_commits()
            .unwrap()
            .iter()
            .flat_map(|commit| &commit.ops)
            .filter(|op| op["op"] == "member.add")
            .count(),
        1
    );
    team.stop();
    println!(
        "PVBOOT_REAL_SELF_REMOVAL_FACT_AND_RECOVERY {}",
        json!({"real_fact":true,"both_witnesses":true,"receipt_unchanged":true,"one_admission":true,"credential_readers_denied":true})
    );
}

#[test]
fn personal_bootstrap_crash_external_sync_status_uses_current_committed_epoch() {
    let f = runtime::installed(false);
    let result = runtime::admin(
        &f.b,
        &["team", "sync-status", "--env", "personal/vault"],
        json!({}),
    );
    let status =
        result.expect("fresh CLI sync-status must read an authenticated committed Personal epoch");
    assert_eq!(status["env_id"], f.env);
    assert!(
        status["peers"]
            .as_array()
            .is_some_and(|peers| !peers.is_empty())
    );
}
