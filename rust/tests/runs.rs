mod session_probe;

use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use zeropw::{
    context::{Config, Context},
    runs::{self, Run, RunRegistry},
};

fn setup(limit: usize) -> (TempDir, Arc<Context>, Arc<RunRegistry>) {
    let temp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            temp.path().join("state"),
            "test-admin-passphrase",
            "test-recovery-passphrase",
            Config::default(),
            Arc::new(zeropw::store::now),
        )
        .unwrap(),
    );
    let registry = RunRegistry::new(ctx.clone(), limit, 0.05);
    (temp, ctx, registry)
}
fn queued(r: &RunRegistry) -> Run {
    r.create(
        "alice",
        "conn",
        "grant",
        "http",
        "sh",
        None,
        "digest",
        Some("http://127.0.0.1:9999"),
        Some(4.into()),
    )
}
fn start(
    r: &Arc<RunRegistry>,
    run: &Run,
    script: &str,
    temp: &TempDir,
    sensitive: &[Vec<u8>],
    timeout: f64,
) {
    r.start(
        run,
        &["/bin/sh".into(), "-c".into(), script.into()],
        &HashMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
        temp.path(),
        sensitive,
        None,
        Some(timeout),
    )
    .unwrap();
}
#[test]
fn state_transitions_and_value_free_audit() {
    let (temp, ctx, r) = setup(1024);
    let run = queued(&r);
    assert_eq!(run.state, "queued");
    start(
        &r,
        &run,
        "printf business-output; printf diagnostics >&2; exit 7",
        &temp,
        &[],
        2.0,
    );
    let done = r.wait(&run, Some(5.0));
    assert_eq!(done.state, "completed");
    assert_eq!(done.exit_code, Some(7));
    assert_eq!(done.stdout, b"business-output");
    assert_eq!(done.stderr, b"diagnostics");
    let text = std::fs::read_to_string(ctx.state.path.join("audit/audit.jsonl")).unwrap();
    assert!(!text.contains("business-output"));
    assert!(!text.contains("diagnostics"));
    let records: Vec<Value> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|s| serde_json::from_str(s).unwrap())
        .filter(|v: &Value| v["run_id"] == run.id)
        .collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["event"], "run_start");
    assert_eq!(records[1]["event"], "run_finish");
    for record in records {
        assert_eq!(record["target"], "http://127.0.0.1:9999");
        assert_eq!(record["policy_version"], 4);
    }
    let public = r.view(&run);
    for hidden in ["caller", "grant", "input_digest", "program", "target"] {
        assert!(public.get(hidden).is_none());
    }
}
#[test]
fn bounded_capture_drains_both_pipes() {
    let (temp, _, r) = setup(31);
    let run = queued(&r);
    start(
        &r,
        &run,
        "head -c 131072 /dev/zero; head -c 131072 /dev/zero >&2",
        &temp,
        &[],
        3.0,
    );
    let done = r.wait(&run, Some(5.0));
    assert_eq!(done.state, "completed");
    assert_eq!(done.stdout.len(), 31);
    assert_eq!(done.stderr.len(), 31);
    assert!(done.stdout_truncated && done.stderr_truncated);
}
#[test]
fn output_encodings_block_both_streams() {
    let (temp, _, r) = setup(1024);
    for output in [
        "synthetic-secret-123",
        "c3ludGhldGljLXNlY3JldC0xMjM=",
        "73796e7468657469632d7365637265742d313233",
        "%73%79%6e%74%68%65%74%69%63%2d%73%65%63%72%65%74%2d%31%32%33",
    ] {
        let run = queued(&r);
        start(
            &r,
            &run,
            &format!("printf '%s' '{output}'; printf harmless >&2"),
            &temp,
            &[b"synthetic-secret-123".to_vec()],
            2.0,
        );
        let done = r.wait(&run, Some(4.0));
        assert_eq!(
            done.state, "blocked",
            "reason={:?} exit={:?} stderr={:?}",
            done.reason, done.exit_code, done.stderr
        );
        assert_eq!(done.stdout, runs::BLOCKED_MARKER.as_bytes());
        assert_eq!(done.stdout, done.stderr);
    }
}
#[test]
fn cancellation_escalates_and_preserves_reason() {
    let (temp, _, r) = setup(1024);
    let run = queued(&r);
    start(
        &r,
        &run,
        "trap '' TERM; printf ready; while :; do sleep 1; done",
        &temp,
        &[],
        10.0,
    );
    std::thread::sleep(Duration::from_millis(100));
    let began = Instant::now();
    let done = r.cancel(&run.id, "alice", "test_cancel").unwrap();
    assert!(began.elapsed() < Duration::from_secs(3));
    assert_eq!(done.state, "cancelled");
    assert_eq!(done.reason.as_deref(), Some("test_cancel"));
    assert!(done.exit_code.is_some());
}
#[test]
fn cancellation_targets_new_session_group_not_coordinator_group() {
    let (temp, _, r) = setup(1024);
    let marker = temp.path().join("child-ready");
    let run = queued(&r);
    r.start(
        &run,
        &session_probe::argv(),
        &session_probe::env(Some(&marker)),
        temp.path(),
        &[],
        None,
        Some(60.0),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        marker.exists(),
        "child must reach the session probe before cancellation"
    );
    let done = r.cancel(&run.id, "alice", "test_cancel").unwrap();
    assert_eq!(done.state, "cancelled");
    assert!(
        String::from_utf8_lossy(&done.stdout).contains("PROBE true true false\n"),
        "group-directed cancellation must target the child-led session without a controlling terminal: {:?}",
        String::from_utf8_lossy(&done.stdout)
    );
}
#[test]
fn cancellation_signals_descendants_in_the_new_process_group() {
    let (temp, _, r) = setup(1024);
    let ready = temp.path().join("descendant-ready");
    let terminated = temp.path().join("descendant-terminated");
    let run = queued(&r);
    // The CLI starts a descendant that records SIGTERM and then waits; the
    // CLI itself keeps running until it is signalled too.
    let descendant = r#"trap ': > "$2"; exit 0' TERM; : > "$1"; sleep 30 & wait $!"#;
    let cli = r#"/bin/sh -c "$1" descendant "$2" "$3" & sleep 30 & wait $!"#;
    r.start(
        &run,
        &[
            "/bin/sh".into(),
            "-c".into(),
            cli.into(),
            "cli".into(),
            descendant.into(),
            ready.to_string_lossy().into_owned(),
            terminated.to_string_lossy().into_owned(),
        ],
        &HashMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
        temp.path(),
        &[],
        None,
        Some(60.0),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !ready.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(ready.exists());
    assert_eq!(
        r.cancel(&run.id, "alice", "test_cancel").unwrap().state,
        "cancelled"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while !terminated.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        terminated.exists(),
        "group cancellation must signal the CLI's descendant too"
    );
}
#[test]
fn timeout_and_spawn_failure_are_terminal() {
    let (temp, _, r) = setup(1024);
    let run = queued(&r);
    start(&r, &run, "sleep 10", &temp, &[], 0.05);
    let done = r.wait(&run, Some(4.0));
    assert_eq!(done.state, "failed");
    assert_eq!(done.reason.as_deref(), Some("timeout"));
    let run = queued(&r);
    let done = r
        .start(
            &run,
            &[temp
                .path()
                .join("missing-executable")
                .to_string_lossy()
                .into_owned()],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            None,
        )
        .unwrap();
    assert_eq!(done.reason.as_deref(), Some("spawn_failed"));
}
#[test]
fn owners_cannot_enumerate_or_cancel_other_runs() {
    let (_, _, r) = setup(10);
    let run = queued(&r);
    assert_eq!(
        r.get(&run.id, "mallory").err().unwrap().reason,
        "run_not_found"
    );
    assert_eq!(
        r.cancel(&run.id, "mallory", "bad").err().unwrap().reason,
        "run_not_found"
    );
    assert_eq!(r.get(&run.id, "alice").unwrap().state, "queued");
}
#[test]
fn queued_cancellation_prevents_spawn_and_cleans_once() {
    let (temp, _, r) = setup(10);
    let run = queued(&r);
    r.cancel(&run.id, "alice", "cancelled_by_caller").unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    r.start(
        &run,
        &[
            "/bin/sh".into(),
            "-c".into(),
            "touch should-not-exist".into(),
        ],
        &HashMap::new(),
        temp.path(),
        &[],
        Some(Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        })),
        Some(2.0),
    )
    .unwrap();
    assert!(!temp.path().join("should-not-exist").exists());
    assert_eq!(count.load(Ordering::SeqCst), 1);
}
#[test]
fn finish_cleanup_happens_before_completion() {
    let (temp, _, r) = setup(10);
    let run = queued(&r);
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    r.start(
        &run,
        &["/usr/bin/true".into()],
        &HashMap::new(),
        temp.path(),
        &[],
        Some(Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        })),
        Some(2.0),
    )
    .unwrap();
    assert_eq!(r.wait(&run, Some(4.0)).state, "completed");
    assert_eq!(count.load(Ordering::SeqCst), 1);
}
#[test]
fn atomic_idempotency_has_one_creator_and_detects_reuse() {
    let (_, _, r) = setup(10);
    let barrier = Arc::new(Barrier::new(16));
    let mut threads = Vec::new();
    for _ in 0..16 {
        let r = r.clone();
        let b = barrier.clone();
        threads.push(std::thread::spawn(move || {
            b.wait();
            r.find_or_create(
                "alice",
                "c",
                "g",
                "http",
                "sh",
                Some("req"),
                "digest",
                None,
                None,
            )
            .unwrap()
        }));
    }
    let outcomes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|(_, created)| *created).count(), 1);
    assert!(outcomes.iter().all(|(r, _)| r.id == outcomes[0].0.id));
    assert_eq!(
        r.find_by_request("alice", "req", "changed")
            .err()
            .unwrap()
            .reason,
        "request_id_reused"
    );
    assert!(r.find_by_request("bob", "req", "digest").unwrap().is_none());
}
#[test]
fn revocation_targets_grant_and_global_stop_cancels_rest() {
    let (_, ctx, _) = setup(10);
    let r = runs::install(ctx.clone());
    let a = queued(&r);
    let b = r.create("bob", "c", "other", "ssh", "ssh", None, "", None, None);
    r.on_revoke("grant", Some("grant"));
    assert_eq!(
        r.get(&a.id, "alice").unwrap().reason.as_deref(),
        Some("grant_revoked")
    );
    assert_eq!(r.get(&b.id, "bob").unwrap().state, "queued");
    r.on_revoke("stop", None);
    assert_eq!(
        r.get(&b.id, "bob").unwrap().reason.as_deref(),
        Some("global_stop")
    );
    assert!(Arc::ptr_eq(&r, &runs::install(ctx.clone())));
    drop(r);
    // Python `tools.install(ctx)` attaches strongly to `ctx.runs`; dropping
    // the returned handle must not erase completed history or revocation state.
    assert!(runs::registry(&ctx).is_some());
}
#[test]
fn installed_registry_retains_history_without_return_owner_and_drops_without_cycle() {
    let temp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            temp.path().join("state"),
            "synthetic-admin-passphrase",
            "synthetic-recovery-passphrase",
            Config::default(),
            Arc::new(zeropw::store::now),
        )
        .unwrap(),
    );
    let run_dir = ctx.config.run_dir.clone().unwrap();
    let weak_ctx = Arc::downgrade(&ctx);
    runs::install(ctx.clone());
    let registry = runs::registry(&ctx).unwrap();
    assert!(Arc::ptr_eq(&registry, &runs::install(ctx.clone())));
    let run = registry.create(
        "alice",
        "conn",
        "grant",
        "http",
        "true",
        Some("request-id"),
        "digest",
        None,
        None,
    );
    registry
        .start(
            &run,
            &["/usr/bin/true".into()],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            Some(2.0),
        )
        .unwrap();
    let completion_deadline = Instant::now() + Duration::from_secs(4);
    assert_eq!(registry.wait(&run, Some(4.0)).state, "completed");
    drop(registry);
    let registry = runs::registry(&ctx).unwrap();
    assert_eq!(
        registry
            .find_by_request("alice", "request-id", "digest")
            .unwrap()
            .unwrap()
            .id,
        run.id
    );
    registry.on_revoke("grant", Some("grant"));
    drop(registry);
    assert!(
        run_dir.exists(),
        "owned execution directory must exist before drop"
    );
    drop(ctx);
    // `wait` observes the published terminal state, which precedes the
    // supervisor closure releasing its temporary strong Context lease. Keep
    // the original four-second completion budget while observing both lease
    // release and the owned-directory cleanup in Context::drop.
    while (weak_ctx.strong_count() != 0 || run_dir.exists()) && Instant::now() < completion_deadline
    {
        std::thread::yield_now();
    }
    assert!(
        weak_ctx.upgrade().is_none(),
        "Context and installed registry must not form an Arc cycle"
    );
    assert!(
        !run_dir.exists(),
        "owned execution directory must be removed with Context"
    );
}
#[test]
fn installed_registry_without_worker_has_no_context_cycle() {
    let temp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            temp.path().join("state"),
            "synthetic-admin-passphrase",
            "synthetic-recovery-passphrase",
            Config::default(),
            Arc::new(zeropw::store::now),
        )
        .unwrap(),
    );
    let run_dir = ctx.config.run_dir.clone().unwrap();
    let weak_ctx = Arc::downgrade(&ctx);
    assert!(run_dir.exists());
    runs::install(ctx.clone());
    assert!(runs::registry(&ctx).is_some());
    drop(ctx);
    assert!(
        weak_ctx.upgrade().is_none(),
        "installed registry must not retain Context without any worker"
    );
    assert!(
        !run_dir.exists(),
        "owned execution directory must be removed"
    );
}
#[test]
fn audit_failure_at_start_prevents_child_and_finish_hides_output() {
    let (temp, ctx, r) = setup(100);
    let file = ctx.state.path.join("audit/audit.jsonl");
    std::fs::rename(&file, file.with_extension("saved")).unwrap();
    std::fs::create_dir(&file).unwrap();
    let run = queued(&r);
    assert!(
        r.start(
            &run,
            &[
                "/bin/touch".into(),
                temp.path().join("bad").to_string_lossy().into_owned()
            ],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            None
        )
        .is_err()
    );
    assert!(!temp.path().join("bad").exists());
    assert_eq!(
        r.get(&run.id, "alice").unwrap().reason.as_deref(),
        Some("audit_unavailable")
    );
    std::fs::remove_dir(&file).unwrap();
    let run = queued(&r);
    start(
        &r,
        &run,
        "sleep 0.2; printf ordinary-business-output",
        &temp,
        &[],
        2.0,
    );
    std::fs::remove_file(&file).unwrap();
    std::fs::create_dir(&file).unwrap();
    let done = r.wait(&run, Some(3.0));
    assert_eq!(done.state, "failed");
    assert_eq!(
        done.reason.as_deref(),
        Some("audit_unavailable"),
        "state={} exit={:?} stderr={:?}",
        done.state,
        done.exit_code,
        done.stderr
    );
    assert!(done.stdout.is_empty() && done.stderr.is_empty());
}
#[test]
fn audit_listener_can_cancel_before_spawn_without_deadlock() {
    let (temp, ctx, r) = setup(10);
    let weak = Arc::downgrade(&r);
    ctx.audit.subscribe(move |record| {
        if record.get("event") == Some(&json!("run_start"))
            && let Some(r) = weak.upgrade()
        {
            r.cancel_all("detector_lockdown", None);
        }
    });
    let run = queued(&r);
    start(&r, &run, "touch forbidden", &temp, &[], 1.0);
    assert_eq!(r.get(&run.id, "alice").unwrap().state, "cancelled");
    assert!(!temp.path().join("forbidden").exists());
}
#[test]
fn finish_listener_can_query_and_cancel_without_publishing_partial_result() {
    let (temp, ctx, r) = setup(1024);
    let weak = Arc::downgrade(&r);
    let (tx, rx) = std::sync::mpsc::channel();
    ctx.audit.subscribe(move |record| {
        if record.get("event") == Some(&json!("run_finish"))
            && let Some(r) = weak.upgrade()
            && let Some(id) = record.get("run_id").and_then(Value::as_str)
        {
            let before = r.get(id, "alice").unwrap();
            assert_eq!(r.cancel_all("listener_stop", None), 0);
            let after = r.cancel(id, "alice", "listener_cancel").unwrap();
            tx.send((before, after)).unwrap();
        }
    });
    let run = queued(&r);
    start(&r, &run, "printf business-output", &temp, &[], 2.0);
    let (before, after) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(before.state, "running");
    assert!(before.stdout.is_empty());
    assert_eq!(after.state, "running");
    assert!(!after.cancel_requested);
    let done = r.wait(&run, Some(5.0));
    assert_eq!(done.state, "completed");
    assert_eq!(done.stdout, b"business-output");
}
/// Every output-filter form of a credential (raw, stripped, encodings and
/// their alignments) exactly as the original `credential_patterns` derived
/// it, for binary values, whitespace and alignment cases
/// (`fixtures/python/runs/credential_patterns.json`).
#[test]
fn patterns_match_python_oracle_for_binary_and_alignment_cases() {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/python/runs/credential_patterns.json"
    ))
    .unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for case in cases {
        let secret = engine.decode(case["secret"].as_str().unwrap()).unwrap();
        let expected: Vec<Vec<u8>> = case["patterns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| engine.decode(p.as_str().unwrap()).unwrap())
            .collect();
        assert_eq!(runs::credential_patterns(&secret), expected, "{secret:?}");
    }
}
