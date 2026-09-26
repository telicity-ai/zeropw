//! Response parity gaps: each test pins one Python behaviour of
//! `zeropw/{incident,intrusion,notify}.py` (and `smtplib` as used there) that
//! the Rust port previously diverged from. Synthetic values and loopback only.
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use serde_json::Value;
use tempfile::TempDir;
use zeropw::audit::RecordArgs;
use zeropw::clock::Clock;
use zeropw::context::{Config, Context};
use zeropw::intrusion;

#[path = "../src/oracle.rs"]
#[allow(dead_code)]
mod oracle;

fn fixture_with_clock(clock: Clock) -> (TempDir, Arc<Context>) {
    let tmp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            tmp.path().join("state"),
            "synthetic-admin-passphrase",
            "synthetic-recovery-passphrase",
            Config {
                socket_dir: Some(tmp.path().join("sockets")),
                run_dir: Some(tmp.path().join("runs")),
                ..Config::default()
            },
            clock,
        )
        .unwrap(),
    );
    (tmp, ctx)
}

fn unknown_tool(ctx: &Context, caller: &str) {
    ctx.audit
        .record(
            "tools_unknown",
            RecordArgs {
                caller: Some(caller),
                result: Some("denied"),
                reason: Some("tool_not_found"),
                ..Default::default()
            },
        )
        .unwrap();
}

/// Python `test_a_failing_open_incident_is_counted_not_raised`: an exception
/// inside `_apply_decision` increments `decision_errors` and the very next
/// crossing still opens an incident. In Rust the equivalent failure is a
/// panic inside `open_incident`; it must neither escape nor poison the
/// decision lock (which silently disabled every later trip).
#[test]
fn panic_inside_the_decision_is_counted_and_detection_keeps_working() {
    // A clock that panics on its N-th call once armed. The arming listener is
    // subscribed before the detector, so on the tripping record the detector
    // reads the clock once (`now`) and `open_incident` reads it next.
    let countdown = Arc::new(AtomicI64::new(0));
    let clock_countdown = Arc::clone(&countdown);
    let clock: Clock = Arc::new(move || {
        if clock_countdown.load(Ordering::SeqCst) > 0
            && clock_countdown.fetch_sub(1, Ordering::SeqCst) == 1
        {
            panic!("synthetic failure inside the intrusion decision");
        }
        1_700_000_000.0
    });
    let (_tmp, ctx) = fixture_with_clock(clock);
    ctx.policy.create_principal("agent-1", "box-1").unwrap();
    let arm = Arc::new(AtomicI64::new(0));
    let (listener_arm, listener_countdown) = (Arc::clone(&arm), Arc::clone(&countdown));
    ctx.audit.subscribe(move |record| {
        if record.get("event").and_then(Value::as_str) == Some("tools_unknown")
            && listener_arm.swap(0, Ordering::SeqCst) == 1
        {
            listener_countdown.store(2, Ordering::SeqCst);
        }
    });
    let detector = intrusion::install(Arc::clone(&ctx), None).unwrap();

    unknown_tool(&ctx, "agent-1");
    arm.store(1, Ordering::SeqCst);
    unknown_tool(&ctx, "agent-1"); // trips unknown_tool; open_incident panics
    assert_eq!(countdown.load(Ordering::SeqCst), 0, "the panic was reached");
    assert_eq!(detector.decision_errors.load(Ordering::SeqCst), 1);
    assert!(
        ctx.policy.open_incident_id().unwrap().is_none(),
        "the failed decision must not have left anything open"
    );

    unknown_tool(&ctx, "agent-1");
    let open = ctx.policy.open_incident_id().unwrap();
    assert!(
        open.is_some(),
        "the next crossing must still open an incident"
    );
    let incident = zeropw::incident::get_incident(&ctx, &open.unwrap()).unwrap();
    assert_eq!(incident.principals, vec!["agent-1".to_owned()]);
    assert_eq!(incident.rule.as_deref(), Some("unknown_tool"));
    assert_eq!(detector.decision_errors.load(Ordering::SeqCst), 1);
}
