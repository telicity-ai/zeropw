//! The request ledger's `updated_at` sweep when a claim saves the ledger.
//! The prototype persisted `updated_at` as a JSON float (`PORTING.md` §0
//! boundary 1): entries older than `LEDGER_TTL_SECONDS` are dropped, newer
//! ones kept. A hand-edited, non-numeric `updated_at` fails the claim closed
//! instead of being guessed at.

use std::sync::Arc;

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::gateway::{LEDGER_DOC, LEDGER_TTL_SECONDS, RequestLedger};

const NOW: f64 = 100_000.0;

fn context(temp: &TempDir) -> Context {
    let clock: zeropw::clock::Clock = Arc::new(|| NOW);
    Context::initialize(
        temp.path().join("state"),
        "synthetic-admin-passphrase",
        "synthetic-recovery-passphrase",
        Config::default(),
        clock,
    )
    .unwrap()
}

fn claim_with_probe(ctx: &Context, index: usize, updated_at: Value) -> Option<bool> {
    ctx.state
        .write_json(
            LEDGER_DOC,
            &json!({"other": {"probe": {"updated_at": updated_at, "state": "completed"}}}),
        )
        .unwrap();
    let result = RequestLedger::new(ctx).claim(
        "caller",
        &format!("request-{index}"),
        "digest",
        "connection",
    );
    let (state, _) = result.ok()?;
    assert_eq!(state, "new");
    let stored = ctx.state.read_json(LEDGER_DOC, json!({})).unwrap();
    Some(stored["other"].get("probe").is_some())
}

#[test]
fn persisted_float_updated_at_drives_the_ttl_sweep() {
    let temp = TempDir::new().unwrap();
    let ctx = context(&temp);
    let cases = [
        (json!(NOW), true),
        (json!(NOW - 1.5), true),
        (json!(NOW - LEDGER_TTL_SECONDS), true),
        (json!(NOW - LEDGER_TTL_SECONDS - 0.5), false),
        (json!(1_700.25), false),
        (json!(0.0), false),
    ];
    for (index, (updated_at, retained)) in cases.into_iter().enumerate() {
        assert_eq!(
            claim_with_probe(&ctx, index, updated_at.clone()),
            Some(retained),
            "updated_at={updated_at}"
        );
    }
}

#[test]
fn non_numeric_updated_at_fails_the_claim_closed() {
    let temp = TempDir::new().unwrap();
    let ctx = context(&temp);
    for (index, text) in ["soon", "1 2", "", "--1"].into_iter().enumerate() {
        assert_eq!(
            claim_with_probe(&ctx, 100 + index, json!(text)),
            None,
            "updated_at={text:?}"
        );
    }
}
