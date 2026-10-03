//! Team snapshot scheduling over hand-written snapshot vectors.
//!
//! `TeamSync` keeps `last_snapshot_total` = the sum of the newest
//! snapshot's `vector` and saves a new snapshot when the refolded total
//! exceeds it by `SNAPSHOT_INTERVAL_COMMITS`. Integer totals are exact at any
//! magnitude; a vector that cannot be summed, or a snapshot that is not an
//! object, makes `register_env` fail closed. Outcomes were measured against
//! the Python prototype's `TeamSync` (whose `sum()` raised in the same
//! places) and are pinned here.
use std::sync::Arc;

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::clock;
use zeropw::context::{Config, Context};
use zeropw::team::identity::{DeviceKey, DeviceRecord};
use zeropw::team::transport::{InProcessTransport, MembershipCheck};
use zeropw::team::{membership, sync};

const ADMIN: &str = "synthetic-admin";

fn no_members() -> MembershipCheck {
    Arc::new(|_: &str, _: &str| -> Option<DeviceRecord> { None })
}

fn rust_schedule(raw: &str) -> Value {
    let root = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            root.path().join("a"),
            ADMIN,
            "synthetic-recovery",
            Config {
                team_sync_interval_seconds: Some(3600.0),
                ..Config::default()
            },
            clock::system(),
        )
        .unwrap(),
    );
    ctx.projects.create("demo", &["dev"]).unwrap();
    let env_id = membership::share_environment(&ctx, None, "demo", "dev", "owner", ADMIN).unwrap()
        ["env_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let snapshots = ctx.state.path.join("team").join(&env_id).join("snapshots");
    std::fs::create_dir_all(&snapshots).unwrap();
    std::fs::write(snapshots.join("0.json"), raw).unwrap();
    let device = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let transport = Arc::new(InProcessTransport::new(device.clone(), no_members()));
    let team = sync::TeamSync::new(ctx.clone(), transport, device);
    let result = match team.register_env(&env_id) {
        Ok(()) => {
            let mut names: Vec<String> = std::fs::read_dir(&snapshots)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            json!(names)
        }
        Err(_) => json!("RAISE"),
    };
    team.stop();
    result
}

/// `_load_env_locked`'s sum of a hand-written snapshot vector and
/// `_refold`'s `total - last_snapshot_total >= SNAPSHOT_INTERVAL_COMMITS`:
/// huge and negative integer entries decide whether the next snapshot is
/// saved; non-numbers, an int too large for its float neighbour, and
/// non-dict shapes make `register_env` fail closed (the Python prototype
/// raised `TypeError`/`OverflowError`/`AttributeError` there).
#[test]
fn snapshot_scheduling_follows_exact_integer_totals_and_fails_closed() {
    let doc = |vector: &str| {
        format!(r#"{{"document": null, "version_order": {{}}, "vector": {vector}}}"#)
    };
    let huge = format!("1{}", "0".repeat(30));
    let enormous = format!("1{}", "0".repeat(400));
    let saved = json!(["0.json", "1.json"]);
    let not_saved = json!(["0.json"]);
    let cases: Vec<(&str, String, Value)> = vec![
        // A positive integer floor would make `all_commits` iterate
        // `range(1, floor + 1)`; only negative ones here.
        ("near_boundary_int", doc(r#"{"x": -999}"#), saved.clone()),
        ("negative_huge", doc(&format!(r#"{{"x": -{huge}}}"#)), saved),
        ("falsy_list_vector", doc("[]"), not_saved.clone()),
        ("null_snapshot", "null".to_string(), not_saved),
        ("string_value", doc(r#"{"x": "a"}"#), json!("RAISE")),
        ("null_value", doc(r#"{"x": null}"#), json!("RAISE")),
        (
            "int_too_large_for_float",
            doc(&format!(r#"{{"x": 0.5, "y": -{enormous}}}"#)),
            json!("RAISE"),
        ),
        ("truthy_list_vector", doc("[1]"), json!("RAISE")),
        ("zero_snapshot", "0".to_string(), json!("RAISE")),
    ];
    for (name, text, expected) in &cases {
        assert_eq!(rust_schedule(text), *expected, "{name}");
    }
}
