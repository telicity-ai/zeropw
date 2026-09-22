//! Exact integer boundaries beyond the signed/unsigned machine range.
use std::sync::Arc;

use serde_json::{Value, json};
use zeropw::{
    audit::RecordArgs,
    context::{Config, Context},
    intrusion::{self, DetectorConfig},
};

#[test]
fn detector_mapping_retains_python_integer_types_and_decimal_json() {
    for falsy in [
        json!(null),
        json!(false),
        json!(0),
        json!(""),
        json!([]),
        json!({}),
    ] {
        assert_eq!(
            DetectorConfig::from_mapping(Some(&falsy)).unwrap(),
            DetectorConfig::default()
        );
    }
    for key in ["weak_threshold", "enumeration_min", "burst_count"] {
        assert!(DetectorConfig::from_mapping(Some(&json!({key:true}))).is_err());
    }
    let enormous = "184467440737095516160000000000000000000";
    let source: Value = serde_json::from_str(&format!(
        "{{\"weak_threshold\":{enormous},\"weak_points\":{{\"scope_violation\":{enormous}}}}}"
    ))
    .unwrap();
    let config = DetectorConfig::from_mapping(Some(&source)).unwrap();
    assert_eq!(json!(config.weak_threshold), source["weak_threshold"]);
    assert_eq!(
        json!(config.weak_points["scope_violation"]),
        source["weak_points"]["scope_violation"]
    );
}

#[test]
fn combined_large_weak_weights_cross_exact_large_threshold() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            tmp.path().join("state"),
            "synthetic-admin",
            "synthetic-recovery",
            Config::default(),
            zeropw::clock::fixed(1_700_000_000.0),
        )
        .unwrap(),
    );
    ctx.policy.create_principal("agent", "runtime").unwrap();
    let config = DetectorConfig::from_mapping(Some(&json!({
        "weak_threshold": 36893488147419103232_u128,
        "weak_points": {"scope_violation": 18446744073709551616_u128}
    })))
    .unwrap();
    let _detector = intrusion::install(Arc::clone(&ctx), Some(config)).unwrap();
    let record = || {
        ctx.audit
            .record(
                "tools_request",
                RecordArgs {
                    caller: Some("agent"),
                    result: Some("denied"),
                    reason: Some("path_not_allowed"),
                    ..Default::default()
                },
            )
            .unwrap()
    };
    record();
    assert!(ctx.policy.open_incident_id().unwrap().is_none());
    record();
    assert!(ctx.policy.open_incident_id().unwrap().is_some());
}
