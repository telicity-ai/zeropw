use serde_json::{Value, json};
use zeropw::{
    crypto::ed25519,
    pybase64,
    pyjson::{self, DumpOptions},
    team::{checkpoint::*, identity::DeviceRecord},
};

#[path = "common/team_checkpoint.rs"]
mod frozen_fixture_consistency;

const MANIFEST: &[u8] = include_bytes!("fixtures/team_checkpoint_v1/manifest.json");
const CONTEXT: &str = include_str!("fixtures/team_checkpoint_v1/context.json");
const T: u64 = 1_800_000_000_001;
fn load(bytes: &[u8]) -> Value {
    pyjson::loads(std::str::from_utf8(bytes).unwrap()).unwrap()
}
fn canon(value: &Value) -> Vec<u8> {
    pyjson::dumps(value, DumpOptions::compact_sorted())
        .unwrap()
        .into_bytes()
}
fn context() -> ExpectedContext {
    let c = pyjson::loads(CONTEXT).unwrap();
    let a = &c["approval"];
    ExpectedContext::from_local_expectations(
        LocalApprovalDescription {
            approval_id: a["approval_id"].as_str().unwrap().into(),
            env_id: a["env_id"].as_str().unwrap().into(),
            signer: a["signer"].as_str().unwrap().into(),
            signer_record: DeviceRecord::from_dict(&a["signer_record"]).unwrap(),
            recipient: a["recipient"].as_str().unwrap().into(),
            recipient_role: RecipientRole::User,
            invite_id: a["invite_id"].as_str().unwrap().into(),
            invitation_expires_at_ms: a["invitation_expires_at_ms"].as_u64().unwrap(),
        },
        AuthenticatedSessionExpectations {
            peer_record: DeviceRecord::from_dict(&c["authenticated_peer_record"]).unwrap(),
            env_id: c["session_env_id"].as_str().unwrap().into(),
            local_recipient: c["local_recipient"].as_str().unwrap().into(),
            session_nonce: c["session_nonce"].as_str().unwrap().into(),
            onboarding_nonce: c["onboarding_nonce"].as_str().unwrap().into(),
        },
    )
    .unwrap()
}
fn resign(mut value: Value) -> Vec<u8> {
    value.as_object_mut().unwrap().remove("sig");
    let sig = ed25519::sign(&[1; 32], &canon(&value)).unwrap();
    value["sig"] = json!(pybase64::b64encode(&sig));
    canon(&value)
}
fn verify(bytes: &[u8]) -> Result<ManifestAttestation, CheckpointError> {
    verify_manifest_bytes(
        bytes,
        &context(),
        VerificationWallTime::from_millis(T).unwrap(),
    )
}

#[test]
fn pinned_baseline_has_literal_canonical_hash_signature_cut_and_counts() {
    let proof = verify(MANIFEST).unwrap();
    assert_eq!(
        proof.manifest_hash(),
        "c0f1ae45ebe4b3bfe033a66c946d02edf562a14b167d01c6b990e093b1b96ddb"
    );
    assert_eq!(proof.counts(), [3, 5, 0, 2, 1]);
    assert_eq!(proof.components().len(), 6);
    assert_eq!(proof.chunks().len(), 1);
    assert_eq!(proof.heads().len(), 2);
    assert_eq!(
        canon(proof.signed_metadata()),
        include_bytes!("fixtures/team_checkpoint_v1/manifest.signed.canon")
    );
    assert_eq!(
        context().approval_sha256(),
        "b6b29bfd0fb8a9d2392a7f8613fc565e4fb79ddb2dd709088d5f6db8d8218fa6"
    );
    let c = load(CONTEXT.as_bytes());
    let pin = DeviceRecord::from_dict(&c["authenticated_peer_record"]).unwrap();
    assert!(ed25519::verify(
        &pin.sign_pub,
        include_bytes!("fixtures/team_checkpoint_v1/manifest.unsigned.canon"),
        &pybase64::b64decode_strict(load(MANIFEST)["sig"].as_str().unwrap()).unwrap()
    ));
}
#[test]
fn every_request_approval_session_binding_refuses_even_when_resigned() {
    for (key, value) in [
        (
            "env_id",
            json!("copdsqhgjnkjc4rardm2bv2bmi-ffffffffffffffffffffffffffffffff"),
        ),
        ("signer", json!("aaaaaaaaaaaaaaaaaaaaaaaaaa")),
        ("recipient", json!("aaaaaaaaaaaaaaaaaaaaaaaaaa")),
        ("recipient_role", json!("admin")),
        ("invite_id", json!("11".repeat(16))),
        ("approval_id", json!("21".repeat(16))),
        ("approval_sha256", json!("0".repeat(64))),
        ("session_nonce", json!("51".repeat(32))),
        ("onboarding_nonce", json!("61".repeat(32))),
    ] {
        let mut value_m = load(MANIFEST);
        value_m[key] = value;
        assert_eq!(
            verify(&resign(value_m)).unwrap_err(),
            CheckpointError::BindingMismatch,
            "{key}"
        );
    }
    let mut c = load(CONTEXT.as_bytes());
    c["authenticated_peer_record"]["agree_pub"] = json!(pybase64::b64encode(&[0; 32]));
    let a = &c["approval"];
    let result = ExpectedContext::from_local_expectations(
        LocalApprovalDescription {
            approval_id: a["approval_id"].as_str().unwrap().into(),
            env_id: a["env_id"].as_str().unwrap().into(),
            signer: a["signer"].as_str().unwrap().into(),
            signer_record: DeviceRecord::from_dict(&a["signer_record"]).unwrap(),
            recipient: a["recipient"].as_str().unwrap().into(),
            recipient_role: RecipientRole::User,
            invite_id: a["invite_id"].as_str().unwrap().into(),
            invitation_expires_at_ms: 1_800_003_600_000,
        },
        AuthenticatedSessionExpectations {
            peer_record: DeviceRecord::from_dict(&c["authenticated_peer_record"]).unwrap(),
            env_id: a["env_id"].as_str().unwrap().into(),
            local_recipient: a["recipient"].as_str().unwrap().into(),
            session_nonce: "50".repeat(32),
            onboarding_nonce: "60".repeat(32),
        },
    );
    assert_eq!(result.unwrap_err(), CheckpointError::BindingMismatch);
}
#[test]
fn closed_schema_features_signature_and_source_integers() {
    for (key, value) in [
        ("domain", json!("other")),
        ("v", json!(2)),
        (
            "required_features",
            json!(["snapshot_bootstrap_v1", "secret_tombstone_v1"]),
        ),
        (
            "required_features",
            json!(["secret_tombstone_v1", "snapshot_bootstrap_v1", "unknown"]),
        ),
        ("extra", json!({"sig":"sensitive-marker"})),
    ] {
        let mut m = load(MANIFEST);
        m[key] = value;
        assert!(verify(&resign(m)).is_err(), "{key}");
    }
    for key in [
        "type",
        "domain",
        "sig",
        "counts",
        "components",
        "payload",
        "approval_id",
    ] {
        let mut m = load(MANIFEST);
        m.as_object_mut().unwrap().remove(key);
        assert!(verify(&canon(&m)).is_err(), "{key}");
    }
    let mut m = load(MANIFEST);
    m["sig"] = json!(pybase64::b64encode(&[0; 64]));
    assert_eq!(
        verify(&canon(&m)).unwrap_err(),
        CheckpointError::SignatureInvalid
    );
    for original in [
        "true",
        "\"1\"",
        "1.0",
        "1e0",
        "-0",
        "-1",
        "1844674407370955161600000000000000000001",
    ] {
        let raw = String::from_utf8(MANIFEST.to_vec()).unwrap().replacen(
            "\"devices\":3",
            &format!("\"devices\":{original}"),
            1,
        );
        assert!(verify(raw.as_bytes()).is_err(), "{original}");
    }
    let raw = String::from_utf8(MANIFEST.to_vec()).unwrap();
    let duplicate = raw.replacen('{', "{\"v\":1,", 1);
    assert_eq!(
        verify(duplicate.as_bytes()).unwrap_err(),
        CheckpointError::DuplicateKey
    );
}
#[test]
fn exact_wall_freshness_and_overflow_boundaries() {
    for (created, expires, authorization, ok) in [
        (T - 1, T, T + 3_600_000, false),
        (T + 60_000, T + 60_001, T + 3_000_000, true),
        (T + 60_001, T + 60_002, T + 3_000_000, false),
        (T, T + 600_000, T + 3_000_000, true),
        (T, T + 600_001, T + 3_000_000, false),
        (T, T + 10, T + 9, false),
        (T, T + 10, 1_800_003_600_001, false),
        (T, T, T + 3_000_000, false),
    ] {
        let mut m = load(MANIFEST);
        m["created_at_ms"] = json!(created);
        m["expires_at_ms"] = json!(expires);
        m["authorization_expires_at_ms"] = json!(authorization);
        assert_eq!(
            verify(&resign(m)).is_ok(),
            ok,
            "{created} {expires} {authorization}"
        );
    }
    let mut m = load(MANIFEST);
    m["expires_at_ms"] = json!(9_223_372_036_854_775_808u64);
    assert_eq!(
        verify(&resign(m)).unwrap_err(),
        CheckpointError::LimitExceeded
    );
    assert!(VerificationWallTime::from_millis(u64::MAX).is_err());
}
#[test]
fn raw_size_partition_and_declared_count_boundaries() {
    let mut padded = MANIFEST.to_vec();
    padded.resize(65_536, b' ');
    verify(&padded).unwrap();
    padded.push(b' ');
    assert_eq!(verify(&padded).unwrap_err(), CheckpointError::LimitExceeded);
    for length in [0, 16_777_217] {
        let mut m = load(MANIFEST);
        m["payload"]["byte_length"] = json!(length);
        assert_eq!(
            verify(&resign(m)).unwrap_err(),
            CheckpointError::LimitExceeded
        );
    }
    for count in [65_537, u32::MAX] {
        let mut m = load(MANIFEST);
        m["counts"]["facts"] = json!(count);
        assert_eq!(
            verify(&resign(m)).unwrap_err(),
            CheckpointError::LimitExceeded
        );
    }
    let mut m = load(MANIFEST);
    m["payload"]["chunks"][0]["byte_length"] = json!(1);
    assert_eq!(
        verify(&resign(m)).unwrap_err(),
        CheckpointError::StructureInvalid
    );
    for n in [256, 257] {
        let mut m = load(MANIFEST);
        let length = n * 65_536;
        m["payload"]["byte_length"] = json!(length);
        m["payload"]["chunks"] = Value::Array(
            (0..n)
                .map(|i| json!({"index":i,"byte_length":65_536,"sha256":"0".repeat(64)}))
                .collect(),
        );
        let result = verify(&resign(m));
        assert_eq!(result.is_ok(), n == 256, "{n}");
    }
}
#[test]
fn debug_and_errors_are_redacted() {
    let proof = verify(MANIFEST).unwrap();
    assert!(!format!("{proof:?}").contains("copds"));
    let error = verify(b"{\"sensitive-marker\":invalid}").unwrap_err();
    assert!(!format!("{error:?} {error}").contains("sensitive-marker"));
}
