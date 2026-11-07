use serde_json::{Value, json};
use zeropw::{
    crypto::ed25519,
    pybase64,
    pyjson::{self, DumpOptions},
    team::{checkpoint::*, identity::DeviceRecord},
};
fn load(bytes: &[u8]) -> Value {
    pyjson::loads(std::str::from_utf8(bytes).unwrap()).unwrap()
}
fn canon(value: &Value) -> Vec<u8> {
    pyjson::dumps(value, DumpOptions::compact_sorted())
        .unwrap()
        .into_bytes()
}
fn context() -> ExpectedContext {
    let c = load(include_bytes!("fixtures/team_checkpoint_v1/context.json"));
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
            invitation_expires_at_ms: 1_800_003_600_000,
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
fn verify(bytes: &[u8]) -> ManifestAttestation {
    verify_manifest_bytes(
        bytes,
        &context(),
        VerificationWallTime::from_millis(1_800_000_000_001).unwrap(),
    )
    .unwrap()
}
#[test]
fn exact_candidate_golden_and_immutable_inspection() {
    let a = verify(include_bytes!("fixtures/team_checkpoint_v1/manifest.json"));
    let p = verify_payload_bytes(
        &a,
        include_bytes!("fixtures/team_checkpoint_v1/payload.json"),
    )
    .unwrap();
    let c = candidate_provenance(&a, &p).unwrap();
    assert_eq!(
        c.canonical_json().unwrap(),
        include_bytes!("fixtures/team_checkpoint_v1/candidate.json")
    );
    let mut inspected = load(&c.canonical_json().unwrap());
    inspected["stage"] = json!("full_history_verified");
    assert_ne!(canon(&inspected), c.canonical_json().unwrap());
    assert!(!format!("{a:?} {p:?} {c:?}").contains("copdsqh"));
}
#[test]
fn exact_per_fact_and_tombstone_candidate_bindings() {
    let a = verify(include_bytes!(
        "fixtures/team_checkpoint_v1/variants/deleted-retained/manifest.json"
    ));
    let p = verify_payload_bytes(
        &a,
        include_bytes!("fixtures/team_checkpoint_v1/variants/deleted-retained/payload.json"),
    )
    .unwrap();
    let c = candidate_provenance(&a, &p).unwrap();
    let value = load(&c.canonical_json().unwrap());
    assert_eq!(
        c.canonical_json().unwrap(),
        include_bytes!("fixtures/team_checkpoint_v1/variants/deleted-retained/candidate.json")
    );
    assert_eq!(value["trust_model"], "administrator_attested");
    assert_eq!(value["stage"], "integrity_checked_not_admitted");
    assert_eq!(
        value["candidate_fact_bindings"].as_array().unwrap().len(),
        p.candidate_fact_hashes().len()
    );
    for (binding, hash) in value["candidate_fact_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .zip(p.candidate_fact_hashes())
    {
        assert_eq!(binding["fact_hash"], hash.as_str());
        assert_eq!(binding["manifest_hash"], a.manifest_hash());
        assert_eq!(binding["approved_signer"], a.signed_metadata()["signer"]);
        assert_eq!(
            binding["approval_sha256"],
            a.signed_metadata()["approval_sha256"]
        );
        assert_eq!(binding["basis"], "administrator_attested_candidate");
    }
}
#[test]
fn another_attestation_cannot_be_paired_even_with_identical_payload() {
    let raw = include_bytes!("fixtures/team_checkpoint_v1/payload.json");
    let a = verify(include_bytes!("fixtures/team_checkpoint_v1/manifest.json"));
    let p = verify_payload_bytes(&a, raw).unwrap();
    let mut m = a.signed_metadata().clone();
    m["transfer_id"] = json!("41".repeat(16));
    m.as_object_mut().unwrap().remove("sig");
    let sig = ed25519::sign(&[1; 32], &canon(&m)).unwrap();
    m["sig"] = json!(pybase64::b64encode(&sig));
    let b = verify(&canon(&m));
    verify_payload_bytes(&b, raw).unwrap();
    assert_eq!(
        candidate_provenance(&b, &p).unwrap_err(),
        CheckpointError::BindingMismatch
    );
}
#[test]
fn source_has_no_production_runtime_caller_or_authority_conversion() {
    for source in [
        include_str!("../src/team/sync.rs"),
        include_str!("../src/team/membership.rs"),
        include_str!("../src/team/pairing.rs"),
        include_str!("../src/team/sync_status.rs"),
        include_str!("../src/team/transport.rs"),
    ] {
        assert!(!source.contains("checkpoint::"));
    }
    for source in [
        include_str!("../src/team/checkpoint/manifest.rs"),
        include_str!("../src/team/checkpoint/payload.rs"),
        include_str!("../src/team/checkpoint/provenance.rs"),
    ] {
        for name in [
            "StateDir",
            "DeviceKey",
            "Kms",
            "verify_fact(",
            "load_facts(",
            "verify_commit(",
            "apply_fact(",
            "receipt_fact(",
            "validate_fact_target(",
            "std::fs",
            "std::net",
        ] {
            assert!(!source.contains(name), "{name}");
        }
    }
}
