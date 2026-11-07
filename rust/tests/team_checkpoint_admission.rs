#[path = "common/team_checkpoint_semantics.rs"]
mod support;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use support::*;
use zeropw::{
    pybase64,
    pyint::PyInt,
    team::{checkpoint::*, commit, sync},
};

fn refusal(h: &History, mut p: Package, expected: SemanticError) {
    p.rebind(&h.keys[h.signer]);
    let m = p.attestation(h);
    let raw = canon(&p.payload);
    let payload =
        verify_payload_bytes(&m, &raw).expect("negative must pass repaired outer integrity");
    let local = h.local(&m);
    assert_eq!(
        verify_retained_authority(&m, &payload, &local).unwrap_err(),
        expected
    );
}
fn with_commit(h: &mut History, c: commit::Commit) {
    h.retained.push(h.history.len());
    h.history.push(c);
}
#[test]
fn stage_pairing_revision_immutability_and_false_final_overlay() {
    let h = history("P1");
    let mut p = h.package();
    p.manifest["expected_final_document_sha256"] = json!("ff".repeat(32));
    p.payload["components"][1]["data"]["expected_final_document_sha256"] = json!("ff".repeat(32));
    p.rebind(&h.keys[h.signer]);
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    let before = raw.clone();
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let local = h.local(&m);
    let c = verify_retained_authority(&m, &payload, &local).unwrap();
    assert_eq!(c.stage(), "retained_authority_checked_not_admitted");
    assert_eq!(c.trust_model(), "administrator_attested");
    assert_eq!(c.payload_sha256(), sha(&raw));
    assert_eq!(c.original_fact_count(), 0);
    assert_eq!(
        c.tombstone_digest(),
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
    );
    assert_eq!(c.operation_position(0).unwrap().3, 0);
    assert!(c.operation_position(100).is_none());
    let mut b = h.bindings(&m);
    b.observation_revision = "b2".repeat(32);
    let new_local =
        SemanticLocalInputs::from_local_observation(b, inventory(), vec![], restrictions())
            .unwrap();
    let new = verify_retained_authority(&m, &payload, &new_local).unwrap();
    assert_ne!(c.observation_revision(), new.observation_revision());
    assert_eq!(raw, before);
    assert_eq!(format!("{c:?}"), "RetainedAuthorityCandidate([redacted])");
    let mut other = h.package();
    other.manifest["transfer_id"] = json!("41".repeat(16));
    other.rebind(&h.keys[1]);
    let other_m = other.attestation(&h);
    assert_eq!(
        verify_retained_authority(&other_m, &payload, &local).unwrap_err(),
        SemanticError::Checkpoint(CheckpointError::BindingMismatch)
    );
    for field in [
        "manifest",
        "approval",
        "environment",
        "session",
        "onboarding",
        "recipient",
        "role",
    ] {
        let mut b = h.bindings(&m);
        match field {
            "manifest" => b.manifest_hash = "12".repeat(32),
            "approval" => b.approval_sha256 = "13".repeat(32),
            "environment" => {
                b.env_id = format!("{}-{}", h.fps[0], "02".repeat(16));
                b.intended_mapping.env_id = b.env_id.clone();
            }
            "session" => b.session_nonce = "14".repeat(32),
            "onboarding" => b.onboarding_nonce = "15".repeat(32),
            "recipient" => b.recipient_record = key(2, 0x22).record().unwrap(),
            "role" => b.recipient_role = RecipientRole::Admin,
            _ => unreachable!(),
        }
        let l = SemanticLocalInputs::from_local_observation(b, inventory(), vec![], restrictions())
            .unwrap();
        assert_eq!(
            verify_retained_authority(&m, &payload, &l).unwrap_err(),
            SemanticError::Checkpoint(CheckpointError::BindingMismatch),
            "{field}"
        );
    }
}

#[test]
fn original_signatures_schema_environment_and_canonical_identity() {
    for kind in [
        "commit-signature",
        "fact-signature",
        "bad-op",
        "bad-target",
        "wrong-environment",
        "wrong-fact-environment",
        "unknown-fact-kind",
        "wrong-hash",
        "unknown-author",
    ] {
        let h = history("P2");
        let mut p = h.package();
        match kind {
            "commit-signature" => {
                p.commit_mut(&h.fps[0], 4)["sig"] = json!(pybase64::b64encode(&[0; 64]));
                p.repair_commits();
            }
            "fact-signature" => {
                p.payload["components"][3]["data"]["records"][0]["record"]["sig"] =
                    json!(pybase64::b64encode(&[0; 64]));
                p.repair_facts();
            }
            "bad-op" => {
                let c = p.commit_mut(&h.fps[0], 4);
                c["ops"][0]["generation_id"] = json!(true);
                resign(c, &h.keys[0]);
                p.repair_commits();
            }
            "bad-target" => {
                let f = &mut p.payload["components"][3]["data"]["records"][0]["record"];
                f["target"] = json!({"secret_id":SECRET,"version_id":V1});
                let idx = h
                    .fps
                    .iter()
                    .position(|fp| Some(fp.as_str()) == f["author"].as_str())
                    .unwrap();
                resign(f, &h.keys[idx]);
                p.repair_facts();
            }
            "wrong-environment" => {
                let c = p.commit_mut(&h.fps[0], 4);
                c["env_id"] = json!(format!("{}-{}", h.fps[0], "00".repeat(16)));
                resign(c, &h.keys[0]);
                p.repair_commits();
            }
            "wrong-fact-environment" => {
                let f = &mut p.payload["components"][3]["data"]["records"][0]["record"];
                f["env_id"] = json!(format!("{}-{}", h.fps[0], "03".repeat(16)));
                let author = h.fps.iter().position(|fp| f["author"] == *fp).unwrap();
                resign(f, &h.keys[author]);
                p.repair_facts();
            }
            "unknown-fact-kind" => {
                let f = &mut p.payload["components"][3]["data"]["records"][0]["record"];
                f["kind"] = json!("unknown");
                p.repair_facts();
            }
            "wrong-hash" => {
                p.payload["components"][2]["data"]["records"][0]["hash"] = json!("00".repeat(32))
            }
            "unknown-author" => {
                let c = p.commit_mut(&h.fps[0], 4);
                c["author"] = json!(h.fps[4]);
                resign(c, &h.keys[4]);
                p.repair_commits();
            }
            _ => unreachable!(),
        }
        p.rebind(&h.keys[h.signer]);
        let m = p.attestation(&h);
        let raw = canon(&p.payload);
        if [
            "wrong-environment",
            "wrong-fact-environment",
            "unknown-fact-kind",
            "wrong-hash",
            "unknown-author",
        ]
        .contains(&kind)
        {
            assert!(verify_payload_bytes(&m, &raw).is_err(), "{kind}");
        } else {
            let payload = verify_payload_bytes(&m, &raw).unwrap();
            let local = h.local(&m);
            let expected = if kind.ends_with("signature") {
                CheckpointError::SignatureInvalid
            } else {
                CheckpointError::SchemaUnsupported
            };
            assert_eq!(
                verify_retained_authority(&m, &payload, &local).unwrap_err(),
                SemanticError::Checkpoint(expected),
                "{kind}"
            );
        }
    }
}

#[test]
fn full_device_copies_include_agreement_key_self_signature_and_dictionary() {
    for site in [
        "genesis",
        "admission",
        "snapshot",
        "table",
        "extra",
        "coercive",
        "missing",
        "invalid-self-signature",
    ] {
        let h = history("P1");
        let mut p = h.package();
        match site {
            "genesis" => {
                let c = p.commit_mut(&h.fps[0], 1);
                c["ops"][0]["owner_device"] = key(0, 0x33).record().unwrap().to_dict();
                resign(c, &h.keys[0]);
                p.repair_commits();
            }
            "admission" => {
                let c = p.commit_mut(&h.fps[1], 1);
                c["ops"][0]["device"] = key(2, 0x33).record().unwrap().to_dict();
                resign(c, &h.keys[1]);
                p.repair_commits();
            }
            "snapshot" => {
                p.payload["components"][1]["data"]["document"]["members"][&h.fps[2]]["device"] =
                    key(2, 0x33).record().unwrap().to_dict()
            }
            "table" => {
                for d in p.payload["components"][0]["data"].as_array_mut().unwrap() {
                    if d["fingerprint"] == h.fps[2] {
                        d["record"] = key(2, 0x33).record().unwrap().to_dict();
                    }
                }
            }
            _ => {
                let c = p.commit_mut(&h.fps[1], 1);
                let d = &mut c["ops"][0]["device"];
                match site {
                    "extra" => d["synthetic-sensitive-marker"] = json!("must-not-echo"),
                    "coercive" => d["agree_pub"] = json!([d["agree_pub"].clone()]),
                    "missing" => {
                        d.as_object_mut().unwrap().remove("sig");
                    }
                    "invalid-self-signature" => d["sig"] = json!(pybase64::b64encode(&[0; 64])),
                    _ => unreachable!(),
                }
                resign(c, &h.keys[1]);
                p.repair_commits();
            }
        }
        p.rebind(&h.keys[1]);
        let m = p.attestation(&h);
        let raw = canon(&p.payload);
        if site == "missing" {
            // The original M2a selector cannot resolve a malformed admission
            // device. This pre-existing structural refusal precedes semantics.
            assert_eq!(
                verify_payload_bytes(&m, &raw).unwrap_err(),
                CheckpointError::StructureInvalid
            );
            continue;
        }
        let payload = verify_payload_bytes(&m, &raw).unwrap_or_else(|e| panic!("{site}: {e}"));
        let l = h.local(&m);
        let e = verify_retained_authority(&m, &payload, &l).unwrap_err();
        assert!(!format!("{e:?} {e}").contains("sensitive"));
        assert_eq!(
            e,
            match site {
                "table" => SemanticError::Checkpoint(CheckpointError::BindingMismatch),
                "coercive" | "missing" | "extra" =>
                    SemanticError::Checkpoint(CheckpointError::SchemaUnsupported),
                "invalid-self-signature" =>
                    SemanticError::Checkpoint(CheckpointError::SignatureInvalid),
                _ => SemanticError::AuthorityUnproven,
            },
            "{site}"
        );
    }
    let mut h = history("P1");
    let p = h.package();
    h.records[1] = key(1, 0x33).record().unwrap();
    assert!(
        verify_manifest_bytes(
            &canon(&p.manifest),
            &h.context(),
            VerificationWallTime::from_millis(1800000000001).unwrap()
        )
        .is_err()
    );
}

#[test]
fn genesis_authority_set_named_admission_and_projection() {
    let mut forged = history("P1");
    forged.table.push(4);
    let mut op = forged.history[0].ops[0].clone();
    op["owner_device"] = forged.records[4].to_dict();
    forged.history[0] = forged.c(4, 1, 1000, &[], vec![op]);
    refusal(&forged, forged.package(), SemanticError::AuthorityUnproven);
    for mutation in [
        "genesis-reference",
        "missing-init",
        "seq-init",
        "init-not-first",
        "duplicate-init",
        "subset",
        "extra-reference",
        "missing-admission",
        "role",
        "multiple-admission",
    ] {
        let h = history("P1");
        let mut p = h.package();
        match mutation {
            "genesis-reference" => {
                p.payload["components"][2]["data"]["genesis_commit_hash"] =
                    json!(h.history[1].hash().unwrap())
            }
            "missing-init" => {
                let c = p.commit_mut(&h.fps[0], 1);
                c["ops"] = json!([{"op":"settings.update","sync_interval_seconds":10}]);
                resign(c, &h.keys[0]);
                p.repair_commits();
            }
            "seq-init" => {
                let c = p.commit_mut(&h.fps[0], 1);
                c["author_seq"] = json!(3);
                resign(c, &h.keys[0]);
                p.repair_commits();
            }
            "init-not-first" => {
                let c = p.commit_mut(&h.fps[0], 1);
                c["ops"].as_array_mut().unwrap().insert(
                    0,
                    json!({"op":"settings.update","sync_interval_seconds":10}),
                );
                resign(c, &h.keys[0]);
                p.repair_commits();
            }
            "duplicate-init" => {
                let init = h.history[0].ops[0].clone();
                let c = p.commit_mut(&h.fps[0], 4);
                c["ops"].as_array_mut().unwrap().push(init);
                resign(c, &h.keys[0]);
                p.repair_commits();
            }
            "subset" => {
                p.payload["components"][2]["data"]["authority_commit_hashes"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            "extra-reference" => {
                let a = p.payload["components"][2]["data"]["authority_commit_hashes"]
                    .as_array_mut()
                    .unwrap();
                a.push(json!(h.history[4].hash().unwrap()));
                a.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
            }
            "missing-admission" => {
                let hash = h.history[1].hash().unwrap();
                p.manifest["recipient_admission_commit_hash"] = json!(hash);
                p.payload["components"][2]["data"]["recipient_admission_commit_hash"] = json!(hash);
            }
            "role" => {
                let c = p.commit_mut(&h.fps[1], 1);
                c["ops"][0]["role"] = json!("admin");
                resign(c, &h.keys[1]);
                p.repair_commits();
            }
            "multiple-admission" => {
                let c = p.commit_mut(&h.fps[1], 1);
                let op = c["ops"][0].clone();
                c["ops"].as_array_mut().unwrap().push(op);
                resign(c, &h.keys[1]);
                p.repair_commits();
            }
            _ => unreachable!(),
        }
        let expected = if ["missing-init", "subset", "extra-reference"].contains(&mutation) {
            SemanticError::HistoryProofUnavailable
        } else {
            SemanticError::AuthorityUnproven
        };
        refusal(&h, p, expected);
    }
    for path in [
        "name",
        "role",
        "status",
        "owner",
        "generation-current",
        "generation-wrap",
        "generation-extra",
    ] {
        let h = history("P1");
        let mut p = h.package();
        let d = &mut p.payload["components"][1]["data"]["document"];
        match path {
            "name" => d["members"][&h.fps[1]]["name"] = json!("self-claimed"),
            "role" => d["members"][&h.fps[2]]["role"] = json!("admin"),
            "status" => d["members"][&h.fps[1]]["status"] = json!("removed"),
            "owner" => d["owner"] = json!(h.fps[1]),
            "generation-current" => d["dek"]["current"] = Value::Null,
            "generation-wrap" => {
                d["dek"]["generations"][G]["wraps"][&h.fps[2]]["nonce"] =
                    json!(pybase64::b64encode(&[0; 12]))
            }
            "generation-extra" => d["dek"]["generations"]["dddddddddddddddd"] = json!({"wraps":{}}),
            _ => unreachable!(),
        }
        refusal(&h, p, SemanticError::SemanticMismatch);
    }
}

#[test]
fn skipped_authority_and_intra_commit_role_order_never_grant_permission() {
    for variant in [
        "owner-role",
        "owner-remove",
        "nonowner-transfer",
        "absent-transfer",
        "removed-transfer",
        "readd",
        "nonadmin-inviter",
        "signer-demoted",
        "signer-removed",
        "recipient-promoted",
        "recipient-removed",
        "unauthorized-data",
        "demote-then-data",
        "remove-then-data",
    ] {
        let mut h = history("P1");
        let o = &h.fps[0];
        let a = &h.fps[1];
        let r = &h.fps[2];
        let (author, ops) = match variant {
            "owner-role" => (
                0,
                vec![json!({"op":"member.set_role","fingerprint":o,"role":"user"})],
            ),
            "owner-remove" => (0, vec![json!({"op":"member.remove","fingerprint":o})]),
            "nonowner-transfer" => (1, vec![json!({"op":"owner.transfer","fingerprint":r})]),
            "absent-transfer" => {
                h.table.push(4);
                (
                    0,
                    vec![json!({"op":"owner.transfer","fingerprint":h.fps[4]})],
                )
            }
            "removed-transfer" => (
                0,
                vec![
                    json!({"op":"member.remove","fingerprint":r}),
                    json!({"op":"owner.transfer","fingerprint":r}),
                ],
            ),
            "readd" => (
                0,
                vec![
                    json!({"op":"member.remove","fingerprint":a}),
                    h.add(1, "admin"),
                ],
            ),
            "nonadmin-inviter" => {
                h.history[1] = h.c(0, 2, 2000, &[(0, 1)], vec![h.add(1, "user")]);
                h.signer = 0;
                (
                    0,
                    vec![json!({"op":"settings.update","sync_interval_seconds":11})],
                )
            }
            "signer-demoted" => (
                0,
                vec![json!({"op":"member.set_role","fingerprint":a,"role":"user"})],
            ),
            "signer-removed" => (0, vec![json!({"op":"member.remove","fingerprint":a})]),
            "recipient-promoted" => (
                0,
                vec![json!({"op":"member.set_role","fingerprint":r,"role":"admin"})],
            ),
            "recipient-removed" => (0, vec![json!({"op":"member.remove","fingerprint":r})]),
            "unauthorized-data" => (
                2,
                vec![json!({"op":"settings.update","sync_interval_seconds":12})],
            ),
            "demote-then-data" => (
                1,
                vec![
                    json!({"op":"member.set_role","fingerprint":a,"role":"user"}),
                    json!({"op":"settings.update","sync_interval_seconds":12}),
                ],
            ),
            "remove-then-data" => (
                1,
                vec![
                    json!({"op":"member.remove","fingerprint":a}),
                    json!({"op":"settings.update","sync_interval_seconds":12}),
                ],
            ),
            _ => unreachable!(),
        };
        let seq = match author {
            0 => 5,
            1 => 3,
            _ => 1,
        };
        let c = h.c(author, seq, 9000, &[(0, 4), (1, 2)], ops);
        with_commit(&mut h, c);
        let ordinary = h.full_fold();
        let skip_expected = [
            "owner-role",
            "owner-remove",
            "nonowner-transfer",
            "absent-transfer",
            "removed-transfer",
            "readd",
            "nonadmin-inviter",
            "unauthorized-data",
            "demote-then-data",
            "remove-then-data",
        ]
        .contains(&variant);
        assert_eq!(
            !ordinary.skipped.is_empty(),
            skip_expected,
            "ordinary skip unchanged: {variant}"
        );
        if variant == "demote-then-data" || variant == "remove-then-data" {
            assert!(
                ordinary
                    .skipped
                    .iter()
                    .any(|(_, i, r)| *i == 1 && r == "not_admin")
            );
        }
        eprintln!("ORDER_NEGATIVE={variant}");
        refusal(&h, h.package(), SemanticError::AuthorityUnproven);
    }
}

#[test]
fn exact_heads_seen_and_retained_gap_hlc_consistency() {
    for mode in [
        "ahead-vector",
        "self-current",
        "self-future",
        "impossible-seen-hlc",
        "nonmonotone-gap",
    ] {
        let h = history("P1");
        let mut p = h.package();
        match mode {
            "ahead-vector" => {
                let c = p.commit_mut(&h.fps[0], 4);
                c["seen"][&h.fps[1]] = json!(3);
                resign(c, &h.keys[0]);
            }
            "self-current" => {
                let c = p.commit_mut(&h.fps[0], 4);
                c["seen"][&h.fps[0]] = json!(4);
                resign(c, &h.keys[0]);
            }
            "self-future" => {
                let c = p.commit_mut(&h.fps[0], 2);
                c["seen"][&h.fps[0]] = json!(3);
                resign(c, &h.keys[0]);
            }
            "impossible-seen-hlc" => {
                let c = p.commit_mut(&h.fps[0], 2);
                c["seen"][&h.fps[1]] = json!(1);
                resign(c, &h.keys[0]);
            }
            "nonmonotone-gap" => {
                let c = p.commit_mut(&h.fps[0], 2);
                c["hlc"] = json!("5000-0000");
                resign(c, &h.keys[0]);
            }
            _ => unreachable!(),
        }
        p.repair_commits();
        refusal(&h, p, SemanticError::SemanticMismatch);
    }
    for mode in [
        "duplicate-slot",
        "missing-head",
        "head-hlc",
        "head-sequence",
        "zero-head",
        "head-hash",
    ] {
        let h = history("P1");
        let mut p = h.package();
        match mode {
            "duplicate-slot" => {
                let c = p.commit_mut(&h.fps[0], 2);
                c["author_seq"] = json!(4);
                resign(c, &h.keys[0]);
                p.repair_commits();
            }
            "missing-head" => {
                let hash = h.history[4].hash().unwrap();
                p.payload["components"][2]["data"]["records"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|e| e["hash"] != hash);
            }
            "head-hlc" => p.manifest["heads"][0]["hlc"]["counter"] = json!(1),
            "head-sequence" => p.manifest["heads"][0]["author_seq"] = json!(99),
            "zero-head" => {
                p.manifest["heads"].as_array_mut().unwrap().push(json!({"author":h.fps[2],"author_seq":0,"commit_hash":h.history[4].hash().unwrap(),"hlc":{"wall_ms":5000,"counter":0}}));
                p.manifest["heads"]
                    .as_array_mut()
                    .unwrap()
                    .sort_by(|a, b| a["author"].as_str().cmp(&b["author"].as_str()));
            }
            "head-hash" => {
                p.manifest["heads"][0]["commit_hash"] = json!(h.history[0].hash().unwrap())
            }
            _ => unreachable!(),
        }
        p.rebind(&h.keys[1]);
        let bytes = canon(&p.manifest);
        if let Ok(m) = verify_manifest_bytes(
            &bytes,
            &h.context(),
            VerificationWallTime::from_millis(1800000000001).unwrap(),
        ) {
            assert!(
                verify_payload_bytes(&m, &canon(&p.payload)).is_err(),
                "{mode}"
            );
        }
    }
    // A retained gap is evidence, never ordinary sequential receipt. Exact
    // huge sequence and signed HLC spelling survive untouched.
    let mut h = history("P1");
    let huge =
        PyInt::from_json_integer(&load(b"1844674407370955161600000000000000000001")).unwrap();
    h.history[4] = commit::sign_commit(
        &h.keys[0],
        &h.env,
        huge.clone(),
        "09007199254740993-0000",
        &BTreeMap::from([(h.fps[0].clone(), 2.into()), (h.fps[1].clone(), 1.into())]),
        h.history[4].ops.clone(),
    )
    .unwrap();
    h.history[5] = commit::sign_commit(
        &h.keys[1],
        &h.env,
        2,
        "09007199254740994-0000",
        &BTreeMap::from([(h.fps[0].clone(), huge), (h.fps[1].clone(), 1.into())]),
        h.history[5].ops.clone(),
    )
    .unwrap();
    let p = h.package();
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let local = h.local(&m);
    let c = verify_retained_authority(&m, &payload, &local).unwrap();
    assert_eq!(
        c.cut_hlc(),
        (&PyInt::from(9007199254740994_i64), &PyInt::from(0))
    );
    assert_eq!(h.history[4].hlc, "09007199254740993-0000");
}

#[test]
fn wrap_source_operation_must_actually_supply_the_generation() {
    let h = history("P1");
    let mut p = h.package();
    let c = p.commit_mut(&h.fps[1], 1);
    c["ops"][0]["wraps"]["dddddddddddddddd"] = c["ops"][0]["wraps"][G].clone();
    resign(c, &h.keys[1]);
    p.repair_commits();
    p.payload["components"][5]["data"]["entries"][0]["generation_id"] = json!("dddddddddddddddd");
    refusal(&h, p, SemanticError::AuthorityUnproven);
    let h = history("P5");
    let mut p = h.package();
    p.payload["components"][5]["data"]["entries"][0]["source_op_index"] = json!(1);
    p.rebind(&h.keys[0]);
    let m = p.attestation(&h);
    assert!(verify_payload_bytes(&m, &canon(&p.payload)).is_err());
}

#[test]
fn successful_rotation_and_complete_generation_projection_match_ordinary_fold() {
    let mut h = history("P1");
    let generation = "dddddddddddddddd";
    let wraps: serde_json::Map<String, Value> = (0..3)
        .map(|i| {
            (
                h.fps[i].clone(),
                wrap_for_generation(
                    &h.env,
                    generation,
                    &h.records[i],
                    (20 + i) as u8,
                    (23 + i) as u8,
                ),
            )
        })
        .collect();
    let c = h.c(
        0,
        5,
        9000,
        &[(0, 4), (1, 2)],
        vec![json!({"op":"dek.rotate","generation_id":generation,"wraps":wraps})],
    );
    with_commit(&mut h, c);
    let mut p = h.package();
    p.payload["components"][5]["data"]["entries"].as_array_mut().unwrap().push(json!({"generation_id":generation,"recipient":h.fps[2],"source_commit_hash":h.history.last().unwrap().hash().unwrap(),"source_op_index":0,"wrap":wraps[&h.fps[2]]}));
    p.rebind(&h.keys[1]);
    let m = p.attestation(&h);
    let bytes = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &bytes).unwrap();
    let l = h.local(&m);
    let candidate = verify_retained_authority(&m, &payload, &l).unwrap();
    let full = h.full_fold();
    let projection = json!({"owner":full.document["owner"],"members":full.document["members"],"dek":full.document["dek"]});
    assert_eq!(
        candidate.authority_projection_sha256(),
        sha(&canon(&projection))
    );
    assert_eq!(full.document["dek"]["current"], generation);
    assert_eq!(
        zeropw::team::envelope::unwrap_dek(&wraps[&h.fps[2]], &h.env, generation, &h.keys[2])
            .unwrap(),
        [6; 32]
    );
    let mut p = h.package();
    let c = p.commit_mut(&h.fps[0], 5);
    c["ops"][0]["generation_id"] = json!(G);
    resign(c, &h.keys[0]);
    p.repair_commits();
    refusal(&h, p, SemanticError::AuthorityUnproven);
}

#[test]
fn a_skipped_grant_cannot_supply_historical_fact_authority() {
    let mut h = history("P1");
    h.table.push(4);
    let c = h.c(2, 1, 9000, &[(0, 4), (1, 2)], vec![h.add(4, "admin")]);
    with_commit(&mut h, c);
    h.facts.push(h.f(
        4,
        "secret_deleted",
        json!({"secret_id":"never-admitted"}),
        10000,
    ));
    assert_eq!(h.full_fold().skipped.last().unwrap().2, "not_admin");
    refusal(&h, h.package(), SemanticError::AuthorityUnproven);
}

#[test]
fn local_known_originals_bind_full_records_and_wrong_tombstone_digest_is_not_vector_equality() {
    let h = history("P2");
    let p = h.package();
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    for altered in [false, true] {
        let mut r = restrictions();
        let fact = h.facts[0].clone();
        r.known_original_facts.push(KnownOriginalFact {
            hash: fact.hash().unwrap(),
            original: fact,
            author_record: if altered {
                key(1, 0x55).record().unwrap()
            } else {
                h.records[1].clone()
            },
        });
        let l = SemanticLocalInputs::from_local_observation(h.bindings(&m), inventory(), vec![], r)
            .unwrap();
        let result = verify_retained_authority(&m, &payload, &l);
        if altered {
            assert_eq!(result.unwrap_err(), SemanticError::FactContradicted);
        } else {
            assert!(result.is_ok());
        }
    }
    let mut bad = h.package();
    let vector = bad.manifest["vector"].clone();
    bad.manifest["tombstone_digest"] = json!("00".repeat(32));
    bad.rebind(&h.keys[0]);
    assert_eq!(bad.manifest["vector"], vector);
    let m = bad.attestation(&h);
    assert_eq!(
        verify_payload_bytes(&m, &canon(&bad.payload)).unwrap_err(),
        CheckpointError::IntegrityMismatch
    );
}

#[test]
fn fact_historical_basis_requires_an_actual_role_interval_not_a_clock_or_table() {
    for case in ["P2", "P3", "P4"] {
        let mut h = history(case);
        let author = if case == "P2" {
            1
        } else if case == "P4" {
            3
        } else {
            0
        };
        // A signed HLC neither supplies nor disproves an admission event.
        h.facts.push(h.f(
            author,
            "secret_deleted",
            json!({"secret_id":"late-clock"}),
            99000,
        ));
        h.facts.push(h.f(
            author,
            "connection_disabled",
            json!({"connection_id":"no-versions"}),
            100,
        ));
        let p = h.package();
        let m = p.attestation(&h);
        let raw = canon(&p.payload);
        let payload = verify_payload_bytes(&m, &raw).unwrap();
        let l = h.local(&m);
        let c = verify_retained_authority(&m, &payload, &l).unwrap();
        for f in &h.facts {
            assert_eq!(
                c.fact_basis(&f.hash().unwrap()),
                Some("administrator_attested_historical")
            );
            assert!(
                c.fact_role_interval(&f.hash().unwrap())
                    .unwrap()
                    .requires_admin()
            );
        }
        assert!(!sync::fact_role_ok(
            &h.full_fold().document,
            "secret_deleted",
            &h.fps[author],
            &json!({"secret_id":SECRET})
        ));
    }
    for author in [2, 4] {
        let mut h = history("P1");
        if author == 4 {
            h.table.push(4);
        }
        h.facts
            .push(h.f(author, "secret_deleted", json!({"secret_id":SECRET}), 8000));
        refusal(&h, h.package(), SemanticError::AuthorityUnproven);
    }
    let mut h = history("P1");
    h.facts
        .push(h.f(2, "incident", json!({"incident_id":"dddddddddddddddd"}), 1));
    let p = h.package();
    let m = p.attestation(&h);
    let bytes = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &bytes).unwrap();
    let l = h.local(&m);
    let c = verify_retained_authority(&m, &payload, &l).unwrap();
    assert!(
        !c.fact_role_interval(&h.facts[0].hash().unwrap())
            .unwrap()
            .requires_admin()
    );
}

#[test]
fn every_removal_fact_scope_is_explicitly_unsupported_after_original_checks() {
    for (author, target) in [(0, 1), (1, 1), (1, 0), (2, 1), (1, 2), (0, 2)] {
        let mut h = history("P1");
        h.facts.push(h.f(
            author,
            "member_removed",
            json!({"fingerprint":h.fps[target]}),
            7000,
        ));
        refusal(&h, h.package(), SemanticError::ScopeUnsupported);
    }
    // Complete reciprocal evidence stays in the bundle: neither inconvenient
    // original may be removed to recover a qualifying historical interval.
    let mut reciprocal = history("P4");
    reciprocal.facts.push(reciprocal.f(
        1,
        "member_removed",
        json!({"fingerprint":reciprocal.fps[3]}),
        5500,
    ));
    reciprocal.facts.push(reciprocal.f(
        3,
        "member_removed",
        json!({"fingerprint":reciprocal.fps[1]}),
        5600,
    ));
    refusal(
        &reciprocal,
        reciprocal.package(),
        SemanticError::ScopeUnsupported,
    );
    let mut rotation = history("P1");
    let op = json!({"op":"dek.rotate","generation_id":"dddddddddddddddd","wraps":{&rotation.fps[0]:wrap_for_generation(&rotation.env,"dddddddddddddddd",&rotation.records[0],20,23)},"removal_fact_hash":"ab".repeat(32)});
    let c = rotation.c(0, 5, 9000, &[(0, 4), (1, 2)], vec![op]);
    with_commit(&mut rotation, c);
    refusal(
        &rotation,
        rotation.package(),
        SemanticError::ScopeUnsupported,
    );
    let mut h = history("P4");
    h.facts
        .push(h.f(3, "member_removed", json!({"fingerprint":h.fps[1]}), 7000));
    refusal(&h, h.package(), SemanticError::ScopeUnsupported);
    let mut h = history("P1");
    let mut f = h.f(1, "member_removed", json!({"fingerprint":h.fps[2]}), 7000);
    f.sig = pybase64::b64encode(&[0; 64]);
    h.facts.push(f);
    refusal(
        &h,
        h.package(),
        SemanticError::Checkpoint(CheckpointError::SignatureInvalid),
    );
    for field in ["bounds", "pending", "self_placed", "witness_commit_hashes"] {
        let h = history("P1");
        let mut p = h.package();
        p.payload["components"][4]["data"][field] = match field {
            "bounds" => json!({&h.fps[1]:1}),
            "pending" => json!([[7000, 0, h.fps[1]]]),
            "self_placed" => json!([h.fps[1]]),
            _ => json!([h.history[2].hash().unwrap()]),
        };
        refusal(&h, p, SemanticError::ScopeUnsupported);
    }
}

#[test]
fn known_original_same_id_omissions_and_independent_restrictions_cannot_be_cleared() {
    let h = history("P2");
    let omitted = h.facts[1].clone();
    let mut p = h.package();
    p.payload["components"][3]["data"]["records"]
        .as_array_mut()
        .unwrap()
        .retain(|e| e["hash"] != omitted.hash().unwrap());
    // Unchanged signed declaration is caught without any local knowledge.
    p.rebind(&h.keys[0]);
    let m = p.attestation(&h);
    assert!(verify_payload_bytes(&m, &canon(&p.payload)).is_err());
    // Coherent new administrator attestation: absence is only detectable from
    // independently retained original evidence. Never invent stronger proof.
    p.repair_facts();
    p.rebind(&h.keys[0]);
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let empty = h.local(&m);
    assert!(verify_retained_authority(&m, &payload, &empty).is_ok());
    let mut r = restrictions();
    r.known_original_facts.push(KnownOriginalFact {
        hash: omitted.hash().unwrap(),
        original: omitted,
        author_record: h.records[1].clone(),
    });
    let local = SemanticLocalInputs::from_local_observation(h.bindings(&m), inventory(), vec![], r)
        .unwrap();
    assert_eq!(
        verify_retained_authority(&m, &payload, &local).unwrap_err(),
        SemanticError::FactContradicted
    );
    for mode in [
        "deleted",
        "revoked",
        "disabled",
        "removed",
        "support-hash",
        "support-announcement",
    ] {
        let h = history("P1");
        let p = h.package();
        let m = p.attestation(&h);
        let raw = canon(&p.payload);
        let payload = verify_payload_bytes(&m, &raw).unwrap();
        let mut r = restrictions();
        match mode {
            "deleted" => {
                r.deleted_secret_ids.insert("deleted-empty".into());
            }
            "revoked" => {
                r.revoked_versions.insert((SECRET.into(), V1.into()));
            }
            "disabled" => {
                r.disabled_connection_ids.insert("disabled-empty".into());
            }
            "removed" => {
                r.removed_members.insert(h.fps[1].clone());
            }
            "support-hash" => {
                r.required_tombstone_support = RequiredTombstoneSupport::Required {
                    known_tombstone_hashes: BTreeSet::from(["aa".repeat(32)]),
                    unresolved_nonempty_digests: BTreeSet::new(),
                }
            }
            "support-announcement" => {
                r.required_tombstone_support = RequiredTombstoneSupport::Required {
                    known_tombstone_hashes: BTreeSet::new(),
                    unresolved_nonempty_digests: BTreeSet::from(["ab".repeat(32)]),
                }
            }
            _ => unreachable!(),
        }
        let l = SemanticLocalInputs::from_local_observation(h.bindings(&m), inventory(), vec![], r)
            .unwrap();
        assert_eq!(
            verify_retained_authority(&m, &payload, &l).unwrap_err(),
            SemanticError::FactContradicted,
            "{mode}"
        );
    }
}

#[test]
fn valid_remote_attestation_cannot_override_existing_state_or_scoped_collisions() {
    let h = history("P2");
    let mut p = h.package();
    // A no-version connection ID still occupies the import identity space.
    p.payload["components"][1]["data"]["document"]["connections"]["empty-connection"] =
        json!({"status":"disabled"});
    p.rebind(&h.keys[0]);
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    for field in [
        "commits",
        "facts",
        "checkpoints",
        "derived",
        "unsent",
        "pending",
        "completed",
        "stale",
        "mapping",
        "other-staging",
        "backup-barrier",
        "private-secret",
        "shared-secret",
        "connection",
        "restored-binding",
    ] {
        let mut i = inventory();
        let mut r = restrictions();
        let mut occupied = vec![];
        match field {
            "commits" => i.admitted_commits = 1,
            "facts" => i.admitted_facts = 1,
            "checkpoints" => i.checkpoints = 1,
            "derived" => i.derived_team_entries = 1,
            "unsent" => i.unsent_edits = 1,
            "pending" => i.pending_imports = 1,
            "completed" => i.completed_imports = 1,
            "stale" => i.stale_restore = true,
            "mapping" => {
                let mut mapping = h.mapping();
                mapping.project = "different".into();
                i.existing_mapping = Some(mapping);
            }
            "other-staging" => i.own_staging_manifest_hash = Some("00".repeat(32)),
            "backup-barrier" => r.backup_barrier = true,
            "private-secret" => occupied.push(OccupiedLocalId {
                id: SECRET.into(),
                kind: LocalIdKind::Secret,
                scope: LocalIdScope::Private {
                    project: "other".into(),
                    environment: "other".into(),
                },
            }),
            "shared-secret" => occupied.push(OccupiedLocalId {
                id: "deleted-empty".into(),
                kind: LocalIdKind::Secret,
                scope: LocalIdScope::Shared {
                    env_id: h.env.clone(),
                },
            }),
            "connection" => occupied.push(OccupiedLocalId {
                id: "empty-connection".into(),
                kind: LocalIdKind::Connection,
                scope: LocalIdScope::Restored {
                    env_id: h.env.clone(),
                },
            }),
            "restored-binding" => r.restored_bindings.push(ObservedBinding {
                secret_id: "deleted-empty".into(),
                mapping: h.mapping(),
            }),
            _ => unreachable!(),
        }
        let l =
            SemanticLocalInputs::from_local_observation(h.bindings(&m), i, occupied, r).unwrap();
        assert_eq!(
            verify_retained_authority(&m, &payload, &l).unwrap_err(),
            SemanticError::ExistingStateUnsupported,
            "{field}"
        );
    }
    let mut i = inventory();
    i.existing_mapping = Some(h.mapping());
    i.own_staging_manifest_hash = Some(m.manifest_hash().into());
    let occupied = vec![OccupiedLocalId {
        id: "unrelated".into(),
        kind: LocalIdKind::Secret,
        scope: LocalIdScope::Private {
            project: "other".into(),
            environment: "other".into(),
        },
    }];
    let l =
        SemanticLocalInputs::from_local_observation(h.bindings(&m), i, occupied, restrictions())
            .unwrap();
    assert!(verify_retained_authority(&m, &payload, &l).is_ok());
    assert!(verify_retained_authority(&m, &payload, &l).is_ok());
    assert_eq!(raw, canon(&p.payload));
}

#[test]
fn ordinary_loader_keeps_its_receipt_boundary_for_historical_deletions() {
    use zeropw::{
        clock,
        context::{Config, Context},
        team::{commit::CommitStore, identity::DeviceKey},
    };
    let temp = tempfile::TempDir::new().unwrap();
    let ctx = Context::initialize(
        temp.path().join("state"),
        "synthetic-only-password",
        "synthetic-only-recovery",
        Config::default(),
        clock::system(),
    )
    .unwrap();
    let h = history("P2");
    for c in &h.history {
        CommitStore::new(ctx.state, &h.env).append(c).unwrap();
    }
    let deletion = h.facts[0].clone();
    let disable = h.f(
        1,
        "connection_disabled",
        json!({"connection_id":"historical"}),
        7000,
    );
    let facts_path = format!("team/{}/facts.jsonl", h.env);
    for f in [&deletion, &disable] {
        ctx.state
            .append_line(
                &facts_path,
                std::str::from_utf8(&canon(&f.to_dict())).unwrap(),
            )
            .unwrap();
    }
    let (facts, hashes, _) = sync::load_facts(&ctx, &h.env).unwrap();
    assert!(!hashes.contains(&deletion.hash().unwrap()));
    assert!(facts.tombstone_facts.is_empty());
    assert!(hashes.contains(&disable.hash().unwrap()));
    // A local receipt is independently signed by the actual synthetic local
    // identity; the authority candidate has no conversion or receipt method.
    let local_key = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    let hash = deletion.hash().unwrap();
    let message = json!({"domain":"zeropw-local-fact-admission-v1","env_id":h.env,"hash":hash});
    let receipt =
        json!({"hash":hash,"sig":pybase64::b64encode(&local_key.sign(&canon(&message)).unwrap())});
    ctx.state
        .append_line(
            &format!("team/{}/fact_admissions.jsonl", h.env),
            std::str::from_utf8(&canon(&receipt)).unwrap(),
        )
        .unwrap();
    ctx.state
        .append_line(
            &facts_path,
            std::str::from_utf8(&canon(&deletion.to_dict())).unwrap(),
        )
        .unwrap();
    let (admitted, hashes, _) = sync::load_facts(&ctx, &h.env).unwrap();
    assert!(hashes.contains(&hash));
    assert_eq!(admitted.tombstone_facts[&hash], deletion.to_dict());
    let before = ctx.state.read_lines(&facts_path, None).unwrap();
    let receipt_before = ctx
        .state
        .read_lines(&format!("team/{}/fact_admissions.jsonl", h.env), None)
        .unwrap();
    let p = h.package();
    let m = p.attestation(&h);
    let bytes = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &bytes).unwrap();
    let l = h.local(&m);
    assert!(verify_retained_authority(&m, &payload, &l).is_ok());
    assert_eq!(before, ctx.state.read_lines(&facts_path, None).unwrap());
    assert_eq!(
        receipt_before,
        ctx.state
            .read_lines(&format!("team/{}/fact_admissions.jsonl", h.env), None)
            .unwrap()
    );
    assert!(
        sync::load_facts(&ctx, &h.env)
            .unwrap()
            .0
            .tombstone_facts
            .contains_key(&hash)
    );
}

fn nested(depth: usize) -> Value {
    let mut v = json!({"$serde_json::private::Number":"synthetic-sensitive-marker"});
    for i in 1..depth {
        v = if i % 2 == 0 {
            json!({"escaped-key-\"":v})
        } else {
            json!([v])
        };
    }
    v
}
#[test]
fn semantic_depth_64_success_error_drop_on_256_kib_stack_and_65_refusal() {
    for fail in [false, true] {
        let h = history("P1");
        let mut p = h.package();
        p.payload["components"][1]["data"]["document"]["opaque"] = nested(59);
        // Also materialize an original operation reaching total payload depth64.
        let c = p.commit_mut(&h.fps[0], 4);
        c["ops"][0]["public"] = nested(55);
        resign(c, &h.keys[0]);
        p.repair_commits();
        if fail {
            p.payload["components"][1]["data"]["document"]["members"][&h.fps[1]]["name"] =
                json!("synthetic-sensitive-marker");
        }
        p.rebind(&h.keys[1]);
        let m = p.attestation(&h);
        let raw = canon(&p.payload);
        let local = h.local(&m);
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let payload = verify_payload_bytes(&m, &raw).unwrap();
                let result = verify_retained_authority(&m, &payload, &local);
                if fail {
                    assert_eq!(result.unwrap_err(), SemanticError::SemanticMismatch);
                } else {
                    let c = result.unwrap();
                    assert_eq!(c.original_fact_count(), 0);
                    assert!(!format!("{c:?}").contains("sensitive"));
                    assert!(
                        !candidate_provenance(&m, &payload)
                            .unwrap()
                            .canonical_json()
                            .unwrap()
                            .is_empty()
                    );
                    drop(c);
                }
                drop(payload);
                drop(local);
                drop(m);
                drop(raw);
            })
            .unwrap()
            .join()
            .unwrap();
    }
    // Deep original fact target: structurally/canonically checked by M2a,
    // then refused by the unchanged target schema, including partial drop.
    let h = history("P1");
    let mut p = h.package();
    let mut f = h.f(
        1,
        "incident",
        json!({"incident_id":"dddddddddddddddd"}),
        7000,
    );
    f.target["opaque"] = nested(56);
    f.sig = pybase64::b64encode(&h.keys[1].sign(&f.canonical_json(false).unwrap()).unwrap());
    p.payload["components"][3]["data"]["records"] =
        json!([{"hash":f.hash().unwrap(),"record":f.to_dict()}]);
    p.repair_facts();
    p.rebind(&h.keys[1]);
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    let l = h.local(&m);
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            let payload = verify_payload_bytes(&m, &raw).unwrap();
            assert_eq!(
                verify_retained_authority(&m, &payload, &l).unwrap_err(),
                SemanticError::Checkpoint(CheckpointError::SchemaUnsupported)
            );
        })
        .unwrap()
        .join()
        .unwrap();
    let h = history("P1");
    let mut p = h.package();
    p.payload["components"][1]["data"]["document"]["opaque"] = nested(60);
    p.rebind(&h.keys[1]);
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            assert_eq!(
                verify_payload_bytes(&m, &raw).unwrap_err(),
                CheckpointError::LimitExceeded
            )
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn semantic_phase_work_and_memory_are_measured_separately() {
    let mut h = history("P1");
    // Bounded substantial original-record count, with literal role-invariant
    // settings ops. All previous originals and the gapped data prefix remain.
    for n in 5..=516 {
        let c = h.c(
            0,
            n,
            10000 + n,
            &[(0, n - 1), (1, 2)],
            vec![json!({"op":"settings.update","sync_interval_seconds":11})],
        );
        with_commit(&mut h, c);
    }
    let mut p = h.package();
    let document = &mut p.payload["components"][1]["data"]["document"];
    let mut wide = serde_json::Map::new();
    for n in 0..100000 {
        wide.insert(format!("opaque-{n}"), json!(n));
    }
    document["opaque"] = Value::Object(wide);
    p.rebind(&h.keys[1]);
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let l = h.local(&m);
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        for line in status
            .lines()
            .filter(|s| s.starts_with("VmHWM:") || s.starts_with("VmRSS:"))
        {
            eprintln!("SEMANTIC_BEFORE_{line}");
        }
    }
    let start = std::time::Instant::now();
    let c = verify_retained_authority(&m, &payload, &l).unwrap();
    let elapsed = start.elapsed();
    assert_eq!(c.checked_operation_count(), 517);
    eprintln!(
        "SEMANTIC_MEASUREMENT payload_bytes={} retained_commits={} opaque_entries=100000 semantic_elapsed_us={}",
        raw.len(),
        payload.canonical_commit_hashes().len(),
        elapsed.as_micros()
    );
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        for line in status
            .lines()
            .filter(|s| s.starts_with("VmHWM:") || s.starts_with("VmRSS:"))
        {
            eprintln!("SEMANTIC_PROCESS_{line}");
        }
    }
}
