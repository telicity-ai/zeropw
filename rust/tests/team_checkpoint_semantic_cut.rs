//! Complete-cut implementation and frozen-helper boundary tests.
#[path = "common/team_checkpoint_m2b2.rs"]
mod support;
use serde_json::{Value, json};
use support::*;
use zeropw::team::checkpoint::*;
use zeropw::team::{commit::Commit, fold};

fn input(case: &str) -> (History, Package) {
    let h = complete_history(case);
    let effects = ordinary_effects(&h);
    let snapshot = ordinary_snapshot(&h, &effects);
    let final_fold =
        fold::fold(&h.env, h.history.clone(), Some(&effects), None, None, None).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/team_checkpoint_m2b2_v1")
        .join(case)
        .join("expected.json");
    let expected = load(&std::fs::read(root).unwrap());
    let p = complete_package(
        &h,
        snapshot.document,
        &final_fold.document,
        final_fold.version_order,
        expected["removals"].clone(),
    );
    (h, p)
}
fn checked_error(h: &History, p: &Package, expected: SemanticError, old_success: bool) {
    let m = p.attestation(h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).expect("inner negative must first pass M2a");
    let local = h.local(&m);
    if old_success {
        assert!(verify_retained_authority(&m, &payload, &local).is_ok());
    }
    assert_eq!(
        verify_complete_cut_semantics(&m, &payload, &local).unwrap_err(),
        expected
    );
    assert_eq!(raw, canon(&p.payload));
}
fn with_schedule(h: &History, schedule: Value) -> Package {
    let effects = ordinary_effects(h);
    let snapshot = ordinary_snapshot(h, &effects);
    let final_fold =
        fold::fold(&h.env, h.history.clone(), Some(&effects), None, None, None).unwrap();
    complete_package(
        h,
        snapshot.document,
        &final_fold.document,
        final_fold.version_order,
        schedule,
    )
}
fn one_other_schedule(h: &History, witness: usize, target: usize, bound: i64, wall: i64) -> Value {
    json!({"bounds":{&h.fps[target]:bound},"pending":[[wall,0,h.fps[target]]],"self_placed":[],"witness_commit_hashes":[h.history[witness].hash().unwrap()]})
}
#[test]
fn every_frozen_complete_case_has_its_exact_finite_result() {
    for case in COMPLETE_CASES {
        let (h, p) = input(case);
        let m = p.attestation(&h);
        let raw = canon(&p.payload);
        let payload = verify_payload_bytes(&m, &raw).unwrap();
        let local = h.local(&m);
        let result = verify_complete_cut_semantics(&m, &payload, &local);
        match case {
            "N01-reciprocal" | "N02-cycle" => {
                assert_eq!(result.unwrap_err(), SemanticError::ScopeUnsupported)
            }
            "N03-same-commit" => assert_eq!(result.unwrap_err(), SemanticError::AuthorityUnproven),
            _ => {
                let c = result.unwrap();
                assert_eq!(c.trust_model(), "administrator_attested");
                assert_eq!(c.manifest_hash(), m.manifest_hash());
                assert_eq!(c.observation_revision(), "a1".repeat(32));
                assert_eq!(c.original_fact_count(), h.facts.len());
                assert_eq!(
                    c.recomputed_final_document_sha256(),
                    p.manifest["expected_final_document_sha256"]
                );
                assert!(!format!("{c:?}").contains("sensitive"));
                for f in &h.facts {
                    assert!(c.contains_original_fact_hash(&f.hash().unwrap()));
                }
                let again = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
                assert_eq!(c.covered_cut_sha256(), again.covered_cut_sha256());
                if case == "D01-overlay" {
                    assert_eq!(c.original_tombstone_count(), 3);
                    assert_eq!(c.allowed_restrictive_skip_count(), 3);
                    assert_eq!(c.required_generation_ids().count(), 0);
                }
                if case == "D02-policy" {
                    assert_eq!(c.required_generation_ids().collect::<Vec<_>>(), [G]);
                }
            }
        }
        assert_eq!(raw, canon(&p.payload));
    }
}
#[test]
fn old_gapped_and_false_final_digest_contract_stays_limited() {
    for case in ["P1", "P2", "P3", "P6-empty", "P6-nonempty"] {
        let h = history(case);
        let p = h.package();
        checked_error(&h, &p, SemanticError::HistoryProofUnavailable, true);
    }
    let (h, mut p) = input("C01-admin");
    p.manifest["expected_final_document_sha256"] = json!("33".repeat(32));
    p.payload["components"][1]["data"]["expected_final_document_sha256"] = json!("33".repeat(32));
    p.rebind(&h.keys[h.signer]);
    checked_error(&h, &p, SemanticError::SemanticMismatch, true);
}
#[test]
fn coherent_document_and_order_mutations_cannot_be_attested_into_success() {
    let (h, base) = input("C01-admin");
    for mutation in [
        "ciphertext",
        "public",
        "kind",
        "missing",
        "active",
        "status",
        "deleted",
        "settings",
        "order-reverse",
        "order-missing",
        "order-duplicate",
        "order-history",
        "embedded-order",
        "coercive-order",
    ] {
        let mut p = Package {
            manifest: base.manifest.clone(),
            payload: base.payload.clone(),
        };
        let snap = &mut p.payload["components"][1]["data"];
        match mutation {
            "ciphertext" => {
                snap["document"]["secrets"][SECRET]["versions"][V1]["ciphertext"] =
                    json!("invented")
            }
            "public" => {
                snap["document"]["secrets"][SECRET]["versions"][V1]["public"] =
                    json!({"opaque":"synthetic-sensitive-marker"})
            }
            "kind" => snap["document"]["secrets"][SECRET]["kind"] = json!("password"),
            "missing" => {
                snap["document"]["secrets"][SECRET]["versions"]
                    .as_object_mut()
                    .unwrap()
                    .remove(V1);
            }
            "active" => snap["document"]["secrets"][SECRET]["active_version"] = json!(V1),
            "status" => {
                snap["document"]["secrets"][SECRET]["versions"][V1]["status"] = json!("revoked")
            }
            "deleted" => snap["document"]["secrets"][SECRET]["deleted"] = json!(true),
            "settings" => snap["document"]["settings"]["sync_interval_seconds"] = json!(99),
            "order-reverse" => snap["version_order"][SECRET] = json!([V2, V1]),
            "order-missing" => snap["version_order"][SECRET] = json!([V2]),
            "order-duplicate" => snap["version_order"][SECRET] = json!([V1, V1, V2]),
            "order-history" => snap["version_order"][SECRET] = json!(["9999999999999999", V1, V2]),
            "embedded-order" => snap["document"]["_version_order"] = json!({SECRET:[V1,V2]}),
            "coercive-order" => snap["version_order"][SECRET] = json!([V1, 42, V2]),
            _ => unreachable!(),
        }
        p.rebind(&h.keys[h.signer]);
        if mutation == "coercive-order" {
            let m = p.attestation(&h);
            assert!(verify_payload_bytes(&m, &canon(&p.payload)).is_err());
            continue;
        }
        checked_error(&h, &p, SemanticError::SemanticMismatch, true);
    }
}
#[test]
fn known_policy_pin_identity_and_container_relationships_are_checked() {
    let (h, base) = input("D02-policy");
    for mutation in [
        "unknown-pin",
        "id",
        "policy",
        "active-selector",
        "malformed-policy",
        "disabled-invalid",
        "bad-container",
        "bad-public",
        "bad-member",
    ] {
        let mut p = Package {
            manifest: base.manifest.clone(),
            payload: base.payload.clone(),
        };
        let d = &mut p.payload["components"][1]["data"]["document"];
        match mutation {
            "unknown-pin" => d["connections"]["git"]["secret_version"] = json!("9999999999999999"),
            "id" => d["connections"]["api"]["id"] = json!("different"),
            "policy" => d["connections"]["api"]["http_scope"]["methods"] = json!(["POST"]),
            "active-selector" => d["connections"]["api"]["secret_version"] = json!(V3),
            "malformed-policy" => d["connections"]["api"]["http_target"]["port"] = json!("443"),
            "disabled-invalid" => {
                d["connections"]["api"]["status"] = json!("disabled");
                d["connections"]["api"]["http_scope"] = json!([]);
            }
            "bad-container" => d["settings"] = json!([]),
            "bad-public" => d["secrets"][SECRET]["versions"][V3]["public"] = json!([]),
            "bad-member" => d["members"][&h.fps[1]]["role"] = json!("owner"),
            _ => unreachable!(),
        }
        p.rebind(&h.keys[h.signer]);
        checked_error(
            &h,
            &p,
            SemanticError::SemanticMismatch,
            mutation != "bad-member",
        );
    }
}
#[test]
fn removal_metadata_witness_and_bound_contradictions_are_exact() {
    let (h, base) = input("R01-other");
    for mutation in [
        "missing-witness",
        "bound",
        "pending",
        "self-extra",
        "extra-witness",
        "unknown-link",
        "wrong-author",
        "wrapped-target",
        "above-bound",
        "wrong-kind-link",
    ] {
        let mut p = Package {
            manifest: base.manifest.clone(),
            payload: base.payload.clone(),
        };
        let mut expected = SemanticError::SemanticMismatch;
        match mutation {
            "missing-witness" => {
                p.payload["components"][4]["data"]["witness_commit_hashes"] = json!([])
            }
            "bound" => p.payload["components"][4]["data"]["bounds"][&h.fps[3]] = json!(2),
            "pending" => p.payload["components"][4]["data"]["pending"][0][0] = json!(5001),
            "self-extra" => {
                p.payload["components"][4]["data"]["self_placed"] = json!([h.fps[0]]);
            }
            "extra-witness" => {
                let a = p.payload["components"][4]["data"]["witness_commit_hashes"]
                    .as_array_mut()
                    .unwrap();
                a.push(json!(h.history[0].hash().unwrap()));
                a.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
            }
            "unknown-link" | "wrong-kind-link" | "wrong-author" | "wrapped-target"
            | "above-bound" => {
                let c = p.commit_mut(&h.fps[1], 2);
                match mutation {
                    "unknown-link" => {
                        c["ops"][0]["removal_fact_hash"] = json!("11".repeat(32));
                        expected = SemanticError::FactContradicted;
                    }
                    "wrong-kind-link" => {
                        let f = h.f(
                            1,
                            "secret_deleted",
                            json!({"secret_id":"deleted-empty"}),
                            7000,
                        );
                        c["ops"][0]["removal_fact_hash"] = json!(f.hash().unwrap());
                        p.payload["components"][3]["data"]["records"]
                            .as_array_mut()
                            .unwrap()
                            .push(json!({"hash":f.hash().unwrap(),"record":f.to_dict()}));
                        p.repair_facts();
                        expected = SemanticError::FactContradicted;
                    }
                    "wrong-author" => {
                        c["ops"][0]
                            .as_object_mut()
                            .unwrap()
                            .remove("removal_fact_hash");
                        expected = SemanticError::HistoryProofUnavailable;
                    }
                    "wrapped-target" => {
                        c["ops"][0]["wraps"][&h.fps[3]] =
                            wrap_for_generation(&h.env, G2, &h.records[3], 0x25, 0x35);
                        expected = SemanticError::FactContradicted;
                    }
                    "above-bound" => {
                        c["seen"][&h.fps[3]] = json!(0);
                        expected = SemanticError::FactContradicted;
                    }
                    _ => {}
                }
                let c = p.commit_mut(&h.fps[1], 2);
                resign(c, &h.keys[1]);
                p.repair_commits();
            }
            _ => unreachable!(),
        }
        p.rebind(&h.keys[h.signer]);
        checked_error(&h, &p, expected, false);
    }
}
#[test]
fn self_placement_bare_mixed_and_original_order_remain_fail_closed() {
    let (h, base) = input("R03-self");
    let mut p = Package {
        manifest: base.manifest.clone(),
        payload: base.payload.clone(),
    };
    let c = p.commit_mut(&h.fps[3], 2);
    c["ops"][0] = json!({"op":"settings.update","sync_interval_seconds":12});
    resign(c, &h.keys[3]);
    p.repair_commits();
    p.rebind(&h.keys[1]);
    checked_error(&h, &p, SemanticError::HistoryProofUnavailable, false);
    let mut p = Package {
        manifest: base.manifest.clone(),
        payload: base.payload.clone(),
    };
    let f = h.f(1, "member_removed", json!({"fingerprint":h.fps[3]}), 5000);
    p.payload["components"][3]["data"]["records"]
        .as_array_mut()
        .unwrap()
        .push(json!({"hash":f.hash().unwrap(),"record":f.to_dict()}));
    p.repair_facts();
    p.rebind(&h.keys[1]);
    checked_error(&h, &p, SemanticError::ScopeUnsupported, false);
    let (mut h, _) = input("N03-same-commit");
    let i = h.history.len() - 1;
    let mut c = h.history[i].to_dict();
    c["ops"].as_array_mut().unwrap().pop();
    resign(&mut c, &h.keys[1]);
    h.history[i] = Commit::from_dict(&c).unwrap();
    let full = h.full_fold();
    let p = complete_package(
        &h,
        full.document.clone(),
        &full.document,
        full.version_order,
        json!({"bounds":{},"pending":[],"self_placed":[],"witness_commit_hashes":[]}),
    );
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let local = h.local(&m);
    assert!(verify_complete_cut_semantics(&m, &payload, &local).is_ok());
}

#[test]
fn complete_candidate_depth64_success_late_error_repeat_drop_and_65_refusal_on_256_kib() {
    for fail in [false, true] {
        let mut h = complete_history("C01-admin");
        let mut c = h.history[4].to_dict();
        c["ops"][0]["public"] = nested(55);
        resign(&mut c, &h.keys[0]);
        h.history[4] = Commit::from_dict(&c).unwrap();
        let mut p = h.package();
        if fail {
            p.manifest["expected_final_document_sha256"] = json!("33".repeat(32));
            p.payload["components"][1]["data"]["expected_final_document_sha256"] =
                json!("33".repeat(32));
            p.rebind(&h.keys[1]);
        }
        let m = p.attestation(&h);
        let raw = canon(&p.payload);
        assert_eq!(measured_container_depth(&raw), 64);
        let local = h.local(&m);
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let payload = verify_payload_bytes(&m, &raw).unwrap();
                for _ in 0..2 {
                    let result = verify_complete_cut_semantics(&m, &payload, &local);
                    if fail {
                        assert_eq!(result.unwrap_err(), SemanticError::SemanticMismatch);
                    } else {
                        let c = result.unwrap();
                        assert_eq!(c.checked_operation_count(), 6);
                        drop(c);
                    }
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
    let h = complete_history("C01-admin");
    let mut p = h.package();
    p.payload["components"][1]["data"]["document"]["opaque"] = nested(60);
    p.rebind(&h.keys[1]);
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    assert_eq!(measured_container_depth(&raw), 65);
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
fn independent_local_facts_restrictions_binding_and_collisions_remain_deny_only() {
    let (h, p) = input("D01-overlay");
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    for what in [
        "missing-original",
        "deletion",
        "revoke",
        "disable",
        "remove",
        "support",
        "stale",
        "collision",
        "restored",
        "mapping",
        "nonce",
        "recipient-copy",
    ] {
        let mut bindings = h.bindings(&m);
        let mut inv = inventory();
        let mut deny = restrictions();
        let mut occupied = vec![];
        match what {
            "missing-original" => {
                let f = h.f(
                    1,
                    "secret_deleted",
                    json!({"secret_id":"deleted-empty"}),
                    9999,
                );
                deny.known_original_facts.push(KnownOriginalFact {
                    hash: f.hash().unwrap(),
                    original: f,
                    author_record: h.records[1].clone(),
                });
            }
            "deletion" => {
                deny.deleted_secret_ids.insert("unknown".into());
            }
            "revoke" => {
                deny.revoked_versions
                    .insert((SECRET.into(), "9999999999999999".into()));
            }
            "disable" => {
                deny.disabled_connection_ids.insert("unknown".into());
            }
            "remove" => {
                deny.removed_members.insert(h.fps[1].clone());
            }
            "support" => {
                deny.required_tombstone_support = RequiredTombstoneSupport::Required {
                    known_tombstone_hashes: Default::default(),
                    unresolved_nonempty_digests: ["99".repeat(32)].into_iter().collect(),
                }
            }
            "stale" => inv.stale_restore = true,
            "collision" => occupied.push(OccupiedLocalId {
                id: "deleted-empty".into(),
                kind: LocalIdKind::Secret,
                scope: LocalIdScope::Private {
                    project: "other".into(),
                    environment: "dev".into(),
                },
            }),
            "restored" => deny.restored_bindings.push(ObservedBinding {
                secret_id: "deleted-empty".into(),
                mapping: h.mapping(),
            }),
            "mapping" => {
                let mut map = h.mapping();
                map.project = "other".into();
                inv.existing_mapping = Some(map);
            }
            "nonce" => bindings.session_nonce = "99".repeat(32),
            "recipient-copy" => bindings.recipient_record = key(2, 0x44).record().unwrap(),
            _ => unreachable!(),
        }
        let local =
            SemanticLocalInputs::from_local_observation(bindings, inv, occupied, deny).unwrap();
        let expected = match what {
            "stale" | "collision" | "restored" | "mapping" => {
                SemanticError::ExistingStateUnsupported
            }
            "nonce" | "recipient-copy" => {
                SemanticError::Checkpoint(CheckpointError::BindingMismatch)
            }
            _ => SemanticError::FactContradicted,
        };
        assert_eq!(
            verify_complete_cut_semantics(&m, &payload, &local).unwrap_err(),
            expected,
            "{what}"
        );
    }
    let mut a = h.bindings(&m);
    a.observation_revision = "22".repeat(32);
    let l = SemanticLocalInputs::from_local_observation(a, inventory(), vec![], restrictions())
        .unwrap();
    assert_eq!(
        verify_complete_cut_semantics(&m, &payload, &l)
            .unwrap()
            .observation_revision(),
        "22".repeat(32)
    );
}

#[test]
fn earlier_same_author_witness_repairs_multiple_ops_and_equal_hlc_rules() {
    let mut h = complete_history("R01-other");
    let f = h.facts[0].clone();
    h.history.push(h.c(
        1,
        3,
        7000,
        &[(0, 3), (1, 2), (3, 1)],
        vec![rotation(&h, G3, &f, &[0, 1, 2])],
    ));
    h.retained = (0..h.history.len()).collect();
    let p = with_schedule(&h, one_other_schedule(&h, 6, 3, 1, 5000));
    checked_error(&h, &p, SemanticError::SemanticMismatch, false);
    let mut h = complete_history("R01-other");
    let f = h.facts[0].clone();
    let mut c = h.history[5].to_dict();
    c["ops"][0]
        .as_object_mut()
        .unwrap()
        .remove("removal_fact_hash");
    resign(&mut c, &h.keys[1]);
    h.history[5] = Commit::from_dict(&c).unwrap();
    h.history.push(h.c(
        0,
        4,
        7000,
        &[(0, 3), (1, 2), (3, 1)],
        vec![rotation(&h, G3, &f, &[0, 1, 2])],
    ));
    h.retained = (0..h.history.len()).collect();
    let p = with_schedule(&h, one_other_schedule(&h, 6, 3, 1, 5000));
    checked_error(&h, &p, SemanticError::HistoryProofUnavailable, false);
    for multiple in [false, true] {
        let mut h = complete_history("R01-other");
        let f = h.facts[0].clone();
        let mut c = h.history[5].to_dict();
        c["hlc"] = json!("5000-0000");
        if multiple {
            c["ops"]
                .as_array_mut()
                .unwrap()
                .push(rotation(&h, G3, &f, &[0, 1, 2]));
        }
        resign(&mut c, &h.keys[1]);
        h.history[5] = Commit::from_dict(&c).unwrap();
        let p = with_schedule(&h, one_other_schedule(&h, 5, 3, 1, 5000));
        let m = p.attestation(&h);
        let raw = canon(&p.payload);
        let payload = verify_payload_bytes(&m, &raw).unwrap();
        let local = h.local(&m);
        let c = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
        assert_eq!(c.removal_witness_count(), 1);
        assert_eq!(c.allowed_restrictive_skip_count(), 0);
        assert_eq!(c.checked_operation_count(), if multiple { 7 } else { 6 });
        assert_eq!(
            p.payload["components"][1]["data"]["document"]["members"][&h.fps[3]]["status"],
            "removed"
        );
    }
}

#[test]
fn retained_contradictions_pre_cut_target_basis_skipped_rotation_and_self_placement() {
    let (h, base) = input("R01-other");
    // A pre-genesis cut cannot authorize removal of a not-yet-admitted target.
    let mut p = Package {
        manifest: base.manifest.clone(),
        payload: base.payload.clone(),
    };
    let fact = h.f(1, "member_removed", json!({"fingerprint":h.fps[3]}), 500);
    p.payload["components"][3]["data"]["records"] =
        json!([{"hash":fact.hash().unwrap(),"record":fact.to_dict()}]);
    p.repair_facts();
    let c = p.commit_mut(&h.fps[1], 2);
    c["ops"][0]["removal_fact_hash"] = json!(fact.hash().unwrap());
    resign(c, &h.keys[1]);
    p.repair_commits();
    p.payload["components"][4]["data"]["pending"][0][0] = json!(500);
    p.rebind(&h.keys[1]);
    checked_error(&h, &p, SemanticError::FactContradicted, false);
    // Same-commit demotion before the linked rotation is an actual skipped
    // authority op, never repaired by regrouping ops by name.
    let mut p = Package {
        manifest: base.manifest.clone(),
        payload: base.payload.clone(),
    };
    let c = p.commit_mut(&h.fps[1], 2);
    c["ops"].as_array_mut().unwrap().insert(
        0,
        json!({"op":"member.set_role","fingerprint":h.fps[1],"role":"user"}),
    );
    resign(c, &h.keys[1]);
    p.repair_commits();
    for w in p.payload["components"][5]["data"]["entries"]
        .as_array_mut()
        .unwrap()
    {
        if w["generation_id"] == G2 {
            w["source_op_index"] = json!(1);
        }
    }
    p.rebind(&h.keys[1]);
    checked_error(&h, &p, SemanticError::AuthorityUnproven, false);
    // An already commit-removed target is outside the conservative fact basis.
    let mut p = Package {
        manifest: base.manifest.clone(),
        payload: base.payload.clone(),
    };
    let c = p.commit_mut(&h.fps[3], 1);
    c["ops"][0] = json!({"op":"member.remove","fingerprint":h.fps[3]});
    resign(c, &h.keys[3]);
    p.repair_commits();
    let hash = p.payload["components"][2]["data"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["record"]["author"] == h.fps[3])
        .unwrap()["hash"]
        .clone();
    p.payload["components"][2]["data"]["authority_commit_hashes"]
        .as_array_mut()
        .unwrap()
        .push(hash);
    p.payload["components"][2]["data"]["authority_commit_hashes"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    p.rebind(&h.keys[1]);
    checked_error(&h, &p, SemanticError::FactContradicted, false);
    let mut h = complete_history("R01-other");
    h.history.push(h.c(
        3,
        2,
        4600,
        &[(0, 3), (1, 1), (3, 1)],
        vec![json!({"op":"settings.update","sync_interval_seconds":99})],
    ));
    h.retained = (0..h.history.len()).collect();
    let p = with_schedule(&h, one_other_schedule(&h, 5, 3, 1, 5000));
    checked_error(&h, &p, SemanticError::FactContradicted, false);
    let mut h = complete_history("R03-self");
    h.history.truncate(5);
    h.history[4] = h.c(
        3,
        1,
        4500,
        &[(0, 3), (1, 1)],
        vec![json!({"op":"member.remove","fingerprint":h.fps[3]})],
    );
    h.history.push(h.c(
        0,
        4,
        4400,
        &[(0, 3), (1, 1)],
        vec![json!({"op":"member.remove","fingerprint":h.fps[3]})],
    ));
    h.retained = (0..h.history.len()).collect();
    let p = with_schedule(
        &h,
        json!({"bounds":{&h.fps[3]:1},"pending":[],"self_placed":[h.fps[3]],"witness_commit_hashes":[h.history[4].hash().unwrap()]}),
    );
    checked_error(&h, &p, SemanticError::AuthorityUnproven, false);
}

#[test]
fn removal_chain_is_not_resolved_by_filtering_and_one_admin_can_remove_two_targets() {
    let mut h = complete_history("N02-cycle");
    h.history.pop();
    h.facts.pop();
    h.retained = (0..h.history.len()).collect();
    let p = with_schedule(
        &h,
        json!({"bounds":{},"pending":[],"self_placed":[],"witness_commit_hashes":[]}),
    );
    checked_error(&h, &p, SemanticError::ScopeUnsupported, false);
    let mut h = complete_history("R01-other");
    h.table.push(4);
    h.history
        .push(h.c(0, 4, 3500, &[(0, 3)], vec![h.add(4, "admin")]));
    let f = h.f(1, "member_removed", json!({"fingerprint":h.fps[4]}), 5100);
    h.history.push(h.c(
        1,
        3,
        6500,
        &[(0, 4), (1, 2), (3, 1)],
        vec![rotation(&h, G3, &f, &[0, 1, 2])],
    ));
    h.facts.push(f);
    h.retained = (0..h.history.len()).collect();
    let mut witnesses = vec![h.history[5].hash().unwrap(), h.history[7].hash().unwrap()];
    witnesses.sort();
    let p = with_schedule(
        &h,
        json!({"bounds":{&h.fps[3]:1,&h.fps[4]:0},"pending":[[5000,0,h.fps[3]],[5100,0,h.fps[4]]],"self_placed":[],"witness_commit_hashes":witnesses}),
    );
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let local = h.local(&m);
    let candidate = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
    assert_eq!(candidate.removal_target_count(), 2);
    assert_eq!(candidate.removal_witness_count(), 2);
}

#[test]
fn original_authentication_huge_slot_gaps_numeric_spelling_and_pairing_are_not_bypassed() {
    let (h, base) = input("C01-admin");
    for which in [
        "signature",
        "authority-set",
        "genesis",
        "huge-gap",
        "spelling",
    ] {
        let mut p = Package {
            manifest: base.manifest.clone(),
            payload: base.payload.clone(),
        };
        match which {
            "signature" => {
                let c = p.commit_mut(&h.fps[0], 4);
                c["sig"] = json!(zeropw::pybase64::b64encode(&[0; 64]));
                p.repair_commits();
            }
            "authority-set" => {
                p.payload["components"][2]["data"]["authority_commit_hashes"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            "genesis" => {
                let c = p.commit_mut(&h.fps[0], 4);
                c["ops"][0] = h.history[0].ops[0].clone();
                resign(c, &h.keys[0]);
                p.repair_commits();
                let hash = p.manifest["heads"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|v| v["author"] == h.fps[0])
                    .unwrap()["commit_hash"]
                    .clone();
                p.payload["components"][2]["data"]["authority_commit_hashes"]
                    .as_array_mut()
                    .unwrap()
                    .push(hash);
                p.payload["components"][2]["data"]["authority_commit_hashes"]
                    .as_array_mut()
                    .unwrap()
                    .sort_by(|a, b| a.as_str().cmp(&b.as_str()));
            }
            "huge-gap" => {
                let huge = load(format!("1{}", "0".repeat(2000)).as_bytes());
                let c = p.commit_mut(&h.fps[0], 4);
                c["author_seq"] = huge.clone();
                resign(c, &h.keys[0]);
                p.manifest["vector"][&h.fps[0]] = huge.clone();
                p.payload["components"][1]["data"]["vector"][&h.fps[0]] = huge.clone();
                for head in p.manifest["heads"].as_array_mut().unwrap() {
                    if head["author"] == h.fps[0] {
                        head["author_seq"] = huge.clone();
                    }
                }
                p.repair_commits();
            }
            "spelling" => {
                let c = p.commit_mut(&h.fps[0], 4);
                c["hlc"] = json!("00005000-000000");
                resign(c, &h.keys[0]);
                p.repair_commits();
            }
            _ => unreachable!(),
        }
        p.rebind(&h.keys[1]);
        if which == "spelling" {
            let m = p.attestation(&h);
            let raw = canon(&p.payload);
            let payload = verify_payload_bytes(&m, &raw).unwrap();
            let local = h.local(&m);
            assert!(verify_complete_cut_semantics(&m, &payload, &local).is_ok());
            assert!(
                std::str::from_utf8(&raw)
                    .unwrap()
                    .contains("00005000-000000")
            );
        } else {
            checked_error(
                &h,
                &p,
                match which {
                    "signature" => SemanticError::Checkpoint(CheckpointError::SignatureInvalid),
                    "genesis" => SemanticError::AuthorityUnproven,
                    _ => SemanticError::HistoryProofUnavailable,
                },
                which == "huge-gap",
            );
        }
    }
    let m = base.attestation(&h);
    let raw = canon(&base.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let local = h.local(&m);
    let mut other = base;
    other.manifest["transfer_id"] = json!("99".repeat(16));
    other.rebind(&h.keys[1]);
    let alternate = other.attestation(&h);
    assert_eq!(
        verify_complete_cut_semantics(&alternate, &payload, &local).unwrap_err(),
        SemanticError::Checkpoint(CheckpointError::BindingMismatch)
    );
    let (h, mut p) = input("R02-multiple");
    let c = p.commit_mut(&h.fps[0], 4);
    c["seen"][&h.fps[3]] = json!(0);
    resign(c, &h.keys[0]);
    p.repair_commits();
    p.rebind(&h.keys[1]);
    checked_error(&h, &p, SemanticError::FactContradicted, false);
}

#[test]
fn generation_summary_is_public_only_and_key_unavailability_is_a_later_gate() {
    let (h, mut p) = input("C01-admin");
    p.payload["components"][5]["data"]["unavailable_generations"] = json!(["9999999999999999"]);
    p.rebind(&h.keys[1]);
    checked_error(&h, &p, SemanticError::SemanticMismatch, true);
    p.payload["components"][5]["data"]["unavailable_generations"] = json!([G]);
    p.payload["components"][5]["data"]["entries"] = json!([]);
    p.rebind(&h.keys[1]);
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let local = h.local(&m);
    let c = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
    assert_eq!(c.required_generation_ids().collect::<Vec<_>>(), [G]);
    assert_eq!(c.referenced_generation_ids().collect::<Vec<_>>(), [G]);

    let mut h = complete_history("C01-admin");
    let wraps: serde_json::Map<_, _> = [0, 1, 2]
        .into_iter()
        .map(|i| {
            (
                h.fps[i].clone(),
                wrap_for_generation(&h.env, G2, &h.records[i], 0x22 + i as u8, 0x32 + i as u8),
            )
        })
        .collect();
    h.history.push(h.c(
        0,
        5,
        7000,
        &[(0, 4), (1, 2)],
        vec![json!({"op":"dek.rotate","generation_id":G2,"wraps":wraps})],
    ));
    h.history.push(h.c(0,6,8000,&[(0,5),(1,2)],vec![json!({"op":"secret.put_version","secret_id":SECRET,"kind":"api_key","generation_id":G2,"version_id":V3,"ciphertext":ciphertext(&h.env,V3,9,b"synthetic-staged-generation"),"public":{}})]));
    h.retained = (0..h.history.len()).collect();
    let mut p = h.package();
    p.payload["components"][5]["data"]["unavailable_generations"] = json!([G2]);
    p.rebind(&h.keys[1]);
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let local = h.local(&m);
    let c = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
    assert_eq!(c.required_generation_ids().collect::<Vec<_>>(), [G, G2]);
    assert_eq!(c.allowed_restrictive_skip_count(), 0);

    let mut h = complete_history("D02-policy");
    h.history.push(h.c(
        0,
        10,
        13000,
        &[(0, 9), (1, 2)],
        vec![json!({"op":"secret.activate","secret_id":SECRET,"version_id":V4})],
    ));
    h.history.push(h.c(
        0,
        11,
        14000,
        &[(0, 10), (1, 2)],
        vec![
            json!({"op":"secret.set_status","secret_id":SECRET,"version_id":V4,"status":"active"}),
        ],
    ));
    h.retained = (0..h.history.len()).collect();
    let p = with_schedule(
        &h,
        json!({"bounds":{},"pending":[],"self_placed":[],"witness_commit_hashes":[]}),
    );
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let local = h.local(&m);
    let c = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
    assert_eq!(c.allowed_restrictive_skip_count(), 2);
    assert_eq!(
        p.payload["components"][1]["data"]["document"]["secrets"][SECRET]["active_version"],
        V2
    );
}

#[test]
fn removal_requires_nonowner_target_and_current_pre_cut_admin_not_any_historical_interval() {
    let (h, mut p) = input("R01-other");
    let fact = h.f(1, "member_removed", json!({"fingerprint":h.fps[0]}), 5000);
    p.payload["components"][3]["data"]["records"] =
        json!([{"hash":fact.hash().unwrap(),"record":fact.to_dict()}]);
    p.repair_facts();
    let c = p.commit_mut(&h.fps[1], 2);
    c["ops"][0]["removal_fact_hash"] = json!(fact.hash().unwrap());
    c["ops"][0]["wraps"]
        .as_object_mut()
        .unwrap()
        .remove(&h.fps[0]);
    resign(c, &h.keys[1]);
    p.repair_commits();
    p.payload["components"][4]["data"]["bounds"] = json!({&h.fps[0]:3});
    p.payload["components"][4]["data"]["pending"] = json!([[5000, 0, h.fps[0]]]);
    p.rebind(&h.keys[1]);
    checked_error(&h, &p, SemanticError::FactContradicted, false);

    let mut h = complete_history("R01-other");
    h.signer = 0;
    h.history.push(h.c(
        0,
        4,
        4800,
        &[(0, 3), (1, 1), (3, 1)],
        vec![json!({"op":"member.set_role","fingerprint":h.fps[1],"role":"user"})],
    ));
    h.retained = (0..h.history.len()).collect();
    let p = with_schedule(&h, one_other_schedule(&h, 5, 3, 1, 5000));
    checked_error(&h, &p, SemanticError::FactContradicted, false);

    let mut h = complete_history("C01-admin");
    h.table.push(3);
    h.facts.push(h.f(
        3,
        "secret_deleted",
        json!({"secret_id":"deleted-empty"}),
        7000,
    ));
    let p = h.package();
    checked_error(&h, &p, SemanticError::FactContradicted, false);
}

fn hwm() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
}
fn measure(h: &History, p: &Package, scope: &str) {
    let m = p.attestation(h);
    let raw = canon(&p.payload);
    assert!(raw.len() <= 16_777_216);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let local = h.local(&m);
    let before = hwm();
    let start = std::time::Instant::now();
    let candidate = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
    let micros = start.elapsed().as_micros();
    let after = hwm();
    println!(
        "M2B2A_RESOURCE {}",
        json!({"scope":scope,"platform":std::env::consts::OS,"payload_bytes":raw.len(),"original_commits":h.history.len(),"original_facts":h.facts.len(),"operations":candidate.checked_operation_count(),"removal_witnesses":candidate.removal_witness_count(),"semantic_microseconds":micros,"process_vmhwm_before_kib":before,"process_vmhwm_after_kib":after})
    );
    assert_eq!(candidate.original_fact_count(), h.facts.len());
    drop(candidate);
}
#[test]
fn resource_near_payload_limit_complete_records_and_large_legacy_snapshot() {
    let mut h = complete_history("C01-admin");
    let mut estimated = 20_000;
    for seq in 5..=65_540 {
        let c = h.c(
            0,
            seq,
            10_000 + seq,
            &[(0, seq - 1), (1, 2)],
            vec![json!({"op":"settings.update","sync_interval_seconds":10})],
        );
        let bytes = c.canonical_json(true).unwrap().len() + 90;
        if estimated + bytes > 15_900_000 {
            break;
        }
        estimated += bytes;
        h.history.push(c);
    }
    h.retained = (0..h.history.len()).collect();
    let p = h.package();
    assert!(h.history.len() > 20_000);
    measure(&h, &p, "complete-original-records-near-byte-cap");
    drop(p);
    drop(h);
    let mut h = complete_history("C01-admin");
    let public: serde_json::Map<_, _> = (0..490_000)
        .map(|n| (format!("opaque{n:06}"), json!(0)))
        .collect();
    let mut c = h.history[4].to_dict();
    c["ops"][0]["public"] = Value::Object(public);
    resign(&mut c, &h.keys[0]);
    h.history[4] = Commit::from_dict(&c).unwrap();
    let p = h.package();
    assert!(canon(&p.payload).len() > 14_000_000);
    measure(
        &h,
        &p,
        "wide-original-and-unflushed-snapshot-490000-public-entries",
    );
    let mut bad = Package {
        manifest: p.manifest.clone(),
        payload: p.payload.clone(),
    };
    bad.manifest["expected_final_document_sha256"] = json!("33".repeat(32));
    bad.payload["components"][1]["data"]["expected_final_document_sha256"] = json!("33".repeat(32));
    bad.rebind(&h.keys[1]);
    let m = bad.attestation(&h);
    let raw = canon(&bad.payload);
    let checked = verify_payload_bytes(&m, &raw).unwrap();
    let local = h.local(&m);
    let start = std::time::Instant::now();
    assert_eq!(
        verify_complete_cut_semantics(&m, &checked, &local).unwrap_err(),
        SemanticError::SemanticMismatch
    );
    println!(
        "M2B2A_RESOURCE {}",
        json!({"scope":"wide-late-semantic-error","semantic_microseconds":start.elapsed().as_micros(),"process_vmhwm_kib":hwm(),"payload_bytes":raw.len()})
    );
}

#[test]
fn resource_many_original_same_target_witnesses_and_minimum_bound() {
    let mut h = complete_history("R01-other");
    h.history.truncate(5);
    h.facts.clear();
    let mut witnesses = vec![];
    for n in 0..5700 {
        let f = h.f(
            1,
            "member_removed",
            json!({"fingerprint":h.fps[3]}),
            5000 + n,
        );
        let generation = format!("{:016x}", 0x1000 + n);
        let c = h.c(
            1,
            2 + n,
            6000 + n,
            &[(0, 3), (1, 1 + n), (3, 1)],
            vec![rotation(&h, &generation, &f, &[0, 1, 2])],
        );
        witnesses.push(c.hash().unwrap());
        h.history.push(c);
        h.facts.push(f);
    }
    h.retained = (0..h.history.len()).collect();
    witnesses.sort();
    let effects = ordinary_effects(&h);
    let snapshot = ordinary_snapshot(&h, &effects);
    let result = fold::fold(&h.env, h.history.clone(), Some(&effects), None, None, None).unwrap();
    let p = complete_package(
        &h,
        snapshot.document,
        &result.document,
        result.version_order,
        json!({"bounds":{&h.fps[3]:1},"pending":[[5000,0,h.fps[3]]],"self_placed":[],"witness_commit_hashes":witnesses}),
    );
    measure(
        &h,
        &p,
        "5700-original-removals-and-5700-earliest-witnesses-one-target",
    );
}

fn nested(depth: usize) -> Value {
    let mut value = json!({"$serde_json::private::Number":"synthetic-sensitive-marker"});
    for i in 1..depth {
        value = if i % 2 == 0 {
            json!({"escaped-key-\"":value})
        } else {
            json!([value])
        };
    }
    value
}

fn measured_container_depth(raw: &[u8]) -> usize {
    let (mut quoted, mut escaped, mut depth, mut maximum) = (false, false, 0, 0);
    for byte in raw {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    maximum = maximum.max(depth);
                }
                b'}' | b']' => depth -= 1,
                _ => {}
            }
        }
    }
    maximum
}

// Run the ordinary uncompacted oracle on the same small stack required for the
// new API. No candidate is involved in generating this expected fold.
#[test]
fn complete_fold_depth64_on_actual_256_kib_stack() {
    let mut h = history("P1");
    let mut original = h.history[4].to_dict();
    original["ops"][0]["public"] = nested(55);
    resign(&mut original, &h.keys[0]);
    h.history[4] = Commit::from_dict(&original).unwrap();
    let p = h.package();
    let m = p.attestation(&h);
    let raw = canon(&p.payload);
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            let checked = zeropw::team::checkpoint::verify_payload_bytes(&m, &raw).unwrap();
            let result = fold::fold(&h.env, h.history, None, None, None, None).unwrap();
            assert_eq!(result.skipped.len(), 0);
            assert!(!canon(&result.document).is_empty());
            assert_eq!(
                result.document["secrets"][SECRET]["versions"][V2]["public"],
                nested(55)
            );
            drop(result);
            drop(checked);
        })
        .unwrap()
        .join()
        .unwrap();
}
