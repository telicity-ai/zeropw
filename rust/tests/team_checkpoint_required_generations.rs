//! Checked entry, failure boundaries, immutable binding and actual small stacks.
#[path = "common/team_checkpoint_required_generations.rs"]
mod support;
use serde_json::json;
use support::*;
use zeropw::{
    pybase64,
    secret::SecretBytes,
    team::{checkpoint::*, identity::DeviceKey},
};

fn unavailable(c: &Case, p: &Package) {
    assert_eq!(
        check(c, p, &c.h.keys[2]).unwrap_err(),
        SemanticError::GenerationUnavailable
    );
}
#[test]
fn success_observes_only_fixed_stage_binding_digests_and_aggregate_counts() {
    let c = build("G01-multiple");
    let (p, _, _) = c.package();
    let original = canon(&p.payload);
    let m = p.attestation(&c.h);
    let payload = verify_payload_bytes(&m, &original).unwrap();
    let local = c.h.local(&m);
    let candidate = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
    assert_eq!(
        candidate.required_generation_ids().collect::<Vec<_>>(),
        [G1, G2]
    );
    for _ in 0..3 {
        let proof = verify_required_generations(&candidate, &c.h.keys[2]).unwrap();
        assert_eq!(
            proof.stage(),
            "required_generation_ciphertexts_checked_not_admitted"
        );
        assert_eq!(proof.trust_model(), "administrator_attested");
        assert_eq!(proof.manifest_hash(), candidate.manifest_hash());
        assert_eq!(
            proof.observation_revision(),
            candidate.observation_revision()
        );
        assert_eq!(proof.covered_cut_sha256(), candidate.covered_cut_sha256());
        assert_eq!(
            proof.recomputed_final_document_sha256(),
            candidate.recomputed_final_document_sha256()
        );
        assert_eq!(
            proof.admitted_fact_hashes_sha256(),
            candidate.admitted_fact_hashes_sha256()
        );
        assert_eq!(proof.tombstone_digest(), candidate.tombstone_digest());
        assert_eq!(
            (
                proof.required_generation_count(),
                proof.checked_ciphertext_count()
            ),
            (2, 4)
        );
        assert_eq!(
            format!("{proof:?}"),
            "RequiredGenerationCandidate([redacted])"
        );
        drop(proof);
    }
    assert_eq!(original, canon(&p.payload));
    assert_eq!(canon(&p.manifest), canon(&p.manifest));
}
#[test]
fn exact_full_recipient_and_both_private_lengths_are_required_even_for_empty() {
    for name in ["G01-multiple", "G05-empty"] {
        let c = build(name);
        let (p, _, _) = c.package();
        let fixed = SemanticError::Checkpoint(CheckpointError::BindingMismatch);
        for wrong in [key(9, 5), key(2, 9), key(0, 3)] {
            assert_eq!(check(&c, &p, &wrong).unwrap_err(), fixed);
        }
        assert_eq!(key(2, 9).fingerprint().unwrap(), c.h.fps[2]);
        assert_ne!(key(2, 9).record().unwrap(), c.h.records[2]);
        for length in [0usize, 31, 33] {
            for sign in [false, true] {
                let wrong = DeviceKey {
                    sign_seed: SecretBytes::new(vec![2; if sign { length } else { 32 }]),
                    agree_private: SecretBytes::new(vec![5; if sign { 32 } else { length }]),
                };
                assert_eq!(check(&c, &p, &wrong).unwrap_err(), fixed);
            }
        }
    }
}
#[test]
fn prior_generations_admitted_to_new_exact_recipient_and_new_owner_attestor() {
    let mut c = build("G02-new-recipient");
    let (p, _, _) = c.package();
    assert_eq!(check(&c, &p, &c.h.keys[2]).unwrap(), (2, 4));
    let successor = c.h.fps[1].clone();
    append(
        &mut c.h,
        vec![json!({"op":"owner.transfer","fingerprint":successor})],
    );
    let (p, _, _) = c.package();
    assert_eq!(check(&c, &p, &c.h.keys[2]).unwrap(), (2, 4));
}
#[test]
fn unavailable_missing_all_or_older_required_wraps_never_fall_back_to_current() {
    for explicit in [false, true] {
        for generations in [vec![G1], vec![G2], vec![G1, G2, G3]] {
            let c = build("G01-multiple");
            let (mut p, _, _) = c.package();
            omit(&mut p, &generations, explicit, &c.h);
            unavailable(&c, &p);
        }
    }
    let c = build("G03-selected-history");
    let (mut p, _, _) = c.package();
    let admission = c.h.history[4].hash().unwrap();
    p.payload["components"][5]["data"]["entries"]
        .as_array_mut()
        .unwrap()
        .retain(|e| !(e["generation_id"] == G1 && e["source_commit_hash"] == admission));
    p.rebind(&c.h.keys[c.h.signer]);
    unavailable(&c, &p);
}
#[test]
fn all_selected_required_wraps_must_authenticate_and_agree_with_effective_dek() {
    for historical in [false, true] {
        for mode in ["tag", "bad-base64", "conflict"] {
            let mut c = build("G03-selected-history");
            let ci = if historical { 0 } else { 4 };
            let target = if historical {
                c.h.fps[2].clone()
            } else {
                G1.into()
            };
            let bad = wrap_bytes(&c.h.env, G1, &c.h.records[2], &[99; 32], 100);
            change_op(&mut c.h, ci, 0, |op| {
                let w = &mut op["wraps"][&target];
                match mode {
                    "tag" => w["ciphertext"] = corrupt(&w["ciphertext"]),
                    "bad-base64" => w["eph_pub"] = json!("!"),
                    _ => *w = bad,
                }
            });
            let (p, _, _) = c.package();
            unavailable(&c, &p);
        }
    }
    // Bad unselected historical material is not claimed as authenticated.
    let mut c = build("G03-selected-history");
    let fp = c.h.fps[2].clone();
    change_op(&mut c.h, 0, 0, |op| {
        op["wraps"][&fp]["ciphertext"] = json!("!")
    });
    let (mut p, _, _) = c.package();
    let hash = c.h.history[0].hash().unwrap();
    p.payload["components"][5]["data"]["entries"]
        .as_array_mut()
        .unwrap()
        .retain(|e| e["source_commit_hash"] != hash);
    p.rebind(&c.h.keys[1]);
    assert_eq!(check(&c, &p, &c.h.keys[2]).unwrap(), (2, 4));
}
#[test]
fn malformed_wrap_fields_low_order_wrong_aad_tags_and_non32_deks_fail_closed() {
    let mut cases = Vec::new();
    for field in ["eph_pub", "nonce", "ciphertext"] {
        for length in [0usize, 1, 11, 12, 16, 31, 32, 33, 47, 48, 49] {
            if length
                != match field {
                    "eph_pub" => 32,
                    "nonce" => 12,
                    _ => 48,
                }
            {
                cases.push((field, length));
            }
        }
    }
    for (field, length) in cases {
        let mut c = build("G01-multiple");
        change_op(&mut c.h, 4, 0, |op| {
            op["wraps"][G1][field] = json!(pybase64::b64encode(&vec![0; length]))
        });
        let (p, _, _) = c.package();
        unavailable(&c, &p);
    }
    for mode in [
        "base64-point",
        "base64-nonce",
        "base64-ciphertext",
        "low-order",
        "wrong-env",
        "wrong-generation",
        "wrong-recipient",
        "tag",
        "wrong-key",
        "length0",
        "length31",
        "length33",
    ] {
        let mut c = build("G01-multiple");
        let replacement = match mode {
            "wrong-env" => Some(wrap_bytes("other-env", G1, &c.h.records[2], &dek(G1), 30)),
            "wrong-generation" => Some(wrap_bytes(&c.h.env, G2, &c.h.records[2], &dek(G1), 30)),
            "wrong-recipient" => Some(wrap_bytes(&c.h.env, G1, &c.h.records[1], &dek(G1), 30)),
            "wrong-key" => Some(wrap_bytes(&c.h.env, G1, &c.h.records[2], &dek(G2), 30)),
            "length0" => Some(wrap_bytes(&c.h.env, G1, &c.h.records[2], &[], 30)),
            "length31" => Some(wrap_bytes(&c.h.env, G1, &c.h.records[2], &[6; 31], 30)),
            "length33" => Some(wrap_bytes(&c.h.env, G1, &c.h.records[2], &[6; 33], 30)),
            _ => None,
        };
        change_op(&mut c.h, 4, 0, |op| {
            let w = &mut op["wraps"][G1];
            match mode {
                "base64-point" => w["eph_pub"] = json!("!"),
                "base64-nonce" => w["nonce"] = json!("!"),
                "base64-ciphertext" => w["ciphertext"] = json!("!"),
                "low-order" => w["eph_pub"] = json!(pybase64::b64encode(&[0; 32])),
                "tag" => w["ciphertext"] = corrupt(&w["ciphertext"]),
                _ => *w = replacement.unwrap(),
            }
        });
        let (p, _, _) = c.package();
        unavailable(&c, &p);
    }
}
#[test]
fn every_required_ciphertext_and_last_unconnected_staged_version_is_checked() {
    for slot in [0usize, 2, 7, 8] {
        // alpha active, alpha staged, beta staged, orphan staged
        for mode in [
            "tag",
            "nonce",
            "key",
            "env",
            "secret",
            "version",
            "short-tag",
            "bad-base64",
        ] {
            let mut c = build("G07-late-failure");
            let op = &c.h.history[5].ops[slot];
            assert_eq!(op["op"], "secret.put_version");
            let sid = op["secret_id"].as_str().unwrap();
            let vid = op["version_id"].as_str().unwrap();
            let g = op["generation_id"].as_str().unwrap();
            let replacement = match mode {
                "key" => Some(cipher(&c.h.env, sid, vid, SENTINEL, &[99; 32], 6)),
                "env" => Some(cipher("other-env", sid, vid, SENTINEL, &dek(g), 6)),
                "secret" => Some(cipher(&c.h.env, "other-secret", vid, SENTINEL, &dek(g), 6)),
                "version" => Some(cipher(&c.h.env, sid, V4, SENTINEL, &dek(g), 6)),
                _ => None,
            };
            change_op(&mut c.h, 5, slot, |op| {
                let entry = &mut op["ciphertext"];
                match mode {
                    "tag" => entry["ciphertext"] = corrupt(&entry["ciphertext"]),
                    "nonce" => entry["nonce"] = json!(pybase64::b64encode(&[99; 12])),
                    "short-tag" => entry["ciphertext"] = json!(pybase64::b64encode(&[0; 15])),
                    "bad-base64" => entry["ciphertext"] = json!("!"),
                    _ => *entry = replacement.unwrap(),
                }
            });
            let (p, _, _) = c.package();
            unavailable(&c, &p);
            unavailable(&c, &p);
        }
    }
}
#[test]
fn inactive_deleted_history_and_no_version_tombstones_are_retained_unassessed() {
    for name in ["G04-deletion", "G05-empty"] {
        let mut c = build(name);
        change_op(&mut c.h, 5, 0, |op| {
            op["ciphertext"]["ciphertext"] = json!("!")
        });
        let (mut p, doc, order) = c.package();
        omit(
            &mut p,
            if name == "G05-empty" {
                &[G1, G2, G3]
            } else {
                &[G1, G3]
            },
            true,
            &c.h,
        );
        assert_eq!(
            check(&c, &p, &c.h.keys[2]).unwrap(),
            if name == "G05-empty" { (0, 0) } else { (1, 1) }
        );
        assert_eq!(doc["secrets"]["alpha"]["versions"][V1]["ciphertext"], "!");
        assert_eq!(order["alpha"], json!([V1, V2, V3, V4]));
        assert!(doc["secrets"]["deleted-empty"].is_null());
        assert!(
            c.h.facts
                .iter()
                .any(|f| f.kind == "secret_deleted" && f.target["secret_id"] == "deleted-empty")
        );
    }
    // The same retained literal version changes from retired to staged in a
    // separately signed history; its corrupt bytes then become mandatory.
    let mut c = build("G01-multiple");
    change_op(&mut c.h, 5, 3, |op| {
        op["ciphertext"]["ciphertext"] = json!("!")
    });
    let (p, _, _) = c.package();
    assert_eq!(check(&c, &p, &c.h.keys[2]).unwrap(), (2, 4));
    change_op(&mut c.h, 5, 4, |op| {
        *op = json!({"op":"settings.update","sync_interval_seconds":13})
    });
    let (p, _, _) = c.package();
    unavailable(&c, &p);
}
#[test]
fn selected_source_errors_remain_upstream_and_image_only_wrap_is_insufficient() {
    let c = build("G01-multiple");
    let (base, _, _) = c.package();
    for mode in ["source", "index", "recipient", "generation", "wrap"] {
        let mut p = Package {
            manifest: base.manifest.clone(),
            payload: base.payload.clone(),
        };
        let e = &mut p.payload["components"][5]["data"]["entries"][0];
        match mode {
            "source" => e["source_commit_hash"] = json!("99".repeat(32)),
            "index" => e["source_op_index"] = json!(999),
            "recipient" => e["recipient"] = json!(c.h.fps[1]),
            "generation" => e["generation_id"] = json!("ffffffffffffffff"),
            _ => e["wrap"]["nonce"] = json!("!"),
        };
        p.rebind(&c.h.keys[1]);
        let m = p.attestation(&c.h);
        assert_eq!(
            verify_payload_bytes(&m, &canon(&p.payload)).unwrap_err(),
            CheckpointError::StructureInvalid
        );
    }
    let mut p = base;
    omit(&mut p, &[G1], false, &c.h);
    assert!(
        !p.payload["components"][1]["data"]["document"]["dek"]["generations"][G1]["wraps"]
            [&c.h.fps[2]]
            .is_null()
    );
    unavailable(&c, &p);
}
#[test]
fn supported_isolated_removal_preserves_old_new_keys_and_m1_restrictions() {
    let c = build("G08-removal");
    let (p, doc, _) = c.package();
    assert_eq!(check(&c, &p, &c.h.keys[2]).unwrap(), (2, 2));
    assert_eq!(doc["members"][&c.h.fps[3]]["status"], "removed");
    assert!(
        doc["dek"]["generations"][G2]["wraps"]
            .get(&c.h.fps[3])
            .is_none()
    );
    let m = p.attestation(&c.h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let local = c.h.local(&m);
    assert_eq!(
        verify_retained_authority(&m, &payload, &local).unwrap_err(),
        SemanticError::ScopeUnsupported
    );
}
#[test]
fn privacy_early_late_repeat_and_drop_do_not_mutate_public_inputs() {
    let mut c = build("G07-late-failure");
    let (base, _, _) = c.package();
    let before = canon(&base.payload);
    let manifest = canon(&base.manifest);
    let history = canon(&json!(
        c.h.history.iter().map(|c| c.to_dict()).collect::<Vec<_>>()
    ));
    for _ in 0..2 {
        assert_eq!(check(&c, &base, &c.h.keys[2]).unwrap(), (2, 4));
    }
    let mut early = Package {
        manifest: base.manifest.clone(),
        payload: base.payload.clone(),
    };
    omit(&mut early, &[G1], true, &c.h);
    let e = check(&c, &early, &c.h.keys[2]).unwrap_err();
    for public in [e.to_string(), format!("{e:?}")] {
        for marker in [
            String::from_utf8(SENTINEL.to_vec()).unwrap(),
            hex::encode(SENTINEL),
            pybase64::b64encode(SENTINEL),
            hex::encode(dek(G1)),
        ] {
            assert!(!public.contains(&marker));
        }
    }
    change_op(&mut c.h, 5, 8, |op| {
        op["ciphertext"]["ciphertext"] = corrupt(&op["ciphertext"]["ciphertext"])
    });
    let (late, _, _) = c.package();
    let late_before = canon(&late.payload);
    unavailable(&c, &late);
    unavailable(&c, &late);
    assert_eq!(late_before, canon(&late.payload));
    assert_eq!(before, canon(&base.payload));
    assert_eq!(manifest, canon(&base.manifest));
    assert_ne!(
        history,
        canon(&json!(
            c.h.history.iter().map(|c| c.to_dict()).collect::<Vec<_>>()
        ))
    );
}
#[test]
fn required_generation_depth64_success_late_error_repeat_drop_on_actual_256_kib() {
    for fail in [false, true] {
        let mut c = build("G07-late-failure");
        change_op(&mut c.h, 5, 8, |op| {
            op["public"] = nested(55);
            if fail {
                op["ciphertext"]["ciphertext"] = corrupt(&op["ciphertext"]["ciphertext"]);
            }
        });
        let (p, _, _) = c.package();
        let m = p.attestation(&c.h);
        let raw = canon(&p.payload);
        assert_eq!(measured_depth(&raw), 64);
        let local = c.h.local(&m);
        let key = key(2, 5);
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let payload = verify_payload_bytes(&m, &raw).unwrap();
                let candidate = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
                for _ in 0..3 {
                    let result = verify_required_generations(&candidate, &key);
                    if fail {
                        assert_eq!(result.unwrap_err(), SemanticError::GenerationUnavailable);
                    } else {
                        let r = result.unwrap();
                        assert_eq!(r.checked_ciphertext_count(), 4);
                        drop(r);
                    }
                }
                drop(candidate);
                drop(payload);
                drop(local);
                drop(m);
                drop(raw);
                drop(key);
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
#[test]
fn required_generation_depth65_refuses_before_crypto_on_actual_256_kib() {
    let c = build("G01-multiple");
    let (mut p, _, _) = c.package();
    p.payload["components"][1]["data"]["document"]["opaque"] = nested(60);
    p.rebind(&c.h.keys[1]);
    let m = p.attestation(&c.h);
    let raw = canon(&p.payload);
    assert_eq!(measured_depth(&raw), 65);
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            assert_eq!(
                verify_payload_bytes(&m, &raw).unwrap_err(),
                CheckpointError::LimitExceeded
            );
            drop(raw);
            drop(m);
        })
        .unwrap()
        .join()
        .unwrap();
}
#[test]
fn bounded_work_measurements_separate_setup_complete_and_key_stage() {
    use std::time::Instant;
    for mode in [
        "near-payload",
        "many-keys",
        "many-versions",
        "empty",
        "late-failure",
    ] {
        let start = Instant::now();
        let mut c = build(if mode == "empty" {
            "G05-empty"
        } else {
            "G01-multiple"
        });
        if mode == "near-payload" {
            let bytes = vec![0x51; 5_800_000];
            let env = c.h.env.clone();
            change_op(&mut c.h, 5, 0, |op| {
                op["ciphertext"] = cipher(&env, "alpha", V1, &bytes, &dek(G1), 99)
            });
        }
        if mode == "many-versions" {
            let ops = (0..4096)
                .map(|i| {
                    put(
                        &c.h,
                        "bulk",
                        &format!("{i:016x}"),
                        G1,
                        "password",
                        SENTINEL,
                        100,
                    )
                })
                .collect();
            append(&mut c.h, ops);
        }
        if mode == "many-keys" {
            let mut ops = Vec::new();
            for i in 0..256 {
                let g = format!("{i:016x}");
                let mut key = vec![0u8; 32];
                key[..8].copy_from_slice(&(i as u64).to_le_bytes());
                let wraps = json!({&c.h.fps[2]:wrap_bytes(&c.h.env,&g,&c.h.records[2],&key,100)});
                ops.push(json!({"op":"dek.rotate","generation_id":g,"wraps":wraps}));
                ops.push(json!({"op":"secret.put_version","secret_id":format!("key-{i}"),"version_id":V1,"generation_id":g,"kind":"api_key","ciphertext":cipher(&c.h.env,&format!("key-{i}"),V1,SENTINEL,&key,100),"public":{}}));
            }
            append(&mut c.h, ops);
        }
        if mode == "late-failure" {
            change_op(&mut c.h, 5, 8, |op| {
                op["ciphertext"]["ciphertext"] = corrupt(&op["ciphertext"]["ciphertext"])
            });
        }
        let (p, _, _) = c.package();
        let setup = start.elapsed();
        let raw = canon(&p.payload);
        assert!(raw.len() <= 16_777_216);
        if mode == "near-payload" {
            assert!(raw.len() > 15_000_000);
        }
        let m = p.attestation(&c.h);
        let local = c.h.local(&m);
        let start = Instant::now();
        let payload = verify_payload_bytes(&m, &raw).unwrap();
        let candidate = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
        let semantics = start.elapsed();
        let start = Instant::now();
        let r = verify_required_generations(&candidate, &c.h.keys[2]);
        let key_time = start.elapsed();
        let counts = if mode == "late-failure" {
            assert_eq!(r.unwrap_err(), SemanticError::GenerationUnavailable);
            (0, 0)
        } else {
            let r = r.unwrap();
            (r.required_generation_count(), r.checked_ciphertext_count())
        };
        println!(
            "MEASURE mode={mode} bytes={} records={} wraps={} setup_us={} complete_us={} key_us={} required={} checked={} key_payload_bytes={} map_and_index_allocator_overhead=unmeasured",
            raw.len(),
            p.manifest["counts"]["versions"],
            p.manifest["counts"]["recipient_wraps"],
            setup.as_micros(),
            semantics.as_micros(),
            key_time.as_micros(),
            counts.0,
            counts.1,
            counts.0 * 32
        );
    }
}

#[test]
fn full_local_record_and_approved_role_mismatch_stay_upstream_refusals() {
    let c = build("G01-multiple");
    let (p, _, _) = c.package();
    let m = p.attestation(&c.h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    for role in [false, true] {
        let mut bindings = c.h.bindings(&m);
        if role {
            bindings.recipient_role = RecipientRole::Admin;
        } else {
            bindings.recipient_record = key(2, 9).record().unwrap();
        }
        let local = SemanticLocalInputs::from_local_observation(
            bindings,
            legacy::inventory(),
            vec![],
            legacy::restrictions(),
        )
        .unwrap();
        assert_eq!(
            verify_complete_cut_semantics(&m, &payload, &local).unwrap_err(),
            SemanticError::Checkpoint(CheckpointError::BindingMismatch)
        );
    }
}
#[test]
fn original_member_add_wrap_for_absent_generation_is_not_applicable_evidence() {
    let mut c = build("G01-multiple");
    let admission = c.h.history[4].ops[0].clone();
    let mut owner = c.h.history[1].to_dict();
    owner["ops"].as_array_mut().unwrap().push(admission);
    legacy::resign(&mut owner, &c.h.keys[0]);
    c.h.history[1] = zeropw::team::commit::Commit::from_dict(&owner).unwrap();
    change_op(&mut c.h, 4, 0, |op| {
        *op = json!({"op":"settings.update","sync_interval_seconds":13})
    });
    let (p, _, _) = c.package();
    let m = p.attestation(&c.h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let local = c.h.local(&m);
    assert_eq!(
        verify_complete_cut_semantics(&m, &payload, &local).unwrap_err(),
        SemanticError::AuthorityUnproven
    );
}
#[test]
fn required_transition_preserves_original_bytes_and_fact_hashes_but_requires_missing_key() {
    let mut c = build("G01-multiple");
    append(
        &mut c.h,
        vec![
            json!({"op":"secret.set_status","secret_id":"alpha","version_id":V1,"status":"retired"}),
            json!({"op":"secret.set_status","secret_id":"alpha","version_id":V2,"status":"retired"}),
        ],
    );
    let (mut p, doc, order) = c.package();
    omit(&mut p, &[G1], true, &c.h);
    assert_eq!(check(&c, &p, &c.h.keys[2]).unwrap(), (1, 2));
    let facts: Vec<_> = c.h.facts.iter().map(|f| f.hash().unwrap()).collect();
    append(
        &mut c.h,
        vec![json!({"op":"secret.activate","secret_id":"alpha","version_id":V2})],
    );
    let (mut p, after, after_order) = c.package();
    omit(&mut p, &[G1], true, &c.h);
    unavailable(&c, &p);
    assert_eq!(order, after_order);
    for vid in [V1, V2, V3, V4] {
        for field in ["nonce", "ciphertext", "generation"] {
            assert_eq!(
                doc["secrets"]["alpha"]["versions"][vid][field],
                after["secrets"]["alpha"]["versions"][vid][field]
            );
        }
    }
    assert_eq!(
        facts,
        c.h.facts
            .iter()
            .map(|f| f.hash().unwrap())
            .collect::<Vec<_>>()
    );
}
#[test]
fn later_required_wrap_tag_failure_is_not_an_available_prefix_result() {
    let mut c = build("G07-late-failure");
    change_op(&mut c.h, 4, 0, |op| {
        op["wraps"][G2]["ciphertext"] = corrupt(&op["wraps"][G2]["ciphertext"])
    });
    let (p, _, _) = c.package();
    for _ in 0..3 {
        unavailable(&c, &p);
    }
}

#[test]
fn required_wrap_depth64_success_error_repeat_drop_on_actual_256_kib() {
    for fail in [false, true] {
        let mut c = build("G07-late-failure");
        change_op(&mut c.h, 4, 0, |op| op["wraps"][G1]["opaque"] = nested(53));
        if fail {
            change_op(&mut c.h, 5, 8, |op| {
                op["ciphertext"]["ciphertext"] = corrupt(&op["ciphertext"]["ciphertext"])
            });
        }
        let (p, _, _) = c.package();
        let m = p.attestation(&c.h);
        let raw = canon(&p.payload);
        assert_eq!(measured_depth(&raw), 64);
        let local = c.h.local(&m);
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let payload = verify_payload_bytes(&m, &raw).unwrap();
                let candidate = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
                for _ in 0..2 {
                    let recipient = key(2, 5);
                    let result = verify_required_generations(&candidate, &recipient);
                    drop(recipient);
                    if fail {
                        assert_eq!(result.unwrap_err(), SemanticError::GenerationUnavailable);
                    } else {
                        drop(result.unwrap());
                    }
                }
                drop(candidate);
                drop(payload);
                drop(local);
                drop(m);
                drop(raw);
            })
            .unwrap()
            .join()
            .unwrap();
    }
}

fn measure_stress(c: &Case, label: &str, setup: std::time::Duration, expected: (usize, usize)) {
    use std::time::Instant;
    let packaging_start = Instant::now();
    let (p, _, _) = c.package();
    let raw = canon(&p.payload);
    let packaging = packaging_start.elapsed();
    assert!((14_000_000..=16_777_216).contains(&raw.len()));
    let m = p.attestation(&c.h);
    let local = c.h.local(&m);
    let start = Instant::now();
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let candidate = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
    let complete = start.elapsed();
    let start = Instant::now();
    let result = verify_required_generations(&candidate, &c.h.keys[2]).unwrap();
    let keys = start.elapsed();
    assert_eq!(
        (
            result.required_generation_count(),
            result.checked_ciphertext_count()
        ),
        expected
    );
    println!(
        "STRESS label={label} bytes={} commits={} versions={} selected_wraps={} fixture_history_us={} fixture_package_us={} complete_us={} key_stage_us={} required={} checked={} key_payload_bytes={} allocator_overhead=not_a_quota",
        raw.len(),
        c.h.history.len(),
        p.manifest["counts"]["versions"],
        p.manifest["counts"]["recipient_wraps"],
        setup.as_micros(),
        packaging.as_micros(),
        complete.as_micros(),
        keys.as_micros(),
        expected.0,
        expected.1,
        expected.0 * 32
    );
    drop(result);
    drop(candidate);
    drop(payload);
    drop(local);
    drop(m);
    assert_eq!(raw, canon(&p.payload));
}
#[test]
fn near_limit_original_record_distribution_authenticates_required_ciphertexts() {
    let start = std::time::Instant::now();
    let mut c = build("G01-multiple");
    let mut estimated = 20_000usize;
    for seq in 6..=65_540 {
        let original = c.h.c(
            0,
            seq,
            10_000 + seq,
            &[(0, seq - 1), (1, 1)],
            vec![json!({"op":"settings.update","sync_interval_seconds":10})],
        );
        let bytes = original.canonical_json(true).unwrap().len() + 90;
        if estimated + bytes > 15_900_000 {
            break;
        }
        estimated += bytes;
        c.h.history.push(original);
    }
    c.h.retained = (0..c.h.history.len()).collect();
    assert!(c.h.history.len() > 20_000);
    measure_stress(
        &c,
        "original-records-near-byte-cap",
        start.elapsed(),
        (2, 4),
    );
}
#[test]
fn near_limit_required_wrap_distribution_authenticates_every_distinct_key_and_version() {
    let start = std::time::Instant::now();
    let mut c = build("G01-multiple");
    let mut ops = Vec::new();
    for i in 0..11_500u64 {
        let generation = format!("{i:016x}");
        let sid = format!("key-{i}");
        let mut bytes = vec![0u8; 32];
        bytes[..8].copy_from_slice(&i.to_le_bytes());
        let wrapped = wrap_bytes(&c.h.env, &generation, &c.h.records[2], &bytes, 100);
        ops.push(
            json!({"op":"dek.rotate","generation_id":generation,"wraps":{&c.h.fps[2]:wrapped}}),
        );
        ops.push(json!({"op":"secret.put_version","secret_id":sid,"version_id":V1,"generation_id":generation,"kind":"api_key","ciphertext":cipher(&c.h.env,&sid,V1,b"x",&bytes,100),"public":{}}));
    }
    // Keep the same 11,500 distinct keys/versions, in bounded original
    // commits. The preserved all-in-one-commit phase13 trial separately
    // exposes the frozen complete-fold per-operation whole-commit hash cost.
    for group in ops.chunks(32) {
        append(&mut c.h, group.to_vec());
    }
    measure_stress(
        &c,
        "11500-distinct-required-original-wraps-in-bounded-commits-near-byte-cap",
        start.elapsed(),
        (11_502, 11_504),
    );
}

#[test]
fn isolated_removal_keeps_observed_original_m1_tombstone_and_support_requirements() {
    let mut c = build("G08-removal");
    let f = c.h.f(
        1,
        "secret_deleted",
        json!({"secret_id":"deleted-removal-empty"}),
        8000,
    );
    let hash = f.hash().unwrap();
    c.h.facts.push(f.clone());
    let (p, doc, order) = c.package();
    let (literal, literal_order) = c.literal_document();
    assert_eq!(canon(&doc), canon(&literal));
    assert_eq!(canon(&order), canon(&literal_order));
    assert!(doc["secrets"]["deleted-removal-empty"].is_null());
    let m = p.attestation(&c.h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let mut deny = legacy::restrictions();
    deny.deleted_secret_ids
        .insert("deleted-removal-empty".into());
    deny.removed_members.insert(c.h.fps[3].clone());
    deny.known_original_facts.push(KnownOriginalFact {
        hash: hash.clone(),
        original: f,
        author_record: c.h.records[1].clone(),
    });
    deny.required_tombstone_support = RequiredTombstoneSupport::Required {
        known_tombstone_hashes: [hash.clone()].into_iter().collect(),
        unresolved_nonempty_digests: [p.manifest["tombstone_digest"].as_str().unwrap().to_owned()]
            .into_iter()
            .collect(),
    };
    let local = SemanticLocalInputs::from_local_observation(
        c.h.bindings(&m),
        legacy::inventory(),
        vec![],
        deny,
    )
    .unwrap();
    let candidate = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
    assert!(candidate.contains_original_fact_hash(&hash));
    let checked = verify_required_generations(&candidate, &c.h.keys[2]).unwrap();
    assert_eq!(
        (
            checked.required_generation_count(),
            checked.checked_ciphertext_count()
        ),
        (2, 2)
    );
    assert_eq!(checked.tombstone_digest(), candidate.tombstone_digest());
    drop(checked);
    assert!(candidate.contains_original_fact_hash(&hash));
    assert_eq!(raw, canon(&p.payload));
}
