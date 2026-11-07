use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeropw::{
    crypto::ed25519,
    pybase64,
    pyjson::{self, DumpOptions},
    team::{checkpoint::*, identity::DeviceRecord},
};
const M: &[u8] = include_bytes!("fixtures/team_checkpoint_v1/manifest.json");
const P: &[u8] = include_bytes!("fixtures/team_checkpoint_v1/payload.json");
fn load(bytes: &[u8]) -> Value {
    pyjson::loads(std::str::from_utf8(bytes).unwrap()).unwrap()
}
fn canon(value: &Value) -> Vec<u8> {
    pyjson::dumps(value, DumpOptions::compact_sorted())
        .unwrap()
        .into_bytes()
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
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
fn sign(mut m: Value) -> Vec<u8> {
    m.as_object_mut().unwrap().remove("sig");
    let sig = ed25519::sign(&[1; 32], &canon(&m)).unwrap();
    m["sig"] = json!(pybase64::b64encode(&sig));
    canon(&m)
}
fn attestation(m: Value) -> ManifestAttestation {
    verify_manifest_bytes(
        &sign(m),
        &context(),
        VerificationWallTime::from_millis(1_800_000_000_001).unwrap(),
    )
    .unwrap()
}
fn raw_binding(mut m: Value, raw: &[u8]) -> ManifestAttestation {
    m["payload"] = json!({"byte_length":raw.len(),"sha256":sha(raw),"chunks":raw.chunks(65_536).enumerate().map(|(i,b)|json!({"index":i,"byte_length":b.len(),"sha256":sha(b)})).collect::<Vec<_>>()});
    attestation(m)
}
fn binding(mut m: Value, payload: &Value) -> (ManifestAttestation, Vec<u8>) {
    for (i, c) in payload["components"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .take(6)
    {
        let bytes = canon(&c["data"]);
        m["components"][i]["byte_length"] = json!(bytes.len());
        m["components"][i]["sha256"] = json!(sha(&bytes));
    }
    let raw = canon(payload);
    (raw_binding(m, &raw), raw)
}
fn repair_records(m: &mut Value, p: &mut Value) {
    let mut mapping = BTreeMap::new();
    for envelope in p["components"][2]["data"]["records"]
        .as_array_mut()
        .unwrap()
    {
        let old = envelope["hash"].as_str().unwrap().to_owned();
        let new = sha(&canon(&envelope["record"]));
        mapping.insert(old, new.clone());
        envelope["hash"] = json!(new);
    }
    p["components"][2]["data"]["records"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["hash"].as_str().cmp(&b["hash"].as_str()));
    let replace = |value: &mut Value| {
        if let Some(new) = value.as_str().and_then(|s| mapping.get(s)) {
            *value = json!(new);
        }
    };
    for head in m["heads"].as_array_mut().unwrap() {
        replace(&mut head["commit_hash"]);
    }
    replace(&mut m["recipient_admission_commit_hash"]);
    let c = &mut p["components"][2]["data"];
    for key in ["genesis_commit_hash", "recipient_admission_commit_hash"] {
        replace(&mut c[key]);
    }
    for v in c["authority_commit_hashes"].as_array_mut().unwrap() {
        replace(v);
    }
    c["authority_commit_hashes"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    for e in p["components"][5]["data"]["entries"]
        .as_array_mut()
        .unwrap()
    {
        replace(&mut e["source_commit_hash"]);
    }
}
fn repair_facts(m: &mut Value, p: &mut Value) {
    let c = &mut p["components"][3]["data"];
    for entry in c["records"].as_array_mut().unwrap() {
        entry["hash"] = json!(sha(&canon(&entry["record"])));
    }
    c["records"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["hash"].as_str().cmp(&b["hash"].as_str()));
    let hashes: Vec<_> = c["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["hash"].clone())
        .collect();
    let tombstones: Vec<_> = c["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["record"]["kind"] == "secret_deleted")
        .map(|e| e["hash"].clone())
        .collect();
    c["admitted_fact_hashes"] = json!(hashes);
    c["tombstone_fact_hashes"] = json!(tombstones);
    m["admitted_fact_hashes_sha256"] = json!(sha(&canon(&c["admitted_fact_hashes"])));
    m["tombstone_digest"] = json!(sha(&canon(&c["tombstone_fact_hashes"])));
}
fn frame(a: &ManifestAttestation, index: usize, bytes: &[u8]) -> Value {
    json!({"type":"BOOTSTRAP_CHUNK","v":1,"transfer_id":a.signed_metadata()["transfer_id"],"manifest_hash":a.manifest_hash(),"index":index,"data_b64":pybase64::b64encode(bytes)})
}

#[test]
fn baseline_exact_component_spans_and_original_record_hash_goldens() {
    let a = attestation(load(M));
    let p = verify_payload_bytes(&a, P).unwrap();
    assert_eq!(p.canonical_commit_hashes().len(), 5);
    assert!(p.candidate_fact_hashes().is_empty());
    let expected = load(include_bytes!("fixtures/team_checkpoint_v1/expected.json"));
    for (i, c) in p.components().iter().enumerate() {
        let e = &expected["component_spans"][i];
        assert_eq!(c.range().start, e["offset"].as_u64().unwrap() as usize);
        assert_eq!(
            c.original_bytes().len(),
            e["byte_length"].as_u64().unwrap() as usize
        );
        assert_eq!(sha(c.original_bytes()), e["sha256"].as_str().unwrap());
    }
    assert_eq!(
        verify_chunk_frame_bytes(
            &a,
            include_bytes!("fixtures/team_checkpoint_v1/chunk-000.json")
        )
        .unwrap()
        .encrypted_bytes(),
        P
    );
}
#[test]
fn every_frozen_candidate_variant_reaches_only_the_limited_stage() {
    for (manifest, payload, candidate) in [
        (
            include_bytes!("fixtures/team_checkpoint_v1/variants/deleted-empty/manifest.json")
                .as_slice(),
            include_bytes!("fixtures/team_checkpoint_v1/variants/deleted-empty/payload.json")
                .as_slice(),
            include_bytes!("fixtures/team_checkpoint_v1/variants/deleted-empty/candidate.json")
                .as_slice(),
        ),
        (
            include_bytes!("fixtures/team_checkpoint_v1/variants/deleted-retained/manifest.json")
                .as_slice(),
            include_bytes!("fixtures/team_checkpoint_v1/variants/deleted-retained/payload.json")
                .as_slice(),
            include_bytes!("fixtures/team_checkpoint_v1/variants/deleted-retained/candidate.json")
                .as_slice(),
        ),
        (
            include_bytes!(
                "fixtures/team_checkpoint_v1/variants/changed-final-digest/manifest.json"
            )
            .as_slice(),
            include_bytes!(
                "fixtures/team_checkpoint_v1/variants/changed-final-digest/payload.json"
            )
            .as_slice(),
            include_bytes!(
                "fixtures/team_checkpoint_v1/variants/changed-final-digest/candidate.json"
            )
            .as_slice(),
        ),
        (
            include_bytes!(
                "fixtures/team_checkpoint_v1/variants/invalid-inner-signature/manifest.json"
            )
            .as_slice(),
            include_bytes!(
                "fixtures/team_checkpoint_v1/variants/invalid-inner-signature/payload.json"
            )
            .as_slice(),
            include_bytes!(
                "fixtures/team_checkpoint_v1/variants/invalid-inner-signature/candidate.json"
            )
            .as_slice(),
        ),
    ] {
        let a = attestation(load(manifest));
        let p = verify_payload_bytes(&a, payload).unwrap();
        assert_eq!(
            candidate_provenance(&a, &p)
                .unwrap()
                .canonical_json()
                .unwrap(),
            candidate
        );
    }
}
#[test]
fn reattested_structural_and_closed_schema_negatives() {
    let cases: Vec<(&str, Value)> = vec![
        ("device record", {
            let mut p = load(P);
            p["components"][0]["data"][0]["record"]["sig"] = json!(pybase64::b64encode(&[0; 64]));
            p
        }),
        ("device order", {
            let mut p = load(P);
            p["components"][0]["data"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1);
            p
        }),
        ("snapshot vector", {
            let mut p = load(P);
            let key = p["components"][1]["data"]["vector"]
                .as_object()
                .unwrap()
                .keys()
                .next()
                .unwrap()
                .clone();
            p["components"][1]["data"]["vector"][key] = json!(3);
            p
        }),
        ("component order", {
            let mut p = load(P);
            p["components"].as_array_mut().unwrap().swap(0, 1);
            p
        }),
        ("component unknown", {
            let mut p = load(P);
            p["components"][4]["extra"] = json!(true);
            p
        }),
        ("payload unknown", {
            let mut p = load(P);
            p["unrecognized"] = json!(0);
            p
        }),
        ("missing wrapper field", {
            let mut p = load(P);
            p["components"][3]["data"]
                .as_object_mut()
                .unwrap()
                .remove("tombstone_fact_hashes");
            p
        }),
        ("missing genesis", {
            let mut p = load(P);
            p["components"][2]["data"]["genesis_commit_hash"] = json!("0".repeat(64));
            p
        }),
        ("missing witness", {
            let mut p = load(P);
            p["components"][4]["data"]["witness_commit_hashes"] = json!(["0".repeat(64)]);
            p
        }),
        ("wrong source", {
            let mut p = load(P);
            p["components"][5]["data"]["entries"][0]["source_commit_hash"] = json!("0".repeat(64));
            p
        }),
        ("wrong wrap recipient", {
            let mut p = load(P);
            p["components"][5]["data"]["entries"][0]["recipient"] = json!("a".repeat(26));
            p
        }),
        ("wrong op index", {
            let mut p = load(P);
            p["components"][5]["data"]["entries"][0]["source_op_index"] = json!(1);
            p
        }),
        ("changed wrap", {
            let mut p = load(P);
            p["components"][5]["data"]["entries"][0]["wrap"]["ciphertext"] = json!("changed");
            p
        }),
        ("unavailable overlap", {
            let mut p = load(P);
            p["components"][5]["data"]["unavailable_generations"] = json!(["a".repeat(16)]);
            p
        }),
        ("legacy versions shape", {
            let mut p = load(P);
            p["components"][1]["data"]["document"]["secrets"]["retained-secret"]["versions"] =
                json!([]);
            p
        }),
        ("version order shape", {
            let mut p = load(P);
            p["components"][1]["data"]["version_order"]["retained-secret"] = json!([true]);
            p
        }),
    ];
    for (name, p) in cases {
        let (a, raw) = binding(load(M), &p);
        assert!(verify_payload_bytes(&a, &raw).is_err(), "{name}");
    }
    // Each mutation below has repaired record/component/chunk/manifest hashes,
    // so refusal exercises record identities or references, not an outer SHA.
    for mode in 0..5 {
        let mut p = load(P);
        let mut m = load(M);
        let records = p["components"][2]["data"]["records"]
            .as_array_mut()
            .unwrap();
        match mode {
            0 => {
                records[1] = records[0].clone();
            }
            1 => {
                records[0]["record"]["extra"] = json!(0);
            }
            2 => {
                records[0]["record"]["author"] = json!("a".repeat(26));
            }
            3 => {
                records[0]["record"]["hlc"] = json!("99999999-0000");
            }
            _ => {
                records[0]["record"]["author_seq"] = json!(9999999);
            }
        }
        repair_records(&mut m, &mut p);
        let (a, raw) = binding(m, &p);
        assert!(
            verify_payload_bytes(&a, &raw).is_err(),
            "record mode {mode}"
        );
    }
}
#[test]
fn counts_hash_sets_tombstones_and_removal_order_are_independently_enforced() {
    let mut m = load(M);
    m["counts"]["versions"] = json!(1);
    let (a, raw) = binding(m, &load(P));
    assert_eq!(
        verify_payload_bytes(&a, &raw).unwrap_err(),
        CheckpointError::StructureInvalid
    );
    for mode in 0..6 {
        let mut p = load(include_bytes!(
            "fixtures/team_checkpoint_v1/variants/deleted-retained/payload.json"
        ));
        let mut m = load(include_bytes!(
            "fixtures/team_checkpoint_v1/variants/deleted-retained/manifest.json"
        ));
        match mode {
            0 => p["components"][3]["data"]["admitted_fact_hashes"] = json!([]),
            1 => p["components"][3]["data"]["tombstone_fact_hashes"] = json!([]),
            2 => {
                let h = p["components"][3]["data"]["admitted_fact_hashes"][0].clone();
                p["components"][3]["data"]["admitted_fact_hashes"] = json!([h, h]);
            }
            3 => m["tombstone_digest"] = json!("0".repeat(64)),
            4 => {
                let fp = m["signer"].clone();
                p["components"][4]["data"]["pending"] = json!([[2, 0, fp], [1, 0, fp]]);
            }
            _ => {
                p["components"][2]["data"]["authority_commit_hashes"] =
                    json!(["0".repeat(64), "0".repeat(64)])
            }
        }
        let (a, raw) = binding(m, &p);
        assert!(verify_payload_bytes(&a, &raw).is_err(), "{mode}");
    }
}
#[test]
fn original_bytes_duplicates_grammar_and_whitespace_scope() {
    let base = String::from_utf8(P.to_vec()).unwrap();
    for raw in [
        base.replacen('{', "{\"v\":1,", 1),
        base.replacen(
            "\"records\":[",
            "\"records\":[{\"hash\":\"x\",\"hash\":invalid},",
            1,
        ),
        base.replacen("\"data\":[", "\"data\":[,", 1),
    ] {
        let a = raw_binding(load(M), raw.as_bytes());
        assert!(verify_payload_bytes(&a, raw.as_bytes()).is_err());
    }
    let outside = base.replacen("\"data\":[", "\"data\":  [", 1);
    let a = raw_binding(load(M), outside.as_bytes());
    let proof = verify_payload_bytes(&a, outside.as_bytes()).unwrap();
    assert_eq!(
        proof.components()[0].original_bytes(),
        include_bytes!("fixtures/team_checkpoint_v1/components/devices.json")
    );
    let old = include_str!("fixtures/team_checkpoint_v1/components/devices.json");
    let changed = old.replacen("},{", "}, {", 1);
    let inside = base.replacen(old, &changed, 1);
    let a = raw_binding(load(M), inside.as_bytes());
    assert_eq!(
        verify_payload_bytes(&a, inside.as_bytes()).unwrap_err(),
        CheckpointError::IntegrityMismatch
    );
    let mut m = load(M);
    m["components"][0]["byte_length"] = json!(changed.len());
    m["components"][0]["sha256"] = json!(sha(changed.as_bytes()));
    let a = raw_binding(m, inside.as_bytes());
    verify_payload_bytes(&a, inside.as_bytes()).unwrap();
    let a = attestation(load(M));
    let mut invalid = P.to_vec();
    invalid[0] = b'!';
    assert_eq!(
        verify_payload_bytes(&a, &invalid).unwrap_err(),
        CheckpointError::IntegrityMismatch
    );
}
#[test]
fn chunk_binding_sizes_canonical_base64_and_stateless_duplicates() {
    let a = attestation(load(M));
    let good = frame(&a, 0, P);
    let raw = canon(&good);
    let one = verify_chunk_frame_bytes(&a, &raw).unwrap();
    let two = verify_chunk_frame_bytes(&a, &raw).unwrap();
    assert_eq!(one.encrypted_bytes(), two.encrypted_bytes());
    for (key, value) in [
        ("manifest_hash", json!("0".repeat(64))),
        ("transfer_id", json!("0".repeat(32))),
        ("index", json!(1)),
        ("data_b64", json!("AA==")),
        ("extra", json!(0)),
    ] {
        let mut frame = good.clone();
        frame[key] = value;
        assert!(
            verify_chunk_frame_bytes(&a, &canon(&frame)).is_err(),
            "{key}"
        );
    }
    let mut padded = raw.clone();
    padded.resize(131_072, b' ');
    verify_chunk_frame_bytes(&a, &padded).unwrap();
    padded.push(b' ');
    assert_eq!(
        verify_chunk_frame_bytes(&a, &padded).unwrap_err(),
        CheckpointError::LimitExceeded
    );
    let mut m = load(M);
    for c in m["components"].as_array_mut().unwrap() {
        c["byte_length"] = json!(1);
    }
    let a = raw_binding(m, &[0]);
    for text in ["AB==", "AA=", "AA===", "AA==\n", "_A=="] {
        let mut f = frame(&a, 0, &[0]);
        f["data_b64"] = json!(text);
        assert!(verify_chunk_frame_bytes(&a, &canon(&f)).is_err(), "{text}");
    }
    let mut bytes = vec![b'a'; 65_536];
    bytes.push(b'b');
    let a = raw_binding(load(M), &bytes);
    for (i, b) in bytes.chunks(65_536).enumerate() {
        let c = verify_chunk_frame_bytes(&a, &canon(&frame(&a, i, b))).unwrap();
        assert_eq!(c.encrypted_bytes(), b);
        assert_eq!(c.index(), i);
    }
    let mut reversed = vec![b'b'];
    reversed.extend_from_slice(&bytes[..65_536]);
    assert_eq!(
        verify_payload_bytes(&a, &reversed).unwrap_err(),
        CheckpointError::IntegrityMismatch
    );
}
#[test]
fn exact_16_mib_raw_payload_limit() {
    let mut bytes = P.to_vec();
    bytes.resize(16_777_216, b' ');
    let a = raw_binding(load(M), &bytes);
    verify_payload_bytes(&a, &bytes).unwrap();
    bytes.push(b' ');
    assert_eq!(
        verify_payload_bytes(&a, &bytes).unwrap_err(),
        CheckpointError::IntegrityMismatch
    );
}
#[test]
fn magic_objects_floats_malformed_m1_targets_and_false_roles_remain_only_candidates() {
    let mut p = load(P);
    let mut m = load(M);
    p["components"][2]["data"]["records"][0]["record"]["ops"][0]["legacy"] = json!({"$serde_json::private::Number":"not-json","$serde_json::private::RawValue":"null","finite":[1.0,-0.0,1e-7]});
    p["components"][1]["data"]["document"]["legacy"] =
        json!({"$serde_json::private::Number":"not-json"});
    p["components"][1]["data"]["document"]["members"] = json!({"self-claimed":{"role":"admin"}});
    repair_records(&mut m, &mut p);
    let (a, raw) = binding(m, &p);
    let payload = verify_payload_bytes(&a, &raw).unwrap();
    let c = load(
        &candidate_provenance(&a, &payload)
            .unwrap()
            .canonical_json()
            .unwrap(),
    );
    assert_eq!(c["stage"], "integrity_checked_not_admitted");
    let mut p = load(include_bytes!(
        "fixtures/team_checkpoint_v1/variants/deleted-empty/payload.json"
    ));
    let mut m = load(include_bytes!(
        "fixtures/team_checkpoint_v1/variants/deleted-empty/manifest.json"
    ));
    p["components"][3]["data"]["records"][0]["record"]["target"] =
        json!({"malformed_m1_target":true,"legacy":{"$serde_json::private::Number":"not-json"}});
    repair_facts(&mut m, &mut p);
    let (a, raw) = binding(m, &p);
    let payload = verify_payload_bytes(&a, &raw).unwrap();
    assert_eq!(payload.candidate_tombstone_fact_hashes().len(), 1);
}

#[test]
fn exact_huge_headers_hlc_and_original_numeric_record_hashes() {
    let mut p = load(P);
    let mut m = load(M);
    let numeric_commit = load(include_bytes!(
        "fixtures/team_checkpoint_v1/numeric-records/commit.signed.canon"
    ));
    let numeric_fact = load(include_bytes!(
        "fixtures/team_checkpoint_v1/numeric-records/fact.signed.canon"
    ));
    let hash = "0e7ee5b295f506164743ede63700b1f220b7d09309e12a1b205aacec37c4b9af";
    let fact_hash = "f43b3bd3357a62fd8e17b569567d0065b146fb3b4ac3c1f9935a37e5d234e031";
    assert_eq!(sha(&canon(&numeric_commit)), hash);
    assert_eq!(sha(&canon(&numeric_fact)), fact_hash);
    let author = numeric_commit["author"].as_str().unwrap().to_owned();
    let seq = load(b"1844674407370955161600000000000000000001");
    m["vector"][&author] = seq.clone();
    p["components"][1]["data"]["vector"][&author] = seq.clone();
    for head in m["heads"].as_array_mut().unwrap() {
        if head["author"] == author {
            head["author_seq"] = seq.clone();
            head["commit_hash"] = json!(hash);
            head["hlc"] = json!({"wall_ms":load(b"9007199254740993"),"counter":seq});
        }
    }
    p["components"][2]["data"]["records"]
        .as_array_mut()
        .unwrap()
        .push(json!({"hash":hash,"record":numeric_commit}));
    p["components"][2]["data"]["records"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["hash"].as_str().cmp(&b["hash"].as_str()));
    p["components"][3]["data"]["records"] = json!([{"hash":fact_hash,"record":numeric_fact}]);
    m["counts"]["commits"] = json!(6);
    m["components"][2]["item_count"] = json!(6);
    m["counts"]["facts"] = json!(1);
    m["components"][3]["item_count"] = json!(1);
    repair_facts(&mut m, &mut p);
    let (a, raw) = binding(m, &p);
    let proof = verify_payload_bytes(&a, &raw).unwrap();
    assert!(proof.canonical_commit_hashes().iter().any(|h| h == hash));
    assert_eq!(proof.candidate_fact_hashes(), &[fact_hash.to_owned()]);
    assert_eq!(
        canon(&a.signed_metadata()["vector"][&author]),
        b"1844674407370955161600000000000000000001"
    );
    assert_eq!(
        canon(&a.signed_metadata()["heads"][0]["hlc"]["wall_ms"]),
        b"9007199254740993"
    );
}
#[test]
fn full_verifier_total_depth_64_65_and_post_parse_helpers_on_256_kib_stack() {
    let mut p = load(P);
    let mut m = load(M);
    let mut legacy = json!("deep-sensitive-marker");
    for _ in 0..55 {
        legacy = Value::Array(vec![legacy]);
    }
    p["components"][2]["data"]["records"][0]["record"]["ops"][0]["legacy"] = legacy;
    repair_records(&mut m, &mut p);
    let (a, raw) = binding(m, &p);
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            let proof = verify_payload_bytes(&a, &raw).unwrap();
            let candidate = candidate_provenance(&a, &proof).unwrap();
            assert!(!candidate.canonical_json().unwrap().is_empty());
            drop(proof);
            drop(candidate);
        })
        .unwrap()
        .join()
        .unwrap();
    let record = p["components"][2]["data"]["records"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e["record"]["ops"][0].get("legacy").is_some())
        .unwrap();
    let legacy = &mut record["record"]["ops"][0]["legacy"];
    *legacy = Value::Array(vec![legacy.take()]);
    let (a, raw) = binding(load(M), &p);
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            assert_eq!(
                verify_payload_bytes(&a, &raw).unwrap_err(),
                CheckpointError::LimitExceeded
            );
        })
        .unwrap()
        .join()
        .unwrap();
}
#[test]
fn reattested_original_header_tokens_and_unique_author_sequences() {
    let payload = String::from_utf8(P.to_vec()).unwrap();
    let component = include_str!("fixtures/team_checkpoint_v1/components/commits.json");
    for token in ["true", "\"1\"", "1.0", "1e0", "-0", "-1"] {
        let changed =
            component.replacen("\"author_seq\":1,", &format!("\"author_seq\":{token},"), 1);
        assert_ne!(changed, component);
        let raw = payload.replacen(component, &changed, 1);
        let mut m = load(M);
        m["components"][2]["byte_length"] = json!(changed.len());
        m["components"][2]["sha256"] = json!(sha(changed.as_bytes()));
        let a = raw_binding(m, raw.as_bytes());
        assert!(verify_payload_bytes(&a, raw.as_bytes()).is_err(), "{token}");
    }
    let mut p = load(P);
    let mut m = load(M);
    let records = p["components"][2]["data"]["records"]
        .as_array_mut()
        .unwrap();
    let mut duplicate = records[0].clone();
    duplicate["record"]["sig"] = json!("deliberately-distinct-canonical-record");
    records.push(duplicate);
    m["counts"]["commits"] = json!(6);
    m["components"][2]["item_count"] = json!(6);
    repair_records(&mut m, &mut p);
    let (a, raw) = binding(m, &p);
    assert_eq!(
        verify_payload_bytes(&a, &raw).unwrap_err(),
        CheckpointError::StructureInvalid
    );
}

#[test]
fn complete_distinct_fact_sets_and_sorted_reference_collections() {
    let mut p = load(include_bytes!(
        "fixtures/team_checkpoint_v1/variants/deleted-retained/payload.json"
    ));
    let mut m = load(include_bytes!(
        "fixtures/team_checkpoint_v1/variants/deleted-retained/manifest.json"
    ));
    let mut second = p["components"][3]["data"]["records"][0].clone();
    second["record"]["hlc"] = json!("8001-0000");
    second["record"]["sig"] = json!("unverified-original-signature-candidate");
    p["components"][3]["data"]["records"]
        .as_array_mut()
        .unwrap()
        .push(second);
    m["counts"]["facts"] = json!(2);
    m["components"][3]["item_count"] = json!(2);
    repair_facts(&mut m, &mut p);
    let (a, raw) = binding(m.clone(), &p);
    let proof = verify_payload_bytes(&a, &raw).unwrap();
    assert_eq!(proof.candidate_fact_hashes().len(), 2);
    assert_eq!(proof.candidate_tombstone_fact_hashes().len(), 2);
    p["components"][3]["data"]["records"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let (a, raw) = binding(m, &p);
    assert_eq!(
        verify_payload_bytes(&a, &raw).unwrap_err(),
        CheckpointError::StructureInvalid
    );
    for mode in 0..5 {
        let mut m = load(M);
        let mut p = load(P);
        match mode {
            0 => {
                p["components"][2]["data"]["authority_commit_hashes"]
                    .as_array_mut()
                    .unwrap()
                    .reverse();
            }
            1 => {
                let entry = p["components"][5]["data"]["entries"][0].clone();
                p["components"][5]["data"]["entries"]
                    .as_array_mut()
                    .unwrap()
                    .push(entry);
                m["counts"]["recipient_wraps"] = json!(2);
                m["components"][5]["item_count"] = json!(2);
            }
            2 => {
                p["components"][4]["data"]["self_placed"] = json!([m["recipient"], m["signer"]]);
            }
            3 => {
                p["components"][4]["data"]["self_placed"] = json!([m["signer"]]);
                p["components"][4]["data"]["pending"] = json!([[0, 0, m["signer"]]]);
            }
            _ => {
                let unknown = "a".repeat(26);
                m["vector"][&unknown] = json!(0);
                p["components"][1]["data"]["vector"][&unknown] = json!(0);
            }
        }
        let (a, raw) = binding(m, &p);
        assert_eq!(
            verify_payload_bytes(&a, &raw).unwrap_err(),
            CheckpointError::StructureInvalid,
            "{mode}"
        );
    }
}

#[test]
fn original_wrap_selectors_and_opaque_ciphertext_integrity() {
    for operation in ["env.init", "dek.rotate", "secret.activate"] {
        let mut p = load(P);
        let mut m = load(M);
        let recipient = m["recipient"].as_str().unwrap().to_owned();
        let source = p["components"][5]["data"]["entries"][0]["source_commit_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        let wrap = p["components"][5]["data"]["entries"][0]["wrap"].clone();
        let record = p["components"][2]["data"]["records"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["hash"] == source)
            .unwrap();
        record["record"]["ops"][0] =
            json!({"op":operation,"generation_id":"a".repeat(16),"wraps":{recipient:wrap}});
        repair_records(&mut m, &mut p);
        let (a, raw) = binding(m, &p);
        assert_eq!(
            verify_payload_bytes(&a, &raw).is_ok(),
            operation != "secret.activate",
            "selector {operation}"
        );
    }
    let a = attestation(load(M));
    for mode in 0..3 {
        let mut p = load(P);
        // The original hashes must reject a ciphertext, version-ID or original
        // version-order mutation before any semantic interpretation.
        match mode {
            0 => {
                p["components"][1]["data"]["document"]["secrets"]["retained-secret"]["versions"]
                    ["b".repeat(16)]["ciphertext"] = json!("changed")
            }
            1 => {
                let versions = p["components"][1]["data"]["document"]["secrets"]["retained-secret"]
                    ["versions"]
                    .as_object_mut()
                    .unwrap();
                let version = versions.remove(&"b".repeat(16)).unwrap();
                versions.insert("d".repeat(16), version);
            }
            _ => p["components"][1]["data"]["version_order"]["retained-secret"]
                .as_array_mut()
                .unwrap()
                .reverse(),
        }
        assert_eq!(
            verify_payload_bytes(&a, &canon(&p)).unwrap_err(),
            CheckpointError::IntegrityMismatch
        );
    }
}
