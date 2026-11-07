#[path = "common/team_checkpoint_semantics.rs"]
mod support;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};
use support::*;
use zeropw::team::{checkpoint::*, commit, envelope, fold, sync, tombstone_gate};

fn fixture(case: &str, name: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/team_checkpoint_semantics_v1")
            .join(case)
            .join(name),
    )
    .unwrap()
}
#[test]
fn deterministic_original_histories_and_literal_oracles() {
    let generate = std::env::var_os("ZEROPW_GENERATE_SEMANTIC_FIXTURES");
    for case in CASES {
        let h = history(case);
        let p = h.package();
        let full = h.full_fold();
        assert!(full.skipped.is_empty(), "{case}: {:?}", full.skipped);
        let originals = json!(h.history.iter().map(|c| c.to_dict()).collect::<Vec<_>>());
        let facts = json!(h.facts.iter().map(|f| f.to_dict()).collect::<Vec<_>>());
        let steps = literal_steps(case);
        let literal=json!(steps.iter().map(|(owner,admins,members)| json!({"owner":h.fps[*owner],"active_admins":admins.iter().map(|i|&h.fps[*i]).collect::<Vec<_>>(),"active_members":members.iter().map(|i|&h.fps[*i]).collect::<Vec<_>>(),"skipped":[]})).collect::<Vec<_>>());
        let mut hashes: Vec<_> = h.facts.iter().map(|f| f.hash().unwrap()).collect();
        hashes.sort();
        let mut tombstones: Vec<_> = h
            .facts
            .iter()
            .filter(|f| f.kind == "secret_deleted")
            .map(|f| f.hash().unwrap())
            .collect();
        tombstones.sort();
        let expected = json!({"case":case,"independent_signer_pin":h.records[h.signer].to_dict(),"full_document":full.document,"version_order":full.version_order,"literal_skipped":[],"original_commit_hashes":h.history.iter().map(|c|c.hash().unwrap()).collect::<Vec<_>>(),"original_fact_hashes":hashes,"original_tombstone_hashes":tombstones,"literal_tombstone_digest":sha(&canon(&json!(tombstones))),"retained_original_indices":h.retained});
        let files = [
            ("history.canon", canon(&originals)),
            ("facts.canon", canon(&facts)),
            ("literal-trace.json", canon(&literal)),
            ("expected.json", canon(&expected)),
            ("manifest.json", canon(&p.manifest)),
            ("payload.json", canon(&p.payload)),
        ];
        let mut files: Vec<(String, Vec<u8>)> =
            files.into_iter().map(|(n, b)| (n.to_owned(), b)).collect();
        for (i, c) in h.history.iter().enumerate() {
            files.push((
                format!("commit-{i:03}.signed.canon"),
                c.canonical_json(true).unwrap(),
            ));
            files.push((
                format!("commit-{i:03}.unsigned.canon"),
                c.canonical_json(false).unwrap(),
            ));
        }
        for (i, f) in h.facts.iter().enumerate() {
            files.push((
                format!("fact-{i:03}.signed.canon"),
                f.canonical_json(true).unwrap(),
            ));
            files.push((
                format!("fact-{i:03}.unsigned.canon"),
                f.canonical_json(false).unwrap(),
            ));
        }
        if let Some(root) = &generate {
            let root = Path::new(root).join(case);
            fs::create_dir_all(&root).unwrap();
            for (name, bytes) in &files {
                fs::write(root.join(name), bytes).unwrap();
            }
        } else {
            for (name, bytes) in &files {
                assert_eq!(*bytes, fixture(case, name), "{case}/{name}");
            }
        }
        // Independent primitive checks on the complete, uncompacted originals.
        for c in &h.history {
            assert!(commit::verify_commit(
                c,
                &h.records[h.fps.iter().position(|f| f == &c.author).unwrap()]
            ));
        }
        for f in &h.facts {
            assert!(sync::verify_fact(
                f,
                &h.records[h.fps.iter().position(|fp| fp == &f.author).unwrap()]
            ));
        }
        let mut op_count = 0;
        for end in 1..=h.history.len() {
            op_count += h.history[end - 1].ops.len();
            let ordinary =
                fold::fold(&h.env, h.history[..end].to_vec(), None, None, None, None).unwrap();
            assert!(ordinary.skipped.is_empty());
            let (owner, admins, members) = &steps[op_count - 1];
            assert_eq!(ordinary.document["owner"], h.fps[*owner]);
            let actual_members: Vec<_> = h
                .fps
                .iter()
                .enumerate()
                .filter(|(_, fp)| ordinary.document["members"][fp.as_str()]["status"] == "active")
                .map(|(i, _)| i)
                .collect();
            let actual_admins: Vec<_> = h
                .fps
                .iter()
                .enumerate()
                .filter(|(_, fp)| sync::is_admin(&ordinary.document, fp))
                .map(|(i, _)| i)
                .collect();
            assert_eq!(&actual_members, members, "{case} complete prefix {end}");
            assert_eq!(&actual_admins, admins, "{case} prefix {end}");
        }
        let maps: BTreeMap<String, Value> = h
            .facts
            .iter()
            .filter(|f| f.kind == "secret_deleted")
            .map(|f| (f.hash().unwrap(), f.to_dict()))
            .collect();
        assert_eq!(
            tombstone_gate::digest(&maps).unwrap(),
            expected["literal_tombstone_digest"]
        );
        let m = p.attestation(&h);
        let raw = canon(&p.payload);
        let checked = verify_payload_bytes(&m, &raw).unwrap();
        let local = h.local(&m);
        let candidate = verify_retained_authority(&m, &checked, &local).unwrap();
        let projection = json!({"owner":full.document["owner"],"members":full.document["members"],"dek":full.document["dek"]});
        assert_eq!(
            candidate.authority_projection_sha256(),
            sha(&canon(&projection))
        );
        assert_eq!(
            candidate.tombstone_digest(),
            expected["literal_tombstone_digest"]
        );
        assert_eq!(candidate.original_fact_count(), h.facts.len());
        for hash in hashes {
            assert!(candidate.contains_original_fact_hash(&hash));
            assert_eq!(
                candidate.fact_basis(&hash),
                Some("administrator_attested_historical")
            );
        }
        if case == "P5" {
            let a = h.f(
                1,
                "secret_deleted",
                json!({"secret_id":"deleted-empty"}),
                8000,
            );
            let mut p = h.package();
            p.payload["components"][3]["data"]["records"] =
                json!([{"hash":a.hash().unwrap(),"record":a.to_dict()}]);
            p.repair_facts();
            p.rebind(&h.keys[h.signer]);
            let m = p.attestation(&h);
            let bytes = canon(&p.payload);
            let payload = verify_payload_bytes(&m, &bytes).unwrap();
            let l = h.local(&m);
            let c = verify_retained_authority(&m, &payload, &l).unwrap();
            let interval = c.fact_role_interval(&a.hash().unwrap()).unwrap();
            assert_eq!(interval.start(), (h.history[2].hash().unwrap().as_str(), 0));
            assert_eq!(
                interval.end(),
                Some((h.history[4].hash().unwrap().as_str(), 1))
            );
            assert!(interval.requires_admin());
        }
    }
}

#[test]
fn complete_uncompacted_fold_version_order_and_m1_irreversible_overlay() {
    for case in ["P1", "P2", "P3", "P6-empty", "P6-nonempty"] {
        let h = history(case);
        let ordinary = h.full_fold();
        assert_eq!(ordinary.version_order[SECRET], json!([V1, V2]));
        assert_eq!(ordinary.document["secrets"][SECRET]["active_version"], V2);
        for (i, nonce, version, value) in [
            (3, 7, V1, b"synthetic-checkpoint-v1".as_slice()),
            (4, 8, V2, b"synthetic-checkpoint-v2".as_slice()),
        ] {
            assert_eq!(
                h.history[i].ops[0]["ciphertext"],
                ciphertext(&h.env, version, nonce, value)
            );
            assert_eq!(
                envelope::decrypt_secret(
                    &[6; 32],
                    &h.env,
                    SECRET,
                    version,
                    h.history[i].ops[0]["ciphertext"].as_object().unwrap()
                )
                .unwrap(),
                value
            );
        }
        let mut effects = fold::Facts::default();
        // Independent literal original-set oracle, not candidate output.
        for f in &h.facts {
            match f.kind.as_str() {
                "secret_deleted" => {
                    effects
                        .deleted_secrets
                        .insert(f.target["secret_id"].as_str().unwrap().into());
                    effects
                        .tombstone_facts
                        .insert(f.hash().unwrap(), f.to_dict());
                }
                "secret_version_revoked" => {
                    effects.revoked_versions.insert((SECRET.into(), V1.into()));
                }
                _ => unreachable!(),
            }
        }
        let final_fold =
            fold::fold(&h.env, h.history.clone(), Some(&effects), None, None, None).unwrap();
        if case == "P2" || case == "P6-nonempty" {
            assert_eq!(effects.tombstone_facts.len(), 3);
            assert_eq!(effects.deleted_secrets.len(), 2);
            assert_eq!(final_fold.document["secrets"][SECRET]["deleted"], true);
            assert!(final_fold.document["secrets"][SECRET]["active_version"].is_null());
            assert!(
                !final_fold.document["secrets"]
                    .as_object()
                    .unwrap()
                    .contains_key("deleted-empty")
            );
            assert_eq!(final_fold.version_order, ordinary.version_order);
        }
    }
}

#[test]
fn deterministic_input_permutations_preserve_every_original_hash() {
    for case in ["P2", "P3", "P4", "P6-empty", "P6-nonempty"] {
        let mut h = history(case);
        let expected = h.package();
        h.facts.reverse();
        h.retained.reverse();
        h.table.reverse();
        let p = h.package();
        assert_eq!(canon(&p.payload), canon(&expected.payload));
        assert_eq!(canon(&p.manifest), canon(&expected.manifest));
        let m = p.attestation(&h);
        let raw = canon(&p.payload);
        let payload = verify_payload_bytes(&m, &raw).unwrap();
        let local = h.local(&m);
        let a = verify_retained_authority(&m, &payload, &local).unwrap();
        let b = verify_retained_authority(&m, &payload, &local).unwrap();
        assert_eq!(a.tombstone_digest(), b.tombstone_digest());
        assert_eq!(a.manifest_hash(), b.manifest_hash());
        for f in &h.facts {
            assert!(a.contains_original_fact_hash(&f.hash().unwrap()));
        }
    }
}
