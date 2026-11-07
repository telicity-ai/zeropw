//! Literal, primitive, original-signature and ordinary-fold oracles.
#[path = "common/team_checkpoint_required_generations.rs"]
mod support;
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path};
use support::*;
use zeropw::team::{checkpoint::*, commit, envelope, fold};

fn independent(c: &Case, p: &Package, final_doc: &Value, order: &Value) {
    let h = &c.h;
    let (literal_document, literal_order) = c.literal_document();
    assert_eq!(canon(&literal_document), canon(final_doc));
    assert_eq!(canon(&literal_order), canon(order));
    for original in &h.history {
        let who = h.fps.iter().position(|fp| fp == &original.author).unwrap();
        assert!(commit::verify_commit(original, &h.records[who]));
    }
    let effects = legacy::ordinary_effects(h);
    let ordinary = fold::fold(&h.env, h.history.clone(), Some(&effects), None, None, None).unwrap();
    assert_eq!(canon(&ordinary.document), canon(final_doc));
    assert_eq!(canon(&ordinary.version_order), canon(order));
    let expected_keys: BTreeSet<_> = c.required().iter().map(|v| v.generation.as_str()).collect();
    let mut actual_keys = BTreeSet::new();
    let mut actual_versions = BTreeSet::new();
    for (sid, s) in final_doc["secrets"].as_object().unwrap() {
        for (vid, v) in s["versions"].as_object().unwrap() {
            if s["deleted"] != true && matches!(v["status"].as_str(), Some("active" | "staged")) {
                actual_keys.insert(v["generation"].as_str().unwrap());
                actual_versions.insert((
                    sid.as_str(),
                    vid.as_str(),
                    v["generation"].as_str().unwrap(),
                ));
            }
        }
    }
    let literal_versions: BTreeSet<_> = c
        .required()
        .iter()
        .map(|v| (v.sid.as_str(), v.vid.as_str(), v.generation.as_str()))
        .collect();
    assert_eq!(actual_keys, expected_keys);
    assert_eq!(actual_versions, literal_versions);
    for v in &c.literal {
        let s = &final_doc["secrets"][&v.sid];
        let entry = &s["versions"][&v.vid];
        assert_eq!(s["kind"], v.kind);
        assert_eq!(s["deleted"] == true, v.deleted);
        assert_eq!(entry["status"], v.status);
        assert_eq!(entry["generation"], v.generation);
        let plaintext = envelope::decrypt_secret(
            &dek(&v.generation),
            &h.env,
            &v.sid,
            &v.vid,
            entry.as_object().unwrap(),
        )
        .unwrap();
        assert!(
            plaintext == v.plaintext,
            "literal synthetic byte oracle differs"
        );
    }
    let entries = p.payload["components"][5]["data"]["entries"]
        .as_array()
        .unwrap();
    // Hand-authored source positions, independent of the new stage and final
    // DEK lookup. Normal prior-generation admission is commit4/op0. Removal
    // has commit3/op0 admission and commit5/op0 rotation.
    let mut positions = if h.name == "G08-removal" {
        vec![(G1, 3usize, 0usize), (G2, 5, 0)]
    } else {
        vec![(G1, 4, 0), (G2, 4, 0), (G3, 4, 0)]
    };
    if h.name == "G03-selected-history" {
        positions.push((G1, 0, 0));
    }
    let actual: BTreeSet<_> = entries
        .iter()
        .map(|e| {
            (
                e["generation_id"].as_str().unwrap().to_owned(),
                e["source_commit_hash"].as_str().unwrap().to_owned(),
                e["source_op_index"].as_u64().unwrap() as usize,
            )
        })
        .collect();
    let wanted: BTreeSet<_> = positions
        .iter()
        .map(|(g, i, o)| (g.to_string(), h.history[*i].hash().unwrap(), *o))
        .collect();
    assert_eq!(actual, wanted);
    for e in entries {
        let g = e["generation_id"].as_str().unwrap();
        let key = envelope::unwrap_dek(&e["wrap"], &h.env, g, &h.keys[2]).unwrap();
        assert!(key == dek(g), "literal synthetic DEK oracle differs");
    }
    let m = p.attestation(h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).unwrap();
    let local = h.local(&m);
    let candidate = verify_complete_cut_semantics(&m, &payload, &local).unwrap();
    assert_eq!(
        candidate.recomputed_final_document_sha256(),
        sha(&canon(final_doc))
    );
    let result = verify_required_generations(&candidate, &h.keys[2]).unwrap();
    assert_eq!(result.required_generation_count(), expected_keys.len());
    assert_eq!(result.checked_ciphertext_count(), c.required().len());
}
#[test]
fn all_eight_cases_match_literal_crypto_and_ordinary_fold_oracles() {
    for name in CASES {
        let c = build(name);
        let (p, doc, order) = c.package();
        independent(&c, &p, &doc, &order);
    }
}
#[test]
fn frozen_catalog_and_every_original_canonical_byte_remain_bound() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/team_checkpoint_required_generations_v1");
    let sums = std::fs::read_to_string(root.join("SHA256SUMS")).unwrap();
    assert_eq!(sums.lines().count(), 57);
    for line in sums.lines() {
        let (h, n) = line.split_once("  ").unwrap();
        assert_eq!(sha(&std::fs::read(root.join(n)).unwrap()), h);
    }
    for name in CASES {
        let c = build(name);
        let (p, doc, order) = c.package();
        let dir = root.join(name);
        for (file, value) in [
            (
                "history.canon",
                json!(c.h.history.iter().map(|c| c.to_dict()).collect::<Vec<_>>()),
            ),
            (
                "facts.canon",
                json!(c.h.facts.iter().map(|f| f.to_dict()).collect::<Vec<_>>()),
            ),
            ("payload.json", p.payload.clone()),
            ("manifest.json", p.manifest.clone()),
            ("expected-final.canon", doc.clone()),
            ("expected.json", c.expectation(&p, &doc)),
            ("crypto-oracle.json", c.crypto_oracle(&p)),
        ] {
            assert_eq!(
                std::fs::read(dir.join(file)).unwrap(),
                canon(&value),
                "{name}/{file}"
            );
        }
        independent(&c, &p, &doc, &order);
    }
}
#[test]
fn legacy_hkdf_boundaries_lenient_base64_and_aad_assurance_are_preserved() {
    let prk = envelope::hkdf_extract(b"salt", b"ikm");
    assert_eq!(
        envelope::hkdf_expand(&prk, b"info", 0).unwrap(),
        Vec::<u8>::new()
    );
    let maximum = envelope::hkdf_expand(&prk, b"info", 8160).unwrap();
    assert_eq!(maximum.len(), 8160);
    // Independent RFC5869 expansion using the existing HMAC primitive, not the
    // changed expansion routine, across block/tail/maximum boundaries.
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    for n in [0usize, 1, 31, 32, 33, 42, 8159, 8160] {
        let mut previous = Vec::new();
        let mut literal = Vec::new();
        for counter in 1..=n.div_ceil(32) {
            let mut m = Hmac::<Sha256>::new_from_slice(&prk).unwrap();
            m.update(&previous);
            m.update(b"info");
            m.update(&[counter as u8]);
            previous = m.finalize().into_bytes().to_vec();
            literal.extend_from_slice(&previous);
        }
        literal.truncate(n);
        assert_eq!(envelope::hkdf_expand(&prk, b"info", n).unwrap(), literal);
    }
    let err = envelope::hkdf_expand(&prk, b"info", 8161).unwrap_err();
    assert_eq!(err.reason, "hkdf_length_too_large");
    let mut c = build("G01-multiple");
    change_op(&mut c.h, 4, 0, |op| {
        for value in op["wraps"][G1].as_object_mut().unwrap().values_mut() {
            *value = json!(format!(" \n!{}!?", value.as_str().unwrap()));
        }
    });
    let (p, _, _) = c.package();
    assert_eq!(check(&c, &p, &c.h.keys[2]).unwrap(), (2, 4));
    let entry = cipher(&c.h.env, "same", V1, SENTINEL, &dek(G1), 7);
    assert!(
        envelope::decrypt_secret(&dek(G1), &c.h.env, "same", V1, entry.as_object().unwrap())
            .is_ok()
    );
    assert!(
        envelope::decrypt_secret(&dek(G2), &c.h.env, "same", V1, entry.as_object().unwrap())
            .is_err()
    );
    // Kind/generation are signed semantic associations; secret AAD does not
    // distinguish identical DEK bytes labeled with different generations.
    assert!(
        envelope::decrypt_secret(&dek(G1), &c.h.env, "same", V1, entry.as_object().unwrap())
            .is_ok()
    );
}
#[test]
fn authenticated_malformed_ssh_is_not_signing_ready_and_arbitrary_bytes_are_allowed() {
    let c = build("G06-byte-kinds");
    let (p, _, _) = c.package();
    assert_eq!(check(&c, &p, &c.h.keys[2]).unwrap(), (2, 6));
    let valid = c.literal.iter().find(|v| v.sid == "ssh-valid").unwrap();
    assert!(zeropw::sshwire::parse_openssh_private_key(&valid.plaintext).is_ok());
    let malformed = c.literal.iter().find(|v| v.sid == "ssh-malformed").unwrap();
    assert!(zeropw::sshwire::parse_openssh_private_key(&malformed.plaintext).is_err());
    assert!(c.literal.iter().any(|v| v.plaintext.is_empty()));
    assert!(
        c.literal
            .iter()
            .any(|v| std::str::from_utf8(&v.plaintext).is_err())
    );
}
#[test]
fn original_fixture_catalogues_are_still_145_149_97_exact_entries() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (name, count) in [
        ("team_checkpoint_v1", 145),
        ("team_checkpoint_semantics_v1", 149),
        ("team_checkpoint_m2b2_v1", 97),
    ] {
        let dir = root.join(name);
        let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
        assert_eq!(sums.lines().count(), count);
        for l in sums.lines() {
            let (h, n) = l.split_once("  ").unwrap();
            assert_eq!(sha(&std::fs::read(dir.join(n)).unwrap()), h);
        }
    }
}
#[test]
#[ignore = "explicit synthetic fixture generation only in assigned isolation"]
fn generate_required_generation_fixtures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/team_checkpoint_required_generations_v1");
    std::fs::create_dir_all(&root).unwrap();
    let readme=b"# Required-generation v1 synthetic fixtures\n\nGenerated only in assigned Mac501 isolation. Eight finite cases independently check literal status/required inventories, exact original source positions, primitive DEK/plaintext bytes and ordinary complete folds before freezing. crypto-oracle.json intentionally contains synthetic keys and values. It is not a runtime output surface. The new stage authenticates retrieval bytes only, with no provider/SSH readiness, freshness, installation or runtime acceptance. Unselected history is not cryptographically assessed; identical DEKs under distinct generation labels share the unchanged secret AAD limitation. Linux NOTRUN; full M2/reviews/release OPEN.\n";
    std::fs::write(root.join("README.md"), readme).unwrap();
    let mut names = vec!["README.md".to_string()];
    for name in CASES {
        let c = build(name);
        let (p, doc, order) = c.package();
        independent(&c, &p, &doc, &order);
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        for (file, value) in [
            (
                "history.canon",
                json!(c.h.history.iter().map(|c| c.to_dict()).collect::<Vec<_>>()),
            ),
            (
                "facts.canon",
                json!(c.h.facts.iter().map(|f| f.to_dict()).collect::<Vec<_>>()),
            ),
            ("payload.json", p.payload.clone()),
            ("manifest.json", p.manifest.clone()),
            ("expected-final.canon", doc.clone()),
            ("expected.json", c.expectation(&p, &doc)),
            ("crypto-oracle.json", c.crypto_oracle(&p)),
        ] {
            std::fs::write(dir.join(file), canon(&value)).unwrap();
            names.push(format!("{name}/{file}"));
        }
    }
    use std::os::unix::fs::PermissionsExt;
    names.sort();
    let mut sums = String::new();
    for n in &names {
        let path = root.join(n);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        sums.push_str(&format!("{}  {n}\n", sha(&std::fs::read(path).unwrap())));
    }
    std::fs::write(root.join("SHA256SUMS"), sums).unwrap();
    std::fs::set_permissions(
        root.join("SHA256SUMS"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
}

#[test]
fn identical_deks_under_distinct_labels_keep_secret_aad_limit_and_original_wrap_requirement() {
    let mut c = build("G01-multiple");
    let replacement = wrap_bytes(&c.h.env, G2, &c.h.records[2], &dek(G1), 120);
    change_op(&mut c.h, 4, 0, |op| op["wraps"][G2] = replacement);
    for slot in [7usize, 8] {
        let op = &c.h.history[5].ops[slot];
        let sid = op["secret_id"].as_str().unwrap().to_owned();
        let v = c
            .literal
            .iter()
            .find(|v| v.sid == sid)
            .unwrap()
            .plaintext
            .clone();
        let encrypted = cipher(&c.h.env, &sid, V1, &v, &dek(G1), 120);
        change_op(&mut c.h, 5, slot, |op| op["ciphertext"] = encrypted);
    }
    let (mut p, _, _) = c.package();
    assert_eq!(check(&c, &p, &c.h.keys[2]).unwrap(), (2, 4));
    omit(&mut p, &[G2], false, &c.h);
    assert_eq!(
        check(&c, &p, &c.h.keys[2]).unwrap_err(),
        SemanticError::GenerationUnavailable
    );
}
