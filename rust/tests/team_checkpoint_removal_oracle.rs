#[path = "common/team_checkpoint_m2b2.rs"]
mod support;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};
use support::*;
use zeropw::team::{checkpoint::*, commit, fold, sync, tombstone_gate};

fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/team_checkpoint_m2b2_v1")
}

// Literal state specification, independently authored here. Neither the data
// builder, new candidate nor ordinary fold generates this expected document.
fn literal_document(h: &History, final_image: bool) -> Value {
    let case = h.name.as_str();
    let removal = case.starts_with('R') || case.starts_with("N01") || case.starts_with("N02");
    let has_d = removal || case == "C03-historical";
    let new_owner = case == "C02-owner";
    let mut doc = json!({"format":"zeropw-team-env-v1","env_id":h.env,"owner":h.fps[if new_owner {1}else{0}],"members":{},"dek":{"current":G,"generations":{G:{"wraps":{}}}},"secrets":{},"connections":{},"settings":{"sync_interval_seconds":if has_d {11}else if case=="N03-same-commit" {12}else{10}}});
    for i in if has_d {
        vec![0, 1, 2, 3]
    } else {
        vec![0, 1, 2]
    } {
        let removed = (i == 3
            && (case == "C03-historical" || (removal && (final_image || case != "R04-pending"))))
            || (i == 1 && (case == "N01-reciprocal" || case == "N02-cycle"))
            || (i == 2 && case == "N02-cycle");
        let role = if (i == 0 && new_owner)
            || (i == 1 && case == "N03-same-commit")
            || (i == 2 && case != "N02-cycle")
        {
            "user"
        } else {
            "admin"
        };
        doc["members"][&h.fps[i]] = json!({"name":(["owner","admin","recipient","former"][i]),"role":role,"status":if removed {"removed"}else{"active"},"device":h.records[i].to_dict()});
        doc["dek"]["generations"][G]["wraps"][&h.fps[i]] =
            wrap(&h.env, &h.records[i], (9 + i) as u8, (12 + i) as u8);
    }
    if matches!(case, "R01-other" | "R02-multiple" | "R04-pending") {
        for (generation, author) in if case == "R02-multiple" {
            vec![(G2, 1), (G3, 0)]
        } else {
            vec![(G2, 1)]
        } {
            let fact = h
                .facts
                .iter()
                .find(|f| f.kind == "member_removed" && f.author == h.fps[author])
                .unwrap();
            let mut wraps = serde_json::Map::new();
            for i in [0, 1, 2] {
                wraps.insert(
                    h.fps[i].clone(),
                    wrap_for_generation(
                        &h.env,
                        generation,
                        &h.records[i],
                        0x22 + i as u8,
                        0x32 + i as u8,
                    ),
                );
            }
            doc["dek"]["generations"][generation] =
                json!({"wraps":wraps,"removal_fact_hash":fact.hash().unwrap()});
            doc["dek"]["current"] = json!(generation);
        }
    }
    if matches!(
        case,
        "C01-admin" | "C02-owner" | "D01-overlay" | "D02-policy"
    ) {
        let deleted = case == "D01-overlay";
        let mut secret = json!({"kind":"api_key","active_version":if deleted {Value::Null}else{json!(V2)},"versions":{}});
        for (vid, nonce, value) in [
            (V1, 7, b"synthetic-checkpoint-v1".as_slice()),
            (V2, 8, b"synthetic-checkpoint-v2".as_slice()),
        ] {
            let encrypted = ciphertext(&h.env, vid, nonce, value);
            let status = if final_image && (deleted || (case == "C02-owner" && vid == V1)) {
                "revoked"
            } else if vid == V2 && !deleted {
                "active"
            } else if vid == V1 && case == "D02-policy" {
                "retired"
            } else {
                "staged"
            };
            secret["versions"][vid] = json!({"status":status,"generation":G,"nonce":encrypted["nonce"],"ciphertext":encrypted["ciphertext"],"public":{}});
        }
        if final_image && deleted {
            secret["deleted"] = json!(true);
        }
        if case == "D02-policy" {
            for (vid, nonce) in [(V3, 9), (V4, 10)] {
                let encrypted = ciphertext(&h.env, vid, nonce, b"synthetic-policy");
                let public = if vid == V3 {
                    json!({"$serde_json::private::RawValue":"not-json","float":load(b"1.0"),"negative_zero":load(b"-0.0"),"big":load(b"-1844674407370955161600000000000000000001")})
                } else {
                    json!({})
                };
                secret["versions"][vid] = json!({"status":if final_image && vid==V4 {"revoked"}else{"staged"},"generation":G,"nonce":encrypted["nonce"],"ciphertext":encrypted["ciphertext"],"public":public});
            }
            // Literal folded fields, including absent policy objects and real
            // explicit retired pin. No CA file or program is opened.
            for (id, kind, pin, time) in [
                ("api", "http", Value::Null, "1970-01-01T00:00:10Z"),
                ("git", "ssh", json!(V1), "1970-01-01T00:00:11Z"),
            ] {
                let mut c = json!({"id":id,"project":"synthetic","environment":"test","service":"controlled","kind":kind,"secret_id":SECRET,"secret_version":pin,"description":"synthetic policy","status":"active","created_at":time,"updated_at":time,"http_target":null,"http_auth":null,"http_scope":null,"ssh_target":null,"cli":null});
                if kind == "http" {
                    c["http_target"] = json!({"scheme":"https","host":"api.example.com","port":443,"ca_file":null,"allow_private_network":false});
                    c["http_auth"] = json!({"mode":"header","header_name":"X-API-Key","value_prefix":"","basic_username":null});
                    c["http_scope"] =
                        json!({"methods":["GET"],"path_prefixes":["/"],"confirm_methods":[]});
                } else {
                    c["ssh_target"] = json!({"host":"ssh.example.com","port":22,"username":"git","host_keys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]});
                }
                doc["connections"][id] = c;
            }
        }
        doc["secrets"][SECRET] = secret;
    }
    doc
}
fn literal_order(case: &str) -> Value {
    match case {
        "C01-admin" | "C02-owner" | "D01-overlay" => json!({SECRET:[V1,V2]}),
        "D02-policy" => json!({SECRET:[V1,V2,V3,V4]}),
        _ => json!({}),
    }
}
fn literal_schedule(h: &History) -> Value {
    let mut bounds = serde_json::Map::new();
    let mut pending = Vec::new();
    let mut self_placed = Vec::new();
    let mut witnesses = Vec::new();
    match h.name.as_str() {
        "R03-self" => {
            bounds.insert(h.fps[3].clone(), json!(2));
            self_placed.push(h.fps[3].clone());
            witnesses.push(h.history[5].hash().unwrap());
        }
        "R01-other" | "R02-multiple" | "R04-pending" | "N01-reciprocal" | "N02-cycle" => {
            bounds.insert(h.fps[3].clone(), json!(1));
            pending.push(json!([
                if h.name == "R04-pending" { 9000 } else { 5000 },
                0,
                h.fps[3]
            ]));
            witnesses.push(h.history[5].hash().unwrap());
            if h.name == "R02-multiple" {
                witnesses.push(h.history[6].hash().unwrap());
            }
            if h.name == "N01-reciprocal" {
                bounds.insert(h.fps[1].clone(), json!(2));
                pending.push(json!([5500, 0, h.fps[1]]));
                witnesses.push(h.history[6].hash().unwrap());
            }
            if h.name == "N02-cycle" {
                bounds.insert(h.fps[2].clone(), json!(0));
                bounds.insert(h.fps[1].clone(), json!(2));
                pending.extend([json!([5500, 0, h.fps[2]]), json!([5700, 0, h.fps[1]])]);
                witnesses.extend([h.history[7].hash().unwrap(), h.history[8].hash().unwrap()]);
            }
        }
        _ => {}
    }
    self_placed.sort();
    witnesses.sort();
    json!({"bounds":bounds,"pending":pending,"self_placed":self_placed,"witness_commit_hashes":witnesses})
}
// Rows are after each original op, in true total order. The symbols below are
// hand specified; skipped reasons include partial M1 mutations.
fn literal_trace(h: &History) -> Value {
    let base = vec![
        (0, vec![0], vec![0], None),
        (0, vec![0, 1], vec![0, 1], None),
        (0, vec![0, 1], vec![0, 1, 2], None),
    ];
    let mut rows = if h.name.starts_with('R')
        || h.name == "C03-historical"
        || h.name == "N01-reciprocal"
        || h.name == "N02-cycle"
    {
        vec![
            (0, vec![0], vec![0], None),
            (0, vec![0, 1], vec![0, 1], None),
            (0, vec![0, 1, 3], vec![0, 1, 3], None),
            (0, vec![0, 1, 3], vec![0, 1, 2, 3], None),
        ]
    } else if h.name == "N03-same-commit" {
        vec![
            (0, vec![0], vec![0], None),
            (0, vec![0], vec![0, 1], None),
            (0, vec![0, 1], vec![0, 1], None),
            (0, vec![0, 1], vec![0, 1], None),
            (0, vec![0, 1], vec![0, 1, 2], None),
            (0, vec![0, 1], vec![0, 1, 2], None),
            (0, vec![0], vec![0, 1, 2], None),
            (0, vec![0], vec![0, 1, 2], Some("not_admin")),
        ]
    } else {
        base
    };
    match h.name.as_str() {
        "C01-admin" | "C02-owner" | "D02-policy" | "D01-overlay" => {
            let skip = if h.name == "D01-overlay" {
                Some("secret_deleted")
            } else {
                None
            };
            rows.extend([
                (0, vec![0, 1], vec![0, 1, 2], skip),
                (0, vec![0, 1], vec![0, 1, 2], skip),
                (0, vec![0, 1], vec![0, 1, 2], skip),
            ]);
            if h.name == "C02-owner" {
                rows.extend([
                    (1, vec![0, 1], vec![0, 1, 2], None),
                    (1, vec![1], vec![0, 1, 2], None),
                ]);
            }
            if h.name == "D02-policy" {
                rows.extend((0..5).map(|_| (0, vec![0, 1], vec![0, 1, 2], None)));
            }
        }
        "C03-historical" | "R03-self" => rows.extend([
            (0, vec![0, 1, 3], vec![0, 1, 2, 3], None),
            (0, vec![0, 1], vec![0, 1, 2], None),
        ]),
        "R01-other" | "R02-multiple" => {
            rows.extend([
                (0, vec![0, 1, 3], vec![0, 1, 2, 3], None),
                (0, vec![0, 1], vec![0, 1, 2], None),
            ]);
            if h.name == "R02-multiple" {
                rows.push((0, vec![0, 1], vec![0, 1, 2], None));
            }
        }
        "R04-pending" => rows.extend([
            (0, vec![0, 1, 3], vec![0, 1, 2, 3], None),
            (0, vec![0, 1, 3], vec![0, 1, 2, 3], None),
        ]),
        "N01-reciprocal" => rows.extend([
            (0, vec![0, 1, 3], vec![0, 1, 2, 3], None),
            (0, vec![0], vec![0, 2], Some("not_admin")),
            (0, vec![0], vec![0, 2], Some("member_removed")),
        ]),
        "N02-cycle" => rows.extend([
            (0, vec![0, 1, 2, 3], vec![0, 1, 2, 3], None),
            (0, vec![0, 1, 2, 3], vec![0, 1, 2, 3], None),
            (0, vec![0], vec![0], Some("not_admin")),
            (0, vec![0], vec![0], Some("member_removed")),
            (0, vec![0], vec![0], Some("member_removed")),
        ]),
        _ => {}
    }
    let ordered = commit::sort_total_order(h.history.clone()).unwrap();
    let locations: Vec<_> = ordered
        .iter()
        .flat_map(|c| {
            c.ops
                .iter()
                .enumerate()
                .map(move |(i, _)| (c.hash().unwrap(), i))
        })
        .collect();
    assert_eq!(locations.len(), rows.len(), "{}", h.name);
    json!(rows.into_iter().zip(locations).map(|((owner,admins,members,skip),(hash,index))|json!({"hash":hash,"op_index":index,"owner":h.fps[owner],"active_admins":admins.iter().map(|i|&h.fps[*i]).collect::<Vec<_>>(),"active_members":members.iter().map(|i|&h.fps[*i]).collect::<Vec<_>>(),"skipped":skip})).collect::<Vec<_>>())
}

#[test]
fn literal_ordinary_and_original_primitive_oracles() {
    let generate = std::env::var_os("ZEROPW_GENERATE_M2B2A_FIXTURES");
    for case in COMPLETE_CASES {
        let h = complete_history(case);
        let effects = ordinary_effects(&h);
        let ordinary =
            fold::fold(&h.env, h.history.clone(), Some(&effects), None, None, None).unwrap();
        let snapshot = ordinary_snapshot(&h, &effects);
        let before = literal_document(&h, false);
        let after = literal_document(&h, true);
        let order = literal_order(case);
        let schedule = literal_schedule(&h);
        let trace = literal_trace(&h);
        assert_eq!(canon(&ordinary.document), canon(&after), "{case}: final");
        assert_eq!(
            canon(&snapshot.document),
            canon(&before),
            "{case}: unflushed"
        );
        assert_eq!(ordinary.version_order, order, "{case}: order");
        let literal_skips: Vec<_> = trace
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| {
                v["skipped"].as_str().map(|reason| {
                    (
                        v["hash"].as_str().unwrap().to_owned(),
                        v["op_index"].as_u64().unwrap() as usize,
                        reason.to_owned(),
                    )
                })
            })
            .collect();
        assert_eq!(ordinary.skipped, literal_skips, "{case}: skips");
        for c in &h.history {
            assert!(commit::verify_commit(
                c,
                &h.records[h.fps.iter().position(|fp| fp == &c.author).unwrap()]
            ));
        }
        for f in &h.facts {
            assert!(sync::verify_fact(
                f,
                &h.records[h.fps.iter().position(|fp| fp == &f.author).unwrap()]
            ));
        }
        let tombstones: BTreeMap<_, _> = h
            .facts
            .iter()
            .filter(|f| f.kind == "secret_deleted")
            .map(|f| (f.hash().unwrap(), f.to_dict()))
            .collect();
        let tombstone_hashes: Vec<_> = tombstones.keys().cloned().collect();
        assert_eq!(
            tombstone_gate::digest(&effects.tombstone_facts).unwrap(),
            sha(&canon(&json!(tombstone_hashes)))
        );
        let p = complete_package(&h, before.clone(), &after, order.clone(), schedule.clone());
        let mut hashes: Vec<_> = h.facts.iter().map(|f| f.hash().unwrap()).collect();
        hashes.sort();
        let expected = json!({"case":case,"independent_signer_pin":h.records[h.signer].to_dict(),"original_commit_hashes":h.history.iter().map(|c|c.hash().unwrap()).collect::<Vec<_>>(),"original_fact_hashes":hashes,"original_tombstone_hashes":tombstone_hashes,"tombstone_digest":sha(&canon(&json!(tombstone_hashes))),"removals":schedule,"version_order":order,"expected_final_document_sha256":sha(&canon(&after)),"semantic_result":match case {"N01-reciprocal"|"N02-cycle"=>"ScopeUnsupported","N03-same-commit"=>"AuthorityUnproven",_=>"candidate"}});
        let files = [
            (
                "history.canon",
                canon(&json!(
                    h.history.iter().map(|c| c.to_dict()).collect::<Vec<_>>()
                )),
            ),
            (
                "facts.canon",
                canon(&json!(
                    h.facts.iter().map(|f| f.to_dict()).collect::<Vec<_>>()
                )),
            ),
            ("payload.json", canon(&p.payload)),
            ("manifest.json", canon(&p.manifest)),
            ("literal-trace.json", canon(&trace)),
            ("expected-unflushed.canon", canon(&before)),
            ("expected-final.canon", canon(&after)),
            ("expected.json", canon(&expected)),
        ];
        for (name, bytes) in files {
            let path = generate
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(root)
                .join(case)
                .join(name);
            if generate.is_some() {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, bytes).unwrap();
            } else {
                assert_eq!(bytes, fs::read(path).unwrap(), "{case}/{name}");
            }
        }
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
                assert_eq!(c.recomputed_final_document_sha256(), sha(&canon(&after)));
                assert_eq!(c.tombstone_digest(), expected["tombstone_digest"]);
            }
        }
    }
}
