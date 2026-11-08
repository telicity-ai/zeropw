//! Synthetic-only independent builder. Executed only in assigned isolation.
#![allow(dead_code)]
#[path = "team_checkpoint_m2b2.rs"]
pub mod legacy;
pub use legacy::{History, Package, canon, key, sha};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use zeropw::{
    crypto::{chacha20poly1305 as aead, x25519},
    pybase64,
    team::{checkpoint::*, commit::Commit, envelope, fold, identity::DeviceRecord},
};
pub const G1: &str = "aaaaaaaaaaaaaaaa";
pub const G2: &str = "dddddddddddddddd";
pub const G3: &str = "eeeeeeeeeeeeeeee";
pub const V1: &str = "1111111111111111";
pub const V2: &str = "2222222222222222";
pub const V3: &str = "3333333333333333";
pub const V4: &str = "4444444444444444";
pub const SENTINEL: &[u8] = b"synthetic-required-generation-private-sentinel-20261108";
pub const CASES: [&str; 8] = [
    "G01-multiple",
    "G02-new-recipient",
    "G03-selected-history",
    "G04-deletion",
    "G05-empty",
    "G06-byte-kinds",
    "G07-late-failure",
    "G08-removal",
];

pub fn dek(g: &str) -> Vec<u8> {
    vec![
        match g {
            G1 => 6,
            G2 => 7,
            G3 => 8,
            _ => panic!("unknown synthetic generation"),
        };
        32
    ]
}
/// Independent deterministic construction with existing primitives; permits
/// intentionally non32-byte authenticated plaintexts for negative tests only.
pub fn wrap_bytes(
    env: &str,
    generation: &str,
    record: &DeviceRecord,
    bytes: &[u8],
    salt: u8,
) -> Value {
    let info = [
        envelope::DEK_INFO_PREFIX,
        env.as_bytes(),
        generation.as_bytes(),
        record.fingerprint().as_bytes(),
    ]
    .concat();
    let eph = [salt; 32];
    let shared = x25519::shared_secret(&eph, &record.agree_pub).unwrap();
    let key = envelope::hkdf(b"", &shared, &info, 32).unwrap();
    let nonce = [salt.wrapping_add(1); 12];
    json!({"eph_pub":pybase64::b64encode(&x25519::public_key(&eph).unwrap()),"nonce":pybase64::b64encode(&nonce),"ciphertext":pybase64::b64encode(&aead::encrypt(&key,&nonce,bytes,&info).unwrap())})
}
pub fn wrap(h: &History, generation: &str, who: usize, salt: u8) -> Value {
    wrap_bytes(&h.env, generation, &h.records[who], &dek(generation), salt)
}
pub fn cipher(env: &str, sid: &str, vid: &str, bytes: &[u8], key: &[u8], salt: u8) -> Value {
    let aad = [env.as_bytes(), b"\0", sid.as_bytes(), b"\0", vid.as_bytes()].concat();
    let nonce = [salt; 12];
    json!({"nonce":pybase64::b64encode(&nonce),"ciphertext":pybase64::b64encode(&aead::encrypt(key,&nonce,bytes,&aad).unwrap())})
}
pub fn put(
    h: &History,
    sid: &str,
    vid: &str,
    generation: &str,
    kind: &str,
    bytes: &[u8],
    salt: u8,
) -> Value {
    json!({"op":"secret.put_version","secret_id":sid,"version_id":vid,"generation_id":generation,"kind":kind,"ciphertext":cipher(&h.env,sid,vid,bytes,&dek(generation),salt),"public":{}})
}
fn member(h: &History, who: usize, role: &str, generations: &[&str]) -> Value {
    let wraps: serde_json::Map<_, _> = generations
        .iter()
        .enumerate()
        .map(|(i, g)| (g.to_string(), wrap(h, g, who, 20 + who as u8 + i as u8)))
        .collect();
    json!({"op":"member.add","device":h.records[who].to_dict(),"name":if who==1 {"admin"} else {"recipient"},"role":role,"wraps":wraps})
}
fn rotation(h: &History, generation: &str, targets: &[usize]) -> Value {
    let wraps: serde_json::Map<_, _> = targets
        .iter()
        .map(|who| {
            (
                h.fps[*who].clone(),
                wrap(h, generation, *who, 50 + *who as u8),
            )
        })
        .collect();
    json!({"op":"dek.rotate","generation_id":generation,"wraps":wraps})
}
pub fn resign_op(h: &mut History, ci: usize, oi: usize, op: Value) {
    let c = &h.history[ci];
    let author = h.fps.iter().position(|fp| fp == &c.author).unwrap();
    let mut value = c.to_dict();
    value["ops"][oi] = op;
    legacy::resign(&mut value, &h.keys[author]);
    h.history[ci] = Commit::from_dict(&value).unwrap();
}
pub fn change_op(h: &mut History, ci: usize, oi: usize, change: impl FnOnce(&mut Value)) {
    let mut op = h.history[ci].ops[oi].clone();
    change(&mut op);
    resign_op(h, ci, oi, op);
}
pub fn append(h: &mut History, ops: Vec<Value>) {
    let seq = h.history.iter().filter(|c| c.author == h.fps[0]).count() as i64 + 1;
    let wall = 1000 * (h.history.len() as i64 + 1);
    h.history
        .push(h.c(0, seq, wall, &[(0, seq - 1), (1, 1)], ops));
    h.retained = (0..h.history.len()).collect();
}
#[derive(Clone)]
pub struct Literal {
    pub sid: String,
    pub vid: String,
    pub generation: String,
    pub kind: String,
    pub status: String,
    pub deleted: bool,
    pub plaintext: Vec<u8>,
}
fn lit(
    sid: &str,
    vid: &str,
    generation: &str,
    kind: &str,
    status: &str,
    deleted: bool,
    plaintext: &[u8],
) -> Literal {
    Literal {
        sid: sid.into(),
        vid: vid.into(),
        generation: generation.into(),
        kind: kind.into(),
        status: status.into(),
        deleted,
        plaintext: plaintext.into(),
    }
}
pub struct Case {
    pub h: History,
    pub literal: Vec<Literal>,
    pub removal: Value,
}
impl Case {
    pub fn required(&self) -> Vec<&Literal> {
        self.literal
            .iter()
            .filter(|v| !v.deleted && matches!(v.status.as_str(), "active" | "staged"))
            .collect()
    }
    pub fn package(&self) -> (Package, Value, Value) {
        package(&self.h, self.removal.clone())
    }
    pub fn expectation(&self, p: &Package, final_doc: &Value) -> Value {
        let tuples: Vec<_> = self
            .required()
            .iter()
            .map(|v| json!([v.sid, v.vid, v.generation]))
            .collect();
        let required: BTreeSet<_> = self
            .required()
            .iter()
            .map(|v| v.generation.as_str())
            .collect();
        // Explicit original operation positions, independently enumerated here.
        let selectors:Vec<_>=p.payload["components"][5]["data"]["entries"].as_array().unwrap().iter().map(|e|json!({"generation":e["generation_id"],"hash":e["source_commit_hash"],"op_index":e["source_op_index"]})).collect();
        let effective = if self.h.name == "G08-removal" {
            vec![(G1, 3usize), (G2, 5)]
        } else {
            vec![(G1, 4), (G2, 4), (G3, 4)]
        };
        let effective:Vec<_>=effective.iter().map(|(g,i)|json!({"generation":g,"hash":self.h.history[*i].hash().unwrap(),"op_index":0})).collect();
        let historical = if self.h.name == "G03-selected-history" {
            json!([{"generation":G1,"hash":self.h.history[0].hash().unwrap(),"op_index":0}])
        } else {
            json!([])
        };
        json!({"case":self.h.name,"effective_originals":effective,"historical_originals":historical,"required_tuples":tuples,"required_generations":required,"checked_ciphertexts":self.required().len(),"selected_originals":selectors,"inventory":self.literal.iter().map(|v|json!({"secret":v.sid,"version":v.vid,"generation":v.generation,"kind":v.kind,"status":v.status,"deleted":v.deleted})).collect::<Vec<_>>(),"expected_final_document_sha256":sha(&canon(final_doc)),"assurance":"authenticated retrieval bytes only; no provider or SSH readiness"})
    }
    pub fn crypto_oracle(&self, p: &Package) -> Value {
        json!({"synthetic_only":true,"env":self.h.env,"recipient":self.h.fps[2],"deks":{G1:hex::encode(dek(G1)),G2:hex::encode(dek(G2)),G3:hex::encode(dek(G3))},"versions":self.literal.iter().map(|v|json!({"secret":v.sid,"version":v.vid,"generation":v.generation,"plaintext_hex":hex::encode(&v.plaintext)})).collect::<Vec<_>>(),"selected_originals":p.payload["components"][5]["data"]["entries"]})
    }
}
pub fn build(name: &str) -> Case {
    let mut h = legacy::history("P1");
    h.name = name.into();
    h.history.clear();
    h.facts.clear();
    let mut init = json!({"op":"env.init","owner_name":"owner","owner_device":h.records[0].to_dict(),"generation_id":G1,"wraps":{&h.fps[0]:wrap(&h,G1,0,10)}});
    if name == "G03-selected-history" {
        init["wraps"][&h.fps[2]] = wrap(&h, G1, 2, 11);
    }
    h.history.push(h.c(0, 1, 1000, &[], vec![init]));
    h.history
        .push(h.c(0, 2, 2000, &[(0, 1)], vec![member(&h, 1, "admin", &[G1])]));
    h.history
        .push(h.c(0, 3, 3000, &[(0, 2)], vec![rotation(&h, G2, &[0, 1])]));
    h.history
        .push(h.c(0, 4, 4000, &[(0, 3)], vec![rotation(&h, G3, &[0, 1])]));
    h.history.push(h.c(
        1,
        1,
        5000,
        &[(0, 4)],
        vec![member(&h, 2, "user", &[G1, G2, G3])],
    ));
    let mut literal = vec![
        lit("alpha", V1, G1, "api_key", "active", false, SENTINEL),
        lit(
            "alpha",
            V2,
            G1,
            "api_key",
            "staged",
            false,
            b"synthetic-staged-second",
        ),
        lit(
            "alpha",
            V3,
            G2,
            "api_key",
            "retired",
            false,
            b"synthetic-retired",
        ),
        lit(
            "alpha",
            V4,
            G2,
            "api_key",
            "revoked",
            false,
            b"synthetic-revoked",
        ),
        lit("beta", V1, G2, "password", "staged", false, b""),
        lit(
            "orphan",
            V1,
            G2,
            "env_var",
            "staged",
            false,
            &[0, 255, 128, 1],
        ),
    ];
    if name == "G06-byte-kinds" {
        // Fixed frozen Python fixture is valid synthetic SSH, with no random
        // PEM checkint regeneration and no signing/provider operation.
        let ssh = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/python/sshwire/from-python.key"),
        )
        .unwrap_or_else(|_| {
            // Existing frozen source path is selected by its inventory in the
            // caller; absence is a prerequisite, never random key generation.
            panic!("frozen synthetic SSH fixture missing")
        });
        literal.push(lit(
            "ssh-valid",
            V1,
            G1,
            "ssh_private_key",
            "staged",
            false,
            &ssh,
        ));
        literal.push(lit(
            "ssh-malformed",
            V1,
            G2,
            "ssh_private_key",
            "staged",
            false,
            b"synthetic-not-an-openssh-key",
        ));
    }
    let mut ops = Vec::new();
    for (i, v) in literal.iter().enumerate() {
        ops.push(put(
            &h,
            &v.sid,
            &v.vid,
            &v.generation,
            &v.kind,
            &v.plaintext,
            70 + i as u8,
        ));
        if v.status == "active" {
            ops.push(json!({"op":"secret.activate","secret_id":v.sid,"version_id":v.vid}));
        } else if v.status != "staged" {
            ops.push(json!({"op":"secret.set_status","secret_id":v.sid,"version_id":v.vid,"status":"retired"}));
        }
    }
    let mut conn = legacy::connection_op(&h, "http", "disabled-alpha", json!(V1));
    conn["secret_id"] = json!("alpha");
    ops.push(conn);
    ops.push(json!({"op":"connection.disable","id":"disabled-alpha"}));
    h.history.push(h.c(0, 5, 6000, &[(0, 4), (1, 1)], ops));
    h.facts.push(h.f(
        0,
        "secret_version_revoked",
        json!({"secret_id":"alpha","version_id":V4}),
        6500,
    ));
    if matches!(name, "G04-deletion" | "G05-empty") {
        h.facts
            .push(h.f(1, "secret_deleted", json!({"secret_id":"alpha"}), 7000));
        h.facts
            .push(h.f(0, "secret_deleted", json!({"secret_id":"alpha"}), 7100));
        h.facts.push(h.f(
            1,
            "secret_deleted",
            json!({"secret_id":"deleted-empty"}),
            7200,
        ));
        h.facts.push(h.f(
            0,
            "secret_version_revoked",
            json!({"secret_id":"beta","version_id":V1}),
            7300,
        ));
        for v in &mut literal {
            if v.sid == "alpha" {
                v.deleted = true;
                v.status = "revoked".into();
            } else if v.sid == "beta" {
                v.status = "revoked".into();
            }
        }
        if name == "G05-empty" {
            h.facts
                .push(h.f(1, "secret_deleted", json!({"secret_id":"orphan"}), 7400));
            for v in &mut literal {
                if v.sid == "orphan" {
                    v.deleted = true;
                    v.status = "revoked".into();
                }
            }
        }
    }
    h.retained = (0..h.history.len()).collect();
    let mut result = Case {
        h,
        literal,
        removal: json!({"bounds":{},"pending":[],"self_placed":[],"witness_commit_hashes":[]}),
    };
    if name == "G08-removal" {
        let mut h = legacy::complete_history("R01-other");
        h.name = name.into();
        change_op(&mut h, 5, 0, |op| {
            for who in [0usize, 1, 2] {
                op["wraps"][&result.h.fps[who]] = wrap_bytes(
                    &h_env(),
                    G2,
                    &result.h.records[who],
                    &dek(G2),
                    50 + who as u8,
                );
            }
        });
        // h_env is the same fixed owner-derived synthetic environment.
        result.literal = vec![
            lit("old", V1, G1, "api_key", "staged", false, SENTINEL),
            lit(
                "new",
                V1,
                G2,
                "password",
                "staged",
                false,
                b"synthetic-new-generation",
            ),
        ];
        let ops = result
            .literal
            .iter()
            .enumerate()
            .map(|(i, v)| {
                put(
                    &h,
                    &v.sid,
                    &v.vid,
                    &v.generation,
                    &v.kind,
                    &v.plaintext,
                    90 + i as u8,
                )
            })
            .collect();
        append(&mut h, ops);
        result.removal = json!({"bounds":{&h.fps[3]:1},"pending":[[5000,0,h.fps[3]]],"self_placed":[],"witness_commit_hashes":[h.history[5].hash().unwrap()]});
        result.h = h;
    }
    result
}
fn h_env() -> String {
    format!(
        "{}-0123456789abcdef0123456789abcdef",
        key(0, 3).fingerprint().unwrap()
    )
}
/// Complete ordinary fold and unflushed snapshot are independent of the new
/// function. The caller separately checks hand-authored status/key inventories.
pub fn package(h: &History, removal: Value) -> (Package, Value, Value) {
    let effects = legacy::ordinary_effects(h);
    let snapshot = legacy::ordinary_snapshot(h, &effects);
    let final_fold =
        fold::fold(&h.env, h.history.clone(), Some(&effects), None, None, None).unwrap();
    let mut p = legacy::complete_package(
        h,
        snapshot.document,
        &final_fold.document,
        final_fold.version_order.clone(),
        removal,
    );
    let mut entries = Vec::new();
    for c in &h.history {
        for (i, op) in c.ops.iter().enumerate() {
            if op["op"] == "member.add" && op["device"] == h.records[2].to_dict() {
                for (g, w) in op["wraps"].as_object().unwrap() {
                    entries.push(json!({"generation_id":g,"recipient":h.fps[2],"source_commit_hash":c.hash().unwrap(),"source_op_index":i,"wrap":w}));
                }
            } else if matches!(op["op"].as_str(), Some("env.init" | "dek.rotate"))
                && let Some(w) = op["wraps"].get(&h.fps[2])
            {
                entries.push(json!({"generation_id":op["generation_id"],"recipient":h.fps[2],"source_commit_hash":c.hash().unwrap(),"source_op_index":i,"wrap":w}));
            }
        }
    }
    entries.sort_by_key(|e| {
        (
            e["generation_id"].as_str().unwrap().to_owned(),
            e["source_commit_hash"].as_str().unwrap().to_owned(),
            e["source_op_index"].as_u64().unwrap(),
        )
    });
    p.payload["components"][5]["data"] = json!({"entries":entries,"unavailable_generations":[]});
    p.rebind(&h.keys[h.signer]);
    (p, final_fold.document, final_fold.version_order)
}
pub fn check(
    c: &Case,
    p: &Package,
    k: &zeropw::team::identity::DeviceKey,
) -> Result<(usize, usize), SemanticError> {
    let m = p.attestation(&c.h);
    let raw = canon(&p.payload);
    let payload = verify_payload_bytes(&m, &raw).expect("negative first passes payload");
    let local = c.h.local(&m);
    let candidate = verify_complete_cut_semantics(&m, &payload, &local)
        .expect("negative first passes complete semantics");
    verify_required_generations(&candidate, k)
        .map(|v| (v.required_generation_count(), v.checked_ciphertext_count()))
}
pub fn omit(p: &mut Package, generations: &[&str], unavailable: bool, h: &History) {
    p.payload["components"][5]["data"]["entries"]
        .as_array_mut()
        .unwrap()
        .retain(|e| !generations.contains(&e["generation_id"].as_str().unwrap()));
    p.payload["components"][5]["data"]["unavailable_generations"] = json!(if unavailable {
        generations.to_vec()
    } else {
        vec![]
    });
    p.rebind(&h.keys[h.signer]);
}
pub fn corrupt(text: &Value) -> Value {
    let mut b = pybase64::b64decode(text.as_str().unwrap()).unwrap();
    *b.last_mut().unwrap() ^= 1;
    json!(pybase64::b64encode(&b))
}
pub fn nested(depth: usize) -> Value {
    (0..depth).fold(json!(0), |v, _| json!({"x":v}))
}
pub fn measured_depth(raw: &[u8]) -> usize {
    let (mut depth, mut max, mut string, mut escape) = (0usize, 0usize, false, false);
    for b in raw {
        if string {
            if escape {
                escape = false;
            } else if *b == b'\\' {
                escape = true;
            } else if *b == b'"' {
                string = false;
            }
        } else {
            match b {
                b'"' => string = true,
                b'{' | b'[' => {
                    depth += 1;
                    max = max.max(depth);
                }
                b'}' | b']' => depth -= 1,
                _ => {}
            }
        }
    }
    max
}

impl Case {
    /// Full hand-authored final document and order, with explicit original
    /// encrypted-wrap positions. No fold or new verifier computes this oracle.
    pub fn literal_document(&self) -> (Value, Value) {
        let h = &self.h;
        let removal = h.name == "G08-removal";
        let mut doc = json!({"format":"zeropw-team-env-v1","env_id":h.env,"owner":h.fps[0],"members":{},"dek":{"current":if removal {G2}else{G3},"generations":{}},"secrets":{},"connections":{},"settings":{"sync_interval_seconds":if removal {11}else{10}}});
        for who in 0..if removal { 4 } else { 3 } {
            doc["members"][&h.fps[who]] = json!({"device":h.records[who].to_dict(),"name":match who {0=>"owner",1=>"admin",2=>"recipient",_=>"former"},"role":if who==2 {"user"}else{"admin"},"status":if who==3 {"removed"}else{"active"}});
        }
        let mut wraps = json!({&h.fps[0]:h.history[0].ops[0]["wraps"][&h.fps[0]],&h.fps[1]:h.history[1].ops[0]["wraps"][G1],&h.fps[2]:h.history[if removal {3}else{4}].ops[0]["wraps"][G1]});
        if removal {
            wraps[&h.fps[3]] = h.history[2].ops[0]["wraps"][G1].clone();
        }
        doc["dek"]["generations"][G1] = json!({"wraps":wraps});
        if removal {
            doc["dek"]["generations"][G2] = json!({"wraps":h.history[5].ops[0]["wraps"],"removal_fact_hash":h.facts[0].hash().unwrap()});
        } else {
            for (g, ci) in [(G2, 2usize), (G3, 3)] {
                doc["dek"]["generations"][g] = json!({"wraps":{&h.fps[0]:h.history[ci].ops[0]["wraps"][&h.fps[0]],&h.fps[1]:h.history[ci].ops[0]["wraps"][&h.fps[1]],&h.fps[2]:h.history[4].ops[0]["wraps"][g]}});
            }
        }
        let mut order = json!({});
        for (i, v) in self.literal.iter().enumerate() {
            if doc["secrets"].get(&v.sid).is_none() {
                doc["secrets"][&v.sid] = json!({"kind":v.kind,"active_version":null,"versions":{}});
                order[&v.sid] = json!([]);
            }
            let encrypted = cipher(
                &h.env,
                &v.sid,
                &v.vid,
                &v.plaintext,
                &dek(&v.generation),
                if removal { 90 + i as u8 } else { 70 + i as u8 },
            );
            doc["secrets"][&v.sid]["versions"][&v.vid] = json!({"nonce":encrypted["nonce"],"ciphertext":encrypted["ciphertext"],"generation":v.generation,"public":{},"status":v.status});
            if v.status == "active" && !v.deleted {
                doc["secrets"][&v.sid]["active_version"] = json!(v.vid);
            }
            if v.deleted {
                doc["secrets"][&v.sid]["deleted"] = json!(true);
            }
            order[&v.sid].as_array_mut().unwrap().push(json!(v.vid));
        }
        if !removal {
            doc["connections"]["disabled-alpha"] = json!({"id":"disabled-alpha","kind":"http","project":"synthetic","environment":"test","service":"controlled","secret_id":"alpha","secret_version":V1,"description":"synthetic policy","status":"disabled","cli":null,"ssh_target":null,"created_at":"1970-01-01T00:00:06Z","updated_at":"1970-01-01T00:00:06Z","http_target":{"scheme":"https","host":"api.example.com","port":443,"ca_file":null,"allow_private_network":false},"http_auth":{"mode":"header","header_name":"X-API-Key","value_prefix":"","basic_username":null},"http_scope":{"methods":["GET"],"path_prefixes":["/"],"confirm_methods":[]}});
        }
        (doc, order)
    }
}
