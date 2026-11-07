//! Separate M2b.2a synthetic data builder. Ordinary folds supply a correlated
//! oracle only; literal/canonical expectations remain independent.
#![allow(dead_code)]
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeropw::{
    crypto::{chacha20poly1305 as aead, x25519},
    pybase64,
    pyint::PyInt,
    pyjson::{self, DumpOptions},
    secret::SecretBytes,
    team::{
        checkpoint::*,
        commit::{self, Commit, Hlc},
        envelope, fold,
        identity::{DeviceKey, DeviceRecord},
        sync::{self, Fact},
    },
};

pub const G: &str = "aaaaaaaaaaaaaaaa";
pub const V1: &str = "bbbbbbbbbbbbbbbb";
pub const V2: &str = "cccccccccccccccc";
pub const SECRET: &str = "retained-secret";
pub const CASES: [&str; 7] = ["P1", "P2", "P3", "P4", "P5", "P6-empty", "P6-nonempty"];
pub fn canon(v: &Value) -> Vec<u8> {
    pyjson::dumps(v, DumpOptions::compact_sorted())
        .unwrap()
        .into_bytes()
}
pub fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
pub fn load(b: &[u8]) -> Value {
    pyjson::loads(std::str::from_utf8(b).unwrap()).unwrap()
}
pub fn key(seed: u8, scalar: u8) -> DeviceKey {
    DeviceKey {
        sign_seed: SecretBytes::from_slice(&[seed; 32]),
        agree_private: SecretBytes::from_slice(&[scalar; 32]),
    }
}
pub fn wrap(env: &str, rec: &DeviceRecord, eph: u8, nonce: u8) -> Value {
    wrap_for_generation(env, G, rec, eph, nonce)
}
pub fn wrap_for_generation(
    env: &str,
    generation: &str,
    rec: &DeviceRecord,
    eph: u8,
    nonce: u8,
) -> Value {
    let info = [
        envelope::DEK_INFO_PREFIX,
        env.as_bytes(),
        generation.as_bytes(),
        rec.fingerprint().as_bytes(),
    ]
    .concat();
    let shared = x25519::shared_secret(&[eph; 32], &rec.agree_pub).unwrap();
    let wk = envelope::hkdf(b"", &shared, &info, 32).unwrap();
    json!({"eph_pub":pybase64::b64encode(&x25519::public_key(&[eph;32]).unwrap()),
        "nonce":pybase64::b64encode(&[nonce;12]),"ciphertext":pybase64::b64encode(&aead::encrypt(&wk,&[nonce;12],&[6;32],&info).unwrap())})
}
pub fn ciphertext(env: &str, version: &str, nonce: u8, value: &[u8]) -> Value {
    let aad = [
        env.as_bytes(),
        b"\0",
        SECRET.as_bytes(),
        b"\0",
        version.as_bytes(),
    ]
    .concat();
    json!({"nonce":pybase64::b64encode(&[nonce;12]),"ciphertext":pybase64::b64encode(&aead::encrypt(&[6;32],&[nonce;12],value,&aad).unwrap())})
}
pub struct History {
    pub name: String,
    pub keys: [DeviceKey; 5],
    pub records: [DeviceRecord; 5],
    pub fps: [String; 5],
    pub env: String,
    pub history: Vec<Commit>,
    pub facts: Vec<Fact>,
    pub signer: usize,
    pub retained: Vec<usize>,
    pub table: Vec<usize>,
}
impl History {
    pub fn c(
        &self,
        author: usize,
        seq: i64,
        wall: i64,
        seen: &[(usize, i64)],
        ops: Vec<Value>,
    ) -> Commit {
        commit::sign_commit(
            &self.keys[author],
            &self.env,
            seq,
            &format!("{wall}-0000"),
            &seen
                .iter()
                .map(|(i, n)| (self.fps[*i].clone(), PyInt::from(*n)))
                .collect(),
            ops,
        )
        .unwrap()
    }
    pub fn f(&self, author: usize, kind: &str, target: Value, wall: i64) -> Fact {
        sync::sign_fact(
            &self.keys[author],
            &self.env,
            kind,
            target,
            &format!("{wall}-0000"),
        )
        .unwrap()
    }
    pub fn add(&self, who: usize, role: &str) -> Value {
        json!({"op":"member.add","name":match who {1=>"admin",2=>"recipient",3=>"former",_=>"unused"},
            "device":self.records[who].to_dict(),"role":role,"wraps":{G:wrap(&self.env,&self.records[who],(9+who) as u8,(12+who) as u8)}})
    }
    pub fn full_fold(&self) -> fold::FoldResult {
        fold::fold(&self.env, self.history.clone(), None, None, None, None).unwrap()
    }
    pub fn package(&self) -> Package {
        let full = self.full_fold();
        let mut vector = full.vector.clone();
        vector
            .entry(self.fps[2].clone())
            .or_insert_with(PyInt::zero);
        let heads:Vec<Value>=vector.iter().filter(|(_,s)| **s>0).map(|(fp,seq)| {
            let c=self.history.iter().find(|c| &c.author==fp && &c.author_seq==seq).unwrap();
            let (w,n)=Hlc::parse(&c.hlc).unwrap();
            json!({"author":fp,"author_seq":seq.value(),"commit_hash":c.hash().unwrap(),"hlc":{"wall_ms":w.value(),"counter":n.value()}})
        }).collect();
        let admission = self
            .history
            .iter()
            .find(|c| {
                c.ops
                    .iter()
                    .any(|op| op["op"] == "member.add" && op["device"] == self.records[2].to_dict())
            })
            .unwrap();
        let op_index = admission
            .ops
            .iter()
            .position(|op| op["op"] == "member.add" && op["device"] == self.records[2].to_dict())
            .unwrap();
        let mut devices: Vec<_> = self
            .table
            .iter()
            .map(|i| json!({"fingerprint":self.fps[*i],"record":self.records[*i].to_dict()}))
            .collect();
        devices.sort_by(|a, b| a["fingerprint"].as_str().cmp(&b["fingerprint"].as_str()));
        let mut records:Vec<_>=self.retained.iter().map(|i|json!({"hash":self.history[*i].hash().unwrap(),"record":self.history[*i].to_dict()})).collect();
        records.sort_by(|a, b| a["hash"].as_str().cmp(&b["hash"].as_str()));
        let mut auth: Vec<_> = self
            .retained
            .iter()
            .map(|i| &self.history[*i])
            .filter(|c| {
                c.ops
                    .iter()
                    .any(|op| is_authority(op["op"].as_str().unwrap()))
            })
            .map(|c| c.hash().unwrap())
            .collect();
        auth.sort();
        let mut facts: Vec<_> = self
            .facts
            .iter()
            .map(|f| json!({"hash":f.hash().unwrap(),"record":f.to_dict()}))
            .collect();
        facts.sort_by(|a, b| a["hash"].as_str().cmp(&b["hash"].as_str()));
        let hashes: Vec<_> = facts.iter().map(|f| f["hash"].clone()).collect();
        let tombstones: Vec<_> = facts
            .iter()
            .filter(|f| f["record"]["kind"] == "secret_deleted")
            .map(|f| f["hash"].clone())
            .collect();
        let final_digest = sha(&canon(&full.document)); // explicitly unverified data-stage claim
        let components = vec![
            json!({"name":"devices","data":devices}),
            json!({"name":"snapshot","data":{"document":full.document,"vector":vector_value(&vector),"version_order":full.version_order,"expected_final_document_sha256":final_digest}}),
            json!({"name":"commits","data":{"records":records,"genesis_commit_hash":self.history[0].hash().unwrap(),"recipient_admission_commit_hash":admission.hash().unwrap(),"authority_commit_hashes":auth}}),
            json!({"name":"facts","data":{"records":facts,"admitted_fact_hashes":hashes,"tombstone_fact_hashes":tombstones}}),
            json!({"name":"removals","data":{"bounds":{},"pending":[],"self_placed":[],"witness_commit_hashes":[]}}),
            json!({"name":"recipient_dek_wraps","data":{"entries":[{"generation_id":G,"recipient":self.fps[2],"source_commit_hash":admission.hash().unwrap(),"source_op_index":op_index,"wrap":admission.ops[op_index]["wraps"][G]}],"unavailable_generations":[]}}),
        ];
        let payload = json!({"format":"zeropw-team-bootstrap-payload-v1","v":1,"env_id":self.env,"components":components});
        let context = self.context();
        let manifest = json!({"type":"BOOTSTRAP_MANIFEST","domain":"zeropw-team-bootstrap-v1","v":1,"trust_model":"administrator_attested",
            "env_id":self.env,"signer":self.fps[self.signer],"recipient":self.fps[2],"recipient_role":"user","invite_id":"10".repeat(16),"approval_id":"20".repeat(16),"approval_sha256":context.approval_sha256(),"session_nonce":"50".repeat(32),"onboarding_nonce":"60".repeat(32),"transfer_id":"40".repeat(16),"recipient_authorization_id":"30".repeat(16),"recipient_admission_commit_hash":admission.hash().unwrap(),"authorization_expires_at_ms":1800003600000_u64,"created_at_ms":1800000000000_u64,"expires_at_ms":1800000600000_u64,"required_features":["secret_tombstone_v1","snapshot_bootstrap_v1"],"vector":vector_value(&vector),"heads":heads,"counts":{},"components":[],"admitted_fact_hashes_sha256":sha(&canon(&json!(hashes))),"tombstone_digest":sha(&canon(&json!(tombstones))),"expected_final_document_sha256":final_digest,"payload":{},"sig":""});
        let mut p = Package { manifest, payload };
        p.rebind(&self.keys[self.signer]);
        p
    }
    pub fn context(&self) -> ExpectedContext {
        ExpectedContext::from_local_expectations(
            LocalApprovalDescription {
                approval_id: "20".repeat(16),
                env_id: self.env.clone(),
                signer: self.fps[self.signer].clone(),
                signer_record: self.records[self.signer].clone(),
                recipient: self.fps[2].clone(),
                recipient_role: RecipientRole::User,
                invite_id: "10".repeat(16),
                invitation_expires_at_ms: 1800003600000,
            },
            AuthenticatedSessionExpectations {
                peer_record: self.records[self.signer].clone(),
                env_id: self.env.clone(),
                local_recipient: self.fps[2].clone(),
                session_nonce: "50".repeat(32),
                onboarding_nonce: "60".repeat(32),
            },
        )
        .unwrap()
    }
    pub fn bindings(&self, m: &ManifestAttestation) -> SemanticBindings {
        SemanticBindings {
            recipient_record: self.records[2].clone(),
            recipient_role: RecipientRole::User,
            env_id: self.env.clone(),
            manifest_hash: m.manifest_hash().into(),
            approval_sha256: self.context().approval_sha256().into(),
            session_nonce: "50".repeat(32),
            onboarding_nonce: "60".repeat(32),
            intended_mapping: self.mapping(),
            observation_revision: "a1".repeat(32),
        }
    }
    pub fn mapping(&self) -> LocalMapping {
        LocalMapping {
            project: "synthetic".into(),
            environment: "test".into(),
            env_id: self.env.clone(),
        }
    }
    pub fn local(&self, m: &ManifestAttestation) -> SemanticLocalInputs {
        SemanticLocalInputs::from_local_observation(
            self.bindings(m),
            inventory(),
            vec![],
            restrictions(),
        )
        .unwrap()
    }
}
pub fn inventory() -> ObservedInventory {
    ObservedInventory {
        admitted_commits: 0,
        admitted_facts: 0,
        checkpoints: 0,
        derived_team_entries: 0,
        unsent_edits: 0,
        pending_imports: 0,
        completed_imports: 0,
        stale_restore: false,
        existing_mapping: None,
        own_staging_manifest_hash: None,
    }
}
pub fn restrictions() -> LocalRestrictions {
    LocalRestrictions {
        known_original_facts: vec![],
        deleted_secret_ids: BTreeSet::new(),
        revoked_versions: BTreeSet::new(),
        disabled_connection_ids: BTreeSet::new(),
        removed_members: BTreeSet::new(),
        restored_bindings: vec![],
        required_tombstone_support: RequiredTombstoneSupport::NotObserved,
        backup_barrier: false,
    }
}
pub fn vector_value(v: &BTreeMap<String, PyInt>) -> Value {
    Value::Object(v.iter().map(|(f, n)| (f.clone(), n.value())).collect())
}
pub fn is_authority(s: &str) -> bool {
    [
        "env.init",
        "member.add",
        "member.set_role",
        "member.remove",
        "owner.transfer",
        "dek.rotate",
    ]
    .contains(&s)
}
pub struct Package {
    pub manifest: Value,
    pub payload: Value,
}
impl Package {
    /// Repair ALL outer claims and sign with the independently pinned synthetic
    /// key. Inner mutations must reach the intended original-record boundary.
    pub fn rebind(&mut self, signer: &DeviceKey) {
        let c = &self.payload["components"];
        let versions: usize = c[1]["data"]["document"]["secrets"]
            .as_object()
            .unwrap()
            .values()
            .map(|s| s["versions"].as_object().unwrap().len())
            .sum();
        let counts = [
            c[0]["data"].as_array().unwrap().len(),
            c[2]["data"]["records"].as_array().unwrap().len(),
            c[3]["data"]["records"].as_array().unwrap().len(),
            versions,
            c[5]["data"]["entries"].as_array().unwrap().len(),
        ];
        self.manifest["counts"] = json!({"devices":counts[0],"commits":counts[1],"facts":counts[2],"versions":counts[3],"recipient_wraps":counts[4]});
        self.manifest["components"]=json!(c.as_array().unwrap().iter().enumerate().map(|(i,c)|{let b=canon(&c["data"]);json!({"name":c["name"],"byte_length":b.len(),"sha256":sha(&b),"item_count":match i {0=>counts[0],1|4=>1,2=>counts[1],3=>counts[2],5=>counts[4],_=>unreachable!()}})}).collect::<Vec<_>>());
        let raw = canon(&self.payload);
        self.bind_raw(&raw, signer);
    }
    pub fn bind_raw(&mut self, raw: &[u8], signer: &DeviceKey) {
        self.manifest["payload"] = json!({"byte_length":raw.len(),"sha256":sha(raw),"chunks":raw.chunks(65536).enumerate().map(|(i,b)|json!({"index":i,"byte_length":b.len(),"sha256":sha(b)})).collect::<Vec<_>>()});
        self.manifest.as_object_mut().unwrap().remove("sig");
        self.manifest["sig"] = json!(pybase64::b64encode(
            &signer.sign(&canon(&self.manifest)).unwrap()
        ));
    }
    pub fn attestation(&self, h: &History) -> ManifestAttestation {
        verify_manifest_bytes(
            &canon(&self.manifest),
            &h.context(),
            VerificationWallTime::from_millis(1800000000001).unwrap(),
        )
        .unwrap()
    }
    pub fn repair_commits(&mut self) {
        let mut replacements = BTreeMap::new();
        for e in self.payload["components"][2]["data"]["records"]
            .as_array_mut()
            .unwrap()
        {
            let new = sha(&canon(&e["record"]));
            replacements.insert(e["hash"].as_str().unwrap().to_owned(), new.clone());
            e["hash"] = json!(new);
        }
        self.payload["components"][2]["data"]["records"]
            .as_array_mut()
            .unwrap()
            .sort_by(|a, b| a["hash"].as_str().cmp(&b["hash"].as_str()));
        let replace = |v: &mut Value| {
            if let Some(new) = v.as_str().and_then(|s| replacements.get(s)) {
                *v = json!(new);
            }
        };
        for h in self.manifest["heads"].as_array_mut().unwrap() {
            replace(&mut h["commit_hash"]);
        }
        replace(&mut self.manifest["recipient_admission_commit_hash"]);
        for name in ["genesis_commit_hash", "recipient_admission_commit_hash"] {
            replace(&mut self.payload["components"][2]["data"][name]);
        }
        for v in self.payload["components"][2]["data"]["authority_commit_hashes"]
            .as_array_mut()
            .unwrap()
        {
            replace(v);
        }
        self.payload["components"][2]["data"]["authority_commit_hashes"]
            .as_array_mut()
            .unwrap()
            .sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        for witness in self.payload["components"][4]["data"]["witness_commit_hashes"]
            .as_array_mut()
            .unwrap()
        {
            replace(witness);
        }
        self.payload["components"][4]["data"]["witness_commit_hashes"]
            .as_array_mut()
            .unwrap()
            .sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        for v in self.payload["components"][5]["data"]["entries"]
            .as_array_mut()
            .unwrap()
        {
            replace(&mut v["source_commit_hash"]);
        }
    }
    pub fn repair_facts(&mut self) {
        let c = &mut self.payload["components"][3]["data"];
        for e in c["records"].as_array_mut().unwrap() {
            e["hash"] = json!(sha(&canon(&e["record"])));
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
        self.manifest["admitted_fact_hashes_sha256"] = json!(sha(&canon(&json!(hashes))));
        self.manifest["tombstone_digest"] = json!(sha(&canon(&json!(tombstones))));
    }
    pub fn commit_mut(&mut self, author: &str, seq: i64) -> &mut Value {
        &mut self.payload["components"][2]["data"]["records"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["record"]["author"] == author && e["record"]["author_seq"] == seq)
            .unwrap()["record"]
    }
}
pub fn resign(value: &mut Value, key: &DeviceKey) {
    let mut unsigned = value.clone();
    unsigned.as_object_mut().unwrap().remove("sig");
    value["sig"] = json!(pybase64::b64encode(&key.sign(&canon(&unsigned)).unwrap()));
}
pub fn history(case: &str) -> History {
    let keys = [
        key(0, 3),
        key(1, 4),
        key(2, 5),
        key(0x11, 0x12),
        key(0x13, 0x14),
    ];
    let records = keys.each_ref().map(|k| k.record().unwrap());
    let fps = records.each_ref().map(|r| r.fingerprint());
    let env = format!("{}-0123456789abcdef0123456789abcdef", fps[0]);
    let mut h = History {
        name: case.into(),
        keys,
        records,
        fps,
        env,
        history: vec![],
        facts: vec![],
        signer: 1,
        retained: vec![],
        table: vec![0, 1, 2],
    };
    h.history.push(h.c(0,1,1000,&[],vec![json!({"op":"env.init","owner_name":"owner","owner_device":h.records[0].to_dict(),"generation_id":G,"wraps":{&h.fps[0]:wrap(&h.env,&h.records[0],9,12)}})]));
    if case == "P4" {
        h.table.push(3);
        h.history
            .push(h.c(0, 2, 2000, &[(0, 1)], vec![h.add(1, "admin")]));
        h.history
            .push(h.c(0, 3, 3000, &[(0, 2)], vec![h.add(3, "admin")]));
        h.history
            .push(h.c(1, 1, 4000, &[(0, 3)], vec![h.add(2, "user")]));
        h.history.push(h.c(
            3,
            1,
            5000,
            &[(0, 3), (1, 1)],
            vec![json!({"op":"settings.update","sync_interval_seconds":11})],
        ));
        h.history.push(h.c(
            3,
            2,
            6000,
            &[(3, 1)],
            vec![json!({"op":"member.remove","fingerprint":h.fps[3]})],
        ));
        h.facts.push(h.f(
            3,
            "secret_deleted",
            json!({"secret_id":"deleted-empty"}),
            7000,
        ));
    } else if case == "P5" {
        h.signer = 0;
        h.history
            .push(h.c(0, 2, 2000, &[(0, 1)], vec![h.add(1, "user")]));
        h.history.push(h.c(
            0,
            3,
            3000,
            &[(0, 2)],
            vec![
                json!({"op":"member.set_role","fingerprint":h.fps[1],"role":"admin"}),
                json!({"op":"settings.update","sync_interval_seconds":11}),
            ],
        ));
        h.history
            .push(h.c(1, 1, 4000, &[(0, 3)], vec![h.add(2, "user")]));
        h.history.push(h.c(
            1,
            2,
            5000,
            &[(1, 1)],
            vec![
                json!({"op":"settings.update","sync_interval_seconds":12}),
                json!({"op":"member.set_role","fingerprint":h.fps[1],"role":"user"}),
            ],
        ));
    } else {
        h.history
            .push(h.c(0, 2, 2000, &[(0, 1)], vec![h.add(1, "admin")]));
        h.history
            .push(h.c(1, 1, 3000, &[(0, 2)], vec![h.add(2, "user")]));
        for (seq, wall, version, nonce, value) in [
            (3, 4000, V1, 7, b"synthetic-checkpoint-v1".as_slice()),
            (4, 5000, V2, 8, b"synthetic-checkpoint-v2".as_slice()),
        ] {
            h.history.push(h.c(0,seq,wall,&[(0,seq-1),(1,1)],vec![json!({"op":"secret.put_version","secret_id":SECRET,"kind":"api_key","generation_id":G,"version_id":version,"ciphertext":ciphertext(&h.env,version,nonce,value),"public":{}})]));
        }
        h.history.push(h.c(
            1,
            2,
            6000,
            &[(0, 4), (1, 1)],
            vec![json!({"op":"secret.activate","secret_id":SECRET,"version_id":V2})],
        ));
        if case == "P2" || case == "P6-nonempty" {
            h.facts = vec![
                h.f(
                    1,
                    "secret_deleted",
                    json!({"secret_id":"deleted-empty"}),
                    7000,
                ),
                h.f(1, "secret_deleted", json!({"secret_id":SECRET}), 8000),
                h.f(0, "secret_deleted", json!({"secret_id":SECRET}), 8500),
            ];
            if case == "P2" {
                h.signer = 0;
                h.history.push(h.c(
                    0,
                    5,
                    9000,
                    &[(0, 4), (1, 2)],
                    vec![json!({"op":"member.set_role","fingerprint":h.fps[1],"role":"user"})],
                ));
            }
        }
        if case == "P3" {
            h.history.push(h.c(
                0,
                5,
                9000,
                &[(0, 4), (1, 2)],
                vec![json!({"op":"owner.transfer","fingerprint":h.fps[1]})],
            ));
            h.history.push(h.c(
                1,
                3,
                10000,
                &[(0, 5), (1, 2)],
                vec![json!({"op":"member.set_role","fingerprint":h.fps[0],"role":"user"})],
            ));
            h.facts = vec![
                h.f(
                    0,
                    "secret_deleted",
                    json!({"secret_id":"deleted-empty"}),
                    7000,
                ),
                h.f(
                    0,
                    "secret_version_revoked",
                    json!({"secret_id":SECRET,"version_id":V1}),
                    8000,
                ),
            ];
        }
    }
    h.retained = (0..h.history.len())
        .filter(|i| case == "P4" || case == "P5" || *i != 3)
        .collect();
    h
}

/// Literal per-operation roles and owner; O/A/R/D are fixed identities, not
/// observations obtained from the candidate or the ordinary fold.
pub fn literal_steps(case: &str) -> Vec<(usize, Vec<usize>, Vec<usize>)> {
    let p1 = vec![
        (0, vec![0], vec![0]),
        (0, vec![0, 1], vec![0, 1]),
        (0, vec![0, 1], vec![0, 1, 2]),
        (0, vec![0, 1], vec![0, 1, 2]),
        (0, vec![0, 1], vec![0, 1, 2]),
        (0, vec![0, 1], vec![0, 1, 2]),
    ];
    match case {
        "P2" => p1
            .into_iter()
            .chain([(0, vec![0], vec![0, 1, 2])])
            .collect(),
        "P3" => p1
            .into_iter()
            .chain([(1, vec![0, 1], vec![0, 1, 2]), (1, vec![1], vec![0, 1, 2])])
            .collect(),
        "P4" => vec![
            (0, vec![0], vec![0]),
            (0, vec![0, 1], vec![0, 1]),
            (0, vec![0, 1, 3], vec![0, 1, 3]),
            (0, vec![0, 1, 3], vec![0, 1, 2, 3]),
            (0, vec![0, 1, 3], vec![0, 1, 2, 3]),
            (0, vec![0, 1], vec![0, 1, 2]),
        ],
        "P5" => vec![
            (0, vec![0], vec![0]),
            (0, vec![0], vec![0, 1]),
            (0, vec![0, 1], vec![0, 1]),
            (0, vec![0, 1], vec![0, 1]),
            (0, vec![0, 1], vec![0, 1, 2]),
            (0, vec![0, 1], vec![0, 1, 2]),
            (0, vec![0], vec![0, 1, 2]),
        ],
        _ => p1,
    }
}

pub const COMPLETE_CASES: [&str; 12] = [
    "C01-admin",
    "C02-owner",
    "C03-historical",
    "R01-other",
    "R02-multiple",
    "R03-self",
    "R04-pending",
    "D01-overlay",
    "D02-policy",
    "N01-reciprocal",
    "N02-cycle",
    "N03-same-commit",
];
pub const G2: &str = "dddddddddddddddd";
pub const G3: &str = "eeeeeeeeeeeeeeee";
pub const V3: &str = "1111111111111111";
pub const V4: &str = "2222222222222222";

pub fn rotation(h: &History, generation: &str, fact: &Fact, targets: &[usize]) -> Value {
    let wraps: serde_json::Map<_, _> = targets
        .iter()
        .map(|i| {
            (
                h.fps[*i].clone(),
                wrap_for_generation(
                    &h.env,
                    generation,
                    &h.records[*i],
                    0x22 + *i as u8,
                    0x32 + *i as u8,
                ),
            )
        })
        .collect();
    json!({"op":"dek.rotate","generation_id":generation,"removal_fact_hash":fact.hash().unwrap(),"wraps":wraps})
}
pub fn complete_history(case: &str) -> History {
    let mut h = history(match case {
        "C02-owner" => "P3",
        "C03-historical" => "P4",
        "N03-same-commit" => "P5",
        _ => "P1",
    });
    h.name = case.into();
    if case.starts_with('R') || case == "N01-reciprocal" || case == "N02-cycle" {
        h = history("P4");
        h.name = case.into();
        h.history.truncate(5);
        h.facts.clear();
        h.history[4] = h.c(
            3,
            1,
            4500,
            &[(0, 3), (1, 1)],
            vec![json!({"op":"settings.update","sync_interval_seconds":11})],
        );
        if case == "R03-self" {
            h.history.push(h.c(
                3,
                2,
                5000,
                &[(3, 1)],
                vec![json!({"op":"member.remove","fingerprint":h.fps[3]})],
            ));
            h.facts
                .push(h.f(3, "member_removed", json!({"fingerprint":h.fps[3]}), 9000));
            h.facts.push(h.f(
                3,
                "secret_deleted",
                json!({"secret_id":"deleted-empty"}),
                10000,
            ));
        } else {
            let f = h.f(
                1,
                "member_removed",
                json!({"fingerprint":h.fps[3]}),
                if case == "R04-pending" { 9000 } else { 5000 },
            );
            h.history.push(h.c(
                1,
                2,
                6000,
                &[(0, 3), (1, 1), (3, 1)],
                vec![rotation(&h, G2, &f, &[0, 1, 2])],
            ));
            h.facts.push(f);
            if case == "R02-multiple" {
                let f = h.f(0, "member_removed", json!({"fingerprint":h.fps[3]}), 5200);
                h.history.push(h.c(
                    0,
                    4,
                    6500,
                    &[(0, 3), (1, 2), (3, 1)],
                    vec![rotation(&h, G3, &f, &[0, 1, 2])],
                ));
                h.facts.push(f);
            }
            if case == "N01-reciprocal" || case == "N02-cycle" {
                let f = h.f(3, "member_removed", json!({"fingerprint":h.fps[1]}), 5500);
                h.history.push(h.c(
                    3,
                    2,
                    6500,
                    &[(0, 3), (1, 2), (3, 1)],
                    vec![rotation(&h, G3, &f, &[0, 2, 3])],
                ));
                h.facts.push(f);
                if case == "N02-cycle" {
                    // R is promoted before the cuts; the three directed edges
                    // are A->D, D->R, R->A. Every original remains supplied.
                    h.history.pop();
                    h.facts.pop();
                    h.history.push(h.c(
                        0,
                        4,
                        4200,
                        &[(0, 3), (1, 1)],
                        vec![json!({"op":"member.set_role","fingerprint":h.fps[2],"role":"admin"})],
                    ));
                    let d = h.f(3, "member_removed", json!({"fingerprint":h.fps[2]}), 5500);
                    let r = h.f(2, "member_removed", json!({"fingerprint":h.fps[1]}), 5700);
                    h.history.push(h.c(
                        3,
                        2,
                        6500,
                        &[(0, 4), (1, 2), (3, 1)],
                        vec![rotation(&h, G3, &d, &[0, 1, 3])],
                    ));
                    h.history.push(h.c(
                        2,
                        1,
                        7000,
                        &[(0, 4), (1, 2), (3, 2)],
                        vec![rotation(&h, "ffffffffffffffff", &r, &[0, 2, 3])],
                    ));
                    h.facts.extend([d, r]);
                }
            }
        }
    }
    if case == "D01-overlay" {
        h.facts = vec![
            h.f(1, "secret_deleted", json!({"secret_id":SECRET}), 7000),
            h.f(0, "secret_deleted", json!({"secret_id":SECRET}), 8500),
            h.f(
                1,
                "secret_deleted",
                json!({"secret_id":"deleted-empty"}),
                7500,
            ),
            h.f(
                0,
                "secret_version_revoked",
                json!({"secret_id":SECRET,"version_id":V1}),
                8000,
            ),
            h.f(
                2,
                "incident",
                json!({"incident_id":"9999999999999999"}),
                9000,
            ),
        ];
    }
    if case == "D02-policy" {
        for (seq, version, nonce) in [(5, V3, 9), (6, V4, 10)] {
            let public = if seq == 5 {
                json!({"$serde_json::private::RawValue":"not-json","float":load(b"1.0"),"negative_zero":load(b"-0.0"),"big":load(b"-1844674407370955161600000000000000000001")})
            } else {
                json!({})
            };
            h.history.push(h.c(0,seq,2000+seq*1000,&[(0,seq-1),(1,2)],vec![json!({"op":"secret.put_version","secret_id":SECRET,"version_id":version,"generation_id":G,"kind":"api_key","ciphertext":ciphertext(&h.env,version,nonce,b"synthetic-policy"),"public":public})]));
        }
        h.history.push(h.c(0,7,9000,&[(0,6),(1,2)],vec![json!({"op":"secret.set_status","secret_id":SECRET,"version_id":V1,"status":"retired"})]));
        for (seq, kind, id, pin) in [
            (8, "http", "api", Value::Null),
            (9, "ssh", "git", json!(V1)),
        ] {
            let op = connection_op(&h, kind, id, pin);
            h.history
                .push(h.c(0, seq, 2000 + seq * 1000, &[(0, seq - 1), (1, 2)], vec![op]));
        }
        h.facts.push(h.f(
            0,
            "secret_version_revoked",
            json!({"secret_id":SECRET,"version_id":V4}),
            12000,
        ));
    }
    if case == "N03-same-commit" {
        let index = h.history.len() - 1;
        let mut c = h.history[index].to_dict();
        c["ops"]
            .as_array_mut()
            .unwrap()
            .push(json!({"op":"settings.update","sync_interval_seconds":13}));
        resign(&mut c, &h.keys[1]);
        h.history[index] = Commit::from_dict(&c).unwrap();
    }
    h.retained = (0..h.history.len()).collect();
    h
}
pub fn connection_op(_h: &History, kind: &str, id: &str, pin: Value) -> Value {
    let mut op = json!({"op":"connection.create","id":id,"project":"synthetic","environment":"test","service":"controlled","kind":kind,"secret_id":SECRET,"secret_version":pin,"description":"synthetic policy"});
    if kind == "http" {
        op["http_target"] = json!({"scheme":"https","host":"api.example.com","port":443,"ca_file":null,"allow_private_network":false});
        op["http_auth"] = json!({"mode":"header","header_name":"X-API-Key","value_prefix":"","basic_username":null});
        op["http_scope"] = json!({"methods":["GET"],"path_prefixes":["/"],"confirm_methods":[]});
    } else {
        op["ssh_target"] = json!({"host":"ssh.example.com","port":22,"username":"git","host_keys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]});
    }
    op
}

/// Actual ordinary M1 application in isolated synthetic state. These local
/// receipts are solely this independent oracle's inputs and never transported.
pub fn ordinary_effects(h: &History) -> fold::Facts {
    use zeropw::{
        clock,
        context::{Config, Context},
        team::commit::CommitStore,
    };
    let tmp = tempfile::TempDir::new().unwrap();
    let ctx = Context::initialize(
        tmp.path().join("state"),
        "synthetic-only-password",
        "synthetic-only-recovery",
        Config::default(),
        clock::system(),
    )
    .unwrap();
    for c in &h.history {
        CommitStore::new(ctx.state, &h.env).append(c).unwrap();
    }
    let local = DeviceKey::load_or_create(ctx.state, ctx.kms).unwrap();
    for f in &h.facts {
        let hash = f.hash().unwrap();
        let msg = json!({"domain":"zeropw-local-fact-admission-v1","env_id":h.env,"hash":hash});
        let receipt =
            json!({"hash":hash,"sig":pybase64::b64encode(&local.sign(&canon(&msg)).unwrap())});
        ctx.state
            .append_line(
                &format!("team/{}/fact_admissions.jsonl", h.env),
                std::str::from_utf8(&canon(&receipt)).unwrap(),
            )
            .unwrap();
        ctx.state
            .append_line(
                &format!("team/{}/facts.jsonl", h.env),
                std::str::from_utf8(&canon(&f.to_dict())).unwrap(),
            )
            .unwrap();
    }
    let (effects, hashes, _) = sync::load_facts(&ctx, &h.env).unwrap();
    assert_eq!(hashes.len(), h.facts.len());
    effects
}
pub fn ordinary_snapshot(h: &History, effects: &fold::Facts) -> fold::FoldResult {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = zeropw::store::StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    fold::snapshot_of_prefix(
        &h.env,
        h.history.clone(),
        &state,
        Some(effects),
        &h.history,
        None,
    )
    .unwrap()
}

pub fn complete_package(
    h: &History,
    unflushed: Value,
    final_document: &Value,
    order: Value,
    removals: Value,
) -> Package {
    let mut p = h.package();
    let digest = sha(&canon(final_document));
    p.payload["components"][1]["data"]["document"] = unflushed;
    p.payload["components"][1]["data"]["version_order"] = order;
    p.payload["components"][1]["data"]["expected_final_document_sha256"] = json!(digest);
    p.manifest["expected_final_document_sha256"] = json!(digest);
    p.payload["components"][4]["data"] = removals;
    let mut entries = p.payload["components"][5]["data"]["entries"]
        .as_array()
        .unwrap()
        .clone();
    for c in &h.history {
        for (i, op) in c
            .ops
            .iter()
            .enumerate()
            .filter(|(_, op)| op["op"] == "dek.rotate")
        {
            if let Some(wrap) = op["wraps"].get(&h.fps[2]) {
                entries.push(json!({"generation_id":op["generation_id"],"recipient":h.fps[2],"source_commit_hash":c.hash().unwrap(),"source_op_index":i,"wrap":wrap}));
            }
        }
    }
    entries.sort_by(|a, b| {
        (
            a["generation_id"].as_str(),
            a["source_commit_hash"].as_str(),
            a["source_op_index"].as_u64(),
        )
            .cmp(&(
                b["generation_id"].as_str(),
                b["source_commit_hash"].as_str(),
                b["source_op_index"].as_u64(),
            ))
    });
    p.payload["components"][5]["data"]["entries"] = json!(entries);
    p.repair_facts();
    p.rebind(&h.keys[h.signer]);
    p
}
