// Controlled loopback encrypted runtime; independent saved full-history oracle.
use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tempfile::TempDir;
use zeropw::{
    clock,
    context::{Config, Context},
    pyint::PyInt,
    pyjson::{self, DumpOptions},
    team::{
        commit::{self, Commit, CommitStore},
        envelope, fold,
        identity::DeviceKey,
        membership,
        sync::TeamSync,
        transport::{
            HandshakeFailedHook, InviteCheck, InviteProof, MembershipCheck, OnSession, Session,
            SessionClosed, TcpTransport, Transport,
        },
    },
};
static RUNTIME_FIXTURES: Mutex<()> = Mutex::new(());
pub(crate) const PASSWORD: &str = "synthetic-bootstrap-admin";
pub(crate) const GENERATION: &str = "0123456789abcdef";
pub(crate) const VALUE: &[u8] = b"synthetic-personal-vault-value";

fn admin_binary() -> std::path::PathBuf {
    option_env!("CARGO_BIN_EXE_zeropw-admin")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("zeropw-admin")
        })
}

pub(crate) fn admin(ctx: &Context, args: &[&str], envelope: Value) -> Result<Value, String> {
    let mut child = Command::new(admin_binary())
        .arg("--state-dir")
        .arg(&ctx.state.path)
        .arg("--input-envelope")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "spawn_failed".to_owned())?;
    let input = zeropw::secret::SecretBytes::new(
        pyjson::dumps(&envelope, DumpOptions::compact_sorted())
            .unwrap()
            .into_bytes(),
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.expose())
        .unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    if !output.status.success() {
        let error =
            pyjson::loads(std::str::from_utf8(&output.stderr).unwrap_or("")).unwrap_or(Value::Null);
        return Err(error["reason"]
            .as_str()
            .unwrap_or("command_failed")
            .to_owned());
    }
    pyjson::loads(std::str::from_utf8(&output.stdout).map_err(|_| "output_invalid".to_owned())?)
        .map_err(|_| "output_invalid".to_owned())
}
fn context(root: &TempDir, name: &str, clock: clock::Clock) -> Arc<Context> {
    Arc::new(
        Context::initialize(
            root.path().join(name),
            PASSWORD,
            "synthetic-bootstrap-recovery",
            Config::default(),
            clock,
        )
        .unwrap(),
    )
}
struct Stop(Vec<Arc<TeamSync>>);
impl Drop for Stop {
    fn drop(&mut self) {
        for team in self.0.iter().rev() {
            team.stop();
        }
    }
}

fn sign(ctx: &Context, key: &DeviceKey, env: &str, seq: i64, ops: Vec<Value>) -> Commit {
    let store = CommitStore::new(ctx.state, env);
    let c = commit::sign_commit(
        key,
        env,
        seq,
        &format!("{}-0000", 1_000_000 + seq),
        &store.vector().unwrap(),
        ops,
    )
    .unwrap();
    let _lock = ctx.state.lock().unwrap();
    store.append(&c).unwrap();
    c
}

#[derive(Clone, Copy, Default)]
pub(crate) struct FaultMode {
    pub(crate) duplicate_chunks: bool,
    pub(crate) lose_ack_and_expire: bool,
    pub(crate) lose_ready_and_renew: bool,
}
#[derive(Default)]
pub(crate) struct Traffic {
    pub(crate) dropped: AtomicBool,
    pub(crate) ready_dropped: AtomicBool,
    pub(crate) manifests: Mutex<Vec<(String, String, String)>>,
    pub(crate) duplicates: AtomicUsize,
    pub(crate) queries: AtomicUsize,
    pub(crate) offset: AtomicI64,
    pub(crate) expiry_jump: AtomicI64,
}
struct FaultTransport {
    inner: Arc<TcpTransport>,
    mode: FaultMode,
    traffic: Arc<Traffic>,
}
struct FaultSession {
    inner: Arc<dyn Session>,
    mode: FaultMode,
    traffic: Arc<Traffic>,
}
impl Session for FaultSession {
    fn peer(&self) -> zeropw::team::identity::DeviceRecord {
        self.inner.peer()
    }
    fn env_id(&self) -> &str {
        self.inner.env_id()
    }
    fn send(&self, message: &Value) -> zeropw::errors::Result<()> {
        if message["type"] == "BOOTSTRAP_MANIFEST" {
            self.traffic.manifests.lock().unwrap().push((
                message["session_nonce"].as_str().unwrap().into(),
                message["onboarding_nonce"].as_str().unwrap().into(),
                message["transfer_id"].as_str().unwrap().into(),
            ));
        }
        if message["type"] == "BOOTSTRAP_READY"
            && self.mode.lose_ready_and_renew
            && !self.traffic.ready_dropped.swap(true, Ordering::SeqCst)
        {
            self.inner.close();
            return Err(zeropw::Error::state("synthetic_lost_ready"));
        }
        if message["type"] == "BOOTSTRAP_ACK"
            && self.mode.lose_ack_and_expire
            && !self.traffic.dropped.swap(true, Ordering::SeqCst)
        {
            self.traffic.offset.store(
                self.traffic.expiry_jump.load(Ordering::SeqCst),
                Ordering::SeqCst,
            );
            self.inner.close();
            return Err(zeropw::Error::state("synthetic_lost_ack"));
        }
        if message["type"] == "BOOTSTRAP_RECEIPT_QUERY" {
            self.traffic.queries.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.send(message)?;
        if message["type"] == "BOOTSTRAP_CHUNK" && self.mode.duplicate_chunks {
            self.inner.send(message)?;
            self.traffic.duplicates.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
    fn recv(&self, timeout: Duration) -> Result<Option<Value>, SessionClosed> {
        self.inner.recv(timeout)
    }
    fn recv_original(&self, timeout: Duration) -> Result<Option<Vec<u8>>, SessionClosed> {
        self.inner.recv_original(timeout)
    }
    fn close(&self) {
        self.inner.close();
    }
    fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }
    fn created_at(&self) -> Instant {
        self.inner.created_at()
    }
    fn transport_kind(&self) -> Option<&'static str> {
        self.inner.transport_kind()
    }
}
impl Transport for FaultTransport {
    fn set_membership(&self, cb: MembershipCheck) {
        self.inner.set_membership(cb);
    }
    fn set_invite_check(&self, cb: Option<InviteCheck>) {
        self.inner.set_invite_check(cb);
    }
    fn set_handshake_failed(&self, cb: Option<HandshakeFailedHook>) {
        self.inner.set_handshake_failed(cb);
    }
    fn listen(&self, address: &str, callback: OnSession) -> zeropw::errors::Result<()> {
        let mode = self.mode;
        let traffic = self.traffic.clone();
        self.inner.listen(
            address,
            Arc::new(move |inner| {
                callback(Arc::new(FaultSession {
                    inner,
                    mode,
                    traffic: traffic.clone(),
                }))
            }),
        )
    }
    fn dial(
        &self,
        address: &str,
        env: &str,
        proof: Option<InviteProof>,
    ) -> Result<Arc<dyn Session>, SessionClosed> {
        let inner = self.inner.dial(address, env, proof)?;
        Ok(Arc::new(FaultSession {
            inner,
            mode: self.mode,
            traffic: self.traffic.clone(),
        }))
    }
    fn close(&self) {
        self.inner.close();
    }
}

pub(crate) struct Installed {
    _stop: Stop,
    pub(crate) root: TempDir,
    pub(crate) a: Arc<Context>,
    pub(crate) b: Arc<Context>,
    pub(crate) env: String,
    pub(crate) history: Vec<Commit>,
    pub(crate) teams: Vec<Arc<TeamSync>>,
    pub(crate) traffic: Arc<Traffic>,
    pub(crate) upstream: Option<zeropw::fake_upstream::FakeUpstream>,
}

fn differing_paths(left: &Value, right: &Value, path: &str, out: &mut Vec<String>) {
    if left == right {
        return;
    }
    if let (Some(a), Some(b)) = (left.as_object(), right.as_object()) {
        let keys = a
            .keys()
            .chain(b.keys())
            .collect::<std::collections::BTreeSet<_>>();
        for key in keys {
            differing_paths(&left[key], &right[key], &format!("{path}/{key}"), out);
        }
    } else if let (Some(a), Some(b)) = (left.as_array(), right.as_array()) {
        for index in 0..a.len().max(b.len()) {
            differing_paths(
                a.get(index).unwrap_or(&Value::Null),
                b.get(index).unwrap_or(&Value::Null),
                &format!("{path}/{index}"),
                out,
            );
        }
    } else {
        out.push(path.into());
    }
}
pub(crate) fn installed(empty: bool) -> Installed {
    installed_with_fault(empty, FaultMode::default())
}
pub(crate) fn installed_with_fault(empty: bool, mode: FaultMode) -> Installed {
    // A real transfer occupies two process slots (A and B). Keep independent
    // fixtures from competing with the production two-transfer budget.
    let _fixture = RUNTIME_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let traffic = Arc::new(Traffic::default());
    let time = traffic.clone();
    let clock: clock::Clock = Arc::new(move || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
            + time.offset.load(Ordering::SeqCst) as f64
    });
    let root = TempDir::new().unwrap();
    let a = context(&root, "a", clock.clone());
    let b = context(&root, "b", clock);
    let upstream = (!empty).then(|| {
        zeropw::fake_upstream::FakeUpstream::new(std::str::from_utf8(VALUE).unwrap()).start()
    });
    a.projects.create("personal", &["vault"]).unwrap();
    b.projects.create("unrelated", &["dev"]).unwrap();
    let ak = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let bk = DeviceKey::load_or_create(b.state, b.kms).unwrap();
    let afp = ak.fingerprint().unwrap();
    let bfp = bk.fingerprint().unwrap();
    let env = format!("{afp}-0123456789abcdef0123456789abcdef");
    zeropw::team::sync::write_env_mapping(a.state, &env, "personal", "vault").unwrap();
    let wrap = envelope::wrap_dek(&[7; 32], &env, GENERATION, &ak.record().unwrap()).unwrap();
    let init = sign(
        &a,
        &ak,
        &env,
        1,
        vec![
            json!({"op":"env.init","owner_device":ak.record().unwrap().to_dict(),"owner_name":"original-owner","generation_id":GENERATION,"wraps":{afp.clone():wrap}}),
        ],
    );
    let mut history = vec![init];
    let put = |sid: &str, version: &str, status: &str| {
        let cipher = envelope::encrypt_secret(&[7; 32], &env, sid, version, VALUE).unwrap();
        {
            let mut ops = vec![
                json!({"op":"secret.put_version","secret_id":sid,"version_id":version,"generation_id":GENERATION,"kind":"api_key","ciphertext":cipher,"public":{}}),
            ];
            if status == "active" {
                ops.push(json!({"op":"secret.activate","secret_id":sid,"version_id":version}));
            }
            ops
        }
    };
    history.push(sign(
        &a,
        &ak,
        &env,
        2,
        if empty {
            vec![json!({"op":"settings.update","sync_interval_seconds":11})]
        } else {
            put("alpha", "1111111111111111", "active")
        },
    ));
    let at = TcpTransport::new(ak.clone(), Arc::new(|_, _| None), 64);
    let ta = TeamSync::new(
        a.clone(),
        Arc::new(FaultTransport {
            inner: at.clone(),
            mode,
            traffic: traffic.clone(),
        }),
        ak.clone(),
    );
    ta.start(Some("127.0.0.1:0")).unwrap();
    let mut stop = Stop(vec![ta.clone()]);
    assert_eq!(ta.compact(&env).unwrap()["removed"], 1);
    history.push(sign(&a,&ak,&env,3,if empty{vec![json!({"op":"settings.update","sync_interval_seconds":12})]}else{{
        let mut ops=put("alpha","2222222222222222","active");
        ops.extend(put("alpha","3333333333333333","staged"));ops.extend(put("alpha","4444444444444444","staged"));ops.extend(put("deleted","5555555555555555","active"));
        let ssh=zeropw::sshwire::Ed25519PrivateKey::from_seed(&[8;32],"synthetic-personal-user").unwrap();let host=zeropw::sshwire::Ed25519PrivateKey::from_seed(&[9;32],"synthetic-personal-host").unwrap();
        let ciphertext=envelope::encrypt_secret(&[7;32],&env,"ssh-key","6666666666666666",ssh.to_openssh_private_key().as_bytes()).unwrap();
        ops.push(json!({"op":"secret.put_version","secret_id":"ssh-key","version_id":"6666666666666666","generation_id":GENERATION,"kind":"ssh_private_key","ciphertext":ciphertext,"public":{"public_key":ssh.public.to_authorized_key("synthetic-personal-user").unwrap()}}));ops.push(json!({"op":"secret.activate","secret_id":"ssh-key","version_id":"6666666666666666"}));
        ops.push(json!({"op":"connection.create","id":"ssh","project":"personal","environment":"vault","service":"synthetic","kind":"ssh","secret_id":"ssh-key","secret_version":null,"description":"","ssh_target":{"host":"127.0.0.1","port":2222,"username":"deploy","host_keys":[host.public.to_authorized_key("synthetic-personal-host").unwrap()]}}));
        let fake=upstream.as_ref().unwrap();for id in ["live","disabled"]{ops.push(json!({"op":"connection.create","id":id,"project":"personal","environment":"vault","service":"synthetic","kind":"http","secret_id":"alpha","secret_version":null,"description":"","http_target":{"scheme":fake.scheme(),"host":fake.host(),"port":fake.port(),"allow_private_network":true},"http_auth":{"mode":"bearer"},"http_scope":{"methods":["GET"],"path_prefixes":["/data"],"deny_methods":[]}}));}ops
    }}));
    assert_eq!(ta.compact(&env).unwrap()["removed"], 1);
    assert!(
        CommitStore::new(a.state, &env)
            .get(&afp, 2)
            .unwrap()
            .is_none()
    );
    assert!(
        CommitStore::new(a.state, &env)
            .get(&afp, 3)
            .unwrap()
            .is_none()
    );
    let mut effects = fold::Facts::default();
    let mut saved_facts = std::collections::BTreeMap::new();
    if !empty {
        for (kind, target) in [
            (
                "secret_version_revoked",
                json!({"secret_id":"alpha","version_id":"4444444444444444"}),
            ),
            ("connection_disabled", json!({"connection_id":"disabled"})),
            ("secret_deleted", json!({"secret_id":"deleted"})),
        ] {
            let value = ta.publish_fact(&env, kind, target).unwrap();
            let fact = zeropw::team::sync::Fact::from_dict(&value).unwrap();
            saved_facts.insert(fact.hash().unwrap(), value);
        }
        effects
            .revoked_versions
            .insert(("alpha".into(), "4444444444444444".into()));
        effects.disabled_connections.insert("disabled".into());
        effects.deleted_secrets.insert("deleted".into());
        for (hash, value) in &saved_facts {
            if value["kind"] == "secret_deleted" {
                effects.tombstone_facts.insert(hash.clone(), value.clone());
            }
        }
    }
    let address = at.bound_address().unwrap();
    let created = admin(
        &a,
        &[
            "team",
            "invite",
            "--env",
            "personal/vault",
            "--role",
            "admin",
            "--name",
            "fresh-admin",
            "--approval",
            "--personal-bootstrap",
            "--address",
            &address,
        ],
        json!({"admin_passphrase":PASSWORD}),
    )
    .unwrap_or_else(|reason| {
        let events = a
            .state
            .read_lines("audit/audit.jsonl", None)
            .unwrap()
            .iter()
            .map(|line| {
                pyjson::loads(line)
                    .map(|v| v["event"].clone())
                    .unwrap_or(Value::Null)
            })
            .collect::<Vec<_>>();
        panic!("invite refused {reason}; synthetic audit event names {events:?}")
    });
    let invitation = created["invite"].as_str().unwrap();
    let bt = TcpTransport::new(bk.clone(), Arc::new(|_, _| None), 64);
    let tb = TeamSync::new(
        b.clone(),
        Arc::new(FaultTransport {
            inner: bt.clone(),
            mode,
            traffic: traffic.clone(),
        }),
        bk.clone(),
    );
    tb.start(None).unwrap();
    stop.0.push(tb.clone());
    let pending = membership::join(
        &b,
        invitation,
        &bt,
        &tb,
        Some("personal"),
        Some("vault"),
        10.0,
    )
    .unwrap();
    let attempt = b
        .state
        .read_json(&format!("team/{env}/bootstrap/attempt.json"), Value::Null)
        .unwrap();
    let expires = attempt["invitation_expires_at_ms"].as_u64().unwrap() as f64 / 1000.0;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    traffic
        .expiry_jump
        .store((expires - now).ceil() as i64 + 2, Ordering::SeqCst);
    assert_eq!(pending["state"], "approval_pending");
    assert!(b.vault.list_secrets(None, None).unwrap().is_empty());
    assert!(!tb.is_active_member(&env, &bfp));
    let listed = admin(
        &a,
        &["team", "join-requests", "--env", "personal/vault"],
        json!({}),
    )
    .unwrap();
    let request = &listed["requests"][0];
    assert_eq!(request["device_record"], bk.record().unwrap().to_dict());
    let id = request["request_id"].as_str().unwrap();
    let binding = request["record_binding"].as_str().unwrap();
    assert!(
        admin(
            &a,
            &[
                "team",
                "approve-join",
                "--env",
                "personal/vault",
                "--fingerprint",
                &bfp,
                "--bootstrap-request",
                id,
                "--record-binding",
                binding
            ],
            json!({"admin_passphrase":"synthetic-wrong"})
        )
        .is_err()
    );
    admin(
        &a,
        &[
            "team",
            "approve-join",
            "--env",
            "personal/vault",
            "--fingerprint",
            &bfp,
            "--bootstrap-request",
            id,
            "--record-binding",
            binding,
        ],
        json!({"admin_passphrase":PASSWORD}),
    )
    .unwrap();
    assert!(
        admin(
            &b,
            &[
                "team",
                "bootstrap-approve",
                "--env",
                "personal/vault",
                "--record-binding",
                pending["inviter_record_binding"].as_str().unwrap(),
                "--self-record-binding",
                pending["self_record_binding"].as_str().unwrap()
            ],
            json!({"admin_passphrase":"synthetic-wrong"})
        )
        .is_err()
    );
    admin(
        &b,
        &[
            "team",
            "bootstrap-approve",
            "--env",
            "personal/vault",
            "--record-binding",
            pending["inviter_record_binding"].as_str().unwrap(),
            "--self-record-binding",
            pending["self_record_binding"].as_str().unwrap(),
        ],
        json!({"admin_passphrase":PASSWORD}),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut renewed = false;
    loop {
        let status = admin(
            &b,
            &["team", "bootstrap-status", "--env", "personal/vault"],
            json!({}),
        )
        .unwrap();
        if mode.lose_ready_and_renew && !renewed && status["state"] == "unsupported" {
            assert!(!b.state.exists("vault/personal_imports.json"));
            assert!(
                !b.state
                    .exists(&format!("team/{env}/bootstrap/receipt.json"))
            );
            assert!(b.vault.list_secrets(None, None).unwrap().is_empty());
            let next = admin(
                &a,
                &[
                    "team",
                    "invite",
                    "--env",
                    "personal/vault",
                    "--role",
                    "admin",
                    "--name",
                    "renewed-fresh-admin",
                    "--approval",
                    "--personal-bootstrap",
                    "--address",
                    &address,
                ],
                json!({"admin_passphrase":PASSWORD}),
            )
            .unwrap();
            let next = next["invite"].as_str().unwrap();
            loop {
                match membership::join(&b, next, &bt, &tb, Some("personal"), Some("vault"), 10.0) {
                    Ok(_) => break,
                    Err(e) if e.reason == "team_bootstrap_busy" => {
                        assert!(Instant::now() < deadline);
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => panic!("renewal refused: {}", e.reason),
                }
            }
            loop {
                let status = admin(
                    &b,
                    &["team", "bootstrap-status", "--env", "personal/vault"],
                    json!({}),
                )
                .unwrap();
                if status["inviter_record_binding"].as_str().is_some() {
                    admin(
                        &b,
                        &[
                            "team",
                            "bootstrap-approve",
                            "--env",
                            "personal/vault",
                            "--record-binding",
                            status["inviter_record_binding"].as_str().unwrap(),
                            "--self-record-binding",
                            status["self_record_binding"].as_str().unwrap(),
                        ],
                        json!({"admin_passphrase":PASSWORD}),
                    )
                    .unwrap();
                    break;
                }
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(100));
            }
            loop {
                let list = admin(
                    &a,
                    &["team", "join-requests", "--env", "personal/vault"],
                    json!({}),
                )
                .unwrap();
                if let Some(request) = list["requests"].as_array().unwrap().first() {
                    admin(
                        &a,
                        &[
                            "team",
                            "approve-join",
                            "--env",
                            "personal/vault",
                            "--fingerprint",
                            &bfp,
                            "--bootstrap-request",
                            request["request_id"].as_str().unwrap(),
                            "--record-binding",
                            request["record_binding"].as_str().unwrap(),
                        ],
                        json!({"admin_passphrase":PASSWORD}),
                    )
                    .unwrap();
                    break;
                }
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(100));
            }
            renewed = true;
            continue;
        }
        let authorization = a
            .state
            .read_json(
                &format!("team/{env}/bootstrap/authorizations/{bfp}.json"),
                Value::Null,
            )
            .unwrap();
        if matches!(
            status["state"].as_str(),
            Some("installed_syncing" | "ready")
        ) && tb.is_active_member(&env, &bfp)
            && authorization["activated"] == true
        {
            break;
        }
        let sender = a
            .state
            .read_json(
                &format!("team/{env}/bootstrap/sender-status.json"),
                Value::Null,
            )
            .unwrap();
        let validation = b
            .state
            .read_json(
                &format!("team/{env}/bootstrap/validation-status.json"),
                Value::Null,
            )
            .unwrap();
        assert!(
            !matches!(
                status["state"].as_str(),
                Some("unsupported" | "recovery_required")
            ) || (mode.lose_ack_and_expire
                && b.state
                    .exists(&format!("team/{env}/bootstrap/receipt.json"))),
            "runtime refused: {}, from {}; sender metadata {}; validation metadata {}",
            status["reason"],
            status["failed_from"],
            sender,
            validation
        );
        assert!(
            Instant::now() < deadline,
            "runtime timeout; state {} reason {}",
            status["state"],
            status["reason"]
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let retained = CommitStore::new(a.state, &env).all_commits().unwrap();
    let admission = retained
        .iter()
        .find(|c| c.ops.iter().any(|o| o["op"] == "member.add"))
        .unwrap()
        .clone();
    history.push(admission);
    // The signed denies were learned after all saved data originals. Build
    // their expected effects literally over the independent full history;
    // folding a disable before its create would erase that historical ID.
    let mut oracle = fold::fold(&env, history.clone(), None, None, None, None).unwrap();
    if !empty {
        oracle.document["connections"]["disabled"]["status"] = json!("disabled");
        oracle.document["secrets"]["alpha"]["versions"]["4444444444444444"]["status"] =
            json!("revoked");
        oracle.document["secrets"]["deleted"]["deleted"] = json!(true);
        oracle.document["secrets"]["deleted"]["active_version"] = Value::Null;
        for version in oracle.document["secrets"]["deleted"]["versions"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            version["status"] = json!("revoked");
        }
    }
    let actual = membership::load_environment(&b, &env).unwrap();
    let mut differences = Vec::new();
    differing_paths(
        &oracle.document,
        &actual.document,
        "document",
        &mut differences,
    );
    assert!(
        differences.is_empty(),
        "independent full-history document differs at {differences:?}"
    );
    assert!(
        oracle.version_order == actual.version_order,
        "independent version-order differs"
    );
    assert_eq!(actual.document["members"][&bfp]["role"], "admin");
    let wrapped = b
        .state
        .read_json(&format!("team/{env}/dek/{GENERATION}.json"), Value::Null)
        .unwrap();
    let key = b
        .kms
        .unwrap(&zeropw::kms::WrappedKey::from_dict(&wrapped).unwrap())
        .unwrap();
    assert!(key.ct_eq(&[7; 32]), "current edit generation unavailable");
    if !empty {
        for version in [2, 3] {
            let plaintext = b
                .vault
                .secret_for_trusted_use("alpha", Some(PyInt::from(version)))
                .unwrap();
            assert!(
                plaintext.ct_eq(VALUE),
                "synthetic ciphertext authentication failed"
            );
        }
    }
    if !empty {
        assert!(
            b.vault
                .secret_for_trusted_use("alpha", Some(1.into()))
                .is_err()
        );
        assert!(
            b.vault
                .secret_for_trusted_use("alpha", Some(4.into()))
                .is_err()
        );
        assert!(b.vault.secret_for_trusted_use("deleted", None).is_err());
        assert_eq!(
            actual.document["secrets"]["alpha"]["versions"]["1111111111111111"]["status"],
            "retired"
        );
        assert_eq!(
            actual.document["secrets"]["alpha"]["versions"]["4444444444444444"]["status"],
            "revoked"
        );
        assert_eq!(
            actual.document["connections"]["disabled"]["status"],
            "disabled"
        );
    }
    let received = b
        .state
        .read_lines(&format!("team/{env}/facts.jsonl"), None)
        .unwrap()
        .iter()
        .map(|line| {
            let value = pyjson::loads(line).unwrap();
            let fact = zeropw::team::sync::Fact::from_dict(&value).unwrap();
            (fact.hash().unwrap(), value)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert!(received == saved_facts, "original fact set differs");
    assert_eq!(effects.tombstone_facts.len(), usize::from(!empty));
    assert!(b.projects.require_environment("unrelated", "dev").is_ok());
    let first = membership::author_commit(
        &b,
        Some(tb.as_ref()),
        &env,
        vec![json!({"op":"settings.update","sync_interval_seconds":13})],
    )
    .unwrap();
    assert_eq!(first.author_seq, 1);
    assert!(
        commit::Hlc::parse(&first.hlc).unwrap()
            > commit::Hlc::parse(&retained.last().unwrap().hlc).unwrap()
    );
    history.push(first);
    let teams = stop.0.clone();
    Installed {
        _stop: stop,
        root,
        a,
        b,
        env,
        history,
        teams,
        traffic,
        upstream,
    }
}

#[test]
fn personal_bootstrap_runtime_twice_compacted_encrypted_pair_and_continuation() {
    let f = installed(false);
    let backup = f.root.path().join("same-device-backup.json");
    f.b.vault.backup(&backup).unwrap();
    let archive = pyjson::loads(&std::fs::read_to_string(backup).unwrap()).unwrap();
    assert!(
        archive["documents"]["vault/personal_bootstrap_backup.json"]["environments"]
            .get(&f.env)
            .is_some()
    );
    assert!(
        f.a.vault
            .secret_for_trusted_use("alpha", None)
            .unwrap()
            .ct_eq(VALUE)
    );
    assert_eq!(f.history.last().unwrap().author_seq, 1);
    assert_eq!(f.traffic.queries.load(Ordering::SeqCst), 0);
    assert!(f.upstream.as_ref().unwrap().requests().is_empty());
}
#[test]
fn personal_bootstrap_runtime_empty_vault_still_installs_current_edit_generation() {
    let f = installed(true);
    for team in f.teams.iter().rev() {
        team.stop();
    }
    let reopened = Context::open(&f.b.state.path, Config::default(), clock::system()).unwrap();
    let c = membership::author_commit(
        &reopened,
        None,
        &f.env,
        vec![json!({"op":"settings.update","sync_interval_seconds":14})],
    )
    .unwrap();
    assert_eq!(c.author_seq, 2);
    assert!(
        commit::Hlc::parse(&c.hlc).unwrap()
            > commit::Hlc::parse(&f.history.last().unwrap().hlc).unwrap()
    );
}

#[test]
fn personal_bootstrap_runtime_lost_ack_uses_challenged_receipt_after_expiry() {
    let f = installed_with_fault(
        true,
        FaultMode {
            lose_ack_and_expire: true,
            ..Default::default()
        },
    );
    assert!(f.traffic.dropped.load(Ordering::SeqCst));
    assert_eq!(f.traffic.queries.load(Ordering::SeqCst), 1);
    let commits = CommitStore::new(f.a.state, &f.env).all_commits().unwrap();
    assert_eq!(
        commits
            .iter()
            .flat_map(|c| &c.ops)
            .filter(|op| op["op"] == "member.add")
            .count(),
        1
    );
    let receipt =
        f.b.state
            .read_json(
                &format!("team/{}/bootstrap/receipt.json", f.env),
                Value::Null,
            )
            .unwrap();
    let journal =
        f.b.state
            .read_json(
                &format!("team/{}/bootstrap/journal.json", f.env),
                Value::Null,
            )
            .unwrap();
    assert_eq!(receipt, journal["receipt"]);
    assert_eq!(journal["state"], "COMMITTED");
    let receiver =
        f.b.state
            .read_json(
                &format!("team/{}/bootstrap/receiver.json", f.env),
                Value::Null,
            )
            .unwrap();
    assert!(
        ((f.b.clock)() * 1000.0) as u64 > receiver["invitation_expires_at_ms"].as_u64().unwrap()
    );
}
#[test]
fn personal_bootstrap_runtime_identical_chunks_are_idempotent_on_encrypted_frames() {
    let f = installed_with_fault(
        true,
        FaultMode {
            duplicate_chunks: true,
            ..Default::default()
        },
    );
    assert!(f.traffic.duplicates.load(Ordering::SeqCst) > 0);
}

#[test]
fn personal_bootstrap_runtime_lost_ready_renews_both_approvals_without_readmission() {
    let f = installed_with_fault(
        true,
        FaultMode {
            lose_ready_and_renew: true,
            ..Default::default()
        },
    );
    assert!(f.traffic.ready_dropped.load(Ordering::SeqCst));
    let manifests = f.traffic.manifests.lock().unwrap();
    assert_eq!(manifests.len(), 2);
    assert_ne!(manifests[0].0, manifests[1].0);
    assert_ne!(manifests[0].1, manifests[1].1);
    assert_ne!(manifests[0].2, manifests[1].2);
    let commits = CommitStore::new(f.a.state, &f.env).all_commits().unwrap();
    assert_eq!(
        commits
            .iter()
            .flat_map(|c| &c.ops)
            .filter(|op| op["op"] == "member.add")
            .count(),
        1
    );
}

/// A separate synthetic sparse state. Its absent DATA prefix is explicitly
/// administrator-attested; no full-history oracle or CompleteCut is claimed.
pub(crate) fn sparse_installed<T>(
    literal: &str,
    observe: impl FnOnce(&Context, &Context) -> T,
) -> (Installed, T) {
    sparse_installed_with_command(literal, observe, admin)
}
pub(crate) fn sparse_installed_with_command<T>(
    literal: &str,
    observe: impl FnOnce(&Context, &Context) -> T,
    command: impl Fn(&Context, &[&str], Value) -> Result<Value, String>,
) -> (Installed, T) {
    let _fixture = RUNTIME_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let root = TempDir::new().unwrap();
    let a = context(&root, "sparse-a", clock::system());
    let b = context(&root, "sparse-b", clock::system());
    let observed = observe(&a, &b);
    a.projects.create("personal", &["vault"]).unwrap();
    b.projects.create("unrelated", &["dev"]).unwrap();
    let ak = DeviceKey::load_or_create(a.state, a.kms).unwrap();
    let bk = DeviceKey::load_or_create(b.state, b.kms).unwrap();
    let afp = ak.fingerprint().unwrap();
    let bfp = bk.fingerprint().unwrap();
    let env = format!("{afp}-0123456789abcdef0123456789abcdef");
    zeropw::team::sync::write_env_mapping(a.state, &env, "personal", "vault").unwrap();
    let wrap = envelope::wrap_dek(&[7; 32], &env, GENERATION, &ak.record().unwrap()).unwrap();
    let authored_at = commit::now_ms();
    let genesis=commit::sign_commit(&ak,&env,1,&format!("{}-0000",authored_at-3),&std::collections::BTreeMap::new(),vec![json!({"op":"env.init","owner_device":ak.record().unwrap().to_dict(),"owner_name":"original-owner","generation_id":GENERATION,"wraps":{afp.clone():wrap}})]).unwrap();
    CommitStore::new(a.state, &env).append(&genesis).unwrap();
    let huge = PyInt::from_json_integer(&pyjson::loads(literal).unwrap()).unwrap();
    let floor = &huge - 1;
    // Literal synthetic checkpoint. The retained owner signature at the floor
    // binds the exact sparse slot; later runtime attests the whole snapshot.
    let mut seed = fold::fold(&env, vec![genesis.clone()], None, None, None, None).unwrap();
    seed.vector.insert(afp.clone(), floor.clone());
    seed.document["settings"]["sync_interval_seconds"] = json!(12);
    fold::save_snapshot(a.state, &env, &floor, &seed).unwrap();
    let floor_record = commit::sign_commit(
        &ak,
        &env,
        floor.clone(),
        &format!("{}-0000", authored_at - 2),
        &std::collections::BTreeMap::from([(afp.clone(), &floor - 1)]),
        vec![json!({"op":"settings.update","sync_interval_seconds":12})],
    )
    .unwrap();
    a.state
        .write_json(
            &format!("team/{env}/commits/{afp}/{floor}.json"),
            &floor_record.to_dict(),
        )
        .unwrap();
    let ciphertext =
        envelope::encrypt_secret(&[7; 32], &env, "alpha", "1111111111111111", VALUE).unwrap();
    let head=commit::sign_commit(&ak,&env,huge.clone(),&format!("{}-0000",authored_at-1),&std::collections::BTreeMap::from([(afp.clone(),floor.clone())]),vec![json!({"op":"secret.put_version","secret_id":"alpha","version_id":"1111111111111111","generation_id":GENERATION,"kind":"api_key","ciphertext":ciphertext,"public":{}}),json!({"op":"secret.activate","secret_id":"alpha","version_id":"1111111111111111"})]).unwrap();
    assert!(
        commit::Hlc::parse(&genesis.hlc).unwrap() < commit::Hlc::parse(&floor_record.hlc).unwrap()
    );
    assert!(
        commit::Hlc::parse(&floor_record.hlc).unwrap() < commit::Hlc::parse(&head.hlc).unwrap()
    );
    CommitStore::new(a.state, &env).append(&head).unwrap();
    let traffic = Arc::new(Traffic::default());
    let mode = FaultMode::default();
    let at = TcpTransport::new(ak.clone(), Arc::new(|_, _| None), 64);
    let ta = TeamSync::new(
        a.clone(),
        Arc::new(FaultTransport {
            inner: at.clone(),
            mode,
            traffic: traffic.clone(),
        }),
        ak.clone(),
    );
    // Enter the actual Personal invite facade before ordinary membership or
    // discovery can run. This first unconsumed invitation needs no address;
    // the subsequent usable invitation includes the actual bound endpoint.
    let first = command(
        &a,
        &[
            "team",
            "invite",
            "--env",
            "personal/vault",
            "--role",
            "admin",
            "--name",
            "pre-marker-owner",
            "--approval",
            "--personal-bootstrap",
        ],
        json!({"admin_passphrase":PASSWORD}),
    )
    .unwrap();
    assert!(first["record_binding"].is_string());
    assert_eq!(
        CommitStore::new(a.state, &env).vector().unwrap()[&afp],
        huge
    );
    ta.start(Some("127.0.0.1:0")).unwrap();
    let mut stop = Stop(vec![ta.clone()]);
    let address = at.bound_address().unwrap();
    let created = command(
        &a,
        &[
            "team",
            "invite",
            "--env",
            "personal/vault",
            "--role",
            "admin",
            "--name",
            "fresh-admin",
            "--approval",
            "--personal-bootstrap",
            "--address",
            &address,
        ],
        json!({"admin_passphrase":PASSWORD}),
    )
    .unwrap_or_else(|reason| {
        let events = a
            .state
            .read_lines("audit/audit.jsonl", None)
            .unwrap()
            .iter()
            .map(|line| {
                pyjson::loads(line)
                    .map(|v| v["event"].clone())
                    .unwrap_or(Value::Null)
            })
            .collect::<Vec<_>>();
        panic!("invite refused {reason}; synthetic audit event names {events:?}")
    });
    let invitation = created["invite"].as_str().unwrap();
    let bt = TcpTransport::new(bk.clone(), Arc::new(|_, _| None), 64);
    let tb = TeamSync::new(
        b.clone(),
        Arc::new(FaultTransport {
            inner: bt.clone(),
            mode,
            traffic: traffic.clone(),
        }),
        bk.clone(),
    );
    tb.start(None).unwrap();
    stop.0.push(tb.clone());
    let pending = membership::join(
        &b,
        invitation,
        &bt,
        &tb,
        Some("personal"),
        Some("vault"),
        10.0,
    )
    .unwrap();
    let attempt = b
        .state
        .read_json(&format!("team/{env}/bootstrap/attempt.json"), Value::Null)
        .unwrap();
    let expires = attempt["invitation_expires_at_ms"].as_u64().unwrap() as f64 / 1000.0;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    traffic
        .expiry_jump
        .store((expires - now).ceil() as i64 + 2, Ordering::SeqCst);
    assert_eq!(pending["state"], "approval_pending");
    assert!(b.vault.list_secrets(None, None).unwrap().is_empty());
    assert!(!tb.is_active_member(&env, &bfp));
    let listed = command(
        &a,
        &["team", "join-requests", "--env", "personal/vault"],
        json!({}),
    )
    .unwrap();
    let request = &listed["requests"][0];
    assert_eq!(request["device_record"], bk.record().unwrap().to_dict());
    let id = request["request_id"].as_str().unwrap();
    let binding = request["record_binding"].as_str().unwrap();
    assert!(
        command(
            &a,
            &[
                "team",
                "approve-join",
                "--env",
                "personal/vault",
                "--fingerprint",
                &bfp,
                "--bootstrap-request",
                id,
                "--record-binding",
                binding
            ],
            json!({"admin_passphrase":"synthetic-wrong"})
        )
        .is_err()
    );
    command(
        &a,
        &[
            "team",
            "approve-join",
            "--env",
            "personal/vault",
            "--fingerprint",
            &bfp,
            "--bootstrap-request",
            id,
            "--record-binding",
            binding,
        ],
        json!({"admin_passphrase":PASSWORD}),
    )
    .unwrap();
    assert!(
        command(
            &b,
            &[
                "team",
                "bootstrap-approve",
                "--env",
                "personal/vault",
                "--record-binding",
                pending["inviter_record_binding"].as_str().unwrap(),
                "--self-record-binding",
                pending["self_record_binding"].as_str().unwrap()
            ],
            json!({"admin_passphrase":"synthetic-wrong"})
        )
        .is_err()
    );
    command(
        &b,
        &[
            "team",
            "bootstrap-approve",
            "--env",
            "personal/vault",
            "--record-binding",
            pending["inviter_record_binding"].as_str().unwrap(),
            "--self-record-binding",
            pending["self_record_binding"].as_str().unwrap(),
        ],
        json!({"admin_passphrase":PASSWORD}),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = command(
            &b,
            &["team", "bootstrap-status", "--env", "personal/vault"],
            json!({}),
        )
        .unwrap();
        let authorization = a
            .state
            .read_json(
                &format!("team/{env}/bootstrap/authorizations/{bfp}.json"),
                Value::Null,
            )
            .unwrap();
        if matches!(
            status["state"].as_str(),
            Some("installed_syncing" | "ready")
        ) && tb.is_active_member(&env, &bfp)
            && authorization["activated"] == true
        {
            break;
        }
        let sender = a
            .state
            .read_json(
                &format!("team/{env}/bootstrap/sender-status.json"),
                Value::Null,
            )
            .unwrap();
        let validation = b
            .state
            .read_json(
                &format!("team/{env}/bootstrap/validation-status.json"),
                Value::Null,
            )
            .unwrap();
        if matches!(
            status["state"].as_str(),
            Some("unsupported" | "recovery_required")
        ) {
            let mut known = vec![genesis.clone(), floor_record.clone(), head.clone()];
            if let Some(c) = CommitStore::new(a.state, &env)
                .get(&afp, &huge + 1)
                .unwrap()
            {
                known.push(c);
            }
            let retained = fold::fold(&env, known, None, None, None, None).unwrap();
            let actual = membership::load_environment(&a, &env).unwrap();
            let mut paths = Vec::new();
            for key in ["owner", "members", "dek"] {
                differing_paths(
                    &retained.document[key],
                    &actual.document[key],
                    key,
                    &mut paths,
                );
            }
            println!(
                "PVBOOT_SPARSE_AUTHORITY_PATHS {}",
                json!({"differences":paths.into_iter().take(16).collect::<Vec<_>>()})
            );
        }
        assert!(
            !matches!(
                status["state"].as_str(),
                Some("unsupported" | "recovery_required")
            ),
            "runtime refused: {}, from {}; sender metadata {}; validation metadata {}",
            status["reason"],
            status["failed_from"],
            sender,
            validation
        );
        assert!(
            Instant::now() < deadline,
            "runtime timeout; state {} reason {}",
            status["state"],
            status["reason"]
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let admission = CommitStore::new(a.state, &env)
        .get(&afp, &huge + 1)
        .unwrap()
        .unwrap();
    assert_eq!(admission.author_seq, &huge + 1);
    assert_eq!(
        admission
            .ops
            .iter()
            .filter(|o| o["op"] == "member.add")
            .count(),
        1
    );
    let receipt = b
        .state
        .read_json(&format!("team/{env}/bootstrap/receipt.json"), Value::Null)
        .unwrap();
    assert_eq!(
        PyInt::from_json_integer(&receipt["vector"][&afp]).unwrap(),
        &huge + 1
    );
    for original in [&genesis, &floor_record, &head, &admission] {
        let retained = CommitStore::new(b.state, &env)
            .get(&afp, &original.author_seq)
            .unwrap()
            .unwrap();
        assert_eq!(retained.to_dict(), original.to_dict());
        assert_eq!(retained.hash().unwrap(), original.hash().unwrap());
    }
    assert_eq!(
        CommitStore::new(b.state, &env).vector().unwrap()[&afp],
        &huge + 1
    );
    assert!(
        b.vault
            .secret_for_trusted_use("alpha", None)
            .unwrap()
            .ct_eq(VALUE)
    );
    let teams = stop.0.clone();
    (
        Installed {
            _stop: stop,
            root,
            a,
            b,
            env,
            history: vec![genesis, floor_record, head, admission],
            teams,
            traffic,
            upstream: None,
        },
        observed,
    )
}

#[test]
fn personal_bootstrap_runtime_sparse_literal_10_40_real_onboarding_and_delta() {
    sparse_onboarding_and_delta("10000000000000000000000000000000000000000");
}
#[test]
fn personal_bootstrap_runtime_sparse_literal_10_80_real_onboarding_and_delta() {
    sparse_onboarding_and_delta(
        "100000000000000000000000000000000000000000000000000000000000000000000000000000000",
    );
}
pub(crate) fn sparse_onboarding_and_delta(literal: &str) {
    let (f, ()) = sparse_installed(literal, |_, _| ());
    sparse_continue_with_command(&f, literal, admin);
}
pub(crate) fn sparse_continue_with_command(
    f: &Installed,
    literal: &str,
    command: impl Fn(&Context, &[&str], Value) -> Result<Value, String>,
) {
    let huge = PyInt::from_json_integer(&pyjson::loads(literal).unwrap()).unwrap();
    let afp = DeviceKey::load_or_create(f.a.state, f.a.kms)
        .unwrap()
        .fingerprint()
        .unwrap();
    let bfp = DeviceKey::load_or_create(f.b.state, f.b.kms)
        .unwrap()
        .fingerprint()
        .unwrap();
    let delta = membership::author_commit(
        &f.b,
        Some(f.teams[1].as_ref()),
        &f.env,
        vec![json!({"op":"settings.update","sync_interval_seconds":17})],
    )
    .unwrap();
    assert_eq!(delta.author_seq, 1);
    let deadline = Instant::now() + Duration::from_secs(35);
    while CommitStore::new(f.a.state, &f.env)
        .get(&bfp, 1)
        .unwrap()
        .is_none()
    {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(100));
    }
    let authored = membership::author_commit(
        &f.a,
        Some(f.teams[0].as_ref()),
        &f.env,
        vec![json!({"op":"settings.update","sync_interval_seconds":19})],
    )
    .unwrap();
    assert_eq!(authored.author_seq, &huge + 2);
    while CommitStore::new(f.b.state, &f.env)
        .get(&afp, &huge + 2)
        .unwrap()
        .is_none()
    {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(100));
    }
    for ctx in [&f.a, &f.b] {
        let log = command(ctx, &["team", "log", "--env", "personal/vault"], json!({})).unwrap();
        assert_eq!(log["log"].as_array().unwrap().len(), 6);
        let head = authored.hash().unwrap();
        command(
            ctx,
            &["team", "diff", "--env", "personal/vault", &head, &head],
            json!({}),
        )
        .unwrap();
        let doc = membership::load_environment(ctx, &f.env).unwrap();
        assert_eq!(doc.vector[&afp], &huge + 2);
        assert_eq!(doc.vector[&bfp], 1);
        assert!(
            ctx.vault
                .secret_for_trusted_use("alpha", None)
                .unwrap()
                .ct_eq(VALUE)
        );
    }
}
