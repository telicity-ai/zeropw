//! A separate, already-open trusted process retains its handles and signer
//! binding while the parent damages and restores actual imported evidence.
#[path = "team_personal_bootstrap_runtime.rs"]
mod runtime;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    process::{Child, ChildStdin, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use zeropw::{
    clock,
    context::{Config, Context},
    gateway,
    policy::Connection,
    pyjson, signer, sshwire,
};

struct ReaderProcess {
    child: Child,
    input: Option<ChildStdin>,
    output: std::sync::mpsc::Receiver<Value>,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl ReaderProcess {
    fn sample(&mut self) -> Value {
        self.input.as_mut().unwrap().write_all(b"sample\n").unwrap();
        self.output
            .recv_timeout(Duration::from_secs(10))
            .expect("owned reader child must return bounded metadata")
    }
    fn finish(&mut self) {
        self.input.take();
        assert!(self.child.wait().unwrap().success());
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
}
impl Drop for ReaderProcess {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
fn connect(path: &std::path::Path) -> sshwire::AgentConnection<UnixStream> {
    let socket = UnixStream::connect(path).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    sshwire::AgentConnection::new(socket)
}
fn bind(client: &mut sshwire::AgentConnection<UnixStream>) {
    let host = sshwire::Ed25519PrivateKey::from_seed(&[9; 32], "synthetic-personal-host").unwrap();
    let session = [3; 32];
    let signature = sshwire::encode_ssh_signature(&host.sign(&session)).unwrap();
    assert_eq!(
        client
            .request(&sshwire::build_session_bind(
                &host.public.blob(),
                &session,
                &signature,
                false
            ))
            .unwrap(),
        sshwire::build_success()
    );
}
fn sign(client: &mut sshwire::AgentConnection<UnixStream>) -> bool {
    let key = sshwire::Ed25519PrivateKey::from_seed(&[8; 32], "synthetic-personal-user").unwrap();
    let data = sshwire::build_userauth_request(
        &[3; 32],
        "deploy",
        "ssh-ed25519",
        &key.public.blob(),
        sshwire::SSH_CONNECTION_SERVICE,
        None,
    );
    let response = client
        .request(&sshwire::build_sign_request(&key.public.blob(), &data, 0))
        .unwrap();
    response.first() == Some(&sshwire::SSH_AGENT_SIGN_RESPONSE)
}

#[test]
fn personal_bootstrap_visibility_reader_child() {
    let Some(path) = std::env::var_os("PVBOOT_VISIBILITY_OWN_STATE") else {
        return;
    };
    let ctx = Arc::new(Context::open(path, Config::default(), clock::system()).unwrap());
    let manager = signer::install(ctx.clone(), None).unwrap();
    let mut handles = Vec::new();
    let mut bindings = Vec::new();
    for id in ["live", "unrelated-http", "ssh", "unrelated-ssh"] {
        let cached = ctx.policy.get_connection(id).unwrap();
        let grant = ctx
            .policy
            .create_grant("visibility", id, Some(3600), None)
            .unwrap();
        if cached.kind == "http" {
            handles.push(
                ctx.handles
                    .issue(
                        "visibility",
                        id,
                        &grant.id,
                        cached.policy_version,
                        3600,
                        None,
                    )
                    .unwrap(),
            );
        } else {
            bindings.push(manager.bind("visibility", id, &grant.id).unwrap());
        }
    }
    let mut target = connect(&bindings[0].socket_path);
    let mut unrelated = connect(&bindings[1].socket_path);
    bind(&mut target);
    bind(&mut unrelated);
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        assert_eq!(line.unwrap(), "sample");
        let replies = handles
            .iter()
            .map(|handle| {
                gateway::relay(
                    &ctx,
                    handle,
                    "GET",
                    "/data",
                    &gateway::Headers::new(),
                    b"",
                    None,
                )
                .relayed()
            })
            .collect::<Vec<_>>();
        let visible = ctx
            .vault
            .list_secrets(None, None)
            .unwrap()
            .iter()
            .any(|s| s.id == "alpha");
        let value = json!({"credential":ctx.vault.secret_for_trusted_use("alpha",None).is_ok(),"listed":visible,"connection":ctx.policy.get_connection("live").is_ok(),"http":replies[0],"unrelated_http":replies[1],"ssh":sign(&mut target),"unrelated_ssh":sign(&mut unrelated)});
        writeln!(stdout, "\nPVBOOT_SAMPLE {value}").unwrap();
        stdout.flush().unwrap();
    }
    manager.shutdown();
}

#[test]
fn personal_bootstrap_visibility_running_process_cached_handles_and_signer_fail_closed() {
    let f = runtime::installed(false);
    for team in f.teams.iter().rev() {
        team.stop();
    }
    f.b.vault
        .put_secret(
            "unrelated-token",
            "api_key",
            runtime::VALUE,
            "unrelated",
            "dev",
            true,
        )
        .unwrap();
    let key = sshwire::Ed25519PrivateKey::from_seed(&[8; 32], "synthetic-personal-user").unwrap();
    f.b.vault
        .put_secret(
            "unrelated-key",
            "ssh_private_key",
            key.to_openssh_private_key().as_bytes(),
            "unrelated",
            "dev",
            true,
        )
        .unwrap();
    for (source, id, secret) in [
        ("live", "unrelated-http", "unrelated-token"),
        ("ssh", "unrelated-ssh", "unrelated-key"),
    ] {
        let doc =
            f.b.state
                .read_json(zeropw::policy::CONNECTIONS, Value::Null)
                .unwrap();
        let mut copy = doc[source].clone();
        copy["id"] = json!(id);
        copy["secret_id"] = json!(secret);
        copy["shared_env"] = Value::Null;
        copy["project"] = json!("unrelated");
        copy["environment"] = json!("dev");
        f.b.policy
            .create_connection(Connection::from_value(&copy).unwrap())
            .unwrap();
    }
    f.b.policy
        .create_principal("visibility", "synthetic")
        .unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "personal_bootstrap_visibility_reader_child",
            "--nocapture",
        ])
        .env("PVBOOT_VISIBILITY_OWN_STATE", &f.b.state.path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let input = child.stdin.take();
    let output = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            let line = line.unwrap();
            if let Some(json) = line.strip_prefix("PVBOOT_SAMPLE ")
                && tx.send(pyjson::loads(json).unwrap()).is_err()
            {
                break;
            }
        }
    });
    let mut child = ReaderProcess {
        child,
        input,
        output: rx,
        reader: Some(reader),
    };
    let allowed = json!({"credential":true,"listed":true,"connection":true,"http":true,"unrelated_http":true,"ssh":true,"unrelated_ssh":true});
    let denied = json!({"credential":false,"listed":false,"connection":false,"http":false,"unrelated_http":true,"ssh":false,"unrelated_ssh":true});
    assert_eq!(child.sample(), allowed);
    let root = &f.b.state.path;
    for (path, damage) in [
        ("vault/personal_imports.json".to_owned(), b"{".to_vec()),
        ("vault/personal_imports.json".to_owned(), b"{}".to_vec()),
        (
            format!("team/{}/bootstrap/journal.json", f.env),
            b"{".to_vec(),
        ),
        (
            format!("team/{}/bootstrap/provenance/payload.json", f.env),
            b"{}".to_vec(),
        ),
    ] {
        let path = root.join(path);
        let original = std::fs::read(&path).unwrap();
        {
            let _lock = f.b.state.lock().unwrap();
            std::fs::write(&path, &damage).unwrap();
        }
        assert_eq!(
            child.sample(),
            denied,
            "corruption must hide only the imported environment"
        );
        {
            let _lock = f.b.state.lock().unwrap();
            std::fs::write(path, original).unwrap();
        }
        assert_eq!(child.sample(), allowed);
    }
    let bk = zeropw::team::identity::DeviceKey::load_or_create(f.b.state, f.b.kms).unwrap();
    let bfp = bk.fingerprint().unwrap();
    let removal = zeropw::team::membership::author_commit(
        &f.b,
        None,
        &f.env,
        vec![json!({"op":"member.remove","fingerprint":bfp})],
    )
    .unwrap();
    assert_eq!(removal.author_seq, 2);
    assert!(
        !f.b.state
            .exists(&format!("team/{}/bootstrap/member-removed.json", f.env))
    );
    assert!(f.b.state.exists(&format!(
        "team/{}/bootstrap/local-removal-denial.json",
        f.env
    )));
    assert_eq!(
        child.sample(),
        denied,
        "cached separate process must deny before FACT"
    );
    assert_eq!(
        child.sample(),
        denied,
        "fresh attempts cannot reuse cached authorization"
    );
    assert!(
        f.b.policy
            .create_grant("visibility", "live", Some(3600), None)
            .is_err()
    );
    println!(
        "PVBOOT_CACHED_REMOVAL_READERS {}",
        json!({"real_signed_sequence":removal.author_seq,"before_fact":true,"cached_http_denied":true,"cached_ssh_denied":true,"trusted_and_list_denied":true,"unrelated_available":true})
    );
    child.finish();
    assert!(f.upstream.as_ref().unwrap().requests().len() >= 10);
}
