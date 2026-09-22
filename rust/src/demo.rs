//! One-command, synthetic-only demonstration of gateway, CLI, SSH signer and incident boundaries.
use std::fs;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::agent_cli;
use crate::context::{Config, Context};
use crate::errors::Error;
use crate::fake_upstream::FakeUpstream;
use crate::policy::{CliProfile, Connection, HttpAuth, HttpScope, HttpTarget, SshTarget};
use crate::sshwire;

const ADMIN: &str = "demo-admin-passphrase";
const RECOVERY: &str = "demo-recovery-passphrase";

struct Demo {
    checks: usize,
    failures: Vec<String>,
    visible: Vec<String>,
}
impl Demo {
    fn new() -> Self {
        Self {
            checks: 0,
            failures: Vec::new(),
            visible: Vec::new(),
        }
    }
    fn say(&self, text: &str) {
        println!("{text}");
    }
    fn check(&mut self, ok: bool, label: &str) {
        self.checks += 1;
        println!("  [{}] {label}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            self.failures.push(label.into());
        }
    }
    fn call(&mut self, url: &str, token: &str, tool: &str, payload: Value) -> (u16, Value) {
        let (status, body) = agent_cli::call_tool(url, token, tool, &payload);
        self.visible
            .push(json!({"tool":tool,"status":status,"body":body}).to_string());
        (status, body)
    }
    fn wait_run(&mut self, url: &str, token: &str, id: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let (_, body) = self.call(url, token, "status", json!({"run_id":id}));
            if ["completed", "failed", "cancelled", "blocked"]
                .contains(&body["state"].as_str().unwrap_or(""))
                || Instant::now() > deadline
            {
                return body;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

fn temp_root() -> Result<PathBuf, Error> {
    let path = std::env::temp_dir().join(format!("zeropw-rust-demo-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&path).map_err(|_| Error::state("demo_temp_failed"))?;
    Ok(path)
}
fn read_state_text(path: &Path, out: &mut String) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                read_state_text(&path, out)
            } else if let Ok(bytes) = fs::read(path) {
                out.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
    }
}

fn run_inner(d: &mut Demo, root: &Path) -> Result<(), Error> {
    d.say("[1] Synthetic state and trusted process");
    let ctx = Arc::new(Context::initialize(
        root.join("state"),
        ADMIN,
        RECOVERY,
        Config {
            handle_ttl_seconds: 300,
            ..Config::default()
        },
        crate::clock::system(),
    )?);
    ctx.projects.create("demo", &["dev", "staging", "prod"])?;
    let synthetic = format!("synthetic-token-{}", uuid::Uuid::new_v4().simple());
    ctx.vault.put_secret(
        "gh-token",
        "api_key",
        synthetic.as_bytes(),
        "demo",
        "dev",
        true,
    )?;
    let mut upstream = FakeUpstream::new(synthetic.clone()).start();
    let program = std::env::current_exe()
        .map_err(|_| Error::state("demo_program_missing"))?
        .with_file_name("zeropw-democli");
    if !program.is_file() {
        upstream.stop();
        return Err(Error::state("demo_program_missing"));
    }
    let http = Connection::new(
        "gh",
        "demo",
        "dev",
        "fake-code-host",
        "http",
        "gh-token",
        None,
        "demo code hosting API",
        Some(HttpTarget::new(
            "http",
            "127.0.0.1",
            i64::from(upstream.port()),
            None,
            false,
        )?),
        Some(HttpAuth::bearer()),
        Some(HttpScope::new(
            Some(vec!["GET".into(), "POST".into(), "DELETE".into()]),
            None,
            vec!["DELETE".into()],
        )?),
        None,
        Some(CliProfile::new(
            program.to_string_lossy().to_string(),
            "http",
            None,
            Default::default(),
        )?),
        0,
        "active",
        "",
        "",
    )?;
    ctx.policy.create_connection(http)?;
    let user_key = sshwire::generate_ed25519_private_key("demo-agent");
    let host_key = sshwire::generate_ed25519_private_key("demo-box");
    ctx.vault.put_secret(
        "box-key",
        "ssh_private_key",
        user_key.to_openssh_private_key().as_bytes(),
        "demo",
        "dev",
        true,
    )?;
    let host_line = host_key
        .public
        .to_authorized_key("demo-box")
        .map_err(|_| Error::state("demo_ssh_failed"))?;
    let ssh = Connection::new(
        "box",
        "demo",
        "dev",
        "ssh-box",
        "ssh",
        "box-key",
        None,
        "demo SSH destination",
        None,
        None,
        None,
        Some(SshTarget::new(
            "demo-box.internal",
            22,
            "deploy",
            vec![host_line],
        )?),
        None,
        0,
        "active",
        "",
        "",
    )?;
    ctx.policy.create_connection(ssh)?;
    let token = ctx.policy.create_principal("agent-1", "default")?;
    let http_grant = ctx
        .policy
        .create_grant("agent-1", "gh", Some(600), Some(50))?;
    let ssh_grant = ctx
        .policy
        .create_grant("agent-1", "box", Some(600), Some(10))?;
    let server = crate::server::ZeroPWServer::new(ctx.clone(), None, None)?;
    server.serve_in_thread()?;
    let url = server.url();
    d.say("    Agent holds only a gateway URL and caller token; no vault value.");

    d.say("[2] One connection, multiple unregistered operations");
    let (status, body) = d.call(&url, &token, "list_connections", json!({}));
    let mut ids = body["connections"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v["id"].as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    ids.sort_unstable();
    d.check(
        status == 200 && ids == ["box", "gh"],
        "both HTTP and SSH connections listed",
    );
    d.check(
        !body.to_string().contains("secret_id"),
        "connection listing has no secret reference or value",
    );
    let (_, body) = d.call(
        &url,
        &token,
        "request",
        json!({"connection":"gh","method":"GET","path":"/repos"}),
    );
    d.check(
        body["status"] == 200 && body["body"].as_str().unwrap_or("").contains("demo"),
        "GET /repos returns business data",
    );
    let (_,body)=d.call(&url,&token,"request",json!({"connection":"gh","method":"POST","path":"/repos/demo/issues","body":"{\"title\":\"hello from agent\"}"}));
    d.check(
        body["status"] == 201,
        "POST creates an issue on the same connection",
    );
    for (argv, expected) in [
        (json!(["list-repos"]), 200),
        (json!(["create-issue", "demo", "issue via cli"]), 201),
    ] {
        let (_, started) = d.call(&url, &token, "exec", json!({"connection":"gh","argv":argv}));
        let done = d.wait_run(&url, &token, started["run_id"].as_str().unwrap_or(""));
        d.check(
            done["state"] == "completed"
                && done["stdout"]
                    .as_str()
                    .unwrap_or("")
                    .contains(&format!("\"status\":{expected}")),
            if expected == 200 {
                "native CLI reads repos"
            } else {
                "native CLI creates issue"
            },
        );
    }
    let recorded = upstream.requests();
    d.check(
        recorded.len() >= 4
            && recorded
                .iter()
                .all(|r| r.headers.get("authorization") == Some(&format!("Bearer {synthetic}"))),
        "upstream receives only the real synthetic credential",
    );

    d.say("[3] Extraction, reflection and scope refusal");
    let (_, started) = d.call(
        &url,
        &token,
        "exec",
        json!({"connection":"gh","argv":["steal"]}),
    );
    let done = d.wait_run(&url, &token, started["run_id"].as_str().unwrap_or(""));
    let stdout = done["stdout"].as_str().unwrap_or("");
    d.check(
        done["state"] == "completed" && !stdout.contains(&synthetic) && !stdout.contains("zpw1."),
        "CLI environment exposes no credential or handle",
    );
    let names = serde_json::from_str::<Value>(stdout)
        .ok()
        .map(|v| v["env_names"].clone())
        .unwrap_or(Value::Null);
    d.check(
        names.as_array().is_some_and(|a| {
            a.iter().any(|v| v == "ZEROPW_API_BASE_URL")
                && !a
                    .iter()
                    .any(|v| v.as_str().is_some_and(|s| s.starts_with("ZEROPW_STATE")))
        }),
        "child receives routing only, not state authority",
    );
    for (method, path, reason, label) in [
        (
            "GET",
            "/echo-headers",
            "credential_reflection_blocked",
            "echoed auth header blocked",
        ),
        (
            "GET",
            "/debug/token",
            "credential_reflection_blocked",
            "debug token endpoint blocked",
        ),
        (
            "GET",
            "/base64-leak",
            "credential_reflection_blocked",
            "encoded token reflection blocked",
        ),
        (
            "GET",
            "/set-cookie",
            "credential_reflection_blocked",
            "cookie reflection blocked",
        ),
        (
            "GET",
            "/redirect",
            "redirect_not_followed",
            "redirect not followed",
        ),
        (
            "PUT",
            "/repos",
            "method_not_allowed",
            "out-of-scope method denied",
        ),
    ] {
        let (_, body) = d.call(
            &url,
            &token,
            "request",
            json!({"connection":"gh","method":method,"path":path}),
        );
        d.check(
            body["reason"] == reason && !body.to_string().contains(&synthetic),
            label,
        );
    }
    let (_, approval) = d.call(
        &url,
        &token,
        "request",
        json!({"connection":"gh","method":"DELETE","path":"/repos/demo"}),
    );
    let digest = approval["approval_digest"]
        .as_str()
        .map(str::to_owned)
        .or_else(|| {
            approval["body"]
                .as_str()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .and_then(|v| v["approval_digest"].as_str().map(str::to_owned))
        });
    d.check(
        approval["status"] == 428 && digest.is_some(),
        "risky DELETE requires one-shot approval",
    );
    if let Some(digest) = digest {
        ctx.policy.approve(&digest)?;
        let (_, body) = d.call(
            &url,
            &token,
            "request",
            json!({"connection":"gh","method":"DELETE","path":"/repos/demo"}),
        );
        d.check(body["status"] == 204, "approved DELETE succeeds");
        let (_, body) = d.call(
            &url,
            &token,
            "request",
            json!({"connection":"gh","method":"DELETE","path":"/repos/demo"}),
        );
        d.check(body["status"] == 428, "approval cannot be replayed");
    }

    d.say("[4] SSH signing bound to destination and session");
    let manager =
        crate::tools::signer_manager(&ctx).ok_or_else(|| Error::state("demo_signer_missing"))?;
    let binding = manager.bind("agent-1", "box", &ssh_grant.id)?;
    let session_id = [7u8; 32];
    let auth = sshwire::build_userauth_request(
        &session_id,
        "deploy",
        "ssh-ed25519",
        &user_key.public.blob(),
        "ssh-connection",
        None,
    );
    let mut conn = sshwire::AgentConnection::new(
        UnixStream::connect(&binding.socket_path).map_err(|_| Error::state("demo_ssh_failed"))?,
    );
    let identities = conn
        .request(&[sshwire::SSH_AGENTC_REQUEST_IDENTITIES])
        .map_err(|_| Error::state("demo_ssh_failed"))?;
    let keys = sshwire::parse_identities_answer(identities.get(1..).unwrap_or(&[]))
        .map_err(|_| Error::state("demo_ssh_failed"))?;
    d.check(
        keys.len() == 1 && keys[0].0 == user_key.public.blob(),
        "only bound public key is listed",
    );
    d.check(
        conn.request(&sshwire::build_sign_request(
            &user_key.public.blob(),
            &auth,
            0,
        ))
        .ok()
        .as_deref()
            == Some(sshwire::build_failure().as_slice()),
        "signing before session bind refused",
    );
    let sig = sshwire::encode_ssh_signature(&host_key.sign(&session_id))
        .map_err(|_| Error::state("demo_ssh_failed"))?;
    let bind = sshwire::build_session_bind(&host_key.public.blob(), &session_id, &sig, false);
    d.check(
        conn.request(&bind).ok().as_deref() == Some(sshwire::build_success().as_slice()),
        "valid destination session bind accepted",
    );
    let response = conn
        .request(&sshwire::build_sign_request(
            &user_key.public.blob(),
            &auth,
            0,
        ))
        .map_err(|_| Error::state("demo_ssh_failed"))?;
    let signature = response
        .get(1..)
        .and_then(|b| sshwire::parse_sign_response(b).ok())
        .and_then(|b| sshwire::parse_ssh_signature(&b).ok());
    d.check(
        response.first() == Some(&sshwire::SSH_AGENT_SIGN_RESPONSE)
            && signature
                .as_ref()
                .is_some_and(|s| user_key.public.verify(&auth, s)),
        "bound userauth signature verifies",
    );
    d.check(
        conn.request(&sshwire::build_sign_request(
            &user_key.public.blob(),
            b"arbitrary bytes",
            0,
        ))
        .ok()
        .as_deref()
            == Some(sshwire::build_failure().as_slice()),
        "arbitrary-byte signing refused",
    );
    let wrong_user = sshwire::build_userauth_request(
        &session_id,
        "root",
        "ssh-ed25519",
        &user_key.public.blob(),
        "ssh-connection",
        None,
    );
    d.check(
        conn.request(&sshwire::build_sign_request(
            &user_key.public.blob(),
            &wrong_user,
            0,
        ))
        .ok()
        .as_deref()
            == Some(sshwire::build_failure().as_slice()),
        "wrong username signing refused",
    );
    d.check(
        conn.request(&[sshwire::SSH_AGENTC_REMOVE_ALL_IDENTITIES])
            .ok()
            .as_deref()
            == Some(sshwire::build_failure().as_slice()),
        "key deletion command refused",
    );
    drop(conn);
    binding.close();

    d.say("[5] Revocation and global stop");
    ctx.policy.revoke_grant(&http_grant.id)?;
    let (_, body) = d.call(
        &url,
        &token,
        "request",
        json!({"connection":"gh","method":"GET","path":"/repos"}),
    );
    d.check(
        body["reason"] == "grant_revoked",
        "revoked grant refuses next request",
    );
    ctx.policy.stop_all()?;
    let (_, body) = d.call(&url, &token, "list_connections", json!({}));
    d.check(
        body["connections"].as_array().is_some_and(Vec::is_empty),
        "global stop hides usable connections",
    );
    ctx.policy.resume()?;
    let (_, body) = d.call(&url, &token, "list_connections", json!({}));
    d.check(
        body["connections"]
            .as_array()
            .is_some_and(|a| a.len() == 1 && a[0]["id"] == "box"),
        "resume preserves only non-revoked SSH grant",
    );

    d.say("[6] Value-free output and state sweep");
    let visible = d.visible.join("\n");
    let encodings = [
        synthetic.clone(),
        crate::pybase64::b64encode(synthetic.as_bytes()),
        hex::encode(synthetic.as_bytes()),
    ];
    d.check(
        !encodings.iter().any(|e| visible.contains(e)),
        "agent-visible data contains no credential encoding",
    );
    let mut state_text = String::new();
    read_state_text(&root.join("state"), &mut state_text);
    d.check(
        !encodings.iter().any(|e| state_text.contains(e)),
        "state and audit files contain no plaintext credential",
    );
    d.check(
        !state_text.contains("PRIVATE KEY"),
        "audit and state text never contain SSH private key marker",
    );

    d.say("[7] Automatic intrusion response and recovery");
    let _detector = crate::intrusion::install(ctx.clone(), None)?;
    let (s1, b1) = d.call(&url, &token, "reveal_secret", json!({}));
    d.check(
        s1 == 404 && b1["reason"] == "tool_not_found",
        "unknown tool first attempt refused",
    );
    d.check(
        ctx.policy.open_incident_id()?.is_none(),
        "single attempt does not yet open incident",
    );
    let (s2, b2) = d.call(&url, &token, "reveal_secret", json!({}));
    d.check(
        s2 == 404 && b2["reason"] == "tool_not_found",
        "unknown tool second attempt refused",
    );
    let id = ctx.policy.open_incident_id()?;
    d.check(id.is_some(), "second attempt opens automatic incident");
    if let Some(id) = id {
        let incident = crate::incident::get_incident(&ctx, &id)?;
        d.check(
            incident.scope == "principal",
            "incident locks down only the compromised caller",
        );
        d.check(
            incident.rule.as_deref() == Some("unknown_tool"),
            "incident cites unknown-tool rule",
        );
        let (status, body) = d.call(&url, &token, "list_connections", json!({}));
        d.check(
            status == 401 && body["reason"] == "principal_disabled",
            "disabled caller cannot continue",
        );
        crate::incident::close_incident(&ctx, &id)?;
        let next = ctx.policy.create_principal("agent-2", "default")?;
        ctx.policy
            .create_grant("agent-2", "gh", Some(600), Some(10))?;
        ctx.policy.resume()?;
        let (_, body) = d.call(
            &url,
            &next,
            "request",
            json!({"connection":"gh","method":"GET","path":"/repos"}),
        );
        d.check(
            body["status"] == 200,
            "new caller can resume after incident close",
        );
        let (status, body) = d.call(&url, &token, "list_connections", json!({}));
        d.check(
            status == 401 && body["reason"] == "principal_disabled",
            "old caller remains disabled",
        );
    }
    server.stop();
    upstream.stop();
    Ok(())
}

/// Run all synthetic demonstrations; returns 0 only when every check passes.
pub fn main() -> i32 {
    let mut d = Demo::new();
    let root = match temp_root() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("demo setup failed");
            return 1;
        }
    };
    let result = run_inner(&mut d, &root);
    let _ = fs::remove_dir_all(&root);
    if result.is_err() {
        d.check(false, "demo setup or operation completed without error");
    }
    if d.failures.is_empty() {
        d.say(&format!(
            "\nAll checks passed ({}). Synthetic credentials stayed inside the trusted process.",
            d.checks
        ));
        0
    } else {
        d.say(&format!(
            "\n{} checks failed / {} total",
            d.failures.len(),
            d.checks
        ));
        1
    }
}
