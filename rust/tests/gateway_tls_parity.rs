//! Gateway TLS parity with Python's `ssl` (OpenSSL): a pinned self-signed
//! `CA:TRUE` certificate (what `openssl req -x509` makes by default, and what
//! `tests/test_gateway.py`'s `TlsTests` use) is accepted as the server's own
//! certificate, with hostname, validity and purpose still enforced; and a
//! handshake that times out, is reset or is cut short maps to Python's
//! reasons. Synthetic credentials and loopback only.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::fake_upstream::FakeUpstream;
use zeropw::gateway::{self, Headers};
use zeropw::policy::{Connection, HttpAuth, HttpScope, HttpTarget};

const SECRET: &str = "synthetic-tls-parity-token-0123456789";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn python(script: &str) -> String {
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
    let mut child = std::process::Command::new(&interpreter)
        .arg("-")
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run {interpreter}: {e}"));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "python oracle failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// A context with the synthetic secret, principal `alice` and a 1 s
/// upstream timeout.
struct Gateway {
    _temp: TempDir,
    ctx: Arc<Context>,
}

impl Gateway {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let config = Config {
            upstream_timeout: 1.0,
            ..Config::default()
        };
        let ctx = Arc::new(
            Context::initialize(
                temp.path().join("state"),
                "synthetic-admin-passphrase",
                "synthetic-recovery-passphrase",
                config,
                zeropw::clock::system(),
            )
            .unwrap(),
        );
        ctx.projects
            .create("demo", zeropw::projects::DEFAULT_ENVIRONMENTS)
            .unwrap();
        ctx.vault
            .put_secret("key", "api_key", SECRET.as_bytes(), "demo", "dev", true)
            .unwrap();
        ctx.policy.create_principal("alice", "cli").unwrap();
        Self { _temp: temp, ctx }
    }

    /// `GET /me` over HTTPS to `127.0.0.1:port` as `alice`.
    fn relay(&self, id: &str, port: u16, ca_file: Option<&Path>) -> (u16, Option<String>) {
        self.relay_host(id, "127.0.0.1", port, ca_file, false)
    }

    fn relay_host(
        &self,
        id: &str,
        host: &str,
        port: u16,
        ca_file: Option<&Path>,
        allow_private_network: bool,
    ) -> (u16, Option<String>) {
        let target = HttpTarget::new(
            "https",
            host,
            i64::from(port),
            ca_file.map(|p| p.display().to_string()),
            allow_private_network,
        )
        .unwrap();
        let connection = Connection::new(
            id,
            "demo",
            "dev",
            "api",
            "http",
            "key",
            None,
            "",
            Some(target),
            Some(HttpAuth::bearer()),
            Some(HttpScope::new(None, None, Vec::new()).unwrap()),
            None,
            None,
            0,
            "active",
            "",
            "",
        )
        .unwrap();
        self.ctx.policy.create_connection(connection).unwrap();
        self.ctx
            .policy
            .create_grant("alice", id, Some(3600), None)
            .unwrap();
        let result = gateway::relay_for_caller_with_resolver(
            &self.ctx,
            "alice",
            id,
            "GET",
            "/me",
            &Headers::new(),
            b"",
            None,
            Arc::new(|_, _| Ok(vec!["127.0.0.1".parse().unwrap()])),
        );
        (result.status, result.reason)
    }
}

/// Python's gateway doing the same relays: `CASES` is a JSON list of
/// `[connection id, port, ca_file or null]`; one `[status, reason]` per line.
const PY_RELAY: &str = r#"
import json, tempfile
from pathlib import Path
from zeropw import gateway, policy as P
from zeropw.context import Config, Context
SECRET = "synthetic-tls-parity-token-0123456789"
tmp = tempfile.TemporaryDirectory()
ctx = Context.initialize(Path(tmp.name) / "state", "synthetic-admin-passphrase", "synthetic-recovery-passphrase",
                         Config(upstream_timeout=1.0))
ctx.projects.create("demo")
ctx.vault.put_secret("key", "api_key", SECRET.encode(), "demo", "dev")
ctx.policy.create_principal("alice")
for cid, port, ca_file in json.loads(CASES):
    ctx.policy.create_connection(P.Connection(id=cid, project="demo", environment="dev", service="api", kind="http",
        secret_id="key", secret_version=None, description="", http_target=P.HttpTarget("https", "127.0.0.1", port, ca_file),
        http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(), ssh_target=None, cli=None,
        policy_version=0, status="active", created_at="", updated_at=""))
    ctx.policy.create_grant("alice", cid, 3600, None)
    result = gateway.relay_for_caller(ctx, "alice", cid, "GET", "/me", {}, b"")
    print(json.dumps([result.status, result.reason]))
"#;

fn python_relays(cases: &[(String, u16, Option<PathBuf>)]) -> Vec<(u16, Option<String>)> {
    let cases: Vec<Value> = cases
        .iter()
        .map(|(id, port, ca)| json!([id, port, ca.as_ref().map(|p| p.display().to_string())]))
        .collect();
    let script = format!("CASES = {:?}\n{PY_RELAY}", Value::from(cases).to_string());
    python(&script)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn python_relay_host(host: &str, port: u16, ca_file: &Path) -> (u16, Option<String>) {
    let script = format!(
        r#"
import tempfile
from pathlib import Path
from zeropw import gateway, policy as P
from zeropw.context import Config, Context
tmp = tempfile.TemporaryDirectory()
ctx = Context.initialize(Path(tmp.name) / "state", "synthetic-admin-passphrase",
    "synthetic-recovery-passphrase", Config(upstream_timeout=1.0))
ctx.projects.create("demo")
ctx.vault.put_secret("key", "api_key", {secret:?}.encode(), "demo", "dev")
ctx.policy.create_principal("alice")
target = P.HttpTarget("https", {host:?}, {port}, {ca:?}, True)
conn = P.Connection(id="host-case", project="demo", environment="dev", service="api", kind="http",
    secret_id="key", secret_version=None, description="", http_target=target,
    http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(), ssh_target=None, cli=None,
    policy_version=0, status="active", created_at="", updated_at="")
ctx.policy.create_connection(conn)
ctx.policy.create_grant("alice", "host-case", 3600, None)
old = gateway._getaddrinfo
gateway._getaddrinfo = lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", {port}))]
try:
    result = gateway.relay_for_caller(ctx, "alice", "host-case", "GET", "/me", {{}}, b"")
finally:
    gateway._getaddrinfo = old
print(result.status)
print(result.reason or "")
"#,
        secret = SECRET,
        host = host,
        port = port,
        ca = ca_file.display().to_string(),
    );
    let output = python(&script);
    let mut lines = output.lines();
    let status = lines.next().unwrap().parse().unwrap();
    let reason = lines.next().filter(|s| !s.is_empty()).map(str::to_string);
    (status, reason)
}

fn server_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> Arc<rustls::ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls_pki_types::CertificateDer::from(cert_der)],
                rustls_pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
            )
            .expect("server config"),
    )
}

// --------------------------------------------------- pinned CA certificates

struct Issued {
    der: Vec<u8>,
    pem: String,
    key_der: Vec<u8>,
}

fn ca_certificate(
    sans: &[&str],
    not_after: Option<(i32, u8, u8)>,
    customize: impl FnOnce(&mut rcgen::CertificateParams),
) -> Issued {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "zeropw synthetic upstream");
    if let Some((year, month, day)) = not_after {
        params.not_before = rcgen::date_time_ymd(year - 1, month, day);
        params.not_after = rcgen::date_time_ymd(year, month, day);
    }
    customize(&mut params);
    let cert = params.self_signed(&key).unwrap();
    Issued {
        der: cert.der().to_vec(),
        pem: cert.pem(),
        key_der: key.serialize_der(),
    }
}

fn serve(issued: &Issued) -> FakeUpstream {
    FakeUpstream::new(SECRET)
        .tls(server_config(issued.der.clone(), issued.key_der.clone()))
        .start()
}

fn pin(dir: &TempDir, name: &str, pems: &[&str]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, pems.concat()).unwrap();
    path
}

/// `TlsTests`' certificates are `openssl req -x509` CA certificates pinned
/// through `ca_file`: OpenSSL accepts them as the server's own certificate.
/// Hostname, validity and a different pinned CA still refuse.
#[test]
fn pinned_self_signed_ca_certificate_is_accepted_with_checks() {
    let g = Gateway::new();
    let dir = TempDir::new().unwrap();
    let good = ca_certificate(&["127.0.0.1"], None, |_| ());
    let fake = serve(&good);
    let pinned = pin(&dir, "good.pem", &[&good.pem]);
    assert_eq!(g.relay("good", fake.port(), Some(&pinned)), (200, None));
    assert_eq!(fake.requests().len(), 1);
    // A bundle holding the certificate among others is still a pin.
    let other = ca_certificate(&["127.0.0.1"], None, |_| ());
    let bundle = pin(&dir, "bundle.pem", &[&other.pem, &good.pem]);
    assert_eq!(g.relay("bundle", fake.port(), Some(&bundle)), (200, None));
    // A different CA:TRUE certificate with the same names is not the pin.
    let wrong_pin = pin(&dir, "other.pem", &[&other.pem]);
    assert_eq!(
        g.relay("other-pin", fake.port(), Some(&wrong_pin)),
        (502, Some("upstream_tls_failed".into()))
    );
    // Not pinned at all: the OS store does not know it.
    assert_eq!(
        g.relay("unpinned", fake.port(), None),
        (502, Some("upstream_tls_failed".into()))
    );
    // Hostname: the pinned certificate names another host.
    let named = ca_certificate(&["other.invalid"], None, |_| ());
    let named_fake = serve(&named);
    let named_pin = pin(&dir, "named.pem", &[&named.pem]);
    assert_eq!(
        g.relay("mismatch", named_fake.port(), Some(&named_pin)),
        (502, Some("upstream_tls_failed".into()))
    );
    // Validity: expired.
    let expired = ca_certificate(&["127.0.0.1"], Some((2021, 1, 1)), |_| ());
    let expired_fake = serve(&expired);
    let expired_pin = pin(&dir, "expired.pem", &[&expired.pem]);
    assert_eq!(
        g.relay("expired", expired_fake.port(), Some(&expired_pin)),
        (502, Some("upstream_tls_failed".into()))
    );
    // Purpose: an EKU without serverAuth, or a key usage without a TLS bit.
    let client_only = ca_certificate(&["127.0.0.1"], None, |p| {
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    });
    let client_fake = serve(&client_only);
    let client_pin = pin(&dir, "client.pem", &[&client_only.pem]);
    assert_eq!(
        g.relay("client-eku", client_fake.port(), Some(&client_pin)),
        (502, Some("upstream_tls_failed".into()))
    );
    let sign_only = ca_certificate(&["127.0.0.1"], None, |p| {
        p.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
    });
    let sign_fake = serve(&sign_only);
    let sign_pin = pin(&dir, "sign.pem", &[&sign_only.pem]);
    assert_eq!(
        g.relay("sign-ku", sign_fake.port(), Some(&sign_pin)),
        (502, Some("upstream_tls_failed".into()))
    );
    let server_eku = ca_certificate(&["127.0.0.1"], None, |p| {
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        p.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
        ];
    });
    let server_fake = serve(&server_eku);
    let server_pin = pin(&dir, "server.pem", &[&server_eku.pem]);
    assert_eq!(
        g.relay("server-eku", server_fake.port(), Some(&server_pin)),
        (200, None)
    );
    // No refused handshake ever carried the credential upstream.
    for fake in [&named_fake, &expired_fake, &client_fake, &sign_fake] {
        assert!(fake.requests().is_empty());
    }
}

fn openssl(args: &[&str]) -> bool {
    std::process::Command::new("openssl")
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// A self-signed certificate made by the `openssl` binary the way
/// `tests/test_gateway.py` makes them (`x509 -req -days N`, so an expired
/// one can be made with OpenSSL 3.0 too).
fn openssl_certificate(dir: &TempDir, name: &str, ext: &str, days: &str) -> (PathBuf, Issued) {
    openssl_certificate_with_cn(dir, name, "127.0.0.1", ext, days)
}

fn openssl_certificate_with_cn(
    dir: &TempDir,
    name: &str,
    common_name: &str,
    ext: &str,
    days: &str,
) -> (PathBuf, Issued) {
    let cnf = dir.path().join(format!("{name}.cnf"));
    std::fs::write(
        &cnf,
        format!(
            "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = {common_name}\n[ext]\n{ext}\n"
        ),
    )
    .unwrap();
    let key = dir.path().join(format!("{name}.key"));
    let csr = dir.path().join(format!("{name}.csr"));
    let crt = dir.path().join(format!("{name}.crt"));
    let (k, c, r, f) = (
        key.to_str().unwrap(),
        csr.to_str().unwrap(),
        crt.to_str().unwrap(),
        cnf.to_str().unwrap(),
    );
    assert!(openssl(&["genpkey", "-algorithm", "RSA", "-out", k]));
    assert!(openssl(&[
        "req", "-new", "-key", k, "-out", c, "-config", f
    ]));
    assert!(openssl(&[
        "x509",
        "-req",
        "-in",
        c,
        "-signkey",
        k,
        "-out",
        r,
        "-days",
        days,
        "-extfile",
        f,
        "-extensions",
        "ext"
    ]));
    let pem = std::fs::read_to_string(&crt).unwrap();
    let der = rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .to_vec();
    let key_pem = std::fs::read(&key).unwrap();
    let key_der = match rustls_pemfile::private_key(&mut key_pem.as_slice())
        .unwrap()
        .unwrap()
    {
        rustls_pki_types::PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
        other => panic!("unexpected key format {other:?}"),
    };
    (crt, Issued { der, pem, key_der })
}

/// The same decisions made by Python's gateway (OpenSSL) and this one, for
/// certificates made the way `tests/test_gateway.py` makes them (`openssl
/// req -x509 ... basicConstraints = CA:TRUE`), served by the same upstream.
#[test]
fn pinned_ca_decisions_match_python() {
    if !openssl(&["version"]) {
        // `TlsTests` is skipped without the openssl binary; say so loudly.
        panic!("openssl binary not available: the differential cannot run");
    }
    let dir = TempDir::new().unwrap();
    let make = |name: &str, ext: &str, days: &str| openssl_certificate(&dir, name, ext, days);
    let base = "subjectAltName = IP:127.0.0.1\nbasicConstraints = CA:TRUE";
    let variants = [
        ("default", base.to_string(), "2"),
        (
            "critical",
            "subjectAltName = IP:127.0.0.1\nbasicConstraints = critical,CA:TRUE,pathlen:0".into(),
            "2",
        ),
        (
            "other-host",
            "subjectAltName = DNS:other.invalid\nbasicConstraints = CA:TRUE".into(),
            "2",
        ),
        ("expired", base.to_string(), "-1"),
        (
            "client-eku",
            format!("{base}\nextendedKeyUsage = clientAuth"),
            "2",
        ),
        (
            "any-eku",
            format!("{base}\nextendedKeyUsage = anyExtendedKeyUsage"),
            "2",
        ),
        (
            "server-eku",
            format!("{base}\nextendedKeyUsage = serverAuth"),
            "2",
        ),
        (
            "sign-ku",
            format!("{base}\nkeyUsage = critical,keyCertSign,cRLSign"),
            "2",
        ),
        (
            "tls-ku",
            format!("{base}\nkeyUsage = digitalSignature,keyCertSign"),
            "2",
        ),
    ];
    let mut fakes = Vec::new();
    let mut cases = Vec::new();
    for (name, ext, days) in &variants {
        let (crt, issued) = make(name, ext, days);
        let fake = serve(&issued);
        cases.push((name.to_string(), fake.port(), Some(crt)));
        fakes.push(fake);
    }
    // A different CA:TRUE certificate pinned for the default server.
    cases.push(("wrong-pin".into(), fakes[0].port(), cases[1].2.clone()));
    let expected = python_relays(&cases);
    let g = Gateway::new();
    let actual: Vec<_> = cases
        .iter()
        .map(|(id, port, ca)| g.relay(id, *port, ca.as_deref()))
        .collect();
    for ((case, rust), python) in cases.iter().zip(&actual).zip(&expected) {
        assert_eq!(rust, python, "case {}", case.0);
    }
    let accepted: Vec<_> = cases
        .iter()
        .zip(&expected)
        .filter(|(_, result)| result.0 == 200)
        .map(|(case, _)| case.0.as_str())
        .collect();
    assert_eq!(accepted, ["default", "critical", "server-eku", "tls-ku"]);
    assert_eq!(expected[0], (200, None));
    assert_eq!(expected[3], (502, Some("upstream_tls_failed".into())));
    assert_eq!(expected[7], (502, Some("upstream_tls_failed".into())));
}

/// An OpenSSL (Python `ssl`) HTTPS upstream presenting `cert`: rustls
/// refuses to serve a certificate with an unhandled critical extension, so
/// the fake upstream cannot present these variants.
fn openssl_upstream(cert: &Path, key: &Path) -> (std::process::Child, u16) {
    let script = format!(
        r#"
import socket, ssl, sys, threading
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain({cert:?}, {key:?})
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(8)
print(listener.getsockname()[1], flush=True)
def answer(raw):
    try:
        with context.wrap_socket(raw, server_side=True) as tls:
            tls.recv(65536)
            body = b'{{"login": "synthetic"}}'
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                        + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    except Exception:
        pass
while True:
    raw, _ = listener.accept()
    threading.Thread(target=answer, args=(raw,), daemon=True).start()
"#,
        cert = cert.display().to_string(),
        key = key.display().to_string(),
    );
    let mut child = std::process::Command::new(
        std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into()),
    )
    .args(["-c", &script])
    .stdout(std::process::Stdio::piped())
    .spawn()
    .unwrap();
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout.take().unwrap()),
        &mut line,
    )
    .unwrap();
    (child, line.trim().parse().unwrap())
}

/// OpenSSL refuses a certificate carrying a critical extension it does not
/// handle ("unhandled critical extension") even when it is the pinned
/// trust anchor; a non-critical unknown extension is ignored. The pinned
/// CA exception must not accept what OpenSSL refuses. (webpki parses a
/// trust anchor with `UnknownExtensionPolicy::IgnoreCritical` but the end
/// entity strictly, so `UnsupportedCriticalExtension` is raised before
/// `CaUsedAsEndEntity` and `PinnedCaVerifier`'s exception is never reached;
/// this test guards that ordering.)
#[test]
fn pinned_ca_with_unhandled_critical_extension_is_refused_like_python() {
    if !openssl(&["version"]) {
        panic!("openssl binary not available: the differential cannot run");
    }
    let dir = TempDir::new().unwrap();
    let base = "subjectAltName = IP:127.0.0.1\nbasicConstraints = CA:TRUE";
    let mut children = Vec::new();
    let mut cases = Vec::new();
    for (name, ext) in [
        (
            "unknown-critical",
            format!("{base}\n1.2.3.4.5 = critical,ASN1:UTF8String:synthetic"),
        ),
        (
            "unknown-noncritical",
            format!("{base}\n1.2.3.4.5 = ASN1:UTF8String:synthetic"),
        ),
    ] {
        let (crt, _) = openssl_certificate(&dir, name, &ext, "2");
        let key = dir.path().join(format!("{name}.key"));
        let (child, port) = openssl_upstream(&crt, &key);
        children.push(child);
        cases.push((name.to_string(), port, Some(crt)));
    }
    let expected = python_relays(&cases);
    let g = Gateway::new();
    let actual: Vec<_> = cases
        .iter()
        .map(|(id, port, ca)| g.relay(id, *port, ca.as_deref()))
        .collect();
    for mut child in children {
        let _ = child.kill();
        let _ = child.wait();
    }
    assert_eq!(actual, expected);
    assert_eq!(expected[0], (502, Some("upstream_tls_failed".into())));
    assert_eq!(expected[1], (200, None));
}

// --------------------------------------------- handshake failure reasons

/// A loopback listener that misbehaves during the TLS handshake.
fn misbehaving(behaviour: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        // One connection from each gateway.
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut hello = [0u8; 4096];
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.read(&mut hello);
            match behaviour {
                "silent" => std::thread::sleep(Duration::from_millis(2500)),
                "reset" => {
                    let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
                }
                "close" => (),
                _ => {
                    let _ =
                        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
                }
            }
            drop(stream);
        }
    });
    (port, handle)
}

/// `_exchange`: `ssl.SSLError` -> `upstream_tls_failed` (including the peer
/// closing mid-handshake and a non-TLS reply), a timeout -> `upstream_timeout`,
/// any other `OSError` (a reset) -> `upstream_unreachable`.
#[test]
fn handshake_failures_map_like_python() {
    let behaviours = ["silent", "reset", "close", "garbage"];
    let servers: Vec<_> = behaviours.iter().map(|b| misbehaving(b)).collect();
    let cases: Vec<(String, u16, Option<PathBuf>)> = behaviours
        .iter()
        .zip(&servers)
        .map(|(b, (port, _))| (b.to_string(), *port, None))
        .collect();
    let expected = python_relays(&cases);
    let g = Gateway::new();
    let actual: Vec<_> = cases
        .iter()
        .map(|(id, port, _)| g.relay(id, *port, None))
        .collect();
    for (_, handle) in servers {
        let _ = handle.join();
    }
    assert_eq!(
        expected,
        vec![
            (502, Some("upstream_timeout".into())),
            (502, Some("upstream_unreachable".into())),
            (502, Some("upstream_tls_failed".into())),
            (502, Some("upstream_tls_failed".into())),
        ]
    );
    assert_eq!(actual, expected);
}

/// Ordinary `CA:FALSE` leaves receive OpenSSL's own SSL-server purpose
/// checks, including key usage and the legacy SGC EKU accepted by Python.
#[test]
fn non_ca_leaf_purpose_decisions_match_python() {
    if !openssl(&["version"]) {
        panic!("openssl binary not available: the measurement cannot run");
    }
    let dir = TempDir::new().unwrap();
    let base = "subjectAltName = IP:127.0.0.1\nbasicConstraints = CA:FALSE";
    let variants = [
        ("leaf-sign-ku", format!("{base}\nkeyUsage = keyCertSign")),
        ("leaf-sgc-eku", format!("{base}\nextendedKeyUsage = nsSGC")),
    ];
    let mut fakes = Vec::new();
    let mut cases = Vec::new();
    for (name, ext) in &variants {
        let (crt, issued) = openssl_certificate(&dir, name, ext, "2");
        let fake = serve(&issued);
        cases.push((name.to_string(), fake.port(), Some(crt)));
        fakes.push(fake);
    }
    let python = python_relays(&cases);
    let g = Gateway::new();
    let rust: Vec<_> = cases
        .iter()
        .map(|(id, port, ca)| g.relay(id, *port, ca.as_deref()))
        .collect();
    let refused = (502, Some("upstream_tls_failed".to_string()));
    assert_eq!(python, vec![refused.clone(), (200, None)]);
    assert_eq!(rust, python);
    assert!(fakes[0].requests().is_empty());
    assert_eq!(fakes[1].requests().len(), 2);
}

/// Python enables OpenSSL's common-name fallback for a DNS hostname when SAN
/// is absent, but does not apply that legacy fallback to an IP address.
#[test]
fn common_name_fallback_matches_python() {
    if !openssl(&["version"]) {
        panic!("openssl binary not available: the differential cannot run");
    }
    let dir = TempDir::new().unwrap();
    let (dns_crt, dns_issued) = openssl_certificate_with_cn(
        &dir,
        "cn-dns",
        "upstream.synthetic",
        "basicConstraints = CA:FALSE\nkeyUsage = digitalSignature",
        "2",
    );
    let dns_fake = serve(&dns_issued);
    let python_dns = python_relay_host("upstream.synthetic", dns_fake.port(), &dns_crt);
    let g = Gateway::new();
    let rust_dns = g.relay_host(
        "cn-dns",
        "upstream.synthetic",
        dns_fake.port(),
        Some(&dns_crt),
        true,
    );
    assert_eq!(python_dns, (200, None));
    assert_eq!(rust_dns, python_dns);
    assert_eq!(dns_fake.requests().len(), 2);

    let (ip_crt, ip_issued) = openssl_certificate(
        &dir,
        "cn-ip",
        "basicConstraints = CA:FALSE\nkeyUsage = digitalSignature",
        "2",
    );
    let ip_fake = serve(&ip_issued);
    let cases = vec![("cn-ip".to_string(), ip_fake.port(), Some(ip_crt))];
    let python_ip = python_relays(&cases);
    let rust_ip = vec![g.relay("cn-ip", ip_fake.port(), cases[0].2.as_deref())];
    let refused = (502, Some("upstream_tls_failed".to_string()));
    assert_eq!(python_ip, vec![refused]);
    assert_eq!(rust_ip, python_ip);
    assert!(ip_fake.requests().is_empty());
}

/// The gateway uses the same OpenSSL signature algorithms as Python, so a
/// P-521 server certificate is verified instead of being rejected merely
/// because rustls' ring provider does not implement that curve.
#[test]
fn p521_server_certificate_matches_python() {
    if !openssl(&["version"]) {
        panic!("openssl binary not available: the differential cannot run");
    }
    let dir = TempDir::new().unwrap();
    let name = "p521";
    let cnf = dir.path().join(format!("{name}.cnf"));
    std::fs::write(
        &cnf,
        "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = 127.0.0.1\n[ext]\nsubjectAltName = IP:127.0.0.1\nbasicConstraints = CA:FALSE\nkeyUsage = digitalSignature\nextendedKeyUsage = serverAuth\n",
    )
    .unwrap();
    let key = dir.path().join(format!("{name}.key"));
    let csr = dir.path().join(format!("{name}.csr"));
    let crt = dir.path().join(format!("{name}.crt"));
    assert!(openssl(&[
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-521",
        "-out",
        key.to_str().unwrap(),
    ]));
    assert!(openssl(&[
        "req",
        "-new",
        "-key",
        key.to_str().unwrap(),
        "-out",
        csr.to_str().unwrap(),
        "-config",
        cnf.to_str().unwrap(),
    ]));
    assert!(openssl(&[
        "x509",
        "-req",
        "-in",
        csr.to_str().unwrap(),
        "-signkey",
        key.to_str().unwrap(),
        "-out",
        crt.to_str().unwrap(),
        "-days",
        "2",
        "-extfile",
        cnf.to_str().unwrap(),
        "-extensions",
        "ext",
    ]));

    // Each gateway gets its own controlled server because this helper is a
    // separate process and the test deliberately tears it down explicitly.
    let (mut python_server, python_port) = openssl_upstream(&crt, &key);
    let python_cases = vec![("p521-python".to_string(), python_port, Some(crt.clone()))];
    let python = python_relays(&python_cases);
    let _ = python_server.kill();
    let _ = python_server.wait();

    let (mut rust_server, rust_port) = openssl_upstream(&crt, &key);
    let g = Gateway::new();
    let rust = vec![g.relay("p521-rust", rust_port, Some(&crt))];
    let _ = rust_server.kill();
    let _ = rust_server.wait();
    assert_eq!(python, vec![(200, None)]);
    assert_eq!(rust, python);
}
