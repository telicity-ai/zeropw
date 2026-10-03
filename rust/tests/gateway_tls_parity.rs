//! Gateway TLS verification against fixed expectations: a pinned
//! self-signed `CA:TRUE` certificate (what `openssl req -x509` makes by
//! default) is accepted as the server's own certificate, with hostname,
//! validity and purpose still enforced; an unpinned or wrong pin is refused;
//! and a handshake that times out, is reset or is cut short maps to the
//! documented reasons. The ClientHello is compared with the one the Python
//! prototype's `ssl` sent (`tests/fixtures/python/gateway/client_hello.json`,
//! see `GENERATE.md` there). Synthetic credentials and loopback only.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::Value;
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::fake_upstream::FakeUpstream;
use zeropw::gateway::{self, Headers};
use zeropw::policy::{Connection, HttpAuth, HttpScope, HttpTarget};

const SECRET: &str = "synthetic-tls-parity-token-0123456789";
const CLIENT_HELLO: &str = include_str!("fixtures/python/gateway/client_hello.json");

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
        (
            result
                .status
                .to_string()
                .parse()
                .expect("ordinary TLS status"),
            result.reason,
        )
    }
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

/// rcgen self-signed `CA:TRUE` certificates pinned through `ca_file`. Whether
/// OpenSSL accepts the basic (no key usage) certificate as the server's own,
/// and whether it finds it in a bundle after another CA with the same
/// subject, differs between the OpenSSL builds of the supported CI
/// platforms (the prototype's `ssl` decided the same way as this gateway on
/// each), so those two only have to be an acceptance or a TLS refusal;
/// every security refusal and the explicit TLS-server-purpose acceptance
/// are fixed expectations.
#[test]
fn pinned_self_signed_ca_certificate_decisions() {
    let g = Gateway::new();
    let dir = TempDir::new().unwrap();
    let same = |id: &str, port: u16, ca: Option<&Path>| {
        let rust = g.relay(id, port, ca);
        eprintln!("rcgen pinned-CA {id}: {rust:?}");
        rust
    };
    let refused = (502, Some("upstream_tls_failed".to_string()));
    let good = ca_certificate(&["127.0.0.1"], None, |_| ());
    let fake = serve(&good);
    let pinned = pin(&dir, "good.pem", &[&good.pem]);
    let good_result = same("good", fake.port(), Some(&pinned));
    assert!(
        good_result == (200, None) || good_result == refused,
        "{good_result:?}"
    );
    // A bundle holding the certificate among others.
    let other = ca_certificate(&["127.0.0.1"], None, |_| ());
    let bundle = pin(&dir, "bundle.pem", &[&other.pem, &good.pem]);
    let bundle_result = same("bundle", fake.port(), Some(&bundle));
    assert!(
        bundle_result == (200, None) || bundle_result == refused,
        "{bundle_result:?}"
    );
    // A different CA:TRUE certificate with the same names is not the pin.
    let wrong_pin = pin(&dir, "other.pem", &[&other.pem]);
    assert_eq!(
        same("other-pin", fake.port(), Some(&wrong_pin)),
        (502, Some("upstream_tls_failed".into()))
    );
    // Not pinned at all: the OS store does not know it.
    assert_eq!(
        same("unpinned", fake.port(), None),
        (502, Some("upstream_tls_failed".into()))
    );
    // Hostname: the pinned certificate names another host.
    let named = ca_certificate(&["other.invalid"], None, |_| ());
    let named_fake = serve(&named);
    let named_pin = pin(&dir, "named.pem", &[&named.pem]);
    assert_eq!(
        same("mismatch", named_fake.port(), Some(&named_pin)),
        (502, Some("upstream_tls_failed".into()))
    );
    // Validity: expired.
    let expired = ca_certificate(&["127.0.0.1"], Some((2021, 1, 1)), |_| ());
    let expired_fake = serve(&expired);
    let expired_pin = pin(&dir, "expired.pem", &[&expired.pem]);
    assert_eq!(
        same("expired", expired_fake.port(), Some(&expired_pin)),
        (502, Some("upstream_tls_failed".into()))
    );
    // Purpose: an EKU without serverAuth, or a key usage without a TLS bit.
    let client_only = ca_certificate(&["127.0.0.1"], None, |p| {
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    });
    let client_fake = serve(&client_only);
    let client_pin = pin(&dir, "client.pem", &[&client_only.pem]);
    assert_eq!(
        same("client-eku", client_fake.port(), Some(&client_pin)),
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
        same("sign-ku", sign_fake.port(), Some(&sign_pin)),
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
        same("server-eku", server_fake.port(), Some(&server_pin)),
        (200, None)
    );
    // No refused handshake ever carried the credential upstream.
    for fake in [&named_fake, &expired_fake, &client_fake, &sign_fake] {
        assert!(fake.requests().is_empty());
    }
    // Only the accepted pins (good and bundle, when accepted) reached it.
    let accepted = [&good_result, &bundle_result]
        .iter()
        .filter(|result| result.0 == 200)
        .count();
    assert_eq!(fake.requests().len(), accepted);
}

fn openssl(args: &[&str]) -> bool {
    std::process::Command::new("openssl")
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn assert_openssl(args: &[&str]) {
    let output = std::process::Command::new("openssl")
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("cannot execute openssl: {error}"));
    assert!(
        output.status.success(),
        "openssl {:?} failed: {}",
        args.first().unwrap_or(&""),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A self-signed certificate made by the `openssl` binary.  Normal variants
/// use `x509 -req` like `tests/test_gateway.py`; the expired variant uses
/// `ca -selfsign` because current OpenSSL releases reject non-positive
/// `x509 -days` values.
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
    let database = dir.path().join(format!("{name}.index"));
    let serial = dir.path().join(format!("{name}.serial"));
    let new_certs = dir.path().join(format!("{name}.newcerts"));
    std::fs::write(&database, "").unwrap();
    std::fs::write(&serial, "01\n").unwrap();
    std::fs::create_dir(&new_certs).unwrap();
    std::fs::write(
        &cnf,
        format!(
            "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = {common_name}\n\
             [ext]\n{ext}\n\
             [ca]\ndefault_ca = CA_default\n\
             [CA_default]\ndatabase = {}\nnew_certs_dir = {}\nserial = {}\n\
             default_md = sha256\ndefault_days = 1\npolicy = policy_any\n\
             x509_extensions = ext\nunique_subject = no\n\
             [policy_any]\ncommonName = supplied\n",
            database.display(),
            new_certs.display(),
            serial.display(),
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
    assert_openssl(&["genpkey", "-algorithm", "RSA", "-out", k]);
    assert_openssl(&["req", "-new", "-key", k, "-out", c, "-config", f]);
    if days.parse::<i64>().unwrap() > 0 {
        assert_openssl(&[
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
            "ext",
        ]);
    } else {
        assert_openssl(&[
            "ca",
            "-selfsign",
            "-batch",
            "-notext",
            "-config",
            f,
            "-in",
            c,
            "-keyfile",
            k,
            "-out",
            r,
            "-startdate",
            "20200101000000Z",
            "-enddate",
            "20210101000000Z",
            "-extensions",
            "ext",
        ]);
    }
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

/// Pinned-CA decisions for certificates made the way the prototype's own TLS
/// tests made them (`openssl req -x509 ... basicConstraints = CA:TRUE`),
/// served by the same upstream: the server's own pinned certificate is
/// accepted when its purpose allows TLS serving; another host, an expired
/// certificate, a non-server purpose and a different pin are refused.
#[test]
fn pinned_ca_decisions() {
    if !openssl(&["version"]) {
        panic!("openssl binary not available: the certificates cannot be made");
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
    let g = Gateway::new();
    let actual: Vec<_> = cases
        .iter()
        .map(|(id, port, ca)| g.relay(id, *port, ca.as_deref()))
        .collect();
    let accepted = ["default", "critical", "server-eku", "tls-ku"];
    for ((name, _, _), result) in cases.iter().zip(&actual) {
        let expected = if accepted.contains(&name.as_str()) {
            (200, None)
        } else {
            (502, Some("upstream_tls_failed".to_string()))
        };
        assert_eq!(result, &expected, "case {name}");
    }
    // Refused handshakes never carried the credential upstream.
    for ((name, _, _), fake) in cases.iter().zip(&fakes) {
        let expected = usize::from(accepted.contains(&name.as_str()));
        assert_eq!(fake.requests().len(), expected, "case {name}");
    }
}

/// An in-process OpenSSL HTTPS upstream presenting `cert`: rustls refuses to
/// serve a certificate with an unhandled critical extension (or a P-521
/// key), so the fake upstream cannot present these variants. Every
/// connection whose handshake completes gets one fixed `200` reply; the
/// count of those is `served`.
struct OpensslUpstream {
    port: u16,
    stop: Arc<AtomicBool>,
    served: Arc<std::sync::atomic::AtomicUsize>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl OpensslUpstream {
    fn start(cert: &Path, key: &Path) -> Self {
        use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        builder
            .set_certificate_file(cert, SslFiletype::PEM)
            .unwrap();
        builder.set_private_key_file(key, SslFiletype::PEM).unwrap();
        builder.check_private_key().unwrap();
        let acceptor = builder.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (flag, count) = (stop.clone(), served.clone());
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                let Ok((stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let Ok(mut tls) = acceptor.accept(stream) else {
                    continue;
                };
                let mut request = [0u8; 65536];
                let _ = tls.read(&mut request);
                let body = br#"{"login": "synthetic"}"#;
                let mut reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                reply.extend_from_slice(body);
                if tls.write_all(&reply).is_ok() {
                    count.fetch_add(1, Ordering::AcqRel);
                }
                let _ = tls.shutdown();
            }
        });
        OpensslUpstream {
            port,
            stop,
            served,
            thread: Some(thread),
        }
    }

    fn served(&self) -> usize {
        self.served.load(Ordering::Acquire)
    }
}

impl Drop for OpensslUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
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
fn pinned_ca_with_unhandled_critical_extension_is_refused() {
    if !openssl(&["version"]) {
        panic!("openssl binary not available: the certificates cannot be made");
    }
    let dir = TempDir::new().unwrap();
    let base = "subjectAltName = IP:127.0.0.1\nbasicConstraints = CA:TRUE";
    let mut servers = Vec::new();
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
        let server = OpensslUpstream::start(&crt, &key);
        cases.push((name.to_string(), server.port, Some(crt)));
        servers.push(server);
    }
    let g = Gateway::new();
    let actual: Vec<_> = cases
        .iter()
        .map(|(id, port, ca)| g.relay(id, *port, ca.as_deref()))
        .collect();
    assert_eq!(
        actual,
        vec![(502, Some("upstream_tls_failed".into())), (200, None)]
    );
    assert_eq!(servers[0].served(), 0);
    assert_eq!(servers[1].served(), 1);
}

// --------------------------------------------- handshake failure reasons

/// A loopback listener that misbehaves during the TLS handshake.
fn misbehaving(behaviour: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        // One connection from the gateway.
        for _ in 0..1 {
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

/// `_exchange`: a TLS error -> `upstream_tls_failed` (including the peer
/// closing mid-handshake and a non-TLS reply), a timeout -> `upstream_timeout`,
/// any other socket error (a reset) -> `upstream_unreachable`.
#[test]
fn handshake_failures_map_to_fixed_reasons() {
    let behaviours = ["silent", "reset", "close", "garbage"];
    let servers: Vec<_> = behaviours.iter().map(|b| misbehaving(b)).collect();
    let g = Gateway::new();
    let actual: Vec<_> = behaviours
        .iter()
        .zip(&servers)
        .map(|(id, (port, _))| g.relay(id, *port, None))
        .collect();
    for (_, handle) in servers {
        let _ = handle.join();
    }
    assert_eq!(
        actual,
        vec![
            (502, Some("upstream_timeout".into())),
            (502, Some("upstream_unreachable".into())),
            (502, Some("upstream_tls_failed".into())),
            (502, Some("upstream_tls_failed".into())),
        ]
    );
}

/// Ordinary `CA:FALSE` leaves receive OpenSSL's own SSL-server purpose
/// checks: a key usage without a TLS bit is refused, and the legacy SGC EKU
/// (which the prototype's OpenSSL accepted) is accepted.
#[test]
fn non_ca_leaf_purpose_decisions() {
    if !openssl(&["version"]) {
        panic!("openssl binary not available: the certificates cannot be made");
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
    let g = Gateway::new();
    let rust: Vec<_> = cases
        .iter()
        .map(|(id, port, ca)| g.relay(id, *port, ca.as_deref()))
        .collect();
    let refused = (502, Some("upstream_tls_failed".to_string()));
    assert_eq!(rust, vec![refused, (200, None)]);
    assert!(fakes[0].requests().is_empty());
    assert_eq!(fakes[1].requests().len(), 1);
}

/// OpenSSL's common-name fallback applies to a DNS hostname when SAN is
/// absent (as in the prototype), but not to an IP address.
#[test]
fn common_name_fallback_applies_to_dns_names_only() {
    if !openssl(&["version"]) {
        panic!("openssl binary not available: the certificates cannot be made");
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
    let g = Gateway::new();
    let rust_dns = g.relay_host(
        "cn-dns",
        "upstream.synthetic",
        dns_fake.port(),
        Some(&dns_crt),
        true,
    );
    assert_eq!(rust_dns, (200, None));
    assert_eq!(dns_fake.requests().len(), 1);

    let (ip_crt, ip_issued) = openssl_certificate(
        &dir,
        "cn-ip",
        "basicConstraints = CA:FALSE\nkeyUsage = digitalSignature",
        "2",
    );
    let ip_fake = serve(&ip_issued);
    let rust_ip = g.relay("cn-ip", ip_fake.port(), Some(&ip_crt));
    assert_eq!(rust_ip, (502, Some("upstream_tls_failed".to_string())));
    assert!(ip_fake.requests().is_empty());
}

/// The gateway uses OpenSSL's signature algorithms (as the prototype's `ssl`
/// did), so a P-521 server certificate is verified instead of being rejected
/// merely because rustls' ring provider does not implement that curve.
#[test]
fn p521_server_certificate_is_verified() {
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

    let server = OpensslUpstream::start(&crt, &key);
    let g = Gateway::new();
    assert_eq!(g.relay("p521", server.port, Some(&crt)), (200, None));
    assert_eq!(server.served(), 1);
}

// ------------------------------------------------ ClientHello on the wire

/// Accepts `count` connections, returning each one's first TLS handshake
/// message (the ClientHello) reassembled from its records, then closes.
fn capture_client_hellos(count: usize) -> (u16, std::thread::JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let mut hellos = Vec::new();
        for _ in 0..count {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut message = Vec::new();
            loop {
                let mut header = [0u8; 5];
                if stream.read_exact(&mut header).is_err() || header[0] != 0x16 {
                    break;
                }
                let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                let mut fragment = vec![0u8; length];
                if stream.read_exact(&mut fragment).is_err() {
                    break;
                }
                message.extend_from_slice(&fragment);
                if message.len() >= 4 {
                    let body = (usize::from(message[1]) << 16)
                        | (usize::from(message[2]) << 8)
                        | usize::from(message[3]);
                    if message.len() >= 4 + body {
                        message.truncate(4 + body);
                        break;
                    }
                }
            }
            hellos.push(message);
        }
        hellos
    });
    (port, handle)
}

/// The ClientHello with its per-connection random values blanked: the
/// 32-byte random, the legacy session id's bytes (its length kept) and each
/// key share's key exchange bytes (group and length kept). Everything else
/// -- version, cipher suites and their order, compression, every extension
/// in order with its content (SNI, groups, signature algorithms,
/// supported versions, padding length, ...) -- is kept verbatim.
fn normalized_client_hello(message: &[u8]) -> Vec<u8> {
    let mut m = message.to_vec();
    assert_eq!(m.first(), Some(&1), "not a ClientHello: {message:?}");
    // type(1) length(3) version(2) random(32)
    for b in &mut m[6..38] {
        *b = 0;
    }
    let mut at = 38;
    let session_len = usize::from(m[at]);
    for b in &mut m[at + 1..at + 1 + session_len] {
        *b = 0;
    }
    at += 1 + session_len;
    let suites = usize::from(u16::from_be_bytes([m[at], m[at + 1]]));
    at += 2 + suites;
    let compression = usize::from(m[at]);
    at += 1 + compression;
    let end = at + 2 + usize::from(u16::from_be_bytes([m[at], m[at + 1]]));
    at += 2;
    while at + 4 <= end {
        let kind = u16::from_be_bytes([m[at], m[at + 1]]);
        let length = usize::from(u16::from_be_bytes([m[at + 2], m[at + 3]]));
        let data = at + 4;
        if kind == 51 {
            // key_share: client_shares<len>: (group(2) key_exchange<len>)*
            let mut share = data + 2;
            while share + 4 <= data + length {
                let key_len = usize::from(u16::from_be_bytes([m[share + 2], m[share + 3]]));
                for b in &mut m[share + 4..share + 4 + key_len] {
                    *b = 0;
                }
                share += 4 + key_len;
            }
        }
        at = data + length;
    }
    m
}

/// The cipher-suite list of a ClientHello.
fn client_hello_suites(message: &[u8]) -> Vec<u8> {
    let at = 38 + 1 + usize::from(message[38]);
    let suites = usize::from(u16::from_be_bytes([message[at], message[at + 1]]));
    message[at + 2..at + 2 + suites].to_vec()
}

/// The ClientHello the gateway's TLS client sends is the one the prototype's
/// `ssl` sent (fixture): same cipher suites in the same order
/// (`create_default_context`'s `PY_SSL_DEFAULT_CIPHER_STRING`), same
/// extensions and SNI behaviour, for a DNS name (SNI sent) and an IP literal
/// (no SNI). When this crate links a different OpenSSL build than the one
/// the fixture was captured with, only the cipher-suite list is a property
/// of this code rather than of the library, so only that is compared.
#[test]
fn client_hello_matches_the_python_fixture() {
    let fixture: Value = serde_json::from_str(CLIENT_HELLO).unwrap();
    let same_library =
        fixture["openssl_version_number"].as_i64().unwrap() == openssl::version::number();
    let hosts = ["upstream.example.test", "127.0.0.1"];
    let (port, capture) = capture_client_hellos(hosts.len());
    let g = Gateway::new();
    for (index, host) in hosts.iter().enumerate() {
        let _ = g.relay_host(&format!("hello-{index}"), host, port, None, true);
    }
    let hellos = capture.join().unwrap();
    assert_eq!(hellos.len(), hosts.len());
    for (host, rust) in hosts.iter().zip(&hellos) {
        let python = hex::decode(fixture["hellos"][host].as_str().unwrap()).unwrap();
        assert_eq!(
            client_hello_suites(rust),
            client_hello_suites(&python),
            "{host}: cipher suites"
        );
        // SNI (extension 0) carries the DNS name and is absent for an IP.
        let sni = String::from_utf8_lossy(rust).contains("upstream.example.test");
        assert_eq!(sni, *host == "upstream.example.test", "{host}: SNI");
        if same_library {
            assert_eq!(
                normalized_client_hello(rust),
                normalized_client_hello(&python),
                "{host}: ClientHello"
            );
        }
    }
}
