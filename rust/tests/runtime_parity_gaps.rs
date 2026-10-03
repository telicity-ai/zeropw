//! Parity gaps between the native runtime (`runs`, `tools`, `server`,
//! `gateway`) and the Python specification, each pinned by the Python
//! behaviour it reproduces. Synthetic credentials and loopback only.
use serde_json::{Value, json};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use zeropw::{
    context::{Config, Context},
    runs::{Run, RunRegistry},
};

fn context() -> (TempDir, Arc<Context>) {
    let temp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            temp.path().join("state"),
            "synthetic-admin-passphrase",
            "synthetic-recovery-passphrase",
            Config::default(),
            zeropw::clock::system(),
        )
        .unwrap(),
    );
    (temp, ctx)
}

fn registry() -> (TempDir, Arc<Context>, Arc<RunRegistry>) {
    let (temp, ctx) = context();
    let registry = RunRegistry::new(ctx.clone(), 1024, 0.05);
    (temp, ctx, registry)
}

fn queued(r: &RunRegistry, program: &str) -> Run {
    r.create(
        "alice", "conn", "grant", "http", program, None, "digest", None, None,
    )
}

fn executable(path: &Path, content: &[u8]) {
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn launch(r: &Arc<RunRegistry>, temp: &TempDir, program: &Path) -> Run {
    launch_with_path(r, temp, &program.to_string_lossy(), "/usr/bin:/bin")
}

fn launch_with_path(r: &Arc<RunRegistry>, temp: &TempDir, program: &str, path: &str) -> Run {
    let program = program.to_string();
    let run = queued(r, &program);
    let started = r
        .start(
            &run,
            std::slice::from_ref(&program),
            &HashMap::from([("PATH".into(), path.into())]),
            temp.path(),
            &[],
            None,
            Some(5.0),
        )
        .unwrap();
    r.wait(&started, Some(8.0))
}

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

/// The Python prototype as the oracle (script on stdin, repository on
/// `PYTHONPATH`), like `zeropw::oracle::python` for library tests.
fn python(script: &str) -> String {
    use std::io::Write;
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

fn run_shape(run: &Run) -> Value {
    json!({"state": run.state, "reason": run.reason, "exit_code": run.exit_code})
}

/// Run script-format fixtures through the original registry so platform
/// loader rules come from the same Python oracle as the product contract.
fn python_shebang_shapes() -> Vec<Value> {
    let output = python(
        r##"
import json, tempfile
from pathlib import Path
from zeropw.context import Context
from zeropw.runs import RunRegistry

with tempfile.TemporaryDirectory(prefix="zeropw-shebang-oracle-") as tmp:
    root = Path(tmp)
    ctx = Context.initialize(root / "state", "synthetic-admin-passphrase", "synthetic-recovery-passphrase")
    registry = RunRegistry(ctx, 1024, 0.05)
    spaced = root / "spaced.sh"
    spaced.write_bytes(b"#! \t/bin/sh -e\nprintf spaced\n")
    spaced.chmod(0o700)
    fixtures = [
        ("chained.sh", ("#!" + str(spaced) + "\nprintf chained-text-never-read\n").encode()),
        ("bare.sh", b"#!/bin/sh"),
        ("bare-spaced.sh", b"#! /bin/sh"),
        ("bare-argument.sh", b"#!/bin/sh -e"),
    ]
    results = []
    for name, content in fixtures:
        path = root / name
        path.write_bytes(content)
        path.chmod(0o700)
        run = registry.create("alice", "conn", "grant", "http", str(path), input_digest="digest")
        started = registry.start(run, [str(path)], {"PATH": "/usr/bin:/bin"}, str(root), timeout=5)
        done = registry.wait(started, 8)
        results.append({"state": done.state, "reason": done.reason, "exit_code": done.exit_code})
    print(json.dumps(results))
    registry.shutdown()
"##,
    );
    serde_json::from_str(&output).unwrap()
}

const SECRET: &str = "synthetic-parity-secret-0123456789";

/// An initialised context holding one bearer HTTP connection (`service`) to
/// a fake upstream and a grant for `alice`.
struct HttpFixture {
    _temp: TempDir,
    ctx: Arc<Context>,
    fake: zeropw::fake_upstream::FakeUpstream,
}

impl HttpFixture {
    fn new() -> Self {
        use zeropw::policy::{Connection, HttpAuth, HttpScope, HttpTarget};
        let (temp, ctx) = context();
        ctx.projects
            .create("demo", zeropw::projects::DEFAULT_ENVIRONMENTS)
            .unwrap();
        ctx.vault
            .put_secret("key", "api_key", SECRET.as_bytes(), "demo", "dev", true)
            .unwrap();
        let fake = zeropw::fake_upstream::FakeUpstream::new(SECRET).start();
        ctx.policy.create_principal("alice", "cli").unwrap();
        let connection = Connection::new(
            "service",
            "demo",
            "dev",
            "api",
            "http",
            "key",
            None,
            "",
            Some(
                HttpTarget::new("http", fake.host(), i64::from(fake.port()), None, false).unwrap(),
            ),
            Some(HttpAuth::bearer()),
            Some(
                HttpScope::new(Some(vec!["GET".into()]), Some(vec!["/".into()]), Vec::new())
                    .unwrap(),
            ),
            None,
            None,
            0,
            "active",
            "",
            "",
        )
        .unwrap();
        ctx.policy.create_connection(connection).unwrap();
        ctx.policy
            .create_grant("alice", "service", Some(3600), None)
            .unwrap();
        Self {
            _temp: temp,
            ctx,
            fake,
        }
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.fake.stop();
    }
}

fn finish_reasons(ctx: &Context, run: &Run) -> Vec<Value> {
    ctx.audit
        .tail(1000)
        .unwrap()
        .into_iter()
        .filter(|record| record["event"] == "run_finish" && record["run_id"] == run.id.as_str())
        .map(|record| record["reason"].clone())
        .collect()
}

// ------------------------------------------------ gap 1: exec format errors

/// `tests/test_runs.py::test_spawn_failure_is_reported_not_raised`: Python's
/// `Popen` calls `execve`, so a file with no recognised executable format is
/// `ENOEXEC` and the run fails `spawn_failed`. libc `execvp` would instead run
/// it through `/bin/sh`; the marker proves the file's text never executed.
#[test]
fn file_without_an_executable_format_fails_spawn_without_running() {
    let (temp, ctx, r) = registry();
    let marker = temp.path().join("marker-noshebang");
    let script = temp.path().join("no-shebang.sh");
    executable(
        &script,
        format!("touch '{}'\necho ran\n", marker.display()).as_bytes(),
    );
    let done = launch(&r, &temp, &script);
    assert_eq!(
        (done.state.as_str(), done.reason.as_deref()),
        ("failed", Some("spawn_failed")),
        "exit={:?} stdout={:?}",
        done.exit_code,
        done.stdout
    );
    assert_eq!(done.exit_code, None);
    assert!(done.stdout.is_empty() && done.stderr.is_empty());
    assert!(!marker.exists(), "a no-#! text file must never be executed");
    assert_eq!(finish_reasons(&ctx, &done), vec![json!("spawn_failed")]);
}

#[test]
fn random_bytes_and_bad_interpreters_fail_spawn_without_running() {
    let (temp, ctx, r) = registry();
    let marker = temp.path().join("marker-bytes");
    let bogus = temp.path().join("bogus.bin");
    let mut content = b"\x00\x01not-an-executable\n".to_vec();
    content.extend_from_slice(format!("touch '{}'\n", marker.display()).as_bytes());
    executable(&bogus, &content);
    let noise = temp.path().join("noise.bin");
    executable(
        &noise,
        &[
            0x9c, 0x13, 0xee, 0x02, 0x51, 0xa0, 0x7d, 0x00, 0xff, 0x10, 0x42,
        ],
    );
    // `#!` naming a text file with no format of its own: the kernel refuses
    // the interpreter with ENOEXEC too (measured with python3.12's Popen).
    let text_interpreter = temp.path().join("interpreter.txt");
    executable(
        &text_interpreter,
        format!("touch '{}'\n", marker.display()).as_bytes(),
    );
    let nested = temp.path().join("nested.sh");
    executable(
        &nested,
        format!(
            "#!{}\ntouch '{}'\n",
            text_interpreter.display(),
            marker.display()
        )
        .as_bytes(),
    );
    // An ELF identification with a type the kernel never executes (ET_REL).
    let object = temp.path().join("object.o");
    let mut elf = b"\x7fELF\x02\x01\x01\x00".to_vec();
    elf.resize(16, 0);
    elf.extend_from_slice(&[1, 0]);
    elf.resize(64, 0);
    executable(&object, &elf);
    // A `#!` name running past the kernel's 256-byte buffer with no blank or
    // newline is assumed truncated (ENOEXEC), never resolved.
    let truncated = temp.path().join("truncated.sh");
    let mut long = b"#!/".to_vec();
    long.extend(std::iter::repeat_n(b'a', 300));
    long.extend_from_slice(format!("\ntouch '{}'\n", marker.display()).as_bytes());
    executable(&truncated, &long);
    // `#!` followed only by blanks names no interpreter.
    let blank = temp.path().join("blank.sh");
    executable(
        &blank,
        format!("#!   \ntouch '{}'\n", marker.display()).as_bytes(),
    );
    let mut programs = vec![bogus, noise, nested, object, truncated, blank];
    // An executable ELF header for a machine this kernel does not run, and
    // one whose program-header entry size is wrong: both ENOEXEC.
    let (native, foreign_machine) = if cfg!(target_arch = "x86_64") {
        (62u16, 183u16)
    } else {
        (183u16, 62u16)
    };
    for (index, (machine, phentsize)) in [(foreign_machine, 56u16), (native, 12u16)]
        .into_iter()
        .enumerate()
    {
        let mut content = vec![0u8; 64];
        content[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\x00");
        content[16..18].copy_from_slice(&2u16.to_le_bytes());
        content[18..20].copy_from_slice(&machine.to_le_bytes());
        content[54..56].copy_from_slice(&phentsize.to_le_bytes());
        content[56..58].copy_from_slice(&1u16.to_le_bytes());
        content.extend_from_slice(format!("\ntouch '{}'\n", marker.display()).as_bytes());
        let path = temp.path().join(format!("elf-{index}"));
        executable(&path, &content);
        if cfg!(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )) {
            programs.push(path);
        }
    }
    for program in &programs {
        let done = launch(&r, &temp, program);
        assert_eq!(
            (done.state.as_str(), done.reason.as_deref()),
            ("failed", Some("spawn_failed")),
            "{program:?}: exit={:?} stderr={:?}",
            done.exit_code,
            String::from_utf8_lossy(&done.stderr)
        );
        assert_eq!(finish_reasons(&ctx, &done), vec![json!("spawn_failed")]);
    }
    assert!(!marker.exists(), "no refused file may execute any text");
}

/// `_posixsubprocess` tries every `PATH` entry and runs the first whose
/// `execve` succeeds: a no-format file (ENOEXEC) or a `#!` naming a missing
/// interpreter (ENOENT) earlier on `PATH` is skipped, never run through a
/// shell (measured with python3.12: `Popen(["tool"], env={"PATH": "A:B"})`
/// prints B's output). With no runnable candidate the spawn fails.
#[test]
fn path_search_skips_candidates_the_kernel_refuses() {
    let (temp, ctx, r) = registry();
    let marker = temp.path().join("marker-path");
    let first = temp.path().join("A");
    let second = temp.path().join("B");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    executable(
        &first.join("tool"),
        format!("touch '{}'\n", marker.display()).as_bytes(),
    );
    executable(&second.join("tool"), b"#!/bin/sh\nprintf \"$0\"\n");
    executable(&first.join("tool2"), b"#!/nonexistent/interpreter\n");
    executable(&second.join("tool2"), b"#!/bin/sh\nprintf second\n");
    executable(
        &first.join("text-only"),
        format!("touch '{}'\n", marker.display()).as_bytes(),
    );
    let path = format!("{}:{}", first.display(), second.display());
    let done = launch_with_path(&r, &temp, "tool", &path);
    assert_eq!(done.state, "completed", "{:?}", done.reason);
    // The kernel hands the interpreter the resolved script path.
    assert_eq!(
        done.stdout,
        second.join("tool").to_string_lossy().as_bytes()
    );
    let done = launch_with_path(&r, &temp, "tool2", &path);
    assert_eq!(
        (done.state.as_str(), done.stdout.as_slice()),
        ("completed", b"second".as_slice())
    );
    for missing in ["text-only", "absent-tool"] {
        let done = launch_with_path(&r, &temp, missing, &path);
        assert_eq!(
            (done.state.as_str(), done.reason.as_deref()),
            ("failed", Some("spawn_failed")),
            "{missing}"
        );
        assert_eq!(finish_reasons(&ctx, &done), vec![json!("spawn_failed")]);
    }
    // `#!/bin/sh\r` names the interpreter "/bin/sh\r": ENOENT, not a shell.
    let crlf = temp.path().join("crlf.sh");
    executable(
        &crlf,
        format!("#!/bin/sh\r\ntouch '{}'\n", marker.display()).as_bytes(),
    );
    let done = launch(&r, &temp, &crlf);
    assert_eq!(
        (done.state.as_str(), done.reason.as_deref()),
        ("failed", Some("spawn_failed"))
    );
    // A FIFO is not a regular file (EACCES); inspecting it must not block.
    let fifo = temp.path().join("fifo");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status();
    if made.is_ok_and(|s| s.success()) {
        std::fs::set_permissions(&fifo, std::fs::Permissions::from_mode(0o700)).unwrap();
        let done = launch(&r, &temp, &fifo);
        assert_eq!(
            (done.state.as_str(), done.reason.as_deref()),
            ("failed", Some("spawn_failed"))
        );
    }
    assert!(!marker.exists(), "a refused candidate must never execute");
}

#[test]
fn shebang_scripts_and_native_programs_still_run() {
    let (temp, _ctx, r) = registry();
    let expected = python_shebang_shapes();
    let marker = temp.path().join("marker-shebang");
    let script = temp.path().join("tool.sh");
    executable(
        &script,
        format!(
            "#!/bin/sh\ntouch '{}'\nprintf script-ran\n",
            marker.display()
        )
        .as_bytes(),
    );
    let done = launch(&r, &temp, &script);
    assert_eq!(done.state, "completed", "{:?}", done.reason);
    assert_eq!(done.stdout, b"script-ran");
    assert!(marker.exists());
    // `#! interpreter` with blanks, and an interpreter that is itself a script.
    let spaced = temp.path().join("spaced.sh");
    executable(&spaced, b"#! \t/bin/sh -e\nprintf spaced\n");
    let chained = temp.path().join("chained.sh");
    executable(
        &chained,
        format!("#!{}\nprintf chained-text-never-read\n", spaced.display()).as_bytes(),
    );
    let done = launch(&r, &temp, &spaced);
    assert_eq!(
        (done.state.as_str(), done.stdout.as_slice()),
        ("completed", b"spaced".as_slice())
    );
    // Linux accepts a script as an interpreter; macOS rejects the second
    // script level. Pin the original registry's result on the current OS.
    let done = launch(&r, &temp, &chained);
    assert_eq!(run_shape(&done), expected[0]);
    if done.state == "completed" {
        assert_eq!(done.stdout, b"spaced");
    } else {
        assert!(done.stdout.is_empty() && done.stderr.is_empty());
    }
    // XNU rejects newline-free interpreter directives that Linux accepts.
    // Exercise several shapes so this remains a loader-class comparison,
    // rather than a special case for the exact bytes in QA-MACOS-EXEC-01.
    for (index, (name, content)) in [
        ("bare.sh", b"#!/bin/sh".as_slice()),
        ("bare-spaced.sh", b"#! /bin/sh".as_slice()),
        ("bare-argument.sh", b"#!/bin/sh -e".as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        let script = temp.path().join(name);
        executable(&script, content);
        let done = launch(&r, &temp, &script);
        assert_eq!(run_shape(&done), expected[index + 1], "{name}");
    }
    let run = queued(&r, "/bin/sh");
    let started = r
        .start(
            &run,
            &["/bin/sh".into(), "-c".into(), "printf native".into()],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            Some(5.0),
        )
        .unwrap();
    let done = r.wait(&started, Some(8.0));
    assert_eq!(
        (done.state.as_str(), done.stdout.as_slice()),
        ("completed", b"native".as_slice())
    );
}

// ---------------------------------------- gap 2: tools.request header names

/// Python setup mirroring [`HttpFixture`], then `tools.dispatch("request")`
/// for each header mapping in `CASES` (base64 JSON); one JSON line per case.
const PY_TOOLS_HEADERS: &str = r#"
import base64, json, tempfile
from pathlib import Path
from zeropw import policy as P, tools
from zeropw.context import Config, Context
from zeropw.errors import ZeroPWError
from zeropw.fake_upstream import FakeUpstream
SECRET = "synthetic-parity-secret-0123456789"
tmp = tempfile.TemporaryDirectory()
ctx = Context.initialize(Path(tmp.name) / "state", "synthetic-admin-passphrase", "synthetic-recovery-passphrase", Config())
ctx.projects.create("demo")
fake = FakeUpstream(SECRET).start()
ctx.vault.put_secret("key", "api_key", SECRET.encode(), "demo", "dev")
ctx.policy.create_principal("alice")
ctx.policy.create_connection(P.Connection(id="service", project="demo", environment="dev", service="api", kind="http",
    secret_id="key", secret_version=None, description="", http_target=P.HttpTarget("http", fake.host, fake.port),
    http_auth=P.HttpAuth("bearer"), http_scope=P.HttpScope(("GET",), ("/",), ()), ssh_target=None, cli=None,
    policy_version=0, status="active", created_at="", updated_at=""))
ctx.policy.create_grant("alice", "service", 3600, None)
for headers in json.loads(base64.b64decode(CASES)):
    before = len(fake.requests)
    try:
        r = tools.dispatch(ctx, "request", "alice", {"connection": "service", "method": "GET", "path": "/me", "headers": headers})
        out = {"status": r["status"], "reason": r["reason"], "sent": len(fake.requests) - before}
    except ZeroPWError as e:
        out = {"error": type(e).__name__, "reason": e.reason}
    print(json.dumps(out, sort_keys=True))
fake.stop()
"#;

#[test]
fn tools_request_header_names_and_values_match_python() {
    use base64::Engine as _;
    let cases = json!([
        {"X_Foo": "1"}, {"X.Foo": "1"}, {"X:Foo": "1"}, {"A".repeat(65): "1"}, {"A".repeat(64): "1"},
        {"Accept\n": "1"}, {"Accept\n\n": "1"}, {"Accept": "x\n"}, {"Accept": "x\n\n"},
        {"X-Foo": "a\nb"}, {"": "1"}, {"Accept": "text/plain"}, {"X-Ok": "1", "X_Bad": "a\u{1}"},
        {"X-Bad": "a\u{1}", "X_Bad": "1"}, {"\u{c4}": "1"}, {"X-Foo": "\u{e9}"}, {"X-Foo": "a\tb"},
        {"x-zeropw-handle": "1"}, {"X!Foo": "1"}, {"X~Foo": "1"}
    ]);
    let encoded = base64::engine::general_purpose::STANDARD.encode(cases.to_string());
    let expected: Vec<Value> = python(&format!("CASES = '{encoded}'\n{PY_TOOLS_HEADERS}"))
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let f = HttpFixture::new();
    let mut actual = Vec::new();
    for headers in cases.as_array().unwrap() {
        let before = f.fake.requests().len();
        let payload =
            json!({"connection": "service", "method": "GET", "path": "/me", "headers": headers});
        actual.push(
            match zeropw::tools::dispatch(&f.ctx, "request", "alice", &payload) {
                Ok(r) => json!({"status": r["status"], "reason": r["reason"],
                                "sent": f.fake.requests().len() - before}),
                Err(e) => json!({"error": e.name, "reason": e.reason}),
            },
        );
    }
    assert_eq!(actual.len(), expected.len());
    for ((case, rust), python) in cases.as_array().unwrap().iter().zip(&actual).zip(&expected) {
        assert_eq!(rust, python, "headers {case}");
    }
    // The cases that motivated the fix, spelled out.
    assert_eq!(expected[0]["reason"], "invalid_header_name");
    assert_eq!(expected[3]["reason"], "invalid_header_name");
    assert_eq!(expected[4]["status"], 200);
}

// ------------------------------- gap 5: set_public_url feeds the gateway

/// `SelfReferenceTests.test_target_that_is_zeropw_itself_is_refused_before_use`
/// ("public" target): the URL recorded by `tools.set_public_url` is what the
/// gateway's cheap pre-use check compares against, so a connection naming
/// ZeroPW's public host and port is refused before any use is consumed or
/// any name is resolved.
#[test]
fn set_public_url_feeds_the_self_reference_precheck() {
    use zeropw::policy::{Connection, HttpAuth, HttpScope, HttpTarget};
    let f = HttpFixture::new();
    let connection = Connection::new(
        "public",
        "demo",
        "dev",
        "api",
        "http",
        "key",
        None,
        "",
        Some(HttpTarget::new("http", "zeropw.invalid", 8443, None, false).unwrap()),
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
    f.ctx.policy.create_connection(connection).unwrap();
    let grant = f
        .ctx
        .policy
        .create_grant("alice", "public", Some(3600), None)
        .unwrap()
        .id;
    assert_eq!(
        zeropw::tools::set_public_url(&f.ctx, "http://ZeroPW.invalid:8443/").unwrap(),
        "http://ZeroPW.invalid:8443"
    );
    let result = zeropw::gateway::relay_for_caller(
        &f.ctx,
        "alice",
        "public",
        "GET",
        "/me",
        &Vec::new(),
        b"",
        None,
    );
    assert_eq!(
        (result.status.clone(), result.reason.as_deref()),
        (501.into(), Some("self_referential_target"))
    );
    assert_eq!(f.ctx.policy.get_grant(&grant).unwrap().uses, 0);
    let last = f.ctx.audit.tail(1).unwrap().pop().unwrap();
    assert_eq!(
        (&last["result"], &last["reason"]),
        (&json!("denied"), &json!("self_referential_target"))
    );
    assert!(f.fake.requests().is_empty());
}

// -------------------------------------------- gap 6: server request framing

/// Python's `ZeroPWServer` (synthetic context) answering each raw request in
/// `CASES` (base64 JSON list): connect, send, half-close, read to EOF. One
/// base64 response per line.
const PY_SERVER_EXCHANGE: &str = r#"
import base64, json, socket, tempfile
from pathlib import Path
from zeropw.context import Config, Context
from zeropw.server import ZeroPWServer
tmp = tempfile.TemporaryDirectory()
ctx = Context.initialize(Path(tmp.name) / "state", "synthetic-admin-passphrase", "synthetic-recovery-passphrase", Config())
server = ZeroPWServer(ctx).serve_in_thread()
for raw in json.loads(base64.b64decode(CASES)):
    with socket.create_connection(server.server_address[:2], timeout=10) as sock:
        sock.sendall(base64.b64decode(raw))
        sock.shutdown(socket.SHUT_WR)
        out = b""
        try:
            while chunk := sock.recv(65536):
                out += chunk
        except OSError:
            pass
    print(base64.b64encode(out).decode())
server.stop()
"#;

fn rust_exchange(url: &str, raw: &[u8]) -> Vec<u8> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(url.trim_start_matches("http://")).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    stream.write_all(raw).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut out = Vec::new();
    let mut chunk = [0u8; 65536];
    while let Ok(n) = stream.read(&mut chunk) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    out
}

/// Replace each `Date:` header value (the only per-response variable).
fn without_dates(response: &[u8]) -> Vec<u8> {
    let text: String = response.iter().map(|b| char::from(*b)).collect();
    let re = regex::Regex::new(r"\r\nDate: [^\r]*\r\n").unwrap();
    re.replace_all(&text, "\r\nDate: <date>\r\n")
        .chars()
        .map(|c| c as u8)
        .collect()
}

/// `tests/test_gateway.py` framing cases plus the `BaseHTTPRequestHandler`
/// rules the audit found diverging: bare-LF lines, other HTTP/1.x versions,
/// malformed and 2.x versions, over-long request and header lines, header
/// count, unknown methods (HTML `send_error`), HTTP/0.9 requests, HTTP/1.0
/// keep-alive and `Expect: 100-continue` by version. Byte-identical replies
/// (apart from `Date`).
#[test]
fn server_framing_matches_python_byte_for_byte() {
    use base64::Engine as _;
    let mut cases: Vec<Vec<u8>> = vec![
        b"GET /healthz HTTP/1.1\nHost: x\n".to_vec(),
        b"GET /healthz HTTP/1.1\nHost: x\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/1.1\r\nHost: x\n".to_vec(),
        b"GET /healthz HTTP/1.2\r\nConnection: close\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/01.1\r\nConnection: close\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/1.x\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/1\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/1.1.1\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/2.0\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/12345678901.1\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/1.1 extra\r\n\r\n".to_vec(),
        b"GET /healthz\r\n\r\n".to_vec(),
        b"POST /healthz\r\n\r\n".to_vec(),
        b"GET\r\n\r\n".to_vec(),
        b"\r\n".to_vec(),
        b"  \t \r\n".to_vec(),
        b"BREW /healthz HTTP/1.1\r\n\r\n".to_vec(),
        b"get /healthz HTTP/1.1\r\n\r\n".to_vec(),
        b"G\xc9T /healthz HTTP/1.1\r\n\r\n".to_vec(),
        b"TRACE /healthz HTTP/1.1\r\nConnection: close\r\n\r\n".to_vec(),
        b"CONNECT x:443 HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        b"GET /healthz HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET /healthz HTTP/1.1\r\nConnection: close\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/1.0\r\n\r\nGET /healthz HTTP/1.1\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/1.1\r\nConnection: close\r\n\r\nGET /healthz HTTP/1.1\r\n\r\n".to_vec(),
        b"POST /v1/tools/list_connections HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        b"POST /v1/tools/list_connections HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        b"POST /v1/tools/list_connections HTTP/1.01\r\nExpect: 100-Continue\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        b"POST /relay HTTP/1.1\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/1.1\r\nHost : x\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/1.1\r\nHost: x\r\n  folded\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/1.1\r\nContent-Length: 1, 1\r\n\r\n".to_vec(),
        b"GET http://x/healthz HTTP/1.1\r\n\r\n".to_vec(),
        b"GET http://x/healthz HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        b"GET //healthz HTTP/1.1\r\nConnection: close\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/1.1\r\nVia: 1.0 edge, 1.1 ZEROPW-RELAY (x)\r\nConnection: close\r\n\r\n".to_vec(),
        b"GET /healthz HTTP/1.1\r\nVia: 1.1\x1czeropw-relay\r\nConnection: close\r\n\r\n".to_vec(),
        b"HEAD /healthz HTTP/1.1\r\nConnection: close\r\n\r\n".to_vec(),
    ];
    // Over-long request line and header line (exactly 65537 bytes, so the
    // server drains the socket), and 100 header lines plus the terminator.
    let mut long_line = b"GET /".to_vec();
    long_line.resize(65537, b'a');
    cases.push(long_line);
    let mut long_header = b"GET /healthz HTTP/1.1\r\nX-Long: ".to_vec();
    let header_start = b"GET /healthz HTTP/1.1\r\n".len();
    long_header.resize(header_start + 65537, b'b');
    cases.push(long_header);
    for (method, count) in [("GET", 100), ("HEAD", 100), ("GET", 99)] {
        let mut many = format!("{method} /healthz HTTP/1.1\r\n").into_bytes();
        for index in 0..count {
            many.extend_from_slice(format!("X-{index}: v\r\n").as_bytes());
        }
        many.extend_from_slice(b"Connection: close\r\n\r\n");
        cases.push(many);
    }
    let encoded: Vec<String> = cases
        .iter()
        .map(|c| base64::engine::general_purpose::STANDARD.encode(c))
        .collect();
    let script = format!(
        "CASES = '{}'\n{PY_SERVER_EXCHANGE}",
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&encoded).unwrap())
    );
    let expected: Vec<Vec<u8>> = python(&script)
        .lines()
        .map(|line| {
            base64::engine::general_purpose::STANDARD
                .decode(line)
                .unwrap()
        })
        .collect();
    assert_eq!(expected.len(), cases.len());
    let (_temp, ctx) = context();
    let server = zeropw::server::ZeroPWServer::new(ctx, Some("127.0.0.1"), Some(0)).unwrap();
    server.serve_in_thread().unwrap();
    let mut mismatches = Vec::new();
    for (case, python) in cases.iter().zip(&expected) {
        let rust = rust_exchange(&server.url(), case);
        if without_dates(&rust) != without_dates(python) {
            mismatches.push(format!(
                "request {:?}\n  python {:?}\n  rust   {:?}",
                String::from_utf8_lossy(&case[..case.len().min(120)]),
                String::from_utf8_lossy(&without_dates(python)),
                String::from_utf8_lossy(&without_dates(&rust))
            ));
        }
    }
    server.stop();
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    // The shapes the audit named, spelled out on Python's own replies.
    let text = |i: usize| String::from_utf8_lossy(&expected[i]).into_owned();
    assert!(text(0).contains("\"malformed_header\""));
    assert!(text(3).starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(text(8).starts_with("<!DOCTYPE HTML>"), "{}", text(8));
    assert!(text(16).starts_with("HTTP/1.1 501 Unsupported method ('BREW')\r\n"));
    assert_eq!(text(21).matches("HTTP/1.1 200 OK").count(), 2);
    assert!(!text(24).contains("100 Continue"));
    assert!(text(25).starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 401"));
    assert!(text(cases.len() - 5).starts_with("HTTP/1.1 414 Request-URI Too Long\r\n"));
}

// ------------------------------------------------ gap 7: run registry parity

/// `credential_patterns` strips with `bytes.strip()` (`Py_ISSPACE`, which
/// includes `\x0b`); the whole pattern list matches Python's.
#[test]
fn credential_patterns_strip_like_bytes_strip() {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    for secret in [
        b"\x0bsynthetic-secret\x0b".as_slice(),
        b"\x0c\t synthetic-secret\r\n",
        b"\x1csynthetic-secret\x1c",
        b"synthetic-secret",
    ] {
        let expected = python(&format!(
            "import base64\nfrom zeropw import runs\nfor p in runs.credential_patterns(base64.b64decode('{}')):\n    print(base64.b64encode(p).decode())\n",
            engine.encode(secret)
        ));
        let actual: Vec<String> = zeropw::runs::credential_patterns(secret)
            .iter()
            .map(|p| engine.encode(p))
            .collect();
        assert_eq!(actual, expected.lines().collect::<Vec<_>>(), "{secret:?}");
    }
}

fn sleeper(r: &Arc<RunRegistry>, temp: &TempDir, grant: &str) -> Run {
    let run = r.create(
        "alice", "conn", grant, "http", "/bin/sh", None, "digest", None, None,
    );
    r.start(
        &run,
        &["/bin/sh".into(), "-c".into(), "sleep 30".into()],
        &HashMap::new(),
        temp.path(),
        &[],
        None,
        Some(60.0),
    )
    .unwrap()
}

/// `on_revoke`: `if kind == "grant" and grant_id` -- an empty grant id is
/// falsy, so the notification cancels every active run.
#[test]
fn grant_revoke_without_an_id_cancels_every_run() {
    let (temp, ctx, r) = registry();
    let first = sleeper(&r, &temp, "grant-1");
    let second = sleeper(&r, &temp, "grant-2");
    r.on_revoke("grant", Some(""));
    for run in [&first, &second] {
        let done = r.wait(run, Some(10.0));
        assert_eq!(
            (done.state.as_str(), done.reason.as_deref()),
            ("cancelled", Some("grant_revoked"))
        );
        assert_eq!(finish_reasons(&ctx, &done), vec![json!("grant_revoked")]);
    }
    // A named grant still cancels only its own runs.
    let third = sleeper(&r, &temp, "grant-3");
    let fourth = sleeper(&r, &temp, "grant-4");
    r.on_revoke("grant", Some("grant-3"));
    assert_eq!(r.wait(&third, Some(10.0)).state, "cancelled");
    assert_eq!(r.get(&fourth.id, "alice").unwrap().state, "running");
    r.shutdown("shutdown");
}

/// Blocks the first `run_finish` audit record (the supervisor is then
/// "mid-finish") and reports when that has begun.
fn slow_first_finish(ctx: &Context) -> Arc<std::sync::atomic::AtomicBool> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let entered = Arc::new(AtomicBool::new(false));
    let flag = entered.clone();
    ctx.audit.subscribe(move |record| {
        if record.get("event").and_then(Value::as_str) == Some("run_finish")
            && !flag.swap(true, Ordering::SeqCst)
        {
            std::thread::sleep(std::time::Duration::from_millis(1500));
        }
    });
    entered
}

fn quick(r: &Arc<RunRegistry>, temp: &TempDir) -> Run {
    let run = r.create(
        "alice", "conn", "grant", "http", "/bin/sh", None, "digest", None, None,
    );
    r.start(
        &run,
        &["/bin/sh".into(), "-c".into(), "printf done".into()],
        &HashMap::new(),
        temp.path(),
        &[],
        None,
        Some(10.0),
    )
    .unwrap()
}

fn await_flag(flag: &std::sync::atomic::AtomicBool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !flag.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(std::time::Instant::now() < deadline, "run never finished");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// `RunRegistry.shutdown` joins every supervisor thread: a run that was
/// already finishing is terminal when `shutdown` returns.
#[test]
fn shutdown_joins_a_run_that_is_finishing() {
    let (temp, ctx, r) = registry();
    let entered = slow_first_finish(&ctx);
    let run = quick(&r, &temp);
    await_flag(&entered);
    r.shutdown("shutdown");
    let after = r.get(&run.id, "alice").unwrap();
    assert_eq!(
        (after.state.as_str(), after.stdout.as_slice()),
        ("completed", b"done".as_slice())
    );
}

/// Python publishes a finishing run's terminal state before recording
/// `run_finish`, so `cancel` neither cancels it nor reports it active.
#[test]
fn cancel_of_a_finishing_run_reports_its_terminal_state() {
    let (temp, ctx, r) = registry();
    let entered = slow_first_finish(&ctx);
    let run = quick(&r, &temp);
    await_flag(&entered);
    let cancelled = r.cancel(&run.id, "alice", "cancelled_by_caller").unwrap();
    assert_eq!(
        (cancelled.state.as_str(), cancelled.reason.as_deref()),
        ("completed", None)
    );
    let cancels = ctx
        .audit
        .tail(100)
        .unwrap()
        .into_iter()
        .filter(|r| r["event"] == "run_cancel")
        .count();
    assert_eq!(cancels, 0);
}

/// `_supervise` joins each output reader for `FINALIZE_WAIT_SECONDS` in
/// turn: stderr, closed 12 s after the child exited while stdout stays open
/// longer, is still collected (measured with python3.12: completed after
/// 12.0 s with stdout b'' and stderr b'err-data').
#[test]
fn each_output_reader_gets_its_own_wait() {
    let (temp, _ctx, r) = registry();
    let script =
        "printf err-data >&2; (sleep 16 2>/dev/null &) ; (exec 1>/dev/null; sleep 12 &) ; exit 0";
    let run = r.create(
        "alice", "conn", "grant", "http", "/bin/sh", None, "digest", None, None,
    );
    let started = r
        .start(
            &run,
            &["/bin/sh".into(), "-c".into(), script.into()],
            &HashMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
            temp.path(),
            &[],
            None,
            Some(5.0),
        )
        .unwrap();
    let done = r.wait(&started, Some(40.0));
    assert_eq!(done.state, "completed", "{:?}", done.reason);
    assert_eq!(done.stdout, b"");
    assert_eq!(done.stderr, b"err-data");
}

/// Python's registry keeps its context alive: dropping every other owner
/// while `start` records `run_start` never leaves the run queued.
#[test]
fn start_keeps_its_context_for_the_whole_start() {
    let temp = TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            temp.path().join("state"),
            "synthetic-admin-passphrase",
            "synthetic-recovery-passphrase",
            Config::default(),
            zeropw::clock::system(),
        )
        .unwrap(),
    );
    let r = zeropw::runs::install(ctx.clone());
    let owner = Arc::new(std::sync::Mutex::new(Some(ctx.clone())));
    let released = owner.clone();
    ctx.audit.subscribe(move |record| {
        if record.get("event").and_then(Value::as_str) == Some("run_start") {
            released.lock().unwrap().take();
        }
    });
    drop(ctx);
    let run = r.create(
        "alice", "conn", "grant", "http", "/bin/sh", None, "digest", None, None,
    );
    let started = r
        .start(
            &run,
            &["/bin/sh".into(), "-c".into(), "printf ok".into()],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            Some(5.0),
        )
        .expect("start must not fail because another owner let go");
    let done = r.wait(&started, Some(10.0));
    assert_eq!(
        (done.state.as_str(), done.stdout.as_slice()),
        ("completed", b"ok".as_slice())
    );
    assert!(owner.lock().unwrap().is_none());
}

/// `tools._resolve_program` in a child process whose `PATH` and cwd are
/// controlled (`std::env::set_var` is `unsafe`): prints one JSON line.
#[test]
fn resolve_program_child() {
    let Ok(program) = std::env::var("ZEROPW_RESOLVE_PROGRAM") else {
        return;
    };
    let resolved = zeropw::tools::resolve_program(&program).map(|p| p.display().to_string());
    println!("RESOLVED={}", json!(resolved));
}

/// `shutil.which` semantics (`PATH=""` matches nothing, `PATH=":"` is the
/// cwd, the first existing executable non-directory wins even when it is
/// not a regular file) and `os.path.abspath` normalisation, against Python.
#[test]
fn resolve_program_matches_python() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().canonicalize().unwrap();
    executable(&root.join("tool"), b"#!/bin/sh\n");
    std::fs::create_dir_all(root.join("dirs/tool")).unwrap();
    std::fs::create_dir(root.join("fifo")).unwrap();
    std::fs::create_dir(root.join("regular")).unwrap();
    executable(&root.join("regular/tool"), b"#!/bin/sh\n");
    let fifo_made = std::process::Command::new("mkfifo")
        .arg(root.join("fifo/tool"))
        .status()
        .is_ok_and(|s| s.success());
    if fifo_made {
        std::fs::set_permissions(
            root.join("fifo/tool"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    let r = root.display().to_string();
    let mut cases = vec![
        ("tool".to_string(), String::new()),
        ("tool".to_string(), ":".to_string()),
        ("tool".to_string(), "/nonexistent-zeropw:".to_string()),
        ("tool".to_string(), format!("{r}/dirs:{r}/regular")),
        ("./tool".to_string(), "/usr/bin:/bin".to_string()),
        (format!("{r}/regular/../tool"), "/usr/bin:/bin".to_string()),
        ("regular//./tool".to_string(), "/usr/bin:/bin".to_string()),
        ("sh".to_string(), "/usr/bin/../bin".to_string()),
        (
            "missing-zeropw-tool".to_string(),
            "/usr/bin:/bin".to_string(),
        ),
    ];
    if fifo_made {
        cases.push(("tool".to_string(), format!("{r}/fifo:{r}/regular")));
    }
    let exe = std::env::current_exe().unwrap();
    // Resolved here: the child's own `PATH` is the case under test.
    let interpreter = std::env::var("ZEROPW_PYTHON")
        .map(std::path::PathBuf::from)
        .ok()
        .or_else(|| zeropw::tools::resolve_program("python3.12"))
        .expect("python3.12 oracle");
    for (program, path) in cases {
        let python_out = std::process::Command::new(&interpreter)
        .args([
            "-c",
            "import json, sys\nfrom zeropw import tools\nprint(json.dumps(tools._resolve_program(sys.argv[1])))",
            &program,
        ])
        .env("PYTHONPATH", repo_root())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PATH", &path)
        .current_dir(&root)
        .output()
        .unwrap();
        assert!(python_out.status.success(), "{python_out:?}");
        let expected = String::from_utf8(python_out.stdout).unwrap();
        let rust_out = std::process::Command::new(&exe)
            .args([
                "resolve_program_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ZEROPW_RESOLVE_PROGRAM", &program)
            .env("PATH", &path)
            .current_dir(&root)
            .output()
            .unwrap();
        let stdout = String::from_utf8(rust_out.stdout).unwrap();
        let actual = stdout
            .lines()
            .find_map(|line| line.split_once("RESOLVED=").map(|(_, value)| value))
            .unwrap_or_else(|| panic!("child printed no result: {stdout}"));
        assert_eq!(actual, expected.trim(), "program {program:?} PATH {path:?}");
    }
}
