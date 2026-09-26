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
    // The kernel runs `/bin/sh -e spaced.sh chained.sh`: nested interpreters work.
    let done = launch(&r, &temp, &chained);
    assert_eq!(
        (done.state.as_str(), done.stdout.as_slice()),
        ("completed", b"spaced".as_slice())
    );
    // A short `#!/bin/sh` with no newline: the kernel's zero padding ends
    // the name, so it runs (measured with python3.12: exit 0).
    let bare = temp.path().join("bare.sh");
    executable(&bare, b"#!/bin/sh");
    let done = launch(&r, &temp, &bare);
    assert_eq!(
        (done.state.as_str(), done.exit_code),
        ("completed", Some(0))
    );
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
        (result.status, result.reason.as_deref()),
        (501, Some("self_referential_target"))
    );
    assert_eq!(f.ctx.policy.get_grant(&grant).unwrap().uses, 0);
    let last = f.ctx.audit.tail(1).unwrap().pop().unwrap();
    assert_eq!(
        (&last["result"], &last["reason"]),
        (&json!("denied"), &json!("self_referential_target"))
    );
    assert!(f.fake.requests().is_empty());
}
