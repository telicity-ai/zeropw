//! Controlled PTY launch semantics must not inherit a test runner's SIG_IGN
//! or blocked SIGINT mask. Original stimulus, deadlines and assertions remain.
use std::process::Command;

#[test]
fn prompt_abort_fixture_is_independent_of_runner_interrupt_disposition() {
    let script = include_str!("astra_cli_runtime_round3.rs")
        .split("let script = r#\"")
        .nth(1)
        .unwrap()
        .split("\"#;")
        .next()
        .unwrap();
    let driver = r#"
import signal,subprocess,sys
def inherited():
 signal.signal(signal.SIGINT,signal.SIG_IGN if sys.argv[1]=='ignored' else signal.SIG_DFL)
 if sys.argv[1]=='blocked':signal.pthread_sigmask(signal.SIG_BLOCK,[signal.SIGINT])
p=subprocess.run([sys.executable,'-I','-c',sys.argv[2]]+sys.argv[3:],preexec_fn=inherited,capture_output=True,timeout=20)
assert p.returncode==0,(p.stdout,p.stderr)
"#;
    #[cfg(target_os = "linux")]
    let read_syscall = libc::SYS_read.to_string();
    #[cfg(not(target_os = "linux"))]
    let read_syscall = "unsupported".to_owned();
    for inherited in ["ignored", "blocked"] {
        for mode in ["python", "rust"] {
            let temp = tempfile::TempDir::new().unwrap();
            let output = Command::new("python3.12")
                .args(["-I", "-c", driver, inherited, script])
                .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
                .arg(temp.path().join("state"))
                .arg(mode)
                .arg(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
                .arg("interrupt")
                .arg(&read_syscall)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{inherited} {mode}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
