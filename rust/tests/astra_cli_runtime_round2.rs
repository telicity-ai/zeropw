//! Independent gpt-6-astra CLI/runtime round-two probes; all state is synthetic.
use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::Arc;
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::{runs::RunRegistry, tools};

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

#[test]
fn ar_runtime_05_unrelated_inheritable_descriptor_is_closed_in_agent_child() {
    let (temp, ctx) = context();
    let synthetic_path = temp.path().join("trusted-synthetic-descriptor");
    std::fs::write(&synthetic_path, b"synthetic-trusted-fd-value-round2").unwrap();
    let file = std::fs::File::open(&synthetic_path).unwrap();
    rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty()).unwrap();
    let oracle = Command::new("python3.12").args(["-I","-c","import os,subprocess,sys; os.fstat(int(sys.argv[1])); p=subprocess.run([sys.executable,'-I','-c','import os,sys\\ntry: print(os.read(int(sys.argv[1]),100).decode())\\nexcept OSError: print(\"closed\")',sys.argv[1]],stdout=subprocess.PIPE,close_fds=True,start_new_session=True); print(p.stdout.decode(),end='')"])
        .arg(file.as_raw_fd().to_string()).output().unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    assert_eq!(oracle.stdout, b"closed\n");
    let registry = RunRegistry::new(ctx, 1024, 0.05);
    let run = registry.create(
        "alice",
        "service",
        "grant",
        "http",
        "python3.12",
        None,
        "digest",
        None,
        None,
    );
    let script = format!(
        "import os\ntry: print(os.read({},100).decode())\nexcept OSError: print('closed')",
        file.as_raw_fd()
    );
    registry
        .start(
            &run,
            &[
                tools::resolve_program("python3.12")
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                "-I".into(),
                "-c".into(),
                script,
            ],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            Some(3.0),
        )
        .unwrap();
    rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::CLOEXEC).unwrap();
    let result = registry.wait(&run, Some(5.0));
    assert_eq!(result.state, "completed");
    assert_eq!(
        result.stdout, b"closed\n",
        "Python Popen(close_fds=True) must not pass unrelated trusted descriptors into agent child"
    );
}

#[test]
fn ar_runtime_06_http_execution_accepts_uncreated_configured_socket_directory() {
    let temp = TempDir::new().unwrap();
    let socket_dir = temp.path().join("provided-sockets");
    let ctx = Arc::new(
        Context::initialize(
            temp.path().join("state"),
            "synthetic-admin-passphrase",
            "synthetic-recovery-passphrase",
            Config {
                socket_dir: Some(socket_dir.clone()),
                run_dir: Some(temp.path().join("provided-runs")),
                ..Config::default()
            },
            zeropw::clock::system(),
        )
        .unwrap(),
    );
    assert!(!socket_dir.exists());
    let registry = RunRegistry::new(ctx, 1024, 0.05);
    let run = registry.create(
        "alice", "service", "grant", "http", "true", None, "digest", None, None,
    );
    registry
        .start(
            &run,
            &["/usr/bin/true".into()],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            Some(3.0),
        )
        .unwrap();
    let result = registry.wait(&run, Some(5.0));
    assert_eq!(
        result.state, "completed",
        "HTTP-only child unexpectedly failed: {:?}",
        result.reason
    );
}

#[test]
fn ar_cli_01_terminal_prompts_hide_both_passphrases() {
    let temp = TempDir::new().unwrap();
    let script = r#"
import errno,fcntl,json,os,pty,select,subprocess,sys,termios,time
master,slave=pty.openpty()
env={'PATH':'/usr/bin:/bin'}
env['PYTHONPATH']=sys.argv[4]
command=([sys.executable,'-m','zeropw.admin_cli'] if sys.argv[3]=='python' else [sys.argv[1]])
def terminal_session():
 os.setsid()
 fcntl.ioctl(0,termios.TIOCSCTTY,0)
p=subprocess.Popen(command+['--state-dir',sys.argv[2],'init'],stdin=slave,stdout=slave,stderr=slave,env=env,close_fds=True,preexec_fn=terminal_session)
os.close(slave)
data=b''
def receive_until(marker):
 global data
 end=time.monotonic()+10
 while marker not in data:
  if time.monotonic()>end: raise AssertionError('prompt timeout: '+repr(data))
  if select.select([master],[],[],0.1)[0]:
   try: chunk=os.read(master,4096)
   except OSError as e:
    if e.errno==errno.EIO: raise AssertionError('early EOF: '+repr(data))
    raise
   if not chunk: raise AssertionError('early EOF')
   data+=chunk
try:
 receive_until(b'Administrator passphrase:')
 os.write(master,b'synthetic-tty-admin-round2\n')
 receive_until(b'Recovery passphrase:')
 os.write(master,b'synthetic-tty-recovery-round2\n')
 end=time.monotonic()+15
 while p.poll() is None and time.monotonic()<end:
  if select.select([master],[],[],0.1)[0]:
   try: data+=os.read(master,4096)
   except OSError as e:
    if e.errno!=errno.EIO: raise
 assert p.wait(timeout=2)==0,repr(data)
 assert b'synthetic-tty-admin-round2' not in data,repr(data)
 assert b'synthetic-tty-recovery-round2' not in data,repr(data)
 assert b'kms_key_id' in data,repr(data)
 print('terminal prompts and echo suppression passed')
finally:
 if p.poll() is None: p.kill();p.wait()
 os.close(master)
"#;
    let oracle = Command::new("python3.12")
        .args(["-I", "-c", script])
        .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg(temp.path().join("python-state"))
        .arg("python")
        .arg(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap();
    assert!(
        oracle.status.success(),
        "Python terminal oracle: {}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    let output = Command::new("python3.12")
        .args(["-I", "-c", script])
        .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg(temp.path().join("state"))
        .arg("rust")
        .arg(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
