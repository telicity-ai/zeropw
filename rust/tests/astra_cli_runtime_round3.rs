//! Independent Astra follow-up boundaries for the session and prompt fixes.
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;
use tempfile::TempDir;
use zeropw::context::{Config, Context};
use zeropw::runs::{self, RunRegistry};

#[test]
fn ar_runtime_07_terminal_status_never_precedes_captured_output_publication() {
    let python = r#"
import json,threading,time
from types import SimpleNamespace
from zeropw.runs import RunRegistry,COMPLETED
entered=threading.Event();release=threading.Event()
class Audit:
 def record(self,*args,**kwargs): entered.set();assert release.wait(5)
r=RunRegistry(SimpleNamespace(clock=time.time,audit=Audit()))
run=r.create('alice','service','grant','http','printf')
t=threading.Thread(target=lambda:r._finalize(run,COMPLETED,None,0,b'business-output'))
t.start();assert entered.wait(5)
result=r.view(run)
release.set();t.join(5)
assert result['state']=='completed' and result['stdout']=='business-output',result
print(json.dumps(result))
"#;
    let oracle = Command::new("python3.12")
        .args(["-c", python])
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
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
    let registry = RunRegistry::new(ctx.clone(), 1024, 0.05);
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let listener_gate = gate.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    ctx.audit.subscribe(move |record| {
        if record.get("event").and_then(serde_json::Value::as_str) == Some("run_finish") {
            entered_tx.send(()).unwrap();
            let (lock, cv) = &*listener_gate;
            let guard = lock.lock().unwrap();
            let _ = cv
                .wait_timeout_while(guard, Duration::from_secs(5), |released| !*released)
                .unwrap();
        }
    });
    let run = registry.create(
        "alice", "service", "grant", "http", "printf", None, "digest", None, None,
    );
    registry
        .start(
            &run,
            &["/usr/bin/printf".into(), "business-output".into()],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            Some(3.0),
        )
        .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // A correct implementation may block this query until finalization is
    // complete, or expose a nonterminal state. Neither permits completed/empty.
    let (tx, rx) = mpsc::channel();
    let (query_registry, query_run) = (registry.clone(), run.clone());
    let query = std::thread::spawn(move || {
        tx.send(query_registry.get(&query_run.id, "alice").unwrap())
            .unwrap();
    });
    let early = rx.recv_timeout(Duration::from_millis(200)).ok();
    let (lock, cv) = &*gate;
    *lock.lock().unwrap() = true;
    cv.notify_all();
    query.join().unwrap();
    let final_result = registry.wait(&run, Some(5.0));
    assert_eq!(final_result.stdout, b"business-output");
    assert_eq!(final_result.state, "completed");
    if let Some(observed) = early {
        assert!(
            !runs::TERMINAL_STATES.contains(&observed.state.as_str())
                || observed.stdout == b"business-output",
            "terminal status was visible before the actual output: state={}, stdout={:?}",
            observed.state,
            observed.stdout
        );
    }
}

fn check_terminal_abort(input: &str) {
    let temp = TempDir::new().unwrap();
    let script = r#"
import errno,fcntl,os,pty,select,signal,subprocess,sys,termios,time
master,slave=pty.openpty()
env={'PATH':'/usr/bin:/bin','PYTHONPATH':sys.argv[4]}
command=([sys.executable,'-m','zeropw.admin_cli'] if sys.argv[3]=='python' else [sys.argv[1]])
keeper='''
import os,signal,subprocess,sys,termios
signal.signal(signal.SIGTTOU,signal.SIG_IGN)
original=termios.tcgetattr(0)
def child_group():
 # The controlled foreground child models an ordinary interactive launch,
 # independent of a CI parent's ignored or blocked interrupt disposition.
 signal.signal(signal.SIGINT,signal.SIG_DFL)
 signal.pthread_sigmask(signal.SIG_UNBLOCK,[signal.SIGINT])
 os.setpgid(0,0);os.tcsetpgrp(0,os.getpgrp());signal.signal(signal.SIGTTOU,signal.SIG_DFL)
p=subprocess.Popen(sys.argv[1:],preexec_fn=child_group,close_fds=True)
try:
 p.wait(timeout=8)
 actual=termios.tcgetattr(0)
 # macOS may set the transient PENDIN bit while restoring canonical input.
 # It describes queued input, not the caller's echo/signal/editing modes.
 expected=original.copy();observed=actual.copy()
 expected[3]&=~getattr(termios,'PENDIN',0);observed[3]&=~getattr(termios,'PENDIN',0)
 assert observed==expected,{'before_lflag':original[3],'after_lflag':actual[3],'exit':p.returncode}
 print('terminal restored',flush=True)
finally:
 if p.poll() is None:p.kill();p.wait(timeout=2)
 os.tcsetpgrp(0,os.getpgrp())
 termios.tcsetattr(0,termios.TCSANOW,original)
'''
def terminal_session():
 os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
p=subprocess.Popen([sys.executable,'-I','-c',keeper]+command+['--state-dir',sys.argv[2],'init'],stdin=slave,stdout=slave,stderr=slave,env=env,close_fds=True,preexec_fn=terminal_session)
data=b'';end=time.monotonic()+5
try:
 while b'Administrator passphrase:' not in data:
  assert time.monotonic()<end,'prompt timed out'
  if select.select([master],[],[],0.1)[0]:data+=os.read(master,4096)
 os.write(master,b'\x03' if sys.argv[5]=='interrupt' else b'\x04')
 end=time.monotonic()+12
 while p.poll() is None and time.monotonic()<end:
  if select.select([master],[],[],0.1)[0]:
   try:data+=os.read(master,4096)
   except OSError as e:
    if e.errno!=errno.EIO:raise
 assert p.wait(timeout=2)==0,data
 assert b'terminal restored' in data,data
finally:
 if p.poll() is None:p.kill();p.wait()
 os.close(master);os.close(slave)
"#;
    for mode in ["python", "rust"] {
        let output = Command::new("python3.12")
            .args(["-I", "-c", script])
            .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
            .arg(temp.path().join(mode))
            .arg(mode)
            .arg(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
            .arg(input)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode} {input}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn ar_cli_02_interrupt_restores_original_terminal_modes() {
    check_terminal_abort("interrupt");
}

#[test]
fn terminal_eof_restores_original_terminal_modes() {
    check_terminal_abort("eof");
}
