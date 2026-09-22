//! Independent gpt-6-astra lifecycle review of product fix d2c87eb at 76e4eed.
//! Synthetic state, controlled children, and real local PTYs only.
use std::process::Command;

#[test]
fn terminal_prompt_completion_preserves_later_interrupt_and_termination() {
    check_terminal_signals("after");
}

#[test]
fn active_terminal_prompt_restores_modes_on_sigterm() {
    check_terminal_signals("during");
}

fn check_terminal_signals(phase: &str) {
    let temp = tempfile::TempDir::new().unwrap();
    let script = r#"
import fcntl,json,os,pathlib,pty,re,select,signal,subprocess,sys,termios,time
from zeropw.context import Context
keeper='''
import json,os,signal,subprocess,sys,termios
signal.signal(signal.SIGTTOU,signal.SIG_IGN)
original=termios.tcgetattr(0)
def child_group():
 os.setpgid(0,0);os.tcsetpgrp(0,os.getpgrp());signal.signal(signal.SIGTTOU,signal.SIG_DFL)
p=subprocess.Popen(sys.argv[1:],preexec_fn=child_group,close_fds=True)
print('CHILD_PID='+str(p.pid),flush=True)
try:
 try:
  code=p.wait(timeout=4);terminated=True
 except subprocess.TimeoutExpired:
  code=None;terminated=False
 actual=termios.tcgetattr(0)
 expected=original.copy();observed=actual.copy()
 expected[3]&=~getattr(termios,'PENDIN',0);observed[3]&=~getattr(termios,'PENDIN',0)
 print('RESULT='+json.dumps({'terminated':terminated,'code':code,'restored':expected==observed}),flush=True)
finally:
 if p.poll() is None:p.kill();p.wait(timeout=2)
 os.tcsetpgrp(0,os.getpgrp());termios.tcsetattr(0,termios.TCSANOW,original)
'''
results=[]
for mode in (('python','rust') if sys.argv[4]=='after' else ('rust',)):
 for sig in ((signal.SIGINT,signal.SIGTERM) if sys.argv[4]=='after' else (signal.SIGTERM,)):
  state=pathlib.Path(sys.argv[2])/f'{mode}-{sig}'
  ctx=Context.initialize(state,'synthetic-admin-round4','synthetic-recovery-round4')
  master,slave=pty.openpty()
  command=([sys.executable,'-m','zeropw.admin_cli'] if mode=='python' else [sys.argv[1]])
  env={'PATH':'/usr/bin:/bin','PYTHONPATH':sys.argv[3]}
  def terminal_session():
   os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
  p=subprocess.Popen([sys.executable,'-I','-c',keeper]+command+['--state-dir',str(state),'restore-ack'],stdin=slave,stdout=slave,stderr=slave,env=env,close_fds=True,preexec_fn=terminal_session)
  data=b'';anchor=None
  try:
   end=time.monotonic()+3
   while b'Administrator passphrase:' not in data or b'CHILD_PID=' not in data:
    assert time.monotonic()<end,('prompt timeout',mode,data)
    if select.select([master],[],[],0.05)[0]:data+=os.read(master,4096)
   child=int(re.search(rb'CHILD_PID=(\d+)',data)[1])
   assert not (termios.tcgetattr(slave)[3]&termios.ECHO),('visible prompt had echo',mode)
   if sys.argv[4]=='after':
    # Delay only the synthetic verification input after the pre-prompt check.
    (state/'admin.json').rename(state/'admin.saved')
    os.mkfifo(state/'admin.json',0o600)
    anchor=os.open(state/'admin.json',os.O_RDWR|os.O_NONBLOCK)
    os.write(master,b'synthetic-admin-round4\n')
    end=time.monotonic()+3
    while not (termios.tcgetattr(slave)[3]&termios.ECHO):
     assert time.monotonic()<end,('prompt never restored echo',mode)
     time.sleep(0.005)
   time.sleep(0.15)
   os.kill(child,sig)
   end=time.monotonic()+7
   while b'RESULT=' not in data:
    assert time.monotonic()<end,('result timeout',mode,data)
    if select.select([master],[],[],0.05)[0]:data+=os.read(master,4096)
   result=json.loads(re.search(rb'RESULT=(\{[^\r\n]+\})',data)[1])
   result.update(mode=mode,signal=int(sig));results.append(result)
   p.wait(timeout=3)
  finally:
   if anchor is not None:os.close(anchor)
   if p.poll() is None:p.kill();p.wait(timeout=2)
   os.close(master);os.close(slave)
print(json.dumps(results))
assert all(r['terminated'] and r['restored'] for r in results),results
"#;
    let output = Command::new("python3.12")
        .args(["-c", script])
        .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg(temp.path())
        .arg(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .arg(phase)
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "post-prompt signals: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn native_agent_help_is_a_successful_offline_operation() {
    for arguments in [vec!["--help"], vec!["-h"], vec!["request", "--help"]] {
        let python = Command::new("python3.12")
            .args(["-m", "zeropw.agent_cli"])
            .args(&arguments)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
            .output()
            .unwrap();
        assert!(python.status.success());
        let native = Command::new(env!("CARGO_BIN_EXE_zeropw-agent"))
            .args(&arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert!(
            native.status.success(),
            "{arguments:?}: native code={:?} stderr={}",
            native.status.code(),
            String::from_utf8_lossy(&native.stderr)
        );
        assert!(native.stderr.is_empty());
        assert!(String::from_utf8_lossy(&native.stdout).contains("usage:"));
    }
}

#[test]
fn finish_audit_callback_can_cancel_another_live_run() {
    use std::{
        collections::HashMap,
        sync::{Arc, mpsc},
        time::Duration,
    };
    use zeropw::{
        context::{Config, Context},
        runs::RunRegistry,
    };
    let temp = tempfile::TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            temp.path().join("state"),
            "synthetic-admin",
            "synthetic-recovery",
            Config::default(),
            zeropw::clock::system(),
        )
        .unwrap(),
    );
    let registry = RunRegistry::new(ctx.clone(), 1024, 0.05);
    let sibling = registry.create(
        "alice", "service", "grant", "http", "sleep", None, "a", None, None,
    );
    registry
        .start(
            &sibling,
            &["/bin/sleep".into(), "20".into()],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            Some(30.0),
        )
        .unwrap();
    let finisher = registry.create(
        "alice", "service", "grant", "http", "printf", None, "b", None, None,
    );
    let finisher_id = finisher.id.clone();
    let weak = Arc::downgrade(&registry);
    let (tx, rx) = mpsc::channel();
    ctx.audit.subscribe(move |record| {
        if record.get("event").and_then(serde_json::Value::as_str) == Some("run_finish")
            && record.get("run_id").and_then(serde_json::Value::as_str) == Some(&finisher_id)
        {
            let registry = weak.upgrade().unwrap();
            let view = registry.get(&finisher_id, "alice").unwrap();
            let cancelled = registry.cancel_all("audit_peer_stop", None);
            tx.send((view, cancelled)).unwrap();
        }
    });
    registry
        .start(
            &finisher,
            &["/usr/bin/printf".into(), "business-output".into()],
            &HashMap::new(),
            temp.path(),
            &[],
            None,
            Some(3.0),
        )
        .unwrap();
    let observed = rx.recv_timeout(Duration::from_secs(5));
    let finished = registry.wait(&finisher, Some(5.0));
    let sibling_done = registry.wait(&sibling, Some(5.0));
    registry.cancel_all("test_cleanup", None);
    let (early, cancelled) = observed.unwrap();
    assert_eq!(early.state, "running");
    assert!(early.stdout.is_empty() && early.stderr.is_empty());
    assert_eq!(cancelled, 1);
    assert_eq!(sibling_done.state, "cancelled");
    assert_eq!(sibling_done.reason.as_deref(), Some("audit_peer_stop"));
    assert_eq!(finished.state, "completed");
    assert_eq!(finished.stdout, b"business-output");
}
