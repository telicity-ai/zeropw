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
p=subprocess.Popen(sys.argv[2:],preexec_fn=child_group,close_fds=True)
if int(sys.argv[1])>=0:
 os.write(int(sys.argv[1]),str(p.pid).encode()+b'\\n');os.close(int(sys.argv[1]))
try:
 try:p.wait(timeout=8)
 except subprocess.TimeoutExpired:
  # Diagnostics only on failure. Never inspect argv, environment, or input.
  try:
   mode=termios.tcgetattr(0)
   observed={'child_pid':p.pid,'child_pgrp':os.getpgid(p.pid),'keeper_pid':os.getpid(),
             'keeper_pgrp':os.getpgrp(),'tty_foreground':os.tcgetpgrp(0),
             'ISIG':bool(mode[3]&termios.ISIG),'ECHO':bool(mode[3]&termios.ECHO),
             'VINTR':repr(mode[6][termios.VINTR]),'VEOF':repr(mode[6][termios.VEOF])}
   if sys.platform.startswith('linux'):
    wanted={'State','SigPnd','ShdPnd','SigBlk','SigIgn','SigCgt'}
    with open(f'/proc/{p.pid}/status') as status:
     observed['proc_status']={line.split(':',1)[0]:line.split(':',1)[1].strip()
                              for line in status if line.split(':',1)[0] in wanted}
    try:
     with open(f'/proc/{p.pid}/wchan') as wchan:observed['wchan']=wchan.read().strip()
    except OSError as exc:observed['wchan_error']=type(exc).__name__
   print('PTY_TIMEOUT_DIAG',repr(observed),flush=True)
  except Exception as exc:
   print('PTY_TIMEOUT_DIAG_ERROR',type(exc).__name__,flush=True)
  raise
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
observe_read=sys.platform.startswith('linux') and sys.argv[3]=='python' and sys.argv[5]=='interrupt'
pid_read=None;pid_write=None;keeper_fd='-1';pass_fds=()
if observe_read:
 pid_read,pid_write=os.pipe();keeper_fd=str(pid_write);pass_fds=(pid_write,)
p=subprocess.Popen([sys.executable,'-I','-c',keeper,keeper_fd]+command+['--state-dir',sys.argv[2],'init'],stdin=slave,stdout=slave,stderr=slave,env=env,close_fds=True,pass_fds=pass_fds,preexec_fn=terminal_session)
if pid_write is not None:os.close(pid_write)
data=b'';end=time.monotonic()+5;child_pid=None
try:
 while b'Administrator passphrase:' not in data:
  assert time.monotonic()<end,('prompt timed out',data)
  if select.select([master],[],[],0.1)[0]:data+=os.read(master,4096)
 if observe_read:
  assert select.select([pid_read],[],[],max(0,end-time.monotonic()))[0],('controlled child PID timed out',data)
  child_pid_bytes=os.read(pid_read,64)
  assert child_pid_bytes.endswith(b'\n') and child_pid_bytes[:-1].isdigit(),('controlled child PID invalid',child_pid_bytes)
  child_pid=int(child_pid_bytes[:-1])
 def pgrp_or_error(fd):
  try:return os.tcgetpgrp(fd)
  except OSError as exc:return f'OSError:{exc.errno}'
 mode=termios.tcgetattr(slave)
 prewrite={'keeper_pid':p.pid,'child_pid':child_pid,'keeper_pgrp':os.getpgid(p.pid),
           'tty_foreground':pgrp_or_error(master),
           'ISIG':bool(mode[3]&termios.ISIG),'ECHO':bool(mode[3]&termios.ECHO),
           'VINTR':repr(mode[6][termios.VINTR]),'VEOF':repr(mode[6][termios.VEOF])}
 if observe_read:
  # CPython may flush the prompt before its blocking /dev/tty read begins.
  # A VINTR delivered in that gap can be handled before the read and leave
  # getpass waiting. Observe the actual foreground child's positive read on
  # our TTY, not the keeper's wait or an ambiguous kernel wchan. This shares
  # the original five-second startup deadline above, with no second signal.
  assert len(sys.argv)>6 and sys.argv[6].isdigit(),('linux SYS_read unavailable',prewrite)
  read_nr=int(sys.argv[6]);owned_tty=os.ttyname(slave)
  ready=False;last={'stage':'no foreground child'}
  while time.monotonic()<end:
   foreground=os.tcgetpgrp(master)
   current=termios.tcgetattr(slave)
   isig=bool(current[3]&termios.ISIG);echo=bool(current[3]&termios.ECHO)
   vintr=current[6][termios.VINTR];vintr3=vintr in (3,b'\x03')
   last={'foreground':foreground,'ISIG':isig,'ECHO':echo,'VINTR_3':vintr3}
   if foreground==child_pid and os.getpgid(child_pid)==child_pid:
    try:
     with open(f'/proc/{child_pid}/syscall') as syscall:words=syscall.read().split()
     if words and words[0] not in ('running','-1'):
      nr=int(words[0],0);last['syscall']=nr
      if nr==read_nr:
       assert len(words)>=4,('linux syscall metadata malformed',last)
       fd=int(words[1],0);count=int(words[3],0)
       last.update({'fd':fd,'positive_count':count>0})
      if nr==read_nr and count>0:
       link=os.readlink(f'/proc/{child_pid}/fd/{fd}')
       tty_fd=link in ('/dev/tty',owned_tty)
       last['controlled_tty_fd']=tty_fd
       ready=tty_fd and isig and not echo and vintr3
    except (OSError,ValueError) as exc:
     raise AssertionError(('linux TTY read observation unavailable',type(exc).__name__,getattr(exc,'errno',None),last)) from exc
   if ready:break
   remaining=end-time.monotonic()
   if remaining>0 and select.select([master],[],[],min(0.01,remaining))[0]:
    data+=os.read(master,4096)
  assert ready,('python prompt never entered controlled TTY read within five seconds',last,prewrite)
 os.write(master,b'\x03' if sys.argv[5]=='interrupt' else b'\x04')
 end=time.monotonic()+12
 while p.poll() is None and time.monotonic()<end:
  if select.select([master],[],[],0.1)[0]:
   try:data+=os.read(master,4096)
   except OSError as e:
    if e.errno!=errno.EIO:raise
 try:exit_code=p.wait(timeout=2)
 except subprocess.TimeoutExpired as exc:raise AssertionError((data,prewrite,'keeper still running')) from exc
 assert exit_code==0,(data,prewrite)
 assert b'terminal restored' in data,data
finally:
 if p.poll() is None:
  # On a readiness failure the foreground child is still waiting. Kill only
  # the process group created by this fixture before stopping its keeper.
  try:
   foreground=os.tcgetpgrp(master)
   if child_pid is not None and foreground==child_pid and foreground!=os.getpgrp() and os.getsid(child_pid)==os.getsid(p.pid):
    os.killpg(child_pid,signal.SIGKILL)
  except OSError:pass
  p.kill();p.wait()
 if pid_read is not None:os.close(pid_read)
 os.close(master);os.close(slave)
"#;
    #[cfg(target_os = "linux")]
    let read_syscall = libc::SYS_read.to_string();
    #[cfg(not(target_os = "linux"))]
    let read_syscall = "unsupported".to_owned();
    for mode in ["python", "rust"] {
        let output = Command::new("python3.12")
            .args(["-I", "-c", script])
            .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
            .arg(temp.path().join(mode))
            .arg(mode)
            .arg(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
            .arg(input)
            .arg(&read_syscall)
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

fn embedded_terminal_driver() -> String {
    include_str!("astra_cli_runtime_round3.rs")
        .split("let script = r#\"")
        .nth(1)
        .unwrap()
        .split("\"#;")
        .next()
        .unwrap()
        .to_owned()
}

fn run_derived_terminal_driver(script: &str, read_syscall: &str) -> std::process::Output {
    let temp = TempDir::new().unwrap();
    Command::new("python3.12")
        .args(["-I", "-c", script])
        .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg(temp.path().join("state"))
        .arg("python")
        .arg(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .arg("interrupt")
        .arg(read_syscall)
        .output()
        .unwrap()
}

#[test]
fn linux_tty_read_observer_fails_closed_without_syscall_abi_or_proc() {
    // Force only the observer branch on macOS as well as Linux. Both probes
    // stop before sending Ctrl+C; the driver cleans its controlled child.
    let source = embedded_terminal_driver();
    let branch = "observe_read=sys.platform.startswith('linux') and sys.argv[3]=='python' and sys.argv[5]=='interrupt'";
    assert_eq!(source.matches(branch).count(), 1);
    let forced = source.replacen(
        branch,
        "observe_read=sys.argv[3]=='python' and sys.argv[5]=='interrupt'",
        1,
    );
    let unavailable = run_derived_terminal_driver(&forced, "unsupported");
    assert!(!unavailable.status.success());
    assert!(
        String::from_utf8_lossy(&unavailable.stderr).contains("linux SYS_read unavailable"),
        "{}",
        String::from_utf8_lossy(&unavailable.stderr)
    );

    let proc_read =
        "with open(f'/proc/{child_pid}/syscall') as syscall:words=syscall.read().split()";
    assert_eq!(forced.matches(proc_read).count(), 1);
    let no_proc = forced.replacen(
        proc_read,
        "raise PermissionError(13,'controlled proc denial')",
        1,
    );
    let denied = run_derived_terminal_driver(&no_proc, "0");
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("linux TTY read observation unavailable"),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );

    // Both valid non-read `/proc/<pid>/syscall` states must remain not-ready,
    // including the short `-1 <sp> <pc>` form (no argument fields).
    let inactive = forced.replacen(
        proc_read,
        "words=['-1','0x0','0x0'] if int(time.monotonic()*100)%2 else ['running']",
        1,
    );
    let inactive_result = run_derived_terminal_driver(&inactive, "0");
    assert!(!inactive_result.status.success());
    assert!(
        String::from_utf8_lossy(&inactive_result.stderr)
            .contains("python prompt never entered controlled TTY read within five seconds"),
        "{}",
        String::from_utf8_lossy(&inactive_result.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_tty_read_observer_rejects_prompt_before_actual_read() {
    let source = embedded_terminal_driver();
    let command = "command=([sys.executable,'-m','zeropw.admin_cli'] if sys.argv[3]=='python' else [sys.argv[1]])";
    assert_eq!(source.matches(command).count(), 1);
    // The controlled foreground child has the exact hidden-echo prompt and
    // signal mode but waits in pause(), not in a read of its terminal.
    let staged = source.replacen(
        command,
        "command=[sys.executable,'-c','import os,signal,sys,termios; mode=termios.tcgetattr(0); mode[3]&=~termios.ECHO; termios.tcsetattr(0,termios.TCSAFLUSH,mode); sys.stderr.write(\"Administrator passphrase:\"); sys.stderr.flush(); signal.pause()']",
        1,
    );
    let output = run_derived_terminal_driver(&staged, &libc::SYS_read.to_string());
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("python prompt never entered controlled TTY read within five seconds"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // A blocked `read` on an unrelated pipe is not a terminal prompt read.
    let wrong_fd = source.replacen(
        command,
        "command=[sys.executable,'-c','import os,sys,termios; mode=termios.tcgetattr(0); mode[3]&=~termios.ECHO; termios.tcsetattr(0,termios.TCSAFLUSH,mode); sys.stderr.write(\"Administrator passphrase:\"); sys.stderr.flush(); r,w=os.pipe(); os.read(r,1)']",
        1,
    );
    let output = run_derived_terminal_driver(&wrong_fd, &libc::SYS_read.to_string());
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("python prompt never entered controlled TTY read within five seconds"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_tty_read_observer_accepts_actual_controlled_terminal_read() {
    let source = embedded_terminal_driver();
    let command = "command=([sys.executable,'-m','zeropw.admin_cli'] if sys.argv[3]=='python' else [sys.argv[1]])";
    assert_eq!(source.matches(command).count(), 1);
    // A synthetic child reaches a positive-length read on /dev/tty. Its
    // atexit handler restores ECHO before the keeper checks terminal modes.
    let active = source.replacen(
        command,
        "command=[sys.executable,'-c','import atexit,os,sys,termios; original=termios.tcgetattr(0); mode=original.copy(); mode[3]&=~termios.ECHO; termios.tcsetattr(0,termios.TCSAFLUSH,mode); atexit.register(termios.tcsetattr,0,termios.TCSANOW,original); sys.stderr.write(\"Administrator passphrase:\"); sys.stderr.flush(); os.read(os.open(\"/dev/tty\",os.O_RDONLY),1)']",
        1,
    );
    let output = run_derived_terminal_driver(&active, &libc::SYS_read.to_string());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
