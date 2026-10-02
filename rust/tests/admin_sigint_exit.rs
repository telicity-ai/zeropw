//! Process-level SIGINT exit-status parity with the original administrator CLI.
//! Synthetic state and a surviving controlling-PTY keeper only.

use std::process::Command;

#[test]
fn administrator_prompt_signal_status_matches_python_and_restores_terminal() {
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
for phase in ('during','after'):
 for mode,sig in ((mode,sig) for mode in ('python','rust') for sig in (signal.SIGINT,signal.SIGTERM)):
  state=pathlib.Path(sys.argv[2])/f'{phase}-{mode}-{sig}'
  Context.initialize(state,'synthetic-admin-sigint','synthetic-recovery-sigint')
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
    assert time.monotonic()<end,('prompt timeout',phase,mode,data)
    if select.select([master],[],[],0.05)[0]:data+=os.read(master,4096)
   child=int(re.search(rb'CHILD_PID=(\d+)',data)[1])
   assert not (termios.tcgetattr(slave)[3]&termios.ECHO),('prompt has echo',phase,mode)
   if phase=='after':
    # Keep the process alive after the password is consumed; only the
    # synthetic administrator verification read is delayed.
    (state/'admin.json').rename(state/'admin.saved')
    os.mkfifo(state/'admin.json',0o600)
    anchor=os.open(state/'admin.json',os.O_RDWR|os.O_NONBLOCK)
    os.write(master,b'synthetic-admin-sigint\n')
    end=time.monotonic()+3
    while not (termios.tcgetattr(slave)[3]&termios.ECHO):
     assert time.monotonic()<end,('echo not restored',phase,mode)
     time.sleep(0.005)
   time.sleep(0.15)
   os.kill(child,sig)
   end=time.monotonic()+7
   while b'RESULT=' not in data:
    assert time.monotonic()<end,('result timeout',phase,mode,data)
    if select.select([master],[],[],0.05)[0]:data+=os.read(master,4096)
   result=json.loads(re.search(rb'RESULT=(\{[^\r\n]+\})',data)[1])
   result.update(phase=phase,mode=mode,signal=int(sig));results.append(result)
   p.wait(timeout=3)
  finally:
   if anchor is not None:os.close(anchor)
   if p.poll() is None:p.kill();p.wait(timeout=2)
   os.close(master);os.close(slave)
print(json.dumps(results))
assert all(r['terminated'] for r in results),results
# Python's default active SIGTERM can skip rpassword's restoration; the
# native CLI promises restoration there and retains its existing regression.
assert all(r['restored'] for r in results if not (r['phase']=='during' and r['mode']=='python' and r['signal']==signal.SIGTERM)),results
assert all(r['code']==(130 if r['signal']==signal.SIGINT else -signal.SIGTERM) for r in results),results
"#;
    let output = Command::new("python3.12")
        .args(["-c", script])
        .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg(temp.path())
        .arg(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "prompt signal-status mismatch: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn administrator_serve_keeps_its_graceful_signal_stop() {
    let temp = tempfile::TempDir::new().unwrap();
    let script = r#"
import json,os,pathlib,select,signal,subprocess,sys,time
from zeropw.context import Context
python_serve='''
import os,signal,sys
from zeropw.admin_cli import main
ready_fd=int(sys.argv.pop(1))
original_signal=signal.signal
installed={}
def observe_registration(signum,handler):
 previous=original_signal(signum,handler)
 if signum in (signal.SIGINT,signal.SIGTERM):installed[signum]=handler
 if signum==signal.SIGTERM:
  assert callable(installed.get(signal.SIGINT)) and callable(handler)
  assert signal.getsignal(signal.SIGINT) is installed[signal.SIGINT]
  assert signal.getsignal(signal.SIGTERM) is handler
  signal.signal=original_signal
  os.write(ready_fd,b'R');os.close(ready_fd)
 return previous
signal.signal=observe_registration
sys.exit(main(sys.argv[1:]))
'''
results=[]
for mode in ('python','rust'):
 for sig in (signal.SIGINT,signal.SIGTERM):
  state=pathlib.Path(sys.argv[2])/f'{mode}-{sig}'
  Context.initialize(state,'synthetic-admin-serve','synthetic-recovery-serve')
  ready_read,ready_write=os.pipe()
  command=([sys.executable,'-c',python_serve,str(ready_write)] if mode=='python' else [sys.argv[1]])
  p=subprocess.Popen(command+['--state-dir',str(state),'serve','--quiet'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin','PYTHONPATH':sys.argv[3]},pass_fds=(ready_write,) if mode=='python' else ())
  os.close(ready_write)
  try:
   deadline=time.monotonic()+5
   ready,_,_=select.select([p.stdout],[],[],max(0,deadline-time.monotonic()))
   assert ready,('serve startup timeout',mode,sig)
   payload=json.loads(p.stdout.readline())
   assert payload['url'].startswith('http://127.0.0.1:'),(mode,payload)
   # Python prints its banner before installing handlers. Observe the actual
   # registrations, without changing them; the native banner follows both.
   if mode=='python':
    ready,_,_=select.select([ready_read],[],[],max(0,deadline-time.monotonic()))
    assert ready and os.read(ready_read,1)==b'R',('serve signal readiness timeout',mode,sig)
   os.kill(p.pid,sig)
   _,stderr=p.communicate(timeout=5)
   results.append({'mode':mode,'signal':int(sig),'code':p.returncode,'stderr':stderr.decode()})
  finally:
   if p.poll() is None:p.kill();p.communicate(timeout=2)
   os.close(ready_read)
print(json.dumps(results))
assert all(r['code']==0 and not r['stderr'] for r in results),results
"#;
    let output = Command::new("python3.12")
        .args(["-c", script])
        .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg(temp.path())
        .arg(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "serve signal-stop mismatch: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn ordinary_non_prompt_command_catches_sigint_as_exit_130() {
    let temp = tempfile::TempDir::new().unwrap();
    let script = r#"
import json,os,pathlib,signal,subprocess,sys,time
from zeropw.context import Context
results=[]
for mode,sig in ((mode,sig) for mode in ('python','rust') for sig in (signal.SIGINT,signal.SIGTERM)):
 state=pathlib.Path(sys.argv[2])/f'{mode}-{sig}'
 Context.initialize(state,'synthetic-admin-fifo','synthetic-recovery-fifo')
 fifo=state/'synthetic-secret-input'
 os.mkfifo(fifo,0o600)
 anchor=os.open(fifo,os.O_RDWR|os.O_NONBLOCK)
 source=open(fifo,'rb',buffering=0)
 command=([sys.executable,'-m','zeropw.admin_cli'] if mode=='python' else [sys.argv[1]])
 env={'PATH':'/usr/bin:/bin','PYTHONPATH':sys.argv[3],'ZEROPW_ADMIN_PASSPHRASE':'synthetic-admin-fifo'}
 p=subprocess.Popen(command+['--state-dir',str(state),'secret','put','--id','synthetic','--kind','api_key','--project','demo','--environment','dev','--stdin'],stdin=source,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
 try:
  time.sleep(1)
  assert p.poll() is None,('command did not block on FIFO',mode,p.returncode)
  os.kill(p.pid,sig)
  _,stderr=p.communicate(timeout=5)
  results.append({'mode':mode,'signal':int(sig),'code':p.returncode,'stderr':stderr.decode()})
 finally:
  if p.poll() is None:p.kill();p.communicate(timeout=2)
  source.close();os.close(anchor)
print(json.dumps(results))
assert all(r['code']==(130 if r['signal']==signal.SIGINT else -signal.SIGTERM) for r in results),results
"#;
    let output = Command::new("python3.12")
        .args(["-c", script])
        .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg(temp.path())
        .arg(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ordinary command SIGINT mismatch: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
