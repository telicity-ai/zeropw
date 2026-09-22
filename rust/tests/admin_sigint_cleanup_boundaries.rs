//! Owner-scoped administrator shutdown cleanup, compared with the Python CLI.

use std::process::Command;

#[test]
fn ordinary_exit_and_interrupt_remove_only_owned_context_directories() {
    let temp = tempfile::TempDir::new().unwrap();
    let script = r#"
import json,os,pathlib,signal,subprocess,sys,time
from zeropw.context import Context
results=[]
for mode in ('python','rust'):
 for outcome in ('signal','success','error'):
  base=pathlib.Path(sys.argv[2])/f'{mode}-{outcome}';base.mkdir()
  state=base/'state'
  Context.initialize(state,'synthetic-admin-cleanup','synthetic-recovery-cleanup').close()
  owned=base/'temp';owned.mkdir()
  # Identically prefixed unowned paths must never be removed by a scan.
  sentinels=('zeropw-runs-adopted','zeropw-sockets-adopted')
  for name in sentinels:(owned/name).mkdir()
  command=([sys.executable,'-m','zeropw.admin_cli'] if mode=='python' else [sys.argv[1]])
  env={'PATH':'/usr/bin:/bin','PYTHONPATH':sys.argv[3],'TMPDIR':str(owned),'ZEROPW_ADMIN_PASSPHRASE':'synthetic-admin-cleanup'}
  arguments=['--state-dir',str(state),'secret','put','--id','synthetic','--kind','api_key','--project','demo','--environment','dev','--stdin'] if outcome!='success' else ['--state-dir',str(state),'secret','list']
  anchor=None;source=None
  if outcome=='signal':
   fifo=base/'input';os.mkfifo(fifo,0o600)
   anchor=os.open(fifo,os.O_RDWR|os.O_NONBLOCK);source=open(fifo,'rb',buffering=0)
  elif outcome=='error':
   source=subprocess.DEVNULL
  p=subprocess.Popen(command+arguments,stdin=source,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
  try:
   if outcome=='signal':
    end=time.monotonic()+5
    while len(list(owned.iterdir()))!=4:
     assert p.poll() is None and time.monotonic()<end,('context dirs missing',mode,outcome)
     time.sleep(.01)
    time.sleep(.15)
    os.kill(p.pid,signal.SIGINT)
   p.communicate(timeout=5)
   names=sorted(x.name for x in owned.iterdir())
   results.append(dict(mode=mode,outcome=outcome,code=p.returncode,names=names))
   assert names==sorted(sentinels),(mode,outcome,names)
   assert p.returncode=={'signal':130,'success':0,'error':1}[outcome],(mode,outcome,p.returncode)
  finally:
   if p.poll() is None:p.kill();p.communicate(timeout=2)
   if source is not None and source is not subprocess.DEVNULL:source.close()
   if anchor is not None:os.close(anchor)
print(json.dumps(results))
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
        "owned-directory boundary: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn active_prompt_sigint_restores_terminal_and_removes_owned_context_directories() {
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
 try:code=p.wait(timeout=4)
 except subprocess.TimeoutExpired:code=None
 actual=termios.tcgetattr(0)
 expected=original.copy();observed=actual.copy()
 expected[3]&=~getattr(termios,'PENDIN',0);observed[3]&=~getattr(termios,'PENDIN',0)
 print('RESULT='+json.dumps({'code':code,'restored':expected==observed}),flush=True)
finally:
 if p.poll() is None:p.kill();p.wait(timeout=2)
 os.tcsetpgrp(0,os.getpgrp());termios.tcsetattr(0,termios.TCSANOW,original)
'''
results=[]
for mode in ('python','rust'):
 base=pathlib.Path(sys.argv[2])/mode;base.mkdir()
 state=base/'state'
 Context.initialize(state,'synthetic-admin-cleanup','synthetic-recovery-cleanup').close()
 owned=base/'temp';owned.mkdir()
 (owned/'zeropw-runs-adopted').mkdir()
 (owned/'zeropw-sockets-adopted').mkdir()
 master,slave=pty.openpty()
 command=([sys.executable,'-m','zeropw.admin_cli'] if mode=='python' else [sys.argv[1]])
 env={'PATH':'/usr/bin:/bin','PYTHONPATH':sys.argv[3],'TMPDIR':str(owned)}
 def terminal_session():
  os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
 p=subprocess.Popen([sys.executable,'-I','-c',keeper]+command+['--state-dir',str(state),'restore-ack'],stdin=slave,stdout=slave,stderr=slave,env=env,close_fds=True,preexec_fn=terminal_session)
 data=b''
 try:
  end=time.monotonic()+5
  while b'Administrator passphrase:' not in data or b'CHILD_PID=' not in data:
   assert time.monotonic()<end,('prompt timeout',mode,data)
   if select.select([master],[],[],0.05)[0]:data+=os.read(master,4096)
  child=int(re.search(rb'CHILD_PID=(\d+)',data)[1])
  assert not(termios.tcgetattr(slave)[3]&termios.ECHO),('echo visible',mode)
  assert len(list(owned.iterdir()))==4,('owned dirs absent',mode)
  os.kill(child,signal.SIGINT)
  end=time.monotonic()+7
  while b'RESULT=' not in data:
   assert time.monotonic()<end,('result timeout',mode,data)
   if select.select([master],[],[],0.05)[0]:data+=os.read(master,4096)
  result=json.loads(re.search(rb'RESULT=(\{[^\r\n]+\})',data)[1])
  result.update(mode=mode,names=sorted(x.name for x in owned.iterdir()))
  results.append(result)
  assert result['code']==130 and result['restored'],result
  assert result['names']==['zeropw-runs-adopted','zeropw-sockets-adopted'],result
  p.wait(timeout=3)
 finally:
  if p.poll() is None:p.kill();p.wait(timeout=2)
  os.close(master);os.close(slave)
print(json.dumps(results))
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
        "active-prompt cleanup: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
