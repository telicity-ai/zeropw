//! Independent SIGINT cleanup parity after opening synthetic Context state.
use std::process::Command;

#[test]
fn ordinary_sigint_removes_context_owned_runtime_directories() {
    let temp = tempfile::TempDir::new().unwrap();
    let script = r#"
import json,os,pathlib,signal,subprocess,sys,time
from zeropw.context import Context
results=[]
for mode in ('python','rust'):
 state=pathlib.Path(sys.argv[2])/mode
 ctx=Context.initialize(state,'synthetic-admin-cleanup','synthetic-recovery-cleanup');ctx.close()
 fifo=state/'synthetic-input';os.mkfifo(fifo,0o600)
 anchor=os.open(fifo,os.O_RDWR|os.O_NONBLOCK);source=open(fifo,'rb',buffering=0)
 owned=state.parent/(mode+'-owned');owned.mkdir()
 command=([sys.executable,'-m','zeropw.admin_cli'] if mode=='python' else [sys.argv[1]])
 env={'PATH':'/usr/bin:/bin','PYTHONPATH':sys.argv[3],'ZEROPW_ADMIN_PASSPHRASE':'synthetic-admin-cleanup','TMPDIR':str(owned)}
 def default_interrupt():
  signal.signal(signal.SIGINT,signal.SIG_DFL);signal.pthread_sigmask(signal.SIG_UNBLOCK,[signal.SIGINT])
 p=subprocess.Popen(command+['--state-dir',str(state),'secret','put','--id','synthetic','--kind','api_key','--project','demo','--environment','dev','--stdin'],stdin=source,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,preexec_fn=default_interrupt)
 try:
  deadline=time.monotonic()+5
  while len(list(owned.iterdir()))!=2:
   assert p.poll() is None and time.monotonic()<deadline,('no context dirs',mode)
   time.sleep(.01)
  before=sorted(x.name for x in owned.iterdir())
  assert any(x.startswith('zeropw-runs-') for x in before),before
  assert any(x.startswith('zeropw-sockets-') for x in before),before
  time.sleep(.15)
  os.kill(p.pid,signal.SIGINT)
  stdout,stderr=p.communicate(timeout=5)
  results.append(dict(mode=mode,code=p.returncode,before=before,after=sorted(x.name for x in owned.iterdir())))
  assert not stdout and not stderr,(mode,stdout,stderr)
 finally:
  if p.poll() is None:p.kill();p.communicate(timeout=2)
  source.close();os.close(anchor)
print(json.dumps(results))
assert all(r['code']==130 and not r['after'] for r in results),results
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
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
