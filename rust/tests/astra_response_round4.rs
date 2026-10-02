//! Independent gpt-6-astra response fix review at 584ac71.
//! Test-only Python driver, synthetic state, actual native notify CLI, loopback SMTP.
use std::process::Command;

#[test]
fn supported_comments_inside_mailbox_match_python() {
    run_probe("comments");
}

#[test]
fn smtp_data_reply_timeout_matches_original_error_identity() {
    run_probe("data_timeout");
}

fn run_probe(probe: &str) {
    let temp = tempfile::TempDir::new().unwrap();
    let script = r#"
import json,os,pathlib,socket,subprocess,sys,threading,time
from zeropw.context import Context
from zeropw.notify import send_test_message
ctx=Context.initialize(pathlib.Path(sys.argv[2])/'state','synthetic-admin','synthetic-recovery')
def receiver():
 listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
 port=listener.getsockname()[1];commands=[]
 def serve():
  with listener:
   wire,_=listener.accept()
   with wire:
    wire.settimeout(3);reader=wire.makefile('rb');wire.sendall(b'220 synthetic ready\r\n')
    while True:
     line=reader.readline()
     if not line:break
     commands.append(line.decode('utf-8').strip());upper=line.upper()
     if upper.startswith(b'EHLO'):reply=b'250 synthetic\r\n'
     elif upper.startswith(b'MAIL') and not upper.startswith(b'MAIL FROM:<SENDER@EXAMPLE.COM>'):reply=b'501 invalid sender\r\n'
     elif upper.startswith(b'RCPT') and not upper.startswith(b'RCPT TO:<RECIPIENT@EXAMPLE.COM>'):reply=b'501 invalid recipient\r\n'
     elif upper.startswith(b'DATA'):
      if sys.argv[3]=='data_timeout':time.sleep(0.2);break
      wire.sendall(b'354 data\r\n')
      while reader.readline()!=b'.\r\n':pass
      reply=b'250 accepted\r\n'
     elif upper.startswith(b'QUIT'):
      wire.sendall(b'221 bye\r\n');break
     else:reply=b'250 ok\r\n'
     wire.sendall(reply)
 thread=threading.Thread(target=serve,daemon=True);thread.start()
 return port,thread,commands
differences=[]
cases=[
 ('sender(Internal)@example.com','recipient@example.com'),
 ('sender@(Internal)example.com','recipient@example.com'),
 ('sender@example.com','recipient(Internal)@example.com'),
 ('sender@example.com','recipient@(Internal)example.com'),
 ('(Nested (inner)) sender@example.com','recipient@example.com'),
 ('sender@example.com(Nested (inner))','recipient@example.com'),
]
if sys.argv[3]=='data_timeout':cases=[('sender@example.com','recipient@example.com')]
for sender,recipient in cases:
 outcomes=[]
 for mode in ('python','rust'):
  port,thread,commands=receiver()
  config={'host':'127.0.0.1','port':port,'mode':'plain','sender':sender,'recipients':[recipient],'timeout_seconds':0.05 if sys.argv[3]=='data_timeout' else 1}
  ctx.state.write_json('notify.json',config)
  if mode=='python':result=send_test_message(ctx)
  else:
   output=subprocess.run([sys.argv[1],'--state-dir',str(ctx.state.path),'incident','notify-test'],capture_output=True,timeout=5,env={'PATH':'/usr/bin:/bin'})
   result=json.loads(output.stdout or output.stderr)
  thread.join(4);assert not thread.is_alive(),'receiver did not finish'
  outcomes.append((result,commands))
 if outcomes[0][0]!=outcomes[1][0]:differences.append({'sender':sender,'recipient':recipient,'outcomes':outcomes})
 if sys.argv[3]=='data_timeout':assert outcomes[0][0]=={'status':'failed','error':'SMTPServerDisconnected'},outcomes
print(json.dumps(differences))
assert not differences,differences
"#;
    let output = Command::new("python3.12")
        .args(["-c", script])
        .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg(temp.path())
        .arg(probe)
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "interior comment parity: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
