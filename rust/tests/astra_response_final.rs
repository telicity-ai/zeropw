//! Independent gpt-6-astra check of the fix's own claimed Python mailbox corpus.
use std::process::Command;

#[test]
fn comment_inside_domain_preserves_original_transport_envelope() {
    let temp = tempfile::TempDir::new().unwrap();
    let script = r#"
import json,pathlib,socket,subprocess,sys,threading
from zeropw.context import Context
from zeropw.notify import send_test_message
ctx=Context.initialize(pathlib.Path(sys.argv[2])/'state','synthetic-admin','synthetic-recovery')
def receiver():
 listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
 port=listener.getsockname()[1];envelopes=[]
 def serve():
  with listener:
   wire,_=listener.accept()
   with wire:
    wire.settimeout(3);reader=wire.makefile('rb');wire.sendall(b'220 synthetic ready\r\n')
    while True:
     line=reader.readline()
     if not line:break
     upper=line.upper()
     if upper.startswith((b'MAIL',b'RCPT')):envelopes.append(line.decode().strip().split(':',1)[1])
     if upper.startswith(b'EHLO'):reply=b'250 synthetic\r\n'
     elif upper.startswith(b'DATA'):
      wire.sendall(b'354 data\r\n')
      while reader.readline()!=b'.\r\n':pass
      reply=b'250 accepted\r\n'
     elif upper.startswith(b'QUIT'):
      wire.sendall(b'221 bye\r\n');break
     else:reply=b'250 ok\r\n'
     wire.sendall(reply)
 thread=threading.Thread(target=serve,daemon=True);thread.start()
 return port,thread,envelopes
differences=[]
for sender,recipient in [
 ('sender@exa(comment)mple.com','recipient@example.com'),
 ('sender@example.com','recipient@exa(comment)mple.com'),
 ('sender@(comment)example.com','recipient@(comment)example.com'),
]:
 outcomes=[]
 for mode in ('python','rust'):
  port,thread,envelopes=receiver()
  ctx.state.write_json('notify.json',{'host':'127.0.0.1','port':port,'mode':'plain','sender':sender,'recipients':[recipient],'timeout_seconds':1})
  if mode=='python':result=send_test_message(ctx)
  else:
   output=subprocess.run([sys.argv[1],'--state-dir',str(ctx.state.path),'incident','notify-test'],capture_output=True,timeout=5,env={'PATH':'/usr/bin:/bin'})
   result=json.loads(output.stdout or output.stderr)
  thread.join(4);assert not thread.is_alive(),'receiver did not finish'
  assert result=={'status':'sent'},(mode,result)
  outcomes.append(envelopes)
 if outcomes[0]!=outcomes[1]:differences.append({'sender':sender,'recipient':recipient,'python':outcomes[0],'rust':outcomes[1]})
print(json.dumps(differences))
assert not differences,differences
"#;
    let output = Command::new("python3.12")
        .args(["-c", script])
        .arg(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg(temp.path())
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mailbox transport parity: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
