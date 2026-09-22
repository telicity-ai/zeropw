//! Resource cleanup is not a terminal-state publication barrier.
use std::{
    collections::HashMap,
    os::unix::net::UnixListener,
    process::Command,
    sync::{Arc, mpsc},
    time::Duration,
};
use zeropw::{
    context::{Config, Context},
    runs::RunRegistry,
};

#[test]
fn cancelled_run_can_still_be_running_after_cleanup_closes_resource() {
    let python = r#"
import json,os,socket,tempfile,threading
from pathlib import Path
from zeropw.context import Context,Config
from zeropw.runs import RunRegistry
with tempfile.TemporaryDirectory() as tmp:
 root=Path(tmp);ctx=Context.initialize(root/'state','synthetic-admin-passphrase','synthetic-recovery-passphrase',Config())
 registry=RunRegistry(ctx,grace_seconds=0.05)
 path=root/'synthetic.sock';listener=socket.socket(socket.AF_UNIX);listener.bind(str(path));listener.listen()
 entered=threading.Event();release=threading.Event();released=[]
 def cleanup():
  listener.close();path.unlink();entered.set();released.append(release.wait(5))
 run=registry.create('alice','conn','grant','ssh','sleep')
 thread=None
 try:
  registry.start(run,['/bin/sleep','4'],{},str(root),cleanup=cleanup,timeout=4)
  assert registry.view(run)['state']=='running'
  thread=threading.Thread(target=lambda:registry.cancel(run.id,'alice','synthetic-withdrawal'))
  thread.start();assert entered.wait(5)
  assert not path.exists()
  assert registry.view(run)['state']=='running'
  assert run.cancel_requested
  release.set();thread.join(5);assert not thread.is_alive()
  assert released==[True]
  assert registry.wait(run,5).state=='cancelled'
  print(json.dumps({'resource_absent_while_running':True,'final':'cancelled'}))
 finally:
  release.set()
  if thread:thread.join(5)
  registry.shutdown();ctx.close()
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
    assert!(String::from_utf8_lossy(&oracle.stdout).contains("resource_absent_while_running"));

    let root = tempfile::TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            root.path().join("state"),
            "synthetic-admin-passphrase",
            "synthetic-recovery-passphrase",
            Config::default(),
            zeropw::clock::system(),
        )
        .unwrap(),
    );
    let registry = RunRegistry::new(ctx, 1024, 0.05);
    let socket = root.path().join("synthetic.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let cleanup_path = socket.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (cleanup_tx, cleanup_rx) = mpsc::channel();
    struct Release(mpsc::Sender<()>);
    impl Drop for Release {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }
    let release = Release(release_tx);
    let run = registry.create(
        "alice", "conn", "grant", "ssh", "sleep", None, "digest", None, None,
    );
    let started = registry
        .start(
            &run,
            &["/bin/sleep".into(), "4".into()],
            &HashMap::new(),
            root.path(),
            &[],
            Some(Box::new(move || {
                drop(listener);
                std::fs::remove_file(cleanup_path).unwrap();
                entered_tx.send(()).unwrap();
                cleanup_tx
                    .send(release_rx.recv_timeout(Duration::from_secs(5)).is_ok())
                    .unwrap();
            })),
            Some(4.0),
        )
        .unwrap();
    assert_eq!(started.state, "running");
    let (cancel_tx, cancel_rx) = mpsc::channel();
    let canceller_registry = registry.clone();
    let id = run.id.clone();
    let canceller = std::thread::spawn(move || {
        let result = canceller_registry.cancel(&id, "alice", "synthetic-withdrawal");
        let _ = cancel_tx.send(result);
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(!socket.exists());
    let during = registry.get(&run.id, "alice").unwrap();
    assert_eq!(during.state, "running");
    assert!(during.cancel_requested);
    drop(release);
    assert!(cleanup_rx.recv_timeout(Duration::from_secs(5)).unwrap());
    assert_eq!(
        cancel_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap()
            .state,
        "cancelled"
    );
    canceller.join().unwrap();
    assert_eq!(registry.wait(&run, Some(5.0)).state, "cancelled");
}
