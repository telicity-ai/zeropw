//! Bounded lifecycle evidence using the real supervisor's existing cleanup hook.
use std::{
    collections::HashMap,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};
use zeropw::{
    context::{Config, Context},
    runs,
};

#[test]
fn supervisor_lease_outlives_caller_then_releases_without_cycle() {
    let root = tempfile::TempDir::new().unwrap();
    let ctx = Arc::new(
        Context::initialize(
            root.path().join("state"),
            "synthetic-admin-passphrase",
            "synthetic-recovery-passphrase",
            Config::default(),
            Arc::new(zeropw::store::now),
        )
        .unwrap(),
    );
    let weak = Arc::downgrade(&ctx);
    let dir = ctx.config.run_dir.clone().unwrap();
    let registry = runs::install(ctx.clone());
    let run = registry.create(
        "alice", "conn", "grant", "http", "true", None, "digest", None, None,
    );
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let deadline = Instant::now() + Duration::from_secs(4);
    registry
        .start(
            &run,
            &["/usr/bin/true".into()],
            &HashMap::new(),
            root.path(),
            &[],
            Some(Box::new(move || {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(4)).unwrap();
            })),
            Some(2.0),
        )
        .unwrap();
    entered_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .unwrap();
    drop(ctx);
    // The installed registry has only a Weak backreference. This live owner
    // is the blocked real supervisor, not an extra Context clone in the test.
    assert!(weak.upgrade().is_some());
    assert!(dir.exists());
    release_tx.send(()).unwrap();
    assert_eq!(
        registry
            .wait(
                &run,
                Some(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .as_secs_f64()
                )
            )
            .state,
        "completed"
    );
    drop(registry);
    while (weak.upgrade().is_some() || dir.exists()) && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(
        weak.upgrade().is_none(),
        "supervisor ownership did not release"
    );
    assert!(!dir.exists(), "Context-owned directory did not disappear");
}
