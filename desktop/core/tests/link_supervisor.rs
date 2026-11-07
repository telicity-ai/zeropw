//! `LinkSupervisor` with a fake `zeropw-link daemon` (records argv and environment, exits on
//! SIGTERM, or on its own when told) and a fake socket: start and readiness, private folder and
//! log, the pid file and adoption, stop, restart after an unexpected exit with a growing
//! backoff, and a missing binary.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::thread;
use std::time::{Duration, Instant};

use common::{
    FakeLink, Fixture, install_fake_link_daemon as install_shared_fake_link_daemon, link_spawns,
    wait_until,
};
use nix::sys::signal::kill;
use nix::unistd::Pid;
use serde_json::json;
use zeropw_desktop_core::link::{Backoff, LinkSupervisor};

// The status socket is an independent fixture. Observe the owned child's
// stable-start marker before killing it or asserting its recorded spawn count.
// This marker follows its one-time exit_after decision, so that setting up the
// next restart cannot make the first child exit before the intended SIGKILL.
fn install_fake_link_daemon(fx: &Fixture) {
    install_shared_fake_link_daemon(fx);
    let path = fx.paths.link_bin();
    let script = fs::read_to_string(&path).unwrap();
    let idle = "while :; do sleep 1; done";
    assert_eq!(script.matches(idle).count(), 1);
    fs::write(
        path,
        script.replace(idle, ": > \"$calls/$n.ready\"\nwhile :; do sleep 1; done"),
    )
    .unwrap();
}

fn wait_for_recorded_daemon(fx: &Fixture, number: usize) {
    assert!(
        wait_until(Duration::from_secs(3), || fx
            .paths
            .bin_dir
            .join(format!("link-calls/{number}.ready"))
            .is_file()),
        "owned fake daemon must finish startup before the test proceeds"
    );
    let calls = link_spawns(fx);
    assert_eq!(calls.len(), number);
    assert_eq!(
        calls[number - 1],
        [
            "daemon",
            "--state",
            &fx.paths.link_state_dir().to_string_lossy()
        ]
    );
}

fn supervisor(fx: &Fixture, backoff: Backoff) -> LinkSupervisor {
    LinkSupervisor::new(&fx.paths)
        .with_timeouts(Duration::from_secs(5), Duration::from_secs(3))
        .with_backoff(backoff)
}

fn status_socket(fx: &Fixture) -> FakeLink {
    FakeLink::start(&fx.paths.link_socket(), |_| {
        Some(json!({"ok": true, "enrolled": false, "online": false, "peers": []}))
    })
}

fn alive(pid: u32) -> bool {
    kill(Pid::from_raw(pid as i32), None).is_ok()
        && !String::from_utf8_lossy(
            &std::process::Command::new("/bin/ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .unwrap()
                .stdout,
        )
        .trim_start()
        .starts_with('Z')
}

#[test]
fn start_runs_the_daemon_privately_and_waits_for_its_socket() {
    let fx = Fixture::new();
    install_fake_link_daemon(&fx);
    let sup = supervisor(&fx, Backoff::default());
    // the socket answers only a little after the daemon starts
    let socket_path = fx.paths.link_socket();
    let late = thread::spawn(move || {
        thread::sleep(Duration::from_millis(400));
        FakeLink::start(&socket_path, |_| {
            Some(json!({"ok": true, "enrolled": false, "online": false, "peers": []}))
        })
    });
    let started = Instant::now();
    let process = sup.start().unwrap();
    assert!(started.elapsed() >= Duration::from_millis(350));
    let _socket = late.join().unwrap();
    assert!(process.running && process.available);
    let pid = process.pid.unwrap();
    wait_for_recorded_daemon(&fx, 1);

    let spawns = link_spawns(&fx);
    assert_eq!(spawns.len(), 1);
    assert_eq!(
        spawns[0],
        [
            "daemon",
            "--state",
            &fx.paths.link_state_dir().to_string_lossy()
        ]
    );
    let env = fs::read_to_string(fx.paths.bin_dir.join("link-calls/1.env")).unwrap();
    for line in env.lines() {
        let key = line.split('=').next().unwrap();
        assert!(
            [
                "PATH",
                "HOME",
                "LANG",
                "TMPDIR",
                "PWD",
                "SHLVL",
                "_",
                "OLDPWD",
                "__CF_USER_TEXT_ENCODING"
            ]
            .contains(&key),
            "unexpected variable {key}"
        );
    }
    let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&fx.paths.link_state_dir()), 0o700);
    assert_eq!(mode(&fx.paths.link_log_file()), 0o600);
    assert_eq!(mode(&fx.paths.link_pid_file()), 0o600);
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(fx.paths.link_pid_file()).unwrap()).unwrap();
    assert_eq!(record["pid"], pid);
    assert!(
        fs::read_to_string(fx.paths.link_log_file())
            .unwrap()
            .contains("fake link daemon 1")
    );

    // a second start while it runs starts nothing
    sup.start().unwrap();
    assert_eq!(link_spawns(&fx).len(), 1);

    // stop: SIGTERM, the pid file goes, and the watch does not bring it back
    sup.stop();
    assert!(wait_until(Duration::from_secs(3), || !alive(pid)));
    assert!(!fx.paths.link_pid_file().exists());
    sup.watch();
    thread::sleep(Duration::from_millis(100));
    sup.watch();
    assert_eq!(link_spawns(&fx).len(), 1);
    assert!(!sup.process().running);
}

#[test]
fn a_daemon_that_exits_is_restarted_after_a_growing_backoff() {
    let fx = Fixture::new();
    install_fake_link_daemon(&fx);
    let _socket = status_socket(&fx);
    let backoff = Backoff {
        initial: Duration::from_millis(700),
        max: Duration::from_secs(10),
        stable: Duration::from_secs(30),
    };
    let sup = supervisor(&fx, backoff);
    sup.start().unwrap();
    wait_for_recorded_daemon(&fx, 1);
    fs::write(fx.paths.bin_dir.join("responses/link.exit_after"), "0").unwrap();
    let first = sup.process().pid.unwrap();
    kill(
        Pid::from_raw(first as i32),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();

    // noticed at once, restarted only after the first delay
    assert!(wait_until(Duration::from_secs(3), || !sup
        .process()
        .running));
    let noticed = Instant::now();
    assert_eq!(sup.process().problem.as_deref(), Some("link_exited"));
    sup.watch();
    assert_eq!(link_spawns(&fx).len(), 1, "restarted before its backoff");
    assert!(wait_until(Duration::from_secs(3), || {
        sup.watch();
        link_spawns(&fx).len() == 2
    }));
    let first_wait = noticed.elapsed();
    assert!(first_wait >= Duration::from_millis(650), "{first_wait:?}");

    // the restarted daemon exits at once too: the next delay is twice as long
    assert!(wait_until(Duration::from_secs(3), || !sup
        .process()
        .running));
    let noticed = Instant::now();
    assert!(wait_until(Duration::from_secs(5), || {
        sup.watch();
        link_spawns(&fx).len() == 3
    }));
    let second_wait = noticed.elapsed();
    assert!(
        second_wait >= Duration::from_millis(1300),
        "{second_wait:?}"
    );
    assert!(sup.process().restarts >= 2);
    fs::remove_file(fx.paths.bin_dir.join("responses/link.exit_after")).unwrap();
    sup.stop();
}

#[test]
fn a_second_supervisor_adopts_a_running_daemon_and_ignores_a_foreign_pid() {
    let fx = Fixture::new();
    install_fake_link_daemon(&fx);
    let _socket = status_socket(&fx);
    let first = supervisor(&fx, Backoff::default());
    let pid = first.start().unwrap().pid.unwrap();
    wait_for_recorded_daemon(&fx, 1);
    let second = supervisor(&fx, Backoff::default());
    let adopted = second.start().unwrap();
    assert_eq!(adopted.pid, Some(pid));
    assert_eq!(link_spawns(&fx).len(), 1);
    second.stop();
    assert!(wait_until(Duration::from_secs(3), || !alive(pid)));

    // a pid file naming some other process is dropped, never signalled
    fs::write(
        fx.paths.link_pid_file(),
        format!(r#"{{"pid":{},"started_at":0}}"#, std::process::id()),
    )
    .unwrap();
    let third = supervisor(&fx, Backoff::default());
    let fresh = third.start().unwrap();
    wait_for_recorded_daemon(&fx, 2);
    assert_ne!(fresh.pid, Some(std::process::id()));
    assert_eq!(link_spawns(&fx).len(), 2);
    third.stop();
    first.stop();
}

#[test]
fn a_daemon_whose_socket_never_answers_times_out_and_a_missing_one_is_reported() {
    let fx = Fixture::new();
    let sup = LinkSupervisor::new(&fx.paths)
        .with_timeouts(Duration::from_millis(600), Duration::from_secs(2));
    let e = sup.start().unwrap_err();
    assert_eq!(e.reason, "link_binary_missing");
    assert!(!sup.process().available);
    sup.watch();
    assert!(link_spawns(&fx).is_empty());

    install_fake_link_daemon(&fx);
    let e = sup.start().unwrap_err();
    assert_eq!(e.reason, "link_start_timeout");
    let process = sup.process();
    assert!(process.running, "the process stays up for the next look");
    assert_eq!(process.problem.as_deref(), Some("link_start_timeout"));
    let pid = process.pid.unwrap();
    sup.stop();
    assert!(wait_until(Duration::from_secs(3), || !alive(pid)));
}

#[test]
fn status_socket_readiness_can_precede_the_owned_child_start_record() {
    let fx = Fixture::new();
    install_fake_link_daemon(&fx);
    let original = fx.paths.bin_dir.join("link-recording");
    fs::copy(fx.paths.link_bin(), &original).unwrap();
    let wrapper = r#"#!/bin/sh
dir=$(cd "$(dirname "$0")" && pwd)
: > "$dir/responses/link.start_blocked"
while [ ! -f "$dir/responses/link.release_start" ]; do sleep 0.01; done
exec "$dir/link-recording" "$@"
"#;
    fs::write(fx.paths.link_bin(), wrapper).unwrap();
    let _socket = status_socket(&fx);
    let sup = supervisor(&fx, Backoff::default());
    let process = sup.start().unwrap();
    assert!(process.running && sup.ready());
    assert!(wait_until(Duration::from_secs(3), || fx
        .paths
        .bin_dir
        .join("responses/link.start_blocked")
        .is_file()));
    let before_release = link_spawns(&fx).len();
    fs::write(fx.paths.bin_dir.join("responses/link.release_start"), "go").unwrap();
    let recorded = wait_until(Duration::from_secs(3), || {
        let calls = link_spawns(&fx);
        calls.len() == 1 && calls[0].len() == 3
    });
    sup.stop();
    assert_eq!(
        before_release, 0,
        "ready socket is independent of the held child"
    );
    assert!(
        recorded,
        "the owned child records its actual start after release"
    );
}
