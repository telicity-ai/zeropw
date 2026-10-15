//! `ServeSupervisor` with the fake serve (prints its URL, then idles) and an in-test loopback
//! `/healthz` responder: start, pid file, attach from a second supervisor, SIGTERM stop,
//! SIGKILL escalation, start failures.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use common::{Fixture, free_port, health_server, wait_until};
use nix::sys::signal::kill;
use nix::unistd::Pid;
use zeropw_desktop_core::serve::{ServeConfig, ServeStatus, ServeSupervisor};

fn supervisor(fx: &Fixture, grace: Duration) -> ServeSupervisor {
    ServeSupervisor::new(&fx.paths).with_timeouts(Duration::from_secs(10), grace)
}

fn gone(pid: u32) -> bool {
    // Signalable means alive or an unreaped zombie of this test process; ps tells them apart.
    if kill(Pid::from_raw(pid as i32), None).is_err() {
        return true;
    }
    let out = std::process::Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    let stat = String::from_utf8_lossy(&out.stdout);
    stat.trim().is_empty() || stat.trim_start().starts_with('Z')
}

#[test]
fn start_records_a_private_pid_file_and_a_second_supervisor_attaches() {
    let fx = Fixture::new();
    let port = health_server();
    let first = supervisor(&fx, Duration::from_secs(3));
    let config = ServeConfig {
        port,
        team_listen: Some("192.168.1.20:47390".into()),
    };
    let status = first.start(&config).unwrap();
    assert!(status.running);
    let url = format!("http://127.0.0.1:{port}");
    assert_eq!(status.url.as_deref(), Some(url.as_str()));
    assert_eq!(status.team_listen.as_deref(), Some("192.168.1.20:47390"));
    let pid = status.pid.unwrap();

    let serve = fx.last("serve");
    assert_eq!(
        serve.args(),
        [
            "serve",
            &format!("--listen=127.0.0.1:{port}"),
            "--team-listen=192.168.1.20:47390",
            "--quiet"
        ]
    );
    assert_eq!(serve.argv[0], fx.state_dir_arg());
    assert!(!serve.argv.contains(&"--input-envelope".to_owned()));
    assert_eq!(serve.env_var("PATH"), Some("/usr/bin:/bin"));

    let pid_file = fx.paths.serve_pid_file();
    let record: serde_json::Value = serde_json::from_slice(&fs::read(&pid_file).unwrap()).unwrap();
    assert_eq!(record["pid"], pid);
    assert_eq!(record["url"], url);
    assert!(record["started_at"].as_u64().unwrap() > 0);
    for file in [&pid_file, &fx.paths.serve_log_file()] {
        assert_eq!(
            fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // Starting again is a no-op.
    assert_eq!(first.start(&config).unwrap().pid, Some(pid));
    assert_eq!(fx.count("serve"), 1);

    // A new app run adopts the running sidecar instead of starting another one.
    let second = supervisor(&fx, Duration::from_secs(3));
    let attached = second.attach();
    assert!(attached.running);
    assert_eq!(attached.pid, Some(pid));
    assert_eq!(second.start(&config).unwrap().pid, Some(pid));
    assert_eq!(fx.count("serve"), 1);

    // Stopping from the second supervisor terminates it with SIGTERM.
    let started = Instant::now();
    assert_eq!(second.stop(), ServeStatus::stopped());
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert!(wait_until(Duration::from_secs(3), || gone(pid)));
    assert!(!pid_file.exists());
    assert!(!first.status().running);
    assert_eq!(first.stop(), ServeStatus::stopped());
}

#[test]
fn stop_escalates_to_sigkill_after_the_grace_period() {
    let fx = Fixture::new();
    fx.serve_ignores_sigterm();
    let port = health_server();
    let sup = supervisor(&fx, Duration::from_secs(1));
    let pid = sup
        .start(&ServeConfig {
            port,
            team_listen: None,
        })
        .unwrap()
        .pid
        .unwrap();
    let started = Instant::now();
    sup.stop();
    let took = started.elapsed();
    assert!(
        took >= Duration::from_secs(1),
        "SIGKILL came before the grace period: {took:?}"
    );
    assert!(took < Duration::from_secs(5), "{took:?}");
    assert!(wait_until(Duration::from_secs(3), || gone(pid)));
    assert!(!sup.status().running);
}

#[test]
fn a_serve_that_exits_reports_the_cli_error_from_its_log() {
    let fx = Fixture::new();
    fx.respond_error(
        "serve",
        "{\"detail\":\"/x/state\",\"error\":\"StateError\",\"reason\":\"state_missing\"}\n",
        1,
    );
    let sup = supervisor(&fx, Duration::from_secs(1));
    let e = sup
        .start(&ServeConfig {
            port: free_port(),
            team_listen: None,
        })
        .unwrap_err();
    assert_eq!(
        (e.error.as_str(), e.reason.as_str()),
        ("StateError", "state_missing")
    );
    assert!(!sup.status().running);
    assert!(!fx.paths.serve_pid_file().exists());
}

#[test]
fn a_serve_that_never_gets_healthy_times_out_and_is_stopped() {
    let fx = Fixture::new();
    let sup = ServeSupervisor::new(&fx.paths)
        .with_timeouts(Duration::from_secs(2), Duration::from_secs(1));
    let started = Instant::now();
    let e = sup
        .start(&ServeConfig {
            port: free_port(),
            team_listen: None,
        })
        .unwrap_err();
    assert_eq!(e.reason, "serve_start_timeout");
    assert!(started.elapsed() < Duration::from_secs(8));
    assert!(!sup.status().running);
    assert!(!fx.paths.serve_pid_file().exists());
}

/// Quitting the app while serve is still starting must not wait out the start budget.
#[test]
fn a_stop_during_a_start_cancels_it_promptly() {
    let fx = Fixture::new();
    // Prints its URL but never answers /healthz, so the start would wait the full 30 s.
    let sup = std::sync::Arc::new(
        ServeSupervisor::new(&fx.paths)
            .with_timeouts(Duration::from_secs(30), Duration::from_secs(2)),
    );
    let starter = sup.clone();
    let port = free_port();
    let start = std::thread::spawn(move || {
        starter.start(&ServeConfig {
            port,
            team_listen: None,
        })
    });
    assert!(wait_until(Duration::from_secs(5), || fx.count("serve") == 1));
    std::thread::sleep(Duration::from_millis(300));
    let stopping = Instant::now();
    assert_eq!(sup.stop(), ServeStatus::stopped());
    assert!(
        stopping.elapsed() < Duration::from_secs(5),
        "{:?}",
        stopping.elapsed()
    );
    let e = start.join().unwrap().unwrap_err();
    assert_eq!(e.reason, "serve_start_cancelled");
    assert!(!sup.status().running);
    assert!(!fx.paths.serve_pid_file().exists());
    // A later start is not affected by the earlier cancellation.
    let healthy = health_server();
    let status = sup
        .start(&ServeConfig {
            port: healthy,
            team_listen: None,
        })
        .unwrap();
    assert!(status.running);
    let pid = status.pid.unwrap();
    sup.stop();
    assert!(wait_until(Duration::from_secs(3), || gone(pid)));
}

#[test]
fn a_serve_printing_a_non_loopback_url_is_refused() {
    let fx = Fixture::new();
    fx.respond("serve", "{\"url\":\"http://10.0.0.1:47380\"}\n");
    let sup = supervisor(&fx, Duration::from_secs(1));
    let e = sup
        .start(&ServeConfig {
            port: free_port(),
            team_listen: None,
        })
        .unwrap_err();
    assert_eq!(e.reason, "serve_output_invalid");
}
