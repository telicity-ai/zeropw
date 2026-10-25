//! The desktop shell's additions to the core, against the fake zeropw-admin:
//! - `--require-admin` goes with exactly the commands the app re-authenticates but the CLI
//!   alone would not (docs/desktop-app.md §5), right after `--input-envelope`, and the fake
//!   CLI refuses such a call without an admin passphrase in the envelope;
//! - terminals outlive their first view: `terminal_list` names them, `terminal_attach` replays
//!   the bounded output ring into a new sink and keeps streaming to it;
//! - `secure_view` reaches the window hook.

mod common;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{FakeScreen, Fixture, err, health_server, wait_until};
use zeropw_desktop_core::commands::*;
use zeropw_desktop_core::terminal::{TerminalManager, TerminalRequest};
use zeropw_desktop_core::{
    Core, CoreConfig, NoEvents, SecretString, Settings, TerminalProgram, TerminalSink,
};

const ADMIN_PASS: &str = "velvet-ocean-27-quartz-lantern";

fn pass() -> SecretString {
    SecretString::from(ADMIN_PASS)
}

/// The fake CLI's keys for the commands that must carry `--require-admin`.
const REQUIRE_ADMIN_KEYS: [&str; 9] = [
    "resume",
    "connection_create-http",
    "connection_create-ssh",
    "connection_update",
    "grant_create",
    "approvals_approve",
    "team_invite",
    "team_remove",
    "restore",
];

#[test]
fn the_core_list_matches_the_documented_reauth_commands() {
    let keys: BTreeSet<String> = REQUIRE_ADMIN_COMMANDS
        .iter()
        .map(|words| words.join("_"))
        .collect();
    let expected: BTreeSet<String> = REQUIRE_ADMIN_KEYS.iter().map(|k| k.to_string()).collect();
    assert_eq!(keys, expected);
}

/// Every command the core runs, once; then each recorded call carries `--require-admin`
/// exactly when its command is in the re-auth list.
#[test]
fn require_admin_goes_with_exactly_the_reauth_commands() {
    let fx = Fixture::new();
    let mut config = CoreConfig::new(fx.paths.clone());
    config.serve_stop_grace = Duration::from_secs(3);
    config.serve_start_timeout = Duration::from_secs(10);
    let core = Core::new(config, Arc::new(NoEvents));
    core.settings_set(Settings {
        gateway_port: health_server(),
        team_listen: None,
    })
    .unwrap();

    let code = core.recovery_generate().unwrap();
    core.vault_init(VaultInitIn {
        admin_passphrase: pass(),
        recovery: RecoveryInput::Ref(code.reference),
    })
    .unwrap();
    core.control_get().unwrap();
    core.stop_all().unwrap();
    core.resume(PassphraseIn {
        admin_passphrase: pass(),
    })
    .unwrap();
    core.project_list().unwrap();
    core.project_create(ProjectCreateIn {
        name: "demo".into(),
        environments: vec!["dev".into()],
    })
    .unwrap();
    core.secret_list(SecretListIn::default()).unwrap();
    core.secret_versions(IdIn { id: "api".into() }).unwrap();
    core.secret_put(SecretPutIn {
        id: "api".into(),
        kind: SecretKind::ApiKey,
        project: "demo".into(),
        environment: "dev".into(),
        source: SecretSource::Typed("sk-synthetic-0123".into()),
    })
    .unwrap();
    core.secret_reveal(SecretRevealIn {
        id: "api".into(),
        version: None,
        admin_passphrase: pass(),
    })
    .unwrap();
    for action in [Core::secret_retire, Core::secret_revoke] {
        action(
            &core,
            SecretVersionIn {
                id: "api".into(),
                version: "1".into(),
            },
        )
        .unwrap();
    }
    core.connection_list().unwrap();
    core.connection_create_http(HttpConnectionIn {
        id: "gh".into(),
        project: "demo".into(),
        environment: "dev".into(),
        service: "github".into(),
        secret_id: "api".into(),
        target: "https://api.github.com".into(),
        auth: HttpAuth::Bearer,
        header_name: None,
        value_prefix: None,
        basic_username: None,
        methods: vec![],
        confirm_methods: vec![],
        path_prefixes: vec![],
        allow_private_network: false,
        cli_program: None,
        ca_file_token: None,
        description: None,
        admin_passphrase: pass(),
    })
    .unwrap();
    core.connection_create_ssh(SshConnectionIn {
        id: "prod".into(),
        project: "demo".into(),
        environment: "dev".into(),
        service: "ssh".into(),
        secret_id: "deploy".into(),
        host: "10.0.0.5".into(),
        port: 22,
        username: "deploy".into(),
        host_keys: vec!["ssh-ed25519 AAAAsynthetic".into()],
        cli_program: "/usr/bin/ssh".into(),
        description: None,
        admin_passphrase: pass(),
    })
    .unwrap();
    core.connection_set_cli_program(CliProgramIn {
        id: "prod".into(),
        cli_program: "/usr/bin/ssh".into(),
        admin_passphrase: pass(),
    })
    .unwrap();
    core.connection_disable(IdIn { id: "gh".into() }).unwrap();
    core.principal_list().unwrap();
    core.principal_create(PrincipalCreateIn {
        id: "agent-1".into(),
        runtime: "default".into(),
    })
    .unwrap();
    core.principal_disable(IdIn {
        id: "agent-1".into(),
    })
    .unwrap();
    core.grant_list(GrantListIn::default()).unwrap();
    core.grant_create(GrantCreateIn {
        principal: "agent-1".into(),
        connection: "gh".into(),
        ttl: "30m".into(),
        max_uses: None,
        admin_passphrase: pass(),
    })
    .unwrap();
    core.grant_revoke(IdIn { id: "g1".into() }).unwrap();
    core.audit_tail(LimitIn { limit: 10 }).unwrap();
    core.alerts(LimitIn { limit: 10 }).unwrap();
    core.approvals_list().unwrap();
    core.approvals_approve(ApproveIn {
        digest: "sha256-synthetic".into(),
        admin_passphrase: pass(),
    })
    .unwrap();
    core.incident_list().unwrap();
    core.incident_show(IdIn { id: "i1".into() }).unwrap();
    core.incident_declare(IncidentDeclareIn {
        scope: IncidentScope::All,
        principal: None,
        runtime: None,
        reason: None,
        admin_passphrase: Some(pass()),
    })
    .unwrap();
    core.incident_close(IncidentCloseIn {
        id: "i1".into(),
        admin_passphrase: pass(),
    })
    .unwrap();
    core.backup_create(Path::new("/tmp/zeropw-synthetic.zpw"))
        .unwrap();
    core.backup_restore(
        Path::new("/tmp/zeropw-synthetic.zpw"),
        PassphraseIn {
            admin_passphrase: pass(),
        },
    )
    .unwrap();
    core.restore_ack(PassphraseIn {
        admin_passphrase: pass(),
    })
    .unwrap();
    core.recover(RecoverIn {
        recovery_passphrase: "abcd efgh ijkl mnop qrst uvw2".into(),
    })
    .unwrap();
    core.team_init().unwrap();
    core.team_share(TeamShareIn {
        project: "demo".into(),
        environment: "dev".into(),
        name: None,
        admin_passphrase: pass(),
    })
    .unwrap();
    core.team_members(EnvIn {
        env: "demo/dev".into(),
    })
    .unwrap();
    core.team_remove(TeamRemoveIn {
        env: "demo/dev".into(),
        device: "ABCDEFGHIJKLMNOPQRSTUVWXYZ".into(),
        admin_passphrase: pass(),
    })
    .unwrap();
    core.team_invite_create(TeamInviteCreateIn {
        env: "demo/dev".into(),
        role: TeamRole::User,
        name: "bob".into(),
        address: "192.168.1.20:47390".into(),
        admin_passphrase: pass(),
    })
    .unwrap();
    core.team_invites(EnvIn {
        env: "demo/dev".into(),
    })
    .unwrap();
    core.team_revoke_invite(TeamRevokeInviteIn {
        env: "demo/dev".into(),
        invite_id: "aa".into(),
    })
    .unwrap();
    let preview = core
        .team_invite_preview(TeamInvitePreviewIn {
            text: "zeropw://join#SYNTHETICINVITE".into(),
        })
        .unwrap();
    core.team_join(TeamJoinIn {
        reference: preview.reference,
        project: None,
        environment: None,
    })
    .unwrap();
    core.serve_stop();

    let mut seen = BTreeSet::new();
    for call in fx.calls() {
        seen.insert(call.key.clone());
        if call.key == "serve" {
            assert!(!call.argv.iter().any(|a| a == "--require-admin"));
            continue;
        }
        assert_eq!(
            call.requires_admin(),
            REQUIRE_ADMIN_KEYS.contains(&call.key.as_str()),
            "{}: {:?}",
            call.key,
            call.argv
        );
        if call.requires_admin() {
            assert_eq!(call.stdin_json()["admin_passphrase"], ADMIN_PASS);
        }
    }
    for key in REQUIRE_ADMIN_KEYS {
        assert!(seen.contains(key), "{key} was not exercised");
    }
    // Every documented command family was exercised, not only the re-auth ones.
    for key in [
        "init",
        "status",
        "stop-all",
        "secret_reveal",
        "restore-ack",
        "incident_close",
        "incident_declare",
        "team_share",
        "team_join",
        "team_invite-info",
        "recover",
        "backup",
    ] {
        assert!(seen.contains(key), "{key} was not exercised");
    }
}

#[test]
fn reauth_commands_still_refuse_an_empty_passphrase_before_running() {
    let fx = Fixture::new();
    let core = Core::new(CoreConfig::new(fx.paths.clone()), Arc::new(NoEvents));
    let empty = || SecretString::from("");
    let reasons = [
        err(core.resume(PassphraseIn {
            admin_passphrase: empty(),
        })),
        err(core.grant_create(GrantCreateIn {
            principal: "a".into(),
            connection: "c".into(),
            ttl: "1h".into(),
            max_uses: None,
            admin_passphrase: empty(),
        })),
        err(core.approvals_approve(ApproveIn {
            digest: "d".into(),
            admin_passphrase: empty(),
        })),
        err(core.team_remove(TeamRemoveIn {
            env: "demo/dev".into(),
            device: "X".into(),
            admin_passphrase: empty(),
        })),
        err(core.backup_restore(
            Path::new("/tmp/x.zpw"),
            PassphraseIn {
                admin_passphrase: empty(),
            },
        )),
    ];
    for e in reasons {
        assert_eq!(e.reason, "passphrase_missing");
    }
    assert!(fx.calls().is_empty());
}

#[derive(Clone, Default)]
struct Captured {
    out: Arc<Mutex<String>>,
    exit: Arc<Mutex<Option<Option<u32>>>>,
}

impl Captured {
    fn text(&self) -> String {
        self.out.lock().unwrap().clone()
    }
    fn exited(&self) -> Option<Option<u32>> {
        *self.exit.lock().unwrap()
    }
    fn sink(&self) -> Box<dyn TerminalSink> {
        Box::new(self.clone())
    }
}

impl TerminalSink for Captured {
    fn data(&mut self, chunk: &str) {
        self.out.lock().unwrap().push_str(chunk);
    }
    fn exit(&mut self, code: Option<u32>) {
        *self.exit.lock().unwrap() = Some(code);
    }
}

fn core_with_shell(fx: &Fixture, script: &str, ring_bytes: usize) -> Core {
    let mut config = CoreConfig::new(fx.paths.clone());
    config.serve_stop_grace = Duration::from_secs(3);
    config.terminal_ring_bytes = ring_bytes;
    config.terminal_program = TerminalProgram::Program {
        path: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
    };
    let core = Core::new(config, Arc::new(NoEvents));
    core.settings_set(Settings {
        gateway_port: health_server(),
        team_listen: None,
    })
    .unwrap();
    core.serve_start().unwrap();
    core
}

#[test]
fn terminals_are_listed_and_reattached_with_their_buffered_output() {
    let fx = Fixture::new();
    let core = core_with_shell(
        &fx,
        r#"echo "first view"; read line; echo "after:$line"; read again; exit 7"#,
        64 * 1024,
    );
    let principal = core
        .principal_create(PrincipalCreateIn {
            id: "agent-1".into(),
            runtime: "default".into(),
        })
        .unwrap();
    let first = Captured::default();
    let opened = core
        .terminal_open(
            TerminalOpenIn {
                token_ref: principal.token_ref.clone(),
                as_user: Some("agent".into()),
            },
            first.sink(),
        )
        .unwrap();
    assert!(wait_until(Duration::from_secs(5), || first
        .text()
        .contains("first view")));

    let list = core.terminal_list();
    assert_eq!(list.terminals.len(), 1);
    let row = &list.terminals[0];
    assert_eq!(row.terminal_id, opened.terminal_id);
    assert_eq!(row.principal, "agent-1");
    assert_eq!(row.as_user.as_deref(), Some("agent"));
    assert!(row.alive);
    let listed = serde_json::to_value(&list).unwrap();
    assert_eq!(
        listed,
        serde_json::json!({"terminals": [{
            "terminal_id": opened.terminal_id, "principal": "agent-1", "as_user": "agent", "alive": true
        }]})
    );
    assert!(!listed.to_string().contains("zpw_synthetic_caller_token"));

    // A second view takes over: it first gets everything so far, then the live output.
    let second = Captured::default();
    let attached = core
        .terminal_attach(
            TerminalIdIn {
                terminal_id: opened.terminal_id.clone(),
            },
            second.sink(),
        )
        .unwrap();
    assert_eq!(attached.terminal_id, opened.terminal_id);
    assert_eq!(attached.suggestions, opened.suggestions);
    assert!(second.text().contains("first view"));
    let before = first.text();
    core.terminal_write(&opened.terminal_id, "hello\n").unwrap();
    assert!(wait_until(Duration::from_secs(5), || second
        .text()
        .contains("after:hello")));
    assert_eq!(first.text(), before, "the replaced view got live output");

    core.terminal_write(&opened.terminal_id, "\n").unwrap();
    assert!(wait_until(Duration::from_secs(10), || second
        .exited()
        .is_some()));
    assert_eq!(second.exited(), Some(Some(7)));
    assert_eq!(first.exited(), None);
    // The exited shell stays listed until closed, and still replays.
    assert!(wait_until(Duration::from_secs(2), || !core
        .terminal_list()
        .terminals[0]
        .alive));
    let third = Captured::default();
    core.terminal_attach(
        TerminalIdIn {
            terminal_id: opened.terminal_id.clone(),
        },
        third.sink(),
    )
    .unwrap();
    assert!(third.text().contains("first view") && third.text().contains("after:hello"));
    assert_eq!(third.exited(), Some(Some(7)));

    core.terminal_close(&opened.terminal_id);
    assert!(core.terminal_list().terminals.is_empty());
    assert_eq!(
        err(core.terminal_attach(
            TerminalIdIn {
                terminal_id: opened.terminal_id
            },
            Captured::default().sink()
        ))
        .reason,
        "terminal_not_found"
    );
    core.shutdown();
}

#[test]
fn the_replay_is_bounded_to_the_newest_output() {
    let fx = Fixture::new();
    let core = core_with_shell(
        &fx,
        r#"i=0; while [ $i -lt 400 ]; do echo "line-$i"; i=$((i+1)); done; echo done-marker; read x"#,
        1024,
    );
    let principal = core
        .principal_create(PrincipalCreateIn {
            id: "agent-1".into(),
            runtime: "default".into(),
        })
        .unwrap();
    let first = Captured::default();
    let opened = core
        .terminal_open(
            TerminalOpenIn {
                token_ref: principal.token_ref,
                as_user: None,
            },
            first.sink(),
        )
        .unwrap();
    assert!(wait_until(Duration::from_secs(10), || first
        .text()
        .contains("done-marker")));
    let second = Captured::default();
    core.terminal_attach(
        TerminalIdIn {
            terminal_id: opened.terminal_id.clone(),
        },
        second.sink(),
    )
    .unwrap();
    let replay = second.text();
    assert!(replay.len() <= 1024, "{}", replay.len());
    assert!(replay.ends_with("done-marker\r\n"), "{replay:?}");
    assert!(!replay.contains("line-0\r\n"));
    // The replay starts on a line boundary, not in the middle of a cut line.
    assert!(replay.starts_with("line-"), "{replay:?}");
    assert!(first.text().contains("line-0\r\n"));
    core.terminal_close(&opened.terminal_id);
    core.shutdown();
}

/// Attaching while the shell is printing loses and repeats nothing: replay plus live output
/// is exactly the shell's output.
#[test]
fn attach_during_output_has_no_gap_and_no_repeat() {
    const LINES: usize = 3000;
    let manager = TerminalManager::new(TerminalProgram::Program {
        path: "/bin/sh".into(),
        args: vec![
            "-c".into(),
            // `stty -onlcr`: no CR insertion by the tty, so the bytes compared are exactly what
            // the program wrote (a BSD tty can emit "\r\r\n" when its output queue fills).
            format!(
                r#"stty -onlcr; i=0; while [ $i -lt {LINES} ]; do echo "n$i"; i=$((i+1)); done"#
            ),
        ],
    });
    let token = SecretString::from("zpw_synthetic_terminal_token");
    let (tx, rx) = mpsc::channel::<()>();
    struct Signal(Captured, mpsc::Sender<()>);
    impl TerminalSink for Signal {
        fn data(&mut self, chunk: &str) {
            self.0.data(chunk);
            let _ = self.1.send(());
        }
        fn exit(&mut self, code: Option<u32>) {
            self.0.exit(code);
        }
    }
    let first = Captured::default();
    let id = manager
        .open(
            &TerminalRequest {
                gateway_url: "http://127.0.0.1:47380",
                token: &token,
                bin_dir: Path::new("/opt/zeropw-bundle"),
                cols: 80,
                rows: 24,
                principal: "agent-1",
                as_user: None,
            },
            Box::new(Signal(first.clone(), tx)),
        )
        .unwrap();
    // Attach as soon as some output has arrived (usually mid-stream).
    rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let second = Captured::default();
    let attached = manager.attach(&id, second.sink()).unwrap();
    assert_eq!(attached.principal, "agent-1");
    assert!(wait_until(Duration::from_secs(20), || second
        .exited()
        .is_some()));
    let lines: Vec<String> = second
        .text()
        .split('\n')
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    let expected: Vec<String> = (0..LINES).map(|i| format!("n{i}")).collect();
    assert_eq!(lines, expected);
    // What the first view got is a prefix of the same stream.
    assert!(second.text().starts_with(&first.text()));
    manager.close(&id);
}

#[test]
fn secure_view_toggles_the_window_hook_and_reports_what_it_got() {
    let fx = Fixture::new();
    let core = Core::new(CoreConfig::new(fx.paths.clone()), Arc::new(NoEvents));
    let screen = FakeScreen::default();
    let on = core
        .secure_view(SecureViewIn { on: true }, &screen)
        .unwrap();
    assert_eq!(on, SecureViewOut { protected: true });
    let off = core
        .secure_view(SecureViewIn { on: false }, &screen)
        .unwrap();
    assert_eq!(off, SecureViewOut { protected: false });
    assert_eq!(*screen.0.lock().unwrap(), [true, false]);
    assert_eq!(
        serde_json::to_value(on).unwrap(),
        serde_json::json!({"protected": true})
    );
    // A platform without capture protection (Linux) says so instead of claiming it.
    let linux = FakeScreen::unsupported();
    assert_eq!(
        core.secure_view(SecureViewIn { on: true }, &linux).unwrap(),
        SecureViewOut { protected: false }
    );
    assert!(fx.calls().is_empty());
    let parsed: SecureViewIn = serde_json::from_value(serde_json::json!({"on": true})).unwrap();
    assert!(parsed.on);
    assert!(serde_json::from_value::<SecureViewIn>(serde_json::json!({"on": 1})).is_err());
}

#[test]
fn invite_previews_stay_pending_until_joined() {
    let fx = Fixture::new();
    let core = Core::new(CoreConfig::new(fx.paths.clone()), Arc::new(NoEvents));
    let preview = core
        .open_deep_link("zeropw://join#SYNTHETICINVITE")
        .unwrap();
    assert!(core.invite_pending(&preview.reference));
    assert!(!core.invite_pending("00000000000000000000000000000000"));
    assert!(!core.invite_pending("not a ref"));
    core.team_join(TeamJoinIn {
        reference: preview.reference.clone(),
        project: None,
        environment: None,
    })
    .unwrap();
    assert!(!core.invite_pending(&preview.reference));
}
