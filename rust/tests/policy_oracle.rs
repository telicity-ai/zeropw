//! Policy boundary tests that used to run the Python prototype live.
//!
//! Persisted state and digests are compared with golden fixtures generated
//! once from the prototype (`tests/fixtures/python/policy/GENERATE.md`);
//! everything else asserts Rust's own explicit expected outcome.
//!
//! Covers:
//! - `hash_token` / `approval_digest` byte-identical with the prototype
//!   (both are persisted).
//! - `address_block_reason` over an explicit address table (private/
//!   loopback/link-local/multicast/reserved/unspecified/IPv4-mapped IPv6/
//!   NAT64/6to4/Teredo/metadata edge cases).
//! - A policy state directory written by the prototype loads and authorizes
//!   in Rust; one written by Rust has the same files and bytes up to the
//!   random grant id and token hash.
//! - Authorization scenarios (revoked, expired, exhausted, stopped,
//!   restore-pending, stale, disabled principal, disabled connection, wrong
//!   scope) with their explicit `(allowed, reason)`.
//! - Malformed stored documents fail closed.

mod python_fixtures;

use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use tempfile::TempDir;
use zeropw::clock;
use zeropw::policy::{
    self, Action, CliProfile, Connection, ConnectionChanges, HttpAuth, HttpScope, HttpTarget,
    Policy, SshTarget,
};
use zeropw::store::StateDir;

// ---------------------------------------------------------------- digests
#[test]
fn hash_token_and_approval_digest_are_byte_identical_with_python() {
    let fixture = python_fixtures::json("policy/digests.json");
    let cases = fixture["approval_digest"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        let field = |i: usize| case[i].as_str().unwrap();
        let body = hex::decode(field(4)).unwrap();
        assert_eq!(
            policy::approval_digest(field(0), field(1), field(2), field(3), &body),
            field(5),
            "approval_digest{case}"
        );
    }
    let tokens = fixture["hash_token"].as_array().unwrap();
    assert_eq!(tokens.len(), 3);
    for case in tokens {
        let token = case[0].as_str().unwrap();
        assert_eq!(
            policy::hash_token(token),
            case[1].as_str().unwrap(),
            "hash_token({token:?})"
        );
    }
}

// ------------------------------------------------------- address classification
/// `(address, reason without allow_private_network, reason with it)`.
#[test]
fn address_block_reason_over_an_address_table() {
    let addresses: &[(&str, Option<&str>, Option<&str>)] = &[
        // public
        ("8.8.8.8", None, None),
        ("1.1.1.1", None, None),
        ("2001:4860:4860::8888", None, None),
        // private / RFC 1918 and friends
        ("10.0.0.1", Some("target_address_not_allowed"), None),
        ("172.16.0.5", Some("target_address_not_allowed"), None),
        ("192.168.1.1", Some("target_address_not_allowed"), None),
        ("127.0.0.1", Some("target_address_not_allowed"), None),
        (
            "0.0.0.0",
            Some("target_address_not_allowed"),
            Some("target_address_not_allowed"),
        ),
        ("255.255.255.255", Some("target_address_not_allowed"), None),
        (
            "224.0.0.1",
            Some("target_address_not_allowed"),
            Some("target_address_not_allowed"),
        ),
        ("100.64.0.1", Some("target_address_not_allowed"), None),
        ("192.0.2.1", Some("target_address_not_allowed"), None),
        ("198.51.100.1", Some("target_address_not_allowed"), None),
        ("203.0.113.1", Some("target_address_not_allowed"), None),
        ("198.18.0.1", Some("target_address_not_allowed"), None),
        ("240.0.0.1", Some("target_address_not_allowed"), None),
        // exceptions to the private list (still global)
        ("192.0.0.9", None, None),
        ("192.0.0.10", None, None),
        // metadata / link-local -- always blocked
        (
            "169.254.169.254",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ),
        (
            "169.254.1.1",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ),
        (
            "100.100.100.200",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ),
        (
            "168.63.129.16",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ),
        // IPv6
        ("::1", Some("target_address_not_allowed"), None),
        (
            "::",
            Some("target_address_not_allowed"),
            Some("target_address_not_allowed"),
        ),
        (
            "fe80::1",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ),
        ("fec0::1", Some("target_address_not_allowed"), None),
        ("2001:db8::1", Some("target_address_not_allowed"), None),
        (
            "2001::1",
            Some("target_address_not_allowed"),
            Some("target_address_not_allowed"),
        ),
        (
            "ff02::1",
            Some("target_address_not_allowed"),
            Some("target_address_not_allowed"),
        ),
        ("fc00::1", Some("target_address_not_allowed"), None),
        ("3fff::1", Some("target_address_not_allowed"), None),
        ("2001:1::1", None, None),
        ("2001:3::1", None, None),
        // IPv6 carrying an embedded IPv4
        ("64:ff9b::8.8.8.8", None, None),
        (
            "64:ff9b::169.254.169.254",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ),
        (
            "64:ff9b:1::8.8.8.8",
            Some("target_address_not_allowed"),
            None,
        ),
        (
            "64:ff9b:1::169.254.169.254",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ),
        ("::ffff:8.8.8.8", None, None),
        (
            "::ffff:169.254.169.254",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ),
        ("::ffff:0:8.8.8.8", Some("target_address_not_allowed"), None),
        (
            "::ffff:0:169.254.169.254",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ),
        ("2002:0808:0808::", Some("target_address_not_allowed"), None),
        (
            "2002:a9fe:a9fe::",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ), // 6to4 embedding 169.254.169.254
        (
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            Some("target_address_not_allowed"),
            None,
        ), // teredo, embeds a client IP
        // provider metadata over IPv6
        (
            "fd00:ec2::254",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ),
        (
            "fd00:ec2::23",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ),
        (
            "fd20:ce::254",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ),
        (
            "fd00:c1::a9fe:a9fe",
            Some("metadata_address_not_allowed"),
            Some("metadata_address_not_allowed"),
        ),
    ];

    for (addr_str, want_private, want_public) in addresses {
        let addr: IpAddr = addr_str
            .parse()
            .expect("std parses every address in this table");
        assert_eq!(
            policy::address_block_reason(addr, false),
            *want_private,
            "address_block_reason({addr_str}, false)"
        );
        assert_eq!(
            policy::address_block_reason(addr, true),
            *want_public,
            "address_block_reason({addr_str}, true)"
        );
    }
}

// ----------------------------------------------------- state directory round trip
#[test]
fn state_written_by_python_authorizes_identically_in_rust() {
    let tmp = TempDir::new().unwrap();
    let state_path = tmp.path().join("state");
    python_fixtures::copy_state("policy/state", &state_path);
    let meta = python_fixtures::json("policy/state-meta.json");
    let grant_id = meta["grant_id"].as_str().unwrap().to_string();

    let state = StateDir::new(&state_path);
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));

    let principal = policy
        .authenticate(meta["principal_token"].as_str().unwrap())
        .expect("the caller token the prototype issued authenticates");
    assert_eq!(principal.id, "agent-1");

    let allowed = policy
        .evaluate(
            "agent-1",
            "gh",
            &Action::http("GET", "/repos"),
            Some(&grant_id),
        )
        .unwrap();
    assert!(allowed.allowed);
    assert_eq!(allowed.reason, "allowed");

    let denied = policy
        .evaluate(
            "agent-1",
            "gh",
            &Action::http("PUT", "/repos"),
            Some(&grant_id),
        )
        .unwrap();
    assert!(!denied.allowed);
    assert_eq!(denied.reason, "method_not_allowed");

    let grant = policy
        .consume(
            &grant_id,
            None,
            None,
            Some(Action::http("GET", "/repos")),
            None,
        )
        .expect("the grant Python wrote is usable from Rust");
    assert_eq!(grant.uses, 1);

    // The recorded use is persisted in the prototype's own document layout.
    let reread = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert_eq!(reread.get_grant(&grant_id).unwrap().uses, 1);
    let grants = state
        .read_json(policy::GRANTS, serde_json::json!({}))
        .unwrap();
    assert_eq!(grants[grant_id.as_str()]["uses"], serde_json::json!(1));
}

/// Replaces the random parts (grant ids, sha256 token hashes) of a policy
/// document so a Rust-written and a Python-written file compare byte for
/// byte.
fn normalize_ids(text: &str) -> String {
    let grant = regex::Regex::new(r"g-[0-9a-f]{16}").unwrap();
    let hash = regex::Regex::new(r"[0-9a-f]{64}").unwrap();
    hash.replace_all(&grant.replace_all(text, "g-<id>"), "<sha256>")
        .into_owned()
}

#[test]
fn state_written_by_rust_matches_the_python_layout_and_authorizes() {
    let tmp = TempDir::new().unwrap();
    let state_path = tmp.path().join("state");
    let state = StateDir::new(&state_path);
    state.create().unwrap();
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
    let token = policy.create_principal("agent-1", "default").unwrap();
    let conn = policy::Connection::new(
        "gh",
        "demo",
        "dev",
        "fake-github",
        "http",
        "gh-token",
        None,
        "demo",
        Some(policy::HttpTarget::new("http", "127.0.0.1", 8080, None, false).unwrap()),
        Some(policy::HttpAuth::bearer()),
        Some(
            policy::HttpScope::new(
                Some(vec!["GET".into(), "POST".into()]),
                Some(vec!["/repos".into(), "/me".into()]),
                vec!["DELETE".into()],
            )
            .unwrap(),
        ),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap();
    policy.create_connection(conn).unwrap();
    let grant = policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap();

    // Same files, and each document byte-identical to what the prototype
    // wrote for the same operations, up to the random ids.
    let fixture_root = python_fixtures::path("policy/state");
    assert_eq!(
        python_fixtures::relative_files(&state_path),
        python_fixtures::relative_files(&fixture_root)
    );
    for name in [policy::PRINCIPALS, policy::CONNECTIONS, policy::GRANTS] {
        let ours = std::fs::read_to_string(state_path.join(name)).unwrap();
        let theirs = std::fs::read_to_string(fixture_root.join(name)).unwrap();
        assert_eq!(normalize_ids(&ours), normalize_ids(&theirs), "{name}");
    }

    assert_eq!(policy.authenticate(&token).unwrap().id, "agent-1");
    let d1 = policy
        .evaluate(
            "agent-1",
            "gh",
            &Action::http("GET", "/repos"),
            Some(&grant.id),
        )
        .unwrap();
    assert_eq!((d1.allowed, d1.reason), (true, "allowed"));
    let d2 = policy
        .evaluate(
            "agent-1",
            "gh",
            &Action::http("PUT", "/repos"),
            Some(&grant.id),
        )
        .unwrap();
    assert_eq!((d2.allowed, d2.reason), (false, "method_not_allowed"));
    let used = policy
        .consume(
            &grant.id,
            None,
            None,
            Some(Action::http("GET", "/repos")),
            None,
        )
        .unwrap();
    assert_eq!(used.uses, 1);
    assert_eq!(policy.get_grant(&grant.id).unwrap().uses, 1);
}

// --------------------------------------------------- authorization scenarios
fn rust_connection() -> policy::Connection {
    policy::Connection::new(
        "gh",
        "demo",
        "dev",
        "fake-github",
        "http",
        "gh-token",
        None,
        "demo",
        Some(policy::HttpTarget::new("http", "127.0.0.1", 8080, None, false).unwrap()),
        Some(policy::HttpAuth::bearer()),
        Some(
            policy::HttpScope::new(
                Some(vec!["GET".into(), "POST".into()]),
                Some(vec!["/repos".into(), "/me".into()]),
                vec![],
            )
            .unwrap(),
        ),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap()
}

fn rust_scenario(name: &str) -> (bool, String) {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let clock_val = std::sync::Arc::new(std::sync::Mutex::new(1_700_000_000.0));
    let clock = {
        let clock_val = clock_val.clone();
        std::sync::Arc::new(move || *clock_val.lock().unwrap()) as zeropw::clock::Clock
    };
    let policy = Policy::new(&state, clock);
    policy.create_principal("agent-1", "default").unwrap();
    policy.create_connection(rust_connection()).unwrap();

    let decision = match name {
        "revoked" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy.revoke_grant(&grant.id).unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "expired" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(10), None)
                .unwrap();
            *clock_val.lock().unwrap() += 10.0;
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "exhausted" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), Some(1))
                .unwrap();
            policy
                .consume(
                    &grant.id,
                    None,
                    None,
                    Some(Action::http("GET", "/repos")),
                    None,
                )
                .unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "stopped" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy.stop_all().unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "restore_pending" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy.set_restore_pending(true).unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "stale" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            let scope = policy::HttpScope::new(
                None,
                Some(vec!["/repos".into(), "/me".into()]),
                vec!["DELETE".into()],
            )
            .unwrap();
            policy
                .update_connection("gh", ConnectionChanges::new().http_scope(Some(scope)))
                .unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "principal_disabled" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy.disable_principal("agent-1", true).unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "connection_disabled" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy.disable_connection("gh").unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "wrong_scope_method" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("DELETE", "/repos"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        "wrong_scope_path" => {
            let grant = policy
                .create_grant("agent-1", "gh", Some(3600), None)
                .unwrap();
            policy
                .evaluate(
                    "agent-1",
                    "gh",
                    &Action::http("GET", "/admin"),
                    Some(&grant.id),
                )
                .unwrap()
        }
        other => panic!("unknown scenario {other}"),
    };
    (decision.allowed, decision.reason.to_string())
}

#[test]
fn authorization_scenarios_deny_with_the_expected_reason() {
    for (name, reason) in [
        ("revoked", "grant_revoked"),
        ("expired", "grant_expired"),
        ("exhausted", "grant_exhausted"),
        ("stopped", "global_stop"),
        ("restore_pending", "restore_pending"),
        ("stale", "grant_stale"),
        ("principal_disabled", "principal_disabled"),
        ("connection_disabled", "connection_disabled"),
        ("wrong_scope_method", "method_not_allowed"),
        ("wrong_scope_path", "path_not_allowed"),
    ] {
        assert_eq!(
            rust_scenario(name),
            (false, reason.to_string()),
            "scenario {name}"
        );
    }
}

// ------------------------------------------------------------------- D-3
// `_canonical_host_key` (`SshTarget.host_keys`) now goes through
// `crate::sshwire`'s general-purpose `authorized_keys` parser instead of a
// duplicate, self-contained one; this checks a table of lines (valid,
// comment, options, tabs, wrong type, bad base64, trailing data, control
// characters, newline "comment") end to end, with the outcomes the prototype
// produced (a stored host key pins the SSH server identity).
#[test]
fn canonical_host_key_over_a_table_of_lines() {
    let good = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBIiixV5ZS+n29XxvfIT9WV3jN8gvyc0/eOKlxJvpz20";
    let lines: Vec<String> = vec![
        good.to_string(),
        format!("{good}  "),
        format!("{good} deploy key"),
        // a leading options field before the key type: the caller
        // (`_canonical_host_key`) requires the line to start with
        // `"ssh-ed25519 "`, so any leading options field already fails
        // that check before the parser ever runs.
        "command=\"/bin/true\" ssh-ed25519 AAAA".to_string(),
        // tab-separated fields are still parsed by `parse_authorized_key_entry`
        good.replacen(' ', "\t", 1),
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDT".to_string(),
        "ssh-ed25519 not-base64!".to_string(),
        // an embedded newline (no genuine wire trailing data reached: the
        // control-character check runs first, exactly like Python's
        // `_CONTROL_CHARS_RE.search(line)`)
        format!("{good}\n[victim.example.com]:22 {good}"),
        format!("{good}\x00"),
        format!("{good} evil\ncomment"),
        // genuine wire-level trailing data: extra bytes appended after the
        // 32-byte key inside the base64 blob itself (no control character
        // involved, so this one actually reaches the parser's own
        // trailing-data check)
        {
            let (_, b64) = good.split_once(' ').unwrap();
            let mut blob = BASE64_STANDARD.decode(b64).unwrap();
            blob.extend_from_slice(b"\x00\x00\x00\x01Z");
            format!("ssh-ed25519 {}", BASE64_STANDARD.encode(blob))
        },
    ];
    let want: &[&str] = &[
        "'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBIiixV5ZS+n29XxvfIT9WV3jN8gvyc0/eOKlxJvpz20'",
        "'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBIiixV5ZS+n29XxvfIT9WV3jN8gvyc0/eOKlxJvpz20'",
        "'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBIiixV5ZS+n29XxvfIT9WV3jN8gvyc0/eOKlxJvpz20 deploy key'",
        "ERR:unsupported_host_key",
        "ERR:unsupported_host_key",
        "ERR:unsupported_host_key",
        "ERR:invalid_host_key",
        "ERR:invalid_host_key",
        "ERR:invalid_host_key",
        "ERR:invalid_host_key",
        "ERR:invalid_host_key",
    ];
    assert_eq!(want.len(), lines.len());

    for (line, want) in lines.iter().zip(want.iter()) {
        let got = SshTarget::new("127.0.0.1", 22, "deploy", vec![line.clone()]);
        match got {
            Ok(target) => {
                let expected = &want[1..want.len() - 1]; // strip the repr quotes
                assert_eq!(
                    target.host_keys[0], *expected,
                    "line={line:?} want={want:?}"
                );
            }
            Err(e) => {
                assert_eq!(*want, format!("ERR:{}", e.reason), "line={line:?}");
            }
        }
    }
}

// ------------------------------------------------------------------- D-5
// `Connection.public_view()["scope"]["methods"]`/`"path_prefixes"` is
// `"all"` when the stored value is falsy -- `None` *or* an empty list --
// not merely `None`. `methods=()` is legal (`HttpScope.__post_init__` only
// rejects an empty `path_prefixes`, not an empty `methods`), so it is a
// real, reachable case, not just a hypothetical.
#[test]
fn public_view_scope_treats_empty_methods_as_all_like_python() {
    let conn = Connection::new(
        "gh",
        "demo",
        "dev",
        "fake-github",
        "http",
        "gh-token",
        None,
        "demo",
        Some(HttpTarget::new("http", "127.0.0.1", 8080, None, false).unwrap()),
        Some(HttpAuth::bearer()),
        Some(HttpScope::new(Some(vec![]), Some(vec!["/repos".into()]), vec![]).unwrap()),
        None,
        None,
        0,
        "active",
        "",
        "",
    )
    .unwrap();
    let view = conn.public_view();
    assert_eq!(view["scope"]["methods"], serde_json::json!("all"));
    assert_eq!(
        view["scope"]["path_prefixes"],
        serde_json::json!(["/repos"])
    );
    assert_eq!(view["scope"]["confirm_methods"], serde_json::json!([]));
}

// ------------------------------------------------------------------- D-6
// `Connection.from_dict` (and the nested-model `build()` it uses) re-runs
// full dataclass `__post_init__` validation on a stored document, so a
// malformed stored field raises the *same documented* `InvalidInput` a bad
// value passed to the constructor directly would -- not a generic
// `state_corrupt` -- except where Python itself lets a built-in exception
// escape uncaught (PORTING.md §3.5) or silently accepts a value Rust's
// typed fields cannot represent (a genuine, narrower residual; see
// `DEVIATIONS.md`).
#[test]
fn connection_from_value_matches_python_over_a_table_of_malformed_documents() {
    // ---- Rust side: the same cases through `Connection::from_value`.
    let http_doc = || rust_connection().to_value();
    let ssh_base = || {
        Connection::new(
            "box",
            "demo",
            "dev",
            "ssh-box",
            "ssh",
            "box-key",
            None,
            "",
            None,
            None,
            None,
            Some(
                SshTarget::new(
                    "127.0.0.1",
                    22,
                    "deploy",
                    vec![
                        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA host"
                            .to_string(),
                    ],
                )
                .unwrap(),
            ),
            None,
            0,
            "active",
            "",
            "",
        )
        .unwrap()
        .to_value()
    };
    let cli_doc = || {
        Connection::new(
            "gh",
            "demo",
            "dev",
            "fake-github",
            "http",
            "gh-token",
            None,
            "demo connection",
            Some(HttpTarget::new("http", "127.0.0.1", 8080, None, false).unwrap()),
            Some(HttpAuth::bearer()),
            Some(
                HttpScope::new(
                    Some(vec!["GET".into(), "POST".into()]),
                    Some(vec!["/repos".into(), "/me".into()]),
                    vec!["DELETE".into()],
                )
                .unwrap(),
            ),
            None,
            Some(CliProfile::new("git", "http", None, Default::default()).unwrap()),
            0,
            "active",
            "",
            "",
        )
        .unwrap()
        .to_value()
    };

    let mut d = http_doc();
    d["http_target"]["port"] = serde_json::json!("8080");
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::InvalidInput)
    );

    let mut d = http_doc();
    d["http_target"]["port"] = serde_json::json!(8080.0);
    assert!(Connection::from_value(&d).is_err());

    let mut d = http_doc();
    d["http_target"]["port"] = serde_json::json!(true);
    assert!(Connection::from_value(&d).is_err());

    let mut d = http_doc();
    // `2**70`: `arbitrary_precision` preserves the exact literal.
    d["http_target"]["port"] = serde_json::Value::Number("1180591620717411303424".parse().unwrap());
    assert!(Connection::from_value(&d).is_err());

    let mut d = http_doc();
    d["http_target"]["allow_private_network"] = serde_json::Value::Null;
    let err = Connection::from_value(&d).unwrap_err();
    assert_eq!(err.reason, "invalid_allow_private_network");

    let mut d = http_doc();
    d["http_target"]["allow_private_network"] = serde_json::json!(1);
    let err = Connection::from_value(&d).unwrap_err();
    assert_eq!(err.reason, "invalid_allow_private_network");

    let mut d = http_doc();
    d["http_target"]["scheme"] = serde_json::json!(5);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_scheme"
    );

    let mut d = http_doc();
    d["http_target"]["host"] = serde_json::json!(5);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_host"
    );

    let mut d = ssh_base();
    d["ssh_target"]["username"] = serde_json::json!(5);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_ssh_username"
    );

    let mut d = ssh_base();
    d["ssh_target"]["host_keys"] = serde_json::json!("");
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "ssh_host_keys_required"
    );

    let mut d = ssh_base();
    d["ssh_target"]["host_keys"] = serde_json::json!("somestring");
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "unsupported_host_key"
    );

    let mut d = ssh_base();
    d["ssh_target"]["host_keys"] = serde_json::json!([5]);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "unsupported_host_key"
    );

    let mut d = cli_doc();
    d["cli"]["extra_env"] = serde_json::json!({"FOO": 5});
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_env_value"
    );

    // `base_url_env` non-string: Python raises an uncaught `TypeError`
    // (§3.5); Rust's `state_corrupt` is the documented counterpart.
    let mut d = cli_doc();
    d["cli"]["base_url_env"] = serde_json::json!(5);
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    // A present-but-JSON-falsy non-string `header_name`/`basic_username`,
    // when `mode` requires the field: Python's `not value` short-circuit
    // gives the documented reason, not an uncaught `TypeError`.
    let mut d = http_doc();
    d["http_auth"]["mode"] = serde_json::json!("header");
    d["http_auth"]["header_name"] = serde_json::json!(0);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_header_name"
    );

    let mut d = http_doc();
    d["http_auth"]["mode"] = serde_json::json!("basic");
    d["http_auth"]["basic_username"] = serde_json::json!(false);
    assert_eq!(
        Connection::from_value(&d).unwrap_err().reason,
        "invalid_basic_username"
    );

    // `policy_version`: Python's `int()` coercion.
    let mut d = http_doc();
    d["policy_version"] = serde_json::json!("3");
    assert_eq!(Connection::from_value(&d).unwrap().policy_version, 3);

    let mut d = http_doc();
    d["policy_version"] = serde_json::json!(3.7);
    assert_eq!(Connection::from_value(&d).unwrap().policy_version, 3);

    let mut d = http_doc();
    d["policy_version"] = serde_json::json!(true);
    assert_eq!(Connection::from_value(&d).unwrap().policy_version, 1);

    let mut d = http_doc();
    d["policy_version"] = serde_json::json!("abc");
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    let mut d = http_doc();
    d.as_object_mut().unwrap().remove("policy_version");
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    // `secret_version`: stored untyped by Python, kept verbatim for every
    // shape (the differential form is `rust/tests/policy_parity_close.rs`).
    let mut d = http_doc();
    d["secret_version"] = serde_json::json!(5);
    assert_eq!(
        Connection::from_value(&d).unwrap().secret_version,
        Some(5.into())
    );

    let mut d = http_doc();
    d["secret_version"] = serde_json::from_str("1000000000000000000000000000000").unwrap();
    let connection = Connection::from_value(&d).unwrap();
    assert_eq!(
        connection
            .secret_version
            .as_ref()
            .unwrap()
            .value()
            .to_string(),
        "1000000000000000000000000000000"
    );
    assert_eq!(connection.to_value()["secret_version"], d["secret_version"]);

    let mut d = http_doc();
    d["secret_version"] = serde_json::json!("abc");
    let connection = Connection::from_value(&d).unwrap();
    assert_eq!(connection.to_value()["secret_version"], d["secret_version"]);
}

// ------------------------------------------------------------------- D-4
// `is_stopped`/`restore_pending`/`_decide`/`usable_connections` read
// `control.json`'s `"stopped"`/`"restore_pending"` flags with Python
// truthiness (`if control.get("stopped")`), not `bool`-only equality: a
// non-boolean truthy stored value (`1`, `"true"`, `[1]`) must still stop
// everything (fail closed): a hand-edited flag never silently re-enables
// access.
#[test]
fn control_flag_truthiness_stops_for_non_boolean_values() {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
    policy.create_principal("agent-1", "default").unwrap();
    policy.create_connection(rust_connection()).unwrap();
    let grant_id = policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap()
        .id;

    let mut control = state
        .read_json(policy::CONTROL, serde_json::json!({}))
        .unwrap();
    control["stopped"] = serde_json::json!(1);
    control["restore_pending"] = serde_json::json!(false);
    state.write_json(policy::CONTROL, &control).unwrap();
    assert!(policy.is_stopped().unwrap());
    assert_eq!(
        policy
            .evaluate(
                "agent-1",
                "gh",
                &Action::http("GET", "/repos"),
                Some(&grant_id)
            )
            .unwrap()
            .reason,
        "global_stop"
    );
    assert!(policy.usable_connections("agent-1").unwrap().is_empty());

    control["stopped"] = serde_json::json!(false);
    control["restore_pending"] = serde_json::json!([1]);
    state.write_json(policy::CONTROL, &control).unwrap();
    assert!(policy.restore_pending().unwrap());
    assert_eq!(
        policy
            .evaluate(
                "agent-1",
                "gh",
                &Action::http("GET", "/repos"),
                Some(&grant_id)
            )
            .unwrap()
            .reason,
        "restore_pending"
    );

    // D-R5-1: same probe against a `stopped` magnitude beyond `f64` range.
    control["restore_pending"] = serde_json::json!(false);
    control["stopped"] = serde_json::from_str(&format!("1{}", "0".repeat(400))).unwrap();
    state.write_json(policy::CONTROL, &control).unwrap();
    assert!(policy.is_stopped().unwrap());
    assert_eq!(
        policy
            .evaluate(
                "agent-1",
                "gh",
                &Action::http("GET", "/repos"),
                Some(&grant_id)
            )
            .unwrap()
            .reason,
        "global_stop"
    );
}

// ------------------------------------------------------- round-2 findings
// (equivalence review of work unit D, `policy.rs`) -- D-R2-1..D-R2-9.

// D-R2-1: `Policy::control` used to fold *any* non-object read (including a
// truthy one like `[1]`) into the default document. Python's `... or
// {defaults}` only falls back for a *falsy* read; a truthy non-dict value is
// returned as-is and every caller's `.get(...)` then raises an uncaught
// `AttributeError` -- fail closed instead (`state_corrupt`).
#[test]
fn control_document_truthy_non_object_fails_closed_like_python_attributeerror() {
    // Truthy non-object: Rust must fail closed with `state_corrupt`.
    for value in [
        serde_json::json!([1]),
        serde_json::json!("x"),
        serde_json::json!(5),
    ] {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        state.write_json(policy::CONTROL, &value).unwrap();
        let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
        let err = policy.is_stopped().unwrap_err();
        assert!(
            err.is(zeropw::errors::ErrorClass::StateError),
            "{value:?}: {err:?}"
        );
        assert_eq!(err.reason, "state_corrupt", "{value:?}");
    }

    // Falsy (missing, `[]`, `null`, `{}`): the default document, exactly
    // like before.
    for value in [
        serde_json::json!([]),
        serde_json::Value::Null,
        serde_json::json!({}),
    ] {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        state.write_json(policy::CONTROL, &value).unwrap();
        let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
        assert!(!policy.is_stopped().unwrap(), "{value:?}");
    }

    // An unparseable file already agreed before this fix (`read_json`
    // itself raises `state_corrupt`) -- still true after it.
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    std::fs::create_dir_all(tmp.path().join("state").join("policy")).unwrap();
    std::fs::write(
        tmp.path().join("state").join("policy/control.json"),
        b"{not json",
    )
    .unwrap();
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert_eq!(policy.is_stopped().unwrap_err().reason, "state_corrupt");
}

// D-R2-2: `Policy::vault_doc` used to swallow a corrupt (unparseable)
// `vault/secrets.json` the same way it treats a successfully-parsed
// non-dict value, silently returning `{}`. Python's `_vault_doc` only
// narrows a *parsed* non-dict to `{}`; an unparseable file makes
// `read_json` itself raise `StateError("state_corrupt", ...)`, uncaught,
// propagating out of `create_grant` (via `_resolved_credential_version`).
#[test]
fn vault_doc_corrupt_file_propagates_state_corrupt_through_create_grant() {
    let tmp = TempDir::new().unwrap();
    let state_path = tmp.path().join("state");
    let state = StateDir::new(&state_path);
    state.create().unwrap();
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
    policy.create_principal("agent-1", "default").unwrap();
    policy.create_connection(rust_connection()).unwrap();
    std::fs::create_dir_all(state_path.join("vault")).unwrap();
    std::fs::write(state_path.join("vault").join("secrets.json"), b"{not json").unwrap();

    let err = policy
        .create_grant("agent-1", "gh", Some(3600), None)
        .unwrap_err();
    assert!(err.is(zeropw::errors::ErrorClass::StateError));
    assert_eq!(err.reason, "state_corrupt");
    assert_eq!(err.detail, "vault/secrets.json");

    // A successfully-*parsed* non-dict value is still treated as `{}`, not
    // an error -- only an unparseable file propagates.
    std::fs::write(state_path.join("vault").join("secrets.json"), b"[1]").unwrap();
    assert!(
        policy
            .create_grant("agent-1", "gh", Some(3600), None)
            .is_ok()
    );
}

// D-R2-3: `Policy::approval_mismatch` used `entry.get("grant").and_then
// (Value::as_str)`, silently treating a present *non-string* `grant` (e.g.
// `5`) the same as a *missing* one and skipping the grant-binding check
// entirely. Python's `recorded_grant = entry.get("grant")` only skips a
// `None`; a present non-string value reaches `self.get_grant(...)`, which
// can never find a match and raises `NotFound` -> `"grant_changed"`.
#[test]
fn approval_mismatch_treats_present_non_string_grant_as_grant_changed() {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let policy = Policy::new(&state, clock::fixed(1_700_000_000.0));
    policy.create_principal("agent-1", "default").unwrap();
    policy.create_connection(rust_connection()).unwrap();

    let mut control = state
        .read_json(policy::CONTROL, serde_json::json!({}))
        .unwrap();
    let mut approvals = serde_json::Map::new();
    approvals.insert(
        "dg1".to_string(),
        serde_json::json!({
            "caller": "agent-1", "connection": "gh", "method": "GET", "path": "/repos",
            "status": "approved", "created_at": "", "expires_at": 1_700_003_600.0,
            "grant": 5, "policy_version": 1, "cycle": 1,
        }),
    );
    control["approvals"] = serde_json::Value::Object(approvals);
    state.write_json(policy::CONTROL, &control).unwrap();

    let consumed = policy
        .consume_approval("dg1", "agent-1", "gh", None, None)
        .unwrap();
    assert!(!consumed, "a non-string grant must not be consumable");

    let after = state
        .read_json(policy::CONTROL, serde_json::json!({}))
        .unwrap();
    let entry = &after["approvals"]["dg1"];
    assert_eq!(entry["status"], serde_json::json!("invalidated"));
    assert_eq!(entry["closed_reason"], serde_json::json!("grant_changed"));
}

// D-R2-6: `HttpTarget::from_value`/`HttpAuth::from_value` silently ignored
// unknown keys. Python builds these via `HttpTarget(**value,
// check_address=False)` / `HttpAuth(**value)`, so an unknown key -- or a
// stored `check_address`, which `Connection.from_dict` itself already
// passes for `HttpTarget` -- collides with or adds an unexpected keyword
// argument, an uncaught `TypeError`, and the whole document fails to load.
#[test]
fn http_target_and_http_auth_reject_unknown_keys_like_pythons_kwarg_unpacking() {
    let base = || rust_connection().to_value();

    let mut d = base();
    d["http_target"]["foo"] = serde_json::json!(1);
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    let mut d = base();
    d["http_target"]["check_address"] = serde_json::json!(false);
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    let mut d = base();
    d["http_auth"]["bogus"] = serde_json::json!("x");
    assert!(
        Connection::from_value(&d)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    assert!(Connection::from_value(&base()).is_ok());
}

// ================================================================ round 3

// D-R3-1: `Policy._principals`/`_connections`/`_grants` are `read_json(name,
// {}) or {}` -- the same falsy/truthy split `Policy._control` (D-R2-1)
// already reproduces. A *truthy* non-dict document ([1], "x", 5) is
// returned verbatim by Python's `or`, and the first `.items()` on it raises
// an uncaught `AttributeError`; a *falsy* one ([], null, {}, 0, "") is
// replaced with `{}`. `list_principals`/`list_connections`/`list_grants`
// are pure reads through exactly these helpers, with no side effects to set
// up first.
#[test]
fn read_doc_matches_pythons_read_json_or_default_falsy_truthy_split() {
    let values: [(serde_json::Value, bool); 8] = [
        (serde_json::json!([1]), true),
        (serde_json::json!("x"), true),
        (serde_json::json!(5), true),
        (serde_json::json!([]), false),
        (serde_json::Value::Null, false),
        (serde_json::json!({}), false),
        (serde_json::json!(0), false),
        (serde_json::json!(""), false),
    ];

    for (value, should_fail) in &values {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        state.write_json(policy::PRINCIPALS, value).unwrap();
        let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
        let result = pol.list_principals();
        if *should_fail {
            let err = result.unwrap_err();
            assert!(
                err.is(zeropw::errors::ErrorClass::StateError),
                "principals value={value:?} err={err:?}"
            );
            let raw =
                std::fs::read_to_string(tmp.path().join("state").join(policy::PRINCIPALS)).unwrap();
            let reparsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(&reparsed, value, "principals.json must be left untouched");
        } else {
            assert!(
                result.is_ok(),
                "principals value={value:?}: {:?}",
                result.err()
            );
        }
    }

    for (value, should_fail) in &values {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        state.write_json(policy::CONNECTIONS, value).unwrap();
        let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
        let result = pol.list_connections();
        if *should_fail {
            let err = result.unwrap_err();
            assert!(
                err.is(zeropw::errors::ErrorClass::StateError),
                "connections value={value:?} err={err:?}"
            );
            let raw = std::fs::read_to_string(tmp.path().join("state").join(policy::CONNECTIONS))
                .unwrap();
            let reparsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(&reparsed, value, "connections.json must be left untouched");
        } else {
            assert!(
                result.is_ok(),
                "connections value={value:?}: {:?}",
                result.err()
            );
        }
    }

    for (value, should_fail) in &values {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        state.write_json(policy::GRANTS, value).unwrap();
        let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
        let result = pol.list_grants(None);
        if *should_fail {
            let err = result.unwrap_err();
            assert!(
                err.is(zeropw::errors::ErrorClass::StateError),
                "grants value={value:?} err={err:?}"
            );
            let raw =
                std::fs::read_to_string(tmp.path().join("state").join(policy::GRANTS)).unwrap();
            let reparsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(&reparsed, value, "grants.json must be left untouched");
        } else {
            assert!(result.is_ok(), "grants value={value:?}: {:?}", result.err());
        }
    }
}

// D-R3-2: `control.setdefault("approvals", {})` only inserts the empty-dict
// default for an ABSENT key; a present non-dict value is returned unchanged
// by `setdefault`, and the subsequent `.get(...)` raises an uncaught
// `AttributeError` -- `request_approval`/`approve`/`consume_approval` must
// fail closed and never overwrite the corrupt value.
#[test]
fn approvals_setdefault_fails_closed_on_truthy_non_object_like_pythons_setdefault() {
    for value in [
        serde_json::json!("x"),
        serde_json::json!([1]),
        serde_json::json!(5),
    ] {
        for op in ["request", "approve", "consume"] {
            let tmp = TempDir::new().unwrap();
            let state = StateDir::new(tmp.path().join("state"));
            state.create().unwrap();
            let control = serde_json::json!({
                "stopped": false, "restore_pending": false, "approvals": value,
            });
            state.write_json(policy::CONTROL, &control).unwrap();
            let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
            let err_class = match op {
                "request" => pol
                    .request_approval("dg1", "agent-1", "conn-1", "GET", "/x")
                    .unwrap_err()
                    .is(zeropw::errors::ErrorClass::StateError),
                "approve" => pol
                    .approve("dg1")
                    .unwrap_err()
                    .is(zeropw::errors::ErrorClass::StateError),
                "consume" => pol
                    .consume_approval("dg1", "agent-1", "conn-1", None, None)
                    .unwrap_err()
                    .is(zeropw::errors::ErrorClass::StateError),
                _ => unreachable!(),
            };
            assert!(err_class, "op={op} value={value:?}");
            let after = state
                .read_json(policy::CONTROL, serde_json::json!({}))
                .unwrap();
            assert_eq!(
                after["approvals"], value,
                "op={op} value={value:?}: approvals must be left untouched"
            );
        }
    }
}

// D-R3-7: `Grant(**entry)` -- an unrecognised key in the stored grant makes
// the `**entry` unpacking raise an uncaught `TypeError`, the same shape
// `HttpTarget`/`HttpAuth` already reject (D-R2-6).
#[test]
fn grant_from_value_rejects_unknown_keys_like_pythons_kwarg_unpacking() {
    // `Grant::from_value` is private (reached only through public `Policy`
    // methods, as `Grant(**entry)` is only ever reached through `Policy`
    // methods in Python); exercise it through `Policy::get_grant`.
    let entry = serde_json::json!({
        "id": "g-1", "principal": "agent-1", "connection": "conn-1", "policy_version": 1,
        "expires_at": null, "max_uses": null, "uses": 0, "status": "active",
        "created_at": "2020-01-01T00:00:00Z", "revoked_at": null, "credential_version": null,
        "unexpected_field": "x",
    });
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut grants = serde_json::Map::new();
    grants.insert("g-1".into(), entry.clone());
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.get_grant("g-1")
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    // A well-formed entry with only known keys still loads.
    let mut ok_entry = entry.clone();
    ok_entry.as_object_mut().unwrap().remove("unexpected_field");
    let mut grants = serde_json::Map::new();
    grants.insert("g-1".into(), ok_entry);
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    assert!(pol.get_grant("g-1").is_ok());
}

// D-R5-9: `recorded = [g for g in grants.values() if ...]` is a full list
// comprehension -- it validates every grant entry's shape (`.get()`/`in`
// raise for a non-dict entry) over the *whole* `grants.values()` before
// `any(...)` ever runs. `break`-ing out of the Rust loop on the first
// mismatch stopped validating entries after that point, so a malformed
// later entry was never noticed and the whole operation succeeded (bumping
// the policy version) where Python raises before doing anything.
#[test]
fn credential_versions_changed_validates_every_grant_before_deciding_any_mismatch() {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut connections = serde_json::Map::new();
    connections.insert(
        "gh".into(),
        serde_json::json!({
            "id": "gh", "project": "demo", "environment": "dev", "service": "fake-github", "kind": "http",
            "secret_id": "gh-token", "secret_version": null, "description": "demo",
            "http_target": {"scheme": "http", "host": "127.0.0.1", "port": 8080, "ca_file": null, "allow_private_network": false},
            "http_auth": {"mode": "bearer", "header_name": null, "value_prefix": null, "basic_username": null},
            "http_scope": {"methods": ["GET", "POST"], "path_prefixes": ["/repos", "/me"], "confirm_methods": []},
            "ssh_target": null, "cli": null, "policy_version": 1, "status": "active", "created_at": "", "updated_at": "",
        }),
    );
    state
        .write_json(policy::CONNECTIONS, &serde_json::Value::Object(connections))
        .unwrap();
    let mut vault = serde_json::Map::new();
    let mut secrets = serde_json::Map::new();
    secrets.insert(
        "gh-token".into(),
        serde_json::json!({"active_version": 1, "versions": {}}),
    );
    vault.insert("secrets".into(), serde_json::Value::Object(secrets));
    state
        .write_json(policy::VAULT_SECRETS, &serde_json::Value::Object(vault))
        .unwrap();
    let mut grants = serde_json::Map::new();
    grants.insert(
        "g-1-mismatch".into(),
        serde_json::json!({"connection": "gh", "status": "active", "credential_version": 99}),
    );
    grants.insert("g-2-malformed".into(), serde_json::json!("not-a-dict"));
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();

    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.credential_versions_changed("gh-token")
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );
    let after = state
        .read_json(policy::CONNECTIONS, serde_json::json!({}))
        .unwrap();
    assert_eq!(after["gh"]["policy_version"], serde_json::json!(1));
}

// D-R3-10: Python indexes `entry["token_hash"]` in `authenticate` and
// `entry["status"]` in `revoke_all` -- both raw dict indexing, not `.get()`
// -- so a malformed entry raises an uncaught `KeyError`, aborting the whole
// operation; `revoke_grants_of` legitimately uses `.get()` and keeps
// skipping a well-formed entry missing a key, but still crashes for an
// entry that isn't a dict at all.
#[test]
fn authenticate_and_revoke_all_fail_closed_on_a_malformed_entry() {
    // `authenticate`: a principal document with an earlier, malformed
    // entry aborts the whole scan even though a later entry would match.
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut principals = serde_json::Map::new();
    principals.insert(
        "bad".into(),
        serde_json::json!({"status": "active", "created_at": ""}),
    );
    principals.insert(
        "good".into(),
        serde_json::json!({
            "token_hash": policy::hash_token("zpwc_abc"), "status": "active", "created_at": "",
        }),
    );
    state
        .write_json(policy::PRINCIPALS, &serde_json::Value::Object(principals))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.authenticate("zpwc_abc")
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    // `revoke_all`: a non-object grant entry aborts before anything is
    // written, not a partial write with the malformed entry skipped.
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut grants = serde_json::Map::new();
    grants.insert("bad".into(), serde_json::json!("not-a-dict"));
    grants.insert("good".into(), serde_json::json!({"status": "active"}));
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.revoke_all()
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );
    let after = state
        .read_json(policy::GRANTS, serde_json::json!({}))
        .unwrap();
    assert_eq!(after["good"]["status"], serde_json::json!("active"));

    // `revoke_grants_of`: a non-object entry also aborts (unlike a
    // well-formed entry missing a key, which is legitimately skipped).
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut grants = serde_json::Map::new();
    grants.insert("bad".into(), serde_json::json!("not-a-dict"));
    grants.insert(
        "good".into(),
        serde_json::json!({"principal": "agent-1", "status": "active"}),
    );
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.revoke_grants_of("agent-1")
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );
}

// D-R5-5: `entry["status"] in ("active", "stale")` is a raw index (missing
// key -> uncaught `KeyError`) plus a *membership* test -- a present
// non-string `status` simply never matches, same as any other value not in
// the tuple, so that one grant is skipped while every other grant is still
// revoked. Treating "present but not a string" the same as "missing"
// refused to revoke *anything* the moment one grant had a non-string
// `status`.
#[test]
fn revoke_all_skips_a_present_non_string_status_but_still_revokes_the_rest() {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut grants = serde_json::Map::new();
    grants.insert(
        "weird".into(),
        serde_json::json!({"status": 5, "principal": "agent-1"}),
    );
    grants.insert(
        "good".into(),
        serde_json::json!({"status": "active", "principal": "agent-1"}),
    );
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    let n = pol.revoke_all().unwrap();
    assert_eq!(n, 1);
    let after = state
        .read_json(policy::GRANTS, serde_json::json!({}))
        .unwrap();
    assert_eq!(after["weird"]["status"], serde_json::json!(5));
    assert_eq!(after["good"]["status"], serde_json::json!("revoked"));
}

// D-R5-6: `secrets.compare_digest(str, str)` raises an uncaught `TypeError`
// the moment either argument has a non-ASCII character; `digest` (a hex
// sha256) is always ASCII, so only a non-ASCII *stored* `token_hash` can
// trigger it, aborting the whole scan -- no later (even well-formed)
// principal can authenticate while such an entry exists. Comparing raw
// bytes never raises, so it previously just failed to match and let every
// other principal keep authenticating.
#[test]
fn authenticate_fails_closed_on_a_non_ascii_stored_token_hash() {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut principals = serde_json::Map::new();
    principals.insert(
        "a-nonascii".into(),
        serde_json::json!({"token_hash": "caf\u{e9}", "status": "active", "created_at": ""}),
    );
    principals.insert(
        "good".into(),
        serde_json::json!({
            "token_hash": policy::hash_token("zpwc_abc"), "status": "active", "created_at": "",
        }),
    );
    state
        .write_json(policy::PRINCIPALS, &serde_json::Value::Object(principals))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.authenticate("zpwc_abc")
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );
}

// ------------------------------------------------------- round-4 findings
// (equivalence review of work unit D, `policy.rs`) -- D-R4-1..D-R4-8, plus
// one further fail-open bug found by this round's exhaustive raw-index
// sweep (`disable_principal`).

// D-R4-1: `resume`'s `if open_incident:` is plain Python truthiness over any
// stored type, not an `isinstance(str)` narrowing -- a stored `incident_open`
// of `5`, `["x"]` or `{"a": 1}` must refuse the resume exactly like a
// non-empty string does. All seven probe values from the finding.
#[test]
fn resume_gates_on_truthiness_of_any_incident_open_type_like_python() {
    let truthy_probes: Vec<(&str, serde_json::Value)> = vec![
        ("int5", serde_json::json!(5)),
        ("list_x", serde_json::json!(["x"])),
        ("dict_a1", serde_json::json!({"a": 1})),
        ("str_inc1", serde_json::json!("inc-1")),
        (
            "huge_int",
            serde_json::from_str(&format!("1{}", "0".repeat(400))).unwrap(),
        ),
        (
            "huge_negative_int",
            serde_json::from_str(&format!("-1{}", "0".repeat(400))).unwrap(),
        ),
    ];
    let falsy_probes: Vec<(&str, serde_json::Value)> = vec![
        ("empty_str", serde_json::json!("")),
        ("null", serde_json::Value::Null),
        ("zero", serde_json::json!(0)),
    ];

    for (label, v) in truthy_probes {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let mut control = serde_json::Map::new();
        control.insert("stopped".into(), serde_json::json!(true));
        control.insert("restore_pending".into(), serde_json::json!(false));
        control.insert("approvals".into(), serde_json::json!({}));
        control.insert("incident_open".into(), v);
        state
            .write_json(policy::CONTROL, &serde_json::Value::Object(control))
            .unwrap();
        let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
        let err = pol
            .resume()
            .expect_err(&format!("label={label} must refuse"));
        assert!(
            err.is(zeropw::errors::ErrorClass::InvalidInput),
            "label={label}"
        );
        assert_eq!(err.reason, "incident_open", "label={label}");
        // The global stop must be left untouched -- `resume` refused before
        // ever writing `control.json`.
        let after = state
            .read_json(policy::CONTROL, serde_json::json!({}))
            .unwrap();
        assert_eq!(after["stopped"], serde_json::json!(true), "label={label}");
    }

    for (label, v) in falsy_probes {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        let mut control = serde_json::Map::new();
        control.insert("stopped".into(), serde_json::json!(true));
        control.insert("restore_pending".into(), serde_json::json!(false));
        control.insert("approvals".into(), serde_json::json!({}));
        control.insert("incident_open".into(), v);
        state
            .write_json(policy::CONTROL, &serde_json::Value::Object(control))
            .unwrap();
        let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
        pol.resume()
            .unwrap_or_else(|e| panic!("label={label} must resume: {e:?}"));
        let after = state
            .read_json(policy::CONTROL, serde_json::json!({}))
            .unwrap();
        assert_eq!(after["stopped"], serde_json::json!(false), "label={label}");
    }
}

// D-R4-2: `_reevaluate_grants`'s `entry["connection"] != connection_id or
// entry["status"] != "active"` raw-indexes every grant entry in the
// document, regardless of whether it matches the connection being updated
// -- a non-object entry or one missing either key aborts the whole
// `update_connection` call, even though `connections.json` was already
// written by that point.
#[test]
fn reevaluate_grants_fails_closed_on_malformed_entries_like_python() {
    fn conn_doc() -> serde_json::Value {
        serde_json::json!({
            "id": "gh", "project": "demo", "environment": "dev", "service": "fake-github", "kind": "http",
            "secret_id": "gh-token", "secret_version": null, "description": "demo",
            "http_target": {"scheme": "http", "host": "127.0.0.1", "port": 8080, "ca_file": null, "allow_private_network": false},
            "http_auth": {"mode": "bearer", "header_name": null, "value_prefix": null, "basic_username": null},
            "http_scope": {"methods": ["GET", "POST"], "path_prefixes": ["/repos", "/me"], "confirm_methods": []},
            "ssh_target": null, "cli": null, "policy_version": 1, "status": "active", "created_at": "", "updated_at": "",
        })
    }

    // Non-object grant entry.
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut connections = serde_json::Map::new();
    connections.insert("gh".into(), conn_doc());
    state
        .write_json(policy::CONNECTIONS, &serde_json::Value::Object(connections))
        .unwrap();
    let mut grants = serde_json::Map::new();
    grants.insert("bad".into(), serde_json::json!("not-a-dict"));
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.update_connection(
            "gh",
            ConnectionChanges::new().description("new".to_string())
        )
        .unwrap_err()
        .is(zeropw::errors::ErrorClass::StateError)
    );
    // The connections document was already written before the malformed
    // grant was reached (matches Python's ordering exactly).
    let after = state
        .read_json(policy::CONNECTIONS, serde_json::json!({}))
        .unwrap();
    assert_eq!(after["gh"]["description"], serde_json::json!("new"));

    // Object entry missing the `connection` key.
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut connections = serde_json::Map::new();
    connections.insert("gh".into(), conn_doc());
    state
        .write_json(policy::CONNECTIONS, &serde_json::Value::Object(connections))
        .unwrap();
    let mut grants = serde_json::Map::new();
    grants.insert("bad".into(), serde_json::json!({"status": "active"}));
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.update_connection(
            "gh",
            ConnectionChanges::new().description("new".to_string())
        )
        .unwrap_err()
        .is(zeropw::errors::ErrorClass::StateError)
    );
}

// D-R4-3: `list_grants`'s principal filter raw-indexes `e["principal"]`
// for every entry (in sorted-key order) once `principal_id` is not `None`,
// aborting on the first malformed entry -- not silently excluding it while
// still returning a matching later entry. This also covers `decide`'s
// no-grant-id path and `usable_connections`, which both call
// `list_grants(Some(caller))`.
#[test]
fn list_grants_fails_closed_when_filtering_by_principal_on_malformed_entries() {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut grants = serde_json::Map::new();
    grants.insert("bad".into(), serde_json::json!("not-a-dict"));
    grants.insert(
        "good".into(),
        serde_json::json!({
            "id": "g-1", "principal": "agent-1", "connection": "gh", "policy_version": 1,
            "expires_at": null, "max_uses": null, "uses": 0, "status": "active",
            "created_at": "", "revoked_at": null, "credential_version": null,
        }),
    );
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.list_grants(Some("agent-1"))
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );
    // `decide`'s no-grant-id path and `usable_connections` both call
    // `list_grants(Some(caller))` and must refuse the same way.
    assert!(
        pol.usable_connections("agent-1")
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );

    let tmp2 = TempDir::new().unwrap();
    let state2 = StateDir::new(tmp2.path().join("state"));
    state2.create().unwrap();
    let mut grants2 = serde_json::Map::new();
    grants2.insert(
        "aaa".into(),
        serde_json::json!({
            "id": "g-0", "connection": "gh", "policy_version": 1,
            "expires_at": null, "max_uses": null, "uses": 0, "status": "active",
            "created_at": "", "revoked_at": null, "credential_version": null,
        }),
    );
    grants2.insert(
        "zzz".into(),
        serde_json::json!({
            "id": "g-1", "principal": "agent-1", "connection": "gh", "policy_version": 1,
            "expires_at": null, "max_uses": null, "uses": 0, "status": "active",
            "created_at": "", "revoked_at": null, "credential_version": null,
        }),
    );
    state2
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants2))
        .unwrap();
    let pol2 = Policy::new(&state2, clock::fixed(1_700_000_000.0));
    assert!(
        pol2.list_grants(Some("agent-1"))
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );
}

// D-R4-6: `approval_matches_grant` collapsed a missing/non-string
// `principal`/`connection` on the revoked grant's raw stored entry to
// `""`, so it never matched an approval whose own `caller`/`connection` was
// absent (`None`) -- but Python's `entry.get("caller") ==
// grant.get("principal")` matches `None == None`, closing the approval
// before `revoke_grant`'s own final `Grant(**entry)` raises. Both languages
// must close the approval despite the ultimate error.
#[test]
fn revoke_grant_closes_approvals_by_none_to_none_match_before_its_own_error() {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut grants = serde_json::Map::new();
    grants.insert(
        "g-1".into(),
        serde_json::json!({
            "id": "g-1", "connection": "gh", "policy_version": 1, "expires_at": null,
            "max_uses": null, "uses": 0, "status": "active", "created_at": "",
            "revoked_at": null, "credential_version": null,
        }),
    );
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    let mut approvals = serde_json::Map::new();
    approvals.insert(
        "ap-1".into(),
        serde_json::json!({"connection": "gh", "status": "pending"}),
    );
    let mut control = serde_json::Map::new();
    control.insert("stopped".into(), serde_json::json!(false));
    control.insert("restore_pending".into(), serde_json::json!(false));
    control.insert("approvals".into(), serde_json::Value::Object(approvals));
    state
        .write_json(policy::CONTROL, &serde_json::Value::Object(control))
        .unwrap();

    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.revoke_grant("g-1")
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );
    let after_grants = state
        .read_json(policy::GRANTS, serde_json::json!({}))
        .unwrap();
    assert_eq!(after_grants["g-1"]["status"], serde_json::json!("revoked"));
    let after_control = state
        .read_json(policy::CONTROL, serde_json::json!({}))
        .unwrap();
    assert_eq!(
        after_control["approvals"]["ap-1"]["status"],
        serde_json::json!("invalidated")
    );
    assert_eq!(
        after_control["approvals"]["ap-1"]["closed_reason"],
        serde_json::json!("grant_revoked")
    );
}

// D-R5-8: Python appends the ledger line (`append_revocation`) *before*
// ever touching `entry` at all; only the following `entry["status"] =
// "revoked"` can raise (an uncaught `TypeError` for a non-dict entry). So
// the revocation survives on disk (the ledger sits outside the backup set
// and is replayed by `collect_revocations`) even though the call itself
// still fails. Shape-checking before `append_revocation` lost that
// surviving ledger line.
#[test]
fn revoke_grant_ledger_line_survives_a_non_object_entry_shape_failure() {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut grants = serde_json::Map::new();
    grants.insert("g-1".into(), serde_json::json!("not-a-dict"));
    state
        .write_json(policy::GRANTS, &serde_json::Value::Object(grants))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.revoke_grant("g-1")
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );
    let ledger_lines = state.read_lines(policy::REVOCATIONS, None).unwrap();
    assert_eq!(
        ledger_lines.len(),
        1,
        "ledger line must survive the failure"
    );
    assert!(ledger_lines[0].contains(r#""id":"g-1""#));
}

// Found by this round's exhaustive sweep of every raw index in policy.py
// (mandatory sweep (a), beyond the eight numbered findings):
// `disable_principal`'s `doc[principal_id]["status"] = "disabled"` is a raw
// subscript *assignment* on the stored entry -- if it is not a dict, Python
// raises an uncaught `TypeError`, aborting before `principals.json` is
// rewritten. The previous `if let Some(entry) = ...
// .and_then(Value::as_object_mut) { ... }` silently skipped the assignment
// instead and fell through to write the document unchanged and return
// `Ok(())`, so a corrupted principal could never actually be disabled.
#[test]
fn disable_principal_fails_closed_on_a_non_object_entry_instead_of_silently_succeeding() {
    let tmp = TempDir::new().unwrap();
    let state = StateDir::new(tmp.path().join("state"));
    state.create().unwrap();
    let mut principals = serde_json::Map::new();
    principals.insert("agent-1".into(), serde_json::json!("not-a-dict"));
    state
        .write_json(policy::PRINCIPALS, &serde_json::Value::Object(principals))
        .unwrap();
    let pol = Policy::new(&state, clock::fixed(1_700_000_000.0));
    assert!(
        pol.disable_principal("agent-1", true)
            .unwrap_err()
            .is(zeropw::errors::ErrorClass::StateError)
    );
    let after = state
        .read_json(policy::PRINCIPALS, serde_json::json!({}))
        .unwrap();
    assert_eq!(after["agent-1"], serde_json::json!("not-a-dict"));
}
