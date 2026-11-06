//! Pairing codes (docs/remote-sync.md §4): `zeropw://pair#<base64url(JSON)>`, made on the Mac
//! that already has the vault and pasted on the Mac that joins it.
//!
//! ```text
//! {"v":1,"service":"https://…","link_token":"…","peer":"<link device ID>","name":"<Mac name>",
//!  "invites":[{"env":"project/environment","invite":"<approval-required team invite>"}]}
//! ```
//!
//! The code is a secret: it carries a one-time link token for the service and one invitation
//! secret per environment. It lives in the one-time store on both Macs and is never logged. A
//! code alone is not enough to join: every invitation requires the inviting Mac's explicit
//! approval of the joining Mac's fingerprint (§3.2). Decoding is strict and offline: the base64url
//! alphabet without padding, the exact keys above, version 1, bounded sizes, and value shapes
//! checked before anything uses them. What the invitations themselves say (inviter fingerprint,
//! addresses, expiry) is read by `team invite-info`, also offline, by the caller.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::admin::is_project_name;
use crate::error::AppError;
use crate::link::{check_display_name, check_service_url, is_device_id, is_link_token};
use crate::secret::SecretString;

pub const PREFIX: &str = "zeropw://pair#";
/// The longest pasted code taken (16 invitations of at most 4096 characters, base64url).
pub const MAX_CODE_CHARS: usize = 96 * 1024;
pub const MAX_INVITES: usize = 16;
const MAX_INVITE_CHARS: usize = 4096;

/// One environment's invitation inside a code.
pub struct PairInvite {
    /// The environment's name on the Mac that made the code (`project/environment`), used as
    /// the default local name on the joining Mac.
    pub env: String,
    pub invite: SecretString,
}

/// A decoded pairing code. No `Debug`, `Clone` or `Serialize`.
pub struct PairingCode {
    pub service: String,
    pub link_token: SecretString,
    /// The link device ID of the Mac that made the code.
    pub peer: String,
    /// That Mac's display name (untrusted text on the joining side).
    pub name: String,
    pub invites: Vec<PairInvite>,
}

#[derive(Serialize)]
struct WireOut<'a> {
    v: u32,
    service: &'a str,
    link_token: &'a str,
    peer: &'a str,
    name: &'a str,
    invites: Vec<InviteOut<'a>>,
}

#[derive(Serialize)]
struct InviteOut<'a> {
    env: &'a str,
    invite: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIn {
    v: u32,
    service: String,
    link_token: SecretString,
    peer: String,
    name: String,
    invites: Vec<InviteIn>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteIn {
    env: String,
    invite: SecretString,
}

fn malformed() -> AppError {
    AppError::invalid_input("pairing_code_malformed")
}

/// `project/environment` with both parts in the CLI's name rule.
pub fn split_env(env: &str) -> Option<(&str, &str)> {
    let (project, environment) = env.split_once('/')?;
    (is_project_name(project) && is_project_name(environment)).then_some((project, environment))
}

/// An invitation as `team invite` prints it (lowercase or uppercase base32), or wrapped in a
/// `zeropw://join#` link. The CLI checks it fully.
fn is_invite_text(text: &str) -> bool {
    let body = text
        .get(..14)
        .filter(|head| head.eq_ignore_ascii_case("zeropw://join#"))
        .map_or(text, |_| &text[14..]);
    !body.is_empty()
        && text.len() <= MAX_INVITE_CHARS
        && body
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'2'..=b'7'))
}

impl PairingCode {
    fn check(&self) -> Result<(), AppError> {
        if check_service_url(&self.service).ok().as_deref() != Some(self.service.as_str())
            || !is_link_token(self.link_token.expose())
            || !is_device_id(&self.peer)
            || check_display_name(&self.name).ok().as_deref() != Some(self.name.as_str())
            || self.invites.is_empty()
            || self.invites.len() > MAX_INVITES
        {
            return Err(malformed());
        }
        let mut seen = std::collections::BTreeSet::new();
        for invite in &self.invites {
            if split_env(&invite.env).is_none()
                || !seen.insert(invite.env.as_str())
                || !is_invite_text(invite.invite.expose())
            {
                return Err(malformed());
            }
        }
        Ok(())
    }

    /// The code text, in a wiped buffer.
    pub fn encode(&self) -> Result<SecretString, AppError> {
        self.check()
            .map_err(|_| AppError::internal("pairing_code_invalid"))?;
        let wire = WireOut {
            v: 1,
            service: &self.service,
            link_token: self.link_token.expose(),
            peer: &self.peer,
            name: &self.name,
            invites: self
                .invites
                .iter()
                .map(|i| InviteOut {
                    env: &i.env,
                    invite: i.invite.expose(),
                })
                .collect(),
        };
        let mut json = Zeroizing::new(Vec::with_capacity(1024));
        serde_json::to_writer(&mut *json, &wire)
            .map_err(|_| AppError::internal("pairing_encode_failed"))?;
        let mut text = Zeroizing::new(String::with_capacity(PREFIX.len() + json.len() * 4 / 3 + 4));
        text.push_str(PREFIX);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_string(&*json, &mut text);
        if text.len() > MAX_CODE_CHARS {
            return Err(AppError::invalid_input("pairing_too_many_environments"));
        }
        Ok(SecretString::new(std::mem::take(&mut *text)))
    }

    /// Parse a pasted code. Surrounding whitespace is ignored; `zeropw://pair/#` is accepted and
    /// the scheme and host are case-insensitive. Every failure is `pairing_code_malformed`
    /// (or `pairing_code_too_long`) without echoing the input.
    pub fn decode(text: &str) -> Result<Self, AppError> {
        let text = text.trim();
        if text.len() > MAX_CODE_CHARS {
            return Err(AppError::invalid_input("pairing_code_too_long"));
        }
        let head = text.get(..13).ok_or_else(malformed)?;
        if !head.eq_ignore_ascii_case("zeropw://pair") {
            return Err(malformed());
        }
        let rest = &text[13..];
        let payload = rest
            .strip_prefix('#')
            .or_else(|| rest.strip_prefix("/#"))
            .ok_or_else(malformed)?;
        if payload.is_empty()
            || !payload
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(malformed());
        }
        let json = Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .map_err(|_| malformed())?,
        );
        let wire: WireIn = serde_json::from_slice(&json).map_err(|_| malformed())?;
        if wire.v != 1 {
            return Err(AppError::invalid_input("pairing_code_version"));
        }
        let code = PairingCode {
            service: wire.service,
            link_token: wire.link_token,
            peer: wire.peer,
            name: wire.name,
            invites: wire
                .invites
                .into_iter()
                .map(|i| PairInvite {
                    env: i.env,
                    invite: i.invite,
                })
                .collect(),
        };
        code.check()?;
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "abcdefghijklmnopqrstuvwxyz";

    fn sample(invites: usize) -> PairingCode {
        PairingCode {
            service: "https://link.example.org".into(),
            link_token: "zplt_synthetic_token_0123".into(),
            peer: PEER.into(),
            name: "studio mac".into(),
            invites: (0..invites)
                .map(|i| PairInvite {
                    env: format!("demo/env{i}"),
                    invite: SecretString::from("syntheticinvitezzzz".repeat(4).as_str()),
                })
                .collect(),
        }
    }

    fn wire(value: serde_json::Value) -> String {
        format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&value).unwrap())
        )
    }

    #[test]
    fn a_code_round_trips() {
        let text = sample(2).encode().unwrap();
        assert!(text.expose().starts_with(PREFIX));
        assert!(!text.expose().contains('='));
        let back = PairingCode::decode(&format!("  {}\n", text.expose())).unwrap();
        assert_eq!(back.service, "https://link.example.org");
        assert_eq!(back.link_token.expose(), "zplt_synthetic_token_0123");
        assert_eq!(back.peer, PEER);
        assert_eq!(back.name, "studio mac");
        assert_eq!(back.invites.len(), 2);
        assert_eq!(back.invites[1].env, "demo/env1");
        // scheme and host in any case, and the slash form
        let upper = text
            .expose()
            .replacen("zeropw://pair#", "ZeroPW://PAIR/#", 1);
        assert!(PairingCode::decode(&upper).is_ok());
    }

    #[test]
    fn malformed_codes_are_refused_without_echo() {
        let good = serde_json::json!({
            "v": 1, "service": "https://link.example.org", "link_token": "zplt_synthetic",
            "peer": PEER, "name": "mac", "invites": [{"env": "demo/dev", "invite": "syntheticinvitezz"}]
        });
        assert!(PairingCode::decode(&wire(good.clone())).is_ok());
        let mut cases: Vec<String> = vec![
            String::new(),
            "zeropw://join#abcdef".into(),
            "zeropw://pair".into(),
            "zeropw://pair#".into(),
            "zeropw://pair?x#abc".into(),
            format!("{PREFIX}not base64!"),
            format!("{PREFIX}{}=", &wire(good.clone())[PREFIX.len()..]),
            format!("{PREFIX}e30"), // {}
        ];
        let mutate = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v = good.clone();
            f(&mut v);
            wire(v)
        };
        cases.push(mutate(&|v| v["extra"] = serde_json::json!(1)));
        cases.push(mutate(&|v| {
            v["service"] = serde_json::json!("http://link.example.org")
        }));
        cases.push(mutate(&|v| {
            v["service"] = serde_json::json!("https://link.example.org/x")
        }));
        cases.push(mutate(&|v| {
            v["peer"] = serde_json::json!("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        }));
        cases.push(mutate(&|v| v["name"] = serde_json::json!("a\u{1b}b")));
        cases.push(mutate(&|v| v["name"] = serde_json::json!("")));
        cases.push(mutate(&|v| {
            v["link_token"] = serde_json::json!("has space")
        }));
        cases.push(mutate(&|v| v["invites"] = serde_json::json!([])));
        cases.push(mutate(&|v| {
            v["invites"][0]["env"] = serde_json::json!("Demo/dev")
        }));
        cases.push(mutate(&|v| {
            v["invites"][0]["env"] = serde_json::json!("demo")
        }));
        cases.push(mutate(&|v| {
            v["invites"][0]["invite"] = serde_json::json!("not-base32!")
        }));
        cases.push(mutate(&|v| {
            v["invites"][0]["extra"] = serde_json::json!(true)
        }));
        cases.push(mutate(&|v| {
            v["invites"] = serde_json::json!([
                {"env": "demo/dev", "invite": "syntheticinvitezz"},
                {"env": "demo/dev", "invite": "syntheticinviteyy"}
            ])
        }));
        cases.push(mutate(&|v| {
            v["invites"] = serde_json::Value::Array(
                (0..=MAX_INVITES)
                    .map(|i| serde_json::json!({"env": format!("demo/e{i}"), "invite": "syntheticinvitezz"}))
                    .collect(),
            )
        }));
        for case in &cases {
            let err = PairingCode::decode(case).err().expect(case);
            assert!(
                err.reason.starts_with("pairing_code_"),
                "{case}: {}",
                err.reason
            );
            assert!(err.detail.is_none());
            assert!(!err.to_string().contains("synthetic"));
        }
        let v2 = mutate(&|v| v["v"] = serde_json::json!(2));
        assert_eq!(
            PairingCode::decode(&v2).err().unwrap().reason,
            "pairing_code_version"
        );
        let long = format!("{PREFIX}{}", "a".repeat(MAX_CODE_CHARS));
        assert_eq!(
            PairingCode::decode(&long).err().unwrap().reason,
            "pairing_code_too_long"
        );
    }

    #[test]
    fn invitations_may_be_links_and_env_names_split() {
        assert!(is_invite_text("zeropw://join#abcdefgh"));
        assert!(is_invite_text("ABCDEFGH234567"));
        assert!(!is_invite_text("zeropw://join#"));
        assert!(!is_invite_text("abc def"));
        assert_eq!(split_env("demo/dev"), Some(("demo", "dev")));
        assert_eq!(split_env("demo/dev/x"), None);
        assert_eq!(split_env("-x/dev"), None);
    }
}
