//! macOS SystemConfiguration proxy settings used by `urllib.request`.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::net::Ipv4Addr;
use std::sync::OnceLock;

use num_bigint::BigUint;
use plist::{Dictionary, Value};
use regex::Regex;
use system_configuration::core_foundation::base::TCFType;
use system_configuration::core_foundation::propertylist::{
    create_data, kCFPropertyListBinaryFormat_v1_0,
};
use system_configuration::dynamic_store::SCDynamicStoreBuilder;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MacProxySettings {
    pub(crate) proxies: BTreeMap<String, String>,
    pub(crate) exclude_simple: bool,
    pub(crate) exceptions: Vec<String>,
}

/// The same normalized dictionary CPython's `_scproxy` receives from
/// `SCDynamicStoreCopyProxies`. The framework call and CF ownership are
/// contained by safe dependency APIs; plist serialization preserves the
/// heterogeneous dictionary without raw-pointer casts in this crate.
pub(crate) fn load() -> Option<MacProxySettings> {
    let store = SCDynamicStoreBuilder::new("ZeroPW agent proxy lookup").build()?;
    let dictionary = store.get_proxies()?;
    let Ok(data) = create_data(dictionary.as_CFTypeRef(), kCFPropertyListBinaryFormat_v1_0) else {
        return None;
    };
    let Ok(value) = Value::from_reader(Cursor::new(data.bytes())) else {
        return None;
    };
    value.as_dictionary().map(from_normalized_dictionary)
}

fn int32(value: &Value) -> Option<i32> {
    value
        .as_signed_integer()
        .and_then(|value| i32::try_from(value).ok())
        .or_else(|| {
            value
                .as_unsigned_integer()
                .and_then(|value| i32::try_from(value).ok())
        })
        .or_else(|| {
            let value = value.as_real()?;
            (value.is_finite()
                && value.fract() == 0.0
                && value >= f64::from(i32::MIN)
                && value <= f64::from(i32::MAX))
            .then_some(value as i32)
        })
}

pub(crate) fn from_normalized_dictionary(dictionary: &Dictionary) -> MacProxySettings {
    let mut settings = MacProxySettings::default();
    for (scheme, enabled, host, port) in [
        ("http", "HTTPEnable", "HTTPProxy", "HTTPPort"),
        ("https", "HTTPSEnable", "HTTPSProxy", "HTTPSPort"),
        ("ftp", "FTPEnable", "FTPProxy", "FTPPort"),
        ("gopher", "GopherEnable", "GopherProxy", "GopherPort"),
        ("socks", "SOCKSEnable", "SOCKSProxy", "SOCKSPort"),
    ] {
        if dictionary.get(enabled).and_then(int32).unwrap_or(0) == 0 {
            continue;
        }
        let Some(host) = dictionary.get(host).and_then(Value::as_string) else {
            continue;
        };
        let proxy = match dictionary.get(port).and_then(int32) {
            Some(port) => format!("http://{host}:{port}"),
            None => format!("http://{host}"),
        };
        settings.proxies.insert(scheme.to_owned(), proxy);
    }
    settings.exclude_simple = dictionary
        .get("ExcludeSimpleHostnames")
        .and_then(int32)
        .is_some_and(|value| value != 0);
    settings.exceptions = dictionary
        .get("ExceptionsList")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_string)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    settings
}

fn split_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((head, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => head,
        _ => host,
    }
}

fn decimal_biguint(value: &str) -> Option<BigUint> {
    crate::pystr::int_from_str_decimal(value)?.parse().ok()
}

fn exception_ip(value: &str) -> Option<(&str, Option<BigUint>)> {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let captures = PATTERN
        .get_or_init(|| Regex::new(r"^(\d+(?:\.\d+)*)(?:/(\d+))?").unwrap())
        .captures(value)?;
    let address = captures.get(1)?.as_str();
    let mask = captures
        .get(2)
        .and_then(|value| decimal_biguint(value.as_str()));
    Some((address, mask))
}

fn abbreviated_ipv4(value: &str) -> Option<BigUint> {
    let mut parts: Vec<BigUint> = value
        .split('.')
        .map(decimal_biguint)
        .collect::<Option<_>>()?;
    if parts.len() != 4 {
        parts.resize(4, BigUint::from(0u8));
        parts.truncate(4);
    }
    Some((&parts[0] << 24usize) | (&parts[1] << 16usize) | (&parts[2] << 8usize) | &parts[3])
}

/// Python 3.12 `fnmatch.fnmatch` on POSIX. Regex translation is sufficient
/// here because atomic groups in CPython's translator only constrain
/// backtracking performance, not the accepted language.
fn fnmatch(name: &str, pattern: &str) -> bool {
    let mut translated = String::from("(?s:");
    let chars: Vec<char> = pattern.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        index += 1;
        match c {
            '*' => {
                if !translated.ends_with(".*") {
                    translated.push_str(".*");
                }
            }
            '?' => translated.push('.'),
            '[' => {
                let start = index;
                let mut end = index;
                if end < chars.len() && chars[end] == '!' {
                    end += 1;
                }
                if end < chars.len() && chars[end] == ']' {
                    end += 1;
                }
                while end < chars.len() && chars[end] != ']' {
                    end += 1;
                }
                if end == chars.len() {
                    translated.push_str(r"\[");
                    continue;
                }
                let mut stuff: String;
                if !chars[start..end].contains(&'-') {
                    stuff = chars[start..end]
                        .iter()
                        .collect::<String>()
                        .replace('\\', r"\\");
                } else {
                    let mut chunks: Vec<Vec<char>> = Vec::new();
                    let mut chunk_start = start;
                    let mut search = start + if chars.get(start) == Some(&'!') { 2 } else { 1 };
                    while let Some(offset) = chars[search.min(end)..end]
                        .iter()
                        .position(|character| *character == '-')
                    {
                        let hyphen = search.min(end) + offset;
                        chunks.push(chars[chunk_start..hyphen].to_vec());
                        chunk_start = hyphen + 1;
                        search = hyphen.saturating_add(3);
                    }
                    let tail = chars[chunk_start..end].to_vec();
                    if tail.is_empty() {
                        if let Some(last) = chunks.last_mut() {
                            last.push('-');
                        }
                    } else {
                        chunks.push(tail);
                    }
                    for current in (1..chunks.len()).rev() {
                        if chunks[current - 1].last() > chunks[current].first() {
                            let mut merged =
                                chunks[current - 1][..chunks[current - 1].len() - 1].to_vec();
                            merged.extend_from_slice(&chunks[current][1..]);
                            chunks[current - 1] = merged;
                            chunks.remove(current);
                        }
                    }
                    stuff = chunks
                        .iter()
                        .map(|chunk| {
                            chunk
                                .iter()
                                .collect::<String>()
                                .replace('\\', r"\\")
                                .replace('-', r"\-")
                        })
                        .collect::<Vec<_>>()
                        .join("-");
                }
                index = end + 1;
                if stuff.is_empty() {
                    translated.push_str(r"[^\s\S]");
                } else if stuff == "!" {
                    translated.push('.');
                } else {
                    if stuff.starts_with('!') {
                        stuff.replace_range(..1, "^");
                    } else if matches!(stuff.chars().next(), Some('^' | '[')) {
                        stuff.insert(0, '\\');
                    }
                    translated.push('[');
                    translated.push_str(&stuff);
                    translated.push(']');
                }
            }
            _ => translated.push_str(&regex::escape(&c.to_string())),
        }
    }
    translated.push_str(r")\z");
    Regex::new(&translated).is_ok_and(|regex| regex.is_match(name))
}

pub(crate) fn proxy_bypass(host: &str, settings: &MacProxySettings) -> bool {
    let hostonly = split_port(host);
    if !host.contains('.') && settings.exclude_simple {
        return true;
    }
    let host_ip = hostonly.parse::<Ipv4Addr>().ok().map(u32::from);
    for value in &settings.exceptions {
        if value.is_empty() {
            continue;
        }
        if let (Some(host_ip), Some((base, mask))) = (host_ip, exception_ip(value)) {
            let mask =
                mask.unwrap_or_else(|| BigUint::from(8usize * (base.matches('.').count() + 1)));
            if mask > BigUint::from(32u8) {
                continue;
            }
            let mask: u32 = mask.to_string().parse().unwrap_or(33);
            let shift = 32 - mask;
            if abbreviated_ipv4(base)
                .is_some_and(|base| BigUint::from(host_ip >> shift) == (base >> shift as usize))
            {
                return true;
            }
        } else if fnmatch(host, value) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn value_dictionary(entries: &[(&str, Value)]) -> Dictionary {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect()
    }

    #[test]
    fn normalized_snapshot_converts_like_scproxy() {
        let dictionary = value_dictionary(&[
            ("HTTPEnable", 1i64.into()),
            ("HTTPProxy", "proxy.example".into()),
            ("HTTPPort", 80i64.into()),
            ("HTTPSEnable", 1i64.into()),
            ("HTTPSProxy", "secure.example".into()),
            ("HTTPSPort", 443i64.into()),
            ("SOCKSEnable", 0i64.into()),
            ("SOCKSProxy", "removed-by-normalization.example".into()),
            ("SOCKSPort", 1080i64.into()),
            ("ExcludeSimpleHostnames", 2i64.into()),
            (
                "ExceptionsList",
                vec![Value::from("*.local"), Value::from("10.0/16")].into(),
            ),
        ]);
        let settings = from_normalized_dictionary(&dictionary);
        assert_eq!(
            settings.proxies,
            BTreeMap::from([
                ("http".to_owned(), "http://proxy.example:80".to_owned()),
                ("https".to_owned(), "http://secure.example:443".to_owned()),
            ])
        );
        assert!(settings.exclude_simple);
        assert_eq!(settings.exceptions, ["*.local", "10.0/16"]);
    }

    #[test]
    fn bypass_patterns_match_urllib_oracle() {
        let settings = MacProxySettings {
            proxies: BTreeMap::new(),
            exclude_simple: true,
            exceptions: vec![
                "*.local".into(),
                "EXACT.example".into(),
                "10.1".into(),
                "172.16/12".into(),
                "١٩٨.٥١.١٠٠/٢٤".into(),
                "192.0.2.0/33".into(),
                "host?.example".into(),
                "node[0-3].example".into(),
                "node[!0-3].example".into(),
                "literal[.example".into(),
            ],
        };
        let hosts = [
            "printer",
            "a.local",
            "A.LOCAL",
            "EXACT.example",
            "exact.example",
            "10.1.2.3",
            "172.31.255.1:443",
            "198.51.100.42",
            "192.0.2.1",
            "host1.example",
            "node2.example",
            "node8.example",
            "literal[.example",
            "other.example",
        ];
        let settings_json = serde_json::to_string(&json!({
            "exclude_simple": settings.exclude_simple,
            "exceptions": &settings.exceptions,
        }))
        .unwrap();
        let hosts_json = serde_json::to_string(&hosts).unwrap();
        let script = format!(
            "import json, urllib.request\nsettings = json.loads({})\nfor host in json.loads({}):\n print(json.dumps(urllib.request._proxy_bypass_macosx_sysconf(host, settings)))\n",
            serde_json::to_string(&settings_json).unwrap(),
            serde_json::to_string(&hosts_json).unwrap(),
        );
        let expected = crate::oracle::python(&script);
        for (host, expected) in hosts.iter().zip(expected.lines()) {
            assert_eq!(
                proxy_bypass(host, &settings),
                expected == "true",
                "proxy_bypass({host:?})"
            );
        }
    }

    #[test]
    fn live_systemconfiguration_snapshot_matches_scproxy() {
        let expected: serde_json::Value = serde_json::from_str(
            crate::oracle::python(
                "import json, _scproxy\nsettings = _scproxy._get_proxy_settings()\nprint(json.dumps({'proxies': _scproxy._get_proxies(), 'exclude_simple': False if settings is None else settings['exclude_simple'], 'exceptions': [] if settings is None else list(settings.get('exceptions', ()))}, sort_keys=True))\n",
            )
            .trim(),
        )
        .unwrap();
        let actual = load().expect("SystemConfiguration proxy snapshot");
        assert_eq!(
            json!({
                "proxies": actual.proxies,
                "exclude_simple": actual.exclude_simple,
                "exceptions": actual.exceptions,
            }),
            expected
        );
    }
}
