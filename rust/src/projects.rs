//! Port of `zeropw/projects.py`: project and environment registry (dev /
//! staging / prod separation).

use serde_json::{Map, Value, json};

use crate::errors::Error;
use crate::store::{StateDir, iso};

pub const DOC: &str = "projects.json";
pub const DEFAULT_ENVIRONMENTS: &[&str] = &["dev", "staging", "prod"];

/// `projects.NAME_RE`: `^[a-z0-9][a-z0-9._-]{0,63}$`, checked by hand (no
/// `regex` dependency needed for a pattern this small, and it keeps the
/// character classes trivially auditable against the Python source).
///
/// Python's `$` (no `re.MULTILINE`) matches either at the end of the string,
/// or immediately before a single `'\n'` that is the very last character --
/// so `NAME_RE.match("abc\n")` succeeds (matching `"abc"`, with the trailing
/// `\n` left over but a `.match()` call doesn't require consuming the whole
/// string). `"abc\n\n"` does *not* match: only the single newline
/// immediately at the end gets this exemption, and there is no way for the
/// tail character class (which excludes `\n`) to reach the second-to-last
/// position. Concretely: strip at most one trailing `'\n'` and require the
/// remainder to match `^[a-z0-9][a-z0-9._-]{0,63}$` exactly.
fn matches_name_re(value: &str) -> bool {
    let core = value.strip_suffix('\n').unwrap_or(value);
    let bytes = core.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    fn is_head(b: u8) -> bool {
        b.is_ascii_lowercase() || b.is_ascii_digit()
    }
    fn is_tail(b: u8) -> bool {
        is_head(b) || b == b'.' || b == b'_' || b == b'-'
    }
    is_head(bytes[0]) && bytes[1..].iter().all(|&b| is_tail(b))
}

/// `projects.validate_name`.
pub fn validate_name(value: &str, what: &str) -> Result<String, Error> {
    if !matches_name_re(value) {
        return Err(Error::invalid_input(format!("invalid_{what}")));
    }
    Ok(value.to_string())
}

/// `projects.Project`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Project {
    pub name: String,
    pub environments: Vec<String>,
    pub created_at: String,
}

/// `projects.Projects`.
pub struct Projects<'a> {
    state: &'a StateDir,
}

impl<'a> Projects<'a> {
    pub fn new(state: &'a StateDir) -> Self {
        Projects { state }
    }

    fn load(&self) -> Result<Map<String, Value>, Error> {
        match self.state.read_json(DOC, json!({}))? {
            Value::Object(map) => Ok(map),
            Value::Null => Ok(Map::new()),
            _ => Ok(Map::new()), // `doc or {}` in Python: any falsy load becomes {}
        }
    }

    /// `Projects.create`. `environments` defaults to
    /// [`DEFAULT_ENVIRONMENTS`] like Python's `DEFAULT_ENVIRONMENTS`.
    pub fn create(&self, name: &str, environments: &[&str]) -> Result<Project, Error> {
        let name = validate_name(name, "project")?;
        let mut envs = Vec::with_capacity(environments.len());
        for e in environments {
            envs.push(validate_name(e, "environment")?);
        }
        if envs.is_empty() {
            return Err(Error::invalid_input("no_environments"));
        }
        let _lock = self.state.lock()?;
        let mut doc = self.load()?;
        if doc.contains_key(&name) {
            return Err(Error::invalid_input("project_exists"));
        }
        let created_at = iso(None);
        doc.insert(
            name.clone(),
            json!({"environments": envs.clone(), "created_at": created_at.clone()}),
        );
        self.state.write_json(DOC, &Value::Object(doc))?;
        Ok(Project {
            name,
            environments: envs,
            created_at,
        })
    }

    /// `Projects.get`.
    pub fn get(&self, name: &str) -> Result<Project, Error> {
        let doc = self.load()?;
        let entry = doc
            .get(name)
            .ok_or_else(|| Error::not_found("project_not_found"))?;
        project_from_entry(name, entry)
    }

    /// `Projects.require_environment`.
    pub fn require_environment(&self, project: &str, environment: &str) -> Result<(), Error> {
        let entry = self.get(project)?;
        if !entry.environments.iter().any(|e| e == environment) {
            return Err(Error::not_found("environment_not_found"));
        }
        Ok(())
    }

    /// `Projects.list`.
    pub fn list(&self) -> Result<Vec<Project>, Error> {
        let doc = self.load()?;
        let mut names: Vec<&String> = doc.keys().collect();
        names.sort();
        names
            .into_iter()
            .map(|n| project_from_entry(n, &doc[n]))
            .collect()
    }
}

fn project_from_entry(name: &str, entry: &Value) -> Result<Project, Error> {
    let environments = entry
        .get("environments")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::state("state_corrupt").with_detail(DOC))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| Error::state("state_corrupt").with_detail(DOC))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let created_at = entry
        .get("created_at")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::state("state_corrupt").with_detail(DOC))?
        .to_string();
    Ok(Project {
        name: name.to_string(),
        environments,
        created_at,
    })
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::errors::ErrorClass;

    fn new_state() -> (TempDir, StateDir) {
        let tmp = TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        state.create().unwrap();
        (tmp, state)
    }

    #[test]
    fn validate_name_accepts_and_rejects() {
        assert!(validate_name("gh", "project").is_ok());
        assert!(validate_name("a1._-z", "project").is_ok());
        assert!(validate_name(&"a".repeat(64), "project").is_ok());
        assert!(validate_name(&"a".repeat(65), "project").is_err());
        assert!(validate_name("", "project").is_err());
        assert!(validate_name("Gh", "project").is_err()); // uppercase not allowed
        assert!(validate_name("-gh", "project").is_err()); // must start alnum
        assert!(validate_name("g h", "project").is_err());
        let err = validate_name("Gh", "project").unwrap_err();
        assert!(err.is(ErrorClass::InvalidInput));
        assert_eq!(err.reason, "invalid_project");
        let err = validate_name("Gh", "environment").unwrap_err();
        assert_eq!(err.reason, "invalid_environment");
    }

    #[test]
    fn create_defaults_to_dev_staging_prod() {
        let (_tmp, state) = new_state();
        let projects = Projects::new(&state);
        let p = projects.create("acme", DEFAULT_ENVIRONMENTS).unwrap();
        assert_eq!(p.name, "acme");
        assert_eq!(p.environments, vec!["dev", "staging", "prod"]);
        assert!(!p.created_at.is_empty());
    }

    #[test]
    fn create_rejects_duplicate_and_empty_environments() {
        let (_tmp, state) = new_state();
        let projects = Projects::new(&state);
        projects.create("acme", &["dev"]).unwrap();
        let err = projects.create("acme", &["dev"]).unwrap_err();
        assert_eq!(err.reason, "project_exists");
        let err = projects.create("other", &[]).unwrap_err();
        assert_eq!(err.reason, "no_environments");
    }

    #[test]
    fn create_rejects_invalid_names() {
        let (_tmp, state) = new_state();
        let projects = Projects::new(&state);
        assert!(projects.create("Bad", &["dev"]).is_err());
        assert!(projects.create("ok", &["Bad"]).is_err());
    }

    #[test]
    fn get_missing_is_not_found() {
        let (_tmp, state) = new_state();
        let projects = Projects::new(&state);
        let err = projects.get("nope").unwrap_err();
        assert!(err.is(ErrorClass::NotFound));
        assert_eq!(err.reason, "project_not_found");
    }

    #[test]
    fn require_environment_checks_membership() {
        let (_tmp, state) = new_state();
        let projects = Projects::new(&state);
        projects.create("acme", &["dev", "prod"]).unwrap();
        assert!(projects.require_environment("acme", "dev").is_ok());
        let err = projects.require_environment("acme", "staging").unwrap_err();
        assert_eq!(err.reason, "environment_not_found");
        let err = projects.require_environment("nope", "dev").unwrap_err();
        assert_eq!(err.reason, "project_not_found");
    }

    #[test]
    fn list_is_sorted_by_name() {
        let (_tmp, state) = new_state();
        let projects = Projects::new(&state);
        projects.create("zeta", &["dev"]).unwrap();
        projects.create("alpha", &["dev"]).unwrap();
        projects.create("mid", &["dev"]).unwrap();
        let names: Vec<_> = projects
            .list()
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(names, vec!["alpha", "mid", "zeta"]);
    }

    #[test]
    fn list_on_empty_store_is_empty() {
        let (_tmp, state) = new_state();
        let projects = Projects::new(&state);
        assert_eq!(projects.list().unwrap(), Vec::new());
    }

    // A-3: Python's `NAME_RE.match(value)` accepts exactly one trailing
    // `"\n"` (a quirk of `$` without `re.MULTILINE`) and returns the
    // *original* string, newline included.
    #[test]
    fn validate_name_accepts_exactly_one_trailing_newline() {
        let ok = validate_name("abc\n", "project").unwrap();
        assert_eq!(ok, "abc\n", "must return the original string unmodified");

        assert!(validate_name("abc\n\n", "project").is_err());
        assert!(validate_name("\nabc", "project").is_err());
        assert!(validate_name("a\nb", "project").is_err());
        assert!(validate_name("\n", "project").is_err());

        let name64 = "a".repeat(64);
        assert!(validate_name(&name64, "project").is_ok());
        let name64_nl = format!("{name64}\n");
        assert_eq!(validate_name(&name64_nl, "project").unwrap(), name64_nl);

        let name65 = "a".repeat(65);
        assert!(validate_name(&name65, "project").is_err());
        let name65_nl = format!("{name65}\n");
        assert!(validate_name(&name65_nl, "project").is_err());
    }
}

/// Differential tests against the CPython oracle.
#[cfg(test)]
mod oracle_tests {
    use super::*;
    use crate::oracle;

    // A-3: table-tests `NAME_RE.match(...)` (the exact regex source, run
    // through CPython) against `matches_name_re` for every case the
    // reviewer flagged, plus the 64/65-char boundary with and without a
    // trailing newline.
    #[test]
    fn validate_name_matches_python_name_re_table() {
        let name64 = "a".repeat(64);
        let name65 = "a".repeat(65);
        let cases: Vec<String> = vec![
            "abc".to_string(),
            "abc\n".to_string(),
            "abc\n\n".to_string(),
            "\nabc".to_string(),
            "a\nb".to_string(),
            "\n".to_string(),
            "".to_string(),
            name64.clone(),
            format!("{name64}\n"),
            format!("{name64}\n\n"),
            name65.clone(),
            format!("{name65}\n"),
        ];
        let script = format!(
            r#"
import re
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{{0,63}}$")
cases = {cases:?}
for c in cases:
    print("MATCH" if NAME_RE.match(c) else "NOMATCH")
"#
        );
        let out = oracle::python(&script);
        let want: Vec<&str> = out.lines().collect();
        assert_eq!(want.len(), cases.len());
        for (case, expected) in cases.iter().zip(want.iter()) {
            let got = if matches_name_re(case) {
                "MATCH"
            } else {
                "NOMATCH"
            };
            assert_eq!(got, *expected, "mismatch for case {case:?}");
        }
    }
}
