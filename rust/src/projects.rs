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
    pub environments: Vec<Value>,
    pub created_at: Value,
}

/// `projects.Projects`.
pub struct Projects<'a> {
    state: &'a StateDir,
}

/// Result of [`Projects::load_raw`]: either the parsed document map (a
/// present JSON object, or the empty-document substitute for any falsy
/// value), or a truthy non-object value preserved as-is so `create` can
/// reproduce Python's `if name in doc` on it (finding A-R7-1).
enum LoadedDoc {
    Object(Map<String, Value>),
    NonObject(Value),
}

impl<'a> Projects<'a> {
    pub fn new(state: &'a StateDir) -> Self {
        Projects { state }
    }

    /// `Projects._load`: `self.state.read_json(DOC, {}) or {}`. Python's `or`
    /// only substitutes `{}` for a *falsy* loaded value (`None`, `False`,
    /// `0`/`0.0`, `""`, `[]`, `{}`) -- a *truthy* non-dict value (`[1]`,
    /// `"abc"`, `True`, a nonzero number) is returned as-is.
    ///
    /// `get`/`list` then always raise an uncaught `AttributeError` on a
    /// truthy non-dict document -- `doc.get(name)` and `sorted(doc.items())`
    /// have no equivalent on `str`/`list`/`bool`/`int` -- confirmed for
    /// every truthy shape by `python_oracle_confirms_load_get_create_edge_cases`.
    /// `state_corrupt` is the closest error either caller already handles
    /// (PORTING.md §3.5), so `load` (used only by `get`/`list`) collapses
    /// every truthy non-object into that error.
    ///
    /// **`create` is different (finding A-R7-1)**: its very next statement,
    /// `if name in doc`, runs *before* any dict-only operation. `in` is a
    /// **substring test** on a `str` document and a **membership test** on a
    /// `list` document, and neither raises -- measured: `"abc"` +
    /// `create("a")`, `"dev-prod-a"` + `create("prod")`, `["acme"]` +
    /// `create("acme")`, `["a","b"]` + `create("a")` all return
    /// `InvalidInput("project_exists")`, not a crash. Only when `name` is
    /// *not* contained does Python's `create` then fall through to the
    /// dict-only `doc[name] = ...` and raise an uncaught `TypeError`. `bool`/
    /// `int` documents raise `TypeError` from `in` itself ("argument of type
    /// 'bool'/'int' is not iterable"), unconditionally. `create` therefore
    /// cannot reuse this `load` helper: see `load_raw`/`create`'s own
    /// containment check below.
    fn load(&self) -> Result<Map<String, Value>, Error> {
        match self.load_raw()? {
            LoadedDoc::Object(map) => Ok(map),
            LoadedDoc::NonObject(_) => Err(escaped("AttributeError")),
        }
    }

    /// Like [`Self::load`] but preserves a truthy non-object document
    /// instead of collapsing it into `state_corrupt`, so `create` can
    /// reproduce Python's `if name in doc` substring/membership test on it
    /// (finding A-R7-1) before falling back to the same `state_corrupt` any
    /// other caller would hit.
    fn load_raw(&self) -> Result<LoadedDoc, Error> {
        let loaded = self.state.read_json(DOC, json!({}))?;
        if is_falsy(&loaded) {
            return Ok(LoadedDoc::Object(Map::new()));
        }
        match loaded {
            Value::Object(map) => Ok(LoadedDoc::Object(map)),
            other => Ok(LoadedDoc::NonObject(other)),
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
        let mut doc = match self.load_raw()? {
            LoadedDoc::Object(map) => map,
            // A-R7-1: `if name in doc` on a truthy non-dict document is a
            // substring test (`str`) or membership test (`list`) in Python,
            // and succeeds without raising -- `project_exists` fires before
            // any dict-only operation is attempted. Only when `name` is
            // *not* contained does Python fall through to `doc[name] = ...`
            // and hit the uncaught `TypeError` (str/list don't support
            // string-keyed assignment), which this port reports as the
            // closest documented error (`state_corrupt`, PORTING.md §3.5).
            LoadedDoc::NonObject(Value::String(s)) => {
                if s.contains(name.as_str()) {
                    return Err(Error::invalid_input("project_exists"));
                }
                return Err(escaped("TypeError"));
            }
            LoadedDoc::NonObject(Value::Array(items)) => {
                let contained = items.iter().any(|item| match item {
                    Value::String(s) => *s == name,
                    _ => false,
                });
                if contained {
                    return Err(Error::invalid_input("project_exists"));
                }
                return Err(escaped("TypeError"));
            }
            // `bool`/number documents: Python's `in` itself raises
            // `TypeError` ("argument of type 'bool'/'int' is not
            // iterable"), unconditionally -- no substring/membership test
            // is even attempted.
            LoadedDoc::NonObject(_) => return Err(escaped("TypeError")),
        };
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
            environments: envs.into_iter().map(Value::String).collect(),
            created_at: Value::String(created_at),
        })
    }

    /// `Projects.get`: `entry = doc.get(name); if entry is None: raise
    /// NotFound(...)`. Python's `dict.get` returns the stored value for a
    /// present key, so a JSON `null` entry (`entry is None`) is
    /// indistinguishable from a missing key -- both raise
    /// `NotFound("project_not_found")`. A-R2-6(a): the previous port only
    /// checked key presence, so a `null` entry fell through to
    /// `project_from_entry` and came back `state_corrupt` instead.
    pub fn get(&self, name: &str) -> Result<Project, Error> {
        let doc = self.load()?;
        match doc.get(name) {
            None | Some(Value::Null) => Err(Error::not_found("project_not_found")),
            Some(entry) => project_from_entry(name, entry),
        }
    }

    /// `Projects.require_environment`.
    pub fn require_environment(&self, project: &str, environment: &str) -> Result<(), Error> {
        self.require_environment_value(&json!(project), &json!(environment))
    }

    /// `Projects.require_environment` for stored JSON arguments (a vault
    /// entry's raw `project`/`environment`). `doc.get(project)` finds only a
    /// `str` key, raises `TypeError` for an unhashable list/dict, and returns
    /// `None` (`project_not_found`) for any other value; `environment not in
    /// entry.environments` is tuple membership with Python `==`.
    pub fn require_environment_value(
        &self,
        project: &Value,
        environment: &Value,
    ) -> Result<(), Error> {
        let entry = match project {
            Value::String(name) => self.get(name)?,
            Value::Array(_) | Value::Object(_) => {
                self.load()?;
                return Err(escaped("TypeError"));
            }
            _ => {
                self.load()?;
                return Err(Error::not_found("project_not_found"));
            }
        };
        if !entry
            .environments
            .iter()
            .any(|e| crate::vault::python_eq(e, environment))
        {
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

/// A built-in exception `projects.py` lets escape on a malformed
/// `projects.json` (PORTING.md §3.5): `StateError("state_corrupt")` carrying
/// the Python exception class name, which is what the administrator CLI's
/// handler prints for it.
fn escaped(class: &'static str) -> Error {
    Error::state("state_corrupt").with_detail(class)
}

/// Python truthiness (`bool(value)`) for a JSON-decoded value, as
/// `Projects._load`'s `... or {}` applies it: `None`, `False`, any
/// zero-valued number (`0`, `0.0`, `-0.0`), an empty string, an empty array,
/// and an empty object are all falsy; everything else (including a
/// non-empty string/array/object, `True`, and any nonzero number) is
/// truthy.
fn is_falsy(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(b) => !*b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(m) => m.is_empty(),
    }
}

/// Builds a [`Project`] from a `projects.json` entry. A-R2-6(b): Python's
/// `Project(name, tuple(entry["environments"]), entry["created_at"])`
/// applies *no* type checking at all -- `tuple(...)` happily iterates a
/// string (`tuple("dev") == ('d', 'e', 'v')`), a list of non-string items
/// (`tuple([1, 2]) == (1, 2)`), or a dict (its keys); `created_at` is
/// whatever JSON value was stored (including `None`), assigned straight
/// through. It raises an uncaught `TypeError` only for a non-iterable
/// `environments` (a number, bool, or `null`), and an uncaught `KeyError`
/// for either field missing outright.
///
/// Iterable persisted shapes and arbitrary `created_at` JSON are retained,
/// including for native admin listing. Missing/non-iterable fields use the
/// existing fail-closed `state_corrupt` boundary (PORTING.md §3.5).
fn project_from_entry(name: &str, entry: &Value) -> Result<Project, Error> {
    // `entry["environments"]`: a non-dict entry cannot be subscripted (`TypeError`).
    let Value::Object(entry) = entry else {
        return Err(escaped("TypeError"));
    };
    let environments = match entry
        .get("environments")
        .ok_or_else(|| escaped("KeyError"))?
    {
        Value::Array(items) => items.clone(),
        Value::String(s) => s.chars().map(|c| Value::String(c.to_string())).collect(),
        Value::Object(map) => map.keys().cloned().map(Value::String).collect(),
        _ => return Err(escaped("TypeError")),
    };
    let created_at = entry
        .get("created_at")
        .ok_or_else(|| escaped("KeyError"))?
        .clone();
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
        assert!(!p.created_at.as_str().unwrap().is_empty());
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

    // A-R2-6(a): a JSON `null` entry is indistinguishable from a missing
    // key in Python's `doc.get(name)` -- both make `entry is None` true, so
    // `get` must report `project_not_found`, not `state_corrupt`.
    #[test]
    fn get_treats_null_entry_as_not_found() {
        let (_tmp, state) = new_state();
        state.write_json(DOC, &json!({"acme": null})).unwrap();
        let projects = Projects::new(&state);
        let err = projects.get("acme").unwrap_err();
        assert!(err.is(ErrorClass::NotFound));
        assert_eq!(err.reason, "project_not_found");
    }

    // A-R2-6(c): a truthy non-dict `projects.json` (a nonempty array, a
    // nonempty string, `true`, a nonzero number) must not be silently
    // treated as an empty document -- `get`/`list` always report
    // `state_corrupt` (Python's uncaught `AttributeError`). For `create`,
    // this specifically covers the *not-contained* case ("acme" is not a
    // substring of "abc", not an element of `[1]`, and `in` itself raises
    // for `true`/`7`), which still falls through to Python's uncaught
    // `TypeError` on `doc[name] = ...` -- `state_corrupt` here too, and the
    // file is left untouched. See `create_project_exists_on_truthy_non_dict_document_when_name_is_contained`
    // (finding A-R7-1, below) for the *contained* case, which Python
    // resolves as `InvalidInput("project_exists")` instead.
    #[test]
    fn truthy_non_dict_document_is_state_corrupt_and_create_does_not_overwrite() {
        let (_tmp, state) = new_state();
        let projects = Projects::new(&state);
        for corrupt in [json!([1]), json!("abc"), json!(true), json!(7)] {
            state.write_json(DOC, &corrupt).unwrap();

            let err = projects.get("acme").unwrap_err();
            assert!(err.is(ErrorClass::StateError), "get: {corrupt:?}");
            assert_eq!(err.reason, "state_corrupt", "get: {corrupt:?}");

            let err = projects.list().unwrap_err();
            assert!(err.is(ErrorClass::StateError), "list: {corrupt:?}");
            assert_eq!(err.reason, "state_corrupt", "list: {corrupt:?}");

            let err = projects.create("acme", &["dev"]).unwrap_err();
            assert!(err.is(ErrorClass::StateError), "create: {corrupt:?}");
            assert_eq!(err.reason, "state_corrupt", "create: {corrupt:?}");

            let on_disk = state.read_json(DOC, json!(null)).unwrap();
            assert_eq!(on_disk, corrupt, "create must leave the file untouched");
        }
    }

    // A-R7-1: `create`'s `if name in doc` is a *substring* test on a `str`
    // document and a *membership* test on a `list` document, both of which
    // succeed (without raising) when `name` IS contained -- Python then
    // raises the documented `InvalidInput("project_exists")`, never reaching
    // the dict-only `TypeError` the previous port assumed unconditionally.
    // Measured against real `python3.12`: `"abc"` + `create("a")`,
    // `"dev-prod-a"` + `create("prod")`, `["acme"]` + `create("acme")`,
    // `["a","b"]` + `create("a")` all return `InvalidInput("project_exists")`
    // and leave the file untouched (the error fires before `write_json`).
    #[test]
    fn create_project_exists_on_truthy_non_dict_document_when_name_is_contained() {
        let (_tmp, state) = new_state();
        let projects = Projects::new(&state);
        let cases: [(Value, &str); 5] = [
            (json!("abc"), "a"),
            (json!("dev-prod-a"), "prod"),
            (json!("zzz"), "z"),
            (json!(["acme"]), "acme"),
            (json!(["a", "b"]), "a"),
        ];
        for (doc, name) in cases {
            state.write_json(DOC, &doc).unwrap();

            let err = projects.create(name, &["dev"]).unwrap_err();
            assert!(
                err.is(ErrorClass::InvalidInput),
                "doc={doc:?} name={name:?}"
            );
            assert_eq!(err.reason, "project_exists", "doc={doc:?} name={name:?}");

            let on_disk = state.read_json(DOC, json!(null)).unwrap();
            assert_eq!(
                on_disk, doc,
                "create must leave the file untouched: doc={doc:?} name={name:?}"
            );
        }
    }

    // A-R7-1: a non-string array element never equals a string `name`
    // (Python's `==` between `str` and another type is `False`, not an
    // error), so it neither triggers `project_exists` nor blocks a *later*
    // matching string element from being found.
    #[test]
    fn create_array_document_ignores_non_string_elements_for_containment() {
        let (_tmp, state) = new_state();
        let projects = Projects::new(&state);

        // "5" (str) does not equal 5 (number) -> not contained -> falls
        // through to the not-contained TypeError-equivalent, state_corrupt.
        state.write_json(DOC, &json!(["a", 5])).unwrap();
        let err = projects.create("5", &["dev"]).unwrap_err();
        assert!(err.is(ErrorClass::StateError));
        assert_eq!(err.reason, "state_corrupt");

        // "a" (str) does equal the string element "a", even with an
        // unrelated non-string element also present.
        state.write_json(DOC, &json!(["a", 5])).unwrap();
        let err = projects.create("a", &["dev"]).unwrap_err();
        assert!(err.is(ErrorClass::InvalidInput));
        assert_eq!(err.reason, "project_exists");
    }

    // A-R2-6(c): every *falsy* non-dict value (`null`/`0`/`0.0`/`""`/`[]`/
    // `false`) must still be treated as an empty document, exactly like
    // Python's `doc or {}`.
    #[test]
    fn falsy_non_dict_document_is_treated_as_empty() {
        let (_tmp, state) = new_state();
        let projects = Projects::new(&state);
        for falsy in [
            json!(null),
            json!(0),
            json!(0.0),
            json!(""),
            json!([]),
            json!(false),
        ] {
            state.write_json(DOC, &falsy).unwrap();
            assert_eq!(projects.list().unwrap(), Vec::new(), "falsy: {falsy:?}");
            let err = projects.get("acme").unwrap_err();
            assert_eq!(err.reason, "project_not_found", "falsy: {falsy:?}");
        }
    }

    // Only non-iterable or missing `environments`, and missing `created_at`,
    // escape Python as built-in exceptions and fail closed here.
    #[test]
    fn noniterable_or_missing_project_fields_are_state_corrupt() {
        let (_tmp, state) = new_state();
        let projects = Projects::new(&state);
        let cases = [
            json!({"acme": {"environments": 5, "created_at": "2024-01-01T00:00:00Z"}}),
            json!({"acme": {"created_at": "2024-01-01T00:00:00Z"}}),
            json!({"acme": {"environments": ["dev"]}}),
        ];
        for doc in cases {
            state.write_json(DOC, &doc).unwrap();
            let err = projects.get("acme").unwrap_err();
            assert!(err.is(ErrorClass::StateError), "doc: {doc:?}");
            assert_eq!(err.reason, "state_corrupt", "doc: {doc:?}");
        }
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

/// Project-name validation against the prototype's
/// `NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")` matched with
/// `re.match`, whose `$` also matches before one trailing newline.
#[cfg(test)]
mod oracle_tests {
    use super::*;

    // A-3: every case the reviewer flagged, plus the 64/65-char boundary with
    // and without a trailing newline.
    #[test]
    fn validate_name_matches_the_name_re_table() {
        let name64 = "a".repeat(64);
        let name65 = "a".repeat(65);
        let cases: Vec<(String, bool)> = vec![
            ("abc".to_string(), true),
            ("abc\n".to_string(), true),
            ("abc\n\n".to_string(), false),
            ("\nabc".to_string(), false),
            ("a\nb".to_string(), false),
            ("\n".to_string(), false),
            ("".to_string(), false),
            (name64.clone(), true),
            (format!("{name64}\n"), true),
            (format!("{name64}\n\n"), false),
            (name65.clone(), false),
            (format!("{name65}\n"), false),
        ];
        for (case, expected) in &cases {
            assert_eq!(matches_name_re(case), *expected, "case {case:?}");
        }
    }
}
