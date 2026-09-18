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
            LoadedDoc::NonObject(_) => Err(state_corrupt()),
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
                return Err(state_corrupt());
            }
            LoadedDoc::NonObject(Value::Array(items)) => {
                let contained = items.iter().any(|item| match item {
                    Value::String(s) => *s == name,
                    _ => false,
                });
                if contained {
                    return Err(Error::invalid_input("project_exists"));
                }
                return Err(state_corrupt());
            }
            // `bool`/number documents: Python's `in` itself raises
            // `TypeError` ("argument of type 'bool'/'int' is not
            // iterable"), unconditionally -- no substring/membership test
            // is even attempted.
            LoadedDoc::NonObject(_) => return Err(state_corrupt()),
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
            environments: envs,
            created_at,
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

/// `state_corrupt` for a malformed `projects.json` document/entry, shared by
/// [`Projects::load`], [`Projects::get`], and [`project_from_entry`].
fn state_corrupt() -> Error {
    Error::state("state_corrupt").with_detail(DOC)
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
/// This port keeps requiring the exact expected JSON shape (`environments`:
/// array of strings; `created_at`: string) and returns `state_corrupt`
/// otherwise, for every one of those cases uniformly -- the same
/// strict-typing convention already used for every other state document in
/// this crate (`policy.rs`'s `Connection`/`Grant`/`Principal` loading,
/// `audit.rs`, `handles.rs`). PORTING.md §3.5 covers the non-iterable/
/// missing-key cases outright (an uncaught Python exception); the
/// loose-but-non-crashing cases (a string or wrong-typed list/dict that
/// Python *would* accept) are recorded in `rust/DEVIATIONS.md` under the
/// same reasoning: the only in-scope caller of `Project.environments`/
/// `.created_at` is `Projects.require_environment`'s membership test
/// (`environment not in entry.environments`), which does not care about
/// element types either way, and every writer in this crate only ever
/// produces well-typed documents, so this is unreachable for any state this
/// crate (or the Python prototype, on the matching write paths) produced
/// itself.
fn project_from_entry(name: &str, entry: &Value) -> Result<Project, Error> {
    let environments = entry
        .get("environments")
        .and_then(Value::as_array)
        .ok_or_else(state_corrupt)?
        .iter()
        .map(|v| v.as_str().map(str::to_string).ok_or_else(state_corrupt))
        .collect::<Result<Vec<_>, _>>()?;
    let created_at = entry
        .get("created_at")
        .and_then(Value::as_str)
        .ok_or_else(state_corrupt)?
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

    // A-R2-6(b): Python's `Project(name, tuple(entry["environments"]),
    // entry["created_at"])` performs no type checking at all (see
    // `rust/DEVIATIONS.md` for the full reasoning); this port instead keeps
    // requiring the exact expected JSON shape for every field, uniformly,
    // and reports `state_corrupt` for anything else -- a non-array/
    // non-string `environments`, a wrong-typed `environments` element, a
    // non-string `created_at`, and a missing field either way.
    #[test]
    fn malformed_environments_or_created_at_is_state_corrupt() {
        let (_tmp, state) = new_state();
        let projects = Projects::new(&state);
        let cases = [
            json!({"acme": {"environments": [1, 2], "created_at": "2024-01-01T00:00:00Z"}}),
            json!({"acme": {"environments": "dev", "created_at": "2024-01-01T00:00:00Z"}}),
            json!({"acme": {"environments": {"a": 1}, "created_at": "2024-01-01T00:00:00Z"}}),
            json!({"acme": {"environments": ["dev"], "created_at": null}}),
            json!({"acme": {"environments": ["dev"], "created_at": 1700000000}}),
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

    // A-R2-6: confirms the actual Python behaviour this row's reasoning and
    // the unit tests above rely on, against a real `python3.12` run of
    // `zeropw.projects.Projects` (not a re-derivation of the Python
    // source): (a) a `null` entry is `NotFound`, same as a missing key; (c)
    // a truthy non-dict document makes `get`/`list`/`create` all raise, and
    // `create` never writes; a falsy non-dict document behaves like `{}`;
    // (b) Python's `Project.environments`/`.created_at` accept values this
    // port rejects as `state_corrupt` (int elements, a string iterated into
    // characters, `None`), with no exception and no observable effect on
    // this crate's one in-scope caller (`require_environment`'s membership
    // test).
    #[test]
    fn python_oracle_confirms_load_get_create_edge_cases() {
        let script = r#"
import tempfile, os
from zeropw.projects import Projects
from zeropw.store import StateDir

def probe(doc):
    """(a)/(c): get/list/create against a whole-document edge case, keyed
    on "acme" so a null-valued (but present) "acme" entry and a genuinely
    absent one are both exercised the same way `create("acme", ["dev"])`
    would collide with."""
    with tempfile.TemporaryDirectory() as d:
        state = StateDir(os.path.join(d, "state"))
        state.create()
        state.write_json("projects.json", doc)
        projects = Projects(state)

        try:
            projects.get("acme")
            get_result = "OK"
        except Exception as exc:
            get_result = type(exc).__name__

        try:
            projects.list()
            list_result = "OK"
        except Exception as exc:
            list_result = type(exc).__name__

        try:
            projects.create("acme", ["dev"])
            create_result = "OK"
        except Exception as exc:
            create_result = type(exc).__name__

        on_disk = state.read_json("projects.json", None)
        unchanged = on_disk == doc
        print(get_result, "|", list_result, "|", create_result, "|", "unchanged" if unchanged else "changed")

def probe_get(entry):
    """(b): what `get()` returns for one already-present, loosely-typed
    "acme" entry (no `create` call, since `create` would just hit
    `project_exists` for a key that's already there)."""
    with tempfile.TemporaryDirectory() as d:
        state = StateDir(os.path.join(d, "state"))
        state.create()
        state.write_json("projects.json", {"acme": entry})
        projects = Projects(state)
        p = projects.get("acme")
        print("env=" + repr(list(p.environments)) + " created_at=" + repr(p.created_at))

def probe_named(doc, name):
    """A-R7-1: like `probe`, but with `name` chosen so `if name in doc`
    (the very first thing `create` does after acquiring the lock) succeeds
    as a substring/membership test on a truthy non-dict document -- the
    case the original `probe(doc)` (fixed at name="acme") never exercised
    because "acme" was never contained in any of its truthy-non-dict
    fixtures."""
    with tempfile.TemporaryDirectory() as d:
        state = StateDir(os.path.join(d, "state"))
        state.create()
        state.write_json("projects.json", doc)
        projects = Projects(state)
        try:
            projects.create(name, ["dev"])
            create_result = "OK"
        except Exception as exc:
            create_result = type(exc).__name__ + (":" + str(exc) if hasattr(exc, "detail") else "")
        on_disk = state.read_json("projects.json", None)
        unchanged = on_disk == doc
        print(create_result, "|", "unchanged" if unchanged else "changed")

# (a) null entry -> get() is NotFound, same as a missing key.
probe({"acme": None})
# (c) truthy non-dict documents -> get/list/create all raise, file untouched.
probe([1])
probe("abc")
probe(True)
probe(7)
# (c) falsy non-dict documents -> treated as {}.
probe(None)
probe(0)
probe("")
probe([])
probe(False)
# (b) loosely-typed environments/created_at -> Project construction succeeds
# in Python with no exception at all.
probe_get({"environments": [1, 2], "created_at": "2024-01-01T00:00:00Z"})
probe_get({"environments": "dev", "created_at": "2024-01-01T00:00:00Z"})
probe_get({"environments": ["dev"], "created_at": None})
# A-R7-1: name IS a substring (str doc) / IS an element (list doc) ->
# create raises the *documented* InvalidInput("project_exists"), not a
# builtin exception, and the file is left untouched either way.
probe_named("abc", "a")
probe_named("dev-prod-a", "prod")
probe_named(["acme"], "acme")
probe_named(["a", "b"], "a")
"#;
        let out = oracle::python(script);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 17, "expected exactly 17 probe cases");

        // (a): null entry -> NotFound (not AttributeError/KeyError).
        assert!(
            lines[0].starts_with("NotFound |"),
            "null entry: {}",
            lines[0]
        );

        // (c): truthy non-dict -> every operation raises, file untouched.
        for line in &lines[1..5] {
            assert!(
                line.contains("AttributeError") || line.contains("TypeError"),
                "truthy non-dict case: {line}"
            );
            assert!(
                line.ends_with("unchanged"),
                "create must not overwrite a truthy non-dict document: {line}"
            );
        }

        // (c): falsy non-dict -> treated as {} (NotFound for a genuinely
        // absent "acme" key; list/create both succeed against an empty
        // document).
        for line in &lines[5..10] {
            assert!(
                line.starts_with("NotFound | OK | OK"),
                "falsy non-dict case: {line}"
            );
        }

        // (b): Python accepts int elements, a string iterated into
        // characters, and a `None` created_at with no exception at all.
        assert_eq!(
            lines[10], "env=[1, 2] created_at='2024-01-01T00:00:00Z'",
            "int elements"
        );
        assert_eq!(
            lines[11], "env=['d', 'e', 'v'] created_at='2024-01-01T00:00:00Z'",
            "string iterated into characters"
        );
        assert_eq!(lines[12], "env=['dev'] created_at=None", "None created_at");

        // A-R7-1: a contained name resolves to the documented
        // InvalidInput("project_exists"), file untouched -- not a builtin
        // exception the way the not-contained cases above are.
        for line in &lines[13..17] {
            assert!(
                line.starts_with("InvalidInput"),
                "contained-name case: {line}"
            );
            assert!(
                line.ends_with("unchanged"),
                "create must not overwrite even on project_exists: {line}"
            );
        }
    }
}
