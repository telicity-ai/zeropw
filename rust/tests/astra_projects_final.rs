//! Independent A-R2-6(b) acceptance boundaries; synthetic state only.
use serde_json::{Value, json};
use std::process::{Command, Output};
use zeropw::{
    context::{Config, Context},
    projects::{DOC, Projects},
};

fn python(script: &str, path: &std::path::Path) -> Output {
    Command::new("python3.12")
        .args(["-c", script])
        .arg(path)
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap()
}

#[test]
fn accepted_persisted_shapes_match_real_python_library_and_both_clis() {
    let temp = tempfile::TempDir::new().unwrap();
    let ctx = Context::initialize(
        temp.path().join("state"),
        "synthetic-admin",
        "synthetic-recovery",
        Config::default(),
        zeropw::clock::system(),
    )
    .unwrap();
    // Preserve insertion order in raw state; dictionary keys are an iterable,
    // not a sorted set. Project names themselves must still list sorted.
    ctx.state.write_bytes(DOC, r#"{"z":{"environments":{"prod":0,"dev":1},"created_at":false},"a":{"environments":"a🌱한","created_at":null},"mix":{"environments":[7,false,null,[],{},"7","dev"],"created_at":[0,{"x":true}]},"empty-list":{"environments":[],"created_at":0},"empty-dict":{"environments":{},"created_at":{}},"empty-string":{"environments":"","created_at":""}}"#.as_bytes()).unwrap();
    let script = r#"
import json,sys
from zeropw.projects import Projects
from zeropw.store import StateDir
p=Projects(StateDir(sys.argv[1]))
def view(v):return dict(name=v.name,environments=list(v.environments),created_at=v.created_at)
result=[]
for item in p.list():
 checks=[]
 for e in ['dev','prod','a','🌱','한','7','False','None','missing','']:
  try:p.require_environment(item.name,e);checks.append('ok')
  except Exception as ex:checks.append(ex.reason)
 result.append(dict(project=view(item),get=view(p.get(item.name)),checks=checks))
print(json.dumps(result,ensure_ascii=False))
"#;
    let expected = python(script, &ctx.state.path);
    assert!(expected.status.success(), "{:?}", expected);
    let expected: Value = serde_json::from_slice(&expected.stdout).unwrap();
    let projects = Projects::new(ctx.state);
    let actual: Vec<Value> = projects.list().unwrap().into_iter().map(|p| {
        let get = projects.get(&p.name).unwrap();
        let checks: Vec<String> = ["dev","prod","a","🌱","한","7","False","None","missing",""]
            .into_iter().map(|e| projects.require_environment(&p.name,e).map(|_|"ok".into()).unwrap_or_else(|e|e.reason.into_owned())).collect();
        json!({"project":{"name":p.name,"environments":p.environments,"created_at":p.created_at},"get":{"name":get.name,"environments":get.environments,"created_at":get.created_at},"checks":checks})
    }).collect();
    assert_eq!(json!(actual), expected);
    let original = Command::new("python3.12")
        .args(["-m", "zeropw.admin_cli", "--state-dir"])
        .arg(&ctx.state.path)
        .args(["project", "list"])
        .env("PYTHONPATH", format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .output()
        .unwrap();
    let native = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
        .arg("--state-dir")
        .arg(&ctx.state.path)
        .args(["project", "list"])
        .output()
        .unwrap();
    assert!(original.status.success() && native.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&native.stdout).unwrap(),
        serde_json::from_slice::<Value>(&original.stdout).unwrap()
    );
    let created = projects.create("ordinary", &["dev", "prod"]).unwrap();
    assert_eq!(created.environments, vec![json!("dev"), json!("prod")]);
    assert!(created.created_at.as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(projects.get("ordinary").unwrap(), created);
}

#[test]
fn missing_or_noniterable_fields_fail_closed_and_do_not_rewrite_state() {
    let temp = tempfile::TempDir::new().unwrap();
    let ctx = Context::initialize(
        temp.path().join("state"),
        "synthetic-admin",
        "synthetic-recovery",
        Config::default(),
        zeropw::clock::system(),
    )
    .unwrap();
    let projects = Projects::new(ctx.state);
    for entry in [
        json!({"environments":null,"created_at":null}),
        json!({"environments":false,"created_at":0}),
        json!({"environments":0,"created_at":0}),
        json!({"environments":1.5,"created_at":0}),
        json!({"created_at":0}),
        json!({"environments":[]}),
    ] {
        ctx.state.write_json(DOC, &json!({"broken":entry})).unwrap();
        let before = std::fs::read(ctx.state.path.join(DOC)).unwrap();
        for result in [
            projects.get("broken").map(|_| ()),
            projects.list().map(|_| ()),
            projects.require_environment("broken", "dev"),
        ] {
            assert_eq!(result.unwrap_err().reason, "state_corrupt");
        }
        let original = python(
            r#"
import sys
from zeropw.projects import Projects
from zeropw.store import StateDir
p=Projects(StateDir(sys.argv[1]))
for f in [lambda:p.get('broken'),p.list,lambda:p.require_environment('broken','dev')]:
 try:f();raise AssertionError('unexpected success')
 except (TypeError,KeyError):pass
"#,
            &ctx.state.path,
        );
        assert!(original.status.success(), "{:?}", original);
        let native = Command::new(env!("CARGO_BIN_EXE_zeropw-admin"))
            .arg("--state-dir")
            .arg(&ctx.state.path)
            .args(["project", "list"])
            .output()
            .unwrap();
        assert_eq!(native.status.code(), Some(1));
        assert_eq!(
            serde_json::from_slice::<Value>(&native.stderr).unwrap()["reason"],
            "state_corrupt"
        );
        assert_eq!(std::fs::read(ctx.state.path.join(DOC)).unwrap(), before);
    }
}
