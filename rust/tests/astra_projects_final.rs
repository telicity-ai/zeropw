//! Independent A-R2-6(b) acceptance boundaries; synthetic state only.
use serde_json::{Value, json};
use std::process::Command;
use zeropw::{
    context::{Config, Context},
    projects::{DOC, Projects},
};

#[test]
fn ordinary_projects_keep_their_environments_and_creation_time() {
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
    let created = projects.create("ordinary", &["dev", "prod"]).unwrap();
    assert_eq!(created.environments, vec![json!("dev"), json!("prod")]);
    assert!(created.created_at.as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(projects.get("ordinary").unwrap(), created);
    projects.create("another", &["dev"]).unwrap();
    // Project names list sorted.
    let names: Vec<String> = projects.list().unwrap().into_iter().map(|p| p.name).collect();
    assert_eq!(names, ["another", "ordinary"]);
    assert!(projects.require_environment("ordinary", "prod").is_ok());
    assert_eq!(
        projects
            .require_environment("ordinary", "staging")
            .unwrap_err()
            .reason,
        "environment_not_found"
    );
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
