use otterfix::candidate::{self, CandidateSummary, FileChange};
use otterfix::cargo_graph::CargoGraph;
use otterfix::contracts::*;
use otterfix::policy::Policy;
use otterfix::provider::*;
use otterfix::{trivy, Result};
use serde_json::{json, Value};
use std::sync::atomic::AtomicBool;

const REPORT: &[u8] = include_bytes!("fixtures/trivy-cargo.json");
fn policy() -> Policy {
    serde_json::from_slice(include_bytes!("fixtures/policy.json")).unwrap()
}
fn budgets() -> Budgets {
    Budgets {
        max_model_calls: 3,
        max_tool_calls: 3,
        max_attempts: 3,
        max_wall_seconds: 30,
        max_output_bytes: 4096,
        max_changed_files: 2,
        max_patch_bytes: 1024,
        max_changed_lines: 10,
    }
}
fn task() -> Task {
    Task {
        schema_version: 1,
        task_id: "synthetic-task".into(),
        base_revision: "base".into(),
        finding_instance_ids: vec![],
        policy_digest: "policy-digest".into(),
        allowed_paths: vec![
            "Cargo.lock".into(),
            "Cargo.toml".into(),
            "src".into(),
            "tests".into(),
            ".github".into(),
        ],
        protected_paths: vec!["src/assertions.rs".into()],
        validation: vec![],
        capability_ids: vec![],
        budgets: budgets(),
    }
}
fn candidate(path: &str) -> CandidateSummary {
    CandidateSummary {
        base_revision: "base".into(),
        policy_digest: "policy-digest".into(),
        patch_bytes: 100,
        changes: vec![FileChange {
            path: path.into(),
            previous_path: None,
            old_mode: Some(0o100644),
            new_mode: Some(0o100644),
            added_lines: 1,
            removed_lines: 1,
            binary: false,
        }],
    }
}
#[test]
fn preserves_instances_provenance_raw_evidence_and_no_fix() {
    let batch = trivy::ingest(REPORT).unwrap();
    assert_eq!(batch.findings.len(), 3);
    assert_eq!(batch.findings[0].package.relationship, Relationship::Direct);
    assert_eq!(
        batch.findings[1].package.relationship,
        Relationship::Transitive
    );
    assert_ne!(batch.findings[1].instance_id, batch.findings[2].instance_id);
    assert_ne!(
        batch.findings[1].package.installed_version,
        batch.findings[2].package.installed_version
    );
    assert_eq!(batch.findings[0].fix_candidates, ["1.0.1", "2.0.0"]);
    assert!(batch.findings[0].package.source.is_none());
    assert_eq!(batch.findings[0].scanner_evidence["FutureEvidence"], true);
    assert_eq!(batch.raw_report["FutureReportField"]["retained"], true);
    assert_eq!(
        batch.provenance.scanner_version.as_deref(),
        Some("synthetic-scanner")
    );
    assert!(batch.provenance.database.is_some());
    assert!(batch
        .provenance
        .limitations
        .iter()
        .any(|text| text.contains("developer dependencies")));
    let triage = policy().triage(batch).unwrap();
    assert_eq!(
        triage
            .decisions
            .iter()
            .map(|decision| &decision.outcome)
            .collect::<Vec<_>>(),
        [
            &Outcome::Eligible,
            &Outcome::NoFix,
            &Outcome::PolicyExcluded
        ]
    );
}
#[test]
fn malformed_and_future_reports_fail_closed() {
    for value in [
        json!({}),
        json!({"SchemaVersion":3}),
        json!({"SchemaVersion":2,"Results":{}}),
        json!({"SchemaVersion":2,"Results":[{}]}),
        json!({"SchemaVersion":2,"Results":[{"Target":"Cargo.lock","Type":"cargo","Class":"lang-pkgs","Vulnerabilities":[{}]}]}),
    ] {
        assert!(trivy::ingest(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    assert!(trivy::ingest(b"{broken").is_err());
    assert!(trivy::ingest(b"[]").is_err());
    assert!(trivy::ingest(b"{\"SchemaVersion\":2}")
        .unwrap()
        .findings
        .is_empty());
}
#[test]
fn unsupported_categories_are_retained_and_not_cleaned_away() {
    let raw = json!({"SchemaVersion":2,"Results":[{"Target":"config.yaml","Class":"config","Type":"yaml","Misconfigurations":[{"ID":"synthetic"}]}]});
    let batch = trivy::ingest(&serde_json::to_vec(&raw).unwrap()).unwrap();
    assert!(batch.findings.is_empty());
    assert_eq!(batch.unsupported.len(), 1);
    assert_eq!(
        batch.unsupported[0].scanner_evidence["Misconfigurations"][0]["ID"],
        "synthetic"
    );
}
#[test]
fn duplicate_scanner_package_ids_do_not_guess_relationship() {
    let mut raw: Value = serde_json::from_slice(REPORT).unwrap();
    let package = raw["Results"][0]["Packages"][0].clone();
    raw["Results"][0]["Packages"]
        .as_array_mut()
        .unwrap()
        .push(package);
    let batch = trivy::ingest(&serde_json::to_vec(&raw).unwrap()).unwrap();
    assert_eq!(
        batch.findings[0].package.relationship,
        Relationship::Unknown
    );
}
#[test]
fn bad_policy_and_unknown_severity_are_explicit() {
    let mut config = policy();
    config.schema_version = 2;
    assert!(config.triage(trivy::ingest(REPORT).unwrap()).is_err());
    let mut batch = trivy::ingest(REPORT).unwrap();
    batch.findings[0].severity = Severity::Unknown;
    assert_eq!(
        policy().triage(batch).unwrap().decisions[0].outcome,
        Outcome::Unsupported
    );
    let mut raw: Value = serde_json::from_slice(include_bytes!("fixtures/policy.json")).unwrap();
    raw["model_can_authorize"] = json!(true);
    assert!(serde_json::from_value::<Policy>(raw).is_err());
}
#[test]
fn no_fix_remains_no_fix_when_fix_filter_is_disabled() {
    let mut config = policy();
    config.require_fix = false;
    assert_eq!(
        config
            .triage(trivy::ingest(REPORT).unwrap())
            .unwrap()
            .decisions[1]
            .outcome,
        Outcome::NoFix
    );
}
#[test]
fn protected_paths_traversal_and_renames_fail() {
    for path in [
        "tests/check.rs",
        ".github/workflows/check.yml",
        "src/assertions.rs",
        "src/../Cargo.toml",
        "/Cargo.lock",
        "src\\foo",
        "src//foo",
        "src/./foo",
        "src/.env",
        "src/.codex/settings",
    ] {
        assert!(
            candidate::check(&task(), &candidate(path)).is_err(),
            "{path}"
        );
    }
    let mut change = candidate("Cargo.lock");
    change.changes[0].previous_path = Some("tests/check.rs".into());
    assert!(candidate::check(&task(), &change).is_err());
    assert!(candidate::check(&task(), &candidate("src-other/file.rs")).is_err());
    assert!(candidate::check(&task(), &candidate("Cargo.lock")).is_ok());
}
#[test]
fn diff_budgets_modes_and_binding_fail_closed() {
    let mut diff = candidate("Cargo.lock");
    diff.patch_bytes = 1025;
    assert!(candidate::check(&task(), &diff).is_err());
    diff.patch_bytes = 100;
    diff.changes[0].added_lines = 11;
    assert!(candidate::check(&task(), &diff).is_err());
    diff.changes[0].added_lines = u64::MAX;
    assert!(candidate::check(&task(), &diff).is_err());
    diff.changes[0].added_lines = 1;
    diff.changes[0].new_mode = Some(0o120000);
    assert!(candidate::check(&task(), &diff).is_err());
    diff.changes[0].new_mode = Some(0o100644);
    diff.base_revision = "different".into();
    assert!(candidate::check(&task(), &diff).is_err());
    let mut config = task();
    config.budgets.max_changed_files = 0;
    assert!(candidate::check(&config, &candidate("Cargo.lock")).is_err());
}
fn metadata() -> Value {
    json!({"version":1,"workspace_members":["root"],"packages":[
        {"id":"root","name":"root","version":"0.1.0","source":null,"manifest_path":"/workspace/Cargo.toml","dependencies":[],"features":{}},
        {"id":"leaf","name":"demo-direct","version":"1.0.0","source":"registry+synthetic","manifest_path":"/registry/Cargo.toml","dependencies":[],"features":{}}
    ],"resolve":{"root":"root","nodes":[
        {"id":"root","features":["default"],"deps":[{"name":"leaf","pkg":"leaf","dep_kinds":[{"kind":null,"target":"cfg(unix)"},{"kind":"build","target":null}]}]},
        {"id":"leaf","features":["feature-a"],"deps":[]}
    ]},"future_field":"retained"})
}
#[test]
fn cargo_graph_preserves_features_kinds_targets_and_sources() {
    let graph = CargoGraph::parse(&serde_json::to_vec(&metadata()).unwrap()).unwrap();
    let resolution = graph.resolve.as_ref().unwrap();
    assert_eq!(
        resolution.nodes[0].deps[0].dep_kinds[0].target.as_deref(),
        Some("cfg(unix)")
    );
    assert_eq!(
        resolution.nodes[0].deps[0].dep_kinds[1].kind.as_deref(),
        Some("build")
    );
    assert_eq!(resolution.nodes[1].features, ["feature-a"]);
    assert_eq!(graph.extra["future_field"], "retained");
    let finding = &trivy::ingest(REPORT).unwrap().findings[0];
    assert!(graph.match_finding(finding, &[]).is_err());
    assert_eq!(
        graph
            .match_finding(finding, &["registry+synthetic".into()])
            .unwrap()
            .id,
        "leaf"
    );
}
#[test]
fn cargo_duplicate_sources_or_incomplete_resolution_require_review() {
    let mut value = metadata();
    let mut duplicate = value["packages"][1].clone();
    duplicate["id"] = json!("other-source");
    duplicate["source"] = json!("registry+other");
    value["packages"].as_array_mut().unwrap().push(duplicate);
    let graph = CargoGraph::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(graph
        .match_finding(
            &trivy::ingest(REPORT).unwrap().findings[0],
            &["registry+synthetic".into()]
        )
        .is_err());
    value["resolve"] = Value::Null;
    assert!(CargoGraph::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = metadata();
    value["resolve"]["nodes"][0]["deps"][0]["pkg"] = json!("missing");
    assert!(CargoGraph::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}
struct ScriptedProvider {
    turns: std::collections::VecDeque<ProviderTurn>,
    received: Vec<ToolReply>,
}
impl Provider for ScriptedProvider {
    fn next(
        &mut self,
        continuation: Option<&Value>,
        replies: &[ToolReply],
        _: &CallContext<'_>,
    ) -> Result<ProviderTurn> {
        if !replies.is_empty() {
            assert_eq!(continuation, Some(&json!("resume-1")));
            self.received.extend_from_slice(replies);
        }
        Ok(self.turns.pop_front().unwrap())
    }
}
#[derive(Default)]
struct RecordingExecutor {
    executed: usize,
}
impl ToolExecutor for RecordingExecutor {
    fn execute(&mut self, _: &ToolRequest, _: &CallContext<'_>) -> Result<Value> {
        self.executed += 1;
        Ok(json!({"untrusted_output":"synthetic"}))
    }
}
fn scripted(calls: Vec<ToolCall>) -> ScriptedProvider {
    ScriptedProvider {
        turns: [
            ProviderTurn {
                continuation: Some(json!("resume-1")),
                calls,
                final_text: None,
            },
            ProviderTurn {
                continuation: None,
                calls: vec![],
                final_text: Some("candidate proposal only".into()),
            },
        ]
        .into(),
        received: vec![],
    }
}
fn file_call() -> ToolCall {
    ToolCall {
        id: "call-1".into(),
        request: ToolRequest::ReadFile {
            path: "src/lib.rs".into(),
        },
    }
}
#[test]
fn provider_tool_continuation_is_bounded_and_untrusted() {
    let mut provider = scripted(vec![file_call()]);
    let mut executor = RecordingExecutor::default();
    let result = run(
        &mut provider,
        &mut executor,
        &["read_file".into()],
        &[],
        &budgets(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(result.model_calls, 2);
    assert_eq!(result.tool_calls, 1);
    assert_eq!(executor.executed, 1);
    assert_eq!(provider.received[0].id, "call-1");
}
#[test]
fn unauthorized_tools_capabilities_and_duplicate_calls_execute_nothing() {
    for calls in [
        vec![file_call()],
        vec![file_call(), file_call()],
        vec![ToolCall {
            id: "command".into(),
            request: ToolRequest::RunCommand {
                capability_id: "unauthorized".into(),
            },
        }],
    ] {
        let mut provider = scripted(calls);
        let mut executor = RecordingExecutor::default();
        assert!(run(
            &mut provider,
            &mut executor,
            &["run_command".into()],
            &[],
            &budgets(),
            &AtomicBool::new(false)
        )
        .is_err());
        assert_eq!(executor.executed, 0);
    }
    let mut call = file_call();
    call.request = ToolRequest::ReadFile {
        path: "../outside".into(),
    };
    let mut executor = RecordingExecutor::default();
    assert!(run(
        &mut scripted(vec![call]),
        &mut executor,
        &["read_file".into()],
        &[],
        &budgets(),
        &AtomicBool::new(false)
    )
    .is_err());
    assert_eq!(executor.executed, 0);
}
#[test]
fn model_tool_output_wall_and_cancellation_budgets_stop() {
    for config in [
        Budgets {
            max_model_calls: 0,
            ..budgets()
        },
        Budgets {
            max_tool_calls: 0,
            ..budgets()
        },
        Budgets {
            max_output_bytes: 1,
            ..budgets()
        },
        Budgets {
            max_wall_seconds: 0,
            ..budgets()
        },
    ] {
        let mut executor = RecordingExecutor::default();
        assert!(run(
            &mut scripted(vec![file_call()]),
            &mut executor,
            &["read_file".into()],
            &[],
            &config,
            &AtomicBool::new(false)
        )
        .is_err());
        assert_eq!(executor.executed, 0);
    }
    let mut executor = RecordingExecutor::default();
    assert!(run(
        &mut scripted(vec![file_call()]),
        &mut executor,
        &["read_file".into()],
        &[],
        &budgets(),
        &AtomicBool::new(true)
    )
    .is_err());
    assert_eq!(executor.executed, 0);
}
#[test]
fn live_providers_are_honestly_unsupported() {
    for kind in [ProviderKind::OpenAi, ProviderKind::Gemini] {
        let mut provider = UnsupportedProvider(kind);
        assert!(run(
            &mut provider,
            &mut RecordingExecutor::default(),
            &[],
            &[],
            &budgets(),
            &AtomicBool::new(false)
        )
        .unwrap_err()
        .0
        .contains("not implemented"));
    }
}
#[test]
fn cli_emits_versioned_json_and_rejects_invalid_arguments() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_otterfix"))
        .args([
            "triage",
            "--report",
            "tests/fixtures/trivy-cargo.json",
            "--policy",
            "tests/fixtures/policy.json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["decisions"][1]["outcome"], "no_fix");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_otterfix"))
        .arg("remediate")
        .output()
        .unwrap()
        .status;
    assert_eq!(status.code(), Some(2));
}
