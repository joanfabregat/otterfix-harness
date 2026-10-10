use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}
impl Severity {
    pub fn from_scanner(value: &str) -> Self {
        match value {
            "LOW" => Self::Low,
            "MEDIUM" => Self::Medium,
            "HIGH" => Self::High,
            "CRITICAL" => Self::Critical,
            _ => Self::Unknown,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relationship {
    Direct,
    Transitive,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIdentity {
    pub ecosystem: String,
    pub name: String,
    pub installed_version: String,
    /// Scanner's opaque package instance identifier, never parsed as a source.
    pub scanner_package_id: Option<String>,
    pub purl: Option<String>,
    /// Source is unknown unless explicitly established by package-manager metadata.
    pub source: Option<String>,
    pub location: String,
    pub relationship: Relationship,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub instance_id: String,
    pub advisory_id: String,
    pub advisory_aliases: Vec<String>,
    pub category: String,
    pub package: PackageIdentity,
    pub severity: Severity,
    pub severity_source: Option<String>,
    /// Scanner-supplied candidates; not verified available or compatible versions.
    pub fix_candidates: Vec<String>,
    pub references: Vec<String>,
    /// Original vulnerability object, including CVSS and future scanner fields.
    pub scanner_evidence: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerProvenance {
    pub scanner: String,
    pub scanner_version: Option<String>,
    pub report_schema_version: u32,
    pub created_at: Option<String>,
    pub artifact_name: Option<String>,
    pub artifact_type: Option<String>,
    pub revision: Option<String>,
    pub image_digests: Vec<String>,
    pub database: Option<Value>,
    pub configuration: Option<Value>,
    pub coverage: Vec<String>,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedFinding {
    pub location: String,
    pub category: String,
    pub reason: String,
    pub scanner_evidence: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingBatch {
    pub schema_version: u32,
    pub provenance: ScannerProvenance,
    pub findings: Vec<Finding>,
    pub unsupported: Vec<UnsupportedFinding>,
    /// Whole parsed report retained; callers must treat all scanner data as untrusted.
    pub raw_report: Value,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Eligible,
    PolicyExcluded,
    NoFix,
    Unsupported,
    CandidateProposed,
    ValidationFailed,
    ValidatedCandidate,
    BudgetExceeded,
    Cancelled,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub finding_instance_id: String,
    pub outcome: Outcome,
    pub reason: String,
    pub policy_version: String,
    pub evaluated_at: String,
    pub intelligence_snapshot: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    pub max_model_calls: u32,
    pub max_tool_calls: u32,
    pub max_attempts: u32,
    pub max_wall_seconds: u64,
    pub max_output_bytes: u64,
    pub max_changed_files: u32,
    pub max_patch_bytes: u64,
    pub max_changed_lines: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationRequirement {
    pub capability_id: String,
    pub coverage: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub schema_version: u32,
    pub task_id: String,
    pub base_revision: String,
    pub finding_instance_ids: Vec<String>,
    pub policy_digest: String,
    pub allowed_paths: Vec<String>,
    pub protected_paths: Vec<String>,
    pub validation: Vec<ValidationRequirement>,
    pub capability_ids: Vec<String>,
    pub budgets: Budgets,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationEvidence {
    pub capability_id: String,
    pub passed: bool,
    pub complete: bool,
    pub candidate_digest: String,
    pub provenance: Value,
    pub coverage: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationResult {
    pub schema_version: u32,
    pub task_id: String,
    pub base_revision: String,
    pub candidate_revision: Option<String>,
    pub patch_digest: Option<String>,
    pub outcome: Outcome,
    pub attempts: u32,
    pub intended_versions: Vec<PackageIdentity>,
    pub resolved_versions: Vec<PackageIdentity>,
    pub validation: Vec<ValidationEvidence>,
    pub model_calls: u32,
    pub tool_calls: u32,
    pub rationale: String,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriageResult {
    pub schema_version: u32,
    pub batch: FindingBatch,
    pub decisions: Vec<Decision>,
}
