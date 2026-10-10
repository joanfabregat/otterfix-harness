use crate::contracts::*;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Trusted caller configuration. Never load candidate-modified policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u32,
    pub version: String,
    pub evaluated_at: String,
    pub intelligence_snapshot: Option<String>,
    pub minimum_severity: Severity,
    pub require_fix: bool,
    pub allowed_ecosystems: Vec<String>,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(Error("unsupported policy schema_version".into()));
        }
        if self.version.trim().is_empty() || self.evaluated_at.trim().is_empty() {
            return Err(Error("policy version and evaluated_at are required".into()));
        }
        Ok(())
    }
    pub fn triage(&self, batch: FindingBatch) -> Result<TriageResult> {
        self.validate()?;
        if batch.schema_version != SCHEMA_VERSION {
            return Err(Error("unsupported finding schema_version".into()));
        }
        let decisions = batch
            .findings
            .iter()
            .map(|finding| {
                let (outcome, reason) = if finding.category != "package_vulnerability"
                    || finding.package.ecosystem != "cargo"
                {
                    (
                        Outcome::Unsupported,
                        "finding category or ecosystem is unsupported",
                    )
                } else if !self.allowed_ecosystems.contains(&finding.package.ecosystem) {
                    (
                        Outcome::PolicyExcluded,
                        "ecosystem excluded by trusted policy",
                    )
                } else if finding.severity == Severity::Unknown {
                    (Outcome::Unsupported, "unknown severity requires review")
                } else if finding.severity < self.minimum_severity {
                    (
                        Outcome::PolicyExcluded,
                        "severity below trusted policy threshold",
                    )
                } else if finding.fix_candidates.is_empty() {
                    (
                        Outcome::NoFix,
                        if self.require_fix {
                            "no scanner fix candidate; policy requires a fix"
                        } else {
                            "no scanner fix candidate; automated no-fix strategies are unsupported"
                        },
                    )
                } else {
                    (
                        Outcome::Eligible,
                        "eligible for source and compatibility analysis; no fix has been validated",
                    )
                };
                Decision {
                    finding_instance_id: finding.instance_id.clone(),
                    outcome,
                    reason: reason.into(),
                    policy_version: self.version.clone(),
                    evaluated_at: self.evaluated_at.clone(),
                    intelligence_snapshot: self.intelligence_snapshot.clone(),
                }
            })
            .collect();
        Ok(TriageResult {
            schema_version: SCHEMA_VERSION,
            batch,
            decisions,
        })
    }
}
