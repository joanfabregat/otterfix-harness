//! Trivy report-schema v2 adapter. All scanner evidence is untrusted.
use crate::contracts::*;
use crate::{Error, Result};
use serde_json::Value;

fn string(value: &Value, key: &str) -> Result<Option<String>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.is_empty() => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        _ => Err(Error(format!("{key} must be a string"))),
    }
}
fn required(value: &Value, key: &str) -> Result<String> {
    string(value, key)?.ok_or_else(|| Error(format!("missing {key}")))
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(values)) => Ok(values),
        _ => Err(Error(format!("{key} must be an array"))),
    }
}
fn strings(value: &Value, key: &str) -> Result<Vec<String>> {
    array(value, key)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error(format!("{key} entries must be strings")))
        })
        .collect()
}
fn object(value: &Value, context: &str) -> Result<()> {
    if value.is_object() {
        Ok(())
    } else {
        Err(Error(format!("{context} must be an object")))
    }
}

pub fn ingest(bytes: &[u8]) -> Result<FindingBatch> {
    let raw: Value = serde_json::from_slice(bytes)?;
    object(&raw, "report")?;
    if raw.get("SchemaVersion").and_then(Value::as_u64) != Some(2) {
        return Err(Error("unsupported Trivy SchemaVersion; expected 2".into()));
    }
    // An omitted Results is a valid empty Trivy report. Arbitrary objects without
    // a recognized schema are never treated as a clean scan.
    let mut findings = Vec::new();
    let mut unsupported = Vec::new();
    let mut coverage = Vec::new();
    for (result_index, result) in array(&raw, "Results")?.iter().enumerate() {
        object(result, "result")?;
        let location = required(result, "Target")?;
        let class = string(result, "Class")?.unwrap_or_default();
        let ecosystem = string(result, "Type")?.unwrap_or_default();
        coverage.push(format!("{class}:{ecosystem}:{location}"));
        let vulnerabilities = array(result, "Vulnerabilities")?;
        if class != "lang-pkgs" || ecosystem != "cargo" {
            unsupported.push(UnsupportedFinding {
                location,
                category: format!("{class}:{ecosystem}"),
                reason: "only Cargo language-package vulnerabilities are supported".into(),
                scanner_evidence: result.clone(),
            });
            continue;
        }
        for key in [
            "Misconfigurations",
            "Secrets",
            "Licenses",
            "CustomResources",
            "ExperimentalModifiedFindings",
        ] {
            if !array(result, key)?.is_empty() {
                unsupported.push(UnsupportedFinding {
                    location: location.clone(),
                    category: key.into(),
                    reason: "finding category is unsupported; evidence was retained".into(),
                    scanner_evidence: result[key].clone(),
                });
            }
        }
        let packages = array(result, "Packages")?;
        for package in packages {
            object(package, "package")?;
        }
        for (vulnerability_index, vulnerability) in vulnerabilities.iter().enumerate() {
            object(vulnerability, "vulnerability")?;
            let advisory_id = required(vulnerability, "VulnerabilityID")?;
            let name = required(vulnerability, "PkgName")?;
            let installed_version = required(vulnerability, "InstalledVersion")?;
            let package_id = string(vulnerability, "PkgID")?;
            let matches: Vec<_> = packages
                .iter()
                .filter(|package| {
                    // Do not fall back to name when an opaque instance ID is present.
                    if let Some(id) = &package_id {
                        package.get("ID").and_then(Value::as_str) == Some(id)
                    } else {
                        package.get("Name").and_then(Value::as_str) == Some(&name)
                            && package.get("Version").and_then(Value::as_str)
                                == Some(&installed_version)
                    }
                })
                .collect();
            let relationship = if matches.len() == 1 {
                match string(matches[0], "Relationship")?.as_deref() {
                    Some("direct") => Relationship::Direct,
                    Some("indirect") => Relationship::Transitive,
                    _ => Relationship::Unknown,
                }
            } else {
                Relationship::Unknown
            };
            let purl = vulnerability
                .get("PkgIdentifier")
                .map(|identifier| string(identifier, "PURL"))
                .transpose()?
                .flatten();
            let fixed = string(vulnerability, "FixedVersion")?.unwrap_or_default();
            let fix_candidates = fixed
                .split(',')
                .map(str::trim)
                .filter(|version| !version.is_empty())
                .map(str::to_owned)
                .collect();
            let mut references = strings(vulnerability, "References")?;
            if let Some(url) = string(vulnerability, "PrimaryURL")? {
                if !references.contains(&url) {
                    references.push(url);
                }
            }
            findings.push(Finding {
                instance_id: format!(
                    "trivy:Results/{result_index}/Vulnerabilities/{vulnerability_index}"
                ),
                advisory_id,
                advisory_aliases: strings(vulnerability, "VendorIDs")?,
                category: "package_vulnerability".into(),
                package: PackageIdentity {
                    ecosystem: ecosystem.clone(),
                    name,
                    installed_version,
                    scanner_package_id: package_id,
                    purl,
                    source: None,
                    location: string(vulnerability, "PkgPath")?.unwrap_or_else(|| location.clone()),
                    relationship,
                },
                severity: Severity::from_scanner(
                    &string(vulnerability, "Severity")?.unwrap_or_default(),
                ),
                severity_source: string(vulnerability, "SeveritySource")?,
                fix_candidates,
                references,
                scanner_evidence: vulnerability.clone(),
            });
        }
    }
    let metadata = raw.get("Metadata").unwrap_or(&Value::Null);
    let trivy = raw.get("Trivy").unwrap_or(&Value::Null);
    Ok(FindingBatch {
        schema_version: SCHEMA_VERSION,
        provenance: ScannerProvenance {
            scanner: "trivy".into(), scanner_version: string(trivy, "Version")?,
            report_schema_version: 2, created_at: string(&raw, "CreatedAt")?,
            artifact_name: string(&raw, "ArtifactName")?, artifact_type: string(&raw, "ArtifactType")?,
            revision: string(metadata, "Commit")?, image_digests: strings(metadata, "RepoDigests")?,
            database: raw.get("DB").cloned(), configuration: raw.get("Configuration").cloned(),
            coverage,
            limitations: vec![
                "Reported coverage is scanner supplied, not independently verified.".into(),
                "Scanner database/configuration provenance may be absent; preserve and supply it externally before comparison.".into(),
                "Trivy Cargo scans exclude developer dependencies when Cargo.toml and Cargo.lock are scanned together.".into(),
                "Fix candidates and package sources require independent Cargo resolution; scanner identities alone do not establish feasibility.".into(),
            ],
        },
        findings, unsupported, raw_report: raw,
    })
}
