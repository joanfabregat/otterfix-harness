//! Preliminary policy checks on caller-authenticated diff metadata.
//!
//! These checks do not read a workspace or authenticate a patch. A trusted
//! validator must independently derive this metadata from the complete frozen
//! diff, check digests and symlinks, and validate the resulting candidate.
//! Path checks cannot identify inline #[test]/#[cfg(test)] code or assertions in
//! ordinary source files. A trusted validator must reject changes to these too.
use crate::contracts::{Task, SCHEMA_VERSION};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileChange {
    pub path: String,
    /// Include the old path for a rename; both paths are checked.
    pub previous_path: Option<String>,
    pub old_mode: Option<u32>,
    pub new_mode: Option<u32>,
    pub added_lines: u64,
    pub removed_lines: u64,
    pub binary: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSummary {
    pub base_revision: String,
    pub policy_digest: String,
    pub patch_bytes: u64,
    pub changes: Vec<FileChange>,
}

pub fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains(':')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."))
}
fn within(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
fn protected_by_default(path: &str) -> bool {
    path.split('/').any(|component| {
        matches!(
            component,
            ".git"
                | ".github"
                | ".gitlab"
                | ".cargo"
                | ".agents"
                | ".codex"
                | ".claude"
                | "tests"
                | "fixtures"
                | "snapshots"
                | "__snapshots__"
                | "AGENTS.md"
                | "CLAUDE.md"
                | ".env"
                | ".npmrc"
                | ".yarnrc"
                | "credentials"
                | "secrets"
                | ".trivyignore"
                | ".trivyignore.yaml"
                | "trivy.yaml"
                | "policy.json"
        ) || component.starts_with(".env.")
    })
}
pub fn check(task: &Task, candidate: &CandidateSummary) -> Result<()> {
    if task.schema_version != SCHEMA_VERSION {
        return Err(Error("unsupported task schema_version".into()));
    }
    if task.base_revision.is_empty()
        || task.policy_digest.is_empty()
        || task.base_revision != candidate.base_revision
        || task.policy_digest != candidate.policy_digest
    {
        return Err(Error(
            "candidate base revision or policy binding mismatch".into(),
        ));
    }
    for path in task.allowed_paths.iter().chain(&task.protected_paths) {
        if !valid_relative_path(path) {
            return Err(Error(
                "trusted path scope must be a normalized relative path; globs are unsupported"
                    .into(),
            ));
        }
    }
    if candidate.changes.len() > task.budgets.max_changed_files as usize
        || candidate.patch_bytes > task.budgets.max_patch_bytes
    {
        return Err(Error("candidate exceeds file or patch byte budget".into()));
    }
    let mut paths = BTreeSet::new();
    let mut lines = 0_u64;
    for change in &candidate.changes {
        if !paths.insert(&change.path) {
            return Err(Error("duplicate candidate path".into()));
        }
        for path in std::iter::once(&change.path).chain(change.previous_path.as_ref()) {
            if !valid_relative_path(path) {
                return Err(Error("unsafe candidate path".into()));
            }
            if protected_by_default(path)
                || task.protected_paths.iter().any(|root| within(path, root))
            {
                return Err(Error("candidate touches a protected path".into()));
            }
            if !task.allowed_paths.iter().any(|root| within(path, root)) {
                return Err(Error("candidate path is outside allowed scope".into()));
            }
        }
        if change.binary
            || change
                .old_mode
                .iter()
                .chain(change.new_mode.iter())
                .any(|mode| *mode != 0o100644)
            || (change.old_mode.is_some()
                && change.new_mode.is_some()
                && change.old_mode != change.new_mode)
        {
            return Err(Error(
                "binary, symlink, executable, or mode changes require review".into(),
            ));
        }
        if change.old_mode.is_none() && change.new_mode.is_none() {
            return Err(Error("candidate file modes are missing".into()));
        }
        lines = lines
            .checked_add(change.added_lines)
            .and_then(|n| n.checked_add(change.removed_lines))
            .ok_or_else(|| Error("changed-line budget overflow".into()))?;
        if lines > task.budgets.max_changed_lines {
            return Err(Error("candidate exceeds changed-line budget".into()));
        }
    }
    Ok(())
}
