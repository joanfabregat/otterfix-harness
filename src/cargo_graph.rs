//! Parse caller-provided `cargo metadata --format-version 1` output.
//! Obtaining metadata may run package tooling and belongs to a trusted executor.
use crate::contracts::Finding;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CargoPackage {
    pub id: String,
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub manifest_path: String,
    pub dependencies: Vec<Value>,
    pub features: Value,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyKind {
    pub kind: Option<String>,
    pub target: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub name: String,
    pub pkg: String,
    pub dep_kinds: Vec<DependencyKind>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveNode {
    pub id: String,
    pub deps: Vec<DependencyEdge>,
    pub features: Vec<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolution {
    pub nodes: Vec<ResolveNode>,
    pub root: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CargoGraph {
    pub version: u32,
    pub packages: Vec<CargoPackage>,
    pub workspace_members: Vec<String>,
    pub resolve: Option<Resolution>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}
impl CargoGraph {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let graph: Self = serde_json::from_slice(bytes)?;
        if graph.version != 1 {
            return Err(Error("unsupported Cargo metadata version".into()));
        }
        let package_ids: BTreeSet<_> = graph.packages.iter().map(|package| &package.id).collect();
        if package_ids.len() != graph.packages.len() {
            return Err(Error("duplicate Cargo package IDs".into()));
        }
        for package in &graph.packages {
            if package.id.is_empty() || package.name.is_empty() || package.version.is_empty() {
                return Err(Error("incomplete Cargo package identity".into()));
            }
        }
        let resolution = graph.resolve.as_ref().ok_or_else(|| {
            Error("complete Cargo resolution is required; --no-deps metadata is unsupported".into())
        })?;
        let node_ids: BTreeSet<_> = resolution.nodes.iter().map(|node| &node.id).collect();
        if node_ids.len() != resolution.nodes.len() {
            return Err(Error("duplicate Cargo resolution nodes".into()));
        }
        for member in &graph.workspace_members {
            if !package_ids.contains(member) || !node_ids.contains(member) {
                return Err(Error("workspace member absent from resolved graph".into()));
            }
        }
        if let Some(root) = &resolution.root {
            if !node_ids.contains(root) {
                return Err(Error("resolution root absent from graph".into()));
            }
        }
        for node in &resolution.nodes {
            if !package_ids.contains(&node.id) {
                return Err(Error("resolution node has no package identity".into()));
            }
            for edge in &node.deps {
                if !package_ids.contains(&edge.pkg)
                    || !node_ids.contains(&edge.pkg)
                    || edge.dep_kinds.is_empty()
                {
                    return Err(Error("incomplete Cargo dependency edge".into()));
                }
            }
        }
        Ok(graph)
    }

    /// Require unambiguous name/version/source mapping; never guess between sources.
    /// Source IDs are opaque exact values approved by the caller, including registries.
    pub fn match_finding<'a>(
        &'a self,
        finding: &Finding,
        allowed_sources: &[String],
    ) -> Result<&'a CargoPackage> {
        if finding.package.ecosystem != "cargo" {
            return Err(Error("unsupported finding ecosystem".into()));
        }
        let matches: Vec<_> = self
            .packages
            .iter()
            .filter(|package| {
                package.name == finding.package.name
                    && package.version == finding.package.installed_version
                    && finding
                        .package
                        .source
                        .as_ref()
                        .is_none_or(|source| package.source.as_ref() == Some(source))
            })
            .collect();
        if matches.len() != 1 {
            return Err(Error(
                "ambiguous or absent Cargo package identity; source evidence required".into(),
            ));
        }
        let package = matches[0];
        let source = package.source.as_ref().ok_or_else(|| {
            Error("local/path package source is unsupported for automatic remediation".into())
        })?;
        if !allowed_sources.contains(source) {
            return Err(Error("Cargo package source is not approved".into()));
        }
        Ok(package)
    }
}
