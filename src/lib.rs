//! Scanner-neutral triage and bounded remediation interfaces.
//!
//! This foundation does not execute repository code, modify files, or establish
//! remediation success. Callers supply trusted policy and execution boundaries.
pub mod candidate;
pub mod cargo_graph;
pub mod contracts;
pub mod policy;
pub mod provider;
pub mod trivy;

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self(format!("invalid JSON contract: {error}"))
    }
}
pub type Result<T> = std::result::Result<T, Error>;
