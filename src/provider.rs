//! Provider-neutral bounded loop. Live HTTP adapters are not implemented.
//! Provider and executor implementations MUST honor the deadline/cancellation
//! context while running; this synchronous core cannot terminate their threads.
use crate::contracts::Budgets;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "tool", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolRequest {
    ReadFinding { instance_id: String },
    ReadFile { path: String },
    Search { query: String },
    InspectDependency { package_id: String },
    RetrieveDocumentation { reference_id: String },
    ApplyPatch { patch: String },
    RunCommand { capability_id: String },
    RequestValidation { capability_id: String },
    SubmitCandidate { candidate_digest: String },
}
impl ToolRequest {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ReadFinding { .. } => "read_finding",
            Self::ReadFile { .. } => "read_file",
            Self::Search { .. } => "search",
            Self::InspectDependency { .. } => "inspect_dependency",
            Self::RetrieveDocumentation { .. } => "retrieve_documentation",
            Self::ApplyPatch { .. } => "apply_patch",
            Self::RunCommand { .. } => "run_command",
            Self::RequestValidation { .. } => "request_validation",
            Self::SubmitCandidate { .. } => "submit_candidate",
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    pub id: String,
    pub request: ToolRequest,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolReply {
    pub id: String,
    pub output: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderTurn {
    /// Adapter-owned conversation continuation; untrusted, not an authorization.
    pub continuation: Option<Value>,
    pub calls: Vec<ToolCall>,
    pub final_text: Option<String>,
}
pub struct CallContext<'a> {
    pub deadline: Instant,
    pub cancelled: &'a AtomicBool,
    pub max_response_bytes: u64,
}
impl CallContext<'_> {
    pub fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) {
            Err(Error("cancelled".into()))
        } else if Instant::now() >= self.deadline {
            Err(Error("wall-clock budget exceeded".into()))
        } else {
            Ok(())
        }
    }
}
/// Credentials stay in the implementation; they are never serialized in tasks.
/// Adapters enforce response limits during receipt, before JSON parsing/allocation.
pub trait Provider {
    fn next(
        &mut self,
        continuation: Option<&Value>,
        replies: &[ToolReply],
        context: &CallContext<'_>,
    ) -> Result<ProviderTurn>;
}
/// A caller-owned supervisor validates tool arguments and trusted capability IDs,
/// protects paths, and executes exclusively inside its reviewed execution boundary.
/// Returned output is bounded and untrusted. Unsupported tools fail closed.
pub trait ToolExecutor {
    fn execute(&mut self, request: &ToolRequest, context: &CallContext<'_>) -> Result<Value>;
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    OpenAi,
    Gemini,
}
/// Explicit placeholder. Neither OpenAI nor Gemini has a live transport yet.
/// Gemini authentication/transport selection is left to a later adapter design.
pub struct UnsupportedProvider(pub ProviderKind);
impl Provider for UnsupportedProvider {
    fn next(
        &mut self,
        _: Option<&Value>,
        _: &[ToolReply],
        _: &CallContext<'_>,
    ) -> Result<ProviderTurn> {
        Err(Error(format!(
            "{:?} live transport is not implemented",
            self.0
        )))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoopResult {
    pub final_text: String,
    pub model_calls: u32,
    pub tool_calls: u32,
    pub output_bytes: u64,
}
/// Budget accounting counts every provider response and executor output, including
/// continuation state. Model/tool calls are reserved before invocation. No repair
/// attempts or security validation are implied by completion of this loop.
pub fn run(
    provider: &mut impl Provider,
    executor: &mut impl ToolExecutor,
    allowed_tools: &[String],
    capability_ids: &[String],
    budgets: &Budgets,
    cancelled: &AtomicBool,
) -> Result<LoopResult> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(budgets.max_wall_seconds))
        .ok_or_else(|| Error("invalid wall-clock budget".into()))?;
    let mut continuation = None;
    let mut replies = Vec::new();
    let mut model_calls = 0;
    let mut tool_calls = 0;
    let mut output_bytes = 0_u64;
    loop {
        let context = CallContext {
            deadline,
            cancelled,
            max_response_bytes: budgets.max_output_bytes.saturating_sub(output_bytes),
        };
        context.check()?;
        if model_calls >= budgets.max_model_calls {
            return Err(Error("model-call budget exceeded".into()));
        }
        model_calls += 1;
        let turn = provider.next(continuation.as_ref(), &replies, &context)?;
        context.check()?;
        output_bytes = output_bytes
            .checked_add(serde_json::to_vec(&turn)?.len() as u64)
            .ok_or_else(|| Error("output budget overflow".into()))?;
        if output_bytes > budgets.max_output_bytes {
            return Err(Error("output-byte budget exceeded".into()));
        }
        if turn.calls.is_empty() {
            return Ok(LoopResult {
                final_text: turn.final_text.ok_or_else(|| {
                    Error("provider returned neither tools nor completion".into())
                })?,
                model_calls,
                tool_calls,
                output_bytes,
            });
        }
        if turn.final_text.is_some() {
            return Err(Error(
                "provider returned both completion and tool calls".into(),
            ));
        }
        // Validate the entire turn before executing any tool in it.
        let mut ids = std::collections::BTreeSet::new();
        for call in &turn.calls {
            if call.id.is_empty() || !ids.insert(&call.id) {
                return Err(Error("duplicate or empty tool call ID".into()));
            }
            if !allowed_tools.iter().any(|name| name == call.request.name()) {
                return Err(Error("tool is not authorized".into()));
            }
            match &call.request {
                ToolRequest::RunCommand { capability_id }
                | ToolRequest::RequestValidation { capability_id }
                    if !capability_ids.contains(capability_id) =>
                {
                    return Err(Error("execution capability is not authorized".into()))
                }
                ToolRequest::ReadFile { path } if !crate::candidate::valid_relative_path(path) => {
                    return Err(Error("unsafe file path".into()))
                }
                _ => {}
            }
        }
        if turn.calls.len() > budgets.max_tool_calls.saturating_sub(tool_calls) as usize {
            return Err(Error("tool-call budget exceeded".into()));
        }
        replies.clear();
        for call in turn.calls {
            let context = CallContext {
                deadline,
                cancelled,
                max_response_bytes: budgets.max_output_bytes.saturating_sub(output_bytes),
            };
            context.check()?;
            tool_calls += 1;
            let output = executor.execute(&call.request, &context)?;
            context.check()?;
            let reply = ToolReply {
                id: call.id,
                output,
            };
            output_bytes = output_bytes
                .checked_add(serde_json::to_vec(&reply)?.len() as u64)
                .ok_or_else(|| Error("output budget overflow".into()))?;
            if output_bytes > budgets.max_output_bytes {
                return Err(Error("output-byte budget exceeded".into()));
            }
            replies.push(reply);
        }
        continuation = turn.continuation;
    }
}
