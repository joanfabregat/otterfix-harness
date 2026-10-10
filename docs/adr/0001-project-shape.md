# ADR 0001: Portable Rust remediation harness with GitHub-first integration

- Status: Accepted
- Date: 2026-10-09
- Scope: Public component boundaries, portability, and contracts

## Context

Security remediation needs dependency analysis, code changes, and independently checked results. Execution can occur in GitHub Actions, customer infrastructure, or managed workers. Hosting-provider workflows and orchestration should not be embedded in the agent loop.

## Decision

Build an open source Rust CLI and library that receive a prepared workspace, versioned findings, trusted policy, validation requirements, execution capabilities, and budgets. The harness mediates model tools, applies candidate changes, performs bounded repair, requests independent validation, and returns a digest-bound patch and structured evidence. Standalone use requires no commercial account or GitHub credentials.

License the CLI, library, and public contracts uniformly under Apache-2.0. Keep one permissive license across these interfaces so callers can embed or distribute the harness without a separate licensing boundary between contracts and execution code.

| Component | Responsibility |
| --- | --- |
| Harness | Finding ingestion, context/model loop, tool policy, bounded candidate changes and repair, validation results |
| Caller or orchestrator | Acquisition, scanning schedule, task lifecycle, credentials, publication, waiting for external checks, delivery coordination |
| Repository CI/CD | Required checks, review and merge protections, release/deployment authorization, health and recovery |

The model cannot authorize merging, release, deployment, or changes to its own policy. The caller schedules subsequent attempts after CI or deployment feedback instead of keeping an agent process waiting indefinitely. Policy is frozen for an attempt and authorization is rechecked before external effects.

Keep the core independent of hosting-provider payloads. Source acquisition/publication, review, CI, release, and deployment are distinct integration capabilities. Git alone does not provide PRs, required checks, or deployment status. Implement GitHub first; defer other hosting providers until there is a concrete use case. An Actions wrapper and managed-worker execution use the same harness.

## Public contracts

The harness owns versioned finding/task/result contracts. A task binds exact base revision, advisory/package identities, allowed paths and protected paths, policy digest, validation coverage, capabilities, and cumulative budgets. Credentials arrive separately at runtime and are never included in serialized tasks or results. Provider-specific identifiers remain integration metadata.

Results bind base and candidate identities, patch digest, changes and rationale, attempts, intended/resolved versions, validation/scanner provenance and coverage, usage, outcome, and limitations. Preserve scanner evidence alongside normalized findings without including confidential source in public fixtures. A validated candidate is distinct from a merged, released, or runtime-verified fix.

The library and CLI are independently distributable. They do not depend on a private repository, sibling checkout, platform database, or frontend. Public documentation covers supported interfaces, behavior, and security assumptions. Commercial internals, customer data, private integrations, credentials, and internal infrastructure belong outside this repository.

## Consequences

Explicit contracts add versioning and adapter work but retain portable execution and standalone usefulness. Initial support is intentionally narrow: Cargo remediation, Trivy ingestion, configurable API model adapters, and one explicitly configured workload-image update shape. Scope and safety constraints are defined in ADRs 0002 and 0003.

## References

- [GitHub App integrations](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/about-creating-github-apps).
- [GitHub workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).
