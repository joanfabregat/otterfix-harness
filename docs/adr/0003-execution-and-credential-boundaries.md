# ADR 0003: Supervised disposable execution and separate publication

- Status: Accepted for boundaries; executor implementations remain incremental
- Date: 2026-10-09
- Scope: Execution capabilities, credentials, validation, and publication

## Context

Source scanning parses untrusted confidential inputs. Package tooling and tests execute repository and dependency code. An ephemeral runner or container does not protect secrets mounted into that same environment. The model must not choose privileges or runtime configuration.

## Decision

Separate trusted orchestration, repository execution, and publication. A trusted supervisor maps capability IDs to prepared workspaces, approved images/tool versions, mounts, network profiles, resource limits, and lifetimes. Model requests cannot supply host paths, runtime flags, images, credentials, remotes, or arbitrary host commands. Tool output remains bounded untrusted data.

| Role | Access and boundary |
| --- | --- |
| Acquisition | Scoped source/registry read access; credentials removed before scanning and tools |
| Scanner | Prepared source/images and read-only database snapshot; no signing or deployment credentials |
| Harness/controller | Model connection and bounded execution interface; does not execute repository tooling in its credential environment |
| Repository tools | Per-task workspace and selected immutable caches; no model key, database access, GitHub write token, cloud credentials, or runtime/signing socket |
| Publisher | Independently verified candidate, fresh trusted checkout, scoped write capability and signing; never executes candidate code |
| Deployment | Repository-owned workflow and authorized artifact/environment; independent approvals and recovery |

Acquire dependencies with lifecycle/build hooks disabled where supported and audit before execution. Build and test offline against immutable caches. Do not reuse caches writable by untrusted execution. Acquire scanner databases separately and hold scanner version, database, configuration, and coverage fixed for baseline/candidate comparison. Network-enabled tooling is an explicit capability with documented egress limitations.

Freeze candidates before independent verification/publication. Verify the complete diff, base identity, digest, path traversal, symlinks, modes, limits, and protected paths. Publication is outside the agent's tool surface. Sign commits using an independently authorized publisher identity; a signature establishes identity rather than correctness.

## Executor interface

Expose bounded command tickets and structured results, including operation identity, exit status, output truncation, elapsed time, validation provenance, and cancellation outcome. Caller-owned executor implementations can use disposable containers, CI runners, or isolated machines. The core does not require a particular container runtime, Kubernetes, or access to its orchestration API.

Cancellation terminates subprocesses and records cleanup failures. A result cannot claim validation passed if required tools timed out, were skipped, or returned incomplete evidence. Unsupported capabilities produce explicit failures rather than falling back to unrestricted execution.

## Deployment assumptions

Controlled development fixtures can use constrained containers. Shared-kernel containers are not a hostile tenant boundary. Deployments processing hostile repositories need isolated disposable machines or an equivalently reviewed boundary, separated from control-plane services and credentials. A GitHub-hosted runner is not sufficient if privileged secrets are exposed to candidate code in the same job.

Production credentials, live-cluster access, and generic rollback remain outside the agent. Infra remediation changes configured desired state and uses independently authorized delivery workflows. Stateful changes require explicit compatibility, data-migration, backup, and recovery plans.

## Consequences

The harness can enforce policy and mediate capabilities, but the caller must implement and verify its execution boundary. Executor conformance tests and honest provenance are required; a configured sandbox label does not prove isolation. Internal installation topology and credential provisioning are documented by each deployment outside this public interface specification.
