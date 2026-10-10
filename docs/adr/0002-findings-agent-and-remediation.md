# ADR 0002: Normalized findings and a bounded API-based remediation agent

- Status: Cargo, OpenAI, and Gemini initial scope accepted; detailed policies and provider transport proposed
- Date: 2026-10-09
- Scope: Scanner independence, model/tool contracts, strategy selection, and verification

## Context

The agent must understand scanner findings, dependency relationships, and application/infrastructure context. It cannot establish package identity, compatibility, or remediation success solely through its own explanation. Scanner and model independence require explicit contracts rather than asking the model to guess arbitrary report formats.

## Decision

Normalize findings through scanner adapters before agent execution. Implement Trivy first and preserve raw reports. A finding contains advisory identifiers/aliases, category, package/resource identity and source, installed version, applicable ranges/fix candidates, dependency/location information, scanned revision or image digest, scanner/database/configuration provenance, coverage, and references. Unsupported formats, identities, and categories produce explicit outcomes. Not every finding has a CVE or NVD entry.

Managed enrichment belongs to the platform. Preserve CVSS source/vector/version, EPSS probability and observation date, and KEV membership/catalog provenance independently. Missing, stale, and conflicting evidence must remain visible. A policy decision records its version, evaluation time, intelligence snapshot, selected action, and reason. No numeric score establishes permission to perform a disruptive upgrade or deploy.

Implement a small Rust agent loop with OpenAI and Gemini API adapters in the initial scope. Gemini transport and model identifiers are configurable; provider authentication remains outside repository tools. Otterfix supplies context and tool definitions, validates requests, runs authorized tools, and sends results back. Keep provider-specific conversation continuation and usage accounting in the adapter. Context limits, cancellation, output limits, model-call limits, and cumulative budgets are enforced outside the model. An Anthropic or existing-agent/ACP adapter may follow.

Expose a narrow initial tool surface: read findings/files, search the workspace, inspect dependencies, retrieve approved documentation, apply patches, run sandbox commands, request trusted validation, and submit a candidate. Shell execution is available only inside the execution boundary. The model cannot choose host mounts, credentials, execution images, Git remotes, deployment targets, or authorization policy. Repository files, logs, reports, and retrieved documents are untrusted inputs even when relevant to the task.

## Remediation scope

Cargo is the first application ecosystem. Graph resolution must account for workspace members, sources, duplicate versions, dependency kinds, features, and target conditions through package-manager metadata rather than scanner findings alone. Unsupported sources/identities escalate. The first infrastructure slice is a configured YAML workload image reference with an explicit owning repository/path/resource and independently resolved image digest. General Kubernetes discovery, arbitrary IaC changes, Helm/operator migration, and stateful major upgrades are deferred.

A fixed-version field supplies candidates, not guaranteed feasible updates. Verify package source, affected ranges, available versions, parent constraints, and actual resolution. First enforce policy, then prefer compatible lockfile updates, compatible direct/parent upgrades, and explicitly allowed major-upgrade proposals with source adaptation. Rank feasible candidates by disruption and evidence rather than LLM confidence alone. Overrides and dependency replacement are deferred; Cargo `[patch]` is not a generic transitive version override.

Group findings requiring the same dependency-root change. Keep unrelated roots separate initially. Correlate attempts with repository, base revision, manifest/resource, package identity, and advisory aliases; serialize overlapping changes. Preserve no-fix, unsupported, policy-excluded, and already-resolved outcomes rather than counting them as successful fixes.

## Validation and repair

Read required validation commands from trusted configuration, never from candidate-modified policy. Run build/tests/lint and security verification for the complete candidate with configured feature/target coverage. Missing required validation is not success. Protect tests, assertions, snapshots, scanner suppressions, workflows, agent configuration, credentials, and policy from automatic modification in the MVP. Explicit workload configuration paths may be changed for authorized infrastructure tasks. Needed test adaptations escalate with evidence.

Compare trusted baseline and candidate with the same scanner version, database snapshot, configuration, and coverage. Reproduce supplied findings before acting, verify intended versions resolved, verify targeted package/advisory instances are gone, and reject newly introduced findings forbidden by policy. A fresh policy scan is required before authorized merge; changes to base, policy, candidate, or evidence validity invalidate eligibility. Trivy excludes Cargo developer dependencies when scanning the manifest and lockfile together; report this coverage limitation rather than implying a clean scan secures every build/test dependency.

Use three total candidate/repair attempts and a 30-minute attempt wall-clock limit as proposed defaults, with configurable model/compute ceilings, output limits, changed-path/file/patch limits, and subprocess limits. All model calls and subprocesses consume cumulative attempt budgets; new CI/deployment repair attempts also consume the platform's remediation/account budgets. Terminate tools on cancellation. Provider-side completion/accounting can race cancellation, so reserve worst-case permitted call costs rather than treating cancellation as zero cost.

A result is a digest-bound patch plus structured evidence and limitations. A successful build is evidence within tested coverage, not proof of behavioral equivalence or absence of every vulnerability. The publisher and authoritative repository CI remain independent gates.

## Alternatives and consequences

Wrapping an unrestricted coding-agent CLI could shorten initial development but would complicate tool mediation and credential isolation. A purpose-built API loop adds context-management and provider-adapter work but lets Otterfix control the actual capabilities. Support two initial model providers behind one contract; additional ecosystems and adapters are deferred.

## References

- [OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling).
- [Claude tool use](https://platform.claude.com/docs/en/agents-and-tools/tool-use/how-tool-use-works).
- [Cargo metadata](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html).
- [Trivy Cargo coverage](https://trivy.dev/docs/latest/coverage/language/rust/).
- [FIRST EPSS](https://www.first.org/epss/).
