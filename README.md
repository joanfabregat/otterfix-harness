# Otterfix Harness

Otterfix Harness is an open source Rust remediation engine: consume normalized security findings, run a bounded API-based agent, and independently validate dependency, code, or configured workload changes.

The core is independent of Git hosting and execution location. GitHub is the first integration target. Callers own acquisition, lifecycle orchestration, publication, and delivery; repository CI/CD retains authoritative checks and deployment approval. Standalone execution requires no commercial service.

Initial scope includes Trivy ingestion, Cargo dependencies, OpenAI and Gemini model adapters, and a narrow configured YAML image-reference update. Every adapter has explicit capabilities and limitations. Read the [architecture decisions](docs/adr/README.md) for the contracts and boundaries. The project currently contains architecture documentation; executable and integration support follow incrementally.
