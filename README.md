# WinHood — Independent Software Audit & Comparative Benchmarking Platform

![Test Coverage](https://img.shields.io/badge/coverage-96.4%25-brightgreen)
![Critical Motors Coverage](https://img.shields.io/badge/scoring%20%7C%20evidence%20%7C%20comparability-%E2%89%A595%25-success)
![Open Standards](https://img.shields.io/badge/standards-SARIF%202.1.0%20%7C%20CWE%20%7C%20OWASP%20%7C%20CVSS%20%7C%20CycloneDX%20%7C%20SPDX-blue)
![Version](https://img.shields.io/badge/version-4.4.0-0ea5e9)

WinHood Benchmarking is an autonomous, deterministic, full-stack platform for independent software quality auditing, security verification, cryptographic evidence provenance, and comparative A/B benchmarking.

WinHood operates strictly as an **independent audit, evidence, and comparative benchmarking category** built around open standards (**SARIF 2.1.0, CWE, OWASP Top 10, CVSS, CycloneDX 1.5, SPDX 2.3**). All static AST, dataflow/taint, secrets, IaC, SCA, Quality Gate, and reporting pipelines execute natively without anchoring on third-party products, while remaining fully interoperable with any **ferramentas que exportam SARIF 2.1.0**.

---

## 1. Core Capabilities

1. **Autonomous Analysis Engine in Modo MQR (`src/analyzers/`):**
   - Pipeline: `ParserRegistry` (TypeScript/JavaScript AST via `@babel/parser`, Python/Java/Go/C#/Rust/SQL structural parsers) → `RuleRegistry` (`4.4.0`) → `TaintAnalyzer` (interprocedural Source → Sink → Sanitizer tracking for SQLi, CMDi, Code Injection, Path Traversal, SSRF `CWE-918`, XSS, Unsafe Deserialization) → `AnalyzerPluginManager` (IaC Terraform/Kubernetes/Dockerfile/CI workflows, versioned `SecretsCatalog` with Shannon entropy & redaction) → `SarifCodec` (SARIF 2.1.0 import/export).
   - Evaluates findings under **Modo MQR (Modern Quality Regime)** and **Perfil de Qualidade Estrita**, classifying impacts across Security, Reliability, and Maintainability with bit-for-bit deterministic digests (`deterministicDigestSha256`).
2. **Versioned Actionable Quality Gates (`src/gate/QualityGateEngine.ts`):**
   - Boolean condition gates (`APPROVED`, `APPROVED_WITH_RESERVATIONS`, `BLOCKED`, `INCONCLUSIVE`, `REJECTED`) with gate versioning, SHA-256 gate hashes, canonical CI exit codes (`0/1/2/3/4`), SSRF-guarded `HMAC-SHA256` webhooks, and automated PR/MR decoration.
3. **Signed SBOM & SCA License Policy (`src/analyzers/sca/`):**
   - Deterministic **CycloneDX 1.5** and **SPDX 2.3** SBOM generation with per-component SHA-256 hashes, `HMAC-SHA256` + `Ed25519` signing/verification, CVE/EPSS/CISA KEV correlation, incremental advisory merging, and license compliance enforcement (`sca:LIC-001`).
4. **Cryptographic Evidence Chain & Multi-Format Signed Reports (`src/evidence/`, `src/reports/ReportExporter.ts`):**
   - Append-only SHA-256 chain + `HMAC-SHA256`/`Ed25519` signed manifest binding `engineVersion`, `ruleCatalogVersion`, `ruleCatalogSha256`, `codeHashSha256`, `artifactHashes`, and applied Quality Gate version/hash.
   - Multi-format CLI and API exports (`winhood report --format=pdf|html|sarif|json`): **SARIF 2.1.0**, **JSON**, **Self-Contained HTML5** (inline CSS, zero external requests), and **Signed Binary PDF (`%PDF-1.4`)** with embedded `Report-SHA256` and `Report-HMAC-SHA256` verification.
   - Reference report artifacts published in [`examples/reports/`](./examples/reports/).
5. **Developer Daily Workflow — VS Code Extension MVP (`packages/vscode-extension/`):**
   - Commands `Winhood: Analisar arquivo atual` and `Winhood: Analisar workspace`, inline Problems diagnostics (`CWE`, `OWASP Top 10`, line/column), contextual Hover with remediation & rule catalog links, deterministic `Quick Fix` Code Actions, semantic Status Bar item (green/yellow/red/gray), and automatic offline CLI fallback.
   - Visual demonstration of inline finding, Hover remediation, Quick Fix, and Quality Gate status bar:
   
   ![WinHood VS Code Extension Demo](./packages/vscode-extension/demo-vscode-gate.svg)

6. **Plug-and-Play CI/CD Connectors (`integrations/`, `templates/`, `examples/`):**
   - Official GitHub Action ([`integrations/github-action/action.yml`](./integrations/github-action/action.yml)), GitLab CI Component ([`templates/winhood.gitlab-ci.yml`](./templates/winhood.gitlab-ci.yml)), Jenkins Shared Library (`winhoodAnalyze()` & `winhoodGate()` in [`integrations/jenkins/vars/`](./integrations/jenkins/vars/)), and ready-to-use pipeline examples in [`examples/`](./examples/).

---

## 2. Documentation & Active Transparency Index

- **Identity & Terminology:**
  - [`GLOSSARY.md`](./GLOSSARY.md) — Canonical definitions of **Modo MQR (Modern Quality Regime)**, **Perfil de Qualidade Estrita**, **Motor de Veracidade**, **Comparabilidade**, **Confiança da Evidência**, and **Quality Gate States**.
  - [`MQR_METHODOLOGY.md`](./MQR_METHODOLOGY.md) — Multi-attribute quality evaluation, Overall vs. New Code, and separated coverage methodology.
- **Transparency, Limitations, Biases & Confidence Model:**
  - [`docs/LIMITATIONS.md`](./docs/LIMITATIONS.md) — Explicit technical boundaries per analysis mode (SAST/Taint, Secrets, SCA, SBOM, IaC, Comparability, and Cryptographic Evidence guarantees).
  - [`docs/BIASES.md`](./docs/BIASES.md) — Known scoring biases (repository scale, language depth, missing data, single-rule flooding) and mathematical mitigations.
  - [`docs/CONFIDENCE_MODEL.md`](./docs/CONFIDENCE_MODEL.md) — Formal mathematical formula and interpretation guide for **Confiança da Evidência (`HIGH`, `MEDIUM`, `LOW`)**.
  - [`LIMITATIONS_AND_BIAS.md`](./LIMITATIONS_AND_BIAS.md) — Operational SLAs and reachability bounds.
- **Contracts, Integrations & Governance:**
  - [`API_REFERENCE.md`](./API_REFERENCE.md) & [`docs/OPENAPI_AND_CLI.md`](./docs/OPENAPI_AND_CLI.md) — OpenAPI 3.0.3 specification, CLI subcommands, and SARIF 2.1.0 contract.
  - [`IDE_INTEGRATION.md`](./IDE_INTEGRATION.md) — VS Code extension (`packages/vscode-extension`) and IDE integration guide.
  - [`EXTERNAL_INTEGRATION.md`](./EXTERNAL_INTEGRATION.md) & [`EXTERNAL_TOOLS.md`](./EXTERNAL_TOOLS.md) — Open-standard interoperability with ferramentas que exportam SARIF 2.1.0, CycloneDX 1.5, SPDX 2.3, and LCOV/Cobertura.
  - [`docs/CI_INTEGRATION.md`](./docs/CI_INTEGRATION.md) — Canonical CI exit codes (`0..4`), GitHub Action, GitLab Component, Jenkins Shared Library, and signed webhook validation in Node.js, Python, and Go.
  - [`RULE_CATALOG.md`](./RULE_CATALOG.md) & [`CHANGELOG_RULES.md`](./CHANGELOG_RULES.md) — Public catalog of rules and SemVer policy.
  - [`CHANGELOG.md`](./CHANGELOG.md) & [`docs/MIGRATION.md`](./docs/MIGRATION.md) — Iteration changelog and configuration migration guide.
  - [`SECURITY_ARCHITECTURE.md`](./SECURITY_ARCHITECTURE.md) — Auth, CSRF, RBAC, DPAPI/KMS, SSRF guard, upload safety, and sandbox isolation.

---

## 3. Running & Verifying

```bash
# Install dependencies
npm install

# TypeScript check
npm run lint

# Run all unit, security, analyzer, gate, CLI, API & IDE extension integration tests
npm test

# Run test suite with coverage gate (>=80% global, >=95% in src/scoring, src/evidence, src/comparability)
npm run test:coverage

# Generate audit reports in all 4 formats (PDF, HTML, SARIF, JSON)
npx tsx cli/winhood-cli.ts report --format=pdf --path ./src/gate --out report.pdf
npx tsx cli/winhood-cli.ts report --format=html --path ./src/gate --out report.html
npx tsx cli/winhood-cli.ts report --format=sarif --path ./src/gate --out report.sarif
npx tsx cli/winhood-cli.ts report --format=json --path ./src/gate --out report.json

# Start fullstack server (Express API + Vite frontend on port 3000)
npm run dev
```
