# WinHood — Independent Software Audit & Comparative Benchmarking Platform

WinHood Benchmarking is an autonomous, deterministic, full-stack platform for independent software quality auditing, security verification, evidence provenance, and comparative A/B benchmarking.

WinHood operates strictly as an **independent audit, evidence, and benchmarking layer** built around open standards (**SARIF 2.1.0, CWE, OWASP Top 10, CVSS, CycloneDX 1.5, SPDX 2.3**). All core static, taint, secrets, IaC, SCA, Quality Gate, and reporting pipelines run natively without depending on external commercial platforms, while remaining interoperable with external scanners via SARIF 2.1.0 and SonarQube Web APIs.

---

## 1. Core Capabilities

1. **Autonomous & Pluggable Analysis Engine (`src/analyzers/`):**
   - Pipeline: `ParserRegistry` (TypeScript/JavaScript AST via `@babel/parser`, Python/Java/Go/C#/Rust structural parsers) → `RuleRegistry` (`4.3.0`) → `TaintAnalyzer` (cross-file Source → Sink → Sanitizer tracking for SQLi, CMDi, Code Injection, Path Traversal, SSRF `CWE-918`, XSS, Unsafe Deserialization) → `AnalyzerPluginManager` (IaC Terraform/Kubernetes/Dockerfile/GitHub Actions, versioned `SecretsCatalog` with Shannon entropy & redaction) → `SarifCodec` (SARIF 2.1.0 import/export).
   - Bit-for-bit deterministic digest (`deterministicDigestSha256`) for identical inputs and rule catalog versions.
2. **Versioned Actionable Quality Gates (`src/gate/QualityGateEngine.ts`):**
   - Boolean condition gates (`APPROVED`, `APPROVED_WITH_RESERVATIONS`, `BLOCKED`, `INCONCLUSIVE`, `REJECTED`) with gate versioning, gate SHA-256 hashes, CLI exit codes (`0/1/2/3`), SSRF-guarded HMAC-SHA256 webhooks, and GitHub/GitLab/Jenkins PR/MR decoration.
3. **Signed SBOM & SCA License Policy (`src/analyzers/sca/`):**
   - Deterministic **CycloneDX 1.5** and **SPDX 2.3** SBOM generation with per-component SHA-256 hashes, HMAC-SHA256 + Ed25519 signing/verification, CVE/EPSS/CISA KEV correlation, incremental advisory merging, and configurable license compliance policies (`sca:LIC-001`).
4. **Cryptographic Evidence Chain & Audit Reporting (`src/engine/evidenceProvenanceEngine.ts`, `src/reports/`):**
   - Append-only SHA-256 chain + HMAC-SHA256/Ed25519 signed manifest binding `engineVersion`, `rulePackVersions`, `ruleCatalogSha256`, `artifactHashes`, and Quality Gate decision/hash.
   - Multi-format exports: **SARIF 2.1.0**, **PDF (`%PDF-1.4`)**, **HTML**, **JSON**, **CSV**, and **Markdown**.
5. **Traceability & Portfolio Governance (`src/evidence/ComplianceMapper.ts`, `src/engine/portfolioEngine.ts`):**
   - Engineering traceability mapping to OWASP Top 10 (2021), CWE Top 25, PCI DSS v4.0, and ISO/IEC 27001:2022 Annex A (explicitly non-certification).
   - Cross-release score/finding deltas, technical debt tracking, and explicit uncovered scope visibility.
6. **Developer & CI/CD Integrations (`cli/`, `integrations/`, `src/api/openApiSpec.ts`):**
   - SemVer CLI (`4.3.0`), OpenAPI 3.0.3 (`GET /api/openapi.json`), pre-commit hook, GitHub Action, GitLab CI, Jenkins step, VS Code extension, and JetBrains plugin, alongside Windows Electron desktop parity.

---

## 2. Documentation Index

- [`RULE_CATALOG.md`](./RULE_CATALOG.md) — Public catalog of rules, CWE/OWASP/CVSS mappings, secrets patterns & exclusions.
- [`CHANGELOG_RULES.md`](./CHANGELOG_RULES.md) — SemVer breaking-change policy and rule engine changelog.
- [`LIMITATIONS_AND_BIAS.md`](./LIMITATIONS_AND_BIAS.md) — Explicit scope limits, taint reachability bounds, and execution SLAs.
- [`docs/OPENAPI_AND_CLI.md`](./docs/OPENAPI_AND_CLI.md) — OpenAPI 3.0.3 contract, CLI subcommands, exit codes, and IDE/CI integrations.
- [`SECURITY_ARCHITECTURE.md`](./SECURITY_ARCHITECTURE.md) — Auth, CSRF, RBAC, DPAPI/KMS, SSRF guard, upload safety, and sandbox isolation.

---

## 3. Running & Verifying

```bash
# Install dependencies
npm install

# TypeScript check
npm run lint

# Run all unit, security, analyzer, gate, CLI & API integration tests
npm test

# Run tests with Node.js native V8 coverage report
npm run test:coverage

# Start fullstack server (Express API + Vite frontend on port 3000)
npm run dev
```
