# WinHood OpenAPI 3.0.3, CLI & CI/IDE Integration Guide

- **API / CLI Version:** `4.3.0` (SemVer)
- **OpenAPI Spec Endpoint:** `GET /api/openapi.json` (and `/openapi.json`)

---

## 1. CLI Usage (`winhood`)

Run directly via `npm run cli -- <command>` or `npx tsx cli/winhood-cli.ts <command>`:

```bash
# 1. Analyze a repository deterministically and emit JSON + SHA-256 deterministic digest
npm run cli -- analyze --path ./src --deterministic --name MyService --software-version 1.2.0

# 2. Evaluate a versioned Quality Gate (returns CI exit code 0/1/2/3)
npm run cli -- gate --path ./src --gate-id winhood-standard-v2 --sarif-out ./winhood.sarif.json

# 3. Generate signed-ready CycloneDX 1.5 / SPDX 2.3 SBOM + license policy check
npm run cli -- sbom --path . --format cyclonedx

# 4. Inspect public versioned rule catalog
npm run cli -- rules

# 5. Import and normalize an external SARIF 2.1.0 report
npm run cli -- sarif-import --input ./external.sarif.json
```

### Actionable CLI Exit Codes
- `0`: Gate `APPROVED` or `APPROVED_WITH_RESERVATIONS` (or utility command succeeded).
- `1`: Gate `BLOCKED` or `REJECTED` — CI/CD pipelines MUST fail the merge/build.
- `2`: Gate `INCONCLUSIVE` — missing required evidence or unverified manifest; requires review.
- `3`: Execution/input error (missing path, malformed arguments, invalid SARIF).

---

## 2. Core REST API Endpoints (OpenAPI 3.0.3)

| Method & Path | Purpose | Auth / RBAC |
| :--- | :--- | :--- |
| `GET /api/health` | Runtime health check (env, port, uptime) | Public |
| `GET /api/openapi.json` | Machine-readable OpenAPI 3.0.3 contract | Public |
| `GET /api/rules/catalog` | Versioned rule catalog, SHA-256 digest & plugins | Authenticated |
| `GET /api/secrets/catalog` | Versioned secret patterns & documented exclusions | Authenticated |
| `POST /api/analyze/sarif` | Run native pipeline or import SARIF 2.1.0 | Authenticated |
| `GET /api/quality-gates` | List versioned Quality Gates and hashes | Authenticated |
| `POST /api/quality-gates` | Register custom versioned Quality Gate | `security:ops` + CSRF |
| `POST /api/quality-gates/evaluate` | Evaluate a gate against a run or finding set | Authenticated |
| `POST /api/webhooks/sign-test` | Sign webhook payload (HMAC-SHA256) / SSRF-guarded dispatch | `security:ops` + CSRF |
| `GET /api/compliance/:runId/matrix` | Non-certification OWASP/CWE/PCI/ISO traceability matrix | Authenticated |
| `GET /api/portfolio/summary` | Cross-release deltas, debt & uncovered scope summary | Authenticated |
| `GET /api/runs/:runId/sbom` | Signed CycloneDX 1.5 / SPDX 2.3 SBOM + signature proof | Authenticated |
| `GET /api/reports/:runId/export` | Export `json`, `sarif`, `html`, `pdf`, `csv`, `md` | Authenticated |
| `POST /api/integrations/pr-decoration` | Generate GitHub/GitLab/Jenkins PR/MR markdown comment | Authenticated |

---

## 3. Developer Workflow Integrations (`integrations/`)

- **Pre-commit Hook:** `integrations/pre-commit/.pre-commit-hooks.yaml`
- **GitHub Action:** `integrations/github-action/action.yml`
- **GitLab CI Template:** `integrations/gitlab/winhood-gitlab-ci.yml`
- **Jenkins Pipeline & Step:** `integrations/jenkins/Jenkinsfile` & `WinHoodGateStep.groovy`
- **VS Code Extension:** `packages/vscode-extension/` (diagnostics + status bar Quality Gate state)
- **JetBrains / IntelliJ Plugin:** `integrations/jetbrains/` (`WinHoodAuditAction.kt`)

### Desktop (Offline Electron) vs Server Parity
Both the Electron desktop app (`electron-main.ts`) and web/CI server (`server.ts`) execute the exact same deterministic `AnalyzerRegistry`, `QualityGateEngine`, `SbomGenerator`, `ComplianceMapper`, and `EvidenceProvenanceEngine` code paths, producing identical deterministic digests for identical inputs.
