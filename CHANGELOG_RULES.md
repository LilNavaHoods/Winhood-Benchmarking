# WinHood Rule Engine & Policy Changelog

## SemVer Policy for Rules & Gates

WinHood applies strict Semantic Versioning (`MAJOR.MINOR.PATCH`) to both the Rule Engine (`RULE_ENGINE_VERSION`) and individual Quality Gates (`QualityGateDefinition.version`):

1. **MAJOR (`X.0.0`) — Breaking Changes:**
   - Removal or renaming of a stable `ruleId`.
   - Severity escalation of an existing rule from non-blocking (`LOW`/`MEDIUM`) to `BLOCKER`/`CRITICAL` in default gates.
   - Structural changes to deterministic digest or scoring normalization weights.
2. **MINOR (`0.X.0`) — Backward-Compatible Additions:**
   - New rules, language parsers, IaC plugins, or new CWE/OWASP mappings.
   - New optional metadata fields on SARIF 2.1.0 or SBOM envelopes.
3. **PATCH (`0.0.X`) — Precision & Bug Fixes:**
   - False-positive exclusions, sanitizer recognizers, and documentation clarifications.

---

## Release History

### `4.3.0` (2026-11-14)
- **Added (`AnalyzerPluginManager`):** Pluggable `AnalyzerPlugin` architecture with per-plugin SLA time budgets (`slaBudgetMs`).
- **Added (`taint:S5144` / CWE-918):** Cross-file SSRF taint tracking for TS/JS, Python, Java, and Go, with automatic `SsrfGuard` sanitizer recognition.
- **Added (`IacAnalyzerPlugin`):** Native Terraform (`.tf`), Kubernetes manifests, `Dockerfile`, and GitHub Actions workflow checks.
- **Added (`SecretScanner` `2026.11.0`):** Versioned public secrets catalog with Shannon entropy scoring, documented false-positive exclusions, and deterministic redaction.
- **Added (`SarifCodec`):** Bidirectional SARIF 2.1.0 export/import with `codeFlows` and strict schema validation.
- **Added (`QualityGateEngine` v2):** Versioned gates (`winhood-standard-v2`, `winhood-zero-trust-v2`, `winhood-release-audit-v1`), CLI exit codes (`0/1/2/3`), signed webhooks, and PR/MR decoration.
- **Added (`SbomGenerator` + `ScaCorrelator`):** Deterministic SBOM mode, per-component SHA-256 digests, HMAC-SHA256 + Ed25519 SBOM signatures, license policy checks (`sca:LIC-001`), and incremental CVE advisory merge.
- **Extended (`SignedEvidenceManifest`):** Manifest payload hash now binds `engineVersion`, `rulePackVersions`, `ruleCatalogSha256`, `artifactHashes`, `gateDecision`, `gateVersion`, and `gateHash`.

### `4.0.0` (2026-11-11)
- Introduced formal measurement provenance states (`MEASURED`, `STATIC_DERIVED`, `IMPORTED`, `NOT_MEASURED`), 19-point veracity matrix, and `BenchmarkMatcher` fairness gate.

### `3.0.0` (2026-11-09)
- Initial MQR scoring model, 12 weighted dimensions, and HMAC-SHA256 append-only evidence chain.
