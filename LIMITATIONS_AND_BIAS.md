# WinHood Limitations, Analysis Boundaries & Execution SLAs

Transparency is a core engineering requirement of WinHood Benchmarking. Every score, finding, and gate decision must be interpreted within the documented technical limits below.

---

## 1. Static & Interprocedural Taint Analysis Boundaries

- **AST & Structural Parsers (`ParserRegistry`):**
  - **TypeScript / JavaScript / JSX / TSX:** Full AST parsed via `@babel/parser`. Dynamic property access via bracket notation (`obj[dynamicKey]`), `eval`-generated code, or runtime monkey-patching cannot be resolved statically.
  - **Python, Java, Go, C#, Rust:** Analyzed via deterministic structural parsers tracking function definitions, parameter signatures, call edges, return bindings, and explicit sanitizer invocations. Complex reflection, metaprogramming, macros, or dynamic dependency injection wiring outside direct symbol imports are marked out of static reach.
- **Interprocedural Call Graph Depth (`TaintAnalyzer`):**
  - Cross-file and intra-file taint propagation traverses direct imports and symbol call graphs up to **2 interprocedural hops**.
  - Sanitizer recognition covers parameterized DB APIs, `SsrfGuard`, `path.basename` / canonical root containment checks, DOMPurify/HTML escaping, and `yaml.safe_load`. Custom wrappers without explicit sanitizer signatures may yield false positives until registered.
  - Multi-hop data flows crossing external message queues (Kafka/RabbitMQ), reflection, or native C/JNI FFI boundaries are **not traced statically** (`NOT_MEASURED` for cross-process runtime taint).

---

## 2. Secrets & SCA Boundaries

- **Secrets (`SecretScanner`):**
  - Uses versioned regex signatures + Shannon entropy thresholds (`minShannonEntropy` ≥ `2.5–3.8` bits/char).
  - *Expected False Positive / False Negative Trade-off:* High-entropy base64 test vectors not annotated with placeholder markers may trigger `MEDIUM` confidence alerts (`sec:S6418-ENTROPY`). Conversely, short custom tokens (< 14 characters) or non-standard secret formats outside the catalog are not flagged without pattern rules.
  - Live credential validation against third-party providers is **never executed automatically** without explicit opt-in (`validationMethod: OPT_IN_PROVIDER_PING` remains `FORMAT_CHECKSUM_ONLY` offline).
- **SCA & SBOM (`SbomGenerator`, `ScaCorrelator`):**
  - Extracts dependencies strictly from manifest/lockfiles present in the ingested tree (`package.json`, `package-lock.json`, `requirements.txt`, `pyproject.toml`, `pom.xml`, `go.mod`, `Cargo.toml`, `*.csproj`).
  - Lockfile-less projects only report direct dependencies (`TRANSITIVE` coverage marked partial).

---

## 3. Compliance Traceability Boundaries

- `ComplianceMapper` maps static findings to **OWASP Top 10 (2021)**, **CWE Top 25**, **PCI DSS v4.0**, and **ISO/IEC 27001:2022 Annex A** strictly as engineering traceability.
- **Absence of static findings in a control MUST NEVER be interpreted as formal compliance or certification.** Organizational, procedural, physical, and runtime controls cannot be verified by source analysis alone.

---

## 4. Dynamic Sandbox & Performance Boundaries

- Unverified/untrusted submitted code is **never** executed in the WinHood host Node.js process.
- Dynamic test and performance benchmarks depend on an available, verified sandbox runner (`SandboxExecutor`). When no OS-level container/sandbox isolation is available, dynamic checks report `NOT_MEASURED` rather than passing or failing silently.

---

## 5. Execution SLAs & Time Budgets

| Analysis Stage | Default Budget (`slaBudgetMs`) | Behavior on Exceeding Budget |
| :--- | :--- | :--- |
| Native AST + Built-in Rules | `45,000 ms` per run | Reports `PARTIAL` scope coverage with explicit timeout note |
| Pluggable Plugin (`AnalyzerPluginManager`) | `5,000 ms` per plugin | Plugin marks `timedOut: true`, returns partial findings safely |
| Cross-file Taint Analysis | `20,000 ms` per software | Caps call-graph expansion deterministically |
| Controlled Test / Perf Runner | `15,000 ms` per target | Terminates child process cleanly; marks metric `FAILED` / `INCONCLUSIVE` |
