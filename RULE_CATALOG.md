# WinHood Public Rule & Secrets Catalog

- **Rule Engine Version:** `4.3.0`
- **Secrets Catalog Version:** `2026.11.0`
- **Standards Mapping:** CWE, OWASP Top 10 (2021), CWE Top 25, CVSS v3.x, SARIF 2.1.0

WinHood acts strictly as an **independent audit, evidence, and comparative benchmarking layer** speaking open standards. Every built-in rule carries a stable rule ID, SemVer rule version, CWE/OWASP metadata, CVSS base score, and positive/negative code examples.

> Machine-readable live catalog: `GET /api/rules/catalog` and `GET /api/secrets/catalog` or `npx winhood rules`.

---

## 1. Core Static & Interprocedural Taint Rules

| Rule ID | Severity | CWE | OWASP Top 10 | CVSS | Languages | Version | Summary |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `ts:S3649` | BLOCKER | CWE-89 | A03:2021 | 9.8 | TS, JS | 1.2.0 | SQL Injection via string concatenation/interpolation |
| `taint:S3649` | BLOCKER | CWE-89 | A03:2021 | 9.8 | TS, JS, Python, Java, C#, Go | 2.0.0 | Interprocedural / cross-file SQL Injection (Source → Sink) |
| `ts:S2076` | BLOCKER | CWE-78 | A03:2021 | 9.8 | TS, JS | 1.3.0 | OS Command Injection / dynamic shell invocation |
| `taint:S2076` | BLOCKER | CWE-78 | A03:2021 | 9.8 | TS, JS, Python, Java, Go | 2.0.0 | Interprocedural Command Injection (Source → Sink) |
| `taint:S1523` | BLOCKER | CWE-95 | A03:2021 | 9.4 | TS, JS, Python | 1.1.0 | Interprocedural Code Injection via `eval`/`Function` |
| `taint:S2083` | CRITICAL | CWE-22 | A01:2021 | 8.6 | TS, JS, Python, Java, Go | 1.2.0 | Interprocedural Path Traversal (Source → File Sink) |
| `taint:S5144` | CRITICAL | CWE-918 | A10:2021 | 8.6 | TS, JS, Python, Java, Go | 1.0.0 | Interprocedural SSRF (Source → HTTP Client Sink without SsrfGuard) |
| `taint:S5131` | HIGH | CWE-79 | A03:2021 | 7.5 | TS, JS, Python | 1.1.0 | Reflected / DOM XSS via untrusted data flow |
| `taint:S5135` | CRITICAL | CWE-502 | A08:2021 | 8.8 | Python, Java, TS, JS | 1.0.0 | Unsafe Deserialization (`pickle.loads`, `yaml.load`, `ObjectInputStream`) |
| `crypto:S4790` | HIGH | CWE-328 | A02:2021 | 7.4 | TS, JS, Python, Java, Go | 1.1.0 | Weak hash algorithm (MD5 / SHA-1) |
| `crypto:S2245` | HIGH | CWE-338 | A02:2021 | 7.1 | TS, JS, Python, Java, Go | 1.0.0 | Non-cryptographic PRNG (`Math.random`, `random.random`) in sensitive flow |

---

## 2. Infrastructure as Code (IaC) Plugin Rules (`winhood-iac-core`)

| Rule ID | Target | Severity | CWE | OWASP Top 10 | CVSS | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `iac:TF-001` | Terraform (`.tf`) | CRITICAL | CWE-284 | A05:2021 | 8.2 | Publicly exposed CIDR `0.0.0.0/0` or public S3 ACL |
| `iac:TF-002` | Terraform (`.tf`) | HIGH | CWE-311 | A02:2021 | 7.4 | Storage/volume encryption explicitly disabled |
| `iac:K8S-001` | Kubernetes YAML | CRITICAL | CWE-250 | A05:2021 | 8.4 | Container `privileged: true` or root UID (`runAsUser: 0`) |
| `iac:DOCKER-001` | Dockerfile | HIGH | CWE-250 | A05:2021 | 7.3 | Final stage runs as `USER root` or omits non-root `USER` |
| `iac:GHA-001` | GitHub Actions | CRITICAL | CWE-94 | A08:2021 | 8.8 | Script injection via `${{ github.event.* }}` inside `run:` |
| `iac:GHA-002` | GitHub Actions | HIGH | CWE-829 | A08:2021 | 7.2 | Unpinned third-party action tag instead of full commit SHA |

---

## 3. SCA License Policy & Secrets Catalog (`2026.11.0`)

- **License Policy (`sca:LIC-001`, CWE-1104):** Flags copyleft/denied licenses (`AGPL-3.0`, `GPL-3.0`, `SSPL-1.0`, etc.) against configurable `LicensePolicyConfig`.
- **Secrets Rules:** `sec:S6418-AWS`, `sec:S6418-GH`, `sec:S6418-PEM`, `sec:S6418-JWT`, `sec:S6418-ENTROPY`.
  - **Entropy Filtering:** Validates Shannon entropy (`minShannonEntropy` per rule) to avoid low-entropy constants.
  - **Documented Exclusions:** Ignores `example`, `sample`, `placeholder`, `changeme`, `dummy`, `mock`, `AKIAIOSFODNN7EXAMPLE`, environment lookups (`process.env.*`, `os.environ`, `${VAR}`), and `NOSONAR` / `winhood-ignore-secret` annotations.
  - **Redaction:** Secret values are always masked (`abcd***xyz`) prior to finding storage, evidence hashing, SARIF/PDF export, or UI display.
