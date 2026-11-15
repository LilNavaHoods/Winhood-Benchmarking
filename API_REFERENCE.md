# Referência de Contratos de API do WinHood (`API_REFERENCE.md`)

Este documento descreve exclusivamente os contratos HTTP REST e formatos de intercâmbio do **WinHood Benchmarking** (`OpenAPI 3.0.3`, `SARIF 2.1.0`, `CycloneDX 1.5`, `SPDX 2.3`).

---

## 1. Especificação OpenAPI 3.0.3

- **Endpoint Público:** `GET /api/openapi.json`
- **Health Check Determinístico:** `GET /api/health`
- **Autenticação:** Cookie de sessão `HttpOnly` + cabeçalho `X-WinHood-CSRF` para operações mutáveis na interface web, ou `Authorization: Bearer <token>` para integrações de IDE e CI/CD.

---

## 2. Endpoints Principais de Análise, Quality Gate e Evidências

| Método e Rota | Descrição Técnica | Padrão Aberto / Contrato |
| :--- | :--- | :--- |
| `POST /api/analyze/sarif` | Executa o pipeline nativo AST + Taint + Segredos + IaC + SCA sobre um mapa de arquivos e retorna o relatório SARIF e a avaliação do gate. | `SARIF 2.1.0` |
| `GET /api/rules/catalog` | Retorna o catálogo versionado de regras com mapeamentos `CWE`, `OWASP Top 10 (2021)` e `CVSS v3.1`. | `CWE / OWASP / CVSS` |
| `GET /api/secrets/catalog` | Retorna o catálogo versionado de detecção de segredos e regras de entropia de Shannon. | Catálogo WinHood |
| `GET /api/quality-gates` | Lista os perfis versionados de Quality Gate (`winhood-standard-v2`, `winhood-zero-trust-v2`). | Gate Engine v2 |
| `POST /api/quality-gates/evaluate` | Avalia uma execução (`runId`) contra um Quality Gate versionado e retorna `gateHash` SHA-256. | Gate Engine v2 |
| `GET /api/runs/:runId/sbom` | Exporta a árvore de dependências assinada criptograficamente (`?format=cyclonedx\|spdx`). | `CycloneDX 1.5` / `SPDX 2.3` |
| `GET /api/reports/:runId/export` | Exporta relatórios auditáveis e assinados (`?format=pdf\|html\|sarif\|json\|md\|csv`). | `PDF 1.4` / `HTML` / `SARIF 2.1.0` / `JSON` |
| `GET /api/compliance/:runId/matrix` | Matriz de rastreabilidade técnica (não certificadora) para OWASP Top 10, CWE Top 25, PCI DSS v4.0 e ISO/IEC 27001. | Rastreabilidade Técnica |
| `POST /api/webhooks/sign-test` | Gera ou dispara webhook assinado via `HMAC-SHA256` protegido contra SSRF (`SsrfGuard`). | Webhook `X-WinHood-Signature` |
| `POST /api/integrations/pr-decoration` | Gera comentário estruturado de PR/MR com delta de apontamentos e decisão do Quality Gate. | GitHub / GitLab / Jenkins |

---

## 3. Contrato de Importação e Exportação SARIF 2.1.0

O WinHood importa e exporta relatórios estritamente em conformidade com o esquema **OASIS SARIF 2.1.0**:

- **Exportação:** Cada apontamento (`NormalizedFinding`) inclui `ruleId`, `level`, `message`, `locations` (arquivo, linha inicial/final, coluna), `codeFlows` (para caminhos Source-to-Sink de Taint Analysis) e `properties` (`cwe`, `owasp`, `cvssBaseScore`, `mqrImpacts`, `confidence`).
- **Importação:** O WinHood aceita relatórios gerados por quaisquer ferramentas que exportam SARIF 2.1.0 via `POST /api/external-reports/import` ou `winhood sarif-import --input <arquivo.sarif>`, preservando a proveniência (`EXTERNAL_TEST_REPORT_IMPORTED`) e o hash SHA-256 do artefato original.
