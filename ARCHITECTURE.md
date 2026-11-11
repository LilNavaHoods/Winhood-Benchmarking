# ARQUITETURA, CONTRATOS DE API, BANCO DE DADOS E SEGURANÇA — WINHOOD

## 1. Arquitetura Hexagonal (Ports & Adapters)

O sistema separa estritamente o domínio analítico (`src/engine/`) dos adaptadores de ferramentas e da camada HTTP (`server.ts`):

- **`src/types/benchmark.ts`**: Contratos canônicos de dados (SARIF 2.1.0, CycloneDX 1.5, JUnit XML, OTLP Metrics, `SignedEvidenceManifest`, `ComparabilityReport`, `PreAnalysisSummary`, `VeracityAuditMatrixRow` e 9 estados de ciclo de vida de achados).
- **`src/engine/methodologyCatalogEngine.ts`**: Catálogo versionado de critérios (`WINHOOD-CATALOG-v4.0.0`), 27 perfis oficiais (12 gerais por dimensão + 15 especializados por domínio funcional), motor de comparabilidade e imparcialidade (`evaluateSoftwareComparability`) e motor de pré-análise (`buildPreAnalysisSummary`).
- **`src/engine/evidenceProvenanceEngine.ts`**: Cadeia imutável de evidências com hash canônico determinístico, assinatura digital `HMAC-SHA256` (`signEvidenceManifestHmacSha256`) e verificador criptográfico de adulteração (`verifyEvidenceChainAndManifest`).
- **`src/engine/scoringEngine.ts`**: Algoritmo determinístico `WINHOOD-SONAR-MQR-v3.0.0`, suporte a dimensões `NOT_APPLICABLE` / `NOT_ASSESSED` / `INCONCLUSIVE` com `score: null`, renormalização automática de pesos (`originalWeights` vs `effectiveWeights`), 5 indicadores executivos separados e travas matemáticas auditáveis (`CAP_APPLIED`).
- **`src/engine/staticAnalyzer.ts`**: Ingestão técnica com SHA-256, validação de segurança de upload (`validateSourceUploadSecurity`), medições reais de duração (`performance.now()`), identificação explícita de `executionMethod: 'NATIVE_AST_ENGINE'` e matriz de reconciliação de veracidade de 19 pontos (`Claimed vs Observed vs Reconciled`).
- **`src/engine/benchmarkOrchestrator.ts`**: Orquestração de execuções, matriz de equivalência funcional com níveis de verificação (`STATIC_EVIDENCE`, `INFERRED_HEURISTIC`, `NOT_VERIFIED`), inspeção estática de manifestos de instalação (`STATIC_MANIFEST_INSPECTION`) e bloqueio automático de vencedor em comparações assimétricas.

## 2. Rotas da API REST (`server.ts`)

- `GET /api/health` & `GET /api/observability` — Saúde operacional, telemetria e status dos adaptadores.
- `GET /api/auth/session` & `POST /api/auth/switch-role` — Sessão ativa e controle RBAC por requisição (`x-winhood-role`) e proteção contra elevação não autorizada em modo estrito (`x-winhood-strict-auth`).
- `GET /api/methodology/catalog` — Catálogo completo de critérios versionados e 27 perfis de avaliação.
- `POST /api/benchmarks/pre-analysis` — Pré-análise de elegibilidade de arquivos, domínio inferido, critérios verificáveis e relatório de comparabilidade antes da execução.
- `GET /api/projects`, `POST /api/projects`, `POST /api/projects/upload`, `PUT /api/projects/:id`, `DELETE /api/projects/:id` — CRUD de projetos e upload seguro.
- `GET /api/softwares`, `POST /api/softwares`, `POST /api/softwares/:id/ingest`, `DELETE /api/softwares/:id` — Cadastro de softwares (com ou sem projeto prévio) e ingestão isolada com SHA-256.
- `GET /api/benchmarks/profiles` — Perfis corporativos e especializados de benchmark.
- `GET /api/benchmark-runs`, `GET /api/benchmark-runs/:id`, `POST /api/benchmark-runs` — Execução e consulta de benchmarks individuais, A/B e de mercado.
- `GET /api/findings` & `POST /api/findings/:id/validate` — Consulta filtrada e triagem DevSecOps em tempo real nos 9 estados de validação com re-assinatura HMAC-SHA256.
- `GET /api/evidence` & `POST /api/evidence/:runId/verify` — Cadeia append-only de evidências, manifesto HMAC-SHA256 e verificação criptográfica de integridade.
- `GET /api/reports/:runId/export?format=json|csv|md|sarif|html&type=...` — Exportação oficial de relatórios de 23 seções.

