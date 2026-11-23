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
- `GET /api/benchmark-runs`, `GET /api/benchmark-runs/:id`, `POST /api/benchmark-runs`, `POST /api/benchmark-runs/:id/cancel` — Execução, consulta e cancelamento seguro de benchmarks individuais, A/B e de mercado.
- `GET /api/findings` & `POST /api/findings/:id/validate` — Consulta filtrada e triagem DevSecOps em tempo real nos 9 estados de validação com re-assinatura HMAC-SHA256.
- `GET /api/evidence` & `POST /api/evidence/:runId/verify` — Cadeia append-only de evidências, manifesto HMAC-SHA256 e verificação criptográfica de integridade.
- `GET /api/reports/:runId/export?format=json|csv|md|sarif|html&type=...` — Exportação oficial de relatórios de 23 seções.
- `GET /api/auth/access-modes`, `POST /api/auth/logout` — Descoberta de modos de acesso disponíveis e encerramento de sessão com limpeza de cookies de autenticação e transação OAuth.
- `GET /api/auth/github/oauth/start`, `GET /api/auth/github/oauth/callback`, `GET /api/auth/github/oauth/status`, `GET|PUT /api/auth/github/oauth/admin/config`, `POST /api/auth/github/oauth/admin/test` — Fluxo OAuth 2.0 Authorization Code + PKCE S256 com redirecionamento direto na mesma aba no navegador (sem `window.open()` nem PAT/Client ID para usuários finais) e painel administrativo protegido para configuração única pelo administrador.

## 3. Separação Browser-Safe (`src/shared/`) vs. Módulos Exclusivos de Backend

Para impedir que dependências nativas do Node.js (`node:child_process`, `node:fs`, `node:crypto`, `node:net`, `node:dns`, `node:os`, `node:worker_threads`, `KeyManagementService`, `QualityGateEngine`) cheguem ao bundle Vite do navegador, o código foi estritamente particionado em três camadas:

- **Camada Compartilhada 100% Browser-Safe (`src/shared/`):**
  - `src/shared/benchmarkCategories.ts`: Definições canônicas de `ALL_BENCHMARK_CATEGORIES`, `DEFAULT_CATEGORY_WEIGHTS` e `MARKET_CATEGORIES`.
  - `src/shared/benchmarkWeights.ts`: Funções puras e determinísticas `normalizeEnabledCategoryWeights`, `validateCategoryWeights`, `validateEquivalenceConditions` e `classifyScoreScale`, consumidas tanto pelo Wizard React quanto pelo `scoringEngine.ts` no backend (fonte única de verdade).
  - `src/shared/benchmarkValidation.ts`: Validações puras de payload, critérios, participantes A/B e integridade de configuração do Wizard.
  - `src/shared/benchmarkConfig.ts`: Tipos e helpers puros de perfis e presets do Wizard (`BenchmarkProfileConfig`, defaults browser-safe).
  - `src/shared/authTypes.ts`: Tipos compartilhados de modo de acesso, constantes de fluxo OAuth (`GITHUB_OAUTH_START_URL`, `GITHUB_OAUTH_UNAVAILABLE_NOTICE`) e mapeamento sanitizado de feedback/erros (`resolveGitHubOAuthCallbackFeedback`).
  - `src/shared/index.ts`: Barrel browser-safe exportando exclusivamente módulos compatíveis com navegador e Node.js.
- **Camada Exclusiva de Frontend (`src/components/`, `src/App.tsx`, `src/utils/csrfFetch.ts`):** Consome apenas `src/shared/` e APIs REST (`/api/*`), nunca importando `src/engine/`, `src/gate/`, `src/security/` ou `server.ts`.
- **Camada Exclusiva de Backend (`server.ts`, `src/engine/`, `src/analyzers/`, `src/gate/`, `src/security/`, `src/evidence/`, `src/execution/`, `src/reports/`):** Executa exclusivamente em Node.js com acesso a `fs`, `crypto`, `child_process`, keystore DPAPI/AES-256-GCM e banco criptografado.
- **Guardrail Automatizado (`scripts/check-browser-imports.mjs`):** Executado via `npm run check:browser-imports` (e validado pela suíte `npm run test:browser-imports`), obrigatoriamente antes de `npm run build`, `npm run build:desktop` e nos jobs Linux/Windows de CI. Analisa via AST o grafo transitivo real de imports estáticos, dinâmicos (`import()`), re-exports, barrel files e aliases TypeScript/Vite a partir de todos os entrypoints do frontend, bloqueando o build diante de qualquer dependência Node-only alcançável.
