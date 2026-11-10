# ARQUITETURA, CONTRATOS DE API, BANCO DE DADOS E SEGURANÇA — WINHOOD

## 1. Arquitetura Hexagonal (Ports & Adapters)

O sistema separa estritamente o domínio analítico (`src/engine/`) dos adaptadores de ferramentas e da camada HTTP (`server.ts`):

- **`src/types/benchmark.ts`**: Contratos canônicos de dados (SARIF 2.1.0, CycloneDX 1.5, JUnit XML, OTLP Metrics, Snapshot Diffs T0/T1/T2).
- **`src/engine/scoringEngine.ts`**: Algoritmo determinístico `WINHOOD-DET-SCORE-v2.4.0`, validação matemática de pesos (`100%`), validação de equivalência experimental, mascaramento de segredos e aplicação de travas matemáticas (*Penalty Caps / Kill Switches*).
- **`src/engine/staticAnalyzer.ts`**: Ingestão técnica com SHA-256 e motores estáticos para SAST, SCA, Secret Scanning, Qualidade, Grafo Arquitetural e SQL.
- **`src/engine/benchmarkOrchestrator.ts`**: Orquestração de execuções, matriz de equivalência funcional, snapshots Windows Sandbox T0/T1/T2 e construção da cadeia imutável de evidências SHA-256 (*append-only*).

## 2. Rotas da API REST (`server.ts`)

- `GET /api/health` — Saúde operacional e integridade do armazenamento persistente.
- `GET /api/observability` — Telemetria OpenTelemetry da plataforma e status dos adaptadores.
- `GET /api/auth/session` & `POST /api/auth/switch-role` — Sessão ativa e controle RBAC (`ADMIN`, `SECURITY_LEAD`, `QA_ENGINEER`, `AUDITOR`).
- `GET /api/dashboard` — Indicadores consolidados exclusivamente a partir de execuções reais persistidas.
- `GET /api/projects`, `POST /api/projects`, `PUT /api/projects/:id`, `DELETE /api/projects/:id` — CRUD de projetos com UUID.
- `GET /api/softwares`, `POST /api/softwares`, `POST /api/softwares/:id/ingest`, `DELETE /api/softwares/:id` — Cadastro de softwares e ingestão isolada com SHA-256.
- `GET /api/benchmarks/profiles` — Perfis reutilizáveis de benchmark.
- `GET /api/benchmark-runs`, `GET /api/benchmark-runs/:id`, `POST /api/benchmark-runs` — Execução e consulta de benchmarks.
- `GET /api/findings` — Consulta filtrada por severidade, categoria, software, ferramenta e regra.
- `GET /api/adapters` & `GET /api/tools` — Catálogo de adaptadores e status (`OPERATIONAL`, `FERRAMENTA NÃO INSTALADA`, `INTEGRAÇÃO NÃO CONFIGURADA`).
- `GET /api/evidence` & `GET /api/audit` — Cadeia append-only de evidências e logs de auditoria RBAC.
- `GET /api/reports/:runId/export?format=json|csv|md&type=...` — Exportação oficial de relatórios.
