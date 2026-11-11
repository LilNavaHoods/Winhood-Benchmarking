# WinHood — Software Benchmark & Quality Analyzer

Plataforma técnica full-stack para avaliação independente e benchmarking comparativo de softwares, realizando auditorias automatizadas de qualidade de código (SonarQube MQR Mode), segurança DevSecOps (SAST Taint Mode, SCA, Segredos, SBOM), acoplamento arquitetural, banco de dados SQL, equivalência funcional por domínio, validação pelo **Motor de Veracidade de 19 Pontos**, **Motor de Comparabilidade e Imparcialidade** e trilha de evidências encadeada **SHA-256** com **Manifesto Assinado Digitalmente (HMAC-SHA256)**.

---

## 1. Arquitetura Visual (WinHood Design System)

- **Theme Color Global:** `#000000` (Preto puro na meta tag, Dark Mode nativo `#080b10` / `#0f141c` e alternância Claro/Escuro).
- **Accent Color (Destaque):** `#31d6c4` (`--accent: #31d6c4`).
- **Tipografia:** `Plus Jakarta Sans` para estrutura de interface e `JetBrains Mono` com `tabular-nums` para alinhamento vertical estrito de métricas, notas `0.00–5.00`, latências e hashes SHA-256.
- **Scrollbars Contextuais (`.df-hover-scroll`):** Barras de rolagem globais ocultas por padrão e reveladas sob `:hover` com 6px em ciano `#31d6c4`.

---

## 2. Arquitetura Técnica e Módulos Implementados

1. **Ingestão de Código-Fonte & Segurança de Upload (`/api/softwares`, `/api/projects/upload`):**
   - Estados formais de ingestão (`METADATA_ONLY`, `SOURCE_IMPORTED`, `SOURCE_PARTIAL`, `SOURCE_VALIDATED`, `SOURCE_FAILED`, `DEMO_FIXTURE`, `TEST_FIXTURE`, `PUBLIC_DOCUMENTATION_ONLY`) e disponibilidade (`FULL_SOURCE`, `PARTIAL_SOURCE`, `PUBLIC_DOCUMENTATION_ONLY`, `CLOSED_SOURCE`).
   - Validação de segurança (`validateSourceUploadSecurity`) bloqueando Path Traversal (`../`), Symlinks, arquivos binários/corrompidos (null-bytes) e arquivos acima de 2 MB.
   - Avaliação e comparação de softwares avulsos ou inter-projetos sem dependência rígida de projeto único.
2. **Catálogo Metodológico Versionado & 27 Perfis Oficiais (`src/engine/methodologyCatalogEngine.ts`):**
   - `WINHOOD-CATALOG-v4.0.0` com 24 critérios formais nas 12 dimensões e distinção estrita entre `STATIC_EVIDENCE`, `DYNAMIC_EVIDENCE`, `DOCUMENTATION_ONLY`, `INFERRED_HEURISTIC` e `NOT_VERIFIED`.
   - **12 Perfis Gerais por Dimensão + 15 Perfis Especializados por Domínio Funcional** (`DOMAIN_SPECIALIZED_PROFILES`), marcando categorias não aplicáveis (`NOT_APPLICABLE`, `score: null`) e normalizando pesos exclusivamente sobre as dimensões avaliadas (`originalWeights` vs `effectiveWeights`).
3. **Motor de Comparabilidade, Imparcialidade & Pré-Análise (`/api/benchmarks/pre-analysis`):**
   - Avalia paridade de escopo, disponibilidade de código-fonte e domínio funcional entre softwares.
   - Bloqueia automaticamente a declaração de vencedor oficial (`winnerSoftwareId: null`) em comparações assimétricas (`FULL_SOURCE` vs `PUBLIC_DOCUMENTATION_ONLY` ou domínios incompatíveis).
4. **Motor de Pontuação Determinística & 5 Indicadores Separados (`src/engine/scoringEngine.ts`):**
   - Separa obrigatoriamente **5 Indicadores Executivos**: `1. Nota Técnica (0.00–5.00 | null)`, `2. Cobertura do Escopo (%)`, `3. Confiança da Evidência (HIGH/MEDIUM/LOW/NONE)`, `4. Decisão do Quality Gate (APPROVED/APPROVED_WITH_RESERVATIONS/BLOCKED/INCONCLUSIVE/REJECTED)` e `5. Estado de Veracidade`.
   - Triagem DevSecOps em tempo real com **9 estados de ciclo de vida** (`CONFIRMED`, `PROBABLE`, `FALSE_POSITIVE`, `INCONCLUSIVE`, `NOT_REPRODUCIBLE`, `NOT_TESTED`, `ACCEPTED_RISK`, `FIXED_PENDING_RETEST`, `VERIFIED_RESOLVED`).
5. **Motor de Evidências, Proveniência & Assinatura Digital HMAC-SHA256 (`src/engine/evidenceProvenanceEngine.ts`):**
   - Cadeia sequencial imutável iniciada em `GENESIS_EVIDENCE_HASH`, manifesto assinado com `HMAC-SHA256` e endpoint de auditoria de integridade (`POST /api/evidence/:runId/verify`) que detecta qualquer adulteração de payload ou índice.

---

## 3. Execução e Testes Automatizados

```bash
# Instalar dependências
npm install

# Executar suíte completa de testes unitários e de integração (node:test)
npx --yes tsx --test src/engine/analyzer.test.ts

# Iniciar servidor full-stack (Express API + Vite Frontend na porta 3000)
npm run dev
```

