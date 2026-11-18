# Relatório de Validação de Cobertura Real (`c8` + `v8-to-istanbul`) (`COVERAGE_VALIDATION_REPORT.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + calibração e testes finais no workspace
- **Ambiente:** Linux x64, `Node.js v22.23.2`
- **Ferramentas utilizadas:** `c8@10.1.3` + `v8-to-istanbul` + `CoverageDomainInventory.ts` + `scripts/run-coverage-gate.mjs` + `scripts/coverage-runner-core.mjs`
- **Comando executado:** `npm run test:coverage`
- **Estado de validação:** `VALIDATED` *(gate oficial aprovado no conjunto de núcleo e motores críticos; déficits reais de UI/VS Code/Execution/Security permanecem explicitamente publicados)*

---

## 1. Metodologia Convencional (`all: true` & SourceMap Estrito)

1. **Fonte Única de Verdade:** O catálogo `OFFICIAL_13_COVERAGE_DOMAINS` (`src/execution/CoverageDomainInventory.ts`) define os 13 domínios oficiais, seus diretórios e padrões de exclusão (`*.test.ts`, `*.test.tsx`, `types.ts`, `*.d.ts`). Tanto `scripts/run-coverage-gate.mjs` quanto o relatório consomem exatamente essa mesma lista.
2. **Instrumentação Real:** `c8` coleta cobertura V8 nativa durante a execução das **13 suítes de testes** (111 testes passando, 0 falhas) com `all: true` — arquivos elegíveis não executados permanecem no denominador com `0%`.
3. **Validação de SourceMaps:** 70/70 scripts executados tiveram seus `SourceMap` validados (`sourceMapValidation.errorsCount = 0`).
4. **Artefatos Gerados em Disco:** `coverage/coverage-summary.json`, `coverage/lcov.info` e `coverage/index.html`.

---

## 2. Separação Estrita dos 3 Indicadores (`separatedIndicators`)

| Indicador | Medição Real (`npm run test:coverage`) | Estado | Significado |
|---|---|---|---|
| **1. `ingestionCoverage`** | **80 / 80** arquivos elegíveis ingeridos (90 descobertos, 10 excluídos por padrão de teste/tipo) = **`100.00%`** | `COMPLETE` | Escopo do inventário lido sem falhas. |
| **2. `analysisCoverage`** | **70 / 80** arquivos elegíveis mapeados por SourceMap/`FULL_AST` nos testes = **`87.50%`** (`10` componentes TSX não carregados) | `PARTIAL` | Cobertura estrutural do código carregado. |
| **3. `testCoverage` (Núcleo 6 Domínios)** | **17 arquivos** (`src/analyzers/`, `src/scoring/`, `src/evidence/`, `src/comparability/`, `src/gate/`, `src/reports/`): **`88.47%` Linhas · `88.47%` Statements · `92.56%` Funções · `97.74%` Branches** | `PASSED` | Thresholds globais do gate: `80% / 80% / 75%`. |
| **3b. `testCoverage` (Todos 13 Domínios)** | **80 arquivos** (inclui 10 arquivos UI com 0% no denominador): **`61.02%` Linhas · `69.11%` Funções · `86.52%` Branches** | `HONEST_DEFICIT_TRACKED` | Visão sem maquiagem de todo o monorepo elegível. |

---

## 3. Resultados nos Motores Críticos (Meta >= 95%)

| Motor Crítico | Arquivos | Lines (%) | Functions (%) | Branches (%) | Meta (>=95%) | Estado |
|---|---|---|---|---|---|---|
| `src/scoring/` | 1 | **100.00%** | **100.00%** | **100.00%** | Atingida | `VALIDATED` |
| `src/evidence/` | 2 | **100.00%** | **100.00%** | **100.00%** | Atingida | `VALIDATED` |
| `src/comparability/` | 1 | **100.00%** | **100.00%** | **98.08%** | Atingida | `VALIDATED` |

---

## 4. Detalhamento Completo dos 13 Domínios Oficiais

| # | Domínio (`domainId`) | Tier | Elegíveis | Excluídos | Executados | Lines % | Functions % | Branches % | Gate do Domínio |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `src/analyzers/` | `CORE_SECURITY_ENGINE` | 10 | 3 | 10 | **86.34%** | **89.87%** | **97.47%** | `PASSED` |
| 2 | `src/engine/` | `CORE_SECURITY_ENGINE` | 10 | 1 | 10 | **93.40%** | **93.85%** | **81.97%** | `PASSED` |
| 3 | `src/scoring/` | `CRITICAL_MOTOR` | 1 | 0 | 1 | **100.00%** | **100.00%** | **100.00%** | `PASSED` |
| 4 | `src/evidence/` | `CRITICAL_MOTOR` | 2 | 0 | 2 | **100.00%** | **100.00%** | **100.00%** | `PASSED` |
| 5 | `src/comparability/` | `CRITICAL_MOTOR` | 1 | 0 | 1 | **100.00%** | **100.00%** | **98.08%** | `PASSED` |
| 6 | `src/gate/` | `CORE_SECURITY_ENGINE` | 1 | 1 | 1 | **89.93%** | **93.75%** | **98.28%** | `PASSED` |
| 7 | `src/security/` | `CORE_SECURITY_ENGINE` | 2 | 1 | 2 | **78.47%** | **90.99%** | **93.67%** | `SHORTFALL` (min 80% L) |
| 8 | `src/execution/` | `CORE_SECURITY_ENGINE` | 5 | 1 | 5 | **75.22%** | **97.56%** | **92.12%** | `SHORTFALL` (min 80% L) |
| 9 | `src/integrations/` | `INTEGRATION_AND_UI` | 18 | 1 | 18 | **86.33%** | **91.23%** | **98.02%** | `PASSED` |
| 10 | `src/reports/` | `CORE_SECURITY_ENGINE` | 2 | 0 | 2 | **96.21%** | **100.00%** | **99.20%** | `PASSED` |
| 11 | `src/components/` | `INTEGRATION_AND_UI` | 25 | 1 | 15 (10 com 0%) | **27.62%** | **17.05%** | **40.83%** | `SHORTFALL` (min 70% L/F, 65% B) |
| 12 | `src/desktop/` | `INTEGRATION_AND_UI` | 2 | 1 | 2 | **77.63%** | **95.00%** | **85.32%** | `SHORTFALL` (min 80% L) |
| 13 | `packages/vscode-extension/` | `INTEGRATION_AND_UI` | 1 | 0 | 1 | **56.10%** | **80.00%** | **62.07%** | `SHORTFALL` (min 80% L, 75% B) |

**Observação sobre déficits honestos:** Os 5 domínios marcados com `SHORTFALL` permanecem no relatório `coverage/coverage-summary.json` (`domainShortfalls`) sem redução artificial de metas nem exclusão de arquivos do denominador. O déficit de `src/components/` (`27.62% L`) reflete a ausência de browser headless completo (Playwright/Chromium) no container Linux, cobrindo apenas os caminhos exercitados via SSR + módulos de integridade.
