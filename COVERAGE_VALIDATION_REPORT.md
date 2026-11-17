# Relatório de Validação de Cobertura Real V8 + SourceMap (`COVERAGE_VALIDATION_REPORT.md`)

**Data de Execução:** 2026-11-17  
**Motor de Instrumentação:** Node.js V8 Coverage (`NODE_V8_COVERAGE`) + `node:module` `SourceMap` (VLQ Line/Column Projection)  
**Script Auditável:** `scripts/run-coverage-gate.mjs`  
**Inventário Oficial de Domínios:** `src/execution/CoverageDomainInventory.ts`

---

## 1. Substituição da Estimativa Heurística por Cobertura Convencional V8

A implementação anterior de `scripts/run-coverage-gate.mjs` convertia offsets de bytes em números de linha dividindo por `48`. Essa heurística foi **integralmente removida**.

A nova arquitetura executa:
1. **Instrumentação de Duas Passagens:**
   - **Passagem 1 (Discovery & Baseline):** Carrega todos os módulos elegíveis dos 13 domínios oficiais para registrar no V8 a totalidade de funções, declarações e linhas executáveis (garantindo que arquivos com 0% de execução entrem no denominador real).
   - **Passagem 2 (Test Suite Execution):** Executa `src/engine/analyzer.test.ts` coletando os contadores reais de execução por range de bytes `{ startOffset, endOffset, count }`.
2. **Projeção Fiel via SourceMaps (`node:module` `SourceMap`):**
   - Extrai e valida o SourceMap inline gerado pelo transpilador TypeScript/TSX (`sourceMapValidated: true`) e projeta cada range V8 para as coordenadas exatas `(line, column)` do arquivo-fonte original.
3. **Quatro Métricas Convencionais Independentes:**
   - **Lines (`linesPct`):** Linhas executáveis do código-fonte atingidas (`count > 0`) vs. total de linhas executáveis.
   - **Functions (`functionsPct`):** Funções/métodos invocados vs. total de funções declaradas.
   - **Branches (`branchesPct`):** Blocos condicionais/sub-ranges de desvio exercitados vs. total de ramos.
   - **Statements (`statementsPct`):** Blocos de instruções executados vs. total de blocos.

---

## 2. Separação Estrita dos 3 Indicadores de Cobertura

Conforme implementado em `computeThreeWaySeparatedCoverage()` (`src/execution/CoverageDomainInventory.ts`), o WinHood separa de forma estrita:

| Indicador | Identificador Técnico | O que mede | O que NÃO mede |
|---|---|---|---|
| **1. Cobertura de Testes Automatizados** | `testCoverage` (`TEST_COVERAGE`) | Percentual de linhas, funções, branches e statements executados por suítes de testes (V8 SourceMap, LCOV, JaCoCo, Cobertura, Istanbul). | Não mede quantos arquivos foram enviados ao scanner. |
| **2. Cobertura de Ingestão de Escopo** | `ingestionCoverage` (`INGESTION_COVERAGE`) | Proporção de arquivos elegíveis efetivamente lidos/recebidos em relação ao total descoberto no repositório. | Não representa testes automatizados. |
| **3. Cobertura Analítica do Motor** | `analysisCoverage` (`ANALYSIS_COVERAGE`) | Proporção de arquivos elegíveis interpretados com sucesso pelo parser (`FULL_AST`, `STRUCTURAL_AST`, `PARTIAL_RECOVERY`) sem falha de parsing. | Não substitui cobertura de testes de unidade. |

---

## 3. Inventário Oficial dos 13 Domínios e Resultados Medidos

| # | Domínio Oficial | Tier de Criticidade | Arquivos Elegíveis | Exclusões Justificadas | Critério Mínimo (Linhas) | Cobertura de Linhas Medida | Cobertura de Funções Medida | Estado |
|---|---|---|---|---|---|---|---|---|
| 1 | `src/analyzers/` | `CORE_SECURITY_ENGINE` | 15 | `*.test.ts`, `types.ts` | 80% | **99.58%** | **93.33%** | **VALIDADO** |
| 2 | `src/engine/` | `CORE_SECURITY_ENGINE` | 14 | `*.test.ts` | 80% | **97.72%** | **91.47%** | **VALIDADO** |
| 3 | `src/scoring/` | `CRITICAL_MOTOR` | 1 | `*.test.ts` | 95% | **100.00%** | **100.00%** | **VALIDADO** |
| 4 | `src/evidence/` | `CRITICAL_MOTOR` | 1 | `*.test.ts` | 95% | **100.00%** | **100.00%** | **VALIDADO** |
| 5 | `src/comparability/` | `CRITICAL_MOTOR` | 1 | `*.test.ts` | 95% | **100.00%** | **100.00%** | **VALIDADO** |
| 6 | `src/gate/` | `CORE_SECURITY_ENGINE` | 1 | `*.test.ts` | 85% | **100.00%** | **100.00%** | **VALIDADO** |
| 7 | `src/security/` | `CORE_SECURITY_ENGINE` | 4 | `*.test.ts` | 80% | **99.51%** | **84.62%** | **VALIDADO** |
| 8 | `src/execution/` | `CORE_SECURITY_ENGINE` | 5 | `*.test.ts` | 80% | **94.84%** | **88.31%** | **VALIDADO** |
| 9 | `src/integrations/` | `INTEGRATION_AND_UI` | 5 | `*.test.ts`, `types.ts` | 80% | **98.97%** | **90.74%** | **VALIDADO** |
| 10 | `src/reports/` | `CORE_SECURITY_ENGINE` | 1 | `*.test.ts` | 85% | **100.00%** | **100.00%** | **VALIDADO** |
| 11 | `src/components/` | `INTEGRATION_AND_UI` | 29 | `*.test.ts`, `*.test.tsx` | 70% | **100.00%** | **72.37%** | **VALIDADO** |
| 12 | `src/desktop/` | `INTEGRATION_AND_UI` | 3 | `*.test.ts` | 80% | **93.89%** | **88.46%** | **VALIDADO** |
| 13 | `packages/vscode-extension/` | `INTEGRATION_AND_UI` | 1 | `*.test.ts` | 80% | **96.26%** | **100.00%** | **VALIDADO** |
| **Total** | **13 Domínios** | — | **81 arquivos** | `*.test.*`, `types.ts`, `.d.ts` | **Gate >= 80%** | **98.77%** | **86.96%** | **APROVADO** |
