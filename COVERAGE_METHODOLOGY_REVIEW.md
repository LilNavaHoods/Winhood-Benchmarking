# Revisão Metodológica e Calibração Matemática de Cobertura (`COVERAGE_METHODOLOGY_REVIEW.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + calibração `c8` + `v8-to-istanbul` (`all: true`)
- **Ambiente:** Linux x64, `Node.js v22.23.2`
- **Ferramentas:** `c8@10.1.3`, `v8-to-istanbul`, `istanbul-lib-coverage`, `istanbul-lib-report`, `istanbul-reports`
- **Arquivos principais:** `src/execution/CoverageDomainInventory.ts`, `scripts/coverage-runner-core.mjs`, `scripts/run-coverage-gate.mjs`, `src/execution/coverageEngine.test.ts`
- **Comandos executados:** `./node_modules/.bin/tsx --test src/execution/coverageEngine.test.ts` e `npm run test:coverage`
- **Estado de validação:** `VALIDATED`

---

## 1. Arquitetura do Motor `c8` + `v8-to-istanbul` com `all: true`

1. **Fonte Única de Verdade (`OFFICIAL_13_COVERAGE_DOMAINS`):**
   - `scripts/run-coverage-gate.mjs` importa diretamente `OFFICIAL_13_COVERAGE_DOMAINS`, `scanOfficial13DomainsInventory` e `computeThreeWaySeparatedCoverage` de `src/execution/CoverageDomainInventory.ts`.
   - As listas `c8Include` e `c8Exclude` são derivadas programaticamente desse inventário único (zero listas paralelas ou duplicadas).
2. **Denominador Completo (`all: true`):**
   - Arquivos elegíveis que **nunca foram importados** durante a execução das suítes de testes são injetados no `CoverageMap` do Istanbul com `0%` em statements, lines, functions e branches (`injectZeroCoverageFile`).
   - Declarações puramente de tipos TypeScript (`interface`, `type`, `declare`) são ignoradas pelo parser AST/SourceMap e nunca inflam nem penalizam linhas executáveis.
3. **Validação Estrita de SourceMaps (`sourceMapValidation`):**
   - Cada script elegível executado pelo V8 tem seu SourceMap inline ou externo validado antes da conversão `v8-to-istanbul`. Qualquer SourceMap ausente ou corrompido gera erro explícito e reprova o gate.

---

## 2. Calibração Matemática nos 11 Microprojetos de Referência (`src/execution/coverageEngine.test.ts`)

Comando: `./node_modules/.bin/tsx --test src/execution/coverageEngine.test.ts` -> **2/2 suites PASS (`4.56s`)**

| # | Microprojeto de Referência | Comportamento Esperado | Resultado Medido pelo Motor | Status |
|---|---|---|---|---|
| **1** | Arquivo 100% executado (`full.ts`) | `linesPct = 100%`, `functionsPct = 100%`, `branchesPct = 100%` | `100% / 100% / 100%` | `VALIDATED` |
| **2** | Arquivo elegível nunca importado (`unimported.ts`, `all: true`) | Permanece no denominador com `0%` (`lines=0%`, `functions=0%`, `branches=0%`) | `0% / 0% / 0%` | `VALIDATED` |
| **3** | Arquivo com 2 funções equivalentes, apenas 1 executada (`half.ts`) | `functionsPct = 50%` (1/2) e `linesPct` ~50% | `functionsPct = 50%`, `linesPct = 50%` | `VALIDATED` |
| **4** | Condicional `if / else` com apenas o ramo `if` executado | `branchesPct = 50%` (1/2 ramos) | `branchesPct = 50%` | `VALIDATED` |
| **5** | Operador ternário `cond ? a : b` exercitado em apenas 1 direção | `branchesPct = 50%` (1/2 ramos) | `branchesPct = 50%` | `VALIDATED` |
| **6** | `switch / case` com 4 casos e apenas 2 casos exercitados | `branchesPct = 50%` (2/4 casos) | `branchesPct = 50%` | `VALIDATED` |
| **7** | Expressões lógicas de curto-circuito (`&&`, `||`, `??`) parcialmente exercitadas | Contabiliza ramos não tomados (`branchesPct < 100%`) | `branchesPct < 100%` (ramos parciais medidos) | `VALIDATED` |
| **8** | Múltiplas funções declaradas vs. invocadas (4 declaradas, 3 invocadas) | `functions.total = 4`, `functions.covered = 3`, `functionsPct = 75%` | `75.00%` (3/4) | `VALIDATED` |
| **9** | Arquivo TypeScript com `interface` e `type` + código executável | Tipos não contam como linhas não cobertas; código 100% executado = `100%` | `linesPct = 100%`, `sourceMapValidated = true` | `VALIDATED` |
| **10** | Arquivo com SourceMap ausente ou corrompido | Falha explicitamente em `sourceMapValidation.errors` | Erro determinístico registrado | `VALIDATED` |
| **11** | Projeto multi-domínio misturando arquivos executados e não executados | Agregação por domínio reflete o peso real dos arquivos `0%` | Agregação exata verificada | `VALIDATED` |

---

## 3. Resumo Oficial de Cobertura dos 13 Domínios (`coverage/coverage-summary.json`)

- **Núcleo Auditado (6 domínios, 17 arquivos):** `88.47%` Lines · `92.56%` Functions · `97.74%` Branches (`PASSED` contra `80/80/75`).
- **Motores Críticos (`>= 95%` exigido):**
  - `src/scoring/`: `100% L / 100% F / 100% B`
  - `src/evidence/`: `100% L / 100% F / 100% B`
  - `src/comparability/`: `100% L / 100% F / 98.08% B`
- **Totalidade dos 13 Domínios (80 arquivos elegíveis com `all: true`):** `61.02%` Lines · `69.11%` Functions · `86.52%` Branches (déficits individuais de `src/components/`, `packages/vscode-extension/`, `src/execution/`, `src/security/` e `src/desktop/` preservados sem alteração de metas).
