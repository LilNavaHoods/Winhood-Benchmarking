# Proveniência dos Conjuntos de Validação e Rigor Estatístico (`INDEPENDENT_DATASET_PROVENANCE.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + reestruturação em 3 conjuntos (Fase 7)
- **Ambiente:** Linux x64, `Node.js v22.23.2`
- **Arquivos principais:** `src/intelligence/datasets/GoldenDatasetCorpus.ts`, `src/validation/GoldenDatasetRunner.ts`, `src/intelligence/intelligence.test.ts`
- **Comando executado:** `npm run test:golden` (`7/7 PASS`, incluindo os 11 cenários estatísticos/integridade)
- **Estado de validação:** `VALIDATED`

---

## 1. Declaração de Proveniência e Limitação de Independência Externa

Todos os casos de teste em `src/intelligence/datasets/GoldenDatasetCorpus.ts` possuem metadados obrigatórios de rastreabilidade (`caseId`, `datasetRole`, `origin`, `license: 'MIT'`, `contentSha256`) verificados em runtime por `computeGoldenCaseContentSha256(item.filesMap)`:

| Papel do Conjunto (`GoldenDatasetRole`) | Constante & Versão | Rótulo Oficial de Origem (`datasetOriginLabel`) | SHA-256 do Corpus | Total de Casos ($N$) | Linguagens Cobertas | Finalidade |
|---|---|---|---|---|---|---|
| `DEVELOPMENT` | `DEVELOPMENT_DATASET_CORPUS` (`WINHOOD-DEVELOPMENT-v3.0.0`) | `WINHOOD_INTERNAL_DEVELOPMENT_CORPUS` | `e5135bd408e33bc8a116e91bae621e13e8433397de3efd6692bbd10d9246a358` | `4` (2 pos, 2 neg) | `TypeScript`, `Python` (2/8) | Calibração inicial durante o desenvolvimento de heurísticas. |
| `REGRESSION` | `GOLDEN_DATASET_CORPUS` (`WINHOOD-INTERNAL-REGRESSION-v3.0.0`) | `WINHOOD_INTERNAL_REGRESSION_CORPUS` | `f8be0c95a257bbd3c83d632f97e386e2b70d7e0cf11cb860512bd7d8b4787ef8` | `26` (13 pos, 13 neg) | **8/8** (`TypeScript`, `JavaScript`, `Python`, `Java`, `C#`, `Go`, `Rust`, `SQL`) | Detecção contínua de regressões e medição de falsos positivos (`FP = 2`). |
| `INTERNAL_HOLDOUT` | `INTERNAL_HOLDOUT_CORPUS` (`WINHOOD-INTERNAL-HOLDOUT-v3.0.0`) | `WINHOOD_INTERNAL_HOLDOUT_CORPUS` | `2aecd49c0d57e8d257c84c7902ba0f053d43bdcf42880b9f873f84255c119ff5` | `18` (9 pos, 9 neg) | **8/8** (`TypeScript`, `JavaScript`, `Python`, `Java`, `C#`, `Go`, `Rust`, `SQL`) | Conjunto holdout congelado (nunca usado para calibrar limiares). |

> **Aviso de Transparência Científica (Obrigatório):**
> `INTERNAL_HOLDOUT` é um conjunto **holdout de autoria interna** da equipe de engenharia do WinHood. O método `runIndependentValidationSuite()` foi marcado como `@deprecated` (mantido apenas como alias retrocompatível para `runHoldoutValidationSuite()`) e os relatórios emitem explicitamente em `limitations`:
> *"Estes corpora são de autoria interna do WinHood; NÃO representam um benchmark externo independente de terceiros (ex.: OWASP Benchmark v1.2 / NIST Juliet)."*

---

## 2. Validação dos 11 Cenários Estatísticos e de Integridade (`src/intelligence/intelligence.test.ts`)

1. **Cenário 1 (`n < 30` vs `n >= 30`):** Confirma que estratos ou conjuntos com $n < 30$ recebem `lowSampleWarning: true` e mensagem explicando que $n < 30$ é um limiar operacional de alerta de amostra reduzida (e não garantia universal de significância estatística), enquanto $n \ge 30$ desativa o alerta quando todos os estratos possuem $\ge 30$ casos.
2. **Cenário 2 (Denominador Zero = `null`):** Um corpus contendo apenas casos negativos (`TP = 0, FP = 0, FN = 0, TN = 4`) retorna `precision: null`, `recall: null`, `f1Score: null`, `truePositiveRate: null`, `falseNegativeRate: null` e `confidenceIntervals95.precision = { pointEstimate: null, lower: null, upper: null, sampleSize: 0 }` (zero fabricação de `0%` ou `100%`).
3. **Cenário 3 (Apenas casos positivos `TN = 0, FP = 0`):** Retorna `trueNegativeRate: null` e `falsePositiveRate: null`.
4. **Cenário 4 (Cálculo exato sem arredondamento intermediário):** Verifica $F_1 = \frac{2TP}{2TP + FP + FN}$ sobre contagens mistas (`TP=7, FP=2, FN=1, TN=5` -> `Precision=0.778`, `Recall=0.875`, `F1=0.824`).
5. **Cenário 5 (Intervalo de Confiança de Wilson 95%):** Verifica limites inferior e superior exatos para $z = 1.959964$.
6. **Cenário 6 (Casos inconclusivos / vazios):** `filesMap: {}` incrementa `inconclusiveCases` sem contaminar `TP/FP/TN/FN`.
7. **Cenário 7 (`evaluatedStrataCount` em Macro-Averages):** Estratos vazios são ignorados na média macro e `evaluatedStrataCount` reflete exatamente o número de estratos avaliados.
8. **Cenário 8 (Cobertura das 8 linguagens declaradas):** `REGRESSION` e `INTERNAL_HOLDOUT` têm `missingDeclaredLanguages = []` (8/8 linguagens representadas).
9. **Cenário 9 (Detecção de linguagem ausente):** Quando uma linguagem declarada não está no corpus (ex.: `DEVELOPMENT`), `missingDeclaredLanguages` lista explicitamente as 6 linguagens ausentes e adiciona aviso em `limitations`.
10. **Cenário 10 (Detecção de adulteração SHA-256):** Modificar 1 caractere de código em um caso sem atualizar `contentSha256` faz `datasetIntegrityVerified = false` e popula `integrityErrors`.
11. **Cenário 11 (Determinismo de `reportSha256`):** Integridade criptográfica do relatório estatístico confirmada.
