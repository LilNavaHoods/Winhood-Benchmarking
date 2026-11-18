# Validação Estatística de Precisão, Recall e Intervalos de Confiança (`BENCHMARK_STATISTICAL_VALIDATION.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + split formal de 3 conjuntos
- **Ambiente:** Linux x64, `Node.js v22.23.2`
- **Implementação:** `src/validation/GoldenDatasetRunner.ts` & `src/intelligence/datasets/GoldenDatasetCorpus.ts`
- **Comando executado:** `npm run test:golden` (`7/7 PASS`, incluindo os 11 cenários estatísticos/integridade da Fase 7)
- **Estado de validação:** `VALIDATED`

---

## 1. Separação Formal em 3 Conjuntos Internos Versionados

Para evitar contaminação entre calibração de regras, regressão contínua e avaliação holdout, os casos de teste são divididos em **3 corpora disjuntos** com hash SHA-256 verificado em cada arquivo (`contentSha256`):

1. **`DEVELOPMENT` (`WINHOOD-DEVELOPMENT-v3.0.0` / `WINHOOD_INTERNAL_DEVELOPMENT_CORPUS`):**
   - 4 casos usados exclusivamente durante o ajuste inicial de heurísticas de parser/regras.
2. **`REGRESSION` (`WINHOOD-INTERNAL-REGRESSION-v3.0.0` / `WINHOOD_INTERNAL_REGRESSION_CORPUS`):**
   - 26 casos cobrindo todas as **8 linguagens declaradas** (`TypeScript`, `JavaScript`, `Python`, `Java`, `C#`, `Go`, `Rust`, `SQL`), incluindo armadilhas de falso positivo (comentários/strings SQL que exercitam a medição honesta de `FP = 2` e `Precision = 0.867`).
3. **`INTERNAL_HOLDOUT` (`WINHOOD-INTERNAL-HOLDOUT-v3.0.0` / `WINHOOD_INTERNAL_HOLDOUT_CORPUS`):**
   - 18 casos (9 vulneráveis + 9 seguros com sanitização contextual) cobrindo todas as **8 linguagens declaradas**, congelados para avaliação sem ajuste de regras.

> **Ressalva Metodológica Obrigatória:** Embora `INTERNAL_HOLDOUT` seja separado de `DEVELOPMENT` e `REGRESSION`, todos os 3 conjuntos são de **autoria interna do projeto WinHood**. Eles **não constituem um benchmark externo independente de terceiros** (como OWASP Benchmark v1.2 ou NIST SARD Juliet Test Suite).

---

## 2. Regras Matemáticas e Tratamento de Denominador Zero

- **Sem Arredondamento Intermediário:** `Precision`, `Recall (TPR)`, `F1-Score` ($2TP / (2TP + FP + FN)$), `TNR`, `FPR` e `FNR` são calculados diretamente a partir das contagens inteiras `TP, FP, TN, FN` e arredondados apenas na formatação final (`3` casas decimais).
- **Denominador Zero = `null`:** Quando `TP + FP = 0` ou `TP + FN = 0`, a métrica e seu intervalo de confiança retornam `null` (nunca `0%` ou `100%` fabricados).
- **Intervalo de Confiança de 95% (Wilson Score — $z = 1.959964$):** Calculado para cada proporção com tamanho amostral explícito.
- **Limiar Operacional `n < 30`:** Sinalizado via `lowSampleWarning: true` e `sampleWarning` textual como indicador operacional de amostra reduzida (e não como prova universal de significância estatística).

---

## 3. Resultados Reais Medidos (`GoldenDatasetRunner.runValidationSuite`)

| Conjunto (`datasetRole`) | Versão & SHA-256 (prefixo) | Linguagens ($8$ decl.) | $N$ Total | TP | TN | FP | FN | Precision (IC 95% Wilson) | Recall / TPR (IC 95% Wilson) | TNR | FPR | F1 Micro | F1 Macro (Ling.) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `DEVELOPMENT` | `v3.0.0` (`e5135bd4...`) | 2 (`TS`, `Py`) | 4 | 2 | 2 | 0 | 0 | `1.000` (`[0.342, 1.000]`, $n=2$) | `1.000` (`[0.342, 1.000]`, $n=2$) | `1.000` | `0.000` | `1.000` | `1.000` (2 estratos) |
| `REGRESSION` | `v3.0.0` (`f8be0c95...`) | **8 / 8** | 26 | 13 | 11 | 2 | 0 | `0.867` (`[0.621, 0.963]`, $n=15$) | `1.000` (`[0.772, 1.000]`, $n=13$) | `0.846` | `0.154` | `0.929` | `0.949` (8 estratos) |
| `INTERNAL_HOLDOUT` | `v3.0.0` (`2aecd49c...`) | **8 / 8** | 18 | 9 | 9 | 0 | 0 | `1.000` (`[0.701, 1.000]`, $n=9$) | `1.000` (`[0.701, 1.000]`, $n=9$) | `1.000` | `0.000` | `1.000` | `1.000` (8 estratos) |
