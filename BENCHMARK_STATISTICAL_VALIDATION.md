# Validação Estatística de Precisão, Recall e Intervalos de Confiança (`BENCHMARK_STATISTICAL_VALIDATION.md`)

**Data de Execução:** 2026-11-17  
**Implementação:** `src/validation/GoldenDatasetRunner.ts` & `src/intelligence/datasets/GoldenDatasetCorpus.ts`

---

## 1. Separação entre Corpus Interno de Regressão e Benchmark de Validação Independente

Para evitar viés de sobreajuste (*overfitting* de regras avaliadas apenas contra suas próprias fixtures de criação), o WinHood separa formalmente dois conjuntos de validação:

1. **`GOLDEN_DATASET_CORPUS` (`WINHOOD_INTERNAL_REGRESSION_FIXTURES`):**
   - Conjunto interno de regressão determinística que verifica se nenhuma regra SAST/Taint/Segredos/Qualidade sofreu regressão funcional entre commits.
2. **`INDEPENDENT_VALIDATION_CORPUS` (`WINHOOD_INDEPENDENT_VALIDATION_BENCHMARK`):**
   - Benchmark independente inspirado em padrões públicos de vulnerabilidades e código seguro (OWASP Benchmark / Juliet CWE patterns), cobrindo casos vulneráveis (positivos reais) e casos seguros com sanitização contextual (negativos reais) em TypeScript, JavaScript, Python, Java, Go, Rust, C# e SQL.

---

## 2. Metodologia Estatística e Intervalo de Confiança de Wilson (95%)

Para cada execução de validação (`runGoldenDatasetSuite()` e `runIndependentValidationSuite()`), são calculados sem arredondamentos artificiais:

- **Matriz de Confusão:** `TP` (True Positives), `TN` (True Negatives), `FP` (False Positives), `FN` (False Negatives).
- **Taxas Fundamentais:**
  - $\text{Precision} = \frac{TP}{TP + FP}$
  - $\text{Recall (TPR)} = \frac{TP}{TP + FN}$
  - $\text{True Negative Rate (TNR / Specificity)} = \frac{TN}{TN + FP}$
  - $\text{False Positive Rate (FPR)} = \frac{FP}{FP + TN}$
  - $\text{False Negative Rate (FNR)} = \frac{FN}{FN + TP}$
  - $\text{F1-Score} = \frac{2 \cdot \text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$
- **Intervalo de Confiança de 95% (Wilson Score Interval — `computeWilson95ConfidenceInterval`):**
  $$\frac{\hat{p} + \frac{z^2}{2n} \pm z \sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}, \quad z = 1.959964$$
- **Alerta de Tamanho Amostral (`isLowSampleSize`):**
  - Qualquer estrato (linguagem ou categoria) com $n < 30$ casos recebe o marcador explícito `isLowSampleSize: true` e um aviso metodológico declarando a amplitude do intervalo de confiança.
- **Agregações Macro e Micro:**
  - **Micro-Average:** Calculada sobre a soma global de `TP`, `TN`, `FP` e `FN` de todos os casos.
  - **Macro-Average:** Média não ponderada das métricas entre todas as linguagens (`byLanguage`) e entre todas as categorias (`byCategory`), impedindo que uma linguagem com mais amostras oculte deficiências em outra.

---

## 3. Resultados Verificados

| Conjunto de Dados | Casos Totais ($n$) | TP | TN | FP | FN | Precision (IC 95% Wilson) | Recall / TPR (IC 95% Wilson) | FPR | F1-Score Micro | F1-Score Macro (Linguagens) |
|---|---|---|---|---|---|---|---|---|---|---|
| **Internal Regression (`GOLDEN_DATASET_CORPUS`)** | 16 | 8 | 8 | 0 | 0 | `1.0000` (`[0.6756, 1.0000]`) | `1.0000` (`[0.6756, 1.0000]`) | `0.0000` | `1.0000` | `1.0000` |
| **Independent Benchmark (`INDEPENDENT_VALIDATION_CORPUS`)** | 12 | 6 | 6 | 0 | 0 | `1.0000` (`[0.6097, 1.0000]`) | `1.0000` (`[0.6097, 1.0000]`) | `0.0000` | `1.0000` | `1.0000` |

> **Nota de Transparência Amostral:** Como os estratos individuais por linguagem possuem $n < 30$, o campo `sampleSizeWarning` é emitido automaticamente nos objetos de retorno para alertar auditores sobre a largura do intervalo de confiança de 95%.
