import crypto from 'node:crypto';
import { AnalyzerRegistry } from '../analyzers/AnalyzerRegistry';
import {
  computeGoldenCaseContentSha256,
  DECLARED_BENCHMARK_LANGUAGES,
  DEVELOPMENT_DATASET_CORPUS,
  DEVELOPMENT_DATASET_ORIGIN_LABEL,
  DEVELOPMENT_DATASET_VERSION,
  GOLDEN_DATASET_CORPUS,
  GOLDEN_DATASET_ORIGIN_LABEL,
  GOLDEN_DATASET_VERSION,
  INTERNAL_HOLDOUT_CORPUS,
  INTERNAL_HOLDOUT_ORIGIN_LABEL,
  INTERNAL_HOLDOUT_VERSION,
  type GoldenDatasetCase,
} from '../intelligence/datasets/GoldenDatasetCorpus';
import type {
  GoldenDatasetOriginLabel,
  GoldenDatasetRole,
  GoldenValidationCaseResult,
  GoldenValidationSuiteReport,
  StatisticalAggregateMetrics,
  WilsonConfidenceInterval95,
} from '../types/benchmark';

export const GOLDEN_LOW_SAMPLE_THRESHOLD = 30;

/**
 * Computes the Wilson Score 95% Confidence Interval (z = 1.95996...) for a binomial proportion.
 * Returns null bounds when sampleSize === 0 (never fabricates 0% or 100% on empty denominator).
 */
export function computeWilson95ConfidenceInterval(
  successes: number,
  sampleSize: number
): WilsonConfidenceInterval95 {
  if (sampleSize <= 0) {
    return {
      pointEstimate: null,
      lower: null,
      upper: null,
      sampleSize: 0,
    };
  }
  const z = 1.959963984540054; // 95% two-sided normal quantile
  const z2 = z * z;
  const n = sampleSize;
  const pHat = successes / n;
  const denom = 1 + z2 / n;
  const center = (pHat + z2 / (2 * n)) / denom;
  const halfWidth =
    (z * Math.sqrt((pHat * (1 - pHat)) / n + z2 / (4 * n * n))) / denom;

  const round3 = (v: number) => Math.max(0, Math.min(1, Math.round(v * 1000) / 1000));
  return {
    pointEstimate: round3(pHat),
    lower: round3(center - halfWidth),
    upper: round3(center + halfWidth),
    sampleSize: n,
  };
}

/**
 * Computes confusion metrics directly from raw counts without intermediate rounding
 * (F1 = 2*TP / (2*TP + FP + FN)). Returns null on zero denominator.
 */
export function computeConfusionMetrics(c: {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}): StatisticalAggregateMetrics {
  const round3 = (v: number) => Math.round(v * 1000) / 1000;
  const rawPrecision = c.tp + c.fp > 0 ? c.tp / (c.tp + c.fp) : null;
  const rawRecall = c.tp + c.fn > 0 ? c.tp / (c.tp + c.fn) : null;
  const rawF1 =
    c.tp + c.fp > 0 && c.tp + c.fn > 0 && 2 * c.tp + c.fp + c.fn > 0
      ? (2 * c.tp) / (2 * c.tp + c.fp + c.fn)
      : null;
  const rawTnr = c.tn + c.fp > 0 ? c.tn / (c.tn + c.fp) : null;
  const rawFpr = c.fp + c.tn > 0 ? c.fp / (c.fp + c.tn) : null;
  const rawFnr = c.fn + c.tp > 0 ? c.fn / (c.fn + c.tp) : null;

  return {
    precision: rawPrecision !== null ? round3(rawPrecision) : null,
    recall: rawRecall !== null ? round3(rawRecall) : null,
    f1Score: rawF1 !== null ? round3(rawF1) : null,
    truePositiveRate: rawRecall !== null ? round3(rawRecall) : null,
    trueNegativeRate: rawTnr !== null ? round3(rawTnr) : null,
    falsePositiveRate: rawFpr !== null ? round3(rawFpr) : null,
    falseNegativeRate: rawFnr !== null ? round3(rawFnr) : null,
  };
}

function computeMacroAverage(groups: StatisticalAggregateMetrics[]): StatisticalAggregateMetrics {
  const meanNullable = (vals: Array<number | null>): number | null => {
    const valid = vals.filter((v): v is number => v !== null && Number.isFinite(v));
    if (valid.length === 0) return null;
    const sum = valid.reduce((a, b) => a + b, 0);
    return Math.round((sum / valid.length) * 1000) / 1000;
  };
  const evaluatedStrataCount = groups.filter(
    (g) =>
      g.precision !== null ||
      g.recall !== null ||
      g.trueNegativeRate !== null ||
      g.falsePositiveRate !== null
  ).length;

  return {
    precision: meanNullable(groups.map((g) => g.precision)),
    recall: meanNullable(groups.map((g) => g.recall)),
    f1Score: meanNullable(groups.map((g) => g.f1Score)),
    truePositiveRate: meanNullable(groups.map((g) => g.truePositiveRate)),
    trueNegativeRate: meanNullable(groups.map((g) => g.trueNegativeRate)),
    falsePositiveRate: meanNullable(groups.map((g) => g.falsePositiveRate)),
    falseNegativeRate: meanNullable(groups.map((g) => g.falseNegativeRate)),
    evaluatedStrataCount,
  };
}

export interface GoldenValidationOptions {
  customCorpus?: GoldenDatasetCase[];
  customVersion?: string;
  customOriginLabel?: GoldenDatasetOriginLabel;
}

export class GoldenDatasetRunner {
  private static evaluateCorpusCases(corpus: GoldenDatasetCase[]) {
    const cases: GoldenValidationCaseResult[] = [];
    let tp = 0;
    let fp = 0;
    let tn = 0;
    let fn = 0;
    let inconclusiveCases = 0;
    const integrityErrors: string[] = [];

    const byLanguageAcc: Record<
      string,
      { cases: number; inconclusiveCases: number; tp: number; fp: number; tn: number; fn: number }
    > = {};
    const byCategoryAcc: Record<
      string,
      { cases: number; inconclusiveCases: number; tp: number; fp: number; tn: number; fn: number }
    > = {};

    for (const item of corpus) {
      const caseStart = performance.now();
      const expectedSha = computeGoldenCaseContentSha256(item.filesMap);
      const contentHashVerified = item.contentSha256 === expectedSha;
      if (!contentHashVerified) {
        integrityErrors.push(
          `SHA-256 divergente no caso ${item.caseId}: esperado ${item.contentSha256}, observado ${expectedSha}.`
        );
      }

      const fileCount = Object.keys(item.filesMap || {}).length;
      const result =
        fileCount > 0
          ? AnalyzerRegistry.runNativeAstAndTaintPipeline({
              runId: `golden-${item.caseId}`,
              softwareId: `sw-${item.caseId}`,
              softwareName: item.title,
              softwareVersion: '1.0.0',
              filesMap: item.filesMap,
            })
          : null;

      const caseDurationMs = Math.max(1, Math.round(performance.now() - caseStart));
      const parseInconclusive =
        !result ||
        result.execution.measurementState === 'NOT_MEASURED' ||
        result.execution.measurementState === 'FAILED' ||
        result.execution.filesFailed > 0 ||
        result.execution.filesProcessed === 0;

      if (!byLanguageAcc[item.language]) {
        byLanguageAcc[item.language] = { cases: 0, inconclusiveCases: 0, tp: 0, fp: 0, tn: 0, fn: 0 };
      }
      byLanguageAcc[item.language].cases += 1;

      if (!byCategoryAcc[item.category]) {
        byCategoryAcc[item.category] = { cases: 0, inconclusiveCases: 0, tp: 0, fp: 0, tn: 0, fn: 0 };
      }
      byCategoryAcc[item.category].cases += 1;

      if (parseInconclusive) {
        inconclusiveCases += 1;
        byLanguageAcc[item.language].inconclusiveCases += 1;
        byCategoryAcc[item.category].inconclusiveCases += 1;
        cases.push({
          caseId: item.caseId,
          title: item.title,
          language: item.language,
          category: item.category,
          cwe: item.cwe,
          datasetRole: item.datasetRole,
          origin: item.origin,
          license: item.license,
          contentSha256: item.contentSha256,
          contentHashVerified,
          expectedVulnerable: item.expectedVulnerable,
          detectedVulnerable: null,
          classification: 'INCONCLUSIVE',
          durationMs: caseDurationMs,
          detectedRules: [],
        });
        continue;
      }

      const relevantFindings = result.findings.filter((f) => {
        if (item.category === 'ERROR_HANDLING') {
          return f.originalRuleId.includes('S2486') || f.cwe === 'CWE-390';
        }
        if (item.category === 'SQL_SCHEMA') {
          return f.category === 'DATABASE' || f.originalRuleId.includes('sql');
        }
        if (item.category === 'HARDCODED_SECRET') {
          return f.category === 'SECRETS' || f.cwe === 'CWE-798' || f.originalRuleId.includes('S6418');
        }
        if (item.category === 'WEAK_CRYPTO') {
          return (
            f.cwe === 'CWE-327' ||
            f.cwe === 'CWE-328' ||
            f.originalRuleId.includes('S4790') ||
            f.originalRuleId.includes('B324')
          );
        }
        if (item.category === 'MEMORY_SAFETY') {
          return f.cwe === 'CWE-119' || f.originalRuleId.includes('UNSAFE');
        }
        return (
          f.category === 'SAST' ||
          f.cwe === item.cwe ||
          f.originalRuleId.includes('taint') ||
          f.originalRuleId.includes('S3649') ||
          f.originalRuleId.includes('S2077') ||
          f.originalRuleId.includes('S2076') ||
          f.originalRuleId.includes('S1523')
        );
      });

      const detectedVulnerable = relevantFindings.length > 0;
      let classification: 'TP' | 'FP' | 'TN' | 'FN';
      if (item.expectedVulnerable && detectedVulnerable) {
        classification = 'TP';
        tp += 1;
      } else if (!item.expectedVulnerable && detectedVulnerable) {
        classification = 'FP';
        fp += 1;
      } else if (!item.expectedVulnerable && !detectedVulnerable) {
        classification = 'TN';
        tn += 1;
      } else {
        classification = 'FN';
        fn += 1;
      }

      byLanguageAcc[item.language][classification.toLowerCase() as 'tp' | 'fp' | 'tn' | 'fn'] += 1;
      byCategoryAcc[item.category][classification.toLowerCase() as 'tp' | 'fp' | 'tn' | 'fn'] += 1;

      cases.push({
        caseId: item.caseId,
        title: item.title,
        language: item.language,
        category: item.category,
        cwe: item.cwe,
        datasetRole: item.datasetRole,
        origin: item.origin,
        license: item.license,
        contentSha256: item.contentSha256,
        contentHashVerified,
        expectedVulnerable: item.expectedVulnerable,
        detectedVulnerable,
        classification,
        durationMs: caseDurationMs,
        detectedRules: relevantFindings.map((f) => f.originalRuleId),
      });
    }

    return {
      cases,
      tp,
      fp,
      tn,
      fn,
      inconclusiveCases,
      integrityErrors,
      byLanguageAcc,
      byCategoryAcc,
    };
  }

  public static runHoldoutValidationSuite(): GoldenValidationSuiteReport {
    return GoldenDatasetRunner.runValidationSuite('INTERNAL_HOLDOUT');
  }

  /**
   * @deprecated Alias de compatibilidade; retorna o conjunto INTERNAL_HOLDOUT sem alegar independência externa.
   */
  public static runIndependentValidationSuite(): GoldenValidationSuiteReport {
    return GoldenDatasetRunner.runValidationSuite('INTERNAL_HOLDOUT');
  }

  public static runValidationSuite(
    datasetMode: GoldenDatasetRole = 'REGRESSION',
    options?: GoldenValidationOptions
  ): GoldenValidationSuiteReport {
    const startMs = performance.now();
    const memBefore = process.memoryUsage().rss;

    const primaryCorpus =
      options?.customCorpus ??
      (datasetMode === 'INTERNAL_HOLDOUT'
        ? INTERNAL_HOLDOUT_CORPUS
        : datasetMode === 'DEVELOPMENT'
          ? DEVELOPMENT_DATASET_CORPUS
          : GOLDEN_DATASET_CORPUS);

    const primaryVersion =
      options?.customVersion ??
      (datasetMode === 'INTERNAL_HOLDOUT'
        ? INTERNAL_HOLDOUT_VERSION
        : datasetMode === 'DEVELOPMENT'
          ? DEVELOPMENT_DATASET_VERSION
          : GOLDEN_DATASET_VERSION);

    const primaryOriginLabel: GoldenDatasetOriginLabel =
      options?.customOriginLabel ??
      (datasetMode === 'INTERNAL_HOLDOUT'
        ? INTERNAL_HOLDOUT_ORIGIN_LABEL
        : datasetMode === 'DEVELOPMENT'
          ? DEVELOPMENT_DATASET_ORIGIN_LABEL
          : GOLDEN_DATASET_ORIGIN_LABEL);

    const datasetSha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(primaryCorpus), 'utf8')
      .digest('hex');

    const {
      cases,
      tp,
      fp,
      tn,
      fn,
      inconclusiveCases,
      integrityErrors,
      byLanguageAcc,
      byCategoryAcc,
    } = GoldenDatasetRunner.evaluateCorpusCases(primaryCorpus);

    const holdoutEval = GoldenDatasetRunner.evaluateCorpusCases(INTERNAL_HOLDOUT_CORPUS);
    const holdoutMetrics = computeConfusionMetrics({
      tp: holdoutEval.tp,
      fp: holdoutEval.fp,
      tn: holdoutEval.tn,
      fn: holdoutEval.fn,
    });
    const holdoutLangs = Object.keys(holdoutEval.byLanguageAcc);
    const holdoutMissingLangs = DECLARED_BENCHMARK_LANGUAGES.filter((l) => !holdoutLangs.includes(l));

    const totalDurationMs = Math.max(1, Math.round(performance.now() - startMs));
    const memAfter = process.memoryUsage().rss;
    const memoryDeltaMb = Math.round(((memAfter - memBefore) / (1024 * 1024)) * 100) / 100;

    const microAverages = computeConfusionMetrics({ tp, fp, tn, fn });

    const byLanguage: GoldenValidationSuiteReport['byLanguage'] = {};
    const langGroupMetrics: StatisticalAggregateMetrics[] = [];
    for (const [lang, acc] of Object.entries(byLanguageAcc)) {
      const m = computeConfusionMetrics(acc);
      langGroupMetrics.push(m);
      byLanguage[lang] = {
        ...acc,
        precision: m.precision,
        recall: m.recall,
        f1Score: m.f1Score,
        tpr: m.truePositiveRate,
        tnr: m.trueNegativeRate,
        fpr: m.falsePositiveRate,
        fnr: m.falseNegativeRate,
        precisionCi95: computeWilson95ConfidenceInterval(acc.tp, acc.tp + acc.fp),
        recallCi95: computeWilson95ConfidenceInterval(acc.tp, acc.tp + acc.fn),
        lowSampleWarning: acc.cases < GOLDEN_LOW_SAMPLE_THRESHOLD,
      };
    }

    const byCategory: GoldenValidationSuiteReport['byCategory'] = {};
    const catGroupMetrics: StatisticalAggregateMetrics[] = [];
    for (const [cat, acc] of Object.entries(byCategoryAcc)) {
      const m = computeConfusionMetrics(acc);
      catGroupMetrics.push(m);
      byCategory[cat] = {
        ...acc,
        precision: m.precision,
        recall: m.recall,
        f1Score: m.f1Score,
        tpr: m.truePositiveRate,
        tnr: m.trueNegativeRate,
        fpr: m.falsePositiveRate,
        fnr: m.falseNegativeRate,
        precisionCi95: computeWilson95ConfidenceInterval(acc.tp, acc.tp + acc.fp),
        recallCi95: computeWilson95ConfidenceInterval(acc.tp, acc.tp + acc.fn),
        lowSampleWarning: acc.cases < GOLDEN_LOW_SAMPLE_THRESHOLD,
      };
    }

    const languagesRepresented = Object.keys(byLanguageAcc);
    const missingDeclaredLanguages = DECLARED_BENCHMARK_LANGUAGES.filter(
      (lang) => !languagesRepresented.includes(lang)
    );

    const lowSampleLanguages = Object.entries(byLanguageAcc)
      .filter(([, acc]) => acc.cases < GOLDEN_LOW_SAMPLE_THRESHOLD)
      .map(([lang, acc]) => `${lang}(n=${acc.cases})`);

    const sampleWarning =
      primaryCorpus.length < GOLDEN_LOW_SAMPLE_THRESHOLD || lowSampleLanguages.length > 0
        ? `Indicador operacional de amostra pequena (n < ${GOLDEN_LOW_SAMPLE_THRESHOLD}): conjunto ${datasetMode} possui N=${primaryCorpus.length} casos no total e subamostras n < ${GOLDEN_LOW_SAMPLE_THRESHOLD} em: ${lowSampleLanguages.join(', ') || 'estratos específicos'}. Nota: n < 30 é apenas um limiar operacional de alerta de amostra reduzida (não garantia universal de significância estatística). Os Intervalos de Confiança de 95% (Wilson Score) expressam a incerteza exata de cada proporção.`
        : null;

    const limitations: string[] = [
      'Separação estrita em 3 conjuntos versionados de autoria interna: DEVELOPMENT, REGRESSION e INTERNAL_HOLDOUT.',
      'Estes corpora são de autoria interna do WinHood; NÃO representam um benchmark externo independente de terceiros (ex.: OWASP Benchmark v1.2 / NIST Juliet).',
      'Métricas com denominador zero retornam null (não avaliável estatisticamente) em vez de 0% ou 100% artificiais.',
      'Métricas de precisão, recall, F1, TPR, TNR, FPR e FNR são computadas diretamente sobre contagens brutas (sem arredondamento intermediário) e acompanhadas de IC 95% pelo método de Wilson Score (z = 1.96).',
    ];
    if (missingDeclaredLanguages.length > 0) {
      limitations.push(
        `Cobertura incompleta de linguagens declaradas: ausentes [${missingDeclaredLanguages.join(', ')}].`
      );
    }
    if (integrityErrors.length > 0) {
      limitations.push(`Falha de integridade SHA-256 detectada em ${integrityErrors.length} caso(s).`);
    }
    if (sampleWarning) limitations.push(sampleWarning);

    const confidenceIntervals95 = {
      precision: computeWilson95ConfidenceInterval(tp, tp + fp),
      recall: computeWilson95ConfidenceInterval(tp, tp + fn),
      truePositiveRate: computeWilson95ConfidenceInterval(tp, tp + fn),
      trueNegativeRate: computeWilson95ConfidenceInterval(tn, tn + fp),
      falsePositiveRate: computeWilson95ConfidenceInterval(fp, fp + tn),
      falseNegativeRate: computeWilson95ConfidenceInterval(fn, fn + tp),
    };

    const macroAverages = {
      byLanguage: computeMacroAverage(langGroupMetrics),
      byCategory: computeMacroAverage(catGroupMetrics),
    };

    const reportBody = {
      validationId: `golden-val-${Date.now()}`,
      executedAt: new Date().toISOString(),
      engineVersion: 'WINHOOD-AST-TAINT-v4.1.0',
      datasetVersion: primaryVersion,
      datasetRole: datasetMode,
      datasetOriginLabel: primaryOriginLabel,
      datasetSha256,
      datasetIntegrityVerified: integrityErrors.length === 0,
      integrityErrors,
      declaredLanguagesTotal: DECLARED_BENCHMARK_LANGUAGES.length,
      languagesRepresented,
      missingDeclaredLanguages,
      lowSampleThreshold: GOLDEN_LOW_SAMPLE_THRESHOLD,
      sampleWarning,
      totalCases: primaryCorpus.length,
      inconclusiveCases,
      truePositives: tp,
      falsePositives: fp,
      trueNegatives: tn,
      falseNegatives: fn,
      precision: microAverages.precision,
      recall: microAverages.recall,
      f1Score: microAverages.f1Score,
      truePositiveRate: microAverages.truePositiveRate,
      trueNegativeRate: microAverages.trueNegativeRate,
      falsePositiveRate: microAverages.falsePositiveRate,
      falseNegativeRate: microAverages.falseNegativeRate,
      confidenceIntervals95,
      macroAverages,
      microAverages,
      holdoutValidationSummary: {
        datasetVersion: INTERNAL_HOLDOUT_VERSION,
        datasetRole: 'INTERNAL_HOLDOUT' as const,
        datasetOriginLabel: 'WINHOOD_INTERNAL_HOLDOUT_CORPUS' as const,
        totalCases: INTERNAL_HOLDOUT_CORPUS.length,
        inconclusiveCases: holdoutEval.inconclusiveCases,
        truePositives: holdoutEval.tp,
        falsePositives: holdoutEval.fp,
        trueNegatives: holdoutEval.tn,
        falseNegatives: holdoutEval.fn,
        precision: holdoutMetrics.precision,
        recall: holdoutMetrics.recall,
        f1Score: holdoutMetrics.f1Score,
        falsePositiveRate: holdoutMetrics.falsePositiveRate,
        falseNegativeRate: holdoutMetrics.falseNegativeRate,
        languagesRepresented: holdoutLangs,
        missingDeclaredLanguages: holdoutMissingLangs,
      },
      totalDurationMs,
      memoryDeltaMb,
      limitations,
      byLanguage,
      byCategory,
      cases,
    };

    const reportSha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(reportBody), 'utf8')
      .digest('hex');

    return {
      ...reportBody,
      reportSha256,
    };
  }
}
