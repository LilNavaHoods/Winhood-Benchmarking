import crypto from 'node:crypto';
import { AnalyzerRegistry } from '../analyzers/AnalyzerRegistry';
import {
  GOLDEN_DATASET_CORPUS,
  GOLDEN_DATASET_ORIGIN_LABEL,
  GOLDEN_DATASET_VERSION,
  INDEPENDENT_VALIDATION_CORPUS,
  INDEPENDENT_VALIDATION_ORIGIN_LABEL,
  INDEPENDENT_VALIDATION_VERSION,
  type GoldenDatasetCase,
} from '../intelligence/datasets/GoldenDatasetCorpus';
import type {
  GoldenValidationCaseResult,
  GoldenValidationSuiteReport,
  StatisticalAggregateMetrics,
  WilsonConfidenceInterval95,
} from '../types/benchmark';

/**
 * Computes the Wilson Score 95% Confidence Interval (z = 1.96) for a binomial proportion.
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

function computeConfusionMetrics(c: {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}): StatisticalAggregateMetrics {
  const round3 = (v: number) => Math.round(v * 1000) / 1000;
  const precision = c.tp + c.fp > 0 ? round3(c.tp / (c.tp + c.fp)) : null;
  const recall = c.tp + c.fn > 0 ? round3(c.tp / (c.tp + c.fn)) : null;
  const f1Score =
    precision !== null && recall !== null && precision + recall > 0
      ? round3((2 * precision * recall) / (precision + recall))
      : null;
  const truePositiveRate = recall;
  const trueNegativeRate = c.tn + c.fp > 0 ? round3(c.tn / (c.tn + c.fp)) : null;
  const falsePositiveRate = c.fp + c.tn > 0 ? round3(c.fp / (c.fp + c.tn)) : null;
  const falseNegativeRate = c.fn + c.tp > 0 ? round3(c.fn / (c.fn + c.tp)) : null;

  return {
    precision,
    recall,
    f1Score,
    truePositiveRate,
    trueNegativeRate,
    falsePositiveRate,
    falseNegativeRate,
  };
}

function computeMacroAverage(groups: StatisticalAggregateMetrics[]): StatisticalAggregateMetrics {
  const meanNullable = (vals: Array<number | null>): number | null => {
    const valid = vals.filter((v): v is number => v !== null && Number.isFinite(v));
    if (valid.length === 0) return null;
    const sum = valid.reduce((a, b) => a + b, 0);
    return Math.round((sum / valid.length) * 1000) / 1000;
  };
  return {
    precision: meanNullable(groups.map((g) => g.precision)),
    recall: meanNullable(groups.map((g) => g.recall)),
    f1Score: meanNullable(groups.map((g) => g.f1Score)),
    truePositiveRate: meanNullable(groups.map((g) => g.truePositiveRate)),
    trueNegativeRate: meanNullable(groups.map((g) => g.trueNegativeRate)),
    falsePositiveRate: meanNullable(groups.map((g) => g.falsePositiveRate)),
    falseNegativeRate: meanNullable(groups.map((g) => g.falseNegativeRate)),
  };
}

export class GoldenDatasetRunner {
  private static evaluateCorpusCases(corpus: GoldenDatasetCase[]) {
    const cases: GoldenValidationCaseResult[] = [];
    let tp = 0;
    let fp = 0;
    let tn = 0;
    let fn = 0;
    let inconclusiveCases = 0;

    const byLanguageAcc: Record<string, { cases: number; tp: number; fp: number; tn: number; fn: number }> = {};
    const byCategoryAcc: Record<string, { cases: number; tp: number; fp: number; tn: number; fn: number }> = {};

    for (const item of corpus) {
      const caseStart = performance.now();
      const result = AnalyzerRegistry.runNativeAstAndTaintPipeline({
        runId: `golden-${item.caseId}`,
        softwareId: `sw-${item.caseId}`,
        softwareName: item.title,
        softwareVersion: '1.0.0',
        filesMap: item.filesMap,
      });

      const caseDurationMs = Math.max(1, Math.round(performance.now() - caseStart));
      const parseInconclusive =
        result.execution.measurementState === 'NOT_MEASURED' ||
        result.execution.measurementState === 'FAILED' ||
        result.execution.filesFailed > 0;

      const relevantFindings = result.findings.filter((f) => {
        if (item.category === 'ERROR_HANDLING') {
          return f.originalRuleId.includes('S2486') || f.cwe === 'CWE-390';
        }
        if (item.category === 'SQL_SCHEMA') {
          return f.category === 'DATABASE' || f.originalRuleId.includes('sql');
        }
        if (item.category === 'HARDCODED_SECRET') {
          return f.category === 'SECRETS' || f.cwe === 'CWE-798';
        }
        if (item.category === 'WEAK_CRYPTO') {
          return (
            f.cwe === 'CWE-327' ||
            f.cwe === 'CWE-328' ||
            f.originalRuleId.includes('S4790') ||
            f.originalRuleId.includes('B324')
          );
        }
        return (
          f.category === 'SAST' ||
          f.cwe === item.cwe ||
          f.originalRuleId.includes('taint') ||
          f.originalRuleId.includes('S3649') ||
          f.originalRuleId.includes('S2076') ||
          f.originalRuleId.includes('S1523')
        );
      });

      if (!byLanguageAcc[item.language]) {
        byLanguageAcc[item.language] = { cases: 0, tp: 0, fp: 0, tn: 0, fn: 0 };
      }
      byLanguageAcc[item.language].cases += 1;

      if (!byCategoryAcc[item.category]) {
        byCategoryAcc[item.category] = { cases: 0, tp: 0, fp: 0, tn: 0, fn: 0 };
      }
      byCategoryAcc[item.category].cases += 1;

      if (parseInconclusive) {
        inconclusiveCases += 1;
        cases.push({
          caseId: item.caseId,
          title: item.title,
          language: item.language,
          category: item.category,
          cwe: item.cwe,
          expectedVulnerable: item.expectedVulnerable,
          detectedVulnerable: null,
          classification: 'INCONCLUSIVE',
          durationMs: caseDurationMs,
          detectedRules: [],
        });
        continue;
      }

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
      byLanguageAcc,
      byCategoryAcc,
    };
  }

  public static runIndependentValidationSuite(): GoldenValidationSuiteReport {
    return GoldenDatasetRunner.runValidationSuite('INDEPENDENT_VALIDATION');
  }

  public static runValidationSuite(
    datasetMode: 'INTERNAL_CALIBRATION' | 'INDEPENDENT_VALIDATION' = 'INTERNAL_CALIBRATION'
  ): GoldenValidationSuiteReport {
    const startMs = performance.now();
    const memBefore = process.memoryUsage().rss;

    const primaryCorpus =
      datasetMode === 'INDEPENDENT_VALIDATION'
        ? INDEPENDENT_VALIDATION_CORPUS
        : GOLDEN_DATASET_CORPUS;
    const primaryVersion =
      datasetMode === 'INDEPENDENT_VALIDATION'
        ? INDEPENDENT_VALIDATION_VERSION
        : GOLDEN_DATASET_VERSION;
    const primaryOriginLabel =
      datasetMode === 'INDEPENDENT_VALIDATION'
        ? INDEPENDENT_VALIDATION_ORIGIN_LABEL
        : GOLDEN_DATASET_ORIGIN_LABEL;

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
      byLanguageAcc,
      byCategoryAcc,
    } = GoldenDatasetRunner.evaluateCorpusCases(primaryCorpus);

    // Also evaluate the independent validation corpus when running the primary suite so both are reported transparently
    const independentEval = GoldenDatasetRunner.evaluateCorpusCases(INDEPENDENT_VALIDATION_CORPUS);
    const independentMetrics = computeConfusionMetrics({
      tp: independentEval.tp,
      fp: independentEval.fp,
      tn: independentEval.tn,
      fn: independentEval.fn,
    });

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
        lowSampleWarning: acc.cases < 5,
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
        lowSampleWarning: acc.cases < 5,
      };
    }

    const lowSampleLanguages = Object.entries(byLanguageAcc)
      .filter(([, acc]) => acc.cases < 5)
      .map(([lang, acc]) => `${lang}(n=${acc.cases})`);

    const sampleWarning =
      primaryCorpus.length < 100 || lowSampleLanguages.length > 0
        ? `Amostra reduzida (N=${primaryCorpus.length}; subamostras <5 em: ${lowSampleLanguages.join(', ') || 'categorias específicas'}). Intervalos de confiança de 95% (Wilson Score) reportados explicitamente; não representa o conjunto oficial OWASP Benchmark v1.2 (2.740+ casos).`
        : null;

    const limitations: string[] = [
      'Separação estrita entre corpus interno de regressão (WINHOOD_INTERNAL_CALIBRATION_CORPUS) e benchmark independente (WINHOOD_INDEPENDENT_VALIDATION_BENCHMARK).',
      'Métricas com denominador zero retornam null (não avaliável estatisticamente) em vez de 100% ou 0% artificiais.',
      'Intervalos de confiança de 95% calculados pelo método exato de Wilson Score (z = 1.96).',
    ];
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
      datasetOriginLabel: primaryOriginLabel,
      datasetSha256,
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
      independentValidationSummary: {
        datasetVersion: INDEPENDENT_VALIDATION_VERSION,
        datasetOriginLabel: INDEPENDENT_VALIDATION_ORIGIN_LABEL,
        totalCases: INDEPENDENT_VALIDATION_CORPUS.length,
        truePositives: independentEval.tp,
        falsePositives: independentEval.fp,
        trueNegatives: independentEval.tn,
        falseNegatives: independentEval.fn,
        precision: independentMetrics.precision,
        recall: independentMetrics.recall,
        f1Score: independentMetrics.f1Score,
        falsePositiveRate: independentMetrics.falsePositiveRate,
        falseNegativeRate: independentMetrics.falseNegativeRate,
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
