import crypto from 'node:crypto';
import { AnalyzerRegistry } from '../analyzers/AnalyzerRegistry';
import {
  GOLDEN_DATASET_CORPUS,
  GOLDEN_DATASET_ORIGIN_LABEL,
  GOLDEN_DATASET_VERSION,
} from '../intelligence/datasets/GoldenDatasetCorpus';
import type {
  GoldenValidationCaseResult,
  GoldenValidationSuiteReport,
} from '../types/benchmark';

export class GoldenDatasetRunner {
  public static runValidationSuite(): GoldenValidationSuiteReport {
    const startMs = performance.now();
    const memBefore = process.memoryUsage().rss;
    const cases: GoldenValidationCaseResult[] = [];

    let tp = 0;
    let fp = 0;
    let tn = 0;
    let fn = 0;
    let inconclusiveCases = 0;

    const byLanguageAcc: Record<string, { cases: number; tp: number; fp: number; tn: number; fn: number }> = {};
    const byCategoryAcc: Record<string, { cases: number; tp: number; fp: number; tn: number; fn: number }> = {};

    const datasetSha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(GOLDEN_DATASET_CORPUS), 'utf8')
      .digest('hex');

    for (const item of GOLDEN_DATASET_CORPUS) {
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

    const totalDurationMs = Math.max(1, Math.round(performance.now() - startMs));
    const memAfter = process.memoryUsage().rss;
    const memoryDeltaMb = Math.round(((memAfter - memBefore) / (1024 * 1024)) * 100) / 100;

    // Never return synthetic 1 or 0 when a metric denominator is 0 — return null!
    const calcMetrics = (c: { tp: number; fp: number; tn: number; fn: number }) => {
      const precision = c.tp + c.fp > 0 ? Math.round((c.tp / (c.tp + c.fp)) * 1000) / 1000 : null;
      const recall = c.tp + c.fn > 0 ? Math.round((c.tp / (c.tp + c.fn)) * 1000) / 1000 : null;
      const f1Score =
        precision !== null && recall !== null && precision + recall > 0
          ? Math.round(((2 * precision * recall) / (precision + recall)) * 1000) / 1000
          : null;
      return { precision, recall, f1Score };
    };

    const globalMetrics = calcMetrics({ tp, fp, tn, fn });
    const fpr = fp + tn > 0 ? Math.round((fp / (fp + tn)) * 1000) / 1000 : null;
    const fnr = fn + tp > 0 ? Math.round((fn / (fn + tp)) * 1000) / 1000 : null;

    const byLanguage: GoldenValidationSuiteReport['byLanguage'] = {};
    for (const [lang, acc] of Object.entries(byLanguageAcc)) {
      byLanguage[lang] = { ...acc, ...calcMetrics(acc) };
    }

    const byCategory: GoldenValidationSuiteReport['byCategory'] = {};
    for (const [cat, acc] of Object.entries(byCategoryAcc)) {
      byCategory[cat] = { ...acc, ...calcMetrics(acc) };
    }

    const lowSampleLanguages = Object.entries(byLanguageAcc)
      .filter(([, acc]) => acc.cases < 5)
      .map(([lang, acc]) => `${lang}(n=${acc.cases})`);

    const sampleWarning =
      GOLDEN_DATASET_CORPUS.length < 100 || lowSampleLanguages.length > 0
        ? `Amostra de calibração interna reduzida (N=${GOLDEN_DATASET_CORPUS.length}; subamostras <5 em: ${lowSampleLanguages.join(', ') || 'categorias específicas'}). Não representa o conjunto oficial OWASP Benchmark v1.2 (2.740+ casos).`
        : null;

    const limitations: string[] = [
      'Corpus interno WinHood (WINHOOD_INTERNAL_CALIBRATION_CORPUS), distinto do OWASP Benchmark oficial externo.',
      'Métricas com denominador zero retornam null (não avaliável estatisticamente) em vez de 100% ou 0% artificiais.',
    ];
    if (sampleWarning) limitations.push(sampleWarning);

    const reportBody = {
      validationId: `golden-val-${Date.now()}`,
      executedAt: new Date().toISOString(),
      engineVersion: 'WINHOOD-AST-TAINT-v4.1.0',
      datasetVersion: GOLDEN_DATASET_VERSION,
      datasetOriginLabel: GOLDEN_DATASET_ORIGIN_LABEL,
      datasetSha256,
      sampleWarning,
      totalCases: GOLDEN_DATASET_CORPUS.length,
      inconclusiveCases,
      truePositives: tp,
      falsePositives: fp,
      trueNegatives: tn,
      falseNegatives: fn,
      precision: globalMetrics.precision,
      recall: globalMetrics.recall,
      f1Score: globalMetrics.f1Score,
      falsePositiveRate: fpr,
      falseNegativeRate: fnr,
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
