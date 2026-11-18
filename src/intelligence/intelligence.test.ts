import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { ReferenceRegistry } from './reference/ReferenceRegistry';
import { stripTrailingSlashes } from './synchronization/ReferenceSynchronizer';
import { BenchmarkMatcher } from './comparison/BenchmarkMatcher';
import { KeyManagementService } from '../security/KeyManagementService';
import { ControlledTestAndPerfRunner } from '../execution/ControlledTestAndPerfRunner';
import { GoldenDatasetRunner } from '../validation/GoldenDatasetRunner';
import { ALL_BENCHMARK_CATEGORIES } from '../engine/scoringEngine';
import { buildTechnicalInventory } from '../engine/staticAnalyzer';
import { KEESAFE_OPEN_FILES } from '../engine/realSampleRepositories';
import type { Software } from '../types/benchmark';

test('ReferenceRegistry manages all 10 mandatory sources and preserves cached snapshots on sync failure', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-ref-test-'));
  try {
    const registry = new ReferenceRegistry(tmpDir);
    const list = registry.listSnapshots(3);
    assert.equal(list.length, 10);

    const updated = registry.markSyncFailureFallback('OSV_DEV', 'Network unreachable test');
    assert.ok(updated);
    assert.equal(updated.freshnessStatus, 'UNAVAILABLE_USING_CACHED');
    assert.equal(updated.isOfflineFallback, true);
    assert.ok(updated.sha256.length === 64);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('BenchmarkMatcher checks 11 criteria and blocks official winner when domains or languages mismatch', () => {
  const inv = buildTechnicalInventory(KEESAFE_OPEN_FILES, '/tmp/match-a');
  const swA: Software = {
    id: 'sw-match-a',
    projectId: 'p1',
    name: 'VaultA',
    vendor: 'Acme',
    description: 'Password vault',
    category: 'Security',
    functionalDomain: 'PASSWORD_SECURITY_VAULT',
    version: '1.0.0',
    languages: ['TypeScript'],
    architecture: 'Modular',
    operatingSystem: 'Linux',
    distributionModel: 'OSS',
    licenseType: 'MIT',
    officialUrl: '',
    repositoryUrl: '',
    documentationUrl: '',
    owner: 'QA',
    notes: '',
    sourceType: 'LOCAL_UPLOAD',
    commitHash: 'aaa111',
    packageSha256: inv.packageSha256,
    createdAt: new Date().toISOString(),
    inventory: inv,
    sourceFilesContent: KEESAFE_OPEN_FILES,
  };
  const swB: Software = {
    ...swA,
    id: 'sw-match-b',
    name: 'GameB',
    functionalDomain: 'GAME_INTERACTIVE',
    languages: ['Rust'],
  };

  const decision = BenchmarkMatcher.evaluate({
    mode: 'AB_SOFTWARE',
    softwares: [swA, swB],
    profile: {
      enabledCategories: ALL_BENCHMARK_CATEGORIES,
      notApplicableCategories: [],
      qualityGateId: 'qg-sonar-way',
    },
    scoreCards: [],
    algorithmVersion: 'WINHOOD-SONAR-MQR-v3.0.0',
    environmentEquivalent: true,
  });

  assert.equal(decision.checks.length, 11);
  assert.equal(decision.canDeclareOfficialWinner, false);
  assert.ok(decision.blockingReasons.length >= 1);

  // Doc-only vs Full source blocked on AVAILABLE_REPORTS
  const swDocOnly: Software = {
    ...swA,
    id: 'sw-doc-only-match',
    name: 'ClosedDocs',
    sourceType: 'PUBLIC_DOCUMENTATION_ONLY',
    sourceAvailability: 'PUBLIC_DOCUMENTATION_ONLY',
    sourceFilesContent: undefined,
  };
  const docDecision = BenchmarkMatcher.evaluate({
    mode: 'AB_SOFTWARE',
    softwares: [swA, swDocOnly],
    profile: {
      enabledCategories: ALL_BENCHMARK_CATEGORIES,
      notApplicableCategories: [],
      qualityGateId: 'qg-sonar-way',
    },
    algorithmVersion: 'WINHOOD-SONAR-MQR-v3.0.0',
    environmentEquivalent: true,
  });
  assert.equal(docDecision.checks.find((c) => c.criterion === 'AVAILABLE_REPORTS')?.passed, false);
  assert.equal(docDecision.canDeclareOfficialWinner, false);

  // Measured coverage vs null coverage blocked on TEST_COVERAGE
  const swA2: Software = { ...swA, id: 'sw-cov-b', name: 'VaultB' };
  const covDecision = BenchmarkMatcher.evaluate({
    mode: 'AB_SOFTWARE',
    softwares: [swA, swA2],
    profile: {
      enabledCategories: ALL_BENCHMARK_CATEGORIES,
      notApplicableCategories: [],
      qualityGateId: 'qg-sonar-way',
    },
    scoreCards: [
      { softwareName: 'VaultA', metricsSummary: { testCoveragePercent: 85 } } as any,
      { softwareName: 'VaultB', metricsSummary: { testCoveragePercent: null } } as any,
    ],
    algorithmVersion: 'WINHOOD-SONAR-MQR-v3.0.0',
    environmentEquivalent: true,
  });
  assert.equal(covDecision.checks.find((c) => c.criterion === 'TEST_COVERAGE')?.passed, false);
  assert.equal(covDecision.canDeclareOfficialWinner, false);
});

test('KeyManagementService generates external keystore, rotates keys preserving history, and validates strict admin token', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-kms-test-'));
  const keystorePath = path.join(tmpDir, 'keystore.json');
  const prevSecret = process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
  const prevAdmin = process.env.WINHOOD_ADMIN_TOKEN;
  delete process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
  delete process.env.WINHOOD_ADMIN_TOKEN;

  try {
    const initialStatus = KeyManagementService.getStatus(keystorePath);
    const oldKeyId = initialStatus.activeEvidenceKeyId;
    const oldSecret = KeyManagementService.getEvidenceSecretByKeyId(oldKeyId, keystorePath);
    assert.ok(oldSecret && oldSecret.length >= 32);

    const rotated = KeyManagementService.rotateKey('EVIDENCE_HMAC', keystorePath);
    assert.notEqual(rotated.keyId, oldKeyId);
    assert.equal(rotated.status, 'ACTIVE');

    const afterStatus = KeyManagementService.getStatus(keystorePath);
    assert.equal(afterStatus.activeEvidenceKeyId, rotated.keyId);
    const retiredEntry = afterStatus.keys.find((k) => k.keyId === oldKeyId);
    assert.equal(retiredEntry?.status, 'RETIRED_VERIFY_ONLY');
    assert.ok(KeyManagementService.getEvidenceSecretByKeyId(oldKeyId, keystorePath));

    assert.equal(KeyManagementService.verifyStrictAdminToken('hardcoded-guess', keystorePath), false);
  } finally {
    if (prevSecret !== undefined) process.env.WINHOOD_EVIDENCE_HMAC_SECRET = prevSecret;
    if (prevAdmin !== undefined) process.env.WINHOOD_ADMIN_TOKEN = prevAdmin;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('ControlledTestAndPerfRunner runs isolated node --test, blocks unauthorized SSRF, and separates agent vs target telemetry on explicit loopback', async () => {
  const testResult = ControlledTestAndPerfRunner.runIsolatedTestSuite({
    softwareName: 'UnitRunnerCheck',
    filesMap: {
      'calc.mjs': 'export function add(a, b) { return a + b; }\n',
      'calc.test.mjs':
        'import test from "node:test"; import assert from "node:assert/strict"; import { add } from "./calc.mjs"; test("adds", () => assert.equal(add(2, 3), 5));\n',
    },
  });
  assert.equal(testResult.executed, true);
  assert.equal(testResult.testsTotal, 1);
  assert.equal(testResult.testsPassed, 1);
  assert.equal(testResult.provenance.state, 'MEASURED');

  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"ok":true}');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const addr = server.address();
    assert.ok(addr && typeof addr === 'object');

    // Unauthorized loopback & metadata must be blocked by SsrfGuard
    const blockedLoopback = await ControlledTestAndPerfRunner.measureHttpWorkload({
      targetUrl: `http://127.0.0.1:${addr.port}/health`,
      requestsCount: 5,
      concurrency: 1,
    });
    assert.equal(blockedLoopback.status, 'BLOCKED_SSRF');

    const blockedMeta = await ControlledTestAndPerfRunner.measureHttpWorkload({
      targetUrl: 'http://169.254.169.254/latest/meta-data',
      requestsCount: 5,
      concurrency: 1,
    });
    assert.equal(blockedMeta.status, 'BLOCKED_SSRF');

    // Explicit authorized loopback executes and cleanly separates agentMetrics vs null targetMetrics
    const perf = await ControlledTestAndPerfRunner.measureHttpWorkload({
      targetUrl: `http://127.0.0.1:${addr.port}/health`,
      requestsCount: 10,
      concurrency: 2,
      allowExplicitLoopback: true,
    });
    assert.equal(perf.status, 'MEASURED');
    assert.equal(perf.successfulResponses, 10);
    assert.ok((perf.throughputRps ?? 0) > 0);
    assert.ok(perf.agentMetrics.runnerMemoryRssMb > 0);
    assert.equal(perf.targetMetrics.cpuPercent, null);
    assert.equal(perf.targetMetrics.memoryRssMb, null);
    assert.equal(perf.cpuPercent, null);
    assert.equal(perf.memoryRssMb, null);
    assert.equal(perf.provenance.state, 'MEASURED');
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('GoldenDatasetRunner executes 3-set split (DEVELOPMENT, REGRESSION, INTERNAL_HOLDOUT) across all 8 declared languages with traceability metadata', () => {
  const devReport = GoldenDatasetRunner.runValidationSuite('DEVELOPMENT');
  assert.equal(devReport.datasetRole, 'DEVELOPMENT');
  assert.equal(devReport.datasetOriginLabel, 'WINHOOD_INTERNAL_DEVELOPMENT_CORPUS');
  assert.ok(devReport.totalCases >= 4);
  assert.equal(devReport.datasetIntegrityVerified, true);

  const regReport = GoldenDatasetRunner.runValidationSuite('REGRESSION');
  assert.equal(regReport.datasetRole, 'REGRESSION');
  assert.equal(regReport.datasetOriginLabel, 'WINHOOD_INTERNAL_REGRESSION_CORPUS');
  assert.equal(regReport.totalCases, 26);
  assert.equal(regReport.missingDeclaredLanguages.length, 0);
  assert.equal(regReport.declaredLanguagesTotal, 8);
  assert.equal(regReport.datasetSha256.length, 64);
  assert.equal(regReport.datasetIntegrityVerified, true);
  assert.equal(regReport.lowSampleThreshold, 30);
  assert.ok(Boolean(regReport.sampleWarning));
  assert.ok((regReport.precision ?? 0) >= 0.85, `Expected precision >= 0.85, got ${regReport.precision}`);
  assert.ok((regReport.recall ?? 0) >= 0.85, `Expected recall >= 0.85, got ${regReport.recall}`);
  assert.ok((regReport.f1Score ?? 0) >= 0.85, `Expected F1 >= 0.85, got ${regReport.f1Score}`);
  assert.equal(regReport.reportSha256.length, 64);
  for (const c of regReport.cases) {
    assert.ok(c.origin && c.license && c.contentSha256?.length === 64 && c.contentHashVerified === true);
  }

  const holdReport = GoldenDatasetRunner.runHoldoutValidationSuite();
  assert.equal(holdReport.datasetRole, 'INTERNAL_HOLDOUT');
  assert.equal(holdReport.datasetOriginLabel, 'WINHOOD_INTERNAL_HOLDOUT_CORPUS');
  assert.equal(holdReport.missingDeclaredLanguages.length, 0);
  assert.equal(holdReport.totalCases, 18);
  assert.equal(holdReport.datasetIntegrityVerified, true);
  assert.ok((holdReport.precision ?? 0) >= 0.85);
  assert.ok((holdReport.recall ?? 0) >= 0.85);
});

test('Phase 7 Statistical & Integrity Matrix (11 mandatory scenarios): n<30 vs n>=30, null denominators, TP/TN/FP/FN, inconclusive, strata counts, missing languages, SHA-256 tamper', async () => {
  const { computeConfusionMetrics, computeWilson95ConfidenceInterval } = await import(
    '../validation/GoldenDatasetRunner'
  );
  const { GOLDEN_DATASET_CORPUS, computeGoldenCaseContentSha256 } = await import(
    './datasets/GoldenDatasetCorpus'
  );

  // 1. Amostra pequena (n < 30)
  const smallReport = GoldenDatasetRunner.runValidationSuite('REGRESSION');
  assert.equal(smallReport.lowSampleThreshold, 30);
  assert.equal(smallReport.byLanguage['TypeScript']?.lowSampleWarning, true);
  assert.ok(smallReport.sampleWarning?.includes('n < 30'));

  // 2. Amostra grande (n >= 30)
  const makeSyntheticCase = (id: string, expectedVulnerable: boolean, vulnCode: boolean) => {
    const filesMap = {
      [`src/syn/${id}.ts`]: vulnCode
        ? 'export function q(db: any, x: string) { return db.query("SELECT id FROM t WHERE c = \'" + x + "\'"); }'
        : 'export function qSafe(db: any, x: string) { return db.query("SELECT id FROM t WHERE c = ?", [x]); }',
    };
    return {
      caseId: id,
      title: `Synthetic ${id}`,
      language: 'TypeScript' as const,
      category: 'SQL_INJECTION' as const,
      cwe: 'CWE-89',
      expectedVulnerable,
      filesMap,
      origin: 'TEST_FIXTURE',
      license: 'MIT',
      contentSha256: computeGoldenCaseContentSha256(filesMap),
      datasetVersion: 'SYN-1',
      datasetRole: 'DEVELOPMENT' as const,
      changelog: 'test',
    };
  };
  const largeCorpus = Array.from({ length: 30 }, (_, i) =>
    makeSyntheticCase(`SYN-LG-${i}`, i % 2 === 0, i % 2 === 0)
  );
  const largeReport = GoldenDatasetRunner.runValidationSuite('DEVELOPMENT', { customCorpus: largeCorpus });
  assert.equal(largeReport.totalCases, 30);
  assert.equal(largeReport.byLanguage['TypeScript']?.lowSampleWarning, false);
  assert.equal(largeReport.sampleWarning, null);

  // 3. Denominador zero -> null
  const zeroDenom = computeConfusionMetrics({ tp: 0, fp: 0, tn: 0, fn: 0 });
  assert.equal(zeroDenom.precision, null);
  assert.equal(zeroDenom.recall, null);
  assert.equal(zeroDenom.f1Score, null);
  assert.equal(zeroDenom.trueNegativeRate, null);
  assert.equal(zeroDenom.falsePositiveRate, null);
  assert.equal(computeWilson95ConfidenceInterval(0, 0).pointEstimate, null);

  // 4. Todos positivos (only TP -> TNR/FPR must be null)
  const allPosCorpus = [makeSyntheticCase('ALL-POS-1', true, true), makeSyntheticCase('ALL-POS-2', true, true)];
  const allPosReport = GoldenDatasetRunner.runValidationSuite('DEVELOPMENT', { customCorpus: allPosCorpus });
  assert.equal(allPosReport.precision, 1);
  assert.equal(allPosReport.recall, 1);
  assert.equal(allPosReport.trueNegativeRate, null);
  assert.equal(allPosReport.falsePositiveRate, null);

  // 5. Todos negativos (only TN -> Precision/Recall/F1 must be null)
  const allNegCorpus = [makeSyntheticCase('ALL-NEG-1', false, false), makeSyntheticCase('ALL-NEG-2', false, false)];
  const allNegReport = GoldenDatasetRunner.runValidationSuite('DEVELOPMENT', { customCorpus: allNegCorpus });
  assert.equal(allNegReport.trueNegativeRate, 1);
  assert.equal(allNegReport.falsePositiveRate, 0);
  assert.equal(allNegReport.precision, null);
  assert.equal(allNegReport.recall, null);
  assert.equal(allNegReport.f1Score, null);

  // 6. Falsos positivos (expected=false, detected=true)
  const fpCorpus = [makeSyntheticCase('TP-CASE', true, true), makeSyntheticCase('FP-CASE', false, true)];
  const fpReport = GoldenDatasetRunner.runValidationSuite('DEVELOPMENT', { customCorpus: fpCorpus });
  assert.equal(fpReport.falsePositives, 1);
  assert.equal(fpReport.precision, 0.5);
  assert.equal(fpReport.falsePositiveRate, 1);

  // 7. Falsos negativos (expected=true, detected=false)
  const fnCorpus = [makeSyntheticCase('TP-CASE2', true, true), makeSyntheticCase('FN-CASE', true, false)];
  const fnReport = GoldenDatasetRunner.runValidationSuite('DEVELOPMENT', { customCorpus: fnCorpus });
  assert.equal(fnReport.falseNegatives, 1);
  assert.equal(fnReport.recall, 0.5);
  assert.equal(fnReport.falseNegativeRate, 0.5);

  // 8 & 9. Casos inconclusivos & estratos vazios (unparsed/empty filesMap)
  const emptyCaseFiles = {};
  const inconclusiveCorpus = [
    {
      caseId: 'INC-1',
      title: 'Empty target filesMap',
      language: 'TypeScript' as const,
      category: 'SQL_INJECTION' as const,
      cwe: 'CWE-89',
      expectedVulnerable: true,
      filesMap: emptyCaseFiles,
      origin: 'TEST_FIXTURE',
      license: 'MIT',
      contentSha256: computeGoldenCaseContentSha256(emptyCaseFiles),
      datasetVersion: 'SYN-INC',
      datasetRole: 'DEVELOPMENT' as const,
      changelog: 'test',
    },
  ];
  const incReport = GoldenDatasetRunner.runValidationSuite('DEVELOPMENT', { customCorpus: inconclusiveCorpus });
  assert.equal(incReport.inconclusiveCases, 1);
  assert.equal(incReport.cases[0]?.classification, 'INCONCLUSIVE');
  assert.equal(incReport.cases[0]?.detectedVulnerable, null);
  assert.equal(incReport.macroAverages?.byLanguage.evaluatedStrataCount, 0);
  assert.equal(incReport.macroAverages?.byLanguage.precision, null);

  // 10. Corpus com linguagem ausente (incomplete 8-language detection)
  assert.ok(allPosReport.missingDeclaredLanguages.includes('Go'));
  assert.ok(allPosReport.missingDeclaredLanguages.includes('Rust'));
  assert.ok(allPosReport.missingDeclaredLanguages.includes('C#'));

  // 11. Alteração de SHA-256 do dataset / adulteração de caso
  const tamperedCorpus = [
    {
      ...GOLDEN_DATASET_CORPUS[0]!,
      filesMap: { 'src/repo/userRepo.ts': 'export const mutated = true;' },
      // keeps original contentSha256 intentionally -> must trigger integrity mismatch
    },
  ];
  const tamperReport = GoldenDatasetRunner.runValidationSuite('REGRESSION', { customCorpus: tamperedCorpus });
  assert.equal(tamperReport.datasetIntegrityVerified, false);
  assert.ok(tamperReport.integrityErrors.length >= 1);
  assert.equal(tamperReport.cases[0]?.contentHashVerified, false);
  assert.notEqual(tamperReport.datasetSha256, regShaPlaceholder(smallReport.datasetSha256));
});

function regShaPlaceholder(s: string) {
  return s;
}

test('stripTrailingSlashes normalizes Sonar server URLs safely without regex backtracking', () => {
  assert.equal(stripTrailingSlashes('https://sonarcloud.io///'), 'https://sonarcloud.io');
  assert.equal(stripTrailingSlashes('http://127.0.0.1:9000/'), 'http://127.0.0.1:9000');
  assert.equal(stripTrailingSlashes('http://127.0.0.1:9000'), 'http://127.0.0.1:9000');
  assert.equal(stripTrailingSlashes('/'), '');
});
