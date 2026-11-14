import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { ReferenceRegistry } from './reference/ReferenceRegistry';
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

test('GoldenDatasetRunner executes 20 paired TP/TN cases with >= 85% Precision, Recall and F1 and honest origin disclosures', () => {
  const report = GoldenDatasetRunner.runValidationSuite();
  assert.equal(report.totalCases, 20);
  assert.equal(report.datasetOriginLabel, 'WINHOOD_INTERNAL_CALIBRATION_CORPUS');
  assert.equal(report.datasetSha256.length, 64);
  assert.ok(Boolean(report.sampleWarning));
  assert.ok((report.precision ?? 0) >= 0.85, `Expected precision >= 0.85, got ${report.precision}`);
  assert.ok((report.recall ?? 0) >= 0.85, `Expected recall >= 0.85, got ${report.recall}`);
  assert.ok((report.f1Score ?? 0) >= 0.85, `Expected F1 >= 0.85, got ${report.f1Score}`);
  assert.equal(report.reportSha256.length, 64);
});
