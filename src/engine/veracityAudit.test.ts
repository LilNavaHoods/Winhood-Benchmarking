import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_CATEGORY_WEIGHTS,
  calculateDeterministicScoreCard,
  computeRenormalizedCategoryWeights,
} from './scoringEngine';
import { computeDeterministicMqrScore } from '../scoring';
import {
  buildToolAdaptersCatalog,
  executeBenchmarkRunOrchestration,
} from './benchmarkOrchestrator';
import { buildFull21SecurityAdaptersCatalog } from './securityAssessmentEngine';
import { MarketCompetitorDiscoveryEngine } from './marketCompetitorDiscoveryEngine';
import {
  computeEvidenceChainHash,
  verifyEvidenceChainAndManifest,
} from './evidenceProvenanceEngine';
import { PdfReportGenerator } from '../reports/PdfReportGenerator';
import type { BenchmarkCategoryKey, Software } from '../types/benchmark';

function createDeterministicSampleSoftware(id: string, name: string): Software {
  const filesMap: Record<string, string> = {
    'src/service/auth.ts': [
      'import crypto from "node:crypto";',
      'export function hashSecret(value: string): string {',
      '  return crypto.createHash("sha256").update(value).digest("hex");',
      '}',
      'export function queryUser(db: any, userId: string) {',
      '  return db.query("SELECT * FROM users WHERE id = " + userId);',
      '}',
    ].join('\n'),
    'src/utils/math.ts': [
      'export function add(a: number, b: number): number {',
      '  return a + b;',
      '}',
    ].join('\n'),
    'package.json': JSON.stringify({
      name: id,
      version: '1.2.3',
      dependencies: { express: '4.18.2' },
    }),
  };

  return {
    id,
    projectId: 'proj-det',
    name,
    vendor: 'WinHood Audit Lab',
    description: 'Snapshot de teste determinístico para auditoria de veracidade.',
    category: 'Security Platform',
    version: '1.2.3',
    languages: ['TypeScript', 'JSON'],
    architecture: 'x64',
    operatingSystem: 'Linux',
    distributionModel: 'On-Premise',
    licenseType: 'MIT',
    officialUrl: 'https://example.local/deterministic-app',
    repositoryUrl: 'https://example.local/deterministic-app.git',
    documentationUrl: 'https://example.local/docs',
    owner: 'WinHood Audit Lab',
    notes: 'Fixture para verificação determinística.',
    sourceType: 'LOCAL_UPLOAD',
    commitHash: 'abc1234def5678',
    packageSha256: 'UNVERIFIED',
    createdAt: '2026-11-22T12:00:00.000Z',
    dataOrigin: 'USER_SOURCE',
    inventory: {
      totalFiles: 3,
      eligibleFiles: 3,
      totalLinesOfCode: 16,
      totalSizeBytes: 512,
      languageBreakdown: { TypeScript: 2, JSON: 1 },
      files: [],
      isolatedStoragePath: `/isolated/${id}`,
      verifiedIntegrity: true,
    },
    sourceFilesContent: filesMap,
  };
}

const STANDARD_EQUIV_ENV = {
  cpuCoresLimit: 4,
  memoryMbLimit: 8192,
  osTarget: 'Linux x64',
  workloadConcurrency: 10,
};

test('Veracity 1: Strict determinism — two identical snapshot runs yield identical scores, canonically sorted findings, and identical evidenceChainHash', () => {
  const fixedTs = '2026-11-22T12:00:00.000Z';
  const swA1 = createDeterministicSampleSoftware('sw-det-a', 'DeterministicApp');
  // Same files in reverse object insertion order to verify insertion-order invariance
  const swA2: Software = {
    ...swA1,
    sourceFilesContent: Object.fromEntries(
      Object.entries(swA1.sourceFilesContent || {}).reverse()
    ),
  };

  const commonParams = {
    runId: 'run-det-001',
    projectId: 'proj-det',
    projectName: 'Determinism Audit Project',
    profileName: 'Auditoria Determinística',
    weights: { ...DEFAULT_CATEGORY_WEIGHTS },
    enablePenaltyCaps: true,
    equivalenceEnvironment: STANDARD_EQUIV_ENV,
    deterministicTimestamp: fixedTs,
  };

  const run1 = executeBenchmarkRunOrchestration({ ...commonParams, softwares: [swA1] });
  const run2 = executeBenchmarkRunOrchestration({ ...commonParams, softwares: [swA2] });

  assert.equal(run1.scoreCards.length, 1);
  assert.equal(run2.scoreCards.length, 1);

  const sc1 = run1.scoreCards[0]!;
  const sc2 = run2.scoreCards[0]!;

  assert.equal(sc1.groupedScores.overallScore, sc2.groupedScores.overallScore);
  assert.deepEqual(sc1.categoryScores, sc2.categoryScores);
  assert.equal(sc1.measuredCoveragePercent, sc2.measuredCoveragePercent);
  assert.deepEqual(
    run1.findings.map((f) => `${f.softwareId}|${f.severity}|${f.originalRuleId}|${f.filePath}:${f.lineNumber}`),
    run2.findings.map((f) => `${f.softwareId}|${f.severity}|${f.originalRuleId}|${f.filePath}:${f.lineNumber}`)
  );

  const hash1 = computeEvidenceChainHash(run1.evidenceChain);
  const hash2 = computeEvidenceChainHash(run2.evidenceChain);
  assert.equal(hash1, hash2);
  assert.equal(run1.signedManifest?.rootChainSha256, run2.signedManifest?.rootChainSha256);
  assert.equal(
    run1.signedManifest?.manifestPayloadSha256,
    run2.signedManifest?.manifestPayloadSha256
  );
  assert.equal(run1.evidenceVerification?.valid, true);
  assert.equal(run2.evidenceVerification?.valid, true);
});

test('Veracity 2: Anti-inflation & weight renormalization — unmeasured categories never receive fabricated positive scores and expose measuredCoveragePercent', () => {
  // 2a. Raw-metrics fallback with NO findings array and empty raw metrics
  const emptyRawScoreCard = calculateDeterministicScoreCard(
    {
      softwareId: 'sw-empty-raw',
      softwareName: 'UnmeasuredRawApp',
      softwareVersion: '0.1.0',
      veracityClassification: 'SUCCESS_VALIDATED',
      coveragePercent: 100,
      eligibleForScoring: true,
      essentialFeaturesMissing: 0,
      visualOnlyFeaturesCount: 0,
      metrics: {
        bugs: 0,
        codeSmells: 0,
        vulnerabilities: 0,
        criticalVulns: 0,
        highVulns: 0,
        mediumVulns: 0,
        lowVulns: 0,
        secretsExposed: 0,
        duplicatedLinesPercent: 0,
        deadCodeSymbols: 0,
        avgCyclomaticComplexity: 0,
        avgCognitiveComplexity: 0,
        technicalDebtMinutes: 0,
        testCoveragePercent: null,
        circularDependencies: 0,
        couplingIndex: 0,
        cohesionIndex: 0,
        dbSchemaIssues: 0,
        p50LatencyMs: 0,
        p95LatencyMs: 0,
        p99LatencyMs: 0,
        throughputRps: 0,
        memoryMb: 0,
        cpuPercent: 0,
        startupTimeMs: 0,
        functionalTestsTotal: 0,
        functionalTestsPassed: 0,
        functionalTestsFailed: 0,
      },
      hasEncryptionAtRest: false,
      hasAuditTrail: false,
      hasCleanSandboxUninstall: null,
      hasCompleteDocumentation: false,
      environmentEquivalent: true,
      runtimeMetrics: { status: 'NOT_MEASURED', reason: 'Sem execução dinâmica.' },
      deterministicTimestamp: '2026-11-22T12:00:00.000Z',
    },
    DEFAULT_CATEGORY_WEIGHTS,
    true
  );

  // Zero measured categories -> technicalScore must be null, measuredCoveragePercent 0, gate INCONCLUSIVE / NOT_EVALUATED
  assert.equal(emptyRawScoreCard.measuredCoveragePercent, 0);
  assert.equal(emptyRawScoreCard.separatedIndicators?.technicalScore, null);
  assert.equal(emptyRawScoreCard.separatedIndicators?.qualityGateDecision, 'INCONCLUSIVE');
  assert.ok(
    emptyRawScoreCard.qualityGate?.status === 'NOT_EVALUATED' ||
      emptyRawScoreCard.qualityGate?.status === 'INCONCLUSIVE',
    `Expected NOT_EVALUATED or INCONCLUSIVE, got ${emptyRawScoreCard.qualityGate?.status}`
  );
  assert.equal(emptyRawScoreCard.weightRenormalization?.applied, true);
  for (const val of Object.values(emptyRawScoreCard.categoryScores)) {
    assert.equal(val, null, 'Unmeasured category must never receive fabricated positive score');
  }

  // 2b. Partial measurement with explicit unmeasuredCategories -> renormalizes remaining weights to 100%
  const enabled: BenchmarkCategoryKey[] = ['security', 'code_quality', 'performance', 'usability'];
  const assessed: BenchmarkCategoryKey[] = ['security', 'code_quality'];
  const renorm = computeRenormalizedCategoryWeights(
    { ...DEFAULT_CATEGORY_WEIGHTS, security: 30, code_quality: 30, performance: 20, usability: 20 },
    enabled,
    assessed
  );
  assert.equal(renorm.applied, true);
  assert.deepEqual(renorm.excludedCategories, ['performance', 'usability']);
  assert.equal(renorm.measuredWeightSum, 60);
  assert.equal(renorm.redistributedWeightPercent, 40);
  assert.equal(renorm.measuredCoveragePercent, 60);
  assert.equal(renorm.effectiveWeights.security, 50);
  assert.equal(renorm.effectiveWeights.code_quality, 50);
  assert.equal(renorm.effectiveWeights.performance, 0);
  assert.equal(renorm.effectiveWeights.usability, 0);

  // 2c. Normalized MQR scoring module excludes NOT_MEASURED and UNAVAILABLE cleanly
  const mqr = computeDeterministicMqrScore({
    dimensions: [
      { dimensionId: 'security', weight: 0.4, state: 'MEASURED', score: 4.0 },
      { dimensionId: 'reliability', weight: 0.3, state: 'UNAVAILABLE', score: 5.0 },
      { dimensionId: 'performance', weight: 0.3, state: 'NOT_MEASURED', score: 5.0 },
    ],
    criticalConfirmedFindings: 0,
    secretsExposed: 0,
  });
  assert.equal(mqr.technicalScore, 4.0);
  assert.equal(mqr.excludedUnavailableCount, 1);
  assert.equal(mqr.excludedNotMeasuredCount, 2);
  assert.equal(mqr.renormalizationApplied, true);
  assert.equal(mqr.measuredCoveragePercent, 40);
});

test('Veracity 3: No hardcoded versions for uninstalled adapters & explicit HEURISTIC_METADATA_SIMILARITY label', () => {
  const mainAdapters = buildToolAdaptersCatalog();
  for (const ad of mainAdapters) {
    assert.notEqual(ad.version, '2026.11', `Adapter ${ad.id} must not emit fabricated version 2026.11`);
    assert.notEqual(ad.version, 'not-installed', `Adapter ${ad.id} must standardize unavailable version as UNAVAILABLE`);
    assert.notEqual(ad.version, 'host-unavailable', `Adapter ${ad.id} must standardize unavailable version as UNAVAILABLE`);
    if (!ad.nativeAvailable && !ad.externalBinaryDetected) {
      assert.equal(
        ad.version,
        'UNAVAILABLE',
        `Uninstalled external adapter ${ad.id} must report version=UNAVAILABLE`
      );
      assert.ok(
        ad.executionStatus === 'NOT_INSTALLED' || ad.executionStatus === 'NOT_MEASURED',
        `Uninstalled adapter ${ad.id} must report NOT_INSTALLED or NOT_MEASURED`
      );
    }
  }

  const sec21Adapters = buildFull21SecurityAdaptersCatalog();
  assert.equal(sec21Adapters.length, 21);
  for (const ad of sec21Adapters) {
    assert.notEqual(ad.version, '2026.11', `Security adapter ${ad.id} must not hardcode 2026.11`);
    if (ad.executionMethod !== 'NATIVE_AST_ENGINE' && !ad.binaryDetected) {
      assert.equal(
        ad.version,
        'UNAVAILABLE',
        `Uninstalled security adapter ${ad.id} must report version=UNAVAILABLE instead of hardcoded version`
      );
      assert.ok(ad.unavailableReason, `Uninstalled security adapter ${ad.id} must provide unavailableReason`);
    }
  }

  const candidates = MarketCompetitorDiscoveryEngine.discoverCompetitors({
    purpose: 'Plataforma SAST e auditoria de segurança de código-fonte',
    features: ['SAST', 'SBOM', 'SCA', 'TypeScript'],
    maxCandidates: 3,
  });
  assert.ok(candidates.length > 0);
  for (const c of candidates) {
    assert.equal(c.similarityOrigin, 'HEURISTIC_METADATA_SIMILARITY');
    assert.equal(c.isMeasuredBenchmark, false);
    assert.ok(
      c.similarityDisclaimer && c.similarityDisclaimer.includes('HEURISTIC_METADATA_SIMILARITY')
    );
  }
});

test('Veracity 4: End-to-end report parity across PDF, HTML, JSON, CSV, SARIF and cryptographic integrity verification', () => {
  const fixedTs = '2026-11-22T12:30:00.000Z';
  const sw = createDeterministicSampleSoftware('sw-parity', 'ParityAuditApp');
  const run = executeBenchmarkRunOrchestration({
    runId: 'run-parity-001',
    projectId: 'proj-parity',
    projectName: 'Parity Audit Project',
    profileName: 'Auditoria Completa',
    softwares: [sw],
    weights: { ...DEFAULT_CATEGORY_WEIGHTS },
    enablePenaltyCaps: true,
    equivalenceEnvironment: STANDARD_EQUIV_ENV,
    deterministicTimestamp: fixedTs,
  });

  const expectedChainHash = run.signedManifest!.rootChainSha256!;
  const expectedScore = run.scoreCards[0]!.groupedScores.overallScore;
  const expectedCoverage = run.scoreCards[0]!.measuredCoveragePercent!;
  const expectedFindingsCount = run.findings.length;

  const pdfExport = PdfReportGenerator.exportReport(run, 'pdf');
  const htmlExport = PdfReportGenerator.exportReport(run, 'html');
  const jsonExport = PdfReportGenerator.exportReport(run, 'json');
  const csvExport = PdfReportGenerator.exportReport(run, 'csv');
  const sarifExport = PdfReportGenerator.exportReport(run, 'sarif');

  // 1. PDF cryptographic verification + tamper detection
  const pdfCheck = PdfReportGenerator.verifyPdfIntegrity(pdfExport.buffer);
  assert.equal(pdfCheck.valid, true);
  assert.equal(pdfCheck.winhoodVersion, '4.4.0');
  assert.equal(pdfCheck.evidenceChainHash, expectedChainHash);

  const wrongSecretCheck = PdfReportGenerator.verifyPdfIntegrity(pdfExport.buffer, 'wrong-secret');
  assert.equal(wrongSecretCheck.valid, false);

  const tamperedHashPdf = Buffer.from(
    pdfExport.buffer.toString('latin1').replace(pdfCheck.reportContentSha256!, 'a'.repeat(64)),
    'latin1'
  );
  assert.equal(PdfReportGenerator.verifyPdfIntegrity(tamperedHashPdf).valid, false);

  // 2. Evidence chain verification + tamper detection
  const chainValid = verifyEvidenceChainAndManifest(run.evidenceChain, run.signedManifest);
  assert.equal(chainValid.valid, true);
  const tamperedChain = run.evidenceChain.map((rec, idx) =>
    idx === 0 ? { ...rec, resultSummary: 'TAMPERED_RESULT' } : rec
  );
  const chainTampered = verifyEvidenceChainAndManifest(tamperedChain, run.signedManifest);
  assert.equal(chainTampered.valid, false);
  assert.equal(chainTampered.verificationState, 'TAMPERED');

  // 3. HTML parity (standalone, zero external URLs, provenance footer, epistemic separation, no fake 0.0 ms)
  const htmlStr = htmlExport.buffer.toString('utf8');
  assert.ok(htmlStr.includes('<!DOCTYPE html>'));
  assert.ok(htmlStr.includes('id="winhood-provenance-footer"'));
  assert.ok(!htmlStr.includes('http://') && !htmlStr.includes('https://'));
  assert.ok(htmlStr.includes(expectedChainHash));
  assert.ok(htmlStr.includes(`${expectedScore.toFixed(2)} / 5.00`));
  assert.ok(htmlStr.includes(`${expectedCoverage}%`));
  assert.ok(htmlStr.includes('Evidência Medida (Fato)'));
  assert.ok(htmlStr.includes('Inferência / Heurística'));
  assert.ok(htmlStr.includes('Não Medido (NOT_MEASURED / UNAVAILABLE)'));
  assert.ok(!htmlStr.includes('Desempenho P95: <strong>0.0 ms'));

  // 4. JSON parity
  const jsonObj = JSON.parse(jsonExport.buffer.toString('utf8'));
  assert.equal(jsonObj.winhoodVersion, '4.4.0');
  assert.equal(jsonObj.evidenceChainHash, expectedChainHash);
  assert.equal(jsonObj.measuredCoveragePercent, expectedCoverage);
  assert.equal(jsonObj.findingsCount, expectedFindingsCount);
  assert.equal(jsonObj.scoreCards[0].groupedScores.overallScore, expectedScore);
  assert.ok(jsonObj.veracityBlock.scopeLimitationsDisclaimer.includes('NOT_MEASURED'));
  assert.ok(jsonObj.epistemicSeparation.measuredEvidenceFacts.length > 0);

  // 5. CSV parity
  const csvStr = csvExport.buffer.toString('utf8');
  assert.ok(csvStr.includes(`WinHoodVersion=4.4.0`));
  assert.ok(csvStr.includes(`EvidenceChainHash=${expectedChainHash}`));
  assert.ok(csvStr.includes(`MeasuredCoveragePercent=${expectedCoverage}`));
  assert.ok(csvStr.includes(`OverallScore=${expectedScore.toFixed(2)}/5.00`));
  assert.ok(csvStr.includes('MEASURED_FACT'));
  assert.ok(csvStr.includes('NOT_MEASURED_OR_UNAVAILABLE'));

  // 6. SARIF parity
  const sarifObj = JSON.parse(sarifExport.buffer.toString('utf8'));
  const sarifProps = sarifObj.runs[0].properties;
  assert.equal(sarifProps.winhoodVersion, '4.4.0');
  assert.equal(sarifProps.evidenceChainHash, expectedChainHash);
  assert.equal(sarifProps.measuredCoveragePercent, expectedCoverage);
  assert.equal(sarifObj.runs[0].results.length, expectedFindingsCount);
  assert.equal(sarifProps.provenanceFooter.reportContentSha256, pdfExport.provenance.reportContentSha256);
});
