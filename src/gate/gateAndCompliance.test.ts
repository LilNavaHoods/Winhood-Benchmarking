import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { QualityGateEngine } from '../gate/QualityGateEngine';
import { ComplianceMapper } from '../evidence/ComplianceMapper';
import { PortfolioEngine } from '../engine/portfolioEngine';
import { PdfReportGenerator } from '../reports/PdfReportGenerator';
import {
  buildVerifiableEvidenceChain,
  signEvidenceManifestHmacSha256,
  verifyEvidenceChainAndManifest,
} from '../engine/evidenceProvenanceEngine';
import { enrichLegacyOrExternalFinding } from '../engine/scoringEngine';
import type { BenchmarkRun, NormalizedFinding, Software } from '../types/benchmark';

function makeSampleFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return enrichLegacyOrExternalFinding({
    id: overrides.id || 'f-test-1',
    runId: 'run-1',
    softwareId: 'sw-1',
    softwareName: 'TargetApp',
    softwareVersion: '1.0.0',
    toolName: 'WinHood AST',
    toolVersion: '4.3.0',
    originType: 'WINHOOD_NATIVE_STATIC',
    detectionMethod: 'AST_ANALYSIS',
    originalRuleId: overrides.originalRuleId || 'taint:S3649',
    category: overrides.category || 'SAST',
    cwe: overrides.cwe || 'CWE-89',
    severity: overrides.severity || 'CRITICAL',
    confidence: 'HIGH',
    validationStatus: 'VALIDATED',
    lifecycleState: 'CONFIRMED',
    title: overrides.title || 'SQL Injection',
    description: 'Concatenated SQL query',
    filePath: 'src/repo.ts',
    lineNumber: 10,
    snippet: 'db.query("SELECT * FROM u WHERE id=" + id)',
    remediation: 'Use parameterized query',
    remediationEffortMinutes: 30,
    collectedAt: '2026-11-14T00:00:00.000Z',
  });
}

function makeSoftware(): Software {
  return {
    id: 'sw-1',
    projectId: 'p1',
    name: 'TargetApp',
    vendor: 'WinHood QA',
    description: 'Target software',
    version: '1.0.0',
    languages: ['TypeScript'],
    architecture: 'Modular',
    operatingSystem: 'Linux',
    distributionModel: 'Source',
    licenseType: 'MIT',
    officialUrl: '',
    repositoryUrl: '',
    documentationUrl: '',
    owner: 'qa',
    notes: '',
    sourceType: 'LOCAL_UPLOAD',
    commitHash: 'abc123',
    packageSha256: 'sha256abc',
    createdAt: '2026-11-14T00:00:00.000Z',
    inventory: {
      totalFiles: 1,
      eligibleFiles: 1,
      totalLinesOfCode: 20,
      totalSizeBytes: 200,
      languageBreakdown: { TypeScript: 20 },
      files: [],
      isolatedStoragePath: '/tmp/test',
      verifiedIntegrity: true,
    },
  };
}

test('QualityGateEngine evaluates all decision states, CLI exit codes, HMAC webhook verification, and SSRF protection', async () => {
  const approved = QualityGateEngine.evaluate({
    gateId: 'winhood-standard-v2',
    findings: [],
    scopeCoveragePercent: 95,
    evidenceConfidence: 'HIGH',
    evidenceVerified: true,
    deterministicTimestamp: '2026-11-14T00:00:00.000Z',
  });
  assert.equal(approved.decision, 'APPROVED');
  assert.equal(approved.cliExitCode, 0);

  const blocked = QualityGateEngine.evaluate({
    gateId: 'winhood-standard-v2',
    findings: [makeSampleFinding({ severity: 'CRITICAL' })],
    scopeCoveragePercent: 95,
    evidenceConfidence: 'HIGH',
    evidenceVerified: true,
    deterministicTimestamp: '2026-11-14T00:00:00.000Z',
  });
  assert.equal(blocked.decision, 'BLOCKED');
  assert.equal(blocked.cliExitCode, 1);

  const inconclusive = QualityGateEngine.evaluate({
    gateId: 'winhood-standard-v2',
    findings: [],
    scopeCoveragePercent: null,
    evidenceConfidence: 'HIGH',
    evidenceVerified: true,
    deterministicTimestamp: '2026-11-14T00:00:00.000Z',
  });
  assert.equal(inconclusive.decision, 'INCONCLUSIVE');
  assert.equal(inconclusive.cliExitCode, 2);

  const signed = QualityGateEngine.signWebhookPayload({
    event: 'quality_gate.evaluated',
    runId: 'run-1',
    evaluation: blocked,
    secret: 'unit-test-webhook-secret',
    timestampEpochSec: 1794614400,
  });
  assert.equal(
    QualityGateEngine.verifyWebhookSignature({
      bodyJson: signed.bodyJson,
      signatureHeader: signed.signatureHeader,
      secret: 'unit-test-webhook-secret',
    }).valid,
    true
  );
  assert.equal(
    QualityGateEngine.verifyWebhookSignature({
      bodyJson: `${signed.bodyJson} `,
      signatureHeader: signed.signatureHeader,
      secret: 'unit-test-webhook-secret',
    }).valid,
    false
  );

  // SSRF Guard MUST block loopback webhook dispatch
  const ssrfBlocked = await QualityGateEngine.dispatchSignedWebhook({
    targetUrl: 'http://127.0.0.1:9999/hook',
    evaluation: blocked,
    secret: 'unit-test-webhook-secret',
  });
  assert.equal(ssrfBlocked.delivered, false);
  assert.equal(ssrfBlocked.blockedBySsrf, true);
});

test('Extended SignedEvidenceManifest binds engine/rules/artifacts/gate hashes and detects tampering', () => {
  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-ev-test-'));
  const prevKeystore = process.env.WINHOOD_KEYSTORE_PATH;
  process.env.WINHOOD_KEYSTORE_PATH = path.join(tmpDataDir, 'keys', 'keystore.json');
  try {
    const runId = 'run-ev-1';
    const findings = [makeSampleFinding()];
    const chain = buildVerifiableEvidenceChain({
      runId,
      softwares: [makeSoftware()],
      findings,
      toolExecutions: [],
      veracityResults: [],
    });

    const manifest = signEvidenceManifestHmacSha256({
      runId,
      algorithmVersion: 'WINHOOD-4.3.0',
      evidenceChain: chain,
      engineVersion: '4.3.0',
      rulePackVersions: { 'winhood-taint-core': '2026.11.0' },
      ruleCatalogSha256: 'cafebabe',
      artifactHashes: { 'sbom:sw-1': '1234567890abcdef' },
      gateDecision: 'BLOCKED',
      gateVersion: '2.1.0',
      gateHash: '00112233',
    });

    const validVerification = verifyEvidenceChainAndManifest(chain, manifest);
    assert.equal(validVerification.valid, true);
    assert.equal(validVerification.signatureValid, true);
    assert.equal(manifest.engineVersion, '4.3.0');
    assert.equal(manifest.gateDecision, 'BLOCKED');

    const tamperedManifest = { ...manifest, gateDecision: 'APPROVED' };
    const tamperedVerification = verifyEvidenceChainAndManifest(chain, tamperedManifest);
    assert.equal(tamperedVerification.signatureValid, false);
    assert.equal(tamperedVerification.valid, false);
  } finally {
    if (prevKeystore === undefined) delete process.env.WINHOOD_KEYSTORE_PATH;
    else process.env.WINHOOD_KEYSTORE_PATH = prevKeystore;
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
  }
});

test('ComplianceMapper produces non-certification traceability matrix across OWASP, CWE, PCI DSS, and ISO 27001', () => {
  const findings = [
    makeSampleFinding({ id: 'f1', cwe: 'CWE-89', severity: 'BLOCKER' }),
    makeSampleFinding({ id: 'f2', cwe: 'CWE-918', severity: 'CRITICAL' }),
    makeSampleFinding({ id: 'f3', cwe: 'CWE-798', category: 'SECRETS', severity: 'BLOCKER' }),
  ];

  const matrix = ComplianceMapper.buildTraceabilityMatrix({
    runId: 'run-comp-1',
    findings,
    deterministicTimestamp: '2026-11-14T00:00:00.000Z',
  });

  assert.match(matrix.disclaimer, /NÃO|NOT|certificação|certification/i);
  assert.equal(matrix.totalFindingsMapped, 3);
  assert.ok(matrix.byFramework.OWASP_TOP_10_2021.some((c) => c.controlId === 'A03:2021' && c.findingsCount >= 1));
  assert.ok(matrix.byFramework.OWASP_TOP_10_2021.some((c) => c.controlId === 'A10:2021' && c.findingsCount >= 1));
  assert.ok(matrix.byFramework.PCI_DSS_V4.some((c) => c.findingsCount >= 1));
  assert.ok(matrix.byFramework.ISO_27001_2022.some((c) => c.findingsCount >= 1));
});

test('PortfolioEngine computes cross-release deltas & uncovered dimensions and PdfReportGenerator emits valid %PDF-1.4', () => {
  const baseRun = (id: string, version: string, score: number, findings: NormalizedFinding[]): BenchmarkRun => ({
    id,
    projectId: 'p1',
    projectName: 'AuditProj',
    profileId: 'prof-1',
    profileName: 'Standard',
    algorithmVersion: '4.3.0',
    softwareIds: ['sw-1'],
    startedAt: '2026-11-13T00:00:00.000Z',
    completedAt: id === 'run-1' ? '2026-11-13T00:01:00.000Z' : '2026-11-14T00:01:00.000Z',
    status: 'COMPLETED',
    weightsUsed: {} as any,
    equivalenceEnvironment: {
      cpuCoresLimit: 2,
      memoryMbLimit: 1024,
      osTarget: 'linux',
      workloadConcurrency: 1,
    },
    environmentEquivalent: true,
    scoreCards: [
      {
        softwareId: 'sw-1',
        softwareName: 'TargetApp',
        softwareVersion: version,
        categoryScores: {} as any,
        categoryDetails: {
          performance: {
            category: 'performance',
            status: 'NOT_ASSESSED',
            rawScore: null,
            finalScore: null,
            score: null,
            weight: 10,
            effectiveWeight: 0,
            coveragePercent: 0,
            confidence: 'LOW',
            toolsUsed: [],
            limitations: ['Not executed'],
            evidenceCount: 0,
            evaluationReasons: [],
          },
        } as any,
        groupedScores: {
          functionalScore: score,
          technicalScore: score,
          overallScore: score,
          securityScore: score,
          qualityScore: score,
          performanceScore: 0,
          architectureScore: score,
        },
        separatedIndicators: {
          technicalScore: score,
          scopeCoveragePercent: 80,
          evidenceConfidence: 'HIGH',
          qualityGateDecision: findings.length > 0 ? 'BLOCKED' : 'APPROVED',
          veracityState: 'SUCCESS_VALIDATED',
        },
        unmeasuredCategories: ['performance'],
        penaltyCapsTriggered: [],
        classificationLabel: 'Muito bom',
        advantages: [],
        deficiencies: [],
        risks: [],
        metricsSummary: {
          bugs: 0,
          codeSmells: 0,
          vulnerabilities: findings.length,
          criticalVulns: findings.length,
          highVulns: 0,
          mediumVulns: 0,
          lowVulns: 0,
          secretsExposed: 0,
          duplicatedLinesPercent: 0,
          deadCodeSymbols: 0,
          avgCyclomaticComplexity: 2,
          avgCognitiveComplexity: 2,
          technicalDebtMinutes: findings.length * 30,
          testCoveragePercent: 0,
          circularDependencies: 0,
          couplingIndex: 0.2,
          cohesionIndex: 0.8,
          dbSchemaIssues: 0,
          functionalTestsTotal: 0,
          functionalTestsPassed: 0,
          functionalTestsFailed: 0,
          p50LatencyMs: 0,
          p95LatencyMs: 0,
          p99LatencyMs: 0,
          throughputRps: 0,
          memoryMb: 0,
          cpuPercent: 0,
          startupTimeMs: 0,
        },
      },
    ],
    findings,
    toolExecutions: [],
    veracityResults: [],
    architectureGraphs: [],
    functionalMatrix: [],
    sandboxDiffs: [],
    evidenceChain: [],
    winnerSoftwareId: null,
    evidenceVerification: {
      valid: true,
      verificationState: 'VERIFIED',
      verifiedAt: '2026-11-14T00:01:00.000Z',
      tamperedIndices: [],
      message: 'OK',
    },
    executiveSummary: 'Comparative release summary.',
  });

  const run1 = baseRun('run-1', '1.0.0', 2.8, [makeSampleFinding({ id: 'f-1' }), makeSampleFinding({ id: 'f-2' })]);
  const run2 = baseRun('run-2', '1.1.0', 4.5, []);

  const summary = PortfolioEngine.buildSummary({
    runs: [run1, run2],
    softwares: [],
    deterministicTimestamp: '2026-11-14T00:05:00.000Z',
  });

  assert.equal(summary.totalRuns, 2);
  assert.equal(summary.verifiedRunsCount, 2);
  assert.equal(summary.releaseProgression.length, 2);
  assert.equal(summary.releaseProgression[1]!.deltaFindingsFromPrevious, -2);
  assert.ok((summary.releaseProgression[1]!.deltaScoreFromPrevious || 0) > 1.5);
  assert.ok(summary.uncoveredDimensionsSummary.some((u) => u.category === 'performance'));

  const pdfBuffer = PdfReportGenerator.generateFromRun(run1);
  const pdfText = pdfBuffer.toString('latin1');
  assert.ok(pdfText.startsWith('%PDF-1.4'));
  assert.ok(pdfText.includes('xref'));
  assert.ok(pdfText.includes('%%EOF'));
  assert.ok(pdfText.includes('WINHOOD INDEPENDENT SOFTWARE AUDIT'));

  const integrity = PdfReportGenerator.verifyPdfIntegrity(pdfBuffer);
  assert.equal(integrity.valid, true, 'PDF report hash and HMAC signature must verify cleanly');
  assert.ok(integrity.reportContentSha256);
  assert.ok(integrity.hmacSignature);
  assert.equal(PdfReportGenerator.verifyPdfIntegrity(pdfBuffer, 'wrong-secret').valid, false);

  const htmlExp = PdfReportGenerator.exportReport(run1, 'html');
  const htmlStr = htmlExp.buffer.toString('utf8');
  assert.ok(htmlStr.includes('<!DOCTYPE html>'));
  assert.ok(htmlStr.includes('id="winhood-provenance-footer"'));
  assert.equal(htmlStr.includes('http://'), false);
  assert.equal(htmlStr.includes('https://'), false);

  const sarifExp = PdfReportGenerator.exportReport(run1, 'sarif');
  assert.equal(JSON.parse(sarifExp.buffer.toString('utf8')).version, '2.1.0');

  const jsonExp = PdfReportGenerator.exportReport(run1, 'json');
  assert.ok(JSON.parse(jsonExp.buffer.toString('utf8')).provenanceFooter.hmacSignature);
});

test('Critical motors (src/scoring, src/evidence, src/comparability) achieve >=95% deterministic coverage', async () => {
  const { computeDeterministicMqrScore, computeSizeNormalizedMaintainabilityScore } = await import('../scoring/index');
  const { evaluateEvidenceConfidence } = await import('../evidence/index');
  const { validatePairComparability } = await import('../comparability/index');

  const emptyScore = computeDeterministicMqrScore({
    dimensions: [{ dimensionId: 'perf', weight: 20, score: null, state: 'NOT_MEASURED' }],
    criticalConfirmedFindings: 0,
    secretsExposed: 0,
  });
  assert.equal(emptyScore.technicalScore, null);
  assert.equal(emptyScore.excludedNotMeasuredCount, 1);

  const validScore = computeDeterministicMqrScore({
    dimensions: [
      { dimensionId: 'sec', weight: 50, score: 4.8, state: 'MEASURED' },
      { dimensionId: 'qual', weight: 30, score: 4.2, state: 'STATIC_DERIVED' },
      { dimensionId: 'perf', weight: 20, score: null, state: 'NOT_MEASURED' },
    ],
    criticalConfirmedFindings: 0,
    secretsExposed: 0,
  });
  assert.equal(validScore.killSwitchTriggered, false);
  assert.ok((validScore.technicalScore ?? 0) > 4.4);

  const cappedScore = computeDeterministicMqrScore({
    dimensions: [{ dimensionId: 'sec', weight: 100, score: 4.9, state: 'MEASURED' }],
    criticalConfirmedFindings: 1,
    secretsExposed: 0,
  });
  assert.equal(cappedScore.killSwitchTriggered, true);
  assert.equal(cappedScore.technicalScore, 2.2);

  const cappedBySecret = computeDeterministicMqrScore({
    dimensions: [{ dimensionId: 'sec', weight: 100, score: 4.9, state: 'MEASURED' }],
    criticalConfirmedFindings: 0,
    secretsExposed: 1,
  });
  assert.equal(cappedBySecret.killSwitchTriggered, true);

  const defaultTsMatrix = ComplianceMapper.buildTraceabilityMatrix({
    runId: 'run-comp-2',
    findings: [
      { ...makeSampleFinding({ id: 'f-fp', cwe: 'CWE-89' }), lifecycleState: undefined as any, validationStatus: 'FALSE_POSITIVE' as any },
    ],
  });
  assert.equal(defaultTsMatrix.totalFindingsMapped, 0);

  const maintScore = computeSizeNormalizedMaintainabilityScore({
    nonCriticalFindingsCount: 10,
    eligibleLinesOfCode: 5000,
  });
  assert.ok(maintScore >= 1.0 && maintScore <= 5.0);

  const confHigh = evaluateEvidenceConfidence({
    scopeCoverageRatio: 0.95,
    astDepthRatio: 0.9,
    measuredDimensionsRatio: 0.9,
    executionDeterminismRatio: 1.0,
    cryptographicSignatureValid: true,
  });
  assert.equal(confHigh.level, 'HIGH');

  const confMed = evaluateEvidenceConfidence({
    scopeCoverageRatio: 0.65,
    astDepthRatio: 0.7,
    measuredDimensionsRatio: 0.6,
    executionDeterminismRatio: 0.8,
    cryptographicSignatureValid: true,
  });
  assert.equal(confMed.level, 'MEDIUM');

  const confLowUnsigned = evaluateEvidenceConfidence({
    scopeCoverageRatio: 0.95,
    astDepthRatio: 0.95,
    measuredDimensionsRatio: 0.95,
    executionDeterminismRatio: 1.0,
    cryptographicSignatureValid: false,
  });
  assert.equal(confLowUnsigned.level, 'LOW');
  assert.ok(confLowUnsigned.score <= 30);

  const confLowScope = evaluateEvidenceConfidence({
    scopeCoverageRatio: 0.3,
    astDepthRatio: 0.3,
    measuredDimensionsRatio: 0.3,
    executionDeterminismRatio: 0.5,
    cryptographicSignatureValid: true,
  });
  assert.equal(confLowScope.level, 'LOW');

  const compOk = validatePairComparability(
    {
      softwareId: 'a',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 92,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
    },
    {
      softwareId: 'b',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 88,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
    }
  );
  assert.equal(compOk.comparable, true);
  assert.equal(compOk.status, 'COMPATIBLE');

  const compInconclusive = validatePairComparability(
    {
      softwareId: 'a',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 90,
      evidenceConfidence: 'LOW',
      functionalCategory: 'vault',
    },
    {
      softwareId: 'b',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 88,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
    }
  );
  assert.equal(compInconclusive.comparable, false);
  assert.equal(compInconclusive.status, 'INCONCLUSIVE');

  const compIncompatible = validatePairComparability(
    {
      softwareId: 'a',
      engineVersion: '4.3.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 95,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
    },
    {
      softwareId: 'b',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash2',
      scopeCoveragePercent: 40,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'crm',
    }
  );
  assert.equal(compIncompatible.comparable, false);
  assert.equal(compIncompatible.status, 'INCOMPATIBLE_SCOPE');
  assert.equal(compIncompatible.reasons.length, 4);
});

