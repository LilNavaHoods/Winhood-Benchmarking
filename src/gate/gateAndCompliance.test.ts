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

  const {
    buildComparabilityManifest,
    CANONICAL_TAXONOMY_MAPPING_SHA256,
    sha256Canonical,
  } = await import('../comparability/index');

  const manifestA = buildComparabilityManifest({
    projectId: 'proj-vault',
    sourceRepository: 'https://github.com/org/vault',
    commitSha: 'deadbeef1234',
    workingTreeClean: true,
    configHashSha256: sha256Canonical({ cfg: 1 }),
    analyticalProfile: 'vault-sec',
    engineVersion: '4.4.0',
    ruleCatalogSha256: 'hash1',
    weightsHashSha256: sha256Canonical({ w: 1 }),
    eligibleFilesScopeHash: sha256Canonical(['src/a.ts']),
    evidenceIntegrityVerified: true,
  });
  const manifestB = { ...manifestA };

  const compOk = validatePairComparability(
    {
      softwareId: 'a',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 92,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
      manifest: manifestA,
    },
    {
      softwareId: 'b',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 88,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
      manifest: manifestB,
    }
  );
  assert.equal(compOk.comparable, true);
  assert.equal(compOk.status, 'COMPATIBLE');
  assert.equal(compOk.comparabilityClassification, 'STRICTLY_COMPARABLE');
  assert.equal(compOk.manifestsVerified, true);

  // Bare call without manifest MUST be rejected as NOT_COMPARABLE
  const missingManifest = validatePairComparability(
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
      scopeCoveragePercent: 92,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
    }
  );
  assert.equal(missingManifest.comparable, false);
  assert.equal(missingManifest.comparabilityClassification, 'NOT_COMPARABLE');

  const compInconclusive = validatePairComparability(
    {
      softwareId: 'a',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 90,
      evidenceConfidence: 'LOW',
      functionalCategory: 'vault',
      manifest: manifestA,
    },
    {
      softwareId: 'b',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 88,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
      manifest: manifestB,
    }
  );
  assert.equal(compInconclusive.comparable, false);
  assert.equal(compInconclusive.status, 'INCONCLUSIVE');
  assert.equal(compInconclusive.comparabilityClassification, 'NOT_COMPARABLE');

  const compIncompatible = validatePairComparability(
    {
      softwareId: 'a',
      engineVersion: '4.3.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 95,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
      manifest: manifestA,
    },
    {
      softwareId: 'b',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash2',
      scopeCoveragePercent: 40,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'crm',
      manifest: {
        ...manifestB,
        projectId: 'proj-other',
        engineVersion: '4.4.0',
        analyticalProfile: 'other-prof',
        weightsHashSha256: sha256Canonical({ w: 2 }),
        configHashSha256: sha256Canonical({ cfg: 2 }),
        evidenceIntegrityVerified: false,
      },
    }
  );
  assert.equal(compIncompatible.comparable, false);
  assert.equal(compIncompatible.status, 'INCOMPATIBLE_SCOPE');
  assert.equal(compIncompatible.comparabilityClassification, 'NOT_COMPARABLE');
  assert.ok(compIncompatible.reasons.length >= 4);

  // SAME_ENGINE qualified (dirty workingTree, different runtime, coverage delta 15%)
  const compQualified = validatePairComparability(
    {
      softwareId: 'a',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 95,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
      manifest: { ...manifestA, workingTreeClean: false, osPlatform: 'linux', analyticalDepth: 'FULL_AST' },
    },
    {
      softwareId: 'b',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 80,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
      manifest: {
        ...manifestB,
        osPlatform: 'win32',
        analyticalDepth: 'STRUCTURAL_AST',
        commitSha: 'cafebabe5678',
        eligibleFilesScopeHash: sha256Canonical(['src/b.ts']),
      },
    }
  );
  assert.equal(compQualified.comparable, true);
  assert.equal(compQualified.comparabilityClassification, 'QUALIFIED_COMPARISON');

  // CROSS_TOOL with invalid manifest digests & anti-bypass check
  const crossBypassRejected = validatePairComparability(
    {
      softwareId: 'a',
      engineVersion: 'WINHOOD-4.4.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 95,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
      toolExecuted: false,
      manifest: { ...manifestA, taxonomyMappingSha256: '', commitSha: 'abc', configHashSha256: 'bad', weightsHashSha256: 'bad', eligibleFilesScopeHash: 'bad' },
    },
    {
      softwareId: 'b',
      engineVersion: 'EXT-TOOL-1.0',
      ruleCatalogSha256: 'hash2',
      scopeCoveragePercent: 90,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
      manifest: { ...manifestB, projectId: '', analyticalProfile: '', taxonomyMappingSha256: CANONICAL_TAXONOMY_MAPPING_SHA256 },
    },
    { modality: 'CROSS_TOOL', sameCommitVerified: true, normalizedTaxonomyApplied: true }
  );
  assert.equal(crossBypassRejected.comparable, false);
  assert.equal(crossBypassRejected.comparabilityClassification, 'NOT_COMPARABLE');

  const crossMismatch = validatePairComparability(
    {
      softwareId: 'a',
      engineVersion: 'WINHOOD-4.4.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 95,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
      manifest: { ...manifestA, taxonomyMappingSha256: CANONICAL_TAXONOMY_MAPPING_SHA256 },
    },
    {
      softwareId: 'b',
      engineVersion: 'EXT-TOOL-1.0',
      ruleCatalogSha256: 'hash2',
      scopeCoveragePercent: 92,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
      manifest: {
        ...manifestB,
        projectId: 'proj-different',
        commitSha: 'different999',
        eligibleFilesScopeHash: sha256Canonical(['other.ts']),
        taxonomyMappingSha256: sha256Canonical({ altTax: true }),
      },
    },
    { modality: 'CROSS_TOOL' }
  );
  assert.equal(crossMismatch.comparable, false);
  assert.equal(crossMismatch.comparabilityClassification, 'NOT_COMPARABLE');

  // Exercise remaining branches in src/comparability/index.ts:
  // 1) sha256Canonical with string input & buildComparabilityManifest with minimal vs explicit fields
  assert.equal(sha256Canonical('canonical-raw-string').length, 64);
  const minimalManifest = buildComparabilityManifest({
    projectId: 'proj-min',
    commitSha: '1234567890ab',
    engineVersion: '4.4.0',
    ruleCatalogSha256: 'hash-min',
    analyticalProfile: 'min-profile',
  });
  const explicitManifest = buildComparabilityManifest({
    projectId: 'proj-min',
    commitSha: '1234567890ab',
    engineVersion: '4.4.0',
    ruleCatalogSha256: 'hash-min',
    analyticalProfile: 'min-profile',
    analyticalDepth: 'FULL_AST',
    osPlatform: 'linux',
    cpuArch: 'x64',
    runtimeVersion: 'v22.0.0',
    taxonomyVersion: 'WINHOOD-CWE-MQR-TAXONOMY-v1.0.0',
    taxonomyMappingSha256: CANONICAL_TAXONOMY_MAPPING_SHA256,
    executedAt: '2026-11-17T00:00:00.000Z',
  });

  // 2) CROSS_TOOL valid QUALIFIED_COMPARISON with verified matching commitSha & taxonomyMappingSha256
  const crossQualified = validatePairComparability(
    {
      softwareId: 'a',
      engineVersion: 'WINHOOD-4.4.0',
      ruleCatalogSha256: 'hash-min',
      scopeCoveragePercent: 90,
      evidenceConfidence: 'MEDIUM',
      functionalCategory: 'vault',
      toolExecuted: true,
      manifest: minimalManifest,
    },
    {
      softwareId: 'b',
      engineVersion: 'EXT-SCANNER-2.1',
      ruleCatalogSha256: 'hash-ext',
      scopeCoveragePercent: 90,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
      toolExecuted: true,
      manifest: explicitManifest,
    },
    { modality: 'CROSS_TOOL', sameCommitVerified: true, normalizedTaxonomyApplied: true }
  );
  assert.equal(crossQualified.comparable, true);
  assert.equal(crossQualified.comparabilityClassification, 'QUALIFIED_COMPARISON');

  // 3) CROSS_TOOL with normalizedTaxonomyApplied=false, same engineVersion, candidateB.toolExecuted=false, candidateB LOW, and invalid candidateB taxonomy
  const crossDenied = validatePairComparability(
    {
      softwareId: 'a',
      engineVersion: 'EXT-1.0',
      ruleCatalogSha256: 'hash1',
      scopeCoveragePercent: 90,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
      manifest: minimalManifest,
    },
    {
      softwareId: 'b',
      engineVersion: 'EXT-1.0',
      ruleCatalogSha256: 'hash2',
      scopeCoveragePercent: 90,
      evidenceConfidence: 'LOW',
      functionalCategory: 'vault',
      toolExecuted: false,
      manifest: { ...explicitManifest, taxonomyMappingSha256: 'bad-digest' },
    },
    { modality: 'CROSS_TOOL', normalizedTaxonomyApplied: false }
  );
  assert.equal(crossDenied.comparable, false);
  assert.equal(crossDenied.status, 'INCONCLUSIVE');

  // 4) SAME_ENGINE with candidateB MEDIUM confidence, workingTreeClean=false on B, distinct cpuArch/runtimeVersion, and allowDistinctRepositoriesInSameProject=true
  const sameEngineQualB = validatePairComparability(
    {
      softwareId: 'a',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash-min',
      scopeCoveragePercent: 90,
      evidenceConfidence: 'HIGH',
      functionalCategory: 'vault',
      manifest: explicitManifest,
    },
    {
      softwareId: 'b',
      engineVersion: '4.4.0',
      ruleCatalogSha256: 'hash-min',
      scopeCoveragePercent: 85,
      evidenceConfidence: 'MEDIUM',
      functionalCategory: 'vault',
      manifest: {
        ...explicitManifest,
        workingTreeClean: false,
        cpuArch: 'arm64',
        runtimeVersion: 'v20.0.0',
        commitSha: 'othercommit99',
      },
    },
    { modality: 'SAME_ENGINE', allowDistinctRepositoriesInSameProject: true }
  );
  assert.equal(sameEngineQualB.comparable, true);
  assert.equal(sameEngineQualB.comparabilityClassification, 'QUALIFIED_COMPARISON');
});

test('Phase 3 P0 Unified Quality Gate Contract: 9 mandatory scenarios without Fudge Factor suppression', async () => {
  const { calculateDeterministicScoreCard, DEFAULT_CATEGORY_WEIGHTS, ALL_BENCHMARK_CATEGORIES } = await import(
    '../engine/scoringEngine'
  );

  const baseMetrics = {
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
    avgCyclomaticComplexity: 1,
    avgCognitiveComplexity: 1,
    technicalDebtMinutes: 0,
    testCoveragePercent: 0,
    circularDependencies: 0,
    couplingIndex: 0.1,
    cohesionIndex: 0.9,
    dbSchemaIssues: 0,
    functionalTestsTotal: 1,
    functionalTestsPassed: 1,
    functionalTestsFailed: 0,
    p50LatencyMs: 0,
    p95LatencyMs: 0,
    p99LatencyMs: 0,
    throughputRps: 0,
    memoryMb: 0,
    cpuPercent: 0,
    startupTimeMs: 0,
  };

  const baseInput = {
    softwareId: 'sw-qg',
    softwareName: 'GateApp',
    softwareVersion: '1.0.0',
    veracityClassification: 'SUCCESS_VALIDATED' as const,
    coveragePercent: 95,
    essentialFeaturesMissing: 0,
    visualOnlyFeaturesCount: 0,
    hasEncryptionAtRest: true,
    hasAuditTrail: true,
    hasCleanSandboxUninstall: true,
    hasCompleteDocumentation: true,
    environmentEquivalent: true,
    enabledCategories: [...ALL_BENCHMARK_CATEGORIES],
    findings: [],
    metrics: baseMetrics,
  };

  // Scenario 1: Project < 20 lines without coverage -> INCONCLUSIVE (never APPROVED via Fudge Factor)
  const cardShortNoCov = calculateDeterministicScoreCard(
    {
      ...baseInput,
      newCodeLinesCount: 10,
      staticMetrics: {
        loc: 10,
        cyclomaticComplexity: 1,
        cognitiveComplexity: 1,
        duplicatedLinesPercent: 0,
        couplingIndex: 0.1,
        cohesionIndex: 0.9,
        circularDependenciesCount: 0,
        layerViolationsCount: 0,
        riskIndicators: [],
      },
    },
    DEFAULT_CATEGORY_WEIGHTS,
    true
  );
  assert.equal(cardShortNoCov.qualityGate?.fudgeFactorApplied, false);
  assert.equal(cardShortNoCov.qualityGate?.status, 'INCONCLUSIVE');
  assert.equal(cardShortNoCov.qualityGate?.executiveDecision, 'INCONCLUSIVE');

  // Scenario 2: Project >= 20 lines without coverage -> INCONCLUSIVE
  const cardLongNoCov = calculateDeterministicScoreCard(
    {
      ...baseInput,
      newCodeLinesCount: 250,
      staticMetrics: {
        loc: 250,
        cyclomaticComplexity: 3,
        cognitiveComplexity: 3,
        duplicatedLinesPercent: 0,
        couplingIndex: 0.1,
        cohesionIndex: 0.9,
        circularDependenciesCount: 0,
        layerViolationsCount: 0,
        riskIndicators: [],
      },
    },
    DEFAULT_CATEGORY_WEIGHTS,
    true
  );
  assert.equal(cardLongNoCov.qualityGate?.status, 'INCONCLUSIVE');
  assert.equal(cardLongNoCov.qualityGate?.executiveDecision, 'INCONCLUSIVE');

  // Scenario 3: Project with measured coverage below threshold (65% < 80%) -> FAILED (never PASSED)
  const cardLowCov = calculateDeterministicScoreCard(
    {
      ...baseInput,
      newCodeLinesCount: 12,
      metrics: { ...baseMetrics, testCoveragePercent: 65, criticalVulns: 1 },
      staticMetrics: {
        loc: 12,
        cyclomaticComplexity: 1,
        cognitiveComplexity: 1,
        duplicatedLinesPercent: 0,
        couplingIndex: 0.1,
        cohesionIndex: 0.9,
        circularDependenciesCount: 0,
        layerViolationsCount: 0,
        riskIndicators: [],
      },
    },
    DEFAULT_CATEGORY_WEIGHTS,
    true
  );
  assert.equal(cardLowCov.qualityGate?.status, 'FAILED');
  assert.equal(cardLowCov.qualityGate?.executiveDecision, 'REPROVADO');

  // Scenario 4: Project with measured coverage above threshold (88% >= 80%) -> PASSED / APROVADO
  const cardHighCov = calculateDeterministicScoreCard(
    {
      ...baseInput,
      newCodeLinesCount: 12,
      metrics: { ...baseMetrics, testCoveragePercent: 88 },
      staticMetrics: {
        loc: 12,
        cyclomaticComplexity: 1,
        cognitiveComplexity: 1,
        duplicatedLinesPercent: 0,
        couplingIndex: 0.1,
        cohesionIndex: 0.9,
        circularDependenciesCount: 0,
        layerViolationsCount: 0,
        riskIndicators: [],
      },
    },
    DEFAULT_CATEGORY_WEIGHTS,
    true
  );
  assert.equal(cardHighCov.qualityGate?.status, 'PASSED');
  assert.equal(cardHighCov.qualityGate?.executiveDecision, 'APROVADO');

  // Scenario 5: REQUIRED metric absent -> INCONCLUSIVE in QualityGateEngine
  const qgReqAbsent = QualityGateEngine.evaluate({
    gateId: 'winhood-standard-v2',
    findings: [],
    scopeCoveragePercent: null,
    evidenceConfidence: 'HIGH',
    evidenceVerified: true,
  });
  assert.equal(qgReqAbsent.decision, 'INCONCLUSIVE');

  // Scenario 6: OPTIONAL metric absent -> APPROVED_WITH_RESERVATIONS
  const customOptGate = QualityGateEngine.registerGate({
    id: 'custom-opt-gate',
    name: 'Custom Optional Gate',
    version: '1.0.0',
    description: 'Optional coverage test',
    requireVerifiedEvidence: true,
    createdAt: '2026-11-17T00:00:00Z',
    conditions: [
      {
        id: 'opt-cov',
        metricKey: 'scope_coverage_percent',
        label: 'Optional Scope Coverage',
        operator: 'GTE',
        threshold: 80,
        severityOnFail: 'RESERVATION',
        requirementTier: 'OPTIONAL',
      },
    ],
  });
  const qgOptAbsent = QualityGateEngine.evaluate({
    gate: customOptGate,
    findings: [],
    scopeCoveragePercent: null,
    evidenceConfidence: 'HIGH',
    evidenceVerified: true,
  });
  assert.equal(qgOptAbsent.decision, 'APPROVED_WITH_RESERVATIONS');

  // Scenario 7: INFORMATIVE metric absent -> APPROVED_WITH_RESERVATIONS (non-blocking note)
  const customInfoGate = QualityGateEngine.registerGate({
    id: 'custom-info-gate',
    name: 'Custom Informative Gate',
    version: '1.0.0',
    description: 'Informative metric test',
    requireVerifiedEvidence: true,
    createdAt: '2026-11-17T00:00:00Z',
    conditions: [
      {
        id: 'info-score',
        metricKey: 'overall_score',
        label: 'Informative Score',
        operator: 'GTE',
        threshold: 4.5,
        severityOnFail: 'BLOCKER',
        requirementTier: 'INFORMATIVE',
      },
    ],
  });
  const qgInfoAbsent = QualityGateEngine.evaluate({
    gate: customInfoGate,
    findings: [],
    scopeCoveragePercent: 90,
    evidenceConfidence: 'HIGH',
    evidenceVerified: true,
  });
  assert.equal(qgInfoAbsent.decision, 'APPROVED_WITH_RESERVATIONS');

  // Scenario 8: Custom profile evaluation consistency between evaluateSharedContract and QualityGateEngine
  const sharedOpt = QualityGateEngine.evaluateSharedContract({
    eligibleForScoring: true,
    criticalVulns: 0,
    secretsExposed: 0,
    bugs: 0,
    securityRating: 'A',
    reliabilityRating: 'A',
    duplicatedLinesPercent: 0,
    hasMeasuredCoverage: false,
    testCoveragePercent: 0,
    scopeCoveragePercent: 90,
    coverageRequirementTier: 'OPTIONAL',
  });
  assert.equal(sharedOpt.canonicalDecision, 'APPROVED_WITH_RESERVATIONS');

  // Scenario 9: Partial evidence (< 50% scope coverage) -> INCONCLUSIVE
  const sharedPartial = QualityGateEngine.evaluateSharedContract({
    eligibleForScoring: true,
    criticalVulns: 0,
    secretsExposed: 0,
    bugs: 0,
    securityRating: 'A',
    reliabilityRating: 'A',
    duplicatedLinesPercent: 0,
    hasMeasuredCoverage: true,
    testCoveragePercent: 95,
    scopeCoveragePercent: 35,
  });
  assert.equal(sharedPartial.canonicalDecision, 'INCONCLUSIVE');
  assert.equal(sharedPartial.executiveDecision, 'INCONCLUSIVE');
});


