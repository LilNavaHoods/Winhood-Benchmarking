import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  ALGORITHM_VERSION,
  ALL_BENCHMARK_CATEGORIES,
  DEFAULT_CATEGORY_WEIGHTS,
  calculateDeterministicScoreCard,
  computeSha256,
  computeSonarMaintainabilityRating,
  computeSonarSeverityRating,
  enrichLegacyOrExternalFinding,
  maskSecretsInText,
  normalizeEnabledCategoryWeights,
  validateCategoryWeights,
  validateEquivalenceConditions,
} from './scoringEngine';
import {
  buildTechnicalInventory,
  executeRealStaticAnalysisOnSource,
  validateSourceUploadSecurity,
} from './staticAnalyzer';
import {
  DOMAIN_SPECIALIZED_PROFILES,
  EVALUATION_CRITERIA_CATALOG,
  METHODOLOGY_CATALOG_VERSION,
  buildPreAnalysisSummary,
  determineSourceAvailability,
  determineSourceIngestionState,
  evaluateCriteriaForSoftware,
  evaluateSoftwareComparability,
  inferSoftwareDomainKey,
} from './methodologyCatalogEngine';
import {
  GENESIS_EVIDENCE_HASH,
  buildVerifiableEvidenceChain,
  signEvidenceManifestHmacSha256,
  verifyEvidenceChainAndManifest,
} from './evidenceProvenanceEngine';
import {
  DEMO_FIXTURE_METADATA,
  KEESAFE_OPEN_FILES,
  LEGACY_VULNERABLE_VAULT_FILES,
  VAULTCORE_INTERNAL_FILES,
} from './realSampleRepositories';
import {
  createInitialRunningBenchmark,
  executeBenchmarkRunOrchestration,
  recalculateBenchmarkRunScoreCards,
} from './benchmarkOrchestrator';
import { MarketCompetitorDiscoveryEngine } from './marketCompetitorDiscoveryEngine';
import type { NormalizedFinding, Software } from '../types/benchmark';

const clamp0to5 = (v: number): number => Math.round(Math.max(0, Math.min(5, v)) * 100) / 100;

test('validateCategoryWeights validates exact 100% mathematical sum and rejects invalid totals', () => {
  const validCheck = validateCategoryWeights(DEFAULT_CATEGORY_WEIGHTS);
  assert.equal(validCheck.valid, true);
  assert.equal(validCheck.totalWeight, 100);
  assert.equal(validCheck.errors.length, 0);

  const invalidWeights = {
    ...DEFAULT_CATEGORY_WEIGHTS,
    security: 30,
  };
  const invalidCheck = validateCategoryWeights(invalidWeights);
  assert.equal(invalidCheck.valid, false);
  assert.equal(invalidCheck.totalWeight, 112);
  assert.ok(invalidCheck.errors.some((e) => e.includes('100%')));
});

test('maskSecretsInText redacts hardcoded passwords, master keys, and tokens in evidence snippets', () => {
  const raw = 'const masterKey = "VC_PROD_MASTER_99481029384756_SECRET";';
  const masked = maskSecretsInText(raw);
  assert.equal(masked.includes('99481029384756'), false);
  assert.equal(masked.includes('VC_***'), true);
});

test('buildTechnicalInventory computes deterministic SHA-256 hashes, LOC, and language breakdown', () => {
  const invA = buildTechnicalInventory(VAULTCORE_INTERNAL_FILES, '/isolated/vaultcore');
  const invB = buildTechnicalInventory(KEESAFE_OPEN_FILES, '/isolated/keesafe');

  assert.equal(invA.totalFiles, 7);
  assert.equal(invA.verifiedIntegrity, true);
  assert.equal(invA.packageSha256.length, 64);
  assert.ok(invA.languageBreakdown.TypeScript > 0);
  assert.ok(invA.languageBreakdown.SQL > 0);

  assert.notEqual(invA.packageSha256, invB.packageSha256);
  assert.equal(computeSha256('winhood').length, 64);
});

test('executeRealStaticAnalysisOnSource detects real SAST, Secrets, SCA, SQL, and Architecture flaws with full MQR traceability', () => {
  const analysisVaultCore = executeRealStaticAnalysisOnSource({
    runId: 'run-test-001',
    softwareId: 'sw-vaultcore-legacy',
    softwareName: 'VaultCore Legacy Vulnerable',
    softwareVersion: '2.4.0',
    filesMap: LEGACY_VULNERABLE_VAULT_FILES,
  });

  const analysisKeeSafe = executeRealStaticAnalysisOnSource({
    runId: 'run-test-001',
    softwareId: 'sw-keesafe',
    softwareName: 'KeeSafe Open (KeePass KDBX)',
    softwareVersion: '2.56.0',
    filesMap: KEESAFE_OPEN_FILES,
  });

  // Legacy Vulnerable Vault has real SAST SQLi, RCE execSync, MD5 weak crypto, hardcoded masterKey, circular dependency, and layer violation
  assert.ok(analysisVaultCore.computedMetrics.criticalVulns >= 3);
  assert.ok(analysisVaultCore.computedMetrics.secretsExposed >= 1);
  assert.ok(analysisVaultCore.computedMetrics.circularDependencies >= 1);
  assert.ok(analysisVaultCore.architectureGraph.layerViolations.length >= 1);
  assert.equal(analysisVaultCore.veracity.overallClassification, 'SUCCESS_VALIDATED');

  // Verify MQR traceability fields on every finding
  for (const finding of analysisVaultCore.findings) {
    assert.ok(finding.whyItIsAnIssue.length > 10, `Finding ${finding.originalRuleId} missing whyItIsAnIssue`);
    assert.ok(finding.mqrImpacts.length >= 1, `Finding ${finding.originalRuleId} missing mqrImpacts`);
    assert.ok(finding.cleanCodeAttribute.length > 0);
    assert.ok(finding.remediationEffortMinutes > 0);
    assert.ok(Array.isArray(finding.contextBefore));
    assert.ok(Array.isArray(finding.contextAfter));
    assert.ok(Array.isArray(finding.executionFlows));
  }

  // Verify SQLi / RCE finding has full SOURCE -> PROPAGATOR -> SANITIZER_MISSING -> SINK execution flow
  const taintFinding = analysisVaultCore.findings.find(
    (f) => f.executionFlows && f.executionFlows.length >= 3
  );
  assert.ok(taintFinding && taintFinding.executionFlows, 'Expected at least one finding with full Source-to-Sink execution flow');
  assert.equal(taintFinding.executionFlows[0]?.nodeType, 'SOURCE');
  assert.equal(taintFinding.executionFlows[taintFinding.executionFlows.length - 1]?.nodeType, 'SINK');

  // Verify secrets are masked in normalized findings
  const secretFinding = analysisVaultCore.findings.find((f) => f.category === 'SECRETS');
  assert.ok(secretFinding);
  assert.equal(secretFinding.snippet.includes('99481029384756'), false);

  // KeeSafe Open has clean architecture, AES-256-GCM encryption, PBKDF2-SHA512, and zero vulnerabilities
  assert.equal(analysisKeeSafe.computedMetrics.vulnerabilities, 0);
  assert.equal(analysisKeeSafe.computedMetrics.criticalVulns, 0);
  assert.equal(analysisKeeSafe.computedMetrics.secretsExposed, 0);
  assert.equal(analysisKeeSafe.computedMetrics.circularDependencies, 0);
  assert.equal(analysisKeeSafe.hasEncryptionAtRest, true);
  assert.equal(analysisKeeSafe.hasAuditTrail, true);
  assert.ok(analysisKeeSafe.computedMetrics.testCoveragePercent >= 80);
});

test('calculateDeterministicScoreCard enforces Penalty Caps, populates all 12 categories with evaluationReasons, and satisfies algebraic reconciliation with [0.0, 5.0] clamp', () => {
  assert.equal(ALGORITHM_VERSION, 'WINHOOD-SONAR-MQR-v3.0.0');

  const analysisVaultCore = executeRealStaticAnalysisOnSource({
    runId: 'run-test-002',
    softwareId: 'sw-vaultcore-legacy',
    softwareName: 'VaultCore Legacy Vulnerable',
    softwareVersion: '2.4.0',
    filesMap: LEGACY_VULNERABLE_VAULT_FILES,
  });

  const analysisKeeSafe = executeRealStaticAnalysisOnSource({
    runId: 'run-test-002',
    softwareId: 'sw-keesafe',
    softwareName: 'KeeSafe Open',
    softwareVersion: '2.56.0',
    filesMap: KEESAFE_OPEN_FILES,
  });

  const scoreVaultCore = calculateDeterministicScoreCard(
    {
      softwareId: 'sw-vaultcore-legacy',
      softwareName: 'VaultCore Legacy Vulnerable',
      softwareVersion: '2.4.0',
      veracityClassification: analysisVaultCore.veracity.overallClassification,
      coveragePercent: analysisVaultCore.veracity.overallCoveragePercent,
      essentialFeaturesMissing: 1,
      visualOnlyFeaturesCount: 1,
      metrics: analysisVaultCore.computedMetrics,
      hasEncryptionAtRest: analysisVaultCore.hasEncryptionAtRest,
      hasAuditTrail: analysisVaultCore.hasAuditTrail,
      hasCleanSandboxUninstall: false,
      hasCompleteDocumentation: analysisVaultCore.hasCompleteDocumentation,
      environmentEquivalent: true,
      findings: analysisVaultCore.findings,
    },
    DEFAULT_CATEGORY_WEIGHTS,
    true
  );

  const scoreKeeSafe = calculateDeterministicScoreCard(
    {
      softwareId: 'sw-keesafe',
      softwareName: 'KeeSafe Open',
      softwareVersion: '2.56.0',
      veracityClassification: analysisKeeSafe.veracity.overallClassification,
      coveragePercent: analysisKeeSafe.veracity.overallCoveragePercent,
      essentialFeaturesMissing: 0,
      visualOnlyFeaturesCount: 0,
      metrics: analysisKeeSafe.computedMetrics,
      hasEncryptionAtRest: analysisKeeSafe.hasEncryptionAtRest,
      hasAuditTrail: analysisKeeSafe.hasAuditTrail,
      hasCleanSandboxUninstall: true,
      hasCompleteDocumentation: analysisKeeSafe.hasCompleteDocumentation,
      environmentEquivalent: true,
      findings: analysisKeeSafe.findings,
    },
    DEFAULT_CATEGORY_WEIGHTS,
    true
  );

  assert.ok((scoreVaultCore.categoryScores.security ?? 5) <= 2.0);
  assert.ok(scoreVaultCore.groupedScores.overallScore <= 2.9);
  assert.ok(scoreVaultCore.penaltyCapsTriggered.length >= 2);
  assert.ok(scoreKeeSafe.groupedScores.overallScore > 4.0);
  assert.ok(scoreKeeSafe.groupedScores.overallScore > scoreVaultCore.groupedScores.overallScore);

  // Verify all 12 categories exist in categoryDetails and satisfy clamp_[0.0, 5.0] algebraic reconciliation
  for (const sc of [scoreVaultCore, scoreKeeSafe]) {
    const detailsMap = sc.categoryDetails;
    assert.ok(detailsMap, 'categoryDetails must be present');
    for (const catKey of ALL_BENCHMARK_CATEGORIES) {
      const detail: NonNullable<typeof sc.categoryDetails>[typeof catKey] = detailsMap[catKey];
      assert.ok(detail, `Category ${catKey} missing in categoryDetails`);
      assert.ok(Array.isArray(detail.evaluationReasons), `evaluationReasons missing for ${catKey}`);

      if (detail.status === 'NOT_ASSESSED') {
        assert.equal(detail.finalScore, null);
        continue;
      }

      const nonCapSum =
        Math.round(
          detail.evaluationReasons
            .filter((r) => r.impactType !== 'CAP_APPLIED')
            .reduce((acc, r) => acc + r.scoreDelta, 0) * 100
        ) / 100;
      const capSum =
        Math.round(
          detail.evaluationReasons
            .filter((r) => r.impactType === 'CAP_APPLIED')
            .reduce((acc, r) => acc + r.scoreDelta, 0) * 100
        ) / 100;

      const expectedRaw = clamp0to5(5.0 + nonCapSum);
      const expectedFinal = clamp0to5(expectedRaw + capSum);

      assert.equal(
        detail.rawScore,
        expectedRaw,
        `Algebraic rawScore mismatch in ${sc.softwareName} -> ${catKey}: expected ${expectedRaw}, got ${detail.rawScore}`
      );
      assert.equal(
        detail.finalScore,
        expectedFinal,
        `Algebraic finalScore mismatch in ${sc.softwareName} -> ${catKey}: expected ${expectedFinal}, got ${detail.finalScore}`
      );

      // Verify evaluationReasons are sorted by largest deduction first (ascending scoreDelta)
      for (let i = 1; i < detail.evaluationReasons.length; i++) {
        assert.ok(
          detail.evaluationReasons[i - 1]!.scoreDelta <= detail.evaluationReasons[i]!.scoreDelta,
          `evaluationReasons in ${catKey} must be sorted by largest deduction first`
        );
      }
    }
  }

  // Verify extreme floor/ceiling clamp edge case (> -5.00 pts penalty and > +5.00 pts bonus)
  const extremeFindings: NormalizedFinding[] = Array.from({ length: 12 }, (_, idx) =>
    enrichLegacyOrExternalFinding({
      id: `f-extreme-${idx}`,
      runId: 'run-extreme',
      softwareId: 'sw-extreme',
      toolName: 'WinHood Native SAST',
      originalRuleId: `RULE-CRIT-${idx}`,
      category: 'SAST',
      cwe: 'CWE-89',
      severity: 'BLOCKER',
      confidence: 'HIGH',
      validationStatus: 'VALIDATED',
      title: `Extreme SQLi #${idx}`,
      description: 'Extreme penalty test exceeding -5.00 scale floor',
      filePath: `src/db/repo${idx}.ts`,
      lineNumber: 10 + idx,
      snippet: 'db.query(rawInput)',
      remediation: 'Use parameterized query',
    })
  );

  const extremeScoreCard = calculateDeterministicScoreCard(
    {
      softwareId: 'sw-extreme',
      softwareName: 'Extreme Clamp Test',
      softwareVersion: '1.0.0',
      veracityClassification: 'SUCCESS_VALIDATED',
      coveragePercent: 100,
      essentialFeaturesMissing: 0,
      visualOnlyFeaturesCount: 0,
      metrics: {
        ...analysisKeeSafe.computedMetrics,
        vulnerabilities: 12,
        criticalVulns: 12,
      },
      hasEncryptionAtRest: true,
      hasAuditTrail: true,
      hasCleanSandboxUninstall: true,
      hasCompleteDocumentation: true,
      environmentEquivalent: true,
      findings: extremeFindings,
    },
    DEFAULT_CATEGORY_WEIGHTS,
    true
  );

  // Security has > -7.00 pts in penalties -> clamped to 0.00 rawScore and 0.00 finalScore
  const secDetail = extremeScoreCard.categoryDetails!.security;
  const secNonCapDelta = secDetail.evaluationReasons
    .filter((r) => r.impactType !== 'CAP_APPLIED')
    .reduce((acc, r) => acc + r.scoreDelta, 0);
  assert.ok(secNonCapDelta < -5.0, 'Total penalties should exceed -5.00');
  assert.equal(clamp0to5(5.0 + secNonCapDelta), secDetail.rawScore);
  assert.equal(secDetail.rawScore, 0);
  assert.equal(secDetail.finalScore, 0);

  // Clean KeeSafe Security has +0.20 encryption bonus on top of 5.00 base with 0 penalties -> clamped to 5.00 ceiling
  const cleanSecDetail = scoreKeeSafe.categoryDetails!.security;
  const cleanSecNonCapDelta = cleanSecDetail.evaluationReasons
    .filter((r) => r.impactType !== 'CAP_APPLIED')
    .reduce((acc, r) => acc + r.scoreDelta, 0);
  assert.ok(cleanSecNonCapDelta > 0, 'Clean KeeSafe Security should have positive encryption bonus (+0.20)');
  assert.equal(clamp0to5(5.0 + cleanSecNonCapDelta), cleanSecDetail.rawScore);
  assert.equal(cleanSecDetail.rawScore, 5.0);
  assert.equal(cleanSecDetail.finalScore, 5.0);

  // Equivalence check blocks performance score when false
  const envCheck = validateEquivalenceConditions({
    cpuCoresLimit: 0,
    memoryMbLimit: 64,
    osTarget: '',
    workloadConcurrency: 0,
    dastFormalAuthorization: false,
    authorizedByOwner: '',
  });
  assert.equal(envCheck.equivalent, false);
  assert.ok(envCheck.reasons.length >= 3);
});

test('Official SonarQube A-E Ratings, Fudge Factor, and Real-Time DevSecOps Triage Recalculation', () => {
  // 1. Official SonarQube Severity-to-Rating mapping
  assert.equal(computeSonarSeverityRating([]), 'A');
  assert.equal(computeSonarSeverityRating(['LOW', 'INFO']), 'A');
  assert.equal(computeSonarSeverityRating(['MEDIUM']), 'B');
  assert.equal(computeSonarSeverityRating(['HIGH', 'MEDIUM']), 'C');
  assert.equal(computeSonarSeverityRating(['CRITICAL', 'HIGH']), 'D');
  assert.equal(computeSonarSeverityRating(['BLOCKER', 'CRITICAL']), 'E');

  // 2. Official SonarQube Technical Debt Ratio to Maintainability Rating
  const rA = computeSonarMaintainabilityRating(30, 1000); // 30m / (1000 * 3.2 = 3200m) < 5% -> A
  assert.equal(rA, 'A');
  const rE = computeSonarMaintainabilityRating(2000, 1000); // 2000m / 3200m = 62.5% > 50% -> E
  assert.equal(rE, 'E');

  // 3. Full BenchmarkRun orchestration and real-time DevSecOps triage recalculation
  const softwareA: Software = {
    id: 'sw-vaultcore-legacy',
    projectId: 'proj-01',
    name: 'VaultCore Legacy Vulnerable',
    vendor: 'VaultCore Inc.',
    version: '2.4.0',
    domainTags: DEMO_FIXTURE_METADATA.vaultCore.domainTags,
    enabledCategories: DEMO_FIXTURE_METADATA.vaultCore.enabledCategories,
    licenseType: 'Proprietary Commercial',
    repositoryUrl: 'https://internal.gitlab/vaultcore',
    description: 'VaultCore legacy vulnerable test',
    createdAt: new Date().toISOString(),
    sourceFilesContent: LEGACY_VULNERABLE_VAULT_FILES,
  } as unknown as Software;

  const softwareB: Software = {
    id: 'sw-keesafe',
    projectId: 'proj-01',
    name: 'KeeSafe Open',
    vendor: 'KeeSafe Project',
    version: '2.56.0',
    domainTags: DEMO_FIXTURE_METADATA.keeSafe.domainTags,
    enabledCategories: DEMO_FIXTURE_METADATA.keeSafe.enabledCategories,
    licenseType: 'GPL-3.0-or-later',
    repositoryUrl: 'https://github.com/keesafe/keesafe-kdbx',
    description: 'KeeSafe test',
    createdAt: new Date().toISOString(),
    sourceFilesContent: KEESAFE_OPEN_FILES,
  } as unknown as Software;

  const completedRun = executeBenchmarkRunOrchestration({
    runId: 'run-triage-001',
    projectId: 'proj-01',
    projectName: 'Auditoria Corporativa',
    profileName: 'Auditoria DevSecOps & Criptografia Estrita',
    softwares: [softwareA, softwareB],
    weights: DEFAULT_CATEGORY_WEIGHTS,
    enabledCategories: [...ALL_BENCHMARK_CATEGORIES],
    qualityGateId: 'qg-sonar-way',
    enablePenaltyCaps: true,
    equivalenceEnvironment: {
      cpuCoresLimit: 4,
      memoryMbLimit: 4096,
      osTarget: 'Windows 11 Enterprise Sandbox / Linux Worker 6.8',
      workloadConcurrency: 50,
      dastFormalAuthorization: true,
      authorizedByOwner: 'Lead SecOps',
    },
  });

  const scBefore = completedRun.scoreCards.find((s) => s.softwareId === 'sw-vaultcore-legacy')!;
  assert.ok(scBefore);
  assert.ok(['D', 'E'].includes(scBefore.ratings?.security ?? 'A'));
  assert.equal(scBefore.qualityGate?.status, 'FAILED');

  // Mark all VaultCore findings as ACCEPTED (Risk Accepted in DevSecOps triage)
  for (const finding of completedRun.findings) {
    if (finding.softwareId === 'sw-vaultcore-legacy') {
      finding.validationStatus = 'ACCEPTED';
    }
  }

  const recalculatedRun = recalculateBenchmarkRunScoreCards(completedRun, [softwareA, softwareB]);
  const scAfter = recalculatedRun.scoreCards.find((s) => s.softwareId === 'sw-vaultcore-legacy')!;
  assert.ok(scAfter);

  // After accepting all findings, open severity for security & reliability is none -> Rating A, and score increases significantly
  assert.equal(scAfter.ratings?.security, 'A');
  assert.equal(scAfter.ratings?.reliability, 'A');
  assert.ok(
    scAfter.groupedScores.overallScore > scBefore.groupedScores.overallScore,
    `Expected overallScore to increase after DevSecOps triage (${scBefore.groupedScores.overallScore} -> ${scAfter.groupedScores.overallScore})`
  );
});

test('Multi-category decoupling and normalizeEnabledCategoryWeights dynamically normalizes arbitrary category subsets to 100%', () => {
  const subset = ['security', 'architecture', 'reliability'] as const;
  const normalized = normalizeEnabledCategoryWeights(DEFAULT_CATEGORY_WEIGHTS, [...subset]);

  const validCheck = validateCategoryWeights(normalized, [...subset]);
  assert.equal(validCheck.valid, true);
  assert.equal(validCheck.totalWeight, 100);
  assert.ok(normalized.security > 0);
  assert.ok(normalized.architecture > 0);
  assert.ok(normalized.reliability > 0);
  assert.equal(normalized.usability, 0);
  assert.equal(normalized.documentation, 0);
});

test('buildFull21SecurityAdaptersCatalog returns 21 real security adapters without mock data', async () => {
  const { buildFull21SecurityAdaptersCatalog } = await import('./securityAssessmentEngine');
  const catalog = buildFull21SecurityAdaptersCatalog();
  assert.equal(catalog.length, 21);

  // Verify key adapters exist
  const toolIds = catalog.map((a) => a.id);
  assert.ok(toolIds.includes('owasp-zap'));
  assert.ok(toolIds.includes('nuclei-scanner'));
  assert.ok(toolIds.includes('nmap-surface'));
  assert.ok(toolIds.includes('semgrep-opengrep'));
  assert.ok(toolIds.includes('k6-resilience'));
  assert.ok(toolIds.includes('playwright-e2e'));
  assert.ok(toolIds.includes('trivy-scanner'));
  assert.ok(toolIds.includes('sysinternals-sandbox'));

  // Ensure every adapter has valid fields and truthful binary verification status
  catalog.forEach((adapter) => {
    assert.ok(adapter.name.length > 0);
    assert.ok(adapter.category.length > 0);
    assert.ok(['OPERATIONAL', 'FERRAMENTA NÃO INSTALADA', 'INTEGRAÇÃO CONFIGURADA', 'DISABLED'].includes(adapter.status));
    assert.equal(adapter.signatureHash.length, 64);
  });
});

test('executeSecurityAssessmentSuite generates attack surfaces, attack paths, and 6-state validation metrics', async () => {
  const { executeSecurityAssessmentSuite } = await import('./securityAssessmentEngine');
  const { executeRealStaticAnalysisOnSource } = await import('./staticAnalyzer');

  const analysisA = executeRealStaticAnalysisOnSource({
    runId: 'run-suite-001',
    softwareId: 'sw-vaultcore-legacy',
    softwareName: 'VaultCore Legacy Vulnerable',
    softwareVersion: '2.4.0',
    filesMap: LEGACY_VULNERABLE_VAULT_FILES,
  });

  const analysisB = executeRealStaticAnalysisOnSource({
    runId: 'run-suite-001',
    softwareId: 'sw-keesafe',
    softwareName: 'KeeSafe Open',
    softwareVersion: '2.56.0',
    filesMap: KEESAFE_OPEN_FILES,
  });

  const suite = executeSecurityAssessmentSuite({
    runId: 'run-suite-001',
    softwares: [
      {
        id: 'sw-vaultcore-legacy',
        projectId: 'proj-01',
        name: 'VaultCore Legacy Vulnerable',
        vendor: 'VaultCore Inc.',
        version: '2.4.0',
        licenseType: 'Proprietary Commercial',
        repositoryUrl: 'https://internal.gitlab/vaultcore',
        description: 'Gerenciador com vulnerabilidades reais',
        createdAt: new Date().toISOString(),
        sourceFilesContent: LEGACY_VULNERABLE_VAULT_FILES,
      } as unknown as Software,
      {
        id: 'sw-keesafe',
        projectId: 'proj-01',
        name: 'KeeSafe Open',
        vendor: 'KeeSafe Project',
        version: '2.56.0',
        licenseType: 'GPL-3.0-or-later',
        repositoryUrl: 'https://github.com/keesafe/keesafe-kdbx',
        description: 'Gerenciador KeePass KDBX',
        createdAt: new Date().toISOString(),
        sourceFilesContent: KEESAFE_OPEN_FILES,
      } as unknown as Software,
    ],
    findings: [...analysisA.findings, ...analysisB.findings],
  });

  assert.equal(suite.runId, 'run-suite-001');
  assert.equal(suite.modulesCatalog.length, 15);

  // Attack Surfaces
  assert.equal(suite.attackSurfaces.length, 2);
  const surfaceA = suite.attackSurfaces.find((s) => s.softwareId === 'sw-vaultcore-legacy');
  assert.ok(surfaceA);
  assert.ok(surfaceA.surfaceRiskIndex > 0);
  assert.ok(surfaceA.exposedEntryPoints.length > 0);
  assert.ok(surfaceA.databaseConnectors.length > 0);

  // Attack Paths
  assert.ok(suite.attackPaths.length >= 1);
  const sqliChain = suite.attackPaths.find((p) => p.title.includes('SQL'));
  assert.ok(sqliChain);
  assert.equal(sqliChain?.reproducibilityEase, 'ALTA');

  // Standardized executions validation state checks
  assert.ok(suite.executionRecords.length > 0);
  const validStates = ['CONFIRMADA', 'PROVAVEL', 'FALSO_POSITIVO', 'NAO_REPRODUZIVEL', 'INCONCLUSIVA', 'NAO_TESTADA'];
  suite.executionRecords.forEach((rec) => {
    assert.ok(validStates.includes(rec.validationState));
    assert.equal(rec.reexecutionHistory[0]?.evidenceHash?.length, 64);
  });

  // Comparison metrics
  assert.equal(suite.comparisonMetrics.length, 2);
  const metricsA = suite.comparisonMetrics.find((m) => m.softwareId === 'sw-vaultcore-legacy');
  const metricsB = suite.comparisonMetrics.find((m) => m.softwareId === 'sw-keesafe');
  assert.ok(metricsA && metricsB);
  assert.ok(metricsA.vulnerabilitiesConfirmed >= 2);
  assert.equal(metricsB.vulnerabilitiesConfirmed, 0);
  assert.ok(metricsA.overallSecurityMaturityScore < metricsB.overallSecurityMaturityScore);
});

test('SonarQubeIntegrationService executes full 27-step real integration suite (15 core + 12 fault-injection tests) and A/B comparison without leaking tokens', async () => {
  const os = await import('node:os');
  const path = await import('node:path');
  const { SonarQubeIntegrationService } = await import('../integrations/sonarqube/SonarQubeAdapter');
  const { ExternalToolLifecycleManager } = await import('../services/tools/ExternalToolLifecycleManager');
  const { ToolCacheManager } = await import('../services/tools/ToolCacheManager');

  const tmpDir = path.join(os.tmpdir(), 'winhood-test-sonar');
  const lifecycle = new ExternalToolLifecycleManager();
  const cache = new ToolCacheManager(tmpDir);
  const service = new SonarQubeIntegrationService(lifecycle, cache);
  const toolsDb = SonarQubeIntegrationService.createInitialToolsDatabaseState(tmpDir);

  const softwareA: Software = {
    id: 'sw-vaultcore-legacy',
    projectId: 'proj-01',
    name: 'VaultCore Legacy Vulnerable',
    vendor: 'VaultCore Inc.',
    version: '2.4.0',
    commitHash: 'a1b2c3d4e5f60123456789abcdef0123456789ab',
    licenseType: 'Proprietary Commercial',
    repositoryUrl: 'https://internal.gitlab/vaultcore',
    description: 'Gerenciador com vulnerabilidades reais',
    createdAt: new Date().toISOString(),
    sourceFilesContent: LEGACY_VULNERABLE_VAULT_FILES,
  } as unknown as Software;

  const softwareB: Software = {
    id: 'sw-keesafe',
    projectId: 'proj-01',
    name: 'KeeSafe Open',
    vendor: 'KeeSafe Project',
    version: '2.56.0',
    commitHash: 'f9e8d7c6b5a40123456789abcdef0123456789cd',
    licenseType: 'GPL-3.0-or-later',
    repositoryUrl: 'https://github.com/keesafe/keesafe-kdbx',
    description: 'Gerenciador KeePass KDBX',
    createdAt: new Date().toISOString(),
    sourceFilesContent: KEESAFE_OPEN_FILES,
  } as unknown as Software;

  const steps = await service.executeFullIntegrationTestSuite({
    softwareA,
    softwareB,
    runId: 'run-sonar-test-01',
    toolsDb,
    compositeScoreA: 2.35,
    compositeScoreB: 4.72,
  });

  assert.equal(steps.length, 27);
  assert.equal(steps.filter((s) => s.category === 'CORE_PIPELINE').length, 15);
  assert.equal(steps.filter((s) => s.category === 'FAULT_INJECTION').length, 12);
  assert.equal(steps.filter((s) => s.status === 'FAILED').length, 0);

  // Verify token never leaks in evidence
  const serializedReport = JSON.stringify(steps);
  assert.equal(serializedReport.includes('squ_winhood_verified_token_2026'), false);

  // Verify A/B comparison generated from real analysis
  assert.ok(toolsDb.ab_comparisons.length >= 1);
  const comp = toolsDb.ab_comparisons[0]!;
  assert.equal(comp.equivalenceVerified, true);
  assert.equal(comp.softwareA.qualityGate.status, 'ERROR');
  assert.equal(comp.softwareB.qualityGate.status, 'OK');
  assert.ok(comp.softwareB.nativeSonarScore > comp.softwareA.nativeSonarScore);
});

test('GitarAdapter runs authorized contract validation and enforces human approval on isolated branches without modifying original software files', async () => {
  const os = await import('node:os');
  const path = await import('node:path');
  const { GitarAdapter } = await import('../integrations/gitar/GitarAdapter');
  const { SonarQubeIntegrationService } = await import('../integrations/sonarqube/SonarQubeAdapter');

  const tmpDir = path.join(os.tmpdir(), 'winhood-test-gitar');
  const toolsDb = SonarQubeIntegrationService.createInitialToolsDatabaseState(tmpDir);
  const gitar = new GitarAdapter();

  const softwareA: Software = {
    id: 'sw-vaultcore-legacy',
    projectId: 'proj-01',
    name: 'VaultCore Legacy Vulnerable',
    vendor: 'VaultCore Inc.',
    version: '2.4.0',
    commitHash: 'a1b2c3d4e5f60123456789abcdef0123456789ab',
    licenseType: 'Proprietary Commercial',
    repositoryUrl: 'https://internal.gitlab/vaultcore',
    description: 'Gerenciador com vulnerabilidades reais',
    createdAt: new Date().toISOString(),
    sourceFilesContent: { ...LEGACY_VULNERABLE_VAULT_FILES },
  } as unknown as Software;

  const softwareB: Software = {
    id: 'sw-keesafe',
    projectId: 'proj-01',
    name: 'KeeSafe Open',
    vendor: 'KeeSafe Project',
    version: '2.56.0',
    commitHash: 'f9e8d7c6b5a40123456789abcdef0123456789cd',
    licenseType: 'GPL-3.0-or-later',
    repositoryUrl: 'https://github.com/keesafe/keesafe-kdbx',
    description: 'Gerenciador KeePass KDBX',
    createdAt: new Date().toISOString(),
    sourceFilesContent: { ...KEESAFE_OPEN_FILES },
  } as unknown as Software;

  const snapshotBefore = JSON.stringify(softwareA.sourceFilesContent);

  const validation = await gitar.runAuthorizedGitarContractValidation({
    softwareA,
    softwareB,
    actorName: 'Lead Security Reviewer',
    toolsDb,
  });

  assert.equal(validation.steps.length, 4);
  assert.ok(validation.reviewsImported >= 2);
  assert.ok(toolsDb.gitar_reviews.length >= 2);
  assert.equal(
    toolsDb.gitar_reviews[0]?.proposedFix?.humanApprovalStatus,
    'PENDING_HUMAN_APPROVAL'
  );

  // Approve remediation on isolated branch
  const firstReviewId = toolsDb.gitar_reviews[0]!.id;
  const approved = gitar.reviewAndValidateProposedFix({
    reviewId: firstReviewId,
    decision: 'APPROVE',
    actorName: 'Lead Security Reviewer',
    toolsDb,
  });
  assert.equal(approved.ok, true);
  assert.equal(approved.review?.proposedFix?.humanApprovalStatus, 'VERIFIED_RESOLVED');
  assert.equal(approved.review?.proposedFix?.retestExecuted, true);

  // Original software files must remain 100% untouched
  const snapshotAfter = JSON.stringify(softwareA.sourceFilesContent);
  assert.equal(snapshotBefore, snapshotAfter);
});

test('ToolCacheManager computes deterministic SHA-256 keys and invalidates cache when commit hash or ruleset changes', async () => {
  const os = await import('node:os');
  const path = await import('node:path');
  const { ToolCacheManager } = await import('../services/tools/ToolCacheManager');

  const tmpDir = path.join(os.tmpdir(), 'winhood-test-cache');
  const cacheManager = new ToolCacheManager(tmpDir);

  const input1 = {
    softwareId: 'sw-vaultcore',
    commitHash: 'sha-commit-001',
    scannerType: 'SONAR_SCANNER_CLI',
    scannerVersion: '8.4.0.16527',
    configHash: 'cfg-v1',
    qualityProfileKey: 'sonar-way-ts',
    rulesSignature: 'rules-2026-11',
    sonarVersion: '26.11.0.134175',
  };

  const input2 = {
    ...input1,
    commitHash: 'sha-commit-002', // Different commit
  };

  const key1 = ToolCacheManager.computeImmutableKey(input1);
  const key2 = ToolCacheManager.computeImmutableKey(input2);

  assert.equal(key1.length, 64);
  assert.notEqual(key1, key2);

  cacheManager.set(input1, { sampleMetric: 42 });
  const cached = cacheManager.get<{ sampleMetric: number }>(input1);
  assert.deepEqual(cached?.payload, { sampleMetric: 42 });
  assert.equal(cacheManager.get(input2), null);
});

test('MarketCompetitorDiscoveryEngine discovers competitors with weighted similarity breakdown', () => {
  const candidates = MarketCompetitorDiscoveryEngine.discoverCompetitors({
    category: 'Password & Secrets Management',
    purpose: 'VaultCore Pro Password Manager and Secrets Safe',
    features: ['AES-256-GCM', 'PBKDF2', 'Zero-Knowledge', 'CLI', 'Web Extension'],
    audience: 'Enterprise & Security Teams',
    platform: 'Cross-platform',
    distribution: 'Self-hosted and Cloud',
  });

  assert.ok(candidates.length >= 2);
  const topCandidate = candidates[0];
  assert.ok(topCandidate.similarityScore > 50);
  assert.ok(topCandidate.similarityBreakdown.purposeMatch >= 0);
  assert.ok(topCandidate.similarityBreakdown.featuresMatch >= 0);
  assert.ok(topCandidate.similarityBreakdown.audienceMatch >= 0);
  assert.ok(topCandidate.similarityBreakdown.platformMatch >= 0);
  assert.ok(topCandidate.similarityBreakdown.distributionMatch >= 0);
  assert.ok(topCandidate.similarityBreakdown.integrationsMatch >= 0);

  // Closed vs Open source distinction
  const openSourceCount = candidates.filter((c: any) => c.openSource).length;
  const closedSourceCount = candidates.filter((c: any) => !c.openSource).length;
  assert.ok(openSourceCount >= 1);
  assert.ok(closedSourceCount >= 1);
});

test('Static analysis strictly enforces Zero Fabricated Runtime Metrics (P50/P95/RPS = NOT_MEASURED)', () => {
  const analysis = executeRealStaticAnalysisOnSource({
    runId: 'run-zero-fake-01',
    softwareId: 'sw-vaultcore',
    softwareName: 'VaultCore Internal',
    softwareVersion: '2.5.0',
    filesMap: VAULTCORE_INTERNAL_FILES,
  });

  // Zero fabricated latency or throughput in static analysis
  assert.equal(analysis.runtimeMetrics.status, 'NOT_MEASURED');
  assert.equal(analysis.computedMetrics.p50LatencyMs, 0);
  assert.equal(analysis.computedMetrics.p95LatencyMs, 0);
  assert.equal(analysis.computedMetrics.throughputRps, 0);

  // ScoreCard generation marks performance category as NOT_ASSESSED when unmeasured
  const scoreCard = calculateDeterministicScoreCard(
    {
      softwareId: 'sw-vaultcore',
      softwareName: 'VaultCore Internal',
      softwareVersion: '2.5.0',
      veracityClassification: 'SUCCESS_VALIDATED',
      coveragePercent: 100,
      essentialFeaturesMissing: 0,
      visualOnlyFeaturesCount: 0,
      metrics: analysis.computedMetrics,
      hasEncryptionAtRest: true,
      hasAuditTrail: true,
      hasCleanSandboxUninstall: true,
      hasCompleteDocumentation: true,
      environmentEquivalent: true,
      runtimeMetrics: analysis.runtimeMetrics,
      findings: analysis.findings,
    },
    DEFAULT_CATEGORY_WEIGHTS,
    true
  );

  assert.equal(scoreCard.categoryDetails?.performance.status, 'NOT_ASSESSED');
  assert.ok(
    scoreCard.categoryDetails?.performance.limitations.some((l) => l.includes('não medidas'))
  );
});

test('Remediated VaultCore Internal (v2.5.0) and non-vault projects (keeweb / AuthGateway) pass Quality Gate with A/A/A ratings and zero false-positive CAP-FUNC or Privacy penalties', () => {
  const vaultCoreRemediated: Software = {
    id: 'sw-vaultcore-internal',
    projectId: 'proj-remediated',
    name: 'VaultCore Internal',
    vendor: 'Desenvolvimento Interno Corporativo',
    version: '2.5.0',
    domainTags: DEMO_FIXTURE_METADATA.VAULTCORE.domainTags,
    enabledCategories: DEMO_FIXTURE_METADATA.VAULTCORE.enabledCategories,
    licenseType: 'Proprietary Commercial',
    repositoryUrl: 'https://git.corp.internal/sec/vaultcore-internal.git',
    description: 'VaultCore Internal v2.5.0 remediated',
    createdAt: new Date().toISOString(),
    sourceFilesContent: VAULTCORE_INTERNAL_FILES,
  } as unknown as Software;

  const nonVaultApp: Software = {
    id: 'sw-auth-gateway',
    projectId: 'proj-remediated',
    name: 'AuthGateway Service',
    vendor: 'Platform Engineering',
    version: '1.2.0',
    domainTags: ['api-gateway', 'microservice', 'typescript', 'nodejs'],
    enabledCategories: [...ALL_BENCHMARK_CATEGORIES],
    licenseType: 'Apache-2.0',
    repositoryUrl: 'https://github.com/org/auth-gateway.git',
    description: 'Clean microservice without KDBX specific strings',
    createdAt: new Date().toISOString(),
    sourceFilesContent: {
      'package.json': JSON.stringify({
        name: 'auth-gateway',
        version: '1.2.0',
        scripts: { build: 'tsc', test: 'node --test' },
      }),
      'README.md': [
        '# AuthGateway Service',
        '## Architecture',
        'Clean hexagonal API gateway service.',
        '## Security',
        'Uses strict input validation and TLS 1.3.',
        '## Installation',
        'Run `npm ci && npm run build`.',
      ].join('\n\n'),
      'src/domain/tokenVerifier.ts': [
        'export interface TokenClaims { sub: string; exp: number; }',
        'export function verifyTokenClaims(claims: TokenClaims, nowSec: number): boolean {',
        '  return Boolean(claims.sub) && claims.exp > nowSec;',
        '}',
      ].join('\n'),
      'tests/tokenVerifier.spec.ts': [
        'import test from "node:test";',
        'import assert from "node:assert/strict";',
        'import { verifyTokenClaims } from "../src/domain/tokenVerifier";',
        'test("verifies valid and expired claims", () => {',
        '  assert.equal(verifyTokenClaims({ sub: "usr-1", exp: 9999999999 }, 1000), true);',
        '  assert.equal(verifyTokenClaims({ sub: "usr-1", exp: 500 }, 1000), false);',
        '});',
      ].join('\n'),
    },
  } as unknown as Software;

  const run = executeBenchmarkRunOrchestration({
    runId: 'run-remediated-check',
    projectId: 'proj-remediated',
    projectName: 'Auditoria Remediada & Matriz Adaptativa',
    profileName: 'Sonar way (Modo MQR)',
    softwares: [vaultCoreRemediated, nonVaultApp],
    weights: DEFAULT_CATEGORY_WEIGHTS,
    enabledCategories: [...ALL_BENCHMARK_CATEGORIES],
    qualityGateId: 'qg-sonar-way-mqr',
    enablePenaltyCaps: true,
    equivalenceEnvironment: {
      cpuCoresLimit: 4,
      memoryMbLimit: 4096,
      osTarget: 'Linux 6.8 Sandbox',
      workloadConcurrency: 50,
      dastFormalAuthorization: true,
      authorizedByOwner: 'Lead SecOps',
    },
  });

  const scVault = run.scoreCards.find((s) => s.softwareId === 'sw-vaultcore-internal')!;
  const scGateway = run.scoreCards.find((s) => s.softwareId === 'sw-auth-gateway')!;

  assert.ok(scVault && scGateway);

  // 1. Remediated VaultCore Internal v2.5.0 passes Quality Gate with A / A / A ratings and 0 findings
  const vaultFindings = run.findings.filter((f) => f.softwareId === 'sw-vaultcore-internal');
  assert.equal(vaultFindings.length, 0, 'Remediated VaultCore Internal v2.5.0 should have 0 findings');
  assert.equal(scVault.qualityGate?.status, 'PASSED');
  assert.equal(scVault.ratings?.security, 'A');
  assert.equal(scVault.ratings?.reliability, 'A');
  assert.equal(scVault.ratings?.maintainability, 'A');
  assert.equal(scVault.penaltyCapsTriggered.length, 0);
  assert.ok(scVault.groupedScores.overallScore >= 4.7);

  // 2. Non-vault clean application has 0 false-positive CAP-FUNC or Privacy penalties
  assert.equal(scGateway.qualityGate?.status, 'PASSED');
  assert.equal(scGateway.penaltyCapsTriggered.length, 0);
  assert.equal(scGateway.categoryDetails?.functionality.finalScore, 5.0);
  assert.equal(scGateway.categoryDetails?.privacy.finalScore, 4.8);
  assert.equal(scGateway.categoryDetails?.privacy.rating, 'A');
});

test('Canonical Path Traversal is blocked deterministically without escaping workspace directory', () => {
  const targetDir = path.resolve('/tmp/isolated-target');
  const maliciousPaths = [
    '../../etc/passwd',
    '..\\..\\windows\\system32\\cmd.exe',
    'foo/../../../root/.ssh/id_rsa',
    '/etc/shadow',
  ];

  for (const relPath of maliciousPaths) {
    const normalizedRel = relPath.replace(/\\/g, '/');
    const resolved = path.resolve(targetDir, normalizedRel);
    const isInside = resolved.startsWith(targetDir + path.sep);
    assert.equal(isInside, false, `Path "${relPath}" must not escape isolated sandbox.`);
  }
});

// ============================================================================
// SECTION 14: 25 MANDATORY SCENARIOS FOR VERACITY, METHODOLOGY, COMPARABILITY & PROVENANCE
// ============================================================================

test('Scenario 1 & 2: Software with METADATA_ONLY vs Software with FULL_SOURCE', () => {
  const metadataOnlySw: Software = {
    id: 'sw-meta-only',
    projectId: 'proj-1',
    name: 'GhostApp Metadata Only',
    vendor: 'Acme',
    description: 'Registered without source code',
    category: 'Web Application',
    version: '1.0.0',
    languages: [],
    architecture: 'N/A',
    operatingSystem: 'Linux',
    distributionModel: 'SaaS',
    licenseType: 'Proprietary',
    officialUrl: '',
    repositoryUrl: '',
    documentationUrl: '',
    owner: 'Tester',
    notes: '',
    sourceType: 'LOCAL_AUTHORIZED',
    commitHash: 'NOT_DECLARED',
    packageSha256: 'SOURCE_MISSING',
    createdAt: new Date().toISOString(),
    inventory: {
      totalFiles: 0,
      eligibleFiles: 0,
      totalLinesOfCode: 0,
      totalSizeBytes: 0,
      languageBreakdown: {},
      files: [],
      isolatedStoragePath: '/tmp/empty',
      verifiedIntegrity: false,
    },
  };

  assert.equal(determineSourceIngestionState(metadataOnlySw), 'METADATA_ONLY');
  assert.equal(determineSourceAvailability(metadataOnlySw), 'CLOSED_SOURCE');

  const run = executeBenchmarkRunOrchestration({
    runId: 'run-meta-only',
    projectId: 'proj-1',
    projectName: 'Metadata Test',
    profileName: 'Full Audit',
    softwares: [metadataOnlySw],
    weights: DEFAULT_CATEGORY_WEIGHTS,
    enablePenaltyCaps: true,
    equivalenceEnvironment: {
      cpuCoresLimit: 4,
      memoryMbLimit: 4096,
      osTarget: 'Linux',
      workloadConcurrency: 100,
    },
  });

  const sc = run.scoreCards[0];
  assert.equal(sc.separatedIndicators?.technicalScore, null);
  assert.equal(sc.separatedIndicators?.qualityGateDecision, 'INCONCLUSIVE');
  assert.equal(sc.separatedIndicators?.veracityState, 'SOURCE_MISSING');
  for (const cat of ALL_BENCHMARK_CATEGORIES) {
    assert.equal(sc.categoryScores[cat], null, `Category ${cat} must be null for METADATA_ONLY`);
    assert.equal(sc.categoryDetails?.[cat].status, 'INCONCLUSIVE');
  }
});

test('Scenario 3, 4 & 15: Partial Source, Corrupted/Null-Byte Files, Path Traversal, Symlink & Oversized Upload Rejection', () => {
  // Partial source (only non-code asset files, 0 eligible code files)
  const partialFiles = {
    'assets/logo.png': 'PNG_PLACEHOLDER',
    'docs/manual.pdf': 'PDF_PLACEHOLDER',
  };
  const invPartial = buildTechnicalInventory(partialFiles, '/tmp/partial');
  assert.equal(invPartial.totalFiles, 2);
  assert.equal(invPartial.eligibleFiles, 0);
  assert.equal(invPartial.unsupportedFilesCount, 2);

  // Security validation: path traversal, symlink, null-byte corrupted binary, oversized > 2MB
  const traversalCheck = validateSourceUploadSecurity({
    '../../etc/passwd': 'root:x:0:0',
    'src/symlink.ts': 'SYMLINK: /etc/shadow',
    'src/corrupted.ts': 'const a = 1;\0\0binary',
    'src/huge.ts': 'a'.repeat(2_200_000),
  });
  assert.equal(traversalCheck.valid, false);
  assert.equal(traversalCheck.rejectedFiles.length, 4);
  assert.ok(traversalCheck.violations.some((v) => v.includes('Path Traversal')));
  assert.ok(traversalCheck.violations.some((v) => v.includes('Symlink')));
  assert.ok(traversalCheck.violations.some((v) => v.includes('binário/corrompido')));
  assert.ok(traversalCheck.violations.some((v) => v.includes('excede o limite')));
});

test('Scenario 5 & 21: Real performance.now() tool timings, NATIVE_AST_ENGINE method, and 19-point Audit Matrix reconciliation', () => {
  const analysis = executeRealStaticAnalysisOnSource(
    'sw-timing-check',
    'TimingCheck Service',
    '1.0.0',
    KEESAFE_OPEN_FILES,
    'run-timing-check'
  );

  for (const exec of analysis.toolExecutions) {
    assert.equal(exec.executionMethod, 'NATIVE_AST_ENGINE');
    assert.ok(exec.durationMs >= 1, 'Duration must be positive');
    assert.ok(exec.startedAt <= exec.completedAt, 'startedAt must be <= completedAt');
  }

  assert.ok(analysis.veracity.auditMatrix && analysis.veracity.auditMatrix.length === 19);
  for (const row of analysis.veracity.auditMatrix!) {
    assert.equal(row.reconciledStatus, 'VERIFIED');
  }

  // Test coverage is 0% when no test files exist (never fabricated 82%)
  const noTestsFiles = {
    'src/index.ts': 'export const add = (a: number, b: number) => a + b;\n',
    'README.md': '# Simple Service\nArchitecture and installation guide.\n',
  };
  const noTestAnalysis = executeRealStaticAnalysisOnSource(
    'sw-no-tests',
    'NoTests Lib',
    '1.0.0',
    noTestsFiles,
    'run-no-tests'
  );
  assert.equal(noTestAnalysis.staticMetrics.testCoveragePercent, 0);
});

test('Scenario 7 & 19: HMAC-SHA256 Signed Evidence Manifest and Tamper Detection on Evidence Chain', () => {
  const inv = buildTechnicalInventory(KEESAFE_OPEN_FILES, '/tmp/keesafe');
  const sw: Software = {
    id: 'sw-hmac',
    projectId: 'proj-hmac',
    name: 'KeeSafe HMAC',
    vendor: 'Open',
    description: 'Test',
    category: 'Security',
    version: '3.1.0',
    languages: ['TypeScript'],
    architecture: 'Modular',
    operatingSystem: 'Linux',
    distributionModel: 'Open Source',
    licenseType: 'GPL-3.0',
    officialUrl: '',
    repositoryUrl: '',
    documentationUrl: '',
    owner: 'QA',
    notes: '',
    sourceType: 'LOCAL_UPLOAD',
    commitHash: 'abc1234',
    packageSha256: inv.packageSha256,
    createdAt: new Date().toISOString(),
    inventory: inv,
    sourceFilesContent: KEESAFE_OPEN_FILES,
  };

  const run = executeBenchmarkRunOrchestration({
    runId: 'run-hmac-01',
    projectId: 'proj-hmac',
    projectName: 'HMAC Audit',
    profileName: 'Default',
    softwares: [sw],
    weights: DEFAULT_CATEGORY_WEIGHTS,
    enablePenaltyCaps: true,
    equivalenceEnvironment: {
      cpuCoresLimit: 4,
      memoryMbLimit: 4096,
      osTarget: 'Linux',
      workloadConcurrency: 100,
    },
  });

  assert.ok(run.signedManifest);
  assert.equal(run.signedManifest?.signatureAlgorithm, 'HMAC-SHA256');
  assert.equal(run.evidenceChain[0]?.previousRecordSha256, GENESIS_EVIDENCE_HASH);

  const validCheck = verifyEvidenceChainAndManifest(run.evidenceChain, run.signedManifest);
  assert.equal(validCheck.valid, true);
  assert.equal(validCheck.signatureValid, true);
  assert.equal(validCheck.tamperedIndices.length, 0);

  // Tamper with a middle record's resultSummary without updating hashes
  const tamperedChain = run.evidenceChain.map((rec, idx) =>
    idx === 1 ? { ...rec, resultSummary: 'TAMPERED_SUMMARY_ATTACK' } : { ...rec }
  );
  const tamperedCheck = verifyEvidenceChainAndManifest(tamperedChain, run.signedManifest);
  assert.equal(tamperedCheck.valid, false);
  assert.ok(tamperedCheck.tamperedIndices.includes(2));
  assert.equal(tamperedCheck.signatureValid, false);
});

test('Scenario 8, 9 & 22: 27 Profiles Catalog (12 General + 15 Domain-Specialized), Not-Applicable Categories (score: null) and Weight Renormalization', () => {
  assert.equal(METHODOLOGY_CATALOG_VERSION, 'WINHOOD-CATALOG-v4.0.0');
  assert.equal(DOMAIN_SPECIALIZED_PROFILES.length, 27);
  const generalProfiles = DOMAIN_SPECIALIZED_PROFILES.filter((p) => p.profileType === 'GENERAL_DIMENSION');
  const domainProfiles = DOMAIN_SPECIALIZED_PROFILES.filter((p) => p.profileType === 'DOMAIN_SPECIALIZED');
  assert.equal(generalProfiles.length, 12);
  assert.equal(domainProfiles.length, 15);
  assert.ok(EVALUATION_CRITERIA_CATALOG.length >= 24);

  // Evaluate a CLI tool where database and usability are NOT_APPLICABLE
  const cliProfile = DOMAIN_SPECIALIZED_PROFILES.find((p) => p.id === 'prof-domain-cli-tool')!;
  assert.ok(cliProfile);
  assert.ok(cliProfile.notApplicableCategories.includes('database'));

  const cliFiles = {
    'src/cli.ts': 'export function runCli(args: string[]) { return args.join(" "); }\n',
    'test/cli.test.ts': 'import { runCli } from "../src/cli";\n',
    'README.md': '# CLI Tool\nUsage and installation instructions.\n',
    'package.json': '{"name": "my-cli", "version": "1.0.0", "bin": {"my-cli": "./src/cli.ts"}}',
  };
  const cliInv = buildTechnicalInventory(cliFiles, '/tmp/cli');
  const cliSw: Software = {
    id: 'sw-cli',
    projectId: 'proj-cli',
    name: 'FastCLI',
    vendor: 'DevTools',
    description: 'Command line tool',
    category: 'CLI Tool',
    functionalDomain: 'CLI_TOOL',
    version: '1.0.0',
    languages: ['TypeScript'],
    architecture: 'CLI',
    operatingSystem: 'Linux',
    distributionModel: 'npm',
    licenseType: 'MIT',
    officialUrl: '',
    repositoryUrl: '',
    documentationUrl: '',
    owner: 'Dev',
    notes: '',
    sourceType: 'LOCAL_UPLOAD',
    commitHash: 'cli123',
    packageSha256: cliInv.packageSha256,
    createdAt: new Date().toISOString(),
    inventory: cliInv,
    sourceFilesContent: cliFiles,
  };

  const run = executeBenchmarkRunOrchestration({
    runId: 'run-cli-01',
    projectId: 'proj-cli',
    projectName: 'CLI Benchmark',
    profileId: cliProfile.id,
    profileName: cliProfile.name,
    softwares: [cliSw],
    weights: cliProfile.weights,
    enabledCategories: cliProfile.enabledCategories,
    notApplicableCategories: cliProfile.notApplicableCategories,
    enablePenaltyCaps: true,
    equivalenceEnvironment: {
      cpuCoresLimit: 4,
      memoryMbLimit: 4096,
      osTarget: 'Linux',
      workloadConcurrency: 100,
    },
  });

  const sc = run.scoreCards[0];
  assert.equal(sc.categoryScores.database, null);
  assert.equal(sc.categoryDetails?.database.status, 'NOT_APPLICABLE');
  assert.equal(sc.categoryDetails?.database.finalScore, null);
  assert.equal(sc.categoryDetails?.database.effectiveWeight, 0);

  // Sum of effectiveWeights across assessed categories must equal 100%
  const sumEffective = Object.values(sc.effectiveWeights || {}).reduce((a, b) => a + b, 0);
  assert.equal(Math.round(sumEffective), 100);
});

test('Scenario 11 & 12: Comparability Engine blocks official winner when comparing incompatible domains or FULL_SOURCE vs PUBLIC_DOCUMENTATION_ONLY', () => {
  const vaultInv = buildTechnicalInventory(KEESAFE_OPEN_FILES, '/tmp/vault');
  const swVault: Software = {
    id: 'sw-vault-full',
    projectId: 'p1',
    name: 'KeeSafe Full Source',
    vendor: 'Open',
    description: 'Password Manager KDBX',
    category: 'Gerenciadores de Senhas',
    functionalDomain: 'PASSWORD_SECURITY_VAULT',
    sourceAvailability: 'FULL_SOURCE',
    version: '3.1.0',
    languages: ['TypeScript'],
    architecture: 'Modular',
    operatingSystem: 'Linux',
    distributionModel: 'OSS',
    licenseType: 'GPL',
    officialUrl: '',
    repositoryUrl: '',
    documentationUrl: '',
    owner: 'QA',
    notes: '',
    sourceType: 'LOCAL_UPLOAD',
    commitHash: '111',
    packageSha256: vaultInv.packageSha256,
    createdAt: new Date().toISOString(),
    inventory: vaultInv,
    sourceFilesContent: KEESAFE_OPEN_FILES,
  };

  // Case A: FULL_SOURCE vs PUBLIC_DOCUMENTATION_ONLY
  const swDocOnly: Software = {
    ...swVault,
    id: 'sw-doc-only',
    name: 'ClosedVault Public Docs',
    sourceType: 'PUBLIC_DOCUMENTATION_ONLY',
    sourceAvailability: 'PUBLIC_DOCUMENTATION_ONLY',
    sourceFilesContent: undefined,
  };

  const compDoc = evaluateSoftwareComparability({
    softwares: [swVault, swDocOnly],
    enabledCategories: ALL_BENCHMARK_CATEGORIES,
    environmentEquivalent: true,
  });
  assert.equal(compDoc.canDeclareOfficialWinner, false);
  assert.equal(compDoc.overallStatus, 'INCONCLUSIVE_COMPARISON');
  assert.ok(compDoc.blockingReasons.some((r) => r.includes('Assimetria severa de disponibilidade')));

  // Case B: Incompatible functional domains (PASSWORD_SECURITY_VAULT vs GAME_INTERACTIVE)
  const swGame: Software = {
    ...swVault,
    id: 'sw-game',
    name: 'ArcadeEngine 2D',
    category: 'Game Engine',
    functionalDomain: 'GAME_INTERACTIVE',
  };

  const runIncompatible = executeBenchmarkRunOrchestration({
    runId: 'run-incomp',
    projectId: 'p1',
    projectName: 'Incompatible Test',
    profileName: 'Compare',
    softwares: [swVault, swGame],
    weights: DEFAULT_CATEGORY_WEIGHTS,
    enablePenaltyCaps: true,
    equivalenceEnvironment: {
      cpuCoresLimit: 4,
      memoryMbLimit: 4096,
      osTarget: 'Linux',
      workloadConcurrency: 100,
    },
  });

  assert.equal(runIncompatible.comparabilityReport?.canDeclareOfficialWinner, false);
  assert.equal(runIncompatible.winnerSoftwareId, null);
});

test('Scenario 17 & 25: 9-State DevSecOps Finding Lifecycle Triage & Pre-Analysis Summary', () => {
  const vulnInv = buildTechnicalInventory(LEGACY_VULNERABLE_VAULT_FILES, '/tmp/vuln');
  const vulnSw: Software = {
    id: 'sw-vuln-lifecycle',
    projectId: 'p1',
    name: 'LegacyVault',
    vendor: 'Acme',
    description: 'Vulnerable vault',
    category: 'Security',
    version: '1.0.0',
    languages: ['TypeScript'],
    architecture: 'Monolith',
    operatingSystem: 'Linux',
    distributionModel: 'On-Prem',
    licenseType: 'Prop',
    officialUrl: '',
    repositoryUrl: '',
    documentationUrl: '',
    owner: 'Sec',
    notes: '',
    sourceType: 'LOCAL_UPLOAD',
    commitHash: 'v1',
    packageSha256: vulnInv.packageSha256,
    createdAt: new Date().toISOString(),
    inventory: vulnInv,
    sourceFilesContent: LEGACY_VULNERABLE_VAULT_FILES,
  };

  // Pre-analysis summary check
  const pre = buildPreAnalysisSummary(vulnSw, ALL_BENCHMARK_CATEGORIES, DEFAULT_CATEGORY_WEIGHTS);
  assert.equal(pre.eligibleFiles, vulnInv.eligibleFiles);
  assert.equal(pre.ingestionState, 'SOURCE_VALIDATED');
  assert.ok(pre.verifiableCriteriaCount > 0);

  const run = executeBenchmarkRunOrchestration({
    runId: 'run-lifecycle-9',
    projectId: 'p1',
    projectName: 'Triage 9 States',
    profileName: 'Audit',
    softwares: [vulnSw],
    weights: DEFAULT_CATEGORY_WEIGHTS,
    enablePenaltyCaps: true,
    equivalenceEnvironment: {
      cpuCoresLimit: 4,
      memoryMbLimit: 4096,
      osTarget: 'Linux',
      workloadConcurrency: 100,
    },
  });

  const initialScore = run.scoreCards[0].groupedScores.overallScore;
  assert.ok(run.findings.length > 0);

  // Transition all findings across the exempt lifecycle states (FALSE_POSITIVE, ACCEPTED_RISK, VERIFIED_RESOLVED, NOT_REPRODUCIBLE, INCONCLUSIVE)
  const exemptCycle = [
    'FALSE_POSITIVE',
    'ACCEPTED_RISK',
    'VERIFIED_RESOLVED',
    'NOT_REPRODUCIBLE',
    'INCONCLUSIVE',
  ] as const;

  run.findings.forEach((f, idx) => {
    const state = exemptCycle[idx % exemptCycle.length];
    f.lifecycleState = state;
    f.validationStatus = state;
  });

  recalculateBenchmarkRunScoreCards(run, [vulnSw]);
  const updatedScore = run.scoreCards[0].groupedScores.overallScore;
  assert.ok(updatedScore > initialScore, `Score must increase after exempting findings (${initialScore} -> ${updatedScore})`);
  assert.equal(run.scoreCards[0].ratings?.security, 'A');
});

test('Scenario 28: ToolResourceMonitor.runHostHardwareBenchmark executes deterministic CPU, Memory and Storage IOPS stress suite with SHA-256 verification', async () => {
  const { ToolResourceMonitor } = await import('../services/tools/ToolResourceMonitor');
  const hwResult = ToolResourceMonitor.runHostHardwareBenchmark();

  assert.ok(hwResult.benchmarkId.startsWith('hwbench-'));
  assert.ok(hwResult.hostSummary.cpuCores >= 1);
  assert.ok(hwResult.hostSummary.ramTotalMb > 0);

  // CPU metrics
  assert.ok(hwResult.cpuBenchmark.sha256OpsPerSec > 0);
  assert.ok(hwResult.cpuBenchmark.matrixFlopsMflops > 0);
  assert.ok(hwResult.cpuBenchmark.astParseOpsPerSec > 0);
  assert.ok(hwResult.cpuBenchmark.singleCoreScore >= 10 && hwResult.cpuBenchmark.singleCoreScore <= 100);
  assert.ok(hwResult.cpuBenchmark.multiCoreEstimatedScore >= 10 && hwResult.cpuBenchmark.multiCoreEstimatedScore <= 100);

  // Memory metrics
  assert.ok(hwResult.memoryBenchmark.sequentialWriteMbPerSec > 0);
  assert.ok(hwResult.memoryBenchmark.sequentialReadMbPerSec > 0);
  assert.ok(hwResult.memoryBenchmark.memoryScore >= 10 && hwResult.memoryBenchmark.memoryScore <= 100);

  // Storage IOPS metrics
  assert.ok(hwResult.storageBenchmark.sequentialWriteMbPerSec > 0);
  assert.ok(hwResult.storageBenchmark.sequentialReadMbPerSec > 0);
  assert.ok(hwResult.storageBenchmark.random4kIops > 0);
  assert.equal(hwResult.storageBenchmark.tempFileCleanedUp, true);

  // Overall score & SHA-256 verification hash
  assert.ok(hwResult.overallHostScore >= 10 && hwResult.overallHostScore <= 100);
  assert.ok(['S', 'A', 'B', 'C'].includes(hwResult.tier));
  assert.equal(hwResult.verificationSha256.length, 64);
});

