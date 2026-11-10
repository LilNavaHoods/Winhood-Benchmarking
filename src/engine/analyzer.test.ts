import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_CATEGORY_WEIGHTS,
  calculateDeterministicScoreCard,
  computeSha256,
  maskSecretsInText,
  validateCategoryWeights,
  validateEquivalenceConditions,
} from './scoringEngine';
import {
  buildTechnicalInventory,
  executeRealStaticAnalysisOnSource,
} from './staticAnalyzer';
import {
  KEESAFE_OPEN_FILES,
  VAULTCORE_INTERNAL_FILES,
} from './realSampleRepositories';
import type { Software } from '../types/benchmark';

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

test('executeRealStaticAnalysisOnSource detects real SAST, Secrets, SCA, SQL, and Architecture flaws in VaultCore vs KeeSafe', () => {
  const analysisVaultCore = executeRealStaticAnalysisOnSource({
    runId: 'run-test-001',
    softwareId: 'sw-vaultcore',
    softwareName: 'VaultCore Internal',
    softwareVersion: '2.4.0',
    filesMap: VAULTCORE_INTERNAL_FILES,
  });

  const analysisKeeSafe = executeRealStaticAnalysisOnSource({
    runId: 'run-test-001',
    softwareId: 'sw-keesafe',
    softwareName: 'KeeSafe Open (KeePass KDBX)',
    softwareVersion: '2.56.0',
    filesMap: KEESAFE_OPEN_FILES,
  });

  // VaultCore Internal has real SAST SQLi, RCE execSync, MD5 weak crypto, hardcoded masterKey, circular dependency, and layer violation
  assert.ok(analysisVaultCore.computedMetrics.criticalVulns >= 3);
  assert.ok(analysisVaultCore.computedMetrics.secretsExposed >= 1);
  assert.ok(analysisVaultCore.computedMetrics.circularDependencies >= 1);
  assert.ok(analysisVaultCore.architectureGraph.layerViolations.length >= 1);
  assert.equal(analysisVaultCore.veracity.overallClassification, 'SUCCESS_VALIDATED');

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

test('calculateDeterministicScoreCard enforces mathematical Penalty Caps / Kill Switches on critical security flaws', () => {
  const analysisVaultCore = executeRealStaticAnalysisOnSource({
    runId: 'run-test-002',
    softwareId: 'sw-vaultcore',
    softwareName: 'VaultCore Internal',
    softwareVersion: '2.4.0',
    filesMap: VAULTCORE_INTERNAL_FILES,
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
      softwareId: 'sw-vaultcore',
      softwareName: 'VaultCore Internal',
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
    },
    DEFAULT_CATEGORY_WEIGHTS,
    true
  );

  assert.ok((scoreVaultCore.categoryScores.security ?? 5) <= 2.0);
  assert.ok(scoreVaultCore.groupedScores.overallScore <= 2.9);
  assert.ok(scoreVaultCore.penaltyCapsTriggered.length >= 2);
  assert.ok(scoreKeeSafe.groupedScores.overallScore > 4.0);
  assert.ok(scoreKeeSafe.groupedScores.overallScore > scoreVaultCore.groupedScores.overallScore);

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
    softwareId: 'sw-vaultcore',
    softwareName: 'VaultCore Internal',
    softwareVersion: '2.4.0',
    filesMap: VAULTCORE_INTERNAL_FILES,
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
        id: 'sw-vaultcore',
        projectId: 'proj-01',
        name: 'VaultCore Internal',
        vendor: 'VaultCore Inc.',
        version: '2.4.0',
        licenseType: 'Proprietary Commercial',
        repositoryUrl: 'https://internal.gitlab/vaultcore',
        description: 'Gerenciador com vulnerabilidades reais',
        createdAt: new Date().toISOString(),
        sourceFilesContent: VAULTCORE_INTERNAL_FILES,
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
  const surfaceA = suite.attackSurfaces.find((s) => s.softwareId === 'sw-vaultcore');
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
  const metricsA = suite.comparisonMetrics.find((m) => m.softwareId === 'sw-vaultcore');
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
    id: 'sw-vaultcore',
    projectId: 'proj-01',
    name: 'VaultCore Internal',
    vendor: 'VaultCore Inc.',
    version: '2.4.0',
    commitHash: 'a1b2c3d4e5f60123456789abcdef0123456789ab',
    licenseType: 'Proprietary Commercial',
    repositoryUrl: 'https://internal.gitlab/vaultcore',
    description: 'Gerenciador com vulnerabilidades reais',
    createdAt: new Date().toISOString(),
    sourceFilesContent: VAULTCORE_INTERNAL_FILES,
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
    id: 'sw-vaultcore',
    projectId: 'proj-01',
    name: 'VaultCore Internal',
    vendor: 'VaultCore Inc.',
    version: '2.4.0',
    commitHash: 'a1b2c3d4e5f60123456789abcdef0123456789ab',
    licenseType: 'Proprietary Commercial',
    repositoryUrl: 'https://internal.gitlab/vaultcore',
    description: 'Gerenciador com vulnerabilidades reais',
    createdAt: new Date().toISOString(),
    sourceFilesContent: { ...VAULTCORE_INTERNAL_FILES },
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

