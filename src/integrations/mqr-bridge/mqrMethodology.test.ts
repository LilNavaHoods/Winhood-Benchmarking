import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { SonarMetricsMapper } from './SonarMetricsMapper';
import { SonarQualityGateMapper } from './SonarQualityGateMapper';
import { SonarResultParser } from './SonarResultParser';
import { MqrBridgeApiClient } from './SonarApiClient';
import { SonarScannerExecutor } from './SonarScannerExecutor';
import { SonarScannerManager } from './SonarScannerManager';

test('FASE 6.1 — SonarMetricsMapper: NUNCA converte métrica ausente em zero, 100% ou rating A', () => {
  const emptyMeasures = SonarMetricsMapper.mapMeasuresPayload({
    analysisId: 'test-empty',
    projectKey: 'proj-empty',
    softwareId: 'sw-empty',
    softwareName: 'Empty Project',
    commitHash: 'abc1234',
    rawMeasures: [],
    rawApiResponseHash: 'hash-empty',
  });

  assert.equal(emptyMeasures.measurementState, 'NOT_MEASURED');
  assert.equal(emptyMeasures.metrics.bugs, null);
  assert.equal(emptyMeasures.metrics.vulnerabilities, null);
  assert.equal(emptyMeasures.metrics.codeSmells, null);
  assert.equal(emptyMeasures.metrics.coveragePercent, null);
  assert.equal(emptyMeasures.metrics.lineCoveragePercent, null);
  assert.equal(emptyMeasures.metrics.branchCoveragePercent, null);
  assert.equal(emptyMeasures.metrics.reliabilityRating, 'NOT_MEASURED');
  assert.equal(emptyMeasures.metrics.securityRating, 'NOT_MEASURED');
  assert.equal(emptyMeasures.metrics.maintainabilityRating, 'NOT_MEASURED');
  assert.equal(emptyMeasures.metrics.securityReviewRating, 'NOT_MEASURED');

  // Nenhuma nota composta nativa pode ser inventada quando ratings estão ausentes
  const compositeScore = SonarMetricsMapper.computeNativeSonarScoreFromRatings(emptyMeasures.metrics);
  assert.equal(compositeScore, null);
});

test('FASE 6.1 — SonarMetricsMapper: separa Overall Code, New Code, MQR vs Standard e métricas de cobertura', () => {
  const mapped = SonarMetricsMapper.mapMeasuresPayload({
    analysisId: 'test-hybrid',
    projectKey: 'proj-hybrid',
    softwareId: 'sw-hybrid',
    softwareName: 'Hybrid Project',
    commitHash: 'def5678',
    rawApiResponseHash: 'hash-hybrid',
    rawMeasures: [
      { metric: 'bugs', value: '0' },
      { metric: 'vulnerabilities', value: '2' },
      { metric: 'code_smells', value: '15' },
      { metric: 'coverage', value: '78.4' },
      { metric: 'line_coverage', value: '82.1' },
      { metric: 'branch_coverage', value: '64.5' },
      { metric: 'lines_to_cover', value: '500' },
      { metric: 'uncovered_lines', value: '89' },
      { metric: 'conditions_to_cover', value: '120' },
      { metric: 'uncovered_conditions', value: '42' },
      { metric: 'reliability_rating', value: '1.0' },
      { metric: 'security_rating', value: '3.0' },
      { metric: 'sqale_rating', value: '2.0' },
      { metric: 'software_quality_security_rating', value: '3.0' },
      { metric: 'new_bugs', period: { index: 1, value: '1' } },
      { metric: 'new_coverage', period: { index: 1, value: '91.2' } },
      { metric: 'new_lines', period: { index: 1, value: '14' } },
    ],
  });

  assert.equal(mapped.measurementState, 'MEASURED');
  assert.equal(mapped.qualityModel, 'HYBRID');
  // Zero real retornado pela API deve ser preservado como 0
  assert.equal(mapped.metrics.bugs, 0);
  assert.equal(mapped.metrics.vulnerabilities, 2);
  // Coberturas separadas
  assert.equal(mapped.metrics.coveragePercent, 78.4);
  assert.equal(mapped.metrics.lineCoveragePercent, 82.1);
  assert.equal(mapped.metrics.branchCoveragePercent, 64.5);
  assert.notEqual(mapped.metrics.lineCoveragePercent, mapped.metrics.branchCoveragePercent);
  // New Code separado de Overall Code
  assert.equal(mapped.newCode?.newBugs, 1);
  assert.equal(mapped.newCode?.newCoveragePercent, 91.2);
  assert.equal(mapped.newCode?.newLines, 14);
  // Ratings reais
  assert.equal(mapped.metrics.reliabilityRating, 'A');
  assert.equal(mapped.metrics.securityRating, 'C');
  assert.equal(mapped.metrics.maintainabilityRating, 'B');
});

test('FASE 6.1 — SonarQualityGateMapper: avalia condições individuais, Fudge Factor (< 20 linhas) e nunca presume Sonar way', () => {
  const qg = SonarQualityGateMapper.mapProjectStatusPayload({
    analysisId: 'qg-test-1',
    projectKey: 'proj-qg',
    softwareId: 'sw-qg',
    softwareName: 'QG Project',
    newLinesCount: 12,
    projectStatus: {
      status: 'ERROR',
      ignoredConditions: true,
      conditions: [
        {
          status: 'OK',
          metricKey: 'new_reliability_rating',
          comparator: 'GT',
          errorThreshold: '1',
          actualValue: '1',
        },
        {
          status: 'ERROR',
          metricKey: 'new_security_rating',
          comparator: 'GT',
          errorThreshold: '1',
          actualValue: '3',
        },
      ],
    },
  });

  assert.equal(qg.status, 'ERROR');
  assert.equal(qg.gateName, 'NOT_VERIFIED');
  assert.equal(qg.gateNameVerified, false);
  assert.equal(qg.fudgeFactorStatus, 'APPLIED_SHORT_CHANGESET');
  assert.equal(qg.conditions.length, 2);
  assert.equal(qg.conditions[1].scope, 'NEW_CODE');
  assert.ok(qg.conditions[1].reasonText?.includes('3'));
});

test('FASE 6.1 — SonarResultParser: Security Hotspots SAFE e ACKNOWLEDGED não são classificados como FIXED nem como vulnerabilidades confirmadas', () => {
  const rawHotspots = [
    {
      key: 'hs-1',
      component: 'proj:src/auth.ts',
      project: 'proj',
      securityCategory: 'auth',
      vulnerabilityProbability: 'HIGH' as const,
      status: 'TO_REVIEW' as const,
      line: 10,
      message: 'Review regex',
    },
    {
      key: 'hs-2',
      component: 'proj:src/crypto.ts',
      project: 'proj',
      securityCategory: 'crypto',
      vulnerabilityProbability: 'MEDIUM' as const,
      status: 'REVIEWED' as const,
      resolution: 'SAFE' as const,
      line: 22,
      message: 'Safe usage',
    },
    {
      key: 'hs-3',
      component: 'proj:src/net.ts',
      project: 'proj',
      securityCategory: 'network',
      vulnerabilityProbability: 'LOW' as const,
      status: 'REVIEWED' as const,
      resolution: 'ACKNOWLEDGED' as const,
      line: 40,
      message: 'Accepted risk',
    },
    {
      key: 'hs-4',
      component: 'proj:src/db.ts',
      project: 'proj',
      securityCategory: 'sql-injection',
      vulnerabilityProbability: 'HIGH' as const,
      status: 'REVIEWED' as const,
      resolution: 'FIXED' as const,
      line: 55,
      message: 'Fixed parameterized query',
    },
  ];

  const breakdown = SonarResultParser.computeHotspotsBreakdown(rawHotspots);
  assert.equal(breakdown.measurementState, 'MEASURED');
  assert.equal(breakdown.totalIdentified, 4);
  assert.equal(breakdown.unreviewedCount, 1);
  assert.equal(breakdown.reviewedCount, 3);
  assert.equal(breakdown.reviewedSafeCount, 1);
  assert.equal(breakdown.acceptedRiskCount, 1);
  assert.equal(breakdown.reviewedFixedCount, 1);

  const parsed = SonarResultParser.parseIssuesAndHotspots({
    analysisId: 'hs-parse',
    projectKey: 'proj',
    softwareId: 'sw-1',
    softwareName: 'App',
    rawIssues: [],
    rawHotspots,
  });

  const normalized = SonarResultParser.mapSonarIssuesToNormalizedFindings(parsed, 'sw-1', 'App');
  assert.equal(normalized.length, 4);
  for (const finding of normalized) {
    assert.equal(finding.validationStatus, 'UNVERIFIED');
  }
});

test('FASE 6.1 — MqrBridgeApiClient: paginação real de issues (COMPLETE e PARTIAL quando página subsequente falha)', async () => {
  let failSecondPage = false;

  const mockServer = http.createServer((req, res) => {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    if (url.pathname === '/api/issues/search') {
      const page = Number(url.searchParams.get('p') || '1');
      if (page === 1) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            total: 3,
            paging: { pageIndex: 1, pageSize: 2, total: 3 },
            issues: [
              { key: 'I-1', rule: 'ts:S1', severity: 'MAJOR', component: 'p:a.ts', project: 'p', message: 'm1', type: 'BUG' },
              { key: 'I-2', rule: 'ts:S2', severity: 'MINOR', component: 'p:b.ts', project: 'p', message: 'm2', type: 'CODE_SMELL' },
            ],
          })
        );
        return;
      }
      if (page === 2) {
        if (failSecondPage) {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ errors: [{ msg: 'Service Unavailable' }] }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            total: 3,
            paging: { pageIndex: 2, pageSize: 2, total: 3 },
            issues: [
              { key: 'I-3', rule: 'ts:S3', severity: 'CRITICAL', component: 'p:c.ts', project: 'p', message: 'm3', type: 'VULNERABILITY' },
            ],
          })
        );
        return;
      }
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => mockServer.listen(0, '127.0.0.1', resolve));
  const address = mockServer.address() as { port: number };
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    const client = new MqrBridgeApiClient({
      serverUrl: baseUrl,
      token: 'squ_test_token',
    });

    const completeRes = await client.fetchAllProjectIssues('p', { pageSize: 2, maxPages: 5 });
    assert.equal(completeRes.issues.length, 3);
    assert.equal(completeRes.pagination.completeness, 'COMPLETE');
    assert.equal(completeRes.pagination.pagesFetched, 2);

    failSecondPage = true;
    const partialRes = await client.fetchAllProjectIssues('p', { pageSize: 2, maxPages: 5 });
    assert.equal(partialRes.issues.length, 2);
    assert.equal(partialRes.pagination.completeness, 'PARTIAL');
  } finally {
    await new Promise<void>((resolve) => mockServer.close(() => resolve()));
  }
});

test('FASE 6.1 — SonarScannerExecutor & SonarScannerManager: caminhos Windows com espaços/parênteses, arquivo temporário e proteção contra Command Injection', async () => {
  // 1. Verificar buildPlatformSafeSpawnSpec no Windows para caminhos com espaços e parênteses
  const winSpec = SonarScannerExecutor.buildPlatformSafeSpawnSpec(
    'C:\\Program Files (x86)\\SonarScanner\\bin\\sonar-scanner.bat',
    ['-Dproject.settings=C:\\Users\\SubZeroDev\\My Projects (2026)\\.winhood-sonar.properties'],
    'win32'
  );
  assert.equal(winSpec.options.shell, false);
  assert.equal(winSpec.options.windowsVerbatimArguments, true);
  assert.ok(winSpec.command.toLowerCase().endsWith('cmd.exe'));

  // 2. Verificar bloqueio de metacaracteres de injeção
  assert.throws(() => {
    SonarScannerExecutor.buildPlatformSafeSpawnSpec(
      'sonar-scanner.bat',
      ['-Dsonar.projectKey=foo & calc.exe'],
      'win32'
    );
  }, /SCANNER_UNSAFE_ARGUMENT_BLOCKED/);

  // 3. Verificar que executeIsolatedScanner NUNCA sobrescreve sonar-project.properties do usuário
  const tmpProj = fs.mkdtempSync(path.join(os.tmpdir(), 'wh-sonar-test-'));
  const userPropsPath = path.join(tmpProj, 'sonar-project.properties');
  const originalContent = 'sonar.projectKey=user-custom-key\n';
  fs.writeFileSync(userPropsPath, originalContent, 'utf8');

  try {
    await SonarScannerExecutor.executeIsolatedScanner({
      scannerType: 'SONAR_SCANNER_CLI',
      executablePath: process.execPath,
      projectBaseDir: tmpProj,
      propertiesContent: 'sonar.projectKey=winhood-temp-key\n',
      timeoutMs: 3000,
    });

    // O arquivo sonar-project.properties do usuário permanece intacto
    assert.equal(fs.readFileSync(userPropsPath, 'utf8'), originalContent);
  } finally {
    fs.rmSync(tmpProj, { recursive: true, force: true });
  }

  // 4. Verificar resolveCrossPlatformProjectBaseDir para artefatos isolados
  const resolved = SonarScannerManager.resolveCrossPlatformProjectBaseDir({
    id: 'sw-win-path-test',
    name: 'WinTest',
    version: '1.0.0',
    sourceType: 'LOCAL_UPLOAD',
    commitHash: 'abc',
    languages: ['TypeScript'],
    inventory: {
      isolatedStoragePath: '/isolated_artifacts/sw-win-path-test',
      files: [],
    },
  } as any);
  assert.ok(!resolved.projectBaseDir.startsWith('/isolated_artifacts/'));
});
