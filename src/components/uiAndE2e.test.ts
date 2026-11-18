import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import type http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import App from '../App';
import { DashboardModule, SemicircularHealthGaugeSvg } from './DashboardModule';
import { HardwareAndDisplayBenchmarkModule } from './HardwareAndDisplayBenchmarkModule';
import { AuthGateModal } from './AuthGateModal';
import { PrivacyAndTermsModal } from './PrivacyAndTermsModal';
import { GovernancePortfolioModule } from './GovernancePortfolioModule';
import { ToolsAndIntegrationsModule } from './ToolsAndIntegrationsModule';
import { SecurityAssessmentSuiteModule } from './SecurityAssessmentSuiteModule';
import { VeracityAdaptersReportsModule } from './VeracityAdaptersReportsModule';
import { DEFAULT_SECURITY_SUITE_FILTERS } from '../utils/securityFindingsFilter';
import { validatePairComparability } from '../comparability/index';
import type { BenchmarkRun } from '../types/benchmark';
import { createWinHoodApp } from '../../server';

function base32ToBuffer(base32: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = base32.replace(/=+$/, '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function generateTotpCode(secretBase32: string, stepOffset = 0): string {
  const key = base32ToBuffer(secretBase32);
  const counter = Math.floor(Date.now() / 1000 / 30) + stepOffset;
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    (((hmac[offset]! & 0x7f) << 24) |
      ((hmac[offset + 1]! & 0xff) << 16) |
      ((hmac[offset + 2]! & 0xff) << 8) |
      (hmac[offset + 3]! & 0xff)) %
    1_000_000;
  return String(code).padStart(6, '0');
}

function extractCookies(res: Response, existing: Record<string, string> = {}): Record<string, string> {
  const updated = { ...existing };
  const anyHeaders = res.headers as unknown as { getSetCookie?: () => string[] };
  const rawList: string[] =
    typeof anyHeaders.getSetCookie === 'function'
      ? anyHeaders.getSetCookie()
      : res.headers.get('set-cookie')
        ? [res.headers.get('set-cookie') as string]
        : [];
  for (const line of rawList) {
    const pair = line.split(';')[0]?.trim();
    if (!pair) continue;
    const eq = pair.indexOf('=');
    if (eq > 0) {
      const k = pair.slice(0, eq).trim();
      const v = pair.slice(eq + 1).trim();
      if (!v || line.toLowerCase().includes('max-age=0')) {
        delete updated[k];
      } else {
        updated[k] = v;
      }
    }
  }
  return updated;
}

function cookieHeader(cookies: Record<string, string>): string {
  return Object.entries(cookies)
    .map(([k, v]) => `${k}=${v}`)
    .join('; ');
}

function readBootstrapTokenFromFile(filePath: string): string {
  const raw = fs.readFileSync(filePath, 'utf8');
  return (
    raw
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'))[0] || ''
  );
}

test('Phase 11 UI Honesty & Automated WCAG 2.2 AA structural DOM audit (SSR)', () => {
  // 1. Root App shell: skip-link, main landmark, nav aria-current, icon button labels
  const appHtml = renderToStaticMarkup(React.createElement(App));
  assert.ok(appHtml.includes('href="#main-content"'), 'App must include WCAG skip-to-content link');
  assert.ok(appHtml.includes('id="main-content"'), 'App must render #main-content landmark');
  assert.ok(appHtml.includes('aria-current="page"'), 'Active sidebar item must set aria-current="page"');
  assert.ok(!appHtml.includes('N=16384'), 'App SSR must not reference legacy N=16384');

  // 2. SemicircularHealthGaugeSvg: must never default to PASSED on missing qualityGateStatus
  const defaultGaugeHtml = renderToStaticMarkup(
    React.createElement(SemicircularHealthGaugeSvg, { score: null, softwareName: 'ProbeTarget' })
  );
  assert.ok(defaultGaugeHtml.includes('NOT_MEASURED'), 'Default gauge must render NOT_MEASURED');
  assert.ok(defaultGaugeHtml.includes('Não Avaliado'), 'Default gauge must render Não Avaliado');
  assert.ok(!defaultGaugeHtml.includes('PASSED'), 'Default gauge must never fabricate PASSED');

  // 3. DashboardModule empty state: honest zero-fabrication notice
  const noopAsync = async () => {};
  const emptyDashHtml = renderToStaticMarkup(
    React.createElement(DashboardModule, {
      data: {
        hasEvaluations: false,
        kpis: {
          totalProjects: 0,
          totalSoftwares: 0,
          totalRuns: 0,
          runningAnalyses: 0,
          completedAnalyses: 0,
          failedAnalyses: 0,
          vulnerabilitiesCount: 0,
          codeQualityIssuesCount: 0,
          avgPerformance: null,
          avgQuality: null,
        },
        latestRun: null,
        historicalRuns: [],
      },
      loading: false,
      onNavigate: () => {},
      onSeedRealWorkspace: noopAsync,
      onResetEmptyWorkspace: noopAsync,
    })
  );
  assert.ok(emptyDashHtml.includes('data-testid="empty-evaluations-state"'));
  assert.ok(emptyDashHtml.includes('Ainda não existem avaliações'));

  // 4. DashboardModule partial run: null security & missing coverage must NOT render 0.00/5.00 or 100%
  const partialRun = {
    id: 'run-partial-ssr-1',
    projectId: 'proj-1',
    projectName: 'Partial Test Project',
    profileId: 'prof-1',
    profileName: 'WinHood Standard',
    status: 'COMPLETED',
    assessmentMode: 'COMPARATIVE_BENCHMARK',
    startedAt: '2026-11-17T10:00:00.000Z',
    completedAt: '2026-11-17T10:00:05.000Z',
    weightsUsed: {
      functionality: 0,
      code_quality: 20,
      security: 25,
      performance: 15,
      architecture: 15,
      database: 10,
      reliability: 15,
      compatibility: 0,
      usability: 0,
      installation: 0,
      privacy: 0,
      documentation: 0,
    },
    equivalenceEnvironment: {
      cpuCoresLimit: 2,
      memoryMbLimit: 1024,
      profileLabel: 'Isolated Benchmark Profile',
    },
    scoreCards: [
      {
        softwareId: 'sw-a',
        softwareName: 'AlphaSvc',
        softwareVersion: '1.0.0',
        classificationLabel: 'BOM',
        advantages: [],
        deficiencies: [],
        groupedScores: {
          overallScore: 4.1,
          technicalScore: 4.1,
          securityScore: 0,
          qualityScore: 4.2,
          architectureScore: 4.0,
          functionalScore: 0,
          performanceScore: 0,
          technicalDebtRatioPercent: 2.5,
        },
        categoryScores: {
          functionality: null,
          code_quality: 4.2,
          security: null,
          performance: null,
          architecture: 4.0,
          database: 4.3,
          reliability: 4.1,
          compatibility: null,
          usability: null,
          installation: null,
          privacy: null,
          documentation: null,
        },
        categoryDetails: {},
        penaltyCapsTriggered: [],
        metricsSummary: {
          vulnerabilities: 0,
          criticalVulns: 0,
          highVulns: 0,
          mediumVulns: 0,
          lowVulns: 0,
          p50LatencyMs: 0,
          p95LatencyMs: 0,
          throughputRps: 0,
          technicalDebtMinutes: null,
          criticalFindings: 0,
          highFindings: 0,
        },
        runtimeMetrics: { status: 'NOT_MEASURED' },
        veracity: {
          veracityState: 'PARTIAL',
          coverageBreakdown: {
            analysis: { percent: null },
            test: { state: 'NOT_MEASURED', percent: null, sourceFormat: null },
          },
        },
      },
      {
        softwareId: 'sw-b',
        softwareName: 'BetaSvc',
        softwareVersion: '1.0.0',
        classificationLabel: 'REGULAR',
        advantages: [],
        deficiencies: [],
        groupedScores: {
          overallScore: 3.8,
          technicalScore: 3.8,
          securityScore: 3.9,
          qualityScore: 3.7,
          architectureScore: 3.8,
          functionalScore: 0,
          performanceScore: 0,
          technicalDebtRatioPercent: 4.0,
        },
        categoryScores: {
          functionality: null,
          code_quality: 3.7,
          security: 3.9,
          performance: null,
          architecture: 3.8,
          database: 3.7,
          reliability: 3.9,
          compatibility: null,
          usability: null,
          installation: null,
          privacy: null,
          documentation: null,
        },
        categoryDetails: {},
        penaltyCapsTriggered: [],
        metricsSummary: {
          vulnerabilities: 1,
          criticalVulns: 0,
          highVulns: 1,
          mediumVulns: 0,
          lowVulns: 0,
          p50LatencyMs: 0,
          p95LatencyMs: 0,
          throughputRps: 0,
          technicalDebtMinutes: 15,
          criticalFindings: 0,
          highFindings: 1,
        },
        runtimeMetrics: { status: 'NOT_MEASURED' },
        veracity: {
          veracityState: 'PARTIAL',
          coverageBreakdown: {
            analysis: { percent: 100 },
            test: { state: 'NOT_MEASURED', percent: null, sourceFormat: null },
          },
        },
      },
    ],
    findings: [],
    evidenceChain: [],
  } as unknown as BenchmarkRun;

  const partialDashHtml = renderToStaticMarkup(
    React.createElement(DashboardModule, {
      data: {
        hasEvaluations: true,
        kpis: {
          totalProjects: 1,
          totalSoftwares: 2,
          totalRuns: 1,
          runningAnalyses: 0,
          completedAnalyses: 1,
          failedAnalyses: 0,
          vulnerabilitiesCount: 1,
          codeQualityIssuesCount: 0,
          avgPerformance: null,
          avgQuality: 3.95,
        },
        latestRun: partialRun,
        historicalRuns: [],
      },
      loading: false,
      onNavigate: () => {},
      onSeedRealWorkspace: noopAsync,
      onResetEmptyWorkspace: noopAsync,
    })
  );
  assert.ok(partialDashHtml.includes('Seg.: NÃO MEDIDO'), 'Null security score must display Seg.: NÃO MEDIDO');
  assert.ok(partialDashHtml.includes('N/A (Não Medido)'), 'Missing category pair must display N/A (Não Medido)');
  assert.ok(partialDashHtml.includes('NOT_MEASURED'), 'Missing analysis coverage or debt must display NOT_MEASURED');
  assert.ok(!partialDashHtml.includes('Seg.: 0.00/5.00'), 'Must not render fabricated 0.00/5.00 when security is null');

  // 5. HardwareAndDisplayBenchmarkModule: unmeasured initial state must NOT render fabricated defaults
  const hwHtml = renderToStaticMarkup(
    React.createElement(HardwareAndDisplayBenchmarkModule, { runs: [], selectedRunId: '' })
  );
  assert.ok(hwHtml.includes('NOT_MEASURED'), 'Unmeasured hardware cards must show NOT_MEASURED');
  assert.ok(!hwHtml.includes('185,000 ops/s'), 'Must not render fabricated 185,000 ops/s');
  assert.ok(!hwHtml.includes('6,120 MB/s'), 'Must not render fabricated 6,120 MB/s');
  assert.ok(!hwHtml.includes('9f86d081884c7d659a2feaa0c55ad015'), 'Must not render fabricated SHA-256 hash');

  // 6. AuthGateModal & PrivacyAndTermsModal: WCAG dialog attributes + N=32768
  const authHtml = renderToStaticMarkup(
    React.createElement(AuthGateModal, {
      bootstrapRequired: false,
      bootstrapTokenFileHint: null,
      mfaRequired: false,
      pendingUser: null,
      onAuthenticated: () => {},
      onRefreshSession: noopAsync,
    })
  );
  assert.ok(authHtml.includes('role="dialog"'), 'AuthGateModal must have role="dialog"');
  assert.ok(authHtml.includes('aria-modal="true"'), 'AuthGateModal must have aria-modal="true"');
  assert.ok(authHtml.includes('aria-labelledby="winhood-auth-title"'));
  assert.ok(!authHtml.includes('16384'), 'AuthGateModal must not display stale N=16384');

  const privacyHtml = renderToStaticMarkup(
    React.createElement(PrivacyAndTermsModal, { isOpen: true, onClose: () => {}, initialTab: 'PRIVACY' })
  );
  assert.ok(privacyHtml.includes('role="dialog"'));
  assert.ok(privacyHtml.includes('aria-label="Fechar janela de Privacidade e Termos"'));

  const securityTabHtml = renderToStaticMarkup(
    React.createElement(PrivacyAndTermsModal, { isOpen: true, onClose: () => {}, initialTab: 'SECURITY' })
  );
  assert.ok(securityTabHtml.includes('N=32768'));
  assert.ok(!securityTabHtml.includes('16384'));

  // 7. Additional core workspace modules render cleanly in SSR
  const govHtml = renderToStaticMarkup(
    React.createElement(GovernancePortfolioModule, { latestRun: partialRun, softwares: [], onNotify: () => {} })
  );
  assert.ok(govHtml.includes('Quality Gates'), 'GovernancePortfolioModule must render Quality Gates');

  const toolsHtml = renderToStaticMarkup(
    React.createElement(ToolsAndIntegrationsModule, { softwares: [], onNotify: () => {} })
  );
  assert.ok(toolsHtml.length > 100);

  const secHtml = renderToStaticMarkup(
    React.createElement(SecurityAssessmentSuiteModule, {
      latestRun: partialRun,
      softwares: [],
      projects: [],
      securitySuiteFilters: DEFAULT_SECURITY_SUITE_FILTERS,
      onSecuritySuiteFiltersChange: () => {},
      onRunUpdated: () => {},
      onRefresh: noopAsync,
      onNotify: () => {},
    })
  );
  assert.ok(secHtml.includes('aria-label="Filtros avançados de achados de segurança"'));

  const reportsHtml = renderToStaticMarkup(
    React.createElement(VeracityAdaptersReportsModule, {
      latestRun: partialRun,
      adapters: [],
      auditLogs: [],
      initialTab: 'reports',
    })
  );
  assert.ok(reportsHtml.includes('aria-label="Filtrar Categoria no Relatório"'));
});

test('Phase 11 E2E: 10 real end-to-end WinHood Benchmarking full-stack HTTP flows', async () => {
  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-e2e-10flows-'));
  let server: http.Server | null = null;
  let cookies: Record<string, string> = {};

  const requestJson = async <T = any>(
    baseUrl: string,
    method: string,
    urlPath: string,
    body?: unknown
  ): Promise<{ status: number; data: T; rawText: string }> => {
    const headers: Record<string, string> = {};
    const cHeader = cookieHeader(cookies);
    if (cHeader) headers['cookie'] = cHeader;
    if (cookies['winhood_csrf']) headers['x-csrf-token'] = decodeURIComponent(cookies['winhood_csrf']);
    if (body !== undefined) headers['content-type'] = 'application/json';

    const res = await fetch(`${baseUrl}${urlPath}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    cookies = extractCookies(res, cookies);
    const rawText = await res.text();
    let parsed: any = null;
    try {
      parsed = JSON.parse(rawText);
    } catch {
      parsed = rawText;
    }
    return { status: res.status, data: parsed as T, rawText };
  };

  try {
    const { app } = await createWinHoodApp({ dataDir: tmpDataDir });
    server = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    // Flow 1: Health + Bootstrap Admin + Cadastro Secundário
    const health = await requestJson(baseUrl, 'GET', '/api/health');
    assert.equal(health.status, 200);
    assert.equal(health.data.status, 'ONLINE');

    const bsStatus = await requestJson(baseUrl, 'GET', '/api/auth/bootstrap-status');
    assert.equal(bsStatus.status, 200);
    assert.equal(bsStatus.data.bootstrapRequired, true);
    const bootstrapToken = readBootstrapTokenFromFile(
      path.resolve(process.cwd(), String(bsStatus.data.bootstrapTokenFileHint || ''))
    );
    assert.ok(bootstrapToken.length >= 16);

    const adminEmail = 'e2e-admin@winhood.local';
    const adminPassword = 'WinHood#E2E!Strong2026';
    const bootstrapRes = await requestJson(baseUrl, 'POST', '/api/auth/bootstrap-admin', {
      name: 'E2E Admin',
      email: adminEmail,
      password: adminPassword,
      bootstrapToken,
    });
    assert.equal(bootstrapRes.status, 201);
    assert.ok(cookies['winhood_csrf'], 'Session must set CSRF token cookie');

    // Flow 2: Login & Sessão real
    await requestJson(baseUrl, 'POST', '/api/auth/logout', {});
    const loginRes = await requestJson(baseUrl, 'POST', '/api/auth/login', {
      email: adminEmail,
      password: adminPassword,
    });
    assert.equal(loginRes.status, 200);
    const meRes = await requestJson(baseUrl, 'GET', '/api/auth/me');
    assert.equal(meRes.status, 200);
    assert.equal(meRes.data.authenticated, true);
    assert.equal(meRes.data.user.email, adminEmail);

    // Flow 3: Configuração TOTP + Verificação RFC 6238 + Re-login com MFA + Remoção
    const mfaSetup = await requestJson(baseUrl, 'POST', '/api/auth/mfa/setup', {});
    assert.equal(mfaSetup.status, 200);
    const secretMatch = String(mfaSetup.data.otpauthUri || '').match(/secret=([A-Z2-7]+)/i);
    assert.ok(secretMatch?.[1], 'otpauthUri must contain Base32 secret');
    const totpSecret = secretMatch[1];
    const mfaConfirm = await requestJson(baseUrl, 'POST', '/api/auth/mfa/confirm', {
      totpCode: generateTotpCode(totpSecret),
    });
    assert.equal(mfaConfirm.status, 200);

    // Logout & re-login requiring MFA
    await requestJson(baseUrl, 'POST', '/api/auth/logout', {});
    const mfaLogin = await requestJson(baseUrl, 'POST', '/api/auth/login', {
      email: adminEmail,
      password: adminPassword,
    });
    assert.equal(mfaLogin.status, 200);
    assert.equal(mfaLogin.data.mfaRequired, true);
    const mfaVerify = await requestJson(baseUrl, 'POST', '/api/auth/mfa/verify', {
      totpCode: generateTotpCode(totpSecret, 1),
    });
    assert.equal(mfaVerify.status, 200);
    assert.equal(mfaVerify.data.authenticated, true);

    // Flow 4: Criação de Projeto & Upload de 2 Softwares reais
    const projRes = await requestJson(baseUrl, 'POST', '/api/projects', {
      name: 'Projeto E2E Comparativo',
      category: 'Backend APIs & Seguranca',
      objective: 'Validacao E2E dos 10 fluxos criticos do WinHood.',
      description: 'Validacao E2E dos 10 fluxos criticos do WinHood.',
    });
    assert.equal(projRes.status, 201);
    const projectId = projRes.data.project.id as string;

    const swCleanRes = await requestJson(baseUrl, 'POST', '/api/softwares', {
      projectId,
      name: 'CleanApi',
      version: '1.0.0',
      vendor: 'E2E Lab',
      templatePreset: 'CUSTOM_FILES',
      customFilesMap: {
        'src/app.ts': [
          'export function findUser(db: { query: (sql: string, params: string[]) => unknown }, id: string) {',
          '  return db.query("SELECT id, name FROM users WHERE id = $1", [id]);',
          '}',
        ].join('\n'),
        'package.json': JSON.stringify({ name: 'clean-api', version: '1.0.0', dependencies: {} }),
      },
    });
    assert.equal(swCleanRes.status, 201);

    const swVulnRes = await requestJson(baseUrl, 'POST', '/api/softwares', {
      projectId,
      name: 'VulnApi',
      version: '1.0.0',
      vendor: 'E2E Lab',
      templatePreset: 'CUSTOM_FILES',
      customFilesMap: {
        'src/vuln.ts': [
          'const AWS_ACCESS_KEY = "AKIA1234567890ABCDEF";',
          'export function unsafeUser(req: { query: { id: string } }, db: { query: (s: string) => unknown }) {',
          '  const id = req.query.id;',
          '  return db.query("SELECT * FROM users WHERE id = " + id);',
          '}',
        ].join('\n'),
        'package.json': JSON.stringify({
          name: 'vuln-api',
          version: '1.0.0',
          dependencies: { lodash: '4.17.15' },
        }),
      },
    });
    assert.equal(swVulnRes.status, 201);

    // Flow 5: Execução real de Análise Comparativa
    const runRes = await requestJson(baseUrl, 'POST', '/api/benchmark-runs', {
      projectId,
      softwareIds: [swCleanRes.data.software.id, swVulnRes.data.software.id],
      wizardMode: 'QUICK',
      assessmentMode: 'AB_COMPARE',
    });
    assert.equal(runRes.status, 201);
    let run = runRes.data.run as BenchmarkRun;
    assert.ok(run.id);

    const pollDeadline = Date.now() + 15_000;
    while (run.status === 'RUNNING' && Date.now() < pollDeadline) {
      await new Promise((r) => setTimeout(r, 100));
      const polled = await requestJson(baseUrl, 'GET', `/api/benchmark-runs/${encodeURIComponent(run.id)}`);
      if (polled.status === 200 && polled.data?.run) {
        run = polled.data.run as BenchmarkRun;
      }
    }
    assert.ok(
      run.status === 'COMPLETED' || run.status === 'COMPLETED_WITH_WARNINGS',
      `Run must finish within 15s (got ${run.status})`
    );
    assert.equal(run.scoreCards.length, 2);

    // Flow 6: Dashboard + Listagem & Triagem de Achados
    const dashRes = await requestJson(baseUrl, 'GET', '/api/dashboard');
    assert.equal(dashRes.status, 200);
    assert.equal(dashRes.data.hasEvaluations, true);

    const findingsRes = await requestJson(baseUrl, 'GET', `/api/findings?runId=${encodeURIComponent(run.id)}`);
    assert.equal(findingsRes.status, 200);
    assert.ok(Array.isArray(findingsRes.data.findings) && findingsRes.data.findings.length >= 1);
    const targetFinding = findingsRes.data.findings[0];
    const triageRes = await requestJson(baseUrl, 'POST', `/api/findings/${encodeURIComponent(targetFinding.id)}/validate`, {
      lifecycleState: 'CONFIRMED',
      verificationNote: 'Confirmado via suíte E2E de 10 fluxos.',
      runId: run.id,
    });
    assert.equal(triageRes.status, 200);

    // Flow 7: Comparação A/B com Manifesto Verificável (rejeita flags soltas sem manifesto)
    const unverifiedAb = validatePairComparability(
      {
        softwareId: swCleanRes.data.software.id,
        engineVersion: '4.4.0',
        ruleCatalogSha256: 'a'.repeat(64),
        scopeCoveragePercent: 100,
        evidenceConfidence: 'HIGH',
        functionalCategory: 'Backend APIs',
        toolIdentifier: 'WinHood Native',
        toolExecuted: true,
      },
      {
        softwareId: swVulnRes.data.software.id,
        engineVersion: '1.0.0',
        ruleCatalogSha256: 'b'.repeat(64),
        scopeCoveragePercent: 100,
        evidenceConfidence: 'HIGH',
        functionalCategory: 'Backend APIs',
        toolIdentifier: 'External Tool',
        toolExecuted: true,
      },
      {
        modality: 'CROSS_TOOL',
        normalizedTaxonomyApplied: true, // loose boolean without manifest!
      }
    );
    assert.equal(unverifiedAb.comparabilityClassification, 'NOT_COMPARABLE', 'Loose boolean without manifest must yield NOT_COMPARABLE');
    assert.equal(unverifiedAb.comparable, false);

    // Flow 8: Avaliação de Quality Gate
    const gateRes = await requestJson(baseUrl, 'POST', '/api/quality-gates/evaluate', {
      runId: run.id,
    });
    assert.equal(gateRes.status, 200);
    assert.ok(['APPROVED', 'APPROVED_WITH_RESERVATIONS', 'BLOCKED', 'INCONCLUSIVE', 'REJECTED'].includes(gateRes.data.evaluation.decision));

    // Flow 9: Exportação SARIF / JSON / PDF / CycloneDX SBOM & Verificação de Cadeia de Evidências
    const sarifRes = await requestJson(baseUrl, 'GET', `/api/reports/${encodeURIComponent(run.id)}/export?format=sarif`);
    assert.equal(sarifRes.status, 200);
    assert.equal(sarifRes.data.version, '2.1.0');

    const pdfRes = await requestJson(baseUrl, 'GET', `/api/reports/${encodeURIComponent(run.id)}/export?format=pdf`);
    assert.equal(pdfRes.status, 200);
    assert.ok(pdfRes.rawText.startsWith('%PDF-1.4'));

    const sbomRes = await requestJson(baseUrl, 'GET', `/api/runs/${encodeURIComponent(run.id)}/sbom?format=cyclonedx-1.5`);
    assert.equal(sbomRes.status, 200);
    assert.equal(sbomRes.data.document.bomFormat, 'CycloneDX');

    const evVerify = await requestJson(baseUrl, 'POST', `/api/evidence/${encodeURIComponent(run.id)}/verify`, {});
    assert.equal(evVerify.status, 200);
    assert.equal(evVerify.data.valid, true);

    // Flow 10: Configurações de Segurança, Keystore status, Remoção MFA, Logout e Revogação
    const ksRes = await requestJson(baseUrl, 'GET', '/api/security/keys/status');
    assert.equal(ksRes.status, 200);
    const mfaDisable = await requestJson(baseUrl, 'POST', '/api/auth/mfa/disable', {
      password: adminPassword,
    });
    assert.equal(mfaDisable.status, 200);
    assert.equal(mfaDisable.data.user.mfaEnabled, false);

    await requestJson(baseUrl, 'POST', '/api/auth/logout', {});
    const afterLogoutMe = await requestJson(baseUrl, 'GET', '/api/auth/me');
    assert.equal(afterLogoutMe.data.authenticated, false);
    const blockedWrite = await requestJson(baseUrl, 'POST', '/api/projects', { name: 'Blocked' });
    assert.ok(blockedWrite.status === 401 || blockedWrite.status === 403);
  } finally {
    if (server) {
      await new Promise<void>((resolve) => server!.close(() => resolve()));
    }
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
  }
});
