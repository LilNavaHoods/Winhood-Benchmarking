import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import {
  ALL_BENCHMARK_CATEGORIES,
  DEFAULT_CATEGORY_WEIGHTS,
  MARKET_CATEGORIES,
} from './benchmarkCategories';
import { normalizeEnabledCategoryWeights } from './benchmarkWeights';
import {
  classifyScoreScale,
  validateCategoryWeights,
  validateEquivalenceConditions,
} from './benchmarkValidation';
import {
  ALL_12_CATEGORIES,
  DOMAIN_SPECIALIZED_PROFILES,
  buildPreAnalysisSummary,
  evaluateSoftwareComparability,
} from './benchmarkConfig';
import * as sharedBarrel from './index';
import * as scoringEngine from '../engine/scoringEngine';
import * as marketDiscovery from '../engine/marketCompetitorDiscoveryEngine';
import * as methodologyCatalog from '../engine/methodologyCatalogEngine';
import {
  isValidRecoveryCodeFormat,
  isValidTotpSixDigit,
  normalizeRecoveryCode,
  normalizeTotpDigits,
} from './authTypes';
import { BenchmarkWizardModule } from '../components/BenchmarkWizardModule';
import { TotpUnlockModal } from '../components/TotpUnlockModal';
import {
  analyzeBrowserDependencyGraph,
  extractRuntimeSpecifiersFromSource,
  isForbiddenBrowserSpecifier,
} from '../../scripts/check-browser-imports.mjs';

test('Shared benchmark categories and default weights maintain exact canonical math (sum = 100%)', () => {
  assert.equal(ALL_BENCHMARK_CATEGORIES.length, 12);
  assert.equal(MARKET_CATEGORIES.length, 16);

  const defaultSum = ALL_BENCHMARK_CATEGORIES.reduce(
    (acc, key) => acc + DEFAULT_CATEGORY_WEIGHTS[key],
    0
  );
  assert.equal(defaultSum, 100);

  const validation = validateCategoryWeights(DEFAULT_CATEGORY_WEIGHTS);
  assert.equal(validation.valid, true);
  assert.equal(validation.totalWeight, 100);
  assert.deepEqual(validation.errors, []);
});

test('normalizeEnabledCategoryWeights normalizes subsets, zeroed weights, and invalid values to 100%', () => {
  // Subset of 3 enabled categories
  const subset: Array<(typeof ALL_BENCHMARK_CATEGORIES)[number]> = [
    'security',
    'code_quality',
    'performance',
  ];
  const normalizedSubset = normalizeEnabledCategoryWeights(DEFAULT_CATEGORY_WEIGHTS, subset);
  const subsetValidation = validateCategoryWeights(normalizedSubset, subset);
  assert.equal(subsetValidation.valid, true);
  assert.equal(subsetValidation.totalWeight, 100);
  assert.equal(normalizedSubset.documentation, 0);
  assert.equal(normalizedSubset.installation, 0);
  assert.ok(normalizedSubset.security > normalizedSubset.performance);

  // Zero / negative / NaN weights fall back to equal distribution summing to 100%
  const zeroWeights = normalizeEnabledCategoryWeights(
    { security: 0, code_quality: -10, performance: Number.NaN },
    subset
  );
  const zeroValidation = validateCategoryWeights(zeroWeights, subset);
  assert.equal(zeroValidation.valid, true);
  assert.equal(zeroValidation.totalWeight, 100);
});

test('validateCategoryWeights rejects invalid totals, NaN, negative, and >100 values', () => {
  const broken = { ...DEFAULT_CATEGORY_WEIGHTS, security: 30 };
  const res = validateCategoryWeights(broken);
  assert.equal(res.valid, false);
  assert.equal(res.totalWeight, 112);
  assert.ok(res.errors.some((e) => e.includes('100%')));

  const invalidEntries = {
    ...DEFAULT_CATEGORY_WEIGHTS,
    security: -5,
    code_quality: 105,
    performance: Number.NaN,
  };
  const resInvalid = validateCategoryWeights(invalidEntries);
  assert.equal(resInvalid.valid, false);
  assert.ok(resInvalid.errors.length >= 3);
});

test('validateEquivalenceConditions validates boundaries and rejects out-of-range settings', () => {
  const valid = validateEquivalenceConditions({
    cpuCoresLimit: 4,
    memoryMbLimit: 4096,
    osTarget: 'Linux Worker 6.8',
    workloadConcurrency: 100,
    dastFormalAuthorization: true,
    authorizedByOwner: 'CISO',
  });
  assert.equal(valid.equivalent, true);
  assert.deepEqual(valid.reasons, []);

  const missing = validateEquivalenceConditions(
    undefined as unknown as Parameters<typeof validateEquivalenceConditions>[0]
  );
  assert.equal(missing.equivalent, false);
  assert.ok(missing.reasons.length === 1);

  const outOfRange = validateEquivalenceConditions({
    cpuCoresLimit: 0,
    memoryMbLimit: 64,
    osTarget: 'X',
    workloadConcurrency: 99999,
    dastFormalAuthorization: false,
  });
  assert.equal(outOfRange.equivalent, false);
  assert.equal(outOfRange.reasons.length, 4);
});

test('classifyScoreScale and browser-safe Optional TOTP helpers return deterministic outputs', () => {
  assert.equal(classifyScoreScale(0.2), 'Inexistente');
  assert.equal(classifyScoreScale(1.5), 'Crítico');
  assert.equal(classifyScoreScale(2.5), 'Insuficiente');
  assert.equal(classifyScoreScale(3.5), 'Adequado');
  assert.equal(classifyScoreScale(4.2), 'Muito bom');
  assert.equal(classifyScoreScale(4.9), 'Excelente');

  assert.equal(normalizeTotpDigits(' 123-456 78 '), '123456');
  assert.equal(isValidTotpSixDigit('123456'), true);
  assert.equal(isValidTotpSixDigit('12345'), false);
  assert.equal(normalizeRecoveryCode(' abcd-12ef '), 'ABCD12EF');
  assert.equal(isValidRecoveryCodeFormat('ABCD-12EF'), true);
  assert.equal(isValidRecoveryCodeFormat('ABCD12EF'), true);
  assert.equal(isValidRecoveryCodeFormat('ZZZ'), false);
});

test('Browser-import checker passes on real WinHood frontend and catches all forbidden Node import patterns', () => {
  // 1. Live repo scan must pass with zero violations
  const liveReport = analyzeBrowserDependencyGraph({ rootDir: process.cwd() });
  assert.equal(
    liveReport.violations.length,
    0,
    `Expected 0 browser-import violations, got: ${JSON.stringify(liveReport.violations, null, 2)}`
  );
  assert.ok(liveReport.scannedFiles.includes('src/components/BenchmarkWizardModule.tsx'));
  assert.ok(liveReport.scannedFiles.includes('src/components/VeracityAdaptersReportsModule.tsx'));
  assert.ok(liveReport.scannedFiles.includes('src/components/TotpUnlockModal.tsx'));
  assert.ok(liveReport.scannedFiles.includes('src/shared/benchmarkWeights.ts'));

  // 2. Specifier detection: type-only imports must be ignored; runtime imports caught
  const extracted = extractRuntimeSpecifiersFromSource(
    'sample.ts',
    `
      import type { ChildProcess } from 'node:child_process';
      import { type Stats } from 'node:fs';
      import { foo } from './ok';
      export * from './barrel';
      export { bar } from './other';
      const dyn = () => import('node:net');
      const req = require('fs');
    `
  ).map((entry) => entry.specifier);
  assert.deepEqual(extracted.sort(), ['./barrel', './ok', './other', 'fs', 'node:net'].sort());
  assert.equal(isForbiddenBrowserSpecifier('node:child_process'), true);
  assert.equal(isForbiddenBrowserSpecifier('child_process'), true);
  assert.equal(isForbiddenBrowserSpecifier('fs/promises'), true);
  assert.equal(isForbiddenBrowserSpecifier('express'), true);
  assert.equal(isForbiddenBrowserSpecifier('react'), false);
  assert.equal(isForbiddenBrowserSpecifier('./shared/benchmarkWeights'), false);

  // 3. Temp fixture with transitive barrel re-export + dynamic import + tsconfig alias
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-browser-check-'));
  try {
    fs.mkdirSync(path.join(tmpRoot, 'src', 'components'), { recursive: true });
    fs.mkdirSync(path.join(tmpRoot, 'src', 'backend'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpRoot, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: {
          paths: { '@/*': ['./*'] },
        },
      }),
      'utf8'
    );
    fs.writeFileSync(
      path.join(tmpRoot, 'src', 'main.tsx'),
      `import { BrokenWizard } from './components/BrokenWizard';\nexport { BrokenWizard };\n`,
      'utf8'
    );
    fs.writeFileSync(
      path.join(tmpRoot, 'src', 'components', 'BrokenWizard.tsx'),
      `import type { ChildProcess } from 'node:child_process';\nimport { helper } from '@/src/backend/barrel';\nexport const BrokenWizard = () => helper();\n`,
      'utf8'
    );
    fs.writeFileSync(
      path.join(tmpRoot, 'src', 'backend', 'barrel.ts'),
      `export * from './secretRunner';\n`,
      'utf8'
    );
    fs.writeFileSync(
      path.join(tmpRoot, 'src', 'backend', 'secretRunner.ts'),
      `import { spawnSync } from 'node:child_process';\nexport const helper = () => spawnSync('echo', ['hi']);\n`,
      'utf8'
    );

    const fixtureReport = analyzeBrowserDependencyGraph({ rootDir: tmpRoot });
    assert.equal(fixtureReport.violations.length, 1);
    assert.equal(fixtureReport.violations[0]!.specifier, 'node:child_process');
    assert.ok(
      fixtureReport.violations[0]!.chain.join(' -> ').includes('src/backend/barrel.ts'),
      'Expected transitive barrel chain to be reported'
    );
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test('BenchmarkWizardModule and TotpUnlockModal render cleanly via SSR without Node-only runtime crashes', () => {
  const wizardHtml = renderToStaticMarkup(
    React.createElement(BenchmarkWizardModule, {
      projects: [],
      softwares: [],
      profiles: [],
      onRunCompleted: async () => {},
      onNotify: () => {},
    })
  );
  assert.ok(
    wizardHtml.includes('Como você deseja avaliar o software?'),
    'Wizard Step 1 heading must render'
  );
  assert.ok(wizardHtml.includes('Modalidade B'), 'Wizard must render Modalidade B (A/B Compare)');
  assert.ok(!wizardHtml.includes('node:child_process'), 'Wizard must never leak Node error');

  const totpHtml = renderToStaticMarkup(
    React.createElement(TotpUnlockModal, {
      onUnlocked: () => {},
    })
  );
  assert.ok(
    totpHtml.includes('Sessão Protegida por 2FA (TOTP)'),
    'TotpUnlockModal must present clean TOTP unlock dialog'
  );
  assert.ok(totpHtml.includes('role="dialog"'));
  assert.ok(totpHtml.includes('aria-modal="true"'));
});

test('Canonical single-source-of-truth identity: backend engines re-export exact shared implementations with zero duplication', () => {
  // scoringEngine canonical identity
  assert.strictEqual(scoringEngine.ALL_BENCHMARK_CATEGORIES, ALL_BENCHMARK_CATEGORIES);
  assert.strictEqual(scoringEngine.DEFAULT_CATEGORY_WEIGHTS, DEFAULT_CATEGORY_WEIGHTS);
  assert.strictEqual(scoringEngine.normalizeEnabledCategoryWeights, normalizeEnabledCategoryWeights);
  assert.strictEqual(scoringEngine.validateCategoryWeights, validateCategoryWeights);
  assert.strictEqual(scoringEngine.validateEquivalenceConditions, validateEquivalenceConditions);
  assert.strictEqual(scoringEngine.classifyScoreScale, classifyScoreScale);

  // marketCompetitorDiscoveryEngine canonical identity
  assert.strictEqual(marketDiscovery.MARKET_CATEGORIES, MARKET_CATEGORIES);

  // methodologyCatalogEngine & benchmarkConfig canonical identity
  assert.strictEqual(ALL_12_CATEGORIES, ALL_BENCHMARK_CATEGORIES);
  assert.strictEqual(methodologyCatalog.ALL_12_CATEGORIES, ALL_BENCHMARK_CATEGORIES);
  assert.strictEqual(methodologyCatalog.DOMAIN_SPECIALIZED_PROFILES, DOMAIN_SPECIALIZED_PROFILES);
  assert.strictEqual(methodologyCatalog.buildPreAnalysisSummary, buildPreAnalysisSummary);
  assert.strictEqual(methodologyCatalog.evaluateSoftwareComparability, evaluateSoftwareComparability);

  // Shared barrel exports match canonical modules
  assert.strictEqual(sharedBarrel.ALL_BENCHMARK_CATEGORIES, ALL_BENCHMARK_CATEGORIES);
  assert.strictEqual(sharedBarrel.DEFAULT_CATEGORY_WEIGHTS, DEFAULT_CATEGORY_WEIGHTS);
  assert.strictEqual(sharedBarrel.MARKET_CATEGORIES, MARKET_CATEGORIES);
  assert.strictEqual(sharedBarrel.normalizeEnabledCategoryWeights, normalizeEnabledCategoryWeights);
  assert.strictEqual(sharedBarrel.validateCategoryWeights, validateCategoryWeights);
  assert.strictEqual(sharedBarrel.validateEquivalenceConditions, validateEquivalenceConditions);
  assert.strictEqual(sharedBarrel.DOMAIN_SPECIALIZED_PROFILES, DOMAIN_SPECIALIZED_PROFILES);
});

test('Strict architectural boundary: frontend bundle graph never pulls src/engine, src/gate, src/security, src/execution, or src/storage', () => {
  const report = analyzeBrowserDependencyGraph({ rootDir: process.cwd() });
  assert.equal(report.ok, true);
  assert.ok(report.scannedFiles.includes('src/shared/benchmarkCategories.ts'));
  assert.ok(report.scannedFiles.includes('src/shared/benchmarkWeights.ts'));
  assert.ok(report.scannedFiles.includes('src/shared/benchmarkValidation.ts'));
  assert.ok(report.scannedFiles.includes('src/shared/benchmarkConfig.ts'));

  const forbiddenPrefixes = [
    'src/engine/',
    'src/gate/',
    'src/security/',
    'src/execution/',
    'src/storage/',
    'src/analyzers/',
    'src/integrations/',
    'src/services/',
    'src/workers/',
    'src/reports/',
  ];
  const leakedServerFiles = report.scannedFiles.filter((file) =>
    forbiddenPrefixes.some((prefix) => file.startsWith(prefix))
  );
  assert.deepEqual(
    leakedServerFiles,
    [],
    `Frontend bundle must not transitively import backend/engine modules, found: ${leakedServerFiles.join(', ')}`
  );
});

test('Shared weight normalization & validation cover single-category, partial subset, zero/negative/NaN/Infinity, and boundary equivalence conditions', () => {
  // Single enabled category normalizes to 100%
  const singleNormalized = normalizeEnabledCategoryWeights(DEFAULT_CATEGORY_WEIGHTS, ['security']);
  assert.equal(singleNormalized.security, 100);
  assert.equal(singleNormalized.code_quality, 0);
  assert.equal(validateCategoryWeights(singleNormalized, ['security']).valid, true);

  // Empty enabledCategories array falls back to validating all 12 canonical categories
  const emptyCatsValidation = validateCategoryWeights(DEFAULT_CATEGORY_WEIGHTS, []);
  assert.equal(emptyCatsValidation.valid, true);
  assert.equal(emptyCatsValidation.totalWeight, 100);

  // Disabled categories are ignored when a subset is enabled and sum of enabled != 100% is rejected
  const partialBad = validateCategoryWeights(DEFAULT_CATEGORY_WEIGHTS, ['security', 'code_quality']);
  assert.equal(partialBad.valid, false);
  assert.equal(partialBad.totalWeight, 30);

  // Total 99% and 101% are rejected
  const sum99 = { ...DEFAULT_CATEGORY_WEIGHTS, documentation: 3 };
  assert.equal(validateCategoryWeights(sum99).valid, false);
  assert.equal(validateCategoryWeights(sum99).totalWeight, 99);

  const sum101 = { ...DEFAULT_CATEGORY_WEIGHTS, documentation: 5 };
  assert.equal(validateCategoryWeights(sum101).valid, false);
  assert.equal(validateCategoryWeights(sum101).totalWeight, 101);

  // All-zero weights rejected by validateCategoryWeights, recovered by normalizeEnabledCategoryWeights
  const allZero = Object.fromEntries(ALL_BENCHMARK_CATEGORIES.map((k) => [k, 0])) as Record<
    (typeof ALL_BENCHMARK_CATEGORIES)[number],
    number
  >;
  assert.equal(validateCategoryWeights(allZero).valid, false);
  const recoveredAll = normalizeEnabledCategoryWeights(allZero, ALL_BENCHMARK_CATEGORIES);
  assert.equal(validateCategoryWeights(recoveredAll, ALL_BENCHMARK_CATEGORIES).valid, true);

  // Infinity weight rejected
  const infWeight = { ...DEFAULT_CATEGORY_WEIGHTS, security: Number.POSITIVE_INFINITY };
  assert.equal(validateCategoryWeights(infWeight).valid, false);

  // Equivalence exact boundary acceptance (min and max)
  assert.equal(
    validateEquivalenceConditions({
      cpuCoresLimit: 1,
      memoryMbLimit: 128,
      osTarget: 'Win',
      workloadConcurrency: 1,
      dastFormalAuthorization: false,
    }).equivalent,
    true
  );
  assert.equal(
    validateEquivalenceConditions({
      cpuCoresLimit: 64,
      memoryMbLimit: 65536,
      osTarget: 'Linux 6.8',
      workloadConcurrency: 5000,
      dastFormalAuthorization: true,
      authorizedByOwner: 'Security Board',
    }).equivalent,
    true
  );
  // Boundary violations (CPU 65, RAM 65537, concurrency 0, empty osTarget)
  const boundaryFail = validateEquivalenceConditions({
    cpuCoresLimit: 65,
    memoryMbLimit: 65537,
    osTarget: '  ',
    workloadConcurrency: 0,
    dastFormalAuthorization: false,
  });
  assert.equal(boundaryFail.equivalent, false);
  assert.equal(boundaryFail.reasons.length, 4);

  // Wizard SSR with empty softwares never renders literal "undefined"
  const emptyWizardHtml = renderToStaticMarkup(
    React.createElement(BenchmarkWizardModule, {
      projects: [],
      softwares: [],
      profiles: [],
      onRunCompleted: async () => {},
      onNotify: () => {},
    })
  );
  assert.equal(emptyWizardHtml.includes('undefined'), false);
});

test('Full-stack Benchmarking A/B flow: validation errors, cancellation, recovery, execution, scorecards, exports, history, and reload persistence', async () => {
  const { createWinHoodApp } = await import('../../server');
  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-wizard-ab-e2e-'));
  let server: import('node:http').Server | null = null;
  let cookies: Record<string, string> = {};

  const extractCookies = (res: Response) => {
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
          delete cookies[k];
        } else {
          cookies[k] = v;
        }
      }
    }
  };

  const reqJson = async <T = any>(
    baseUrl: string,
    method: string,
    urlPath: string,
    body?: unknown
  ): Promise<{ status: number; data: T; rawText: string }> => {
    const headers: Record<string, string> = {};
    const cHeader = Object.entries(cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    if (cHeader) headers['cookie'] = cHeader;
    if (cookies['winhood_csrf']) headers['x-csrf-token'] = decodeURIComponent(cookies['winhood_csrf']);
    if (body !== undefined) headers['content-type'] = 'application/json';

    const res = await fetch(`${baseUrl}${urlPath}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    extractCookies(res);
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
    server = await new Promise<import('node:http').Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const port = (server.address() as import('node:net').AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    // 1. Verify immediate Unrestricted Local Access (no login/signup required)
    const totpStatusRes = await reqJson(baseUrl, 'GET', '/api/totp/status');
    assert.equal(totpStatusRes.status, 200);
    assert.equal(totpStatusRes.data.enabled, false);
    assert.equal(totpStatusRes.data.unlocked, true);

    // 2. Create project + 2 real softwares + 1 metadata-only software
    const projRes = await reqJson(baseUrl, 'POST', '/api/projects', {
      name: 'Benchmark A/B Wizard Suite',
      category: 'Backend APIs',
      objective: 'Validar fluxo completo de 22 etapas do Wizard e Benchmark A/B.',
      description: 'Suite automatizada de regressão do Wizard.',
    });
    assert.equal(projRes.status, 201);
    const projectId = projRes.data.project.id as string;

    const swARes = await reqJson(baseUrl, 'POST', '/api/softwares', {
      projectId,
      name: 'ServiceAlpha',
      version: '2.1.0',
      vendor: 'WinHood QA',
      templatePreset: 'CUSTOM_FILES',
      customFilesMap: {
        'src/index.ts': [
          'export function sumPositive(nums: number[]): number {',
          '  return nums.filter((n) => Number.isFinite(n) && n > 0).reduce((a, b) => a + b, 0);',
          '}',
        ].join('\n'),
        'package.json': JSON.stringify({ name: 'service-alpha', version: '2.1.0', dependencies: {} }),
      },
    });
    assert.equal(swARes.status, 201);
    const swAId = swARes.data.software.id as string;

    const swBRes = await reqJson(baseUrl, 'POST', '/api/softwares', {
      projectId,
      name: 'ServiceBeta',
      version: '1.4.0',
      vendor: 'WinHood QA',
      templatePreset: 'CUSTOM_FILES',
      customFilesMap: {
        'src/legacy.ts': [
          'const HARDCODED_SECRET = "AKIA9999888877776666";',
          'export function queryRaw(db: { query: (sql: string) => unknown }, userInput: string) {',
          '  return db.query("SELECT * FROM items WHERE name = " + userInput);',
          '}',
        ].join('\n'),
        'package.json': JSON.stringify({
          name: 'service-beta',
          version: '1.4.0',
          dependencies: { lodash: '4.17.15' },
        }),
      },
    });
    assert.equal(swBRes.status, 201);
    const swBId = swBRes.data.software.id as string;

    const swMetaOnlyRes = await reqJson(baseUrl, 'POST', '/api/softwares', {
      projectId,
      name: 'NoSourceApp',
      version: '0.1.0',
      vendor: 'WinHood QA',
      templatePreset: 'METADATA_ONLY',
    });
    assert.equal(swMetaOnlyRes.status, 201);
    const swMetaId = swMetaOnlyRes.data.software.id as string;

    // 3. Mandatory error scenarios: missing fields, invalid modes, invalid weights, invalid environment
    const missingSw = await reqJson(baseUrl, 'POST', '/api/benchmark-runs', {
      projectId,
      softwareIds: [],
    });
    assert.equal(missingSw.status, 400);

    const unknownSw = await reqJson(baseUrl, 'POST', '/api/benchmark-runs', {
      projectId,
      softwareIds: ['sw-does-not-exist'],
    });
    assert.equal(unknownSw.status, 400);

    const abSingleSw = await reqJson(baseUrl, 'POST', '/api/benchmark-runs', {
      projectId,
      softwareIds: [swAId],
      assessmentMode: 'AB_COMPARE',
    });
    assert.equal(abSingleSw.status, 400);

    const indivTwoSw = await reqJson(baseUrl, 'POST', '/api/benchmark-runs', {
      projectId,
      softwareIds: [swAId, swBId],
      assessmentMode: 'INDIVIDUAL',
    });
    assert.equal(indivTwoSw.status, 400);

    const noSourceRun = await reqJson(baseUrl, 'POST', '/api/benchmark-runs', {
      projectId,
      softwareIds: [swMetaId],
      assessmentMode: 'INDIVIDUAL',
    });
    assert.equal(noSourceRun.status, 400);
    assert.equal(noSourceRun.data.code, 'SOURCE_REQUIRED');

    const badSum12 = await reqJson(baseUrl, 'POST', '/api/benchmark-runs', {
      projectId,
      softwareIds: [swAId, swBId],
      assessmentMode: 'AB_COMPARE',
      weights: { ...DEFAULT_CATEGORY_WEIGHTS, security: 30 },
    });
    assert.equal(badSum12.status, 400);

    const badSubsetWeights = await reqJson(baseUrl, 'POST', '/api/benchmark-runs', {
      projectId,
      softwareIds: [swAId, swBId],
      assessmentMode: 'AB_COMPARE',
      enabledCategories: ['security', 'code_quality'],
      weights: { ...DEFAULT_CATEGORY_WEIGHTS, security: 40, code_quality: 40 },
    });
    assert.equal(badSubsetWeights.status, 400);

    const negativeWeight = await reqJson(baseUrl, 'POST', '/api/benchmark-runs', {
      projectId,
      softwareIds: [swAId, swBId],
      assessmentMode: 'AB_COMPARE',
      weights: { ...DEFAULT_CATEGORY_WEIGHTS, security: -10, code_quality: 40 },
    });
    assert.equal(negativeWeight.status, 400);

    const invalidEnv = await reqJson(baseUrl, 'POST', '/api/benchmark-runs', {
      projectId,
      softwareIds: [swAId, swBId],
      assessmentMode: 'AB_COMPARE',
      equivalenceEnvironment: {
        cpuCoresLimit: 0,
        memoryMbLimit: 32,
        osTarget: 'X',
        workloadConcurrency: 99999,
        dastFormalAuthorization: false,
      },
    });
    assert.equal(invalidEnv.status, 400);

    // 4. Cancellation (emergency-stop) on nonexistent ID -> 404, and on active run -> deterministic cancel
    const stopMissing = await reqJson(baseUrl, 'POST', '/api/benchmark-runs/run-nonexistent/emergency-stop', {});
    assert.equal(stopMissing.status, 404);

    const runToCancelRes = await reqJson(baseUrl, 'POST', '/api/benchmark-runs', {
      projectId,
      softwareIds: [swAId, swBId],
      assessmentMode: 'AB_COMPARE',
    });
    assert.equal(runToCancelRes.status, 201);
    const cancelledId = runToCancelRes.data.run.id as string;

    const stopRes = await reqJson(
      baseUrl,
      'POST',
      `/api/benchmark-runs/${encodeURIComponent(cancelledId)}/emergency-stop`,
      {}
    );
    assert.equal(stopRes.status, 200);
    assert.equal(stopRes.data.ok, true);

    // Wait beyond the 150ms orchestration delay to ensure timer was cancelled and status was not overwritten
    await new Promise((r) => setTimeout(r, 300));
    const afterCancel = await reqJson(baseUrl, 'GET', `/api/benchmark-runs/${encodeURIComponent(cancelledId)}`);
    assert.equal(afterCancel.status, 200);
    assert.equal(afterCancel.data.run.status, 'COMPLETED_WITH_WARNINGS');
    assert.ok(String(afterCancel.data.run.progress?.stageLabel || '').includes('Cancelado'));

    // 5. Recovery after error/cancellation: execute full A/B benchmark with custom subset of categories normalized to 100%
    const subsetCats: Array<(typeof ALL_BENCHMARK_CATEGORIES)[number]> = [
      'security',
      'code_quality',
      'architecture',
      'reliability',
    ];
    const normalizedWeights = normalizeEnabledCategoryWeights(DEFAULT_CATEGORY_WEIGHTS, subsetCats);
    assert.equal(validateCategoryWeights(normalizedWeights, subsetCats).valid, true);

    const createAbRes = await reqJson(baseUrl, 'POST', '/api/benchmark-runs', {
      projectId,
      softwareIds: [swAId, swBId],
      assessmentMode: 'AB_COMPARE',
      wizardMode: 'CUSTOM',
      enabledCategories: subsetCats,
      weights: normalizedWeights,
      enablePenaltyCaps: true,
      equivalenceEnvironment: {
        cpuCoresLimit: 4,
        memoryMbLimit: 4096,
        osTarget: 'Linux Worker 6.8',
        workloadConcurrency: 100,
        dastFormalAuthorization: true,
        authorizedByOwner: 'QA E2E Suite',
      },
    });
    assert.equal(createAbRes.status, 201);
    let completedRun = createAbRes.data.run;
    assert.ok(completedRun.id);

    // Poll progress and run until completion
    const deadline = Date.now() + 15_000;
    while (completedRun.status === 'RUNNING' && Date.now() < deadline) {
      const progRes = await reqJson(
        baseUrl,
        'GET',
        `/api/benchmark-runs/${encodeURIComponent(completedRun.id)}/progress`
      );
      assert.equal(progRes.status, 200);
      await new Promise((r) => setTimeout(r, 100));
      const runPoll = await reqJson(baseUrl, 'GET', `/api/benchmark-runs/${encodeURIComponent(completedRun.id)}`);
      if (runPoll.status === 200 && runPoll.data?.run) {
        completedRun = runPoll.data.run;
      }
    }
    assert.ok(
      completedRun.status === 'COMPLETED' || completedRun.status === 'COMPLETED_WITH_WARNINGS',
      `Expected completed benchmark run, got ${completedRun.status}`
    );

    // 6. Verify Scorecards, Categories, and A/B Comparison
    assert.equal(completedRun.scoreCards.length, 2);
    const alphaCard = completedRun.scoreCards.find((c: any) => c.softwareId === swAId);
    const betaCard = completedRun.scoreCards.find((c: any) => c.softwareId === swBId);
    assert.ok(alphaCard && betaCard);
    assert.equal(typeof alphaCard.groupedScores.overallScore, 'number');
    assert.equal(typeof betaCard.groupedScores.overallScore, 'number');
    assert.ok(
      alphaCard.groupedScores.overallScore >= betaCard.groupedScores.overallScore,
      'Clean ServiceAlpha should score >= vulnerable ServiceBeta'
    );
    assert.deepEqual(completedRun.enabledCategories, subsetCats);

    // 7. Verify Exports (JSON, Markdown, HTML, SARIF, PDF)
    for (const fmt of ['json', 'markdown', 'html', 'sarif', 'pdf']) {
      const exp = await reqJson(
        baseUrl,
        'GET',
        `/api/reports/${encodeURIComponent(completedRun.id)}/export?format=${fmt}`
      );
      assert.equal(exp.status, 200, `Export format=${fmt} must return 200`);
      assert.ok(exp.rawText.length > 50, `Export format=${fmt} must be non-empty`);
    }

    // 8. Verify History endpoint & Dashboard
    const historyRes = await reqJson(baseUrl, 'GET', '/api/benchmark-runs');
    assert.equal(historyRes.status, 200);
    assert.ok(historyRes.data.runs.some((r: any) => r.id === completedRun.id));

    const dashRes = await reqJson(baseUrl, 'GET', '/api/dashboard');
    assert.equal(dashRes.status, 200);
    assert.equal(dashRes.data.hasEvaluations, true);
    assert.ok(dashRes.data.kpis.totalRuns >= 2);

    // 9. Verify Disk Persistence across fresh app/server reload
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = null;

    const reloaded = await createWinHoodApp({ dataDir: tmpDataDir });
    const persistedRun = reloaded.getDb().runs.find((r) => r.id === completedRun.id);
    assert.ok(persistedRun, 'Completed benchmark run must persist on disk across server restarts');
    assert.equal(persistedRun.scoreCards.length, 2);
  } finally {
    if (server) {
      await new Promise<void>((resolve) => server!.close(() => resolve()));
    }
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
  }
});

test('TotpUnlockModal UX renders clean RFC-6238 unlock prompt with zero login, password, PIN, or OAuth fields', () => {
  const html = renderToStaticMarkup(
    React.createElement(TotpUnlockModal, {
      onUnlocked: () => {},
    })
  );
  assert.ok(html.includes('Sessão Protegida por 2FA (TOTP)'));
  assert.ok(html.includes('id="totp-unlock-code"'));
  assert.equal(html.includes('Entrar com GitHub'), false, 'Must not render GitHub OAuth CTA');
  assert.equal(html.includes('type="password"'), false, 'Must not render password login field');
  assert.equal(html.includes('Personal Access Token'), false, 'Must not render PAT input');
  assert.equal(html.includes('Client Secret'), false, 'Must not render OAuth Client Secret');
});
