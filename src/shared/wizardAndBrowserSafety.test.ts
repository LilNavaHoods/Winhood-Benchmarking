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
import {
  classifyScoreScale,
  normalizeEnabledCategoryWeights,
  validateCategoryWeights,
  validateEquivalenceConditions,
} from './benchmarkWeights';
import { resolveGitHubOAuthErrorMessage } from './authTypes';
import { BenchmarkWizardModule } from '../components/BenchmarkWizardModule';
import { AuthGateModal } from '../components/AuthGateModal';
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

test('classifyScoreScale and resolveGitHubOAuthErrorMessage return deterministic outputs', () => {
  assert.equal(classifyScoreScale(0.2), 'Inexistente');
  assert.equal(classifyScoreScale(1.5), 'Crítico');
  assert.equal(classifyScoreScale(2.5), 'Insuficiente');
  assert.equal(classifyScoreScale(3.5), 'Adequado');
  assert.equal(classifyScoreScale(4.2), 'Muito bom');
  assert.equal(classifyScoreScale(4.9), 'Excelente');

  assert.ok(resolveGitHubOAuthErrorMessage('access_denied')?.includes('cancelada'));
  assert.ok(resolveGitHubOAuthErrorMessage('not_configured')?.includes('administrador'));
  assert.ok(resolveGitHubOAuthErrorMessage('signup_disabled')?.includes('desabilitado'));
  assert.ok(resolveGitHubOAuthErrorMessage('unknown_code_xyz')?.includes('GitHub'));
  assert.equal(resolveGitHubOAuthErrorMessage(null), null);
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
  assert.ok(liveReport.scannedFiles.includes('src/components/AuthGateModal.tsx'));
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

test('BenchmarkWizardModule and AuthGateModal render cleanly via SSR without Node-only runtime crashes', () => {
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

  const authHtml = renderToStaticMarkup(
    React.createElement(AuthGateModal, {
      bootstrapRequired: false,
      mfaRequired: false,
      pendingUser: null,
      onAuthenticated: () => {},
      onRefreshSession: async () => {},
    })
  );
  assert.ok(
    authHtml.includes('Entrar ou cadastrar com GitHub'),
    'AuthGateModal must present clean GitHub social login CTA'
  );
});
