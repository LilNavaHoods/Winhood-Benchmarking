#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';

/**
 * WinHood CI Step & Multiplatform Job Aggregator
 *
 * Maps raw GitHub Actions outcomes/conclusions and job results strictly to:
 *   PASSED | FAILED | SKIPPED | NOT_EXECUTED | PARTIAL | BLOCKED
 *
 * Guarantees:
 * - Zero hardcoded "PASSED" strings.
 * - Missing artifacts caused by upstream producer failure remain explicitly causal
 *   and never downgrade a failed step into PASSED.
 * - Preserves overall failure status whenever any mandatory job or stage fails.
 */

export const VALID_SUMMARY_STATES = Object.freeze([
  'PASSED',
  'FAILED',
  'SKIPPED',
  'NOT_EXECUTED',
  'PARTIAL',
  'BLOCKED',
]);

export function normalizeStepState(outcome, conclusion) {
  const raw = String(outcome || conclusion || '').trim().toLowerCase();
  if (!raw || raw === 'not_executed' || raw === 'none') return 'NOT_EXECUTED';
  if (raw === 'success' || raw === 'passed') return 'PASSED';
  if (raw === 'failure' || raw === 'failed' || raw === 'timed_out' || raw === 'startup_failure') {
    return 'FAILED';
  }
  if (raw === 'cancelled') return 'BLOCKED';
  if (raw === 'skipped') return 'SKIPPED';
  if (raw === 'partial') return 'PARTIAL';
  if (raw === 'blocked') return 'BLOCKED';
  return 'NOT_EXECUTED';
}

export function normalizeJobState(jobResult) {
  const raw = String(jobResult || '').trim().toLowerCase();
  if (raw === 'success' || raw === 'passed') return 'PASSED';
  if (raw === 'failure' || raw === 'failed') return 'FAILED';
  if (raw === 'cancelled') return 'BLOCKED';
  if (raw === 'skipped') return 'SKIPPED';
  if (raw === 'partial') return 'PARTIAL';
  if (raw === 'blocked') return 'BLOCKED';
  return 'NOT_EXECUTED';
}

export function evaluateArtifactAvailability({
  artifactPresent,
  producerState,
  artifactName,
}) {
  if (artifactPresent) {
    return {
      status: 'PASSED',
      detail: `Artefato \`${artifactName}\` presente e verificado.`,
    };
  }
  if (producerState === 'FAILED' || producerState === 'BLOCKED') {
    return {
      status: producerState,
      detail: `Artefato \`${artifactName}\` ausente porque a etapa produtora concluiu com \`${producerState}\`.`,
    };
  }
  if (producerState === 'SKIPPED' || producerState === 'NOT_EXECUTED') {
    return {
      status: producerState,
      detail: `Artefato \`${artifactName}\` não gerado porque a etapa produtora foi \`${producerState}\`.`,
    };
  }
  return {
    status: 'FAILED',
    detail: `Artefato obrigatório \`${artifactName}\` ausente apesar da etapa produtora indicar \`${producerState}\`.`,
  };
}

export function generateCiSummaryReport(input) {
  const linux = input.linux || {};
  const windows = input.windows || {};

  const linuxJobStatus = normalizeJobState(linux.jobResult);
  const windowsJobStatus = normalizeJobState(windows.jobResult);

  const linuxSteps = {
    lockfile: normalizeStepState(linux.steps?.lockfile),
    positioning: normalizeStepState(linux.steps?.positioning),
    install: normalizeStepState(linux.steps?.install),
    audit: normalizeStepState(linux.steps?.audit),
    browser_imports: normalizeStepState(linux.steps?.browser_imports),
    typecheck: normalizeStepState(linux.steps?.typecheck),
    lint: normalizeStepState(linux.steps?.lint),
    build: normalizeStepState(linux.steps?.build),
    wizard_tests: normalizeStepState(linux.steps?.wizard_tests),
    security_tests: normalizeStepState(linux.steps?.security_tests),
    coverage: normalizeStepState(linux.steps?.coverage),
    determinism: normalizeStepState(linux.steps?.determinism),
    dogfood_action: normalizeStepState(linux.steps?.dogfood_action),
    vscode_ext: normalizeStepState(linux.steps?.vscode_ext),
    build_desktop: normalizeStepState(linux.steps?.build_desktop),
  };

  const windowsSteps = {
    lockfile: normalizeStepState(windows.steps?.lockfile),
    install: normalizeStepState(windows.steps?.install),
    browser_imports: normalizeStepState(windows.steps?.browser_imports),
    lint: normalizeStepState(windows.steps?.lint),
    build: normalizeStepState(windows.steps?.build),
    unit_tests: normalizeStepState(windows.steps?.unit_tests),
    build_desktop: normalizeStepState(windows.steps?.build_desktop),
    pack_win: normalizeStepState(windows.steps?.pack_win),
    inno_compile: normalizeStepState(windows.steps?.inno_compile),
    installer_e2e: normalizeStepState(windows.steps?.installer_e2e),
  };

  const coverageArtifact = evaluateArtifactAvailability({
    artifactPresent: Boolean(input.artifacts?.coverageSummaryPresent),
    producerState: linuxSteps.coverage,
    artifactName: 'coverage/coverage-summary.json',
  });

  const desktopArtifact = evaluateArtifactAvailability({
    artifactPresent: Boolean(input.artifacts?.desktopManifestPresent),
    producerState: linuxSteps.build_desktop,
    artifactName: 'dist-desktop/build-manifest.json',
  });

  const winInstallerArtifact = evaluateArtifactAvailability({
    artifactPresent: Boolean(input.artifacts?.windowsInstallerPresent),
    producerState: windowsSteps.inno_compile,
    artifactName: 'release-windows/installer/WinHood-Benchmarking-Setup.exe',
  });

  const allCriticalStates = [
    linuxJobStatus,
    windowsJobStatus,
    ...Object.values(linuxSteps),
    ...Object.values(windowsSteps),
  ];

  let overallStatus = 'PASSED';
  if (
    linuxJobStatus === 'FAILED' ||
    windowsJobStatus === 'FAILED' ||
    Object.values(linuxSteps).includes('FAILED') ||
    Object.values(windowsSteps).includes('FAILED')
  ) {
    overallStatus = 'FAILED';
  } else if (
    allCriticalStates.includes('BLOCKED')
  ) {
    overallStatus = 'BLOCKED';
  } else if (
    linuxJobStatus === 'SKIPPED' ||
    windowsJobStatus === 'SKIPPED' ||
    linuxJobStatus === 'NOT_EXECUTED' ||
    windowsJobStatus === 'NOT_EXECUTED' ||
    allCriticalStates.includes('SKIPPED') ||
    allCriticalStates.includes('NOT_EXECUTED') ||
    allCriticalStates.includes('PARTIAL')
  ) {
    overallStatus = 'PARTIAL';
  }

  const covEvidence = input.coverageTelemetry
    ? `Lines: ${input.coverageTelemetry.linesPct}% / Functions: ${input.coverageTelemetry.functionsPct}% / Branches: ${input.coverageTelemetry.branchesPct}% (13 domains: ${input.coverageTelemetry.all13DomainsLinesPct ?? 'N/A'}%)`
    : coverageArtifact.detail;

  const lines = [
    '## WinHood Multiplatform CI Consolidated Summary',
    '',
    `- **Overall Verdict:** \`${overallStatus}\``,
    `- **Linux Validation Job:** \`${linuxJobStatus}\``,
    `- **Windows Desktop & Installer Job:** \`${windowsJobStatus}\``,
    '',
    '### Linux (`ubuntu-latest`) Stage Breakdown',
    '',
    '| Stage (`step.id`) | Status | Evidence / Causal Context |',
    '| :--- | :--- | :--- |',
    `| Lockfile Integrity (\`lockfile\`) | \`${linuxSteps.lockfile}\` | \`package-lock.json\` only, zero \`bun.lock\` |`,
    `| Independent Positioning (\`positioning\`) | \`${linuxSteps.positioning}\` | \`node scripts/verify-independent-positioning.mjs\` |`,
    `| Deterministic Install (\`install\`) | \`${linuxSteps.install}\` | \`npm ci --ignore-scripts\` + \`npm ls --depth=0\` |`,
    `| NPM Vulnerability Governance (\`audit\`) | \`${linuxSteps.audit}\` | \`node scripts/verify-npm-audit.mjs\` (${input.auditStatus || 'status from step output'}) |`,
    `| Browser-Safe Imports Guardrail (\`browser_imports\`) | \`${linuxSteps.browser_imports}\` | \`npm run check:browser-imports\` + \`npm run test:browser-imports\` |`,
    `| TypeScript Typecheck (\`typecheck\`) | \`${linuxSteps.typecheck}\` | \`npm run typecheck\` (\`tsc --noEmit\`) |`,
    `| TypeScript Strict (\`lint\`) | \`${linuxSteps.lint}\` | \`npm run lint\` (\`tsc --noEmit\`) |`,
    `| Production Frontend Build (\`build\`) | \`${linuxSteps.build}\` | \`npm run build\` (Vite + browser-safe import gate) |`,
    `| Benchmark Wizard & A/B E2E (\`wizard_tests\`) | \`${linuxSteps.wizard_tests}\` | \`src/shared/wizardAndBrowserSafety.test.ts\` |`,
    `| OAuth, Security & Keystore Suite (\`security_tests\`) | \`${linuxSteps.security_tests}\` | \`npm run test:security\` |`,
    `| Coverage Gate c8 (\`coverage\`) | \`${linuxSteps.coverage}\` | ${covEvidence} |`,
    `| Coverage Artifact | \`${coverageArtifact.status}\` | ${coverageArtifact.detail} |`,
    `| CLI Determinism (\`determinism\`) | \`${linuxSteps.determinism}\` | Consecutive SHA-256 CLI output equality |`,
    `| GitHub Action Dogfooding (\`dogfood_action\`) | \`${linuxSteps.dogfood_action}\` | \`./integrations/github-action\` SARIF generation |`,
    `| VS Code Extension Tests (\`vscode_ext\`) | \`${linuxSteps.vscode_ext}\` | \`packages/vscode-extension/test/extension.integration.test.ts\` |`,
    `| Desktop Bundle Build (\`build_desktop\`) | \`${linuxSteps.build_desktop}\` | ${desktopArtifact.detail} |`,
    '',
    '### Windows (`windows-latest`) Stage Breakdown',
    '',
    '| Stage (`step.id`) | Status | Evidence / Causal Context |',
    '| :--- | :--- | :--- |',
    `| Lockfile Integrity (\`lockfile\`) | \`${windowsSteps.lockfile}\` | \`package-lock.json\` verified on Windows |`,
    `| Deterministic Install (\`install\`) | \`${windowsSteps.install}\` | \`npm ci --ignore-scripts\` + Electron runtime |`,
    `| Browser-Safe Imports (\`browser_imports\`) | \`${windowsSteps.browser_imports}\` | \`npm run check:browser-imports\` + \`npm run test:browser-imports\` |`,
    `| TypeScript Strict (\`lint\`) | \`${windowsSteps.lint}\` | \`npm run typecheck && npm run lint\` on win32-x64 |`,
    `| Production Frontend Build (\`build\`) | \`${windowsSteps.build}\` | \`npm run build\` on win32-x64 |`,
    `| Multiplatform Unit/Desktop/OAuth Tests (\`unit_tests\`) | \`${windowsSteps.unit_tests}\` | \`npm test\` |`,
    `| Desktop Bundle Build (\`build_desktop\`) | \`${windowsSteps.build_desktop}\` | \`npm run build:desktop\` |`,
    `| Unpacked Win32 Electron (\`pack_win\`) | \`${windowsSteps.pack_win}\` | \`npm run pack:win\` |`,
    `| Inno Setup Compile (\`inno_compile\`) | \`${windowsSteps.inno_compile}\` | ${winInstallerArtifact.detail} |`,
    `| Inno Setup E2E Lifecycle (\`installer_e2e\`) | \`${windowsSteps.installer_e2e}\` | Silent install -> launch/health/security -> \`%LOCALAPPDATA%\` -> uninstall |`,
    '',
  ];

  return {
    overallStatus,
    linuxJobStatus,
    windowsJobStatus,
    linuxSteps,
    windowsSteps,
    artifacts: {
      coverageArtifact,
      desktopArtifact,
      winInstallerArtifact,
    },
    markdown: lines.join('\n'),
  };
}

export function runSelfTest() {
  const allLinuxOk = {
    lockfile: 'success',
    positioning: 'success',
    install: 'success',
    audit: 'success',
    browser_imports: 'success',
    typecheck: 'success',
    lint: 'success',
    build: 'success',
    wizard_tests: 'success',
    security_tests: 'success',
    coverage: 'success',
    determinism: 'success',
    dogfood_action: 'success',
    vscode_ext: 'success',
    build_desktop: 'success',
  };
  const allWinOk = {
    lockfile: 'success',
    install: 'success',
    browser_imports: 'success',
    lint: 'success',
    build: 'success',
    unit_tests: 'success',
    build_desktop: 'success',
    pack_win: 'success',
    inno_compile: 'success',
    installer_e2e: 'success',
  };

  // Scenario 1: Linux success + Windows success
  const s1 = generateCiSummaryReport({
    linux: { jobResult: 'success', steps: allLinuxOk },
    windows: { jobResult: 'success', steps: allWinOk },
    artifacts: {
      coverageSummaryPresent: true,
      desktopManifestPresent: true,
      windowsInstallerPresent: true,
    },
    coverageTelemetry: { linesPct: 84.25, functionsPct: 89.47, branchesPct: 97.68, all13DomainsLinesPct: 60.97 },
  });
  assert.equal(s1.overallStatus, 'PASSED');
  assert.equal(s1.linuxSteps.browser_imports, 'PASSED');
  assert.equal(s1.linuxSteps.lint, 'PASSED');
  assert.equal(s1.windowsSteps.installer_e2e, 'PASSED');

  // Scenario 2: Linux success + Windows failure
  const s2 = generateCiSummaryReport({
    linux: { jobResult: 'success', steps: s1.linuxSteps },
    windows: {
      jobResult: 'failure',
      steps: {
        lockfile: 'success',
        install: 'success',
        browser_imports: 'success',
        lint: 'failure',
        build: 'skipped',
        unit_tests: 'skipped',
        build_desktop: 'skipped',
        pack_win: 'skipped',
        inno_compile: 'skipped',
        installer_e2e: 'skipped',
      },
    },
    artifacts: { coverageSummaryPresent: true, desktopManifestPresent: true, windowsInstallerPresent: false },
  });
  assert.equal(s2.overallStatus, 'FAILED');
  assert.equal(s2.windowsJobStatus, 'FAILED');
  assert.equal(s2.windowsSteps.lint, 'FAILED');
  assert.equal(s2.windowsSteps.unit_tests, 'SKIPPED');

  // Scenario 3: Linux failure + Windows skipped / not executed
  const s3 = generateCiSummaryReport({
    linux: {
      jobResult: 'failure',
      steps: {
        lockfile: 'success',
        positioning: 'failure',
        install: 'skipped',
        audit: 'skipped',
        browser_imports: 'skipped',
        typecheck: 'skipped',
        lint: 'skipped',
        build: 'skipped',
        wizard_tests: 'skipped',
        security_tests: 'skipped',
        coverage: 'skipped',
        determinism: 'skipped',
        dogfood_action: 'skipped',
        vscode_ext: 'skipped',
        build_desktop: 'skipped',
      },
    },
    windows: { jobResult: 'skipped', steps: {} },
    artifacts: { coverageSummaryPresent: false, desktopManifestPresent: false, windowsInstallerPresent: false },
  });
  assert.equal(s3.overallStatus, 'FAILED');
  assert.equal(s3.windowsJobStatus, 'SKIPPED');
  assert.equal(s3.linuxSteps.lint, 'SKIPPED');
  assert.ok(!s3.markdown.includes('| TypeScript Strict (`lint`) | `PASSED`'), 'Must never hardcode lint as PASSED');

  // Scenario 4: Failure before coverage (browser_imports fails -> build & coverage SKIPPED)
  const s4 = generateCiSummaryReport({
    linux: {
      jobResult: 'failure',
      steps: {
        lockfile: 'success',
        positioning: 'success',
        install: 'success',
        audit: 'success',
        browser_imports: 'failure',
        typecheck: 'skipped',
        lint: 'skipped',
        build: 'skipped',
        wizard_tests: 'skipped',
        security_tests: 'skipped',
        coverage: 'skipped',
        determinism: 'skipped',
        dogfood_action: 'skipped',
        vscode_ext: 'skipped',
        build_desktop: 'skipped',
      },
    },
    windows: { jobResult: 'success', steps: allWinOk },
    artifacts: { coverageSummaryPresent: false, desktopManifestPresent: false, windowsInstallerPresent: true },
  });
  assert.equal(s4.overallStatus, 'FAILED');
  assert.equal(s4.linuxSteps.browser_imports, 'FAILED');
  assert.equal(s4.linuxSteps.coverage, 'SKIPPED');
  assert.equal(s4.artifacts.coverageArtifact.status, 'SKIPPED');

  // Scenario 5: Missing artifact after producer step failed
  const s5 = generateCiSummaryReport({
    linux: {
      jobResult: 'failure',
      steps: {
        ...allLinuxOk,
        coverage: 'failure',
        determinism: 'skipped',
        dogfood_action: 'skipped',
        vscode_ext: 'skipped',
        build_desktop: 'skipped',
      },
    },
    windows: { jobResult: 'success', steps: allWinOk },
    artifacts: { coverageSummaryPresent: false, desktopManifestPresent: false, windowsInstallerPresent: true },
  });
  assert.equal(s5.overallStatus, 'FAILED');
  assert.equal(s5.artifacts.coverageArtifact.status, 'FAILED');
  assert.match(s5.artifacts.coverageArtifact.detail, /concluiu com `FAILED`/);

  // Scenario 6: Desktop build NOT_EXECUTED
  const s6 = generateCiSummaryReport({
    linux: {
      jobResult: 'success',
      steps: { ...allLinuxOk, build_desktop: 'not_executed' },
    },
    windows: {
      jobResult: 'success',
      steps: {
        ...allWinOk,
        build_desktop: 'not_executed',
        pack_win: 'not_executed',
        inno_compile: 'not_executed',
        installer_e2e: 'not_executed',
      },
    },
    artifacts: { coverageSummaryPresent: true, desktopManifestPresent: false, windowsInstallerPresent: false },
  });
  assert.equal(s6.overallStatus, 'PARTIAL');
  assert.equal(s6.linuxSteps.build_desktop, 'NOT_EXECUTED');
  assert.equal(s6.artifacts.desktopArtifact.status, 'NOT_EXECUTED');

  // Scenario 7: Partially completed / BLOCKED (e.g. cancelled job or blocked installer)
  const s7 = generateCiSummaryReport({
    linux: { jobResult: 'success', steps: allLinuxOk },
    windows: {
      jobResult: 'cancelled',
      steps: { ...allWinOk, inno_compile: 'blocked', installer_e2e: 'not_executed' },
    },
    artifacts: { coverageSummaryPresent: true, desktopManifestPresent: true, windowsInstallerPresent: false },
  });
  assert.equal(s7.overallStatus, 'BLOCKED');
  assert.equal(s7.windowsJobStatus, 'BLOCKED');
  assert.equal(s7.windowsSteps.inno_compile, 'BLOCKED');

  return { passed: true, scenariosTested: 7 };
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);

if (isMain) {
  const args = new Set(process.argv.slice(2));
  if (args.has('--self-test')) {
    const res = runSelfTest();
    console.log(`[WinHood CI Summary] SELF-TEST PASSED (${res.scenariosTested}/7 propagation scenarios verified).`);
    process.exit(0);
  }

  if (args.has('--render-github-summary')) {
    const payload = process.env.CI_SUMMARY_INPUT_JSON
      ? JSON.parse(process.env.CI_SUMMARY_INPUT_JSON)
      : {};
    const report = generateCiSummaryReport(payload);
    if (process.env.GITHUB_STEP_SUMMARY) {
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, report.markdown + '\n', 'utf8');
    }
    console.log(report.markdown);
    if (report.overallStatus === 'FAILED' || report.overallStatus === 'BLOCKED') {
      process.exit(1);
    }
  }
}
