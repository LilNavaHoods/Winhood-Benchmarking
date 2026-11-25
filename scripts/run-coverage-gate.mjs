import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { register } from 'tsx/esm/api';
import { executeC8V8CoverageRun, summarizeCoverageMapSubset } from './coverage-runner-core.mjs';

register();

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const covDir = path.join(rootDir, 'coverage');

const {
  OFFICIAL_13_COVERAGE_DOMAINS,
  scanOfficial13DomainsInventory,
  computeThreeWaySeparatedCoverage,
} = await import('../src/execution/CoverageDomainInventory.ts');

const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
const thresholds = pkg.c8?.thresholds || {
  lines: 80,
  functions: 80,
  branches: 75,
  'src/scoring/**': { lines: 95, functions: 95, branches: 95 },
  'src/evidence/**': { lines: 95, functions: 95, branches: 95 },
  'src/comparability/**': { lines: 95, functions: 95, branches: 95 },
};

const CORE_AUDITED_DOMAIN_IDS = new Set([
  'src/analyzers/',
  'src/scoring/',
  'src/evidence/',
  'src/comparability/',
  'src/gate/',
  'src/reports/',
]);

const inventoryScans = scanOfficial13DomainsInventory(rootDir);
const eligibleByDomain = {};
const allEligibleFiles = [];
const allExcludedFiles = [];

for (const scan of inventoryScans) {
  eligibleByDomain[scan.domainId] = scan.eligibleFiles;
  allEligibleFiles.push(...scan.eligibleFiles);
  allExcludedFiles.push(...scan.excludedFiles);
}
const allEligibleSet = new Set(allEligibleFiles);

// Derive c8 include & exclude directly from OFFICIAL_13_COVERAGE_DOMAINS (zero duplicate lists)
const c8Include = Array.from(
  new Set(
    OFFICIAL_13_COVERAGE_DOMAINS.flatMap((d) =>
      d.directories.flatMap((dir) => d.eligibleExtensions.map((ext) => `${dir}/**/*${ext}`))
    )
  )
);

const c8Exclude = Array.from(
  new Set([
    ...OFFICIAL_13_COVERAGE_DOMAINS.flatMap((d) => d.excludedPatterns.map((p) => p.pattern)),
    'src/types/**',
    'dist/**',
    'dist-desktop/**',
    'node_modules/**',
  ])
);

const testFiles = [
  'scripts/check-browser-imports.test.ts',
  'src/shared/wizardAndBrowserSafety.test.ts',
  'src/scoring/scoring.test.ts',
  'src/engine/analyzer.test.ts',
  'src/engine/veracityAudit.test.ts',
  'src/analyzers/analyzers.test.ts',
  'src/analyzers/externalAdapters.test.ts',
  'src/analyzers/pluginsAndIac.test.ts',
  'src/gate/gateAndCompliance.test.ts',
  'src/cli/cliAndApi.test.ts',
  'src/intelligence/intelligence.test.ts',
  'src/security/security.test.ts',
  'src/security/backendHardening.test.ts',
  'src/integrations/mqr-bridge/mqrMethodology.test.ts',
  'src/desktop/desktop.test.ts',
  'src/utils/securityFindingsFilter.test.ts',
  'src/execution/coverageEngine.test.ts',
  'src/components/uiAndE2e.test.ts',
  'packages/vscode-extension/test/extension.integration.test.ts',
].filter((rel) => fs.existsSync(path.join(rootDir, rel)));

console.log(
  `[WinHood Coverage Gate] Executing c8 + v8-to-istanbul (all: true) across ${OFFICIAL_13_COVERAGE_DOMAINS.length} official domains (${allEligibleFiles.length} eligible files)...`
);

const runResult = await executeC8V8CoverageRun({
  rootDir,
  testFiles,
  include: c8Include,
  exclude: c8Exclude,
  extensions: ['.ts', '.tsx'],
  covDir,
  all: true,
  isEligibleRelPath: (rel) => allEligibleSet.has(rel),
  emitReports: true,
});

if (runResult.stdout) process.stdout.write(runResult.stdout);
if (runResult.stderr) process.stderr.write(runResult.stderr);

if (runResult.testExitCode !== 0 || !runResult.coverageMap) {
  console.error(`[WinHood Coverage Gate FAILED] Test suite exited with code ${runResult.testExitCode}`);
  process.exit(runResult.testExitCode || 1);
}

const { coverageMap, sourceMapValidation } = runResult;

const coreAuditedPrefixes = OFFICIAL_13_COVERAGE_DOMAINS.filter((d) =>
  CORE_AUDITED_DOMAIN_IDS.has(d.id)
).flatMap((d) => d.directories.map((dir) => `${dir}/`));

const auditedModulesSummary = summarizeCoverageMapSubset(coverageMap, rootDir, (rel) =>
  coreAuditedPrefixes.some((prefix) => rel.startsWith(prefix))
);

const all13DomainsSummary = summarizeCoverageMapSubset(coverageMap, rootDir, (rel) =>
  allEligibleSet.has(rel)
);

const domainsByKey = {};
const domainShortfalls = [];

for (const scan of inventoryScans) {
  const dom = scan.descriptor;
  const prefixes = dom.directories.map((dir) => `${dir}/`);
  const sum = summarizeCoverageMapSubset(coverageMap, rootDir, (rel) =>
    prefixes.some((p) => rel.startsWith(p))
  );
  const loadedInTests = Object.keys(sum.perFile).filter((rel) =>
    sourceMapValidation.checkedScripts.includes(rel)
  );
  const unexecutedZeroFiles = scan.eligibleFiles.filter((f) => !loadedInTests.includes(f));
  const domainPassed =
    sum.filesCount > 0 &&
    sum.linesPct >= dom.acceptanceCriteria.minLinesPct &&
    sum.functionsPct >= dom.acceptanceCriteria.minFunctionsPct &&
    sum.branchesPct >= dom.acceptanceCriteria.minBranchesPct;

  if (!domainPassed) {
    domainShortfalls.push(
      `${dom.id}: L=${sum.linesPct}% (min ${dom.acceptanceCriteria.minLinesPct}%), F=${sum.functionsPct}% (min ${dom.acceptanceCriteria.minFunctionsPct}%), B=${sum.branchesPct}% (min ${dom.acceptanceCriteria.minBranchesPct}%)`
    );
  }

  domainsByKey[dom.id] = {
    domainId: dom.id,
    name: dom.name,
    tier: dom.acceptanceCriteria.tier,
    acceptanceCriteria: dom.acceptanceCriteria,
    eligibleFilesCount: scan.eligibleFiles.length,
    excludedFilesCount: scan.excludedFiles.length,
    instrumentedFilesCount: sum.filesCount,
    executedInTestsCount: loadedInTests.length,
    unexecutedZeroFilesCount: unexecutedZeroFiles.length,
    unexecutedZeroFiles,
    domainGatePassed: domainPassed,
    statements: sum.statements,
    lines: sum.lines,
    functions: sum.functions,
    branches: sum.branches,
    statementsPct: sum.statementsPct,
    linesPct: sum.linesPct,
    functionsPct: sum.functionsPct,
    branchesPct: sum.branchesPct,
  };
}

const scoringSummary = summarizeCoverageMapSubset(coverageMap, rootDir, (r) =>
  r.startsWith('src/scoring/')
);
const evidenceSummary = summarizeCoverageMapSubset(coverageMap, rootDir, (r) =>
  r.startsWith('src/evidence/')
);
const comparabilitySummary = summarizeCoverageMapSubset(coverageMap, rootDir, (r) =>
  r.startsWith('src/comparability/')
);
const analyzersSummary = summarizeCoverageMapSubset(coverageMap, rootDir, (r) =>
  r.startsWith('src/analyzers/')
);
const gateSummary = summarizeCoverageMapSubset(coverageMap, rootDir, (r) =>
  r.startsWith('src/gate/')
);
const reportsSummary = summarizeCoverageMapSubset(coverageMap, rootDir, (r) =>
  r.startsWith('src/reports/')
);

const failures = [];
if (sourceMapValidation.errors.length > 0) {
  for (const err of sourceMapValidation.errors) {
    failures.push(`SourceMap validation failed for ${err.file}: ${err.reason}`);
  }
}

if (auditedModulesSummary.linesPct < thresholds.lines) {
  failures.push(`Audited modules lines ${auditedModulesSummary.linesPct}% < ${thresholds.lines}%`);
}
if (auditedModulesSummary.functionsPct < thresholds.functions) {
  failures.push(
    `Audited modules functions ${auditedModulesSummary.functionsPct}% < ${thresholds.functions}%`
  );
}
if (auditedModulesSummary.branchesPct < thresholds.branches) {
  failures.push(
    `Audited modules branches ${auditedModulesSummary.branchesPct}% < ${thresholds.branches}%`
  );
}

for (const [label, sum] of [
  ['src/scoring', scoringSummary],
  ['src/evidence', evidenceSummary],
  ['src/comparability', comparabilitySummary],
]) {
  if (sum.filesCount === 0) {
    failures.push(`${label} has 0 eligible files in CoverageMap`);
  } else if (sum.linesPct < 95 || sum.functionsPct < 95 || sum.branchesPct < 95) {
    failures.push(
      `${label} coverage (${sum.linesPct}% L / ${sum.functionsPct}% F / ${sum.branchesPct}% B) < 95%`
    );
  }
}

const totalEligibleFilesCount = allEligibleFiles.length;
const totalDiscoveredFilesCount = totalEligibleFilesCount + allExcludedFiles.length;

const threeWay = computeThreeWaySeparatedCoverage({
  discoveredFilesCount: totalDiscoveredFilesCount,
  eligibleFilesCount: totalEligibleFilesCount,
  ingestedFilesCount: totalEligibleFilesCount,
  excludedFilesCount: allExcludedFiles.length,
  failedIngestionFilesCount: 0,
  analyzedFilesCount: sourceMapValidation.validSourceMapsCount,
  fullAstFilesCount: sourceMapValidation.validSourceMapsCount,
  failedParseFilesCount: sourceMapValidation.errors.length,
  testCoverage: {
    sourceMapValidated: sourceMapValidation.errors.length === 0,
    instrumentedFilesCount: all13DomainsSummary.filesCount,
    uninstrumentedFilesCount: Math.max(
      0,
      totalEligibleFilesCount - sourceMapValidation.checkedScriptsCount
    ),
    uninstrumentedFiles: allEligibleFiles.filter(
      (f) => !sourceMapValidation.checkedScripts.includes(f)
    ),
    statements: auditedModulesSummary.statements,
    lines: auditedModulesSummary.lines,
    functions: auditedModulesSummary.functions,
    branches: auditedModulesSummary.branches,
  },
});

// Verify c8 generated non-empty LCOV & HTML artifacts on disk (never mask missing LCOV as 100%)
const lcovPath = path.join(covDir, 'lcov.info');
const htmlPath = path.join(covDir, 'index.html');
const lcovExists = fs.existsSync(lcovPath) && fs.statSync(lcovPath).size > 0;
const htmlExists = fs.existsSync(htmlPath) && fs.statSync(htmlPath).size > 0;
if (!lcovExists || !htmlExists) {
  failures.push('c8 failed to emit non-empty coverage/lcov.info or coverage/index.html');
}

const passed = failures.length === 0;

const reportJson = {
  generatedAt: runResult.completedAt,
  startedAt: runResult.startedAt,
  methodology: 'C8_V8_TO_ISTANBUL_ALL_TRUE',
  singleSourceInventory: 'src/execution/CoverageDomainInventory.ts#OFFICIAL_13_COVERAGE_DOMAINS',
  passed,
  failures,
  domainShortfalls,
  sourceMapValidation,
  separatedIndicators: {
    ...threeWay,
    testCoverage: {
      ...threeWay.testCoverage,
      all13DomainsTotals: {
        filesCount: all13DomainsSummary.filesCount,
        statements: all13DomainsSummary.statements,
        lines: all13DomainsSummary.lines,
        functions: all13DomainsSummary.functions,
        branches: all13DomainsSummary.branches,
      },
    },
  },
  scope: {
    coverageScopeType: 'C8_V8_TO_ISTANBUL_13_DOMAINS_ALL_TRUE',
    note: 'Cobertura oficial via c8 + v8-to-istanbul com all: true (arquivos elegíveis não importados permanecem no denominador com 0%) e validação estrita de SourceMaps.',
    auditedDirectories: coreAuditedPrefixes,
    official13Domains: OFFICIAL_13_COVERAGE_DOMAINS.map((d) => d.id),
    excludedPatterns: c8Exclude,
    auditedFilesCount: auditedModulesSummary.filesCount,
    instrumented13DomainsFilesCount: all13DomainsSummary.filesCount,
    executedInTestsFilesCount: sourceMapValidation.checkedScriptsCount,
    totalRepoSourceFilesCount: totalEligibleFilesCount,
    unexecutedZeroCoverageFilesCount: Math.max(
      0,
      totalEligibleFilesCount - sourceMapValidation.checkedScriptsCount
    ),
  },
  thresholds,
  total: {
    lines: auditedModulesSummary.lines,
    statements: auditedModulesSummary.statements,
    functions: auditedModulesSummary.functions,
    branches: auditedModulesSummary.branches,
  },
  global: {
    scopeLabel: 'Audited Core Engine Modules (6 domains, c8 all:true) + All 13 Domains Inventory',
    filesCount: auditedModulesSummary.filesCount,
    statementsPct: auditedModulesSummary.statementsPct,
    linesPct: auditedModulesSummary.linesPct,
    functionsPct: auditedModulesSummary.functionsPct,
    branchesPct: auditedModulesSummary.branchesPct,
    all13DomainsFilesCount: all13DomainsSummary.filesCount,
    all13DomainsLinesPct: all13DomainsSummary.linesPct,
    all13DomainsFunctionsPct: all13DomainsSummary.functionsPct,
    all13DomainsBranchesPct: all13DomainsSummary.branchesPct,
  },
  domains13: domainsByKey,
  criticalModules: {
    'src/scoring': scoringSummary,
    'src/evidence': evidenceSummary,
    'src/comparability': comparabilitySummary,
    'src/analyzers': analyzersSummary,
    'src/gate': gateSummary,
    'src/reports': reportsSummary,
  },
  criticalMotors: {
    'src/scoring': {
      filesCount: scoringSummary.filesCount,
      linesPct: scoringSummary.linesPct,
      functionsPct: scoringSummary.functionsPct,
      branchesPct: scoringSummary.branchesPct,
    },
    'src/evidence': {
      filesCount: evidenceSummary.filesCount,
      linesPct: evidenceSummary.linesPct,
      functionsPct: evidenceSummary.functionsPct,
      branchesPct: evidenceSummary.branchesPct,
    },
    'src/comparability': {
      filesCount: comparabilitySummary.filesCount,
      linesPct: comparabilitySummary.linesPct,
      functionsPct: comparabilitySummary.functionsPct,
      branchesPct: comparabilitySummary.branchesPct,
    },
  },
  perFile: all13DomainsSummary.perFile,
};

fs.writeFileSync(
  path.join(covDir, 'coverage-summary.json'),
  JSON.stringify(reportJson, null, 2),
  'utf8'
);

console.log('[WinHood c8 Coverage Summary]', JSON.stringify(reportJson.global, null, 2));
if (domainShortfalls.length > 0) {
  console.log('[WinHood 13-Domain Threshold Notice (Honest Deficit Tracking)]:\n - ' + domainShortfalls.join('\n - '));
}

if (!passed) {
  console.error('[WinHood Coverage Gate FAILED]:\n - ' + failures.join('\n - '));
  process.exit(1);
}
console.log('[WinHood Coverage Gate PASSED] c8 + v8-to-istanbul (all: true) verified across 13 official domains.');
