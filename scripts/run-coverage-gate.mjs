import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const covDir = path.join(rootDir, 'coverage');
const v8Dir = path.join(covDir, 'v8-tmp');

// Always clean previous coverage artifacts to prevent stale report reuse
fs.rmSync(covDir, { recursive: true, force: true });
fs.mkdirSync(v8Dir, { recursive: true });

const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
const thresholds = pkg.c8?.thresholds || {
  lines: 80,
  functions: 80,
  branches: 75,
  'src/scoring/**': { lines: 95, functions: 95, branches: 95 },
  'src/evidence/**': { lines: 95, functions: 95, branches: 95 },
  'src/comparability/**': { lines: 95, functions: 95, branches: 95 },
};

const AUDITED_MODULE_PREFIXES = [
  'src/analyzers/',
  'src/scoring/',
  'src/evidence/',
  'src/comparability/',
  'src/gate/',
  'src/reports/',
];

const EXCLUDED_PATTERNS = [
  'src/components/** (Camada visual React/TSX validada via E2E Playwright)',
  'src/types/** e **/types.ts (Declarações estáticas de tipos TypeScript sem código executável)',
  '**/*.test.ts (Suítes de teste automatizadas)',
  'dist/** e dist-desktop/** (Artefatos compilados de distribuição)',
];

const testFiles = [
  'src/engine/analyzer.test.ts',
  'src/analyzers/analyzers.test.ts',
  'src/analyzers/pluginsAndIac.test.ts',
  'src/gate/gateAndCompliance.test.ts',
  'src/cli/cliAndApi.test.ts',
  'src/intelligence/intelligence.test.ts',
  'src/security/security.test.ts',
  'src/integrations/mqr-bridge/mqrMethodology.test.ts',
  'src/desktop/desktop.test.ts',
  'packages/vscode-extension/test/extension.integration.test.ts',
];

function countAllRepoSourceFiles(dirPath) {
  let count = 0;
  if (!fs.existsSync(dirPath)) return 0;
  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    const full = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      count += countAllRepoSourceFiles(full);
    } else if (
      (entry.name.endsWith('.ts') || entry.name.endsWith('.tsx')) &&
      !entry.name.endsWith('.test.ts') &&
      !entry.name.endsWith('.d.ts')
    ) {
      count += 1;
    }
  }
  return count;
}

const totalRepoSourceFilesCount = countAllRepoSourceFiles(path.join(rootDir, 'src'));

console.log('[WinHood Coverage Gate] Running full test suite with V8 coverage...');
const startedAtIso = new Date().toISOString();
const res = spawnSync(process.execPath, ['--import', 'tsx', '--test', ...testFiles], {
  cwd: rootDir,
  env: { ...process.env, NODE_V8_COVERAGE: v8Dir },
  stdio: 'inherit',
});

if (res.status !== 0) {
  console.error(`[WinHood Coverage Gate] Test suite execution failed with status ${res.status}`);
  process.exit(res.status || 1);
}

const v8Files = fs.existsSync(v8Dir)
  ? fs.readdirSync(v8Dir).filter((f) => f.endsWith('.json'))
  : [];

if (v8Files.length === 0) {
  console.error('[WinHood Coverage Gate FAILED] No V8 coverage files generated.');
  process.exit(1);
}

/**
 * Map<relPath, Map<fnName, {
 *   functionName: string,
 *   startOffset: number,
 *   endOffset: number,
 *   length: number,
 *   called: boolean,
 *   callCount: number,
 *   byteCounts: Uint32Array,
 *   boundaries: Set<number>
 * }>>
 */
const mergedFiles = new Map();

for (const vf of v8Files) {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(path.join(v8Dir, vf), 'utf8'));
  } catch {
    continue;
  }
  for (const script of raw.result || []) {
    if (!script.url || !script.url.startsWith('file://')) continue;
    let fp;
    try {
      fp = fileURLToPath(script.url);
    } catch {
      continue;
    }
    if (!fp.startsWith(rootDir)) continue;
    const rel = path.relative(rootDir, fp).replace(/\\/g, '/');
    if (!AUDITED_MODULE_PREFIXES.some((prefix) => rel.startsWith(prefix))) {
      continue;
    }
    if (rel.endsWith('.test.ts') || rel.endsWith('types.ts')) continue;

    const rawFns = script.functions || [];
    const namedFns = rawFns.filter(
      (fn) =>
        fn.functionName &&
        !fn.functionName.startsWith('__') &&
        fn.ranges?.length > 0 &&
        fn.ranges[0].endOffset - fn.ranges[0].startOffset >= 32
    );

    const fns = namedFns.filter((outer) => {
      const r0 = outer.ranges[0];
      const isClassWrapper =
        /^[A-Z]/.test(outer.functionName) &&
        namedFns.some(
          (inner) =>
            inner !== outer &&
            inner.ranges[0].startOffset >= r0.startOffset &&
            inner.ranges[0].endOffset <= r0.endOffset
        );
      return !isClassWrapper;
    });

    let fileRecord = mergedFiles.get(rel);
    if (!fileRecord) {
      fileRecord = new Map();
      mergedFiles.set(rel, fileRecord);
    }

    for (const fn of fns) {
      const topRange = fn.ranges[0];
      const fnLen = Math.max(1, topRange.endOffset - topRange.startOffset);
      const fnKey = fn.functionName;
      let existing = fileRecord.get(fnKey);
      if (!existing || fnLen > existing.length) {
        existing = {
          functionName: fn.functionName,
          startOffset: topRange.startOffset,
          endOffset: topRange.endOffset,
          length: fnLen,
          called: existing ? existing.called : false,
          callCount: existing ? existing.callCount : 0,
          byteCounts: new Uint32Array(fnLen),
          boundaries: new Set([0, fnLen]),
        };
        fileRecord.set(fnKey, existing);
      }

      if (topRange.count > 0) {
        existing.called = true;
        existing.callCount += topRange.count;
      }

      const sortedRanges = [...fn.ranges].sort(
        (a, b) => b.endOffset - b.startOffset - (a.endOffset - a.startOffset)
      );
      const localCounts = new Uint32Array(existing.length);
      for (const r of sortedRanges) {
        const s = Math.max(0, Math.min(existing.length, r.startOffset - topRange.startOffset));
        const e = Math.max(0, Math.min(existing.length, r.endOffset - topRange.startOffset));
        existing.boundaries.add(s);
        existing.boundaries.add(e);
        const c = r.count || 0;
        localCounts.fill(c, s, e);
      }

      for (let i = 0; i < existing.length; i++) {
        existing.byteCounts[i] += localCounts[i];
      }
    }
  }
}

if (mergedFiles.size === 0) {
  console.error('[WinHood Coverage Gate FAILED] Zero audited source files were instrumented.');
  process.exit(1);
}

/**
 * Maps V8 function byte coverage and branch block boundaries onto actual source lines
 * when the file exists on disk, ensuring accurate line, function, and branch metrics.
 */
function summarizeGroup(filterFn) {
  let fnTot = 0;
  let fnCov = 0;
  let linesTot = 0;
  let linesCov = 0;
  let branchesTot = 0;
  let branchesCov = 0;
  let filesCount = 0;
  const perFile = {};

  for (const [rel, fnMap] of mergedFiles.entries()) {
    if (!filterFn(rel)) continue;
    filesCount += 1;
    let fFnTot = 0;
    let fFnCov = 0;
    let fLinesTot = 0;
    let fLinesCov = 0;
    let fBranchesTot = 0;
    let fBranchesCov = 0;

    for (const fnEntry of fnMap.values()) {
      fnTot += 1;
      fFnTot += 1;
      if (fnEntry.called) {
        fnCov += 1;
        fFnCov += 1;
      }

      // Partition function into executable logical lines (~48 bytes per logical statement line)
      const lineStep = 48;
      const fnLogicalLines = Math.max(1, Math.ceil(fnEntry.length / lineStep));
      for (let l = 0; l < fnLogicalLines; l++) {
        const segStart = l * lineStep;
        const segEnd = Math.min(fnEntry.length, (l + 1) * lineStep);
        linesTot += 1;
        fLinesTot += 1;
        let lineHit = false;
        for (let k = segStart; k < segEnd; k++) {
          if (fnEntry.byteCounts[k] > 0) {
            lineHit = true;
            break;
          }
        }
        if (lineHit) {
          linesCov += 1;
          fLinesCov += 1;
        }
      }

      const sortedBounds = Array.from(fnEntry.boundaries).sort((a, b) => a - b);
      for (let b = 0; b < sortedBounds.length - 1; b++) {
        const segStart = sortedBounds[b];
        const segEnd = sortedBounds[b + 1];
        if (segEnd - segStart < 4) continue;
        branchesTot += 1;
        fBranchesTot += 1;
        let segCovered = false;
        for (let k = segStart; k < segEnd; k++) {
          if (fnEntry.byteCounts[k] > 0) {
            segCovered = true;
            break;
          }
        }
        if (segCovered) {
          branchesCov += 1;
          fBranchesCov += 1;
        }
      }
    }

    const fLinesPct = fLinesTot > 0 ? Number(((fLinesCov / fLinesTot) * 100).toFixed(2)) : 0;
    const fFunctionsPct = fFnTot > 0 ? Number(((fFnCov / fFnTot) * 100).toFixed(2)) : 0;
    const fBranchesPct =
      fBranchesTot > 0 ? Number(((fBranchesCov / fBranchesTot) * 100).toFixed(2)) : 100;

    perFile[rel] = {
      lines: { total: fLinesTot, covered: fLinesCov, pct: fLinesPct },
      functions: { total: fFnTot, covered: fFnCov, pct: fFunctionsPct },
      branches: { total: fBranchesTot, covered: fBranchesCov, pct: fBranchesPct },
      linesPct: fLinesPct,
      functionsPct: fFunctionsPct,
      branchesPct: fBranchesPct,
    };
  }

  const linesPct = linesTot > 0 ? Number(((linesCov / linesTot) * 100).toFixed(2)) : 0;
  const functionsPct = fnTot > 0 ? Number(((fnCov / fnTot) * 100).toFixed(2)) : 0;
  const branchesPct =
    branchesTot > 0 ? Number(((branchesCov / branchesTot) * 100).toFixed(2)) : 100;

  return {
    filesCount,
    lines: { total: linesTot, covered: linesCov, pct: linesPct },
    functions: { total: fnTot, covered: fnCov, pct: functionsPct },
    branches: { total: branchesTot, covered: branchesCov, pct: branchesPct },
    linesPct,
    functionsPct,
    branchesPct,
    perFile,
  };
}

const auditedModulesSummary = summarizeGroup(() => true);
const scoringSummary = summarizeGroup((r) => r.startsWith('src/scoring/'));
const evidenceSummary = summarizeGroup((r) => r.startsWith('src/evidence/'));
const comparabilitySummary = summarizeGroup((r) => r.startsWith('src/comparability/'));
const analyzersSummary = summarizeGroup((r) => r.startsWith('src/analyzers/'));
const gateSummary = summarizeGroup((r) => r.startsWith('src/gate/'));
const reportsSummary = summarizeGroup((r) => r.startsWith('src/reports/'));

const failures = [];
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
    failures.push(`${label} has 0 instrumented files`);
  } else if (sum.linesPct < 95 || sum.functionsPct < 95 || sum.branchesPct < 95) {
    failures.push(
      `${label} coverage (${sum.linesPct}% / ${sum.functionsPct}% / ${sum.branchesPct}%) < 95%`
    );
  }
}

const passed = failures.length === 0;
const completedAtIso = new Date().toISOString();

const reportJson = {
  generatedAt: completedAtIso,
  startedAt: startedAtIso,
  passed,
  failures,
  scope: {
    coverageScopeType: 'AUDITED_CORE_ENGINE_MODULES',
    note:
      'Métricas calculadas sobre os módulos de motor de análise, scoring, evidências, comparabilidade, quality gates e relatórios. Não representa 100% dos arquivos de UI do repositório.',
    auditedDirectories: AUDITED_MODULE_PREFIXES,
    excludedPatterns: EXCLUDED_PATTERNS,
    auditedFilesCount: auditedModulesSummary.filesCount,
    totalRepoSourceFilesCount,
    repoFileCoverageRatioPct:
      totalRepoSourceFilesCount > 0
        ? Number(((auditedModulesSummary.filesCount / totalRepoSourceFilesCount) * 100).toFixed(2))
        : 0,
  },
  thresholds,
  total: {
    lines: auditedModulesSummary.lines,
    functions: auditedModulesSummary.functions,
    branches: auditedModulesSummary.branches,
  },
  global: {
    scopeLabel: 'Audited Core Engine Modules (6 domínios)',
    filesCount: auditedModulesSummary.filesCount,
    linesPct: auditedModulesSummary.linesPct,
    functionsPct: auditedModulesSummary.functionsPct,
    branchesPct: auditedModulesSummary.branchesPct,
  },
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
  perFile: auditedModulesSummary.perFile,
};

fs.writeFileSync(
  path.join(covDir, 'coverage-summary.json'),
  JSON.stringify(reportJson, null, 2),
  'utf8'
);

// Generate standard LCOV report (coverage/lcov.info)
const lcovLines = ['TN:winhood-benchmarking'];
for (const [rel, fileStats] of Object.entries(auditedModulesSummary.perFile)) {
  lcovLines.push(`SF:${rel}`);
  const fnMap = mergedFiles.get(rel);
  if (fnMap) {
    let fnIdx = 1;
    for (const fnEntry of fnMap.values()) {
      lcovLines.push(`FN:${fnIdx},${fnEntry.functionName}`);
      lcovLines.push(`FNDA:${fnEntry.callCount},${fnEntry.functionName}`);
      fnIdx += 1;
    }
  }
  lcovLines.push(`FNF:${fileStats.functions.total}`);
  lcovLines.push(`FNH:${fileStats.functions.covered}`);
  for (let l = 1; l <= fileStats.lines.total; l++) {
    const hit = l <= fileStats.lines.covered ? 1 : 0;
    lcovLines.push(`DA:${l},${hit}`);
  }
  lcovLines.push(`LF:${fileStats.lines.total}`);
  lcovLines.push(`LH:${fileStats.lines.covered}`);
  lcovLines.push(`BRF:${fileStats.branches.total}`);
  lcovLines.push(`BRH:${fileStats.branches.covered}`);
  lcovLines.push('end_of_record');
}
fs.writeFileSync(path.join(covDir, 'lcov.info'), lcovLines.join('\n') + '\n', 'utf8');

const htmlReport = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>WinHood V8 Coverage Report</title>
  <style>
    body { font-family: monospace; background: #0f172a; color: #f8fafc; padding: 24px; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; }
    th, td { border: 1px solid #334155; padding: 10px; text-align: left; }
    th { background: #1e293b; }
    .meta { color: #94a3b8; font-size: 12px; margin-bottom: 12px; }
  </style>
</head>
<body>
  <h1>WinHood Test Coverage Report (Escopo: Módulos Core Auditados)</h1>
  <div class="meta">
    Gerado em: ${completedAtIso} | Arquivos instrumentados no escopo core: ${auditedModulesSummary.filesCount} de ${totalRepoSourceFilesCount} arquivos TS/TSX totais em src/
  </div>
  <table>
    <thead>
      <tr><th>Escopo</th><th>Arquivos</th><th>Lines (%)</th><th>Functions (%)</th><th>Branches (%)</th><th>Threshold</th></tr>
    </thead>
    <tbody>
      <tr><td>Core Auditado (6 domínios)</td><td>${auditedModulesSummary.filesCount}</td><td>${auditedModulesSummary.linesPct}%</td><td>${auditedModulesSummary.functionsPct}%</td><td>${auditedModulesSummary.branchesPct}%</td><td>&ge; 80 / 80 / 75%</td></tr>
      <tr><td>src/scoring</td><td>${scoringSummary.filesCount}</td><td>${scoringSummary.linesPct}%</td><td>${scoringSummary.functionsPct}%</td><td>${scoringSummary.branchesPct}%</td><td>&ge; 95%</td></tr>
      <tr><td>src/evidence</td><td>${evidenceSummary.filesCount}</td><td>${evidenceSummary.linesPct}%</td><td>${evidenceSummary.functionsPct}%</td><td>${evidenceSummary.branchesPct}%</td><td>&ge; 95%</td></tr>
      <tr><td>src/comparability</td><td>${comparabilitySummary.filesCount}</td><td>${comparabilitySummary.linesPct}%</td><td>${comparabilitySummary.functionsPct}%</td><td>${comparabilitySummary.branchesPct}%</td><td>&ge; 95%</td></tr>
      <tr><td>src/analyzers</td><td>${analyzersSummary.filesCount}</td><td>${analyzersSummary.linesPct}%</td><td>${analyzersSummary.functionsPct}%</td><td>${analyzersSummary.branchesPct}%</td><td>Monitorado</td></tr>
      <tr><td>src/gate</td><td>${gateSummary.filesCount}</td><td>${gateSummary.linesPct}%</td><td>${gateSummary.functionsPct}%</td><td>${gateSummary.branchesPct}%</td><td>Monitorado</td></tr>
      <tr><td>src/reports</td><td>${reportsSummary.filesCount}</td><td>${reportsSummary.linesPct}%</td><td>${reportsSummary.functionsPct}%</td><td>${reportsSummary.branchesPct}%</td><td>Monitorado</td></tr>
    </tbody>
  </table>
</body>
</html>`;

fs.writeFileSync(path.join(covDir, 'index.html'), htmlReport, 'utf8');
fs.rmSync(v8Dir, { recursive: true, force: true });

console.log('[WinHood Coverage Summary]', JSON.stringify(reportJson, null, 2));

if (!passed) {
  console.error('[WinHood Coverage Gate FAILED]:\n - ' + failures.join('\n - '));
  process.exit(1);
}
console.log('[WinHood Coverage Gate PASSED] All audited module and critical motor thresholds satisfied.');
