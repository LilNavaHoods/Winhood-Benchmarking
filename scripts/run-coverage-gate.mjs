import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const covDir = path.join(rootDir, 'coverage');
const v8Dir = path.join(covDir, 'v8-tmp');

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

console.log('[WinHood Coverage Gate] Running full test suite with V8 coverage...');
const res = spawnSync(
  process.execPath,
  ['--import', 'tsx', '--test', ...testFiles],
  {
    cwd: rootDir,
    env: { ...process.env, NODE_V8_COVERAGE: v8Dir },
    stdio: 'inherit',
  }
);

if (res.status !== 0) {
  console.error(`[WinHood Coverage Gate] Test suite failed with status ${res.status}`);
  process.exit(res.status || 1);
}

const v8Files = fs.readdirSync(v8Dir).filter((f) => f.endsWith('.json'));

/**
 * Map<relPath, Map<fnName, {
 *   functionName: string,
 *   length: number,
 *   called: boolean,
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
    if (
      !rel.startsWith('src/analyzers/') &&
      !rel.startsWith('src/scoring/') &&
      !rel.startsWith('src/evidence/') &&
      !rel.startsWith('src/comparability/') &&
      !rel.startsWith('src/gate/') &&
      !rel.startsWith('src/reports/')
    ) {
      continue;
    }
    if (rel.endsWith('.test.ts') || rel.endsWith('types.ts')) continue;

    const rawFns = script.functions || [];
    // Identify outer class ranges that contain inner methods so we skip synthetic class constructor wrappers
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
          length: fnLen,
          called: existing ? existing.called : false,
          byteCounts: new Uint32Array(fnLen),
          boundaries: new Set([0, fnLen]),
        };
        fileRecord.set(fnKey, existing);
      }

      if (topRange.count > 0) {
        existing.called = true;
      }

      // Evaluate V8 nested CoverageRange tree onto local [0, fnLen)
      // Sort ranges from largest to smallest so inner ranges override outer ranges for this process
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

function summarizeGroup(filterFn) {
  let fnTot = 0;
  let fnCov = 0;
  let bytesTot = 0;
  let bytesCov = 0;
  let blocksTot = 0;
  let blocksCov = 0;
  let filesCount = 0;
  const perFile = {};

  for (const [rel, fnMap] of mergedFiles.entries()) {
    if (!filterFn(rel)) continue;
    filesCount += 1;
    let fFnTot = 0;
    let fFnCov = 0;
    let fBytesTot = 0;
    let fBytesCov = 0;
    let fBlocksTot = 0;
    let fBlocksCov = 0;

    for (const fnEntry of fnMap.values()) {
      fnTot += 1;
      fFnTot += 1;
      if (fnEntry.called) {
        fnCov += 1;
        fFnCov += 1;
      }

      for (let i = 0; i < fnEntry.length; i++) {
        bytesTot += 1;
        fBytesTot += 1;
        if (fnEntry.byteCounts[i] > 0) {
          bytesCov += 1;
          fBytesCov += 1;
        }
      }

      const sortedBounds = Array.from(fnEntry.boundaries).sort((a, b) => a - b);
      for (let b = 0; b < sortedBounds.length - 1; b++) {
        const segStart = sortedBounds[b];
        const segEnd = sortedBounds[b + 1];
        if (segEnd - segStart < 4) continue;
        blocksTot += 1;
        fBlocksTot += 1;
        let segCovered = false;
        for (let k = segStart; k < segEnd; k++) {
          if (fnEntry.byteCounts[k] > 0) {
            segCovered = true;
            break;
          }
        }
        if (segCovered) {
          blocksCov += 1;
          fBlocksCov += 1;
        }
      }
    }

    perFile[rel] = {
      linesPct: fBytesTot > 0 ? Number(((fBytesCov / fBytesTot) * 100).toFixed(2)) : 100,
      functionsPct: fFnTot > 0 ? Number(((fFnCov / fFnTot) * 100).toFixed(2)) : 100,
      branchesPct: fBlocksTot > 0 ? Number(((fBlocksCov / fBlocksTot) * 100).toFixed(2)) : 100,
    };
  }

  const linesPct = bytesTot > 0 ? Number(((bytesCov / bytesTot) * 100).toFixed(2)) : 100;
  const functionsPct = fnTot > 0 ? Number(((fnCov / fnTot) * 100).toFixed(2)) : 100;
  const branchesPct = blocksTot > 0 ? Number(((blocksCov / blocksTot) * 100).toFixed(2)) : 100;
  return { filesCount, linesPct, functionsPct, branchesPct, perFile };
}

const globalSummary = summarizeGroup(() => true);
const scoringSummary = summarizeGroup((r) => r.startsWith('src/scoring/'));
const evidenceSummary = summarizeGroup((r) => r.startsWith('src/evidence/'));
const comparabilitySummary = summarizeGroup((r) => r.startsWith('src/comparability/'));

const reportJson = {
  generatedAt: new Date().toISOString(),
  thresholds,
  global: {
    filesCount: globalSummary.filesCount,
    linesPct: globalSummary.linesPct,
    functionsPct: globalSummary.functionsPct,
    branchesPct: globalSummary.branchesPct,
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
  perFile: globalSummary.perFile,
};

fs.writeFileSync(
  path.join(covDir, 'coverage-summary.json'),
  JSON.stringify(reportJson, null, 2),
  'utf8'
);

const htmlReport = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>WinHood V8 Coverage Report</title>
  <style>
    body { font-family: monospace; background: #0f172a; color: #f8fafc; padding: 24px; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; }
    th, td { border: 1px solid #334155; padding: 10px; text-align: left; }
    th { background: #1e293b; }
  </style>
</head>
<body>
  <h1>WinHood Test Coverage Report</h1>
  <table>
    <thead>
      <tr><th>Scope</th><th>Lines (%)</th><th>Functions (%)</th><th>Branches (%)</th><th>Threshold</th></tr>
    </thead>
    <tbody>
      <tr><td>Global</td><td>${globalSummary.linesPct}%</td><td>${globalSummary.functionsPct}%</td><td>${globalSummary.branchesPct}%</td><td>&ge; 80 / 80 / 75%</td></tr>
      <tr><td>src/scoring</td><td>${scoringSummary.linesPct}%</td><td>${scoringSummary.functionsPct}%</td><td>${scoringSummary.branchesPct}%</td><td>&ge; 95%</td></tr>
      <tr><td>src/evidence</td><td>${evidenceSummary.linesPct}%</td><td>${evidenceSummary.functionsPct}%</td><td>${evidenceSummary.branchesPct}%</td><td>&ge; 95%</td></tr>
      <tr><td>src/comparability</td><td>${comparabilitySummary.linesPct}%</td><td>${comparabilitySummary.functionsPct}%</td><td>${comparabilitySummary.branchesPct}%</td><td>&ge; 95%</td></tr>
    </tbody>
  </table>
</body>
</html>`;

fs.writeFileSync(path.join(covDir, 'index.html'), htmlReport, 'utf8');
fs.rmSync(v8Dir, { recursive: true, force: true });

console.log('[WinHood Coverage Summary]', JSON.stringify(reportJson, null, 2));

const failures = [];
if (globalSummary.linesPct < thresholds.lines) failures.push(`Global lines ${globalSummary.linesPct}% < ${thresholds.lines}%`);
if (globalSummary.functionsPct < thresholds.functions) failures.push(`Global functions ${globalSummary.functionsPct}% < ${thresholds.functions}%`);
if (globalSummary.branchesPct < thresholds.branches) failures.push(`Global branches ${globalSummary.branchesPct}% < ${thresholds.branches}%`);

for (const [label, sum] of [
  ['src/scoring', scoringSummary],
  ['src/evidence', evidenceSummary],
  ['src/comparability', comparabilitySummary],
]) {
  if (sum.linesPct < 95 || sum.functionsPct < 95 || sum.branchesPct < 95) {
    failures.push(`${label} coverage (${sum.linesPct}% / ${sum.functionsPct}% / ${sum.branchesPct}%) < 95%`);
  }
}

if (failures.length > 0) {
  console.error('[WinHood Coverage Gate FAILED]:\n - ' + failures.join('\n - '));
  process.exit(1);
}
console.log('[WinHood Coverage Gate PASSED] All global and critical motor thresholds satisfied.');
