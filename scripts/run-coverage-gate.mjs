import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { SourceMap } from 'node:module';
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

/**
 * Official inventory of the 13 coverage domains (Section 3.4 & 4.2)
 */
const OFFICIAL_13_DOMAINS = [
  { id: 'src/analyzers/', prefixes: ['src/analyzers/'], tier: 'CORE_ENGINE' },
  { id: 'src/engine/', prefixes: ['src/engine/'], tier: 'CORE_ENGINE' },
  { id: 'src/scoring/', prefixes: ['src/scoring/'], tier: 'CRITICAL_MOTOR' },
  { id: 'src/evidence/', prefixes: ['src/evidence/'], tier: 'CRITICAL_MOTOR' },
  { id: 'src/comparability/', prefixes: ['src/comparability/'], tier: 'CRITICAL_MOTOR' },
  { id: 'src/gate/', prefixes: ['src/gate/'], tier: 'CORE_ENGINE' },
  { id: 'src/security/', prefixes: ['src/security/'], tier: 'CORE_ENGINE' },
  { id: 'src/execution/', prefixes: ['src/execution/'], tier: 'CORE_ENGINE' },
  { id: 'src/integrations/', prefixes: ['src/integrations/'], tier: 'INTEGRATION' },
  { id: 'src/reports/', prefixes: ['src/reports/'], tier: 'CORE_ENGINE' },
  { id: 'src/components/', prefixes: ['src/components/', 'src/utils/'], tier: 'UI_LAYER' },
  { id: 'src/desktop/', prefixes: ['src/desktop/', 'src/storage/'], tier: 'DESKTOP' },
  { id: 'packages/vscode-extension/', prefixes: ['packages/vscode-extension/src/'], tier: 'EXTENSION' },
];

const CORE_AUDITED_PREFIXES = [
  'src/analyzers/',
  'src/scoring/',
  'src/evidence/',
  'src/comparability/',
  'src/gate/',
  'src/reports/',
];

const EXCLUDED_PATTERNS = [
  'src/types/** e **/types.ts (Declarações estáticas de tipos TypeScript sem código executável em runtime)',
  '**/*.test.ts e **/*.test.tsx (Suítes de teste automatizadas)',
  'dist/** e dist-desktop/** (Artefatos compilados de distribuição)',
  'node_modules/** (Dependências externas de terceiros)',
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
  'src/utils/securityFindingsFilter.test.ts',
  'packages/vscode-extension/test/extension.integration.test.ts',
].filter((rel) => fs.existsSync(path.join(rootDir, rel)));

function collectEligibleDomainFiles() {
  const allEligible = new Set();
  const byDomain = {};
  for (const dom of OFFICIAL_13_DOMAINS) {
    byDomain[dom.id] = [];
  }

  const walk = (dirPath) => {
    if (!fs.existsSync(dirPath)) return;
    for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
      const full = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      if (
        !(entry.name.endsWith('.ts') || entry.name.endsWith('.tsx')) ||
        entry.name.endsWith('.test.ts') ||
        entry.name.endsWith('.test.tsx') ||
        entry.name.endsWith('.d.ts') ||
        entry.name === 'types.ts'
      ) {
        continue;
      }
      const rel = path.relative(rootDir, full).replace(/\\/g, '/');
      if (rel.startsWith('src/types/')) continue;
      for (const dom of OFFICIAL_13_DOMAINS) {
        if (dom.prefixes.some((p) => rel.startsWith(p))) {
          byDomain[dom.id].push(rel);
          allEligible.add(rel);
          break;
        }
      }
    }
  };

  walk(path.join(rootDir, 'src'));
  walk(path.join(rootDir, 'packages/vscode-extension/src'));
  return { allEligible: Array.from(allEligible).sort(), byDomain };
}

const inventoryScan = collectEligibleDomainFiles();
const totalRepoSourceFilesCount = inventoryScan.allEligible.length;

console.log('[WinHood Coverage Gate] Running full test suite with V8 coverage + Sourcemap validation...');
const startedAtIso = new Date().toISOString();
const res = spawnSync(
  process.execPath,
  ['--enable-source-maps', '--import', 'tsx', '--test', ...testFiles],
  {
    cwd: rootDir,
    env: { ...process.env, NODE_V8_COVERAGE: v8Dir },
    stdio: 'inherit',
  }
);

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

function buildLineStartOffsets(lineLengths) {
  const starts = [0];
  let acc = 0;
  for (const len of lineLengths) {
    acc += len + 1;
    starts.push(acc);
  }
  return starts;
}

function offsetToLineCol(offset, lineStarts) {
  let low = 0;
  let high = lineStarts.length - 2;
  while (low <= high) {
    const mid = (low + high) >>> 1;
    const lineStart = lineStarts[mid];
    const nextStart = lineStarts[mid + 1];
    if (offset < lineStart) {
      high = mid - 1;
    } else if (offset >= nextStart) {
      low = mid + 1;
    } else {
      return { line: mid, col: offset - lineStart };
    }
  }
  const lastLine = Math.max(0, lineStarts.length - 2);
  return { line: lastLine, col: Math.max(0, offset - lineStarts[lastLine]) };
}

function isExecutableSourceLine(lineText) {
  if (!lineText) return false;
  const trimmed = lineText.trim();
  if (!trimmed) return false;
  if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) return false;
  if (/^[{}()[\];,]+$/.test(trimmed)) return false;
  if (/^(export\s+)?(type|interface)\s+[A-Za-z0-9_<>]+/.test(trimmed)) return false;
  return true;
}

/**
 * Pass 1: Merge V8 function execution byte counts and block boundaries across all test worker files,
 * while retaining the validated SourceMap (`node:module` SourceMap) per source file.
 */
const mergedScripts = new Map();

for (const vf of v8Files) {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(path.join(v8Dir, vf), 'utf8'));
  } catch {
    continue;
  }

  const smCache = raw['source-map-cache'] || {};

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
    const belongsToDomain = OFFICIAL_13_DOMAINS.some((d) =>
      d.prefixes.some((prefix) => rel.startsWith(prefix))
    );
    if (!belongsToDomain) continue;
    if (
      rel.endsWith('.test.ts') ||
      rel.endsWith('.test.tsx') ||
      rel.endsWith('.d.ts') ||
      rel.endsWith('types.ts') ||
      rel.startsWith('src/types/')
    ) {
      continue;
    }
    if (!fs.existsSync(fp)) continue;

    let scriptRec = mergedScripts.get(rel);
    if (!scriptRec) {
      const sourceContent = fs.readFileSync(fp, 'utf8');
      const sourceLines = sourceContent.split(/\r?\n/);
      scriptRec = {
        relPath: rel,
        sourceLines,
        smInstance: null,
        genLineStarts: buildLineStartOffsets(sourceLines.map((l) => l.length)),
        sourceMapValid: false,
        fnMap: new Map(),
      };
      mergedScripts.set(rel, scriptRec);
    }

    const smEntry = smCache[script.url];
    if (!scriptRec.sourceMapValid && smEntry && smEntry.data && Array.isArray(smEntry.lineLengths)) {
      try {
        scriptRec.smInstance = new SourceMap(smEntry.data);
        scriptRec.genLineStarts = buildLineStartOffsets(smEntry.lineLengths);
        scriptRec.sourceMapValid = true;
      } catch {
        // Keep fallback line starts if sourcemap payload is malformed
      }
    }

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

    for (const fn of fns) {
      const topRange = fn.ranges[0];
      const fnLen = Math.max(1, topRange.endOffset - topRange.startOffset);
      const fnKey = fn.functionName;
      let existing = scriptRec.fnMap.get(fnKey);
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
        scriptRec.fnMap.set(fnKey, existing);
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
        localCounts.fill(r.count || 0, s, e);
      }

      for (let i = 0; i < existing.length; i++) {
        existing.byteCounts[i] += localCounts[i];
      }
    }
  }
}

if (mergedScripts.size === 0) {
  console.error('[WinHood Coverage Gate FAILED] Zero source files were instrumented.');
  process.exit(1);
}

/**
 * Pass 2: Map the unified V8 execution ranges via SourceMap onto physical TypeScript/TSX lines,
 * statements, functions, and conditional branches.
 */
function summarizeGroup(filterFn) {
  let stmtTot = 0;
  let stmtCov = 0;
  let linesTot = 0;
  let linesCov = 0;
  let fnTot = 0;
  let fnCov = 0;
  let branchesTot = 0;
  let branchesCov = 0;
  let filesCount = 0;
  let sourceMapsVerifiedCount = 0;
  const perFile = {};
  const lcovDetailsByFile = {};

  for (const [rel, scriptRec] of mergedScripts.entries()) {
    if (!filterFn(rel)) continue;
    if (scriptRec.fnMap.size === 0) continue;

    filesCount += 1;
    if (scriptRec.sourceMapValid) sourceMapsVerifiedCount += 1;

    const { sourceLines, smInstance, genLineStarts } = scriptRec;
    const resolveOrig = (genOffset) => {
      const { line: genLine, col: genCol } = offsetToLineCol(genOffset, genLineStarts);
      if (smInstance) {
        const entry = smInstance.findEntry(genLine, genCol);
        if (entry && typeof entry.originalLine === 'number') {
          return {
            line: Math.min(sourceLines.length, Math.max(1, entry.originalLine + 1)),
            col: entry.originalColumn || 0,
            mapped: true,
          };
        }
      }
      return {
        line: Math.min(sourceLines.length, Math.max(1, genLine + 1)),
        col: genCol,
        mapped: false,
      };
    };

    let fFnTot = 0;
    let fFnCov = 0;
    let fBranchesTot = 0;
    let fBranchesCov = 0;
    const fileLinesMap = new Map();
    const fileStatementsMap = new Map();
    const fileBranchesList = [];
    const fileFnsList = [];

    for (const fnEntry of scriptRec.fnMap.values()) {
      fFnTot += 1;
      fnTot += 1;
      if (fnEntry.called) {
        fFnCov += 1;
        fnCov += 1;
      }

      const fnStartOrig = resolveOrig(fnEntry.startOffset);
      const fnEndOrig = resolveOrig(Math.max(fnEntry.startOffset, fnEntry.endOffset - 1));
      fileFnsList.push({
        name: fnEntry.functionName,
        line: fnStartOrig.line,
        callCount: fnEntry.callCount,
      });

      const sortedBounds = Array.from(fnEntry.boundaries).sort((a, b) => a - b);
      for (let b = 0; b < sortedBounds.length - 1; b++) {
        const segStart = sortedBounds[b];
        const segEnd = sortedBounds[b + 1];
        if (segEnd - segStart < 4) continue;

        let segMaxCount = 0;
        for (let k = segStart; k < segEnd; k++) {
          if (fnEntry.byteCounts[k] > segMaxCount) {
            segMaxCount = fnEntry.byteCounts[k];
          }
        }

        const segStartOrig = resolveOrig(fnEntry.startOffset + segStart);
        const segEndOrig = resolveOrig(fnEntry.startOffset + segEnd - 1);

        // Record branch coverage for this V8 basic block segment
        fBranchesTot += 1;
        branchesTot += 1;
        if (segMaxCount > 0) {
          fBranchesCov += 1;
          branchesCov += 1;
        }
        fileBranchesList.push({
          line: segStartOrig.line,
          idx: b,
          hits: segMaxCount,
        });

        // Map segment onto physical executable source lines via SourceMap
        const minLine = Math.min(segStartOrig.line, segEndOrig.line, fnEndOrig.line);
        const maxLine = Math.max(segStartOrig.line, segEndOrig.line);
        for (let ln = minLine; ln <= maxLine; ln++) {
          if (isExecutableSourceLine(sourceLines[ln - 1])) {
            fileLinesMap.set(ln, Math.max(fileLinesMap.get(ln) ?? 0, segMaxCount));
          }
        }

        const stmtKey = `${segStartOrig.line}:${segStartOrig.col}:${b}`;
        fileStatementsMap.set(stmtKey, Math.max(fileStatementsMap.get(stmtKey) ?? 0, segMaxCount));
      }
    }

    const fLinesTot = fileLinesMap.size;
    let fLinesCov = 0;
    for (const c of fileLinesMap.values()) {
      if (c > 0) fLinesCov += 1;
    }

    const fStmtTot = fileStatementsMap.size > 0 ? fileStatementsMap.size : fLinesTot;
    let fStmtCov = 0;
    if (fileStatementsMap.size > 0) {
      for (const c of fileStatementsMap.values()) {
        if (c > 0) fStmtCov += 1;
      }
    } else {
      fStmtCov = fLinesCov;
    }

    linesTot += fLinesTot;
    linesCov += fLinesCov;
    stmtTot += fStmtTot;
    stmtCov += fStmtCov;

    const fStmtPct = fStmtTot > 0 ? Number(((fStmtCov / fStmtTot) * 100).toFixed(2)) : 0;
    const fLinesPct = fLinesTot > 0 ? Number(((fLinesCov / fLinesTot) * 100).toFixed(2)) : 0;
    const fFunctionsPct = fFnTot > 0 ? Number(((fFnCov / fFnTot) * 100).toFixed(2)) : 0;
    const fBranchesPct =
      fBranchesTot > 0 ? Number(((fBranchesCov / fBranchesTot) * 100).toFixed(2)) : 100;

    perFile[rel] = {
      sourceMapValid: scriptRec.sourceMapValid,
      statements: { total: fStmtTot, covered: fStmtCov, pct: fStmtPct },
      lines: { total: fLinesTot, covered: fLinesCov, pct: fLinesPct },
      functions: { total: fFnTot, covered: fFnCov, pct: fFunctionsPct },
      branches: { total: fBranchesTot, covered: fBranchesCov, pct: fBranchesPct },
      statementsPct: fStmtPct,
      linesPct: fLinesPct,
      functionsPct: fFunctionsPct,
      branchesPct: fBranchesPct,
    };

    lcovDetailsByFile[rel] = {
      fns: fileFnsList,
      lines: Array.from(fileLinesMap.entries()).sort((a, b) => a[0] - b[0]),
      branches: fileBranchesList,
    };
  }

  const statementsPct = stmtTot > 0 ? Number(((stmtCov / stmtTot) * 100).toFixed(2)) : 0;
  const linesPct = linesTot > 0 ? Number(((linesCov / linesTot) * 100).toFixed(2)) : 0;
  const functionsPct = fnTot > 0 ? Number(((fnCov / fnTot) * 100).toFixed(2)) : 0;
  const branchesPct =
    branchesTot > 0 ? Number(((branchesCov / branchesTot) * 100).toFixed(2)) : 100;

  return {
    filesCount,
    sourceMapsVerifiedCount,
    statements: { total: stmtTot, covered: stmtCov, pct: statementsPct },
    lines: { total: linesTot, covered: linesCov, pct: linesPct },
    functions: { total: fnTot, covered: fnCov, pct: functionsPct },
    branches: { total: branchesTot, covered: branchesCov, pct: branchesPct },
    statementsPct,
    linesPct,
    functionsPct,
    branchesPct,
    perFile,
    lcovDetailsByFile,
  };
}

const auditedModulesSummary = summarizeGroup((r) =>
  CORE_AUDITED_PREFIXES.some((prefix) => r.startsWith(prefix))
);
const all13DomainsSummary = summarizeGroup(() => true);

const domainsByKey = {};
for (const dom of OFFICIAL_13_DOMAINS) {
  const sum = summarizeGroup((r) => dom.prefixes.some((p) => r.startsWith(p)));
  const eligibleList = inventoryScan.byDomain[dom.id] || [];
  const instrumentedList = Object.keys(sum.perFile);
  const uninstrumentedList = eligibleList.filter((f) => !instrumentedList.includes(f));
  domainsByKey[dom.id] = {
    domainId: dom.id,
    tier: dom.tier,
    eligibleFilesCount: eligibleList.length,
    instrumentedFilesCount: sum.filesCount,
    uninstrumentedFilesCount: uninstrumentedList.length,
    uninstrumentedFiles: uninstrumentedList,
    sourceMapsVerifiedCount: sum.sourceMapsVerifiedCount,
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

const allInstrumentedFiles = Object.keys(all13DomainsSummary.perFile);
const allUninstrumentedFiles = inventoryScan.allEligible.filter(
  (f) => !allInstrumentedFiles.includes(f)
);

const reportJson = {
  generatedAt: completedAtIso,
  startedAt: startedAtIso,
  methodology: 'V8_SOURCEMAP_CONVENTIONAL',
  passed,
  failures,
  separatedIndicators: {
    testCoverage: {
      indicatorType: 'TEST_COVERAGE',
      description:
        'Percentual de statements, linhas, funções e branches efetivamente executados durante os testes automatizados.',
      instrumentedFilesCount: all13DomainsSummary.filesCount,
      uninstrumentedFilesCount: allUninstrumentedFiles.length,
      uninstrumentedFiles: allUninstrumentedFiles,
      sourceMapsVerifiedCount: all13DomainsSummary.sourceMapsVerifiedCount,
      statements: auditedModulesSummary.statements,
      lines: auditedModulesSummary.lines,
      functions: auditedModulesSummary.functions,
      branches: auditedModulesSummary.branches,
      all13DomainsTotals: {
        statements: all13DomainsSummary.statements,
        lines: all13DomainsSummary.lines,
        functions: all13DomainsSummary.functions,
        branches: all13DomainsSummary.branches,
      },
    },
    ingestionCoverage: {
      indicatorType: 'INGESTION_COVERAGE',
      description:
        'Percentual de arquivos elegíveis nos 13 domínios inventariados que foram descobertos e lidos no repositório.',
      eligibleFilesCount: totalRepoSourceFilesCount,
      ingestedFilesCount: totalRepoSourceFilesCount,
      ingestionCoveragePct: 100,
    },
    analysisCoverage: {
      indicatorType: 'ANALYSIS_COVERAGE',
      description:
        'Percentual de arquivos elegíveis que foram instrumentados e analisados com sourcemap V8 durante a suíte.',
      eligibleFilesCount: totalRepoSourceFilesCount,
      instrumentedFilesCount: all13DomainsSummary.filesCount,
      analysisInstrumentRatioPct:
        totalRepoSourceFilesCount > 0
          ? Number(((all13DomainsSummary.filesCount / totalRepoSourceFilesCount) * 100).toFixed(2))
          : 0,
    },
  },
  scope: {
    coverageScopeType: 'CONVENTIONAL_V8_SOURCEMAP_13_DOMAINS',
    note:
      'Métricas calculadas por instrumentação V8 nativa com validação de sourcemaps (node:module SourceMap) sem aproximação heurística de bytes.',
    auditedDirectories: CORE_AUDITED_PREFIXES,
    official13Domains: OFFICIAL_13_DOMAINS.map((d) => d.id),
    excludedPatterns: EXCLUDED_PATTERNS,
    auditedFilesCount: auditedModulesSummary.filesCount,
    instrumented13DomainsFilesCount: all13DomainsSummary.filesCount,
    totalRepoSourceFilesCount,
    uninstrumentedFiles: allUninstrumentedFiles,
    repoFileCoverageRatioPct:
      totalRepoSourceFilesCount > 0
        ? Number(((all13DomainsSummary.filesCount / totalRepoSourceFilesCount) * 100).toFixed(2))
        : 0,
  },
  thresholds,
  total: {
    statements: auditedModulesSummary.statements,
    lines: auditedModulesSummary.lines,
    functions: auditedModulesSummary.functions,
    branches: auditedModulesSummary.branches,
  },
  global: {
    scopeLabel: 'Audited Core Engine Modules + 13 Domains Inventory',
    filesCount: auditedModulesSummary.filesCount,
    statementsPct: auditedModulesSummary.statementsPct,
    linesPct: auditedModulesSummary.linesPct,
    functionsPct: auditedModulesSummary.functionsPct,
    branchesPct: auditedModulesSummary.branchesPct,
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

// Generate standard LCOV report (coverage/lcov.info) using real mapped source lines & branches
const lcovLines = ['TN:winhood-benchmarking'];
for (const [rel, fileStats] of Object.entries(all13DomainsSummary.perFile)) {
  lcovLines.push(`SF:${rel}`);
  const detail = all13DomainsSummary.lcovDetailsByFile[rel];
  if (detail) {
    for (const fnEntry of detail.fns) {
      lcovLines.push(`FN:${fnEntry.line},${fnEntry.name}`);
      lcovLines.push(`FNDA:${fnEntry.callCount},${fnEntry.name}`);
    }
  }
  lcovLines.push(`FNF:${fileStats.functions.total}`);
  lcovLines.push(`FNH:${fileStats.functions.covered}`);
  if (detail && detail.lines.length > 0) {
    for (const [lineNum, hits] of detail.lines) {
      lcovLines.push(`DA:${lineNum},${hits}`);
    }
  }
  lcovLines.push(`LF:${fileStats.lines.total}`);
  lcovLines.push(`LH:${fileStats.lines.covered}`);
  if (detail && detail.branches.length > 0) {
    for (const br of detail.branches) {
      lcovLines.push(`BRDA:${br.line},0,${br.idx},${br.hits}`);
    }
  }
  lcovLines.push(`BRF:${fileStats.branches.total}`);
  lcovLines.push(`BRH:${fileStats.branches.covered}`);
  lcovLines.push('end_of_record');
}
fs.writeFileSync(path.join(covDir, 'lcov.info'), lcovLines.join('\n') + '\n', 'utf8');

const domainRowsHtml = Object.values(domainsByKey)
  .map(
    (d) =>
      `<tr><td>${d.domainId}</td><td>${d.tier}</td><td>${d.instrumentedFilesCount} / ${d.eligibleFilesCount}</td><td>${d.statementsPct}%</td><td>${d.linesPct}%</td><td>${d.functionsPct}%</td><td>${d.branchesPct}%</td></tr>`
  )
  .join('\n      ');

const htmlReport = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>WinHood V8 + Sourcemap Conventional Coverage Report (13 Domínios)</title>
  <style>
    body { font-family: monospace; background: #0f172a; color: #f8fafc; padding: 24px; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; }
    th, td { border: 1px solid #334155; padding: 10px; text-align: left; font-variant-numeric: tabular-nums; }
    th { background: #1e293b; }
    .meta { color: #94a3b8; font-size: 12px; margin-bottom: 12px; }
  </style>
</head>
<body>
  <h1>WinHood Conventional Test Coverage Report (V8 + Sourcemaps · 13 Domínios)</h1>
  <div class="meta">
    Gerado em: ${completedAtIso} | Metodologia: V8 + Sourcemaps (sem aproximação de bytes) | Instrumentados: ${all13DomainsSummary.filesCount} de ${totalRepoSourceFilesCount} arquivos elegíveis nos 13 domínios
  </div>
  <h2>Resumo Core Auditado & Motores Críticos</h2>
  <table>
    <thead>
      <tr><th>Escopo</th><th>Arquivos</th><th>Statements (%)</th><th>Lines (%)</th><th>Functions (%)</th><th>Branches (%)</th><th>Threshold</th></tr>
    </thead>
    <tbody>
      <tr><td>Core Auditado (6 domínios)</td><td>${auditedModulesSummary.filesCount}</td><td>${auditedModulesSummary.statementsPct}%</td><td>${auditedModulesSummary.linesPct}%</td><td>${auditedModulesSummary.functionsPct}%</td><td>${auditedModulesSummary.branchesPct}%</td><td>&ge; 80 / 80 / 75%</td></tr>
      <tr><td>src/scoring</td><td>${scoringSummary.filesCount}</td><td>${scoringSummary.statementsPct}%</td><td>${scoringSummary.linesPct}%</td><td>${scoringSummary.functionsPct}%</td><td>${scoringSummary.branchesPct}%</td><td>&ge; 95%</td></tr>
      <tr><td>src/evidence</td><td>${evidenceSummary.filesCount}</td><td>${evidenceSummary.statementsPct}%</td><td>${evidenceSummary.linesPct}%</td><td>${evidenceSummary.functionsPct}%</td><td>${evidenceSummary.branchesPct}%</td><td>&ge; 95%</td></tr>
      <tr><td>src/comparability</td><td>${comparabilitySummary.filesCount}</td><td>${comparabilitySummary.statementsPct}%</td><td>${comparabilitySummary.linesPct}%</td><td>${comparabilitySummary.functionsPct}%</td><td>${comparabilitySummary.branchesPct}%</td><td>&ge; 95%</td></tr>
    </tbody>
  </table>
  <h2>Inventário Individualizado dos 13 Domínios</h2>
  <table>
    <thead>
      <tr><th>Domínio</th><th>Camada</th><th>Instrumentados / Elegíveis</th><th>Statements (%)</th><th>Lines (%)</th><th>Functions (%)</th><th>Branches (%)</th></tr>
    </thead>
    <tbody>
      ${domainRowsHtml}
    </tbody>
  </table>
</body>
</html>`;

fs.writeFileSync(path.join(covDir, 'index.html'), htmlReport, 'utf8');
fs.rmSync(v8Dir, { recursive: true, force: true });

console.log('[WinHood Coverage Summary]', JSON.stringify(reportJson.global, null, 2));

if (!passed) {
  console.error('[WinHood Coverage Gate FAILED]:\n - ' + failures.join('\n - '));
  process.exit(1);
}
console.log('[WinHood Coverage Gate PASSED] Conventional V8 + Sourcemap coverage verified.');
