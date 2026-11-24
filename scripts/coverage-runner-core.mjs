import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { createRequire, SourceMap } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { Report } = require('c8');
const c8Require = createRequire(require.resolve('c8'));
const libCoverage = c8Require('istanbul-lib-coverage');
const libReport = c8Require('istanbul-lib-report');
const istanbulReports = c8Require('istanbul-reports');

function toPosixRel(rootDir, absPath) {
  return path.relative(rootDir, absPath).replace(/\\/g, '/');
}

export function validateV8SourceMapsInDir({
  v8Dir,
  rootDir,
  isEligibleRelPath,
  requireSourceMapForJs = false,
}) {
  const v8Files = fs.existsSync(v8Dir)
    ? fs.readdirSync(v8Dir).filter((f) => f.endsWith('.json'))
    : [];

  const checkedScripts = new Set();
  const validScripts = new Set();
  const errorMap = new Map();

  for (const vf of v8Files) {
    let raw;
    try {
      raw = JSON.parse(fs.readFileSync(path.join(v8Dir, vf), 'utf8'));
    } catch (err) {
      errorMap.set(vf, `CORRUPT_V8_COVERAGE_JSON: ${err?.message || String(err)}`);
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
      const rel = toPosixRel(rootDir, fp);
      if (!isEligibleRelPath(rel)) continue;
      if (!fs.existsSync(fp)) continue;

      checkedScripts.add(rel);
      const ext = path.extname(rel).toLowerCase();
      const needsSourceMap = ext === '.ts' || ext === '.tsx' || requireSourceMapForJs;
      const smEntry = smCache[script.url];

      if (!needsSourceMap) {
        validScripts.add(rel);
        continue;
      }

      if (!smEntry || !smEntry.data) {
        // Also check external .map or inline sourceMappingURL inside disk file
        const diskContent = fs.readFileSync(fp, 'utf8');
        const mapCommentMatch = diskContent.match(/\/\/# sourceMappingURL=(.+)$/m);
        if (mapCommentMatch) {
          const target = mapCommentMatch[1].trim();
          if (target.startsWith('data:application/json')) {
            try {
              const b64 = target.split(',')[1] || '';
              const decoded = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
              new SourceMap(decoded);
              validScripts.add(rel);
              continue;
            } catch (err) {
              errorMap.set(rel, `INVALID_INLINE_SOURCEMAP: ${err?.message || String(err)}`);
              continue;
            }
          } else {
            const mapAbs = path.resolve(path.dirname(fp), target);
            if (!fs.existsSync(mapAbs)) {
              errorMap.set(rel, `MISSING_EXTERNAL_SOURCEMAP: ${target}`);
              continue;
            }
            try {
              const parsedMap = JSON.parse(fs.readFileSync(mapAbs, 'utf8'));
              new SourceMap(parsedMap);
              validScripts.add(rel);
              continue;
            } catch (err) {
              errorMap.set(rel, `INVALID_EXTERNAL_SOURCEMAP: ${err?.message || String(err)}`);
              continue;
            }
          }
        }
        errorMap.set(rel, 'MISSING_V8_SOURCEMAP_CACHE');
        continue;
      }

      try {
        const sm = new SourceMap(smEntry.data);
        if (!sm.payload || !Array.isArray(sm.payload.sources) || sm.payload.sources.length === 0) {
          errorMap.set(rel, 'EMPTY_SOURCEMAP_SOURCES');
          continue;
        }
        validScripts.add(rel);
      } catch (err) {
        errorMap.set(rel, `INVALID_V8_SOURCEMAP: ${err?.message || String(err)}`);
      }
    }
  }

  return {
    v8FilesCount: v8Files.length,
    checkedScriptsCount: checkedScripts.size,
    checkedScripts: Array.from(checkedScripts).sort((a, b) => a.localeCompare(b)),
    validSourceMapsCount: validScripts.size,
    errors: Array.from(errorMap.entries()).map(([file, reason]) => ({ file, reason })),
  };
}

/**
 * @typedef {{ total: number; covered: number; pct: number }} MetricCountSummary
 * @typedef {{
 *   statements: MetricCountSummary;
 *   lines: MetricCountSummary;
 *   functions: MetricCountSummary;
 *   branches: MetricCountSummary;
 *   statementsPct: number;
 *   linesPct: number;
 *   functionsPct: number;
 *   branchesPct: number;
 * }} FileCoverageSummary
 */

/**
 * @param {any} coverageMap
 * @param {string} rootDir
 * @param {(rel: string, absPath: string) => boolean} filterFn
 */
export function summarizeCoverageMapSubset(coverageMap, rootDir, filterFn) {
  let stmtTot = 0;
  let stmtCov = 0;
  let linesTot = 0;
  let linesCov = 0;
  let fnTot = 0;
  let fnCov = 0;
  let branchesTot = 0;
  let branchesCov = 0;
  let filesCount = 0;
  /** @type {Record<string, FileCoverageSummary>} */
  const perFile = {};

  for (const absPath of coverageMap.files()) {
    const rel = toPosixRel(rootDir, absPath);
    if (!filterFn(rel, absPath)) continue;
    filesCount += 1;
    const sum = coverageMap.fileCoverageFor(absPath).toSummary();

    stmtTot += sum.statements.total;
    stmtCov += sum.statements.covered;
    linesTot += sum.lines.total;
    linesCov += sum.lines.covered;
    fnTot += sum.functions.total;
    fnCov += sum.functions.covered;
    branchesTot += sum.branches.total;
    branchesCov += sum.branches.covered;

    perFile[rel] = {
      statements: {
        total: sum.statements.total,
        covered: sum.statements.covered,
        pct: sum.statements.pct,
      },
      lines: {
        total: sum.lines.total,
        covered: sum.lines.covered,
        pct: sum.lines.pct,
      },
      functions: {
        total: sum.functions.total,
        covered: sum.functions.covered,
        pct: sum.functions.pct,
      },
      branches: {
        total: sum.branches.total,
        covered: sum.branches.covered,
        pct: sum.branches.pct,
      },
      statementsPct: sum.statements.pct,
      linesPct: sum.lines.pct,
      functionsPct: sum.functions.pct,
      branchesPct: sum.branches.pct,
    };
  }

  const pct = (c, t) => (t > 0 ? Number(((c / t) * 100).toFixed(2)) : 100);
  const statementsPct = stmtTot > 0 ? pct(stmtCov, stmtTot) : 0;
  const linesPct = linesTot > 0 ? pct(linesCov, linesTot) : 0;
  const functionsPct = fnTot > 0 ? pct(fnCov, fnTot) : 0;
  const branchesPct = branchesTot > 0 ? pct(branchesCov, branchesTot) : 100;

  return {
    filesCount,
    statements: { total: stmtTot, covered: stmtCov, pct: statementsPct },
    lines: { total: linesTot, covered: linesCov, pct: linesPct },
    functions: { total: fnTot, covered: fnCov, pct: functionsPct },
    branches: { total: branchesTot, covered: branchesCov, pct: branchesPct },
    statementsPct,
    linesPct,
    functionsPct,
    branchesPct,
    perFile,
  };
}

/**
 * @param {object} opts
 * @param {string} opts.rootDir
 * @param {string[]} opts.testFiles
 * @param {string[]} [opts.nodeArgs]
 * @param {string[]} [opts.include]
 * @param {string[]} [opts.exclude]
 * @param {string[]} [opts.extensions]
 * @param {string} opts.covDir
 * @param {boolean} [opts.all]
 * @param {(rel: string) => boolean} [opts.isEligibleRelPath]
 * @param {boolean} [opts.requireSourceMapForJs]
 * @param {boolean} [opts.emitReports]
 * @param {string[]} [opts.reporters]
 */
export async function executeC8V8CoverageRun({
  rootDir,
  testFiles,
  nodeArgs = ['--enable-source-maps', '--import', 'tsx', '--test'],
  include,
  exclude,
  extensions = ['.ts', '.tsx'],
  covDir,
  all = true,
  isEligibleRelPath = (_rel) => true,
  requireSourceMapForJs = false,
  emitReports = true,
}) {
  const v8Dir = path.join(covDir, 'v8-tmp');
  fs.rmSync(covDir, { recursive: true, force: true });
  fs.mkdirSync(v8Dir, { recursive: true });

  const childEnv = { ...process.env, NODE_V8_COVERAGE: v8Dir };
  delete childEnv.NODE_TEST_CONTEXT;

  const startedAt = new Date().toISOString();
  const res = spawnSync(process.execPath, [...nodeArgs, ...testFiles], {
    cwd: rootDir,
    env: childEnv,
    stdio: 'pipe',
    encoding: 'utf8',
  });

  const smValidation = validateV8SourceMapsInDir({
    v8Dir,
    rootDir,
    isEligibleRelPath,
    requireSourceMapForJs,
  });

  if (res.status !== 0) {
    fs.rmSync(v8Dir, { recursive: true, force: true });
    return {
      testExitCode: res.status || 1,
      stdout: res.stdout || '',
      stderr: res.stderr || '',
      startedAt,
      completedAt: new Date().toISOString(),
      sourceMapValidation: smValidation,
      coverageMap: null,
    };
  }

  if (smValidation.v8FilesCount === 0) {
    fs.rmSync(v8Dir, { recursive: true, force: true });
    throw new Error('NO_V8_COVERAGE_FILES_GENERATED');
  }

  const makeConfiguredReport = (allFlag, tempDirectory, rawOverride) => {
    const rep = new Report({
      include,
      exclude,
      extension: extensions,
      excludeAfterRemap: true,
      all: allFlag,
      reporter: ['lcovonly', 'html', 'json'],
      reportsDirectory: covDir,
      tempDirectory,
      resolve: rootDir,
      src: [rootDir],
      excludeNodeModules: true,
    });
    const TestExclude = rep.exclude.constructor;
    rep.exclude = new TestExclude({
      cwd: rootDir,
      exclude,
      include,
      extension: extensions,
      relativePath: true,
      excludeNodeModules: true,
    });
    if (rawOverride) {
      rep._loadReports = () => [rawOverride];
    }
    return rep;
  };

  const coverageMap = libCoverage.createCoverageMap();
  const v8JsonFiles = fs
    .readdirSync(v8Dir)
    .filter((f) => f.endsWith('.json'))
    .sort();

  for (const vf of v8JsonFiles) {
    let parsedV8;
    try {
      parsedV8 = JSON.parse(fs.readFileSync(path.join(v8Dir, vf), 'utf8'));
    } catch {
      continue;
    }
    const subReport = makeConfiguredReport(false, v8Dir, parsedV8);
    const subMap = await subReport.getCoverageMapFromAllCoverageFiles();
    coverageMap.merge(subMap);
  }

  if (all) {
    const emptyTmpDir = path.join(covDir, 'v8-empty-tmp');
    fs.mkdirSync(emptyTmpDir, { recursive: true });
    try {
      const emptyReport = makeConfiguredReport(true, emptyTmpDir, null);
      const emptyMap = await emptyReport.getCoverageMapFromAllCoverageFiles();
      const coveredSet = new Set(coverageMap.files());
      for (const absPath of emptyMap.files()) {
        if (!coveredSet.has(absPath)) {
          coverageMap.addFileCoverage(emptyMap.fileCoverageFor(absPath));
        }
      }
    } finally {
      fs.rmSync(emptyTmpDir, { recursive: true, force: true });
    }
  }

  if (emitReports) {
    const context = libReport.createContext({
      dir: covDir,
      coverageMap,
    });
    for (const repName of ['lcovonly', 'html', 'json']) {
      istanbulReports.create(repName, { skipEmpty: false }).execute(context);
    }
  }

  fs.rmSync(v8Dir, { recursive: true, force: true });

  return {
    testExitCode: 0,
    stdout: res.stdout || '',
    stderr: res.stderr || '',
    startedAt,
    completedAt: new Date().toISOString(),
    sourceMapValidation: smValidation,
    coverageMap,
  };
}
