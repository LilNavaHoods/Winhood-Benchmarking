import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import esbuild from 'esbuild';
import {
  OFFICIAL_13_COVERAGE_DOMAINS,
  scanOfficial13DomainsInventory,
  computeThreeWaySeparatedCoverage,
} from './CoverageDomainInventory';

const require = createRequire(import.meta.url);

async function runMicroproject(
  files: Record<string, string>,
  testEntryRel: string,
  options?: {
    extensions?: string[];
    include?: string[];
    requireSourceMapForJs?: boolean;
    nodeArgs?: string[];
  }
) {
  const { executeC8V8CoverageRun, summarizeCoverageMapSubset } = await import(
    '../../scripts/coverage-runner-core.mjs'
  );
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wh-micro-cov-'));
  const covDir = path.join(tmpDir, 'coverage');
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = path.join(tmpDir, rel);
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, content, 'utf8');
    }
    const res = await executeC8V8CoverageRun({
      rootDir: tmpDir,
      testFiles: [testEntryRel],
      nodeArgs: options?.nodeArgs || ['--enable-source-maps', '--test'],
      include: options?.include || ['src/**/*'],
      exclude: ['**/*.test.*', 'coverage/**'],
      extensions: options?.extensions || ['.mjs', '.js', '.ts'],
      covDir,
      all: true,
      isEligibleRelPath: (rel) => rel.startsWith('src/') && !rel.includes('.test.'),
      requireSourceMapForJs: options?.requireSourceMapForJs ?? false,
      emitReports: false,
    });
    assert.equal(res.testExitCode, 0, `Microproject test failed: ${res.stderr}`);
    assert.ok(res.coverageMap, 'CoverageMap must be produced');
    const summary = summarizeCoverageMapSubset(res.coverageMap, tmpDir, (rel) =>
      rel.startsWith('src/')
    );
    return { res, summary, tmpDir };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

test('CoverageDomainInventory provides single source of truth for 13 official domains and 3 independent indicators', () => {
  assert.equal(OFFICIAL_13_COVERAGE_DOMAINS.length, 13);
  const scan = scanOfficial13DomainsInventory(process.cwd());
  assert.equal(scan.length, 13);
  for (const dom of scan) {
    assert.ok(dom.eligibleFiles.length > 0, `Domain ${dom.domainId} must have eligible files`);
    for (const f of dom.eligibleFiles) {
      assert.equal(f.endsWith('.test.ts'), false);
      assert.equal(f.endsWith('.test.tsx'), false);
      assert.equal(path.basename(f), path.basename(f));
      assert.notEqual(path.basename(f), 'types.ts');
    }
  }

  const bundle = computeThreeWaySeparatedCoverage({
    discoveredFilesCount: 100,
    eligibleFilesCount: 80,
    ingestedFilesCount: 60,
    analyzedFilesCount: 72,
    testCoverage: {
      sourceMapValidated: true,
      lines: { total: 100, covered: 85, pct: 85 },
    },
  });
  assert.equal(bundle.testCoverage.lines.pct, 85);
  assert.equal(bundle.ingestionCoverage.ingestionCoveragePct, 75);
  assert.equal(bundle.analysisCoverage.analysisCoveragePct, 90);
});

test('Phase 4 P0 Reference Microprojects (1 to 11): exact mathematical c8 + v8-to-istanbul calibration', async () => {
  // 1. Executed function (100%)
  {
    const { summary } = await runMicroproject(
      {
        'src/m1.mjs': 'export function add(a, b) {\n  return a + b;\n}\n',
        'src/m1.test.mjs':
          'import test from "node:test"; import assert from "node:assert/strict"; import { add } from "./m1.mjs"; test("m1", () => assert.equal(add(2, 3), 5));\n',
      },
      'src/m1.test.mjs'
    );
    assert.equal(summary.perFile['src/m1.mjs']?.functionsPct, 100);
    assert.equal(summary.perFile['src/m1.mjs']?.linesPct, 100);
  }

  // 2. Unexecuted function (0% in function)
  {
    const { summary } = await runMicroproject(
      {
        'src/m2.mjs': 'export function neverCalled(x) {\n  const y = x * 2;\n  return y + 1;\n}\n',
        'src/m2.test.mjs':
          'import test from "node:test"; import assert from "node:assert/strict"; import "./m2.mjs"; test("m2", () => assert.ok(true));\n',
      },
      'src/m2.test.mjs'
    );
    assert.equal(summary.perFile['src/m2.mjs']?.functionsPct, 0);
    assert.equal(summary.perFile['src/m2.mjs']?.functions.total, 1);
    assert.equal(summary.perFile['src/m2.mjs']?.functions.covered, 0);
  }

  // 3. Partially executed branch (50% of branches in if/else)
  {
    const { summary } = await runMicroproject(
      {
        'src/m3.mjs': [
          'export function signLabel(n) {',
          '  if (n > 0) {',
          '    return "pos";',
          '  } else {',
          '    return "non-pos";',
          '  }',
          '}',
        ].join('\n'),
        'src/m3.test.mjs':
          'import test from "node:test"; import assert from "node:assert/strict"; import { signLabel } from "./m3.mjs"; test("m3", () => assert.equal(signLabel(5), "pos"));\n',
      },
      'src/m3.test.mjs'
    );
    const b = summary.perFile['src/m3.mjs']?.branches;
    assert.ok(b && b.total >= 2);
    assert.ok((b.pct ?? 100) < 100 && (b.pct ?? 0) > 0, `Expected partial branch coverage, got ${b.pct}%`);
  }

  // 4. Fully executed branch (100%)
  {
    const { summary } = await runMicroproject(
      {
        'src/m4.mjs': [
          'export function signLabel(n) {',
          '  if (n > 0) {',
          '    return "pos";',
          '  } else {',
          '    return "non-pos";',
          '  }',
          '}',
        ].join('\n'),
        'src/m4.test.mjs':
          'import test from "node:test"; import assert from "node:assert/strict"; import { signLabel } from "./m4.mjs"; test("m4", () => { assert.equal(signLabel(5), "pos"); assert.equal(signLabel(-1), "non-pos"); });\n',
      },
      'src/m4.test.mjs'
    );
    assert.equal(summary.perFile['src/m4.mjs']?.branchesPct, 100);
    assert.equal(summary.perFile['src/m4.mjs']?.linesPct, 100);
  }

  // 5. Anonymous / arrow function (one called, one uncalled)
  {
    const { summary } = await runMicroproject(
      {
        'src/m5.mjs': [
          'export const doubleFn = (v) => v * 2;',
          'export const tripleFn = (v) => v * 3;',
        ].join('\n'),
        'src/m5.test.mjs':
          'import test from "node:test"; import assert from "node:assert/strict"; import { doubleFn } from "./m5.mjs"; test("m5", () => assert.equal(doubleFn(4), 8));\n',
      },
      'src/m5.test.mjs'
    );
    const fnStats = summary.perFile['src/m5.mjs']?.functions;
    assert.equal(fnStats?.total, 2);
    assert.equal(fnStats?.covered, 1);
    assert.equal(fnStats?.pct, 50);
  }

  // 6. try/catch (normal and exception path)
  {
    const { summary } = await runMicroproject(
      {
        'src/m6.mjs': [
          'export function safeParse(raw) {',
          '  try {',
          '    return JSON.parse(raw);',
          '  } catch {',
          '    return null;',
          '  }',
          '}',
        ].join('\n'),
        'src/m6.test.mjs': [
          'import test from "node:test";',
          'import assert from "node:assert/strict";',
          'import { safeParse } from "./m6.mjs";',
          'test("m6", () => {',
          '  assert.deepEqual(safeParse("{\\"ok\\":true}"), { ok: true });',
          '  assert.equal(safeParse("{broken"), null);',
          '});',
        ].join('\n'),
      },
      'src/m6.test.mjs'
    );
    assert.equal(summary.perFile['src/m6.mjs']?.linesPct, 100);
    assert.equal(summary.perFile['src/m6.mjs']?.branchesPct, 100);
  }

  // 7. Eligible file never imported by tests (0% in denominator via all: true)
  {
    const { summary } = await runMicroproject(
      {
        'src/used.mjs': 'export function ping() {\n  return 1;\n}\n',
        'src/never-imported.mjs': 'export function orphan(x) {\n  const a = x + 1;\n  const b = a * 2;\n  return b;\n}\n',
        'src/m7.test.mjs':
          'import test from "node:test"; import assert from "node:assert/strict"; import { ping } from "./used.mjs"; test("m7", () => assert.equal(ping(), 1));\n',
      },
      'src/m7.test.mjs'
    );
    assert.equal(summary.filesCount, 2, 'Both used.mjs and never-imported.mjs must appear in denominator');
    assert.equal(summary.perFile['src/used.mjs']?.linesPct, 100);
    assert.equal(summary.perFile['src/never-imported.mjs']?.linesPct, 0);
  }

  // 8. Invalid SourceMap detected explicitly without silent fallback
  {
    const { res } = await runMicroproject(
      {
        'src/m8-badmap.mjs':
          'export function bad() {\n  return 42;\n}\n//# sourceMappingURL=data:application/json;base64,bm90LWpzb24=\n',
        'src/m8.test.mjs':
          'import test from "node:test"; import assert from "node:assert/strict"; import { bad } from "./m8-badmap.mjs"; test("m8", () => assert.equal(bad(), 42));\n',
      },
      'src/m8.test.mjs',
      { requireSourceMapForJs: true }
    );
    assert.ok(
      res.sourceMapValidation.errors.some(
        (e) =>
          e.file === 'src/m8-badmap.mjs' &&
          (e.reason.includes('INVALID_INLINE_SOURCEMAP') || e.reason.includes('INVALID_V8_SOURCEMAP'))
      ),
      `Expected explicit invalid sourcemap error, got ${JSON.stringify(res.sourceMapValidation)}`
    );
  }

  // 9. Missing SourceMap detected explicitly when required
  {
    const { res } = await runMicroproject(
      {
        'src/m9-nomap.mjs': 'export function nomap() {\n  return 7;\n}\n',
        'src/m9.test.mjs':
          'import test from "node:test"; import assert from "node:assert/strict"; import { nomap } from "./m9-nomap.mjs"; test("m9", () => assert.equal(nomap(), 7));\n',
      },
      'src/m9.test.mjs',
      { requireSourceMapForJs: true }
    );
    assert.ok(
      res.sourceMapValidation.errors.some(
        (e) => e.file === 'src/m9-nomap.mjs' && e.reason.includes('MISSING_V8_SOURCEMAP_CACHE')
      ),
      `Expected explicit missing sourcemap error, got ${JSON.stringify(res.sourceMapValidation)}`
    );
  }

  // 10. Multi-function file with deterministic partial coverage (2/3 functions = 66.67%)
  {
    const { summary } = await runMicroproject(
      {
        'src/m10.mjs': [
          'export function f1() { return 1; }',
          'export function f2() { return 2; }',
          'export function f3() { return 3; }',
        ].join('\n'),
        'src/m10.test.mjs':
          'import test from "node:test"; import assert from "node:assert/strict"; import { f1, f2 } from "./m10.mjs"; test("m10", () => { assert.equal(f1(), 1); assert.equal(f2(), 2); });\n',
      },
      'src/m10.test.mjs'
    );
    assert.equal(summary.perFile['src/m10.mjs']?.functions.total, 3);
    assert.equal(summary.perFile['src/m10.mjs']?.functions.covered, 2);
    assert.equal(summary.perFile['src/m10.mjs']?.functionsPct, 66.66);
  }

  // 11. TypeScript transpiled to JavaScript with exact original .ts line/column mapping via SourceMap
  {
    const tsSource = [
      'export interface CalcInput { value: number; }',
      'export function computeValue(input: CalcInput): number {',
      '  if (input.value > 10) {',
      '    return input.value * 2;',
      '  }',
      '  return input.value + 1;',
      '}',
    ].join('\n');

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wh-micro-ts-'));
    try {
      const tsPath = path.join(tmpDir, 'src', 'calc.ts');
      const mjsPath = path.join(tmpDir, 'src', 'calc.mjs');
      const testPath = path.join(tmpDir, 'src', 'calc.test.mjs');
      fs.mkdirSync(path.dirname(tsPath), { recursive: true });
      fs.writeFileSync(tsPath, tsSource, 'utf8');

      const transformed = esbuild.transformSync(tsSource, {
        loader: 'ts',
        format: 'esm',
        sourcemap: 'inline',
        sourcefile: tsPath,
      });
      fs.writeFileSync(mjsPath, transformed.code, 'utf8');
      fs.writeFileSync(
        testPath,
        'import test from "node:test"; import assert from "node:assert/strict"; import { computeValue } from "./calc.mjs"; test("ts-map", () => assert.equal(computeValue({ value: 20 }), 40));\n',
        'utf8'
      );

      const { executeC8V8CoverageRun } = await import('../../scripts/coverage-runner-core.mjs');
      const covDir = path.join(tmpDir, 'coverage');
      const runRes = await executeC8V8CoverageRun({
        rootDir: tmpDir,
        testFiles: ['src/calc.test.mjs'],
        nodeArgs: ['--enable-source-maps', '--test'],
        include: ['src/**/*'],
        exclude: ['**/*.test.*'],
        extensions: ['.mjs', '.ts'],
        covDir,
        all: false,
        isEligibleRelPath: (rel) => rel.endsWith('calc.mjs') || rel.endsWith('calc.ts'),
        emitReports: false,
      });
      assert.equal(runRes.testExitCode, 0);
      assert.equal(runRes.sourceMapValidation.errors.length, 0);
      assert.ok(runRes.coverageMap);
      const mappedFiles = runRes.coverageMap.files().map((f: string) => path.relative(tmpDir, f).replace(/\\/g, '/'));
      assert.ok(mappedFiles.includes('src/calc.ts'), `Expected remapped src/calc.ts, got ${JSON.stringify(mappedFiles)}`);
      const fc = runRes.coverageMap.fileCoverageFor(tsPath);
      const lineCov = fc.getLineCoverage();
      // Line 4 (`return input.value * 2;`) executed (>0), Line 6 (`return input.value + 1;`) unexecuted (0)
      assert.ok((lineCov[4] ?? 0) > 0, `Expected TS line 4 covered, got ${JSON.stringify(lineCov)}`);
      assert.equal(lineCov[6], 0, `Expected TS line 6 uncovered (0), got ${JSON.stringify(lineCov)}`);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }
});
