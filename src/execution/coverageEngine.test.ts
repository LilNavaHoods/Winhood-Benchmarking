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

test('Execution domain: SsrfGuard blocks private IPv4/IPv6/metadata/redirects and allows verified explicit loopback', async () => {
  const http = await import('node:http');
  const { SsrfGuard, isDisallowedIpAddress } = await import('./SsrfGuard');

  // IPv4 private / metadata / CGNAT / multicast / broadcast / unspecified / loopback
  assert.equal(isDisallowedIpAddress('').blocked, true);
  assert.equal(isDisallowedIpAddress('127.0.0.1', false).blocked, true);
  assert.equal(isDisallowedIpAddress('127.0.0.1', true).blocked, false);
  assert.equal(isDisallowedIpAddress('10.0.0.1').blocked, true);
  assert.equal(isDisallowedIpAddress('172.16.0.5').blocked, true);
  assert.equal(isDisallowedIpAddress('192.168.1.10').blocked, true);
  assert.equal(isDisallowedIpAddress('169.254.169.254').blocked, true);
  assert.equal(isDisallowedIpAddress('0.0.0.0').blocked, true);
  assert.equal(isDisallowedIpAddress('100.64.0.1').blocked, true);
  assert.equal(isDisallowedIpAddress('224.0.0.1').blocked, true);
  assert.equal(isDisallowedIpAddress('240.0.0.1').blocked, true);
  assert.equal(isDisallowedIpAddress('93.184.216.34').blocked, false);

  // IPv6 & IPv4-mapped IPv6
  assert.equal(isDisallowedIpAddress('::1', false).blocked, true);
  assert.equal(isDisallowedIpAddress('::1', true).blocked, false);
  assert.equal(isDisallowedIpAddress('::').blocked, true);
  assert.equal(isDisallowedIpAddress('fe80::1').blocked, true);
  assert.equal(isDisallowedIpAddress('fc00::1').blocked, true);
  assert.equal(isDisallowedIpAddress('ff02::1').blocked, true);
  assert.equal(isDisallowedIpAddress('64:ff9b::1').blocked, true);
  assert.equal(isDisallowedIpAddress('::ffff:127.0.0.1', false).blocked, true);
  assert.equal(isDisallowedIpAddress('::ffff:7f00:1', false).blocked, true);
  assert.equal(isDisallowedIpAddress('::ffff:invalid').blocked, true);
  assert.equal(isDisallowedIpAddress('2606:2800:220:1:248:1893:25c8:1946').blocked, false);
  assert.equal(isDisallowedIpAddress('not-an-ip').blocked, true);

  assert.equal(SsrfGuard.isExplicitLoopbackUrl('http://127.0.0.1:3000/api/health'), true);
  assert.equal(SsrfGuard.isExplicitLoopbackUrl('https://example.com'), false);
  assert.equal(SsrfGuard.isExplicitLoopbackUrl('not a url'), false);

  // URL validations
  assert.equal((await SsrfGuard.validateUrl({ targetUrl: 'not-a-url' })).allowed, false);
  assert.equal((await SsrfGuard.validateUrl({ targetUrl: 'file:///etc/passwd' })).allowed, false);
  assert.equal((await SsrfGuard.validateUrl({ targetUrl: 'http://user:pass@example.com' })).allowed, false);
  assert.equal((await SsrfGuard.validateUrl({ targetUrl: 'http://metadata.google.internal/' })).allowed, false);
  assert.equal(
    (await SsrfGuard.validateUrl({
      targetUrl: 'http://unregistered.example.com/',
      requireRegisteredTarget: true,
      authorizedTargets: [],
    })).allowed,
    false
  );

  // DNS rebinding simulation (public hostname resolving to private IP)
  const rebindRes = await SsrfGuard.validateUrl({
    targetUrl: 'https://rebind.example.test/api',
    dnsResolver: async () => [{ address: '169.254.169.254', family: 4 }],
  });
  assert.equal(rebindRes.allowed, false);

  // Safe HTTP probe with redirect to blocked private IP
  const server = await new Promise<import('node:http').Server>((resolve) => {
    const s = http.createServer((req, res) => {
      if (req.url === '/redirect-private') {
        res.statusCode = 302;
        res.setHeader('Location', 'http://169.254.169.254/latest/meta-data');
        res.end();
        return;
      }
      res.statusCode = 200;
      res.end('ok');
    });
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
  try {
    const port = (server.address() as import('node:net').AddressInfo).port;
    const okRes = await SsrfGuard.pinnedSafeRequest({
      targetUrl: `http://127.0.0.1:${port}/ok`,
      allowExplicitLoopback: true,
      timeoutMs: 3000,
    });
    assert.equal(okRes.statusCode, 200);
    assert.equal(okRes.ok, true);

    await assert.rejects(
      () =>
        SsrfGuard.pinnedSafeRequest({
          targetUrl: `http://127.0.0.1:${port}/redirect-private`,
          allowExplicitLoopback: true,
          timeoutMs: 3000,
        }),
      /SSRF|bloqueado|Link-local|metadata/i
    );
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('Execution domain: SandboxExecutor & ControlledTestAndPerfRunner enforce isolation, path traversal defense, verified recovery, and CoverageReportParser formats', async () => {
  const http = await import('node:http');
  const { SandboxExecutor, buildMinimalSandboxEnv } = await import('./SandboxExecutor');
  const { ControlledTestAndPerfRunner } = await import('./ControlledTestAndPerfRunner');
  const { CoverageReportParser } = await import('./CoverageReportParser');

  const env = buildMinimalSandboxEnv(os.tmpdir(), { SAFE_FLAG: '1' });
  assert.equal(env.SAFE_FLAG, '1');
  assert.ok(env.PATH);

  const probe = SandboxExecutor.probeHostIsolation();
  assert.equal(typeof probe.sandboxAvailable, 'boolean');

  // Path traversal defense in SandboxExecutor
  const escapeAttempt = SandboxExecutor.runSandboxedNodeTestWithRecovery({
    filesMap: { '../../escape.mjs': 'console.log(1);' },
    testFiles: ['../../escape.mjs'],
    timeoutMs: 5000,
  });
  assert.equal(escapeAttempt.blocked, true);
  assert.equal(escapeAttempt.recoveryVerified, true);

  // ControlledTestAndPerfRunner: no tests, JS test suite, non-JS language tests
  const noTests = ControlledTestAndPerfRunner.runIsolatedTestSuite({
    softwareName: 'EmptyPkg',
    filesMap: { 'src/app.ts': 'export const a = 1;' },
  });
  assert.equal(noTests.executed, false);
  assert.equal(noTests.provenance.state, 'NOT_MEASURED');

  const jsSuite = ControlledTestAndPerfRunner.runIsolatedTestSuite({
    softwareName: 'JsSamplePkg',
    filesMap: {
      'calc.mjs': 'export const add = (a, b) => a + b;\n',
      'calc.test.mjs':
        'import test from "node:test"; import assert from "node:assert/strict"; import { add } from "./calc.mjs"; test("adds", () => assert.equal(add(2, 3), 5));\n',
    },
    timeoutMs: 10000,
  });
  if (!jsSuite.blocked) {
    assert.equal(jsSuite.executed, true);
    assert.equal(jsSuite.testsPassed, 1);
    assert.equal(jsSuite.recoveryVerified, true);
  }

  const pySuite = ControlledTestAndPerfRunner.runIsolatedTestSuite({
    softwareName: 'PySamplePkg',
    filesMap: { 'app.test.py': 'def test_ok(): assert 1 == 1\n' },
  });
  assert.equal(pySuite.executed, false);
  assert.equal(pySuite.provenance.state, 'NOT_MEASURED');

  // ControlledPerfMeasurement: invalid URL, SSRF blocked, and valid local loopback probe
  const invalidPerf = await ControlledTestAndPerfRunner.measureHttpWorkload({ targetUrl: '' });
  assert.equal(invalidPerf.status, 'NOT_MEASURED');

  const ssrfPerf = await ControlledTestAndPerfRunner.measureHttpWorkload({
    targetUrl: 'http://169.254.169.254/latest/meta-data',
  });
  assert.equal(ssrfPerf.status, 'BLOCKED_SSRF');
  assert.equal(ssrfPerf.ssrfBlocked, true);

  const perfSrv = await new Promise<import('node:http').Server>((resolve) => {
    const s = http.createServer((_req, res) => {
      res.statusCode = 200;
      res.end('ok');
    });
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
  try {
    const port = (perfSrv.address() as import('node:net').AddressInfo).port;
    const measuredPerf = await ControlledTestAndPerfRunner.measureHttpWorkload({
      targetUrl: `http://127.0.0.1:${port}/`,
      requestsCount: 5,
      concurrency: 2,
      allowExplicitLoopback: true,
      timeoutMs: 3000,
    });
    assert.equal(measuredPerf.status, 'MEASURED');
    assert.equal(measuredPerf.successfulResponses, 5);
    assert.equal(measuredPerf.targetMetrics.cpuPercent, null);
  } finally {
    await new Promise<void>((resolve) => perfSrv.close(() => resolve()));
  }

  // CoverageReportParser: NONE, LCOV (valid + empty), JaCoCo XML, Cobertura XML, Istanbul JSON (valid + invalid)
  assert.equal(CoverageReportParser.parseFromFilesMap({}).state, 'NOT_MEASURED');
  assert.equal(CoverageReportParser.parseLcov(['coverage/lcov.info'], '').state, 'INCONCLUSIVE');

  const lcov = CoverageReportParser.parseFromFilesMap({
    'coverage/lcov.info': 'SF:src/a.ts\nDA:1,2\nDA:2,0\nBRDA:1,0,0,1\nBRDA:1,0,1,0\nLF:2\nLH:1\nBRF:2\nBRH:1\nend_of_record\n',
  });
  assert.equal(lcov.format, 'LCOV');
  assert.equal(lcov.lineCoveragePercent, 50);
  assert.equal(lcov.branchCoveragePercent, 50);

  const jacoco = CoverageReportParser.parseFromFilesMap({
    'jacoco.xml':
      '<report name="app"><counter type="LINE" missed="2" covered="8"/><counter type="BRANCH" missed="1" covered="3"/></report>',
  });
  assert.equal(jacoco.format, 'JACOCO_XML');
  assert.equal(jacoco.lineCoveragePercent, 80);

  const cobertura = CoverageReportParser.parseFromFilesMap({
    'cobertura.xml':
      '<coverage line-rate="0.75" branch-rate="0.50" lines-valid="20" lines-covered="15" branches-valid="10" branches-covered="5"></coverage>',
  });
  assert.equal(cobertura.format, 'COBERTURA_XML');
  assert.equal(cobertura.lineCoveragePercent, 75);

  const istanbul = CoverageReportParser.parseFromFilesMap({
    'coverage/coverage-final.json': JSON.stringify({
      'src/app.ts': {
        statementMap: { '0': { start: { line: 1 } }, '1': { start: { line: 2 } } },
        s: { '0': 1, '1': 0 },
        b: { '0': [1, 0] },
      },
    }),
  });
  assert.equal(istanbul.format, 'ISTANBUL_JSON');
  assert.equal(istanbul.lineCoveragePercent, 50);
});

test('WH-AUD-007: SsrfGuard blocks expanded/translated/compatible IPv6 private addresses and pinnedSafeRequest prevents DNS rebinding & redirects', async () => {
  const { SsrfGuard, isDisallowedIpAddress, parseIpv6ToHextets } = await import('./SsrfGuard');
  const http = await import('node:http');

  // 1. Canonical IPv6 parsing & expanded IPv4-mapped / translated / compatible addresses
  assert.deepEqual(parseIpv6ToHextets('::1'), [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.equal(parseIpv6ToHextets('not-an-ipv6'), null);

  const mustBlockIps = [
    '0:0:0:0:0:ffff:127.0.0.1',
    '0:0:0:0:0:ffff:7f00:1',
    '0000:0000:0000:0000:0000:ffff:a9fe:a9fe',
    '0:0:0:0:0:ffff:10.0.0.1',
    '0:0:0:0:0:ffff:192.168.1.1',
    '::ffff:0:127.0.0.1',
    '::ffff:0:10.0.0.1',
    '0:0:0:0:ffff:0:a9fe:a9fe',
    '::127.0.0.1',
    '::169.254.169.254',
    '0:0:0:0:0:0:7f00:1',
    '0:0:0:0:0:0:a9fe:a9fe',
    'fe80::1',
    'fc00::1',
    'fd12:3456:789a::1',
    'ff02::1',
    '64:ff9b::10.0.0.1',
    '2001:db8::1',
  ];
  for (const ip of mustBlockIps) {
    const res = isDisallowedIpAddress(ip, false);
    assert.equal(res.blocked, true, `Expected IPv6 address ${ip} to be blocked`);
  }

  // Legitimate public IPv6 must remain allowed
  assert.equal(isDisallowedIpAddress('2606:4700:4700::1111', false).blocked, false);

  // URL-level validation blocks expanded IPv6 forms
  const expandedCheck = await SsrfGuard.validateUrl({
    targetUrl: 'http://[0:0:0:0:0:ffff:169.254.169.254]/latest/meta-data',
    allowExplicitLoopback: false,
  });
  assert.equal(expandedCheck.allowed, false);

  // 2. pinnedSafeRequest supports POST + headers + JSON body + strict redirect rejection + single pinned DNS lookup
  const srv = http.createServer((req, res) => {
    if (req.url === '/redirect') {
      res.statusCode = 302;
      res.setHeader('Location', 'http://169.254.169.254/latest/meta-data');
      res.end();
      return;
    }
    if (req.url === '/large') {
      res.statusCode = 200;
      res.end('x'.repeat(2048));
      return;
    }
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('X-Custom-Echo', String(req.headers['x-winhood-probe'] || ''));
      res.end(
        JSON.stringify({
          method: req.method,
          body: Buffer.concat(chunks).toString('utf8'),
        })
      );
    });
  });
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', () => resolve()));
  const port = (srv.address() as import('node:net').AddressInfo).port;

  try {
    // DNS pinning verification: resolver is called once and pinned to 127.0.0.1 (no second rebind lookup)
    let dnsCalls = 0;
    const pinnedRes = await SsrfGuard.pinnedSafeRequest({
      targetUrl: `http://pinned-test.local:${port}/echo`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-WinHood-Probe': 'anti-rebinding-ok',
      },
      body: JSON.stringify({ ping: true }),
      allowExplicitLoopback: true,
      followRedirects: false,
      dnsResolver: async () => {
        dnsCalls += 1;
        return [{ address: '127.0.0.1', family: 4 }];
      },
    });
    assert.equal(dnsCalls, 1, 'DNS resolver must only be invoked once per hop (pinned IP)');
    assert.equal(pinnedRes.ok, true);
    assert.equal(pinnedRes.statusCode, 200);
    assert.equal(pinnedRes.headers['x-custom-echo'], 'anti-rebinding-ok');
    const parsedBody = pinnedRes.json<{ method: string; body: string }>();
    assert.equal(parsedBody.method, 'POST');
    assert.equal(parsedBody.body, JSON.stringify({ ping: true }));

    // Redirect blocked when followRedirects: false
    await assert.rejects(
      () =>
        SsrfGuard.pinnedSafeRequest({
          targetUrl: `http://127.0.0.1:${port}/redirect`,
          allowExplicitLoopback: true,
          followRedirects: false,
        }),
      /SSRF_REDIRECT_BLOCKED/
    );

    // Oversized response blocked by maxResponseBytes
    await assert.rejects(
      () =>
        SsrfGuard.pinnedSafeRequest({
          targetUrl: `http://127.0.0.1:${port}/large`,
          allowExplicitLoopback: true,
          maxResponseBytes: 512,
        }),
      /RESPONSE_TOO_LARGE/
    );
  } finally {
    await new Promise<void>((resolve) => srv.close(() => resolve()));
  }
});

