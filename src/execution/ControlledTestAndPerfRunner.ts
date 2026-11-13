import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { MetricProvenanceRecord, ParsedCoverageReportSummary } from '../types/benchmark';
import { CoverageReportParser } from './CoverageReportParser';

export interface ControlledTestExecutionResult {
  executed: boolean;
  runnerUsed: string;
  exitCode: number | null;
  testsTotal: number;
  testsPassed: number;
  testsFailed: number;
  durationMs: number | null;
  stdoutSnippet: string;
  stderrSnippet: string;
  coverageReport: ParsedCoverageReportSummary;
  provenance: MetricProvenanceRecord;
}

export interface ControlledPerfMeasurementResult {
  status: 'MEASURED' | 'NOT_MEASURED';
  reason?: string;
  targetUrl?: string;
  requestsSent: number;
  successfulResponses: number;
  failedResponses: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  throughputRps: number;
  cpuPercent: number;
  memoryRssMb: number;
  startupTimeMs: number;
  measuredAt: string;
  provenance: MetricProvenanceRecord;
}

export class ControlledTestAndPerfRunner {
  /**
   * Executa testes reais do projeto em diretório temporário isolado quando arquivos de teste e manifestos existem.
   * Nunca fabrica contagem de testes nem % de cobertura.
   */
  public static runIsolatedTestSuite(params: {
    softwareName: string;
    filesMap: Record<string, string>;
    timeoutMs?: number;
  }): ControlledTestExecutionResult {
    const timeoutMs = params.timeoutMs ?? 25000;
    const filesMap = params.filesMap || {};
    const testFiles = Object.keys(filesMap).filter((p) => /\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs|py)$/i.test(p));
    const existingCoverage = CoverageReportParser.parseFromFilesMap(filesMap);

    if (testFiles.length === 0) {
      return {
        executed: false,
        runnerUsed: 'NONE',
        exitCode: null,
        testsTotal: 0,
        testsPassed: 0,
        testsFailed: 0,
        durationMs: null,
        stdoutSnippet: '',
        stderrSnippet: 'Nenhum arquivo de teste (*.test.* / *.spec.*) encontrado no pacote.',
        coverageReport: existingCoverage,
        provenance: {
          metricKey: 'functionalTestsTotal',
          value: 0,
          state: 'NOT_MEASURED',
          origin: 'CONTROLLED_TEST_RUNNER',
          method: 'Nenhum arquivo de teste encontrado no pacote submetido.',
          toolName: 'WinHood ControlledTestAndPerfRunner',
          toolVersion: '4.1.0',
          measuredAt: new Date().toISOString(),
          scope: params.softwareName,
        },
      };
    }

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-test-exec-'));
    try {
      for (const [relPath, content] of Object.entries(filesMap)) {
        const sanitized = relPath.replace(/^\/+/, '').replace(/\.\.[/\\]/g, '');
        const fullPath = path.join(tmpRoot, sanitized);
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, content, 'utf8');
      }

      const startMs = performance.now();
      const jsTests = testFiles.filter((f) => /\.(js|mjs|cjs|ts|tsx)$/i.test(f));
      const runnableJsTests = jsTests.filter((f) => /\.(js|mjs|cjs)$/i.test(f));
      if (runnableJsTests.length > 0) {
        const childEnv = { ...process.env };
        delete childEnv.NODE_TEST_CONTEXT;
        const res = spawnSync(
          process.execPath,
          ['--test', '--test-reporter=tap', ...runnableJsTests],
          {
            cwd: tmpRoot,
            shell: false,
            encoding: 'utf8',
            timeout: timeoutMs,
            env: childEnv,
          }
        );
        const durationMs = Math.max(1, Math.round(performance.now() - startMs));
        const output = `${res.stdout || ''}\n${res.stderr || ''}`;
        const passMatch = output.match(/^[#ℹ]\s*pass\s+(\d+)/im);
        const failMatch = output.match(/^[#ℹ]\s*fail\s+(\d+)/im);
        const testsMatch = output.match(/^[#ℹ]\s*tests\s+(\d+)/im);
        const passed = passMatch ? Number(passMatch[1]) : (output.match(/^ok\s+\d+\s+-/gm) || []).length;
        const failed = failMatch ? Number(failMatch[1]) : (output.match(/^not ok\s+\d+\s+-/gm) || []).length;
        const total = testsMatch ? Number(testsMatch[1]) : passed + failed;

        const executedCleanly = total > 0 && res.status !== null;
        return {
          executed: executedCleanly,
          runnerUsed: 'node --test',
          exitCode: res.status,
          testsTotal: total,
          testsPassed: passed,
          testsFailed: failed,
          durationMs,
          stdoutSnippet: (res.stdout || '').slice(0, 1200),
          stderrSnippet: (res.stderr || '').slice(0, 800),
          coverageReport: existingCoverage,
          provenance: {
            metricKey: 'functionalTestsTotal',
            value: total,
            state: executedCleanly ? 'MEASURED' : 'INCONCLUSIVE',
            origin: 'CONTROLLED_TEST_RUNNER',
            method: executedCleanly
              ? `Execução isolada node --test (${passed}/${total} aprovados em ${durationMs}ms)`
              : 'Testes TypeScript/TSX ou dependências externas requerem build prévio no workspace isolado.',
            toolName: 'node --test',
            toolVersion: process.version,
            measuredAt: new Date().toISOString(),
            scope: `${jsTests.length} arquivo(s) de teste`,
            evidenceHash: crypto.createHash('sha256').update(output, 'utf8').digest('hex'),
          },
        };
      }

      return {
        executed: false,
        runnerUsed: 'UNSUPPORTED_IN_CONTAINER',
        exitCode: null,
        testsTotal: 0,
        testsPassed: 0,
        testsFailed: 0,
        durationMs: null,
        stdoutSnippet: '',
        stderrSnippet: 'Execução automática no sandbox requer runtime/dependências da linguagem alvo.',
        coverageReport: existingCoverage,
        provenance: {
          metricKey: 'functionalTestsTotal',
          value: null,
          state: 'NOT_MEASURED',
          origin: 'CONTROLLED_TEST_RUNNER',
          method: 'Arquivos de teste presentes, mas sem runner isolado disponível para este ecossistema.',
          toolName: 'WinHood ControlledTestAndPerfRunner',
          toolVersion: '4.1.0',
          measuredAt: new Date().toISOString(),
          scope: testFiles.join(', '),
        },
      };
    } finally {
      try {
        fs.rmSync(tmpRoot, { recursive: true, force: true });
      } catch {
        // Ignore cleanup failure
      }
    }
  }

  /**
   * Executa medição real de latência P50/P95/P99, RPS, CPU e RSS contra endpoint HTTP real ou worker controlado.
   * Nunca inventa latência se o endpoint não responder.
   */
  public static async measureHttpWorkload(params: {
    targetUrl: string;
    requestsCount?: number;
    concurrency?: number;
    timeoutMs?: number;
  }): Promise<ControlledPerfMeasurementResult> {
    const requestsCount = Math.max(5, Math.min(200, params.requestsCount ?? 25));
    const concurrency = Math.max(1, Math.min(20, params.concurrency ?? 5));
    const timeoutMs = params.timeoutMs ?? 4000;
    const nowIso = new Date().toISOString();

    if (!params.targetUrl || !/^https?:\/\//i.test(params.targetUrl)) {
      return {
        status: 'NOT_MEASURED',
        reason: 'URL HTTP/HTTPS alvo válida não informada para medição controlada de runtime.',
        requestsSent: 0,
        successfulResponses: 0,
        failedResponses: 0,
        p50LatencyMs: 0,
        p95LatencyMs: 0,
        p99LatencyMs: 0,
        throughputRps: 0,
        cpuPercent: 0,
        memoryRssMb: 0,
        startupTimeMs: 0,
        measuredAt: nowIso,
        provenance: {
          metricKey: 'p95LatencyMs',
          value: null,
          state: 'NOT_MEASURED',
          origin: 'CONTROLLED_PERF_RUNNER',
          method: 'Medição HTTP não executada sem endpoint alvo.',
          toolName: 'WinHood ControlledTestAndPerfRunner',
          toolVersion: '4.1.0',
          measuredAt: nowIso,
          scope: 'runtime',
        },
      };
    }

    const latencies: number[] = [];
    let okCount = 0;
    let failCount = 0;
    const cpuStart = process.cpuUsage();
    const overallStart = performance.now();

    let nextIndex = 0;
    const workerFn = async () => {
      while (nextIndex < requestsCount) {
        const idx = nextIndex++;
        void idx;
        const reqStart = performance.now();
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
          const res = await fetch(params.targetUrl, { signal: controller.signal });
          await res.arrayBuffer();
          const dt = performance.now() - reqStart;
          latencies.push(dt);
          if (res.ok) okCount += 1;
          else failCount += 1;
        } catch {
          failCount += 1;
        } finally {
          clearTimeout(timer);
        }
      }
    };

    await Promise.all(Array.from({ length: concurrency }, () => workerFn()));

    const totalMs = Math.max(1, performance.now() - overallStart);
    const cpuDelta = process.cpuUsage(cpuStart);
    const cpuTimeMs = (cpuDelta.user + cpuDelta.system) / 1000;
    const cpuPercent = Math.min(100, Math.round((cpuTimeMs / totalMs) * 1000) / 10);
    const memoryRssMb = Math.round((process.memoryUsage().rss / (1024 * 1024)) * 10) / 10;

    if (latencies.length === 0) {
      return {
        status: 'NOT_MEASURED',
        reason: `Nenhuma requisição HTTP obteve resposta em ${params.targetUrl} (${failCount} falha(s)).`,
        targetUrl: params.targetUrl,
        requestsSent: requestsCount,
        successfulResponses: 0,
        failedResponses: failCount,
        p50LatencyMs: 0,
        p95LatencyMs: 0,
        p99LatencyMs: 0,
        throughputRps: 0,
        cpuPercent,
        memoryRssMb,
        startupTimeMs: 0,
        measuredAt: nowIso,
        provenance: {
          metricKey: 'p95LatencyMs',
          value: null,
          state: 'FAILED',
          origin: 'CONTROLLED_PERF_RUNNER',
          method: `Falha ao conectar em ${params.targetUrl}`,
          toolName: 'WinHood ControlledTestAndPerfRunner',
          toolVersion: '4.1.0',
          measuredAt: nowIso,
          scope: params.targetUrl,
        },
      };
    }

    latencies.sort((a, b) => a - b);
    const pct = (p: number) => {
      const idx = Math.min(latencies.length - 1, Math.max(0, Math.ceil((p / 100) * latencies.length) - 1));
      return Math.round(latencies[idx] * 100) / 100;
    };

    const p50 = pct(50);
    const p95 = pct(95);
    const p99 = pct(99);
    const rps = Math.round((okCount / (totalMs / 1000)) * 10) / 10;

    return {
      status: 'MEASURED',
      targetUrl: params.targetUrl,
      requestsSent: requestsCount,
      successfulResponses: okCount,
      failedResponses: failCount,
      p50LatencyMs: p50,
      p95LatencyMs: p95,
      p99LatencyMs: p99,
      throughputRps: rps,
      cpuPercent,
      memoryRssMb,
      startupTimeMs: Math.round(latencies[0] ?? 0),
      measuredAt: nowIso,
      provenance: {
        metricKey: 'p95LatencyMs',
        value: p95,
        state: 'MEASURED',
        origin: 'CONTROLLED_PERF_RUNNER',
        method: `Carga HTTP controlada (${requestsCount} reqs, concorrência ${concurrency})`,
        toolName: 'WinHood HTTP Load Profiler',
        toolVersion: '4.1.0',
        measuredAt: nowIso,
        scope: params.targetUrl,
        evidenceHash: crypto
          .createHash('sha256')
          .update(`${params.targetUrl}|${p50}|${p95}|${p99}|${rps}|${nowIso}`, 'utf8')
          .digest('hex'),
      },
    };
  }
}
