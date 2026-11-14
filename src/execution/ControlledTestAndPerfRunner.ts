import crypto from 'node:crypto';
import type {
  ExecutionSandboxControl,
  IsolationLifecycleState,
  MetricProvenanceRecord,
  ParsedCoverageReportSummary,
} from '../types/benchmark';
import { CoverageReportParser } from './CoverageReportParser';
import { SandboxExecutor } from './SandboxExecutor';
import { type AuthorizedPerfTarget, SsrfGuard } from './SsrfGuard';

export interface ControlledTestExecutionResult {
  executed: boolean;
  blocked: boolean;
  runnerUsed: string;
  isolationMode: ExecutionSandboxControl['isolationMode'];
  isolationState: IsolationLifecycleState;
  recoveryVerified: boolean;
  exitCode: number | null;
  testsTotal: number;
  testsPassed: number;
  testsFailed: number;
  durationMs: number | null;
  stdoutSnippet: string;
  stderrSnippet: string;
  coverageReport: ParsedCoverageReportSummary;
  limitations: string[];
  provenance: MetricProvenanceRecord;
}

export interface AgentRunnerMetrics {
  runnerCpuPercent: number;
  runnerMemoryRssMb: number;
  probeTimeMs: number;
}

export interface TargetProcessMetrics {
  cpuPercent: number | null;
  memoryRssMb: number | null;
  startupTimeMs: number | null;
  instrumentationMethod: 'NOT_MONITORED_REMOTE_HTTP' | 'OS_PROCESS_INSTRUMENTED';
}

export interface ControlledPerfMeasurementResult {
  status: 'MEASURED' | 'BLOCKED_SSRF' | 'NOT_MEASURED' | 'FAILED';
  reason?: string;
  targetUrl?: string;
  ssrfBlocked?: boolean;
  requestsSent: number;
  successfulResponses: number;
  httpErrorCount: number;
  timeoutCount: number;
  failedResponses: number;
  p50LatencyMs: number | null;
  p95LatencyMs: number | null;
  p99LatencyMs: number | null;
  throughputRps: number | null;
  agentMetrics: AgentRunnerMetrics;
  targetMetrics: TargetProcessMetrics;
  // Kept for backwards schema checks where null indicates unmeasured target telemetry
  cpuPercent: number | null;
  memoryRssMb: number | null;
  startupTimeMs: number | null;
  measuredAt: string;
  provenance: MetricProvenanceRecord;
}

export class ControlledTestAndPerfRunner {
  /**
   * Executa testes do projeto EXCLUSIVAMENTE dentro do SandboxExecutor isolado
   * (Docker rootless / bwrap / Node --permission + env mínimo sanitizado + cleanup verificado).
   * Nunca recorre a execução direta no host se não houver mecanismo real de isolamento.
   */
  public static runIsolatedTestSuite(params: {
    softwareName: string;
    filesMap: Record<string, string>;
    timeoutMs?: number;
  }): ControlledTestExecutionResult {
    const timeoutMs = params.timeoutMs ?? 25000;
    const filesMap = params.filesMap || {};
    const testFiles = Object.keys(filesMap).filter((p) =>
      /\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs|py|java|cs|go)$/i.test(p)
    );
    const existingCoverage = CoverageReportParser.parseFromFilesMap(filesMap);
    const probe = SandboxExecutor.probeHostIsolation();

    if (testFiles.length === 0) {
      return {
        executed: false,
        blocked: false,
        runnerUsed: 'NONE',
        isolationMode: probe.isolationMode,
        isolationState: 'NOT_INITIALIZED',
        recoveryVerified: false,
        exitCode: null,
        testsTotal: 0,
        testsPassed: 0,
        testsFailed: 0,
        durationMs: null,
        stdoutSnippet: '',
        stderrSnippet: 'Nenhum arquivo de teste (*.test.* / *.spec.*) encontrado no pacote.',
        coverageReport: existingCoverage,
        limitations: [],
        provenance: {
          metricKey: 'functionalTestsTotal',
          value: 0,
          state: 'NOT_MEASURED',
          origin: 'CONTROLLED_TEST_RUNNER',
          method: 'Nenhum arquivo de teste encontrado no pacote submetido.',
          toolName: 'WinHood ControlledTestAndPerfRunner',
          toolVersion: '4.2.0',
          measuredAt: new Date().toISOString(),
          scope: params.softwareName,
        },
      };
    }

    const runnableJsTests = testFiles.filter((f) => /\.(js|mjs|cjs)$/i.test(f));
    if (runnableJsTests.length > 0) {
      const sandboxRes = SandboxExecutor.runSandboxedNodeTestWithRecovery({
        filesMap,
        testFiles: runnableJsTests,
        timeoutMs,
      });

      if (sandboxRes.blocked) {
        return {
          executed: false,
          blocked: true,
          runnerUsed: 'BLOCKED_NO_SANDBOX',
          isolationMode: sandboxRes.isolationMode,
          isolationState: sandboxRes.isolationState,
          recoveryVerified: sandboxRes.recoveryVerified,
          exitCode: null,
          testsTotal: 0,
          testsPassed: 0,
          testsFailed: 0,
          durationMs: sandboxRes.durationMs,
          stdoutSnippet: '',
          stderrSnippet: sandboxRes.stderr,
          coverageReport: existingCoverage,
          limitations: sandboxRes.limitations,
          provenance: {
            metricKey: 'functionalTestsTotal',
            value: null,
            state: 'FAILED',
            origin: 'CONTROLLED_TEST_RUNNER',
            method: sandboxRes.stderr,
            toolName: 'WinHood SandboxExecutor',
            toolVersion: '4.2.0',
            measuredAt: sandboxRes.completedAt,
            scope: params.softwareName,
          },
        };
      }

      const output = `${sandboxRes.stdout}\n${sandboxRes.stderr}`;
      const passMatch = output.match(/^[#ℹ]\s*pass\s+(\d+)/im);
      const failMatch = output.match(/^[#ℹ]\s*fail\s+(\d+)/im);
      const testsMatch = output.match(/^[#ℹ]\s*tests\s+(\d+)/im);
      const passed = passMatch
        ? Number(passMatch[1])
        : (output.match(/^ok\s+\d+\s+-/gm) || []).length;
      const failed = failMatch
        ? Number(failMatch[1])
        : (output.match(/^not ok\s+\d+\s+-/gm) || []).length;
      const total = testsMatch ? Number(testsMatch[1]) : passed + failed;

      const executedCleanly = sandboxRes.executed && total > 0;
      return {
        executed: executedCleanly,
        blocked: false,
        runnerUsed: `node --test (${sandboxRes.isolationMode})`,
        isolationMode: sandboxRes.isolationMode,
        isolationState: sandboxRes.isolationState,
        recoveryVerified: sandboxRes.recoveryVerified,
        exitCode: sandboxRes.exitCode,
        testsTotal: total,
        testsPassed: passed,
        testsFailed: failed,
        durationMs: sandboxRes.durationMs,
        stdoutSnippet: sandboxRes.stdout.slice(0, 1200),
        stderrSnippet: sandboxRes.stderr.slice(0, 800),
        coverageReport: existingCoverage,
        limitations: sandboxRes.limitations,
        provenance: {
          metricKey: 'functionalTestsTotal',
          value: total,
          state: executedCleanly ? 'MEASURED' : 'INCONCLUSIVE',
          origin: 'CONTROLLED_TEST_RUNNER',
          method: executedCleanly
            ? `Execução isolada (${sandboxRes.isolationMode}, cleanup=${sandboxRes.recoveryVerified}): ${passed}/${total} aprovados em ${sandboxRes.durationMs}ms`
            : 'Execução em sandbox finalizada sem casos TAP contabilizáveis ou com timeout.',
          toolName: `SandboxExecutor (${sandboxRes.isolationMode})`,
          toolVersion: process.version,
          measuredAt: sandboxRes.completedAt,
          scope: `${runnableJsTests.length} arquivo(s) de teste JS/MJS/CJS`,
          evidenceHash: sandboxRes.stdoutSha256,
        },
      };
    }

    return {
      executed: false,
      blocked: !probe.dockerAvailable && !probe.bwrapAvailable,
      runnerUsed: 'UNAVAILABLE_FOR_TARGET_LANGUAGE',
      isolationMode: probe.isolationMode,
      isolationState: 'ISOLATION_CONFIGURED',
      recoveryVerified: false,
      exitCode: null,
      testsTotal: 0,
      testsPassed: 0,
      testsFailed: 0,
      durationMs: null,
      stdoutSnippet: '',
      stderrSnippet:
        'Execução segura de testes TS/Python/Java/C#/Go requer container Docker ou runtime isolado da linguagem alvo (não disponível neste host).',
      coverageReport: existingCoverage,
      limitations: [
        `Arquivos de teste presentes (${testFiles.length}), mas nenhum runner isolado seguro disponível para esta linguagem neste host.`,
      ],
      provenance: {
        metricKey: 'functionalTestsTotal',
        value: null,
        state: 'NOT_MEASURED',
        origin: 'CONTROLLED_TEST_RUNNER',
        method: 'Arquivos de teste encontrados, porém sem container/runtime isolado compatível com o ecossistema alvo.',
        toolName: 'WinHood ControlledTestAndPerfRunner',
        toolVersion: '4.2.0',
        measuredAt: new Date().toISOString(),
        scope: testFiles.join(', '),
      },
    };
  }

  /**
   * Executa medição real de latência P50/P95/P99 e throughput RPS com proteção SSRF (SsrfGuard):
   * - Bloqueia RFC1918, loopback, link-local, metadata, IPv6 privados e redirects maliciosos.
   * - Separa métricas do agente medidor (runnerCpuPercent, runnerMemoryRssMb) das métricas do software alvo
   *   (cpuPercent, memoryRssMb, startupTimeMs = null/NOT_MEASURED sem telemetria OS do processo alvo).
   */
  public static async measureHttpWorkload(params: {
    targetUrl: string;
    requestsCount?: number;
    concurrency?: number;
    timeoutMs?: number;
    authorizedTargets?: AuthorizedPerfTarget[];
    requireRegisteredTarget?: boolean;
    allowExplicitLoopback?: boolean;
  }): Promise<ControlledPerfMeasurementResult> {
    const requestsCount = Math.max(5, Math.min(200, params.requestsCount ?? 25));
    const concurrency = Math.max(1, Math.min(20, params.concurrency ?? 5));
    const timeoutMs = params.timeoutMs ?? 4000;
    const nowIso = new Date().toISOString();

    const emptyTargetMetrics: TargetProcessMetrics = {
      cpuPercent: null,
      memoryRssMb: null,
      startupTimeMs: null,
      instrumentationMethod: 'NOT_MONITORED_REMOTE_HTTP',
    };

    if (!params.targetUrl || !/^https?:\/\//i.test(params.targetUrl)) {
      return {
        status: 'NOT_MEASURED',
        reason: 'URL HTTP/HTTPS alvo válida não informada para medição controlada de runtime.',
        requestsSent: 0,
        successfulResponses: 0,
        httpErrorCount: 0,
        timeoutCount: 0,
        failedResponses: 0,
        p50LatencyMs: null,
        p95LatencyMs: null,
        p99LatencyMs: null,
        throughputRps: null,
        agentMetrics: {
          runnerCpuPercent: 0,
          runnerMemoryRssMb: Math.round((process.memoryUsage().rss / (1024 * 1024)) * 10) / 10,
          probeTimeMs: 0,
        },
        targetMetrics: emptyTargetMetrics,
        cpuPercent: null,
        memoryRssMb: null,
        startupTimeMs: null,
        measuredAt: nowIso,
        provenance: {
          metricKey: 'p95LatencyMs',
          value: null,
          state: 'NOT_MEASURED',
          origin: 'CONTROLLED_PERF_RUNNER',
          method: 'Medição HTTP não executada sem endpoint alvo.',
          toolName: 'WinHood ControlledTestAndPerfRunner',
          toolVersion: '4.2.0',
          measuredAt: nowIso,
          scope: 'runtime',
        },
      };
    }

    // Enforce SSRF policy BEFORE dispatching any network request
    const ssrfValidation = await SsrfGuard.validateUrl({
      targetUrl: params.targetUrl,
      authorizedTargets: params.authorizedTargets,
      requireRegisteredTarget: params.requireRegisteredTarget,
      allowExplicitLoopback: params.allowExplicitLoopback,
    });

    if (!ssrfValidation.allowed) {
      return {
        status: 'BLOCKED_SSRF',
        reason: ssrfValidation.reason,
        targetUrl: params.targetUrl,
        ssrfBlocked: true,
        requestsSent: 0,
        successfulResponses: 0,
        httpErrorCount: 0,
        timeoutCount: 0,
        failedResponses: 0,
        p50LatencyMs: null,
        p95LatencyMs: null,
        p99LatencyMs: null,
        throughputRps: null,
        agentMetrics: {
          runnerCpuPercent: 0,
          runnerMemoryRssMb: Math.round((process.memoryUsage().rss / (1024 * 1024)) * 10) / 10,
          probeTimeMs: 0,
        },
        targetMetrics: emptyTargetMetrics,
        cpuPercent: null,
        memoryRssMb: null,
        startupTimeMs: null,
        measuredAt: nowIso,
        provenance: {
          metricKey: 'p95LatencyMs',
          value: null,
          state: 'FAILED',
          origin: 'CONTROLLED_PERF_RUNNER',
          method: `Bloqueado por SsrfGuard: ${ssrfValidation.reason}`,
          toolName: 'WinHood SsrfGuard',
          toolVersion: '4.2.0',
          measuredAt: nowIso,
          scope: params.targetUrl,
        },
      };
    }

    const latencies: number[] = [];
    let okCount = 0;
    let httpErrorCount = 0;
    let timeoutCount = 0;
    let ssrfRedirectBlocked = false;
    let ssrfBlockReason = '';

    const cpuStart = process.cpuUsage();
    const overallStart = performance.now();

    let nextIndex = 0;
    const workerFn = async () => {
      while (nextIndex < requestsCount) {
        const idx = nextIndex++;
        void idx;
        try {
          const resp = await SsrfGuard.pinnedSafeRequest({
            targetUrl: params.targetUrl,
            authorizedTargets: params.authorizedTargets,
            requireRegisteredTarget: params.requireRegisteredTarget,
            allowExplicitLoopback: params.allowExplicitLoopback,
            timeoutMs,
            maxRedirects: 3,
          });
          latencies.push(resp.latencyMs);
          if (resp.ok) okCount += 1;
          else httpErrorCount += 1;
        } catch (err: any) {
          const msg = err?.message || '';
          if (msg.startsWith('SSRF_BLOCKED:')) {
            ssrfRedirectBlocked = true;
            ssrfBlockReason = msg;
          } else {
            timeoutCount += 1;
          }
        }
      }
    };

    await Promise.all(Array.from({ length: concurrency }, () => workerFn()));

    const totalMs = Math.max(1, performance.now() - overallStart);
    const cpuDelta = process.cpuUsage(cpuStart);
    const cpuTimeMs = (cpuDelta.user + cpuDelta.system) / 1000;
    const runnerCpuPercent = Math.min(100, Math.round((cpuTimeMs / totalMs) * 1000) / 10);
    const runnerMemoryRssMb = Math.round((process.memoryUsage().rss / (1024 * 1024)) * 10) / 10;

    const agentMetrics: AgentRunnerMetrics = {
      runnerCpuPercent,
      runnerMemoryRssMb,
      probeTimeMs: Math.round(totalMs),
    };

    if (ssrfRedirectBlocked) {
      return {
        status: 'BLOCKED_SSRF',
        reason: ssrfBlockReason || 'Redirecionamento bloqueado pela política SSRF.',
        targetUrl: params.targetUrl,
        ssrfBlocked: true,
        requestsSent: requestsCount,
        successfulResponses: okCount,
        httpErrorCount,
        timeoutCount,
        failedResponses: httpErrorCount + timeoutCount,
        p50LatencyMs: null,
        p95LatencyMs: null,
        p99LatencyMs: null,
        throughputRps: null,
        agentMetrics,
        targetMetrics: emptyTargetMetrics,
        cpuPercent: null,
        memoryRssMb: null,
        startupTimeMs: null,
        measuredAt: nowIso,
        provenance: {
          metricKey: 'p95LatencyMs',
          value: null,
          state: 'FAILED',
          origin: 'CONTROLLED_PERF_RUNNER',
          method: ssrfBlockReason,
          toolName: 'WinHood SsrfGuard',
          toolVersion: '4.2.0',
          measuredAt: nowIso,
          scope: params.targetUrl,
        },
      };
    }

    if (latencies.length === 0) {
      return {
        status: 'FAILED',
        reason: `Nenhuma requisição HTTP obteve resposta em ${params.targetUrl} (${timeoutCount} timeout/erro de conexão).`,
        targetUrl: params.targetUrl,
        requestsSent: requestsCount,
        successfulResponses: 0,
        httpErrorCount,
        timeoutCount,
        failedResponses: httpErrorCount + timeoutCount,
        p50LatencyMs: null,
        p95LatencyMs: null,
        p99LatencyMs: null,
        throughputRps: null,
        agentMetrics,
        targetMetrics: emptyTargetMetrics,
        cpuPercent: null,
        memoryRssMb: null,
        startupTimeMs: null,
        measuredAt: nowIso,
        provenance: {
          metricKey: 'p95LatencyMs',
          value: null,
          state: 'FAILED',
          origin: 'CONTROLLED_PERF_RUNNER',
          method: `Falha ao conectar em ${params.targetUrl}`,
          toolName: 'WinHood ControlledTestAndPerfRunner',
          toolVersion: '4.2.0',
          measuredAt: nowIso,
          scope: params.targetUrl,
        },
      };
    }

    latencies.sort((a, b) => a - b);
    const pct = (p: number) => {
      const idx = Math.min(latencies.length - 1, Math.max(0, Math.ceil((p / 100) * latencies.length) - 1));
      return Math.round(latencies[idx]! * 100) / 100;
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
      httpErrorCount,
      timeoutCount,
      failedResponses: httpErrorCount + timeoutCount,
      p50LatencyMs: p50,
      p95LatencyMs: p95,
      p99LatencyMs: p99,
      throughputRps: rps,
      agentMetrics,
      targetMetrics: emptyTargetMetrics,
      // CPU/RSS/startup of the evaluated target process remain null unless instrumented locally;
      // runner's own CPU/RSS are strictly isolated inside `agentMetrics`.
      cpuPercent: null,
      memoryRssMb: null,
      startupTimeMs: null,
      measuredAt: nowIso,
      provenance: {
        metricKey: 'p95LatencyMs',
        value: p95,
        state: 'MEASURED',
        origin: 'CONTROLLED_PERF_RUNNER',
        method: `Carga HTTP controlada c/ IP pinado (${requestsCount} reqs, concorrência ${concurrency}); telemetria CPU/RAM do alvo = NOT_MEASURED.`,
        toolName: 'WinHood HTTP Load Profiler (SSRF-Safe)',
        toolVersion: '4.2.0',
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
