import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import express from 'express';
import { EphemeralWorkspaceManager } from '../execution/EphemeralWorkspaceManager';
import { registerGracefulShutdown } from '../server/gracefulShutdown';
import {
  ALLOWED_SCANNER_TOOL_IDS,
  SCANNER_TOOL_CATALOG,
  type ScannerToolId,
  type ScannerToolJobOutput,
  type ToolCapabilityRecord,
} from './ScannerJobOrchestrator';

interface PinnedScannerRunnerSpec {
  toolId: ScannerToolId;
  binaryNames: string[];
  versionArgs: string[];
  buildArgs: (workspaceDir: string, outFilePath: string) => string[];
  outputFormat: 'JSON' | 'SARIF';
  readsFromFile?: boolean;
  validateParsedOutput: (parsed: unknown) => { valid: boolean; findingsCount: number };
  selfTestFiles: Record<string, string>;
}

const SAFE_WORKER_PATH =
  process.platform === 'win32'
    ? `${process.env.SystemRoot || 'C:\\Windows'}\\System32;${process.env.SystemRoot || 'C:\\Windows'}`
    : '/usr/local/bin:/usr/bin:/bin:/opt/winhood-scanners/bin';

function resolveAllowedBinary(binaryNames: string[]): string | null {
  const searchDirs =
    process.platform === 'win32'
      ? SAFE_WORKER_PATH.split(';')
      : [
          '/opt/winhood-scanners/bin',
          '/usr/local/bin',
          '/usr/bin',
          '/bin',
          path.join(process.cwd(), 'node_modules', '.bin'),
        ];

  for (const binName of binaryNames) {
    if (!/^[a-zA-Z0-9._-]+$/.test(binName)) continue;
    for (const dir of searchDirs) {
      const candidate = path.join(dir, process.platform === 'win32' ? `${binName}.exe` : binName);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
      if (process.platform === 'win32') {
        const cmdCandidate = path.join(dir, `${binName}.cmd`);
        if (fs.existsSync(cmdCandidate)) return cmdCandidate;
      }
    }
  }
  return null;
}

function buildSanitizedScannerEnv(workspaceDir: string): NodeJS.ProcessEnv {
  return {
    PATH: `${SAFE_WORKER_PATH}:${path.join(process.cwd(), 'node_modules', '.bin')}`,
    HOME: workspaceDir,
    TMPDIR: workspaceDir,
    TMP: workspaceDir,
    TEMP: workspaceDir,
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    NO_COLOR: '1',
    SEMGREP_SEND_METRICS: 'off',
    SEMGREP_ENABLE_VERSION_CHECK: '0',
    DO_NOT_TRACK: '1',
  };
}

const PINNED_SCANNER_SPECS: Record<ScannerToolId, PinnedScannerRunnerSpec> = {
  semgrep: {
    toolId: 'semgrep',
    binaryNames: ['semgrep', 'opengrep'],
    versionArgs: ['--version'],
    buildArgs: (ws) => ['scan', '--json', '--quiet', '--metrics=off', '--no-git-ignore', ws],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      const obj = p as { results?: unknown[] };
      return { valid: Boolean(obj && Array.isArray(obj.results)), findingsCount: obj?.results?.length ?? 0 };
    },
    selfTestFiles: { 'sample.js': 'const x = 1;\nexport default x;\n' },
  },
  codeql: {
    toolId: 'codeql',
    binaryNames: ['codeql'],
    versionArgs: ['version', '--format=terse'],
    buildArgs: (ws, outFile) => ['database', 'analyze', '--format=sarifv2.1.0', `--output=${outFile}`, '--no-download', ws],
    outputFormat: 'SARIF',
    readsFromFile: true,
    validateParsedOutput: (p) => {
      const obj = p as { version?: string; runs?: Array<{ results?: unknown[] }> };
      const valid = Boolean(obj && obj.version === '2.1.0' && Array.isArray(obj.runs));
      const findingsCount = valid
        ? (obj.runs || []).reduce((acc, r) => acc + (Array.isArray(r.results) ? r.results.length : 0), 0)
        : 0;
      return { valid, findingsCount };
    },
    selfTestFiles: { 'sample.js': 'export const ok = 1;\n' },
  },
  gitleaks: {
    toolId: 'gitleaks',
    binaryNames: ['gitleaks'],
    versionArgs: ['version'],
    buildArgs: (ws, outFile) => [
      'detect',
      '--no-git',
      '--source',
      ws,
      '--report-format',
      'json',
      '--report-path',
      outFile,
      '--exit-code',
      '0',
    ],
    outputFormat: 'JSON',
    readsFromFile: true,
    validateParsedOutput: (p) => ({
      valid: Array.isArray(p),
      findingsCount: Array.isArray(p) ? p.length : 0,
    }),
    selfTestFiles: { 'sample.txt': 'clean_config=true\n' },
  },
  eslint: {
    toolId: 'eslint',
    binaryNames: ['eslint'],
    versionArgs: ['--version'],
    buildArgs: (ws) => ['--format', 'json', '--no-error-on-unmatched-pattern', ws],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      if (!Array.isArray(p)) return { valid: false, findingsCount: 0 };
      const count = p.reduce(
        (acc, item) => acc + (Array.isArray((item as { messages?: unknown[] })?.messages) ? (item as { messages: unknown[] }).messages.length : 0),
        0
      );
      return { valid: true, findingsCount: count };
    },
    selfTestFiles: { 'sample.js': 'export const ok = 1;\n' },
  },
  ruff: {
    toolId: 'ruff',
    binaryNames: ['ruff'],
    versionArgs: ['--version'],
    buildArgs: (ws) => ['check', '--output-format', 'json', '--exit-zero', ws],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => ({
      valid: Array.isArray(p),
      findingsCount: Array.isArray(p) ? p.length : 0,
    }),
    selfTestFiles: { 'sample.py': 'def ok() -> int:\n    return 1\n' },
  },
  bandit: {
    toolId: 'bandit',
    binaryNames: ['bandit'],
    versionArgs: ['--version'],
    buildArgs: (ws) => ['-r', ws, '-f', 'json', '-q', '--exit-zero'],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      const obj = p as { results?: unknown[] };
      return { valid: Boolean(obj && Array.isArray(obj.results)), findingsCount: obj?.results?.length ?? 0 };
    },
    selfTestFiles: { 'sample.py': 'def ok():\n    return 1\n' },
  },
  roslyn: {
    toolId: 'roslyn',
    binaryNames: ['dotnet'],
    versionArgs: ['--version'],
    buildArgs: (ws, outFile) => [
      'build',
      ws,
      '--no-restore',
      '/p:TreatWarningsAsErrors=false',
      `/p:ErrorLog=${outFile},version=2.1`,
    ],
    outputFormat: 'SARIF',
    readsFromFile: true,
    validateParsedOutput: (p) => {
      const obj = p as { version?: string; runs?: Array<{ results?: unknown[] }> };
      return {
        valid: Boolean(obj && Array.isArray(obj.runs)),
        findingsCount: Array.isArray(obj?.runs)
          ? obj.runs.reduce((acc, r) => acc + (Array.isArray(r.results) ? r.results.length : 0), 0)
          : 0,
      };
    },
    selfTestFiles: { 'Sample.cs': 'public class Sample { public int Ok() => 1; }\n' },
  },
  spotbugs: {
    toolId: 'spotbugs',
    binaryNames: ['spotbugs'],
    versionArgs: ['-version'],
    buildArgs: (ws) => ['-textui', '-sarif', ws],
    outputFormat: 'SARIF',
    validateParsedOutput: (p) => {
      const obj = p as { runs?: unknown[] };
      return { valid: Boolean(obj && Array.isArray(obj.runs)), findingsCount: 0 };
    },
    selfTestFiles: { 'Sample.java': 'public class Sample { public int ok() { return 1; } }\n' },
  },
  checkstyle: {
    toolId: 'checkstyle',
    binaryNames: ['checkstyle'],
    versionArgs: ['--version'],
    buildArgs: (ws) => ['-c', '/google_checks.xml', '-f', 'sarif', ws],
    outputFormat: 'SARIF',
    validateParsedOutput: (p) => {
      const obj = p as { runs?: unknown[] };
      return { valid: Boolean(obj && Array.isArray(obj.runs)), findingsCount: 0 };
    },
    selfTestFiles: { 'Sample.java': 'public class Sample { public int ok() { return 1; } }\n' },
  },
  'osv-scanner': {
    toolId: 'osv-scanner',
    binaryNames: ['osv-scanner'],
    versionArgs: ['--version'],
    buildArgs: (ws) => ['scan', '--format=json', '--offline', '-r', ws],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      const obj = p as { results?: unknown[] };
      return { valid: Boolean(obj && Array.isArray(obj.results)), findingsCount: obj?.results?.length ?? 0 };
    },
    selfTestFiles: { 'package-lock.json': JSON.stringify({ name: 'selftest', lockfileVersion: 3, packages: {} }) },
  },
  syft: {
    toolId: 'syft',
    binaryNames: ['syft'],
    versionArgs: ['version'],
    buildArgs: (ws) => ['scan', `dir:${ws}`, '-o', 'cyclonedx-json'],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      const obj = p as { bomFormat?: string; components?: unknown[] };
      return {
        valid: obj?.bomFormat === 'CycloneDX',
        findingsCount: Array.isArray(obj?.components) ? obj.components.length : 0,
      };
    },
    selfTestFiles: { 'package.json': JSON.stringify({ name: 'selftest', version: '1.0.0' }) },
  },
  grype: {
    toolId: 'grype',
    binaryNames: ['grype'],
    versionArgs: ['version'],
    buildArgs: (ws) => [`dir:${ws}`, '-o', 'json'],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      const obj = p as { matches?: unknown[] };
      return { valid: Boolean(obj && Array.isArray(obj.matches)), findingsCount: obj?.matches?.length ?? 0 };
    },
    selfTestFiles: { 'package.json': JSON.stringify({ name: 'selftest', version: '1.0.0' }) },
  },
  trivy: {
    toolId: 'trivy',
    binaryNames: ['trivy'],
    versionArgs: ['--version'],
    buildArgs: (ws) => ['fs', '--format', 'json', '--offline-scan', '--quiet', ws],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      const obj = p as { Results?: unknown[] };
      return { valid: Boolean(obj && typeof obj === 'object'), findingsCount: obj?.Results?.length ?? 0 };
    },
    selfTestFiles: { 'package.json': JSON.stringify({ name: 'selftest', version: '1.0.0' }) },
  },
};

function detectBinaryVersion(binaryPath: string, versionArgs: string[]): string | null {
  try {
    const res = spawnSync(binaryPath, versionArgs, {
      shell: false,
      encoding: 'utf8',
      timeout: 4_000,
      env: { PATH: SAFE_WORKER_PATH, LANG: 'C.UTF-8' },
    });
    const combined = `${res.stdout || ''}\n${res.stderr || ''}`.trim();
    return combined ? combined.split(/\r?\n/)[0]?.trim() || null : null;
  } catch {
    return null;
  }
}

export async function runIsolatedScannerTool(params: {
  jobId: string;
  toolId: ScannerToolId;
  filesMap: Record<string, string>;
  timeoutMs: number;
  baseWorkspaceDir?: string;
}): Promise<ScannerToolJobOutput> {
  const spec = PINNED_SCANNER_SPECS[params.toolId];
  const binPath = resolveAllowedBinary(spec.binaryNames);
  if (!binPath) {
    return {
      toolId: params.toolId,
      state: 'NOT_INSTALLED',
      version: null,
      exitCode: null,
      durationMs: 0,
      outputFormat: spec.outputFormat,
      outputValidated: false,
      findingsCount: 0,
      rawOutputSha256: crypto.createHash('sha256').update(`NOT_INSTALLED:${params.toolId}`).digest('hex'),
      limitations: [`Binário (${spec.binaryNames.join(' / ')}) não instalado no container worker.`],
    };
  }

  const version = detectBinaryVersion(binPath, spec.versionArgs);
  const startMs = performance.now();

  const { result } = await EphemeralWorkspaceManager.withWorkspace(
    {
      jobId: `${params.jobId}-${params.toolId}`,
      filesMap: params.filesMap,
      baseDir: params.baseWorkspaceDir,
    },
    (ws) => {
      const outFilePath = path.join(ws.rootPath, `.winhood_${params.toolId}_out.json`);
      const args = spec.buildArgs(ws.rootPath, outFilePath);
      const env = buildSanitizedScannerEnv(ws.rootPath);

      const proc = spawnSync(binPath, args, {
        cwd: ws.rootPath,
        shell: false,
        encoding: 'utf8',
        timeout: Math.max(2_000, Math.min(180_000, params.timeoutMs)),
        maxBuffer: 12 * 1024 * 1024,
        env,
      });

      const durationMs = Math.max(1, Math.round(performance.now() - startMs));
      const timedOut = Boolean(proc.error && (proc.error as NodeJS.ErrnoException).code === 'ETIMEDOUT');
      if (timedOut) {
        return {
          toolId: params.toolId,
          state: 'TIMED_OUT' as const,
          version,
          exitCode: proc.status,
          durationMs,
          outputFormat: spec.outputFormat,
          outputValidated: false,
          findingsCount: 0,
          rawOutputSha256: crypto.createHash('sha256').update('TIMED_OUT').digest('hex'),
          limitations: [`Execução excedeu timeout de ${params.timeoutMs}ms.`],
          errorMessage: 'SCANNER_EXECUTION_TIMED_OUT',
        };
      }

      const rawOutput =
        spec.readsFromFile && fs.existsSync(outFilePath)
          ? fs.readFileSync(outFilePath, 'utf8')
          : proc.stdout || '';
      const rawOutputSha256 = crypto.createHash('sha256').update(rawOutput, 'utf8').digest('hex');

      if (!rawOutput.trim()) {
        return {
          toolId: params.toolId,
          state: proc.status === 0 ? ('COMPLETED' as const) : ('FAILED' as const),
          version,
          exitCode: proc.status,
          durationMs,
          outputFormat: spec.outputFormat,
          outputValidated: false,
          findingsCount: 0,
          rawOutputSha256,
          limitations: ['Saída vazia do analisador; resultado não pôde ser validado estruturalmente.'],
          errorMessage: proc.stderr?.slice(0, 400) || undefined,
        };
      }

      try {
        const parsed = JSON.parse(rawOutput);
        const validation = spec.validateParsedOutput(parsed);
        return {
          toolId: params.toolId,
          state: validation.valid ? ('COMPLETED' as const) : ('FAILED' as const),
          version,
          exitCode: proc.status,
          durationMs,
          outputFormat: spec.outputFormat,
          outputValidated: validation.valid,
          findingsCount: validation.findingsCount,
          rawOutputSha256,
          normalizedPayload: validation.valid ? parsed : undefined,
          limitations: validation.valid
            ? []
            : ['Saída JSON/SARIF produzida pelo analisador não atendeu ao esquema esperado.'],
        };
      } catch {
        return {
          toolId: params.toolId,
          state: 'FAILED' as const,
          version,
          exitCode: proc.status,
          durationMs,
          outputFormat: spec.outputFormat,
          outputValidated: false,
          findingsCount: 0,
          rawOutputSha256,
          limitations: ['Falha ao interpretar saída JSON/SARIF do analisador.'],
          errorMessage: (proc.stderr || rawOutput).slice(0, 400),
        };
      }
    }
  );

  return result;
}

/**
 * Probes every cataloged tool by actually executing it on a minimal ephemeral self-test file.
 * A tool is NEVER marked `OPERATIONAL` solely because its binary exists on PATH.
 */
export async function probeVerifiedWorkerCapabilities(
  baseWorkspaceDir?: string
): Promise<ToolCapabilityRecord[]> {
  const isContainerizedWorker =
    process.env.WINHOOD_SCANNER_WORKER_CONTAINER === 'true' || fs.existsSync('/.dockerenv');
  const results: ToolCapabilityRecord[] = [];

  for (const catalogEntry of SCANNER_TOOL_CATALOG) {
    const spec = PINNED_SCANNER_SPECS[catalogEntry.toolId];
    const binPath = resolveAllowedBinary(spec.binaryNames);
    const checkedAt = new Date().toISOString();

    if (!binPath) {
      results.push({
        toolId: catalogEntry.toolId,
        displayName: catalogEntry.displayName,
        purpose: catalogEntry.purpose,
        binaryNames: [...catalogEntry.binaryNames],
        installed: false,
        version: null,
        executionEnvironment: isContainerizedWorker ? 'DOCKER_SCANNER_WORKER' : 'UNAVAILABLE',
        isolationAvailable: isContainerizedWorker,
        executionPerformed: false,
        outputValidated: false,
        limitations: ['Ferramenta não instalada nesta imagem de worker.'],
        finalState: 'NOT_INSTALLED',
        checkedAt,
      });
      continue;
    }

    const version = detectBinaryVersion(binPath, spec.versionArgs);
    if (!isContainerizedWorker && process.env.WINHOOD_ALLOW_WORKER_SELFTEST_HOST !== 'true') {
      results.push({
        toolId: catalogEntry.toolId,
        displayName: catalogEntry.displayName,
        purpose: catalogEntry.purpose,
        binaryNames: [...catalogEntry.binaryNames],
        installed: true,
        version,
        executionEnvironment: 'UNAVAILABLE',
        isolationAvailable: false,
        executionPerformed: false,
        outputValidated: false,
        limitations: [
          'Binário detectado, porém isolamento de container worker não está ativo; execução bloqueada.',
        ],
        finalState: 'BLOCKED',
        checkedAt,
      });
      continue;
    }

    const probeRun = await runIsolatedScannerTool({
      jobId: `selftest-${catalogEntry.toolId}`,
      toolId: catalogEntry.toolId,
      filesMap: spec.selfTestFiles,
      timeoutMs: 12_000,
      baseWorkspaceDir,
    });

    const operational = probeRun.state === 'COMPLETED' && probeRun.outputValidated;
    results.push({
      toolId: catalogEntry.toolId,
      displayName: catalogEntry.displayName,
      purpose: catalogEntry.purpose,
      binaryNames: [...catalogEntry.binaryNames],
      installed: true,
      version: probeRun.version || version,
      executionEnvironment: isContainerizedWorker ? 'DOCKER_SCANNER_WORKER' : 'OS_SANDBOX_SUBPROCESS',
      isolationAvailable: isContainerizedWorker,
      executionPerformed: true,
      outputValidated: probeRun.outputValidated,
      limitations: probeRun.limitations,
      finalState: operational ? 'OPERATIONAL' : 'EXECUTION_FAILED',
      checkedAt,
    });
  }

  return results;
}

export function createScannerWorkerApp(options?: {
  workerToken?: string;
  baseWorkspaceDir?: string;
}): express.Express {
  const app = express();
  const expectedToken = (
    options?.workerToken ??
    process.env.WINHOOD_SCANNER_WORKER_TOKEN ??
    ''
  ).trim();

  if (process.env.NODE_ENV === 'production' && expectedToken.length < 24) {
    throw new Error(
      'SCANNER_WORKER_TOKEN_REQUIRED: WINHOOD_SCANNER_WORKER_TOKEN (>= 24 caracteres) é obrigatório em produção.'
    );
  }

  app.disable('x-powered-by');
  app.use(express.json({ limit: '50mb' }));

  // Healthcheck (no secrets exposed)
  app.get('/worker/health', (_req, res) => {
    res.json({
      status: 'ONLINE',
      service: 'winhood-scanner-worker',
      nonRootUid: typeof process.getuid === 'function' ? process.getuid() : null,
      activeWorkspaces: EphemeralWorkspaceManager.getActiveWorkspaceCount(),
      timestamp: new Date().toISOString(),
    });
  });

  // Authenticate all operational worker routes via constant-time Bearer check
  app.use((req, res, next) => {
    if (!expectedToken) return next();
    const authHeader = String(req.headers.authorization || '');
    const provided = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const a = Buffer.from(provided, 'utf8');
    const b = Buffer.from(expectedToken, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(401).json({ error: 'WORKER_UNAUTHORIZED' });
    }
    return next();
  });

  app.get('/worker/capabilities', async (_req, res) => {
    const capabilities = await probeVerifiedWorkerCapabilities(options?.baseWorkspaceDir);
    res.json({
      service: 'winhood-scanner-worker',
      checkedAt: new Date().toISOString(),
      capabilities,
    });
  });

  app.post('/worker/execute', async (req, res) => {
    const body = req.body as {
      jobId?: string;
      toolIds?: string[];
      filesMap?: Record<string, string>;
      timeoutMs?: number;
    };
    const jobId = String(body?.jobId || `job-${crypto.randomUUID()}`).replace(/[^a-zA-Z0-9_-]/g, '_');
    const rawToolIds = Array.isArray(body?.toolIds) ? body.toolIds : [];
    const validToolIds = rawToolIds.filter((t): t is ScannerToolId =>
      ALLOWED_SCANNER_TOOL_IDS.has(t as ScannerToolId)
    );
    if (validToolIds.length === 0) {
      return res.status(400).json({ error: 'INVALID_TOOL_IDS' });
    }
    if (!body?.filesMap || typeof body.filesMap !== 'object' || Array.isArray(body.filesMap)) {
      return res.status(400).json({ error: 'INVALID_FILES_MAP' });
    }
    const timeoutMs = Math.max(2_000, Math.min(180_000, Number(body.timeoutMs) || 30_000));

    const results: ScannerToolJobOutput[] = [];
    for (const toolId of validToolIds) {
      const out = await runIsolatedScannerTool({
        jobId,
        toolId,
        filesMap: body.filesMap,
        timeoutMs,
        baseWorkspaceDir: options?.baseWorkspaceDir,
      });
      results.push(out);
    }

    return res.json({
      jobId,
      completedAt: new Date().toISOString(),
      results,
    });
  });

  return app;
}

export async function startScannerWorkerServer(options?: {
  host?: string;
  port?: number;
  workerToken?: string;
  baseWorkspaceDir?: string;
}): Promise<{ server: http.Server; port: number; url: string; close: () => Promise<void> }> {
  const app = createScannerWorkerApp({
    workerToken: options?.workerToken,
    baseWorkspaceDir: options?.baseWorkspaceDir,
  });
  const host = options?.host || process.env.WINHOOD_WORKER_BIND_HOST || '127.0.0.1';
  const port = options?.port ?? Number(process.env.WINHOOD_WORKER_PORT || 4100);

  const server = await new Promise<http.Server>((resolve, reject) => {
    const srv = app.listen(port, host, () => resolve(srv));
    srv.once('error', reject);
  });

  const addr = server.address();
  const effectivePort = typeof addr === 'object' && addr ? addr.port : port;
  const isMain =
    typeof process !== 'undefined' &&
    Array.isArray(process.argv) &&
    Boolean(process.argv[1]) &&
    /scanner[-_]worker/i.test(process.argv[1]!);

  const shutdownController = registerGracefulShutdown({
    server,
    onAfterClose: () => {
      EphemeralWorkspaceManager.cleanupAllActiveWorkspaces();
    },
    signals: isMain ? ['SIGINT', 'SIGTERM'] : [],
    exitProcess: isMain,
    enableIpcShutdown: isMain,
  });

  return {
    server,
    port: effectivePort,
    url: `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${effectivePort}`,
    close: async () => {
      shutdownController.unregister();
      await shutdownController.shutdown('WORKER_CLOSE');
    },
  };
}

const isWorkerEntrypoint =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  Boolean(process.argv[1]) &&
  /scanner[-_]worker/i.test(process.argv[1]!);

if (isWorkerEntrypoint) {
  startScannerWorkerServer({
    host: process.env.WINHOOD_WORKER_BIND_HOST || '0.0.0.0',
    port: Number(process.env.WINHOOD_WORKER_PORT || 4100),
  })
    .then(({ port }) => {
      console.log(`[WinHood Scanner Worker] Listening on internal port ${port}`);
    })
    .catch((err) => {
      console.error('[WinHood Scanner Worker] Fatal startup error:', err);
      process.exit(1);
    });
}
