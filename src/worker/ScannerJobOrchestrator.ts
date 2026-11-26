import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { SandboxExecutor } from '../execution/SandboxExecutor';

export type ScannerToolId =
  | 'semgrep'
  | 'codeql'
  | 'gitleaks'
  | 'eslint'
  | 'ruff'
  | 'bandit'
  | 'roslyn'
  | 'spotbugs'
  | 'checkstyle'
  | 'osv-scanner'
  | 'syft'
  | 'grype'
  | 'trivy';

export type ScannerJobState =
  | 'QUEUED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED'
  | 'TIMED_OUT'
  | 'BLOCKED';

export type ToolCapabilityFinalState =
  | 'OPERATIONAL'
  | 'BLOCKED'
  | 'NOT_INSTALLED'
  | 'INSTALLED_UNVERIFIED'
  | 'EXECUTION_FAILED';

export interface ToolCapabilityRecord {
  toolId: ScannerToolId;
  displayName: string;
  purpose: string;
  binaryNames: string[];
  installed: boolean;
  version: string | null;
  executionEnvironment: 'DOCKER_SCANNER_WORKER' | 'OS_SANDBOX_SUBPROCESS' | 'UNAVAILABLE';
  isolationAvailable: boolean;
  executionPerformed: boolean;
  outputValidated: boolean;
  limitations: string[];
  finalState: ToolCapabilityFinalState;
  checkedAt: string;
}

export interface ScannerJobRequest {
  projectId?: string;
  softwareId?: string;
  toolIds: ScannerToolId[];
  filesMap: Record<string, string>;
  timeoutMs?: number;
  maxRetries?: number;
}

export interface ScannerToolJobOutput {
  toolId: ScannerToolId;
  state: 'COMPLETED' | 'BLOCKED' | 'NOT_INSTALLED' | 'FAILED' | 'TIMED_OUT';
  version: string | null;
  exitCode: number | null;
  durationMs: number;
  outputFormat: 'SARIF' | 'JSON' | 'TEXT';
  outputValidated: boolean;
  findingsCount: number;
  rawOutputSha256: string;
  normalizedPayload?: unknown;
  limitations: string[];
  errorMessage?: string;
}

export interface ScannerJobRecord {
  jobId: string;
  projectId: string | null;
  softwareId: string | null;
  toolIds: ScannerToolId[];
  state: ScannerJobState;
  executionBackend: 'DOCKER_SCANNER_WORKER' | 'LOCAL_ISOLATION_PROBE' | 'BLOCKED_NO_ISOLATION';
  inputSha256: string;
  outputSha256: string | null;
  fileCount: number;
  attemptCount: number;
  maxRetries: number;
  timeoutMs: number;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  durationMs: number | null;
  cancelRequested: boolean;
  recoveredFromInterruption: boolean;
  results: ScannerToolJobOutput[];
  errorMessage: string | null;
}

export interface ScannerToolCatalogSpec {
  toolId: ScannerToolId;
  displayName: string;
  purpose: string;
  binaryNames: string[];
  outputFormat: 'SARIF' | 'JSON';
  expectedExtensions: string[];
}

export const SCANNER_TOOL_CATALOG: readonly ScannerToolCatalogSpec[] = [
  {
    toolId: 'semgrep',
    displayName: 'Semgrep / Opengrep',
    purpose: 'SAST (Multi-language semantic rules)',
    binaryNames: ['semgrep', 'opengrep'],
    outputFormat: 'JSON',
    expectedExtensions: ['.ts', '.tsx', '.js', '.jsx', '.py', '.java', '.go', '.cs', '.rs'],
  },
  {
    toolId: 'codeql',
    displayName: 'CodeQL CLI',
    purpose: 'Semantic Taint & Dataflow Analysis',
    binaryNames: ['codeql'],
    outputFormat: 'SARIF',
    expectedExtensions: ['.ts', '.tsx', '.js', '.jsx', '.py', '.java', '.go', '.cs'],
  },
  {
    toolId: 'gitleaks',
    displayName: 'Gitleaks',
    purpose: 'Secrets Detection',
    binaryNames: ['gitleaks'],
    outputFormat: 'JSON',
    expectedExtensions: ['*'],
  },
  {
    toolId: 'eslint',
    displayName: 'ESLint',
    purpose: 'JavaScript / TypeScript Quality & Security',
    binaryNames: ['eslint'],
    outputFormat: 'JSON',
    expectedExtensions: ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'],
  },
  {
    toolId: 'ruff',
    displayName: 'Ruff',
    purpose: 'Python Quality & Lint',
    binaryNames: ['ruff'],
    outputFormat: 'JSON',
    expectedExtensions: ['.py'],
  },
  {
    toolId: 'bandit',
    displayName: 'Bandit',
    purpose: 'Python SAST Security',
    binaryNames: ['bandit'],
    outputFormat: 'JSON',
    expectedExtensions: ['.py'],
  },
  {
    toolId: 'roslyn',
    displayName: 'Roslyn Analyzers (.NET)',
    purpose: '.NET / C# Static Analysis',
    binaryNames: ['dotnet'],
    outputFormat: 'SARIF',
    expectedExtensions: ['.cs', '.csproj'],
  },
  {
    toolId: 'spotbugs',
    displayName: 'SpotBugs',
    purpose: 'Java Security & Bug Analysis',
    binaryNames: ['spotbugs'],
    outputFormat: 'SARIF',
    expectedExtensions: ['.java'],
  },
  {
    toolId: 'checkstyle',
    displayName: 'Checkstyle',
    purpose: 'Java Code Quality & Style',
    binaryNames: ['checkstyle'],
    outputFormat: 'SARIF',
    expectedExtensions: ['.java'],
  },
  {
    toolId: 'osv-scanner',
    displayName: 'OSV-Scanner',
    purpose: 'SCA Dependency Vulnerability Scanning',
    binaryNames: ['osv-scanner'],
    outputFormat: 'JSON',
    expectedExtensions: ['package-lock.json', 'requirements.txt', 'go.mod', 'Cargo.lock', 'pom.xml'],
  },
  {
    toolId: 'syft',
    displayName: 'Syft',
    purpose: 'SBOM Generation (CycloneDX / SPDX)',
    binaryNames: ['syft'],
    outputFormat: 'JSON',
    expectedExtensions: ['*'],
  },
  {
    toolId: 'grype',
    displayName: 'Grype',
    purpose: 'SBOM & Dependency Vulnerability Matching',
    binaryNames: ['grype'],
    outputFormat: 'JSON',
    expectedExtensions: ['*'],
  },
  {
    toolId: 'trivy',
    displayName: 'Trivy',
    purpose: 'SCA / IaC / Container Misconfiguration Scanning',
    binaryNames: ['trivy'],
    outputFormat: 'JSON',
    expectedExtensions: ['*'],
  },
] as const;

export const ALLOWED_SCANNER_TOOL_IDS = new Set<ScannerToolId>(
  SCANNER_TOOL_CATALOG.map((s) => s.toolId)
);

function computeCanonicalFilesSha256(filesMap: Record<string, string>): string {
  const hash = crypto.createHash('sha256');
  const sortedKeys = Object.keys(filesMap || {}).sort((a, b) => a.localeCompare(b));
  for (const key of sortedKeys) {
    hash.update(key, 'utf8');
    hash.update('\0', 'utf8');
    hash.update(String(filesMap[key] ?? ''), 'utf8');
    hash.update('\n', 'utf8');
  }
  return hash.digest('hex');
}

function sha256Json(payload: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(payload), 'utf8').digest('hex');
}

export interface ScannerWorkerRemoteExecutor {
  executeJob: (params: {
    jobId: string;
    toolIds: ScannerToolId[];
    filesMap: Record<string, string>;
    timeoutMs: number;
    signal: AbortSignal;
  }) => Promise<ScannerToolJobOutput[]>;
  fetchCapabilities: () => Promise<ToolCapabilityRecord[]>;
}

export interface ScannerJobOrchestratorOptions {
  dataDir?: string;
  maxConcurrency?: number;
  defaultTimeoutMs?: number;
  workerUrl?: string;
  workerToken?: string;
  remoteExecutor?: ScannerWorkerRemoteExecutor;
}

/**
 * ScannerJobOrchestrator (Phase P0)
 *
 * Manages asynchronous, bounded-concurrency execution of external security/quality scanners:
 * - Dispatches jobs exclusively to the isolated `winhood-scanner-worker` container service
 *   (or an explicitly injected verified isolated executor).
 * - Never executes arbitrary external scanners directly on the host without OS/container isolation;
 *   returns explicit `BLOCKED` state when isolation is unavailable.
 * - Persists job audit metadata and SHA-256 input/output digests (NEVER plaintext source code).
 * - Recovers interrupted `RUNNING`/`QUEUED` jobs cleanly on service restart.
 */
export class ScannerJobOrchestrator {
  private readonly storePath: string | null;
  private readonly maxConcurrency: number;
  private readonly defaultTimeoutMs: number;
  private readonly workerUrl: string | null;
  private readonly workerToken: string;
  private readonly remoteExecutor?: ScannerWorkerRemoteExecutor;

  private readonly jobs = new Map<string, ScannerJobRecord>();
  private readonly pendingPayloads = new Map<string, Record<string, string>>();
  private readonly activeAbortControllers = new Map<string, AbortController>();
  private readonly queue: string[] = [];
  private activeCount = 0;

  constructor(options?: ScannerJobOrchestratorOptions) {
    this.storePath = options?.dataDir
      ? path.join(path.resolve(options.dataDir), 'database', 'scanner_jobs.json')
      : null;
    this.maxConcurrency = Math.max(1, Math.min(8, options?.maxConcurrency ?? 2));
    this.defaultTimeoutMs = Math.max(2_000, Math.min(300_000, options?.defaultTimeoutMs ?? 45_000));
    const configuredUrl = (options?.workerUrl ?? process.env.WINHOOD_SCANNER_WORKER_URL ?? '').trim();
    this.workerUrl = configuredUrl ? configuredUrl.replace(/\/+$/, '') : null;
    this.workerToken = (options?.workerToken ?? process.env.WINHOOD_SCANNER_WORKER_TOKEN ?? '').trim();
    this.remoteExecutor = options?.remoteExecutor;

    this.loadPersistedJobsAndRecover();
  }

  private loadPersistedJobsAndRecover(): void {
    if (!this.storePath || !fs.existsSync(this.storePath)) return;
    try {
      const raw = fs.readFileSync(this.storePath, 'utf8');
      const parsed = JSON.parse(raw) as { jobs?: ScannerJobRecord[] };
      if (!Array.isArray(parsed?.jobs)) return;
      let mutated = false;
      for (const job of parsed.jobs) {
        if (!job?.jobId) continue;
        if (job.state === 'RUNNING' || job.state === 'QUEUED') {
          job.state = 'FAILED';
          job.recoveredFromInterruption = true;
          job.completedAt = new Date().toISOString();
          job.errorMessage =
            'JOB_INTERRUPTED_ON_RESTART: Execução interrompida por reinicialização do serviço; payload em memória não persistido em texto puro. Reenvie o job se necessário.';
          mutated = true;
        }
        this.jobs.set(job.jobId, job);
      }
      if (mutated) {
        this.persistJobs();
      }
    } catch {
      // Ignore unreadable history on boot
    }
  }

  private persistJobs(): void {
    if (!this.storePath) return;
    try {
      fs.mkdirSync(path.dirname(this.storePath), { recursive: true, mode: 0o700 });
      const payload = JSON.stringify(
        {
          schemaVersion: '1.0.0',
          updatedAt: new Date().toISOString(),
          jobs: Array.from(this.jobs.values()).slice(-200),
        },
        null,
        2
      );
      const tmp = `${this.storePath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
      fs.writeFileSync(tmp, payload, { encoding: 'utf8', mode: 0o600 });
      fs.renameSync(tmp, this.storePath);
    } catch {
      // Non-fatal persistence failure
    }
  }

  public getJob(jobId: string): ScannerJobRecord | null {
    return this.jobs.get(jobId) ?? null;
  }

  public listJobs(): ScannerJobRecord[] {
    return Array.from(this.jobs.values()).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  public async getCapabilities(): Promise<{
    workerConfigured: boolean;
    workerReachable: boolean;
    isolationSummary: string;
    capabilities: ToolCapabilityRecord[];
  }> {
    if (this.remoteExecutor) {
      try {
        const capabilities = await this.remoteExecutor.fetchCapabilities();
        return {
          workerConfigured: true,
          workerReachable: true,
          isolationSummary: 'Isolated Scanner Worker (Verified Execution Matrix)',
          capabilities,
        };
      } catch {
        // Fall through to honest unavailable report
      }
    }

    if (this.workerUrl) {
      try {
        const headers: Record<string, string> = {};
        if (this.workerToken) {
          headers.Authorization = `Bearer ${this.workerToken}`;
        }
        const res = await fetch(`${this.workerUrl}/worker/capabilities`, {
          method: 'GET',
          headers,
          signal: AbortSignal.timeout(5_000),
        });
        if (res.ok) {
          const data = (await res.json()) as { capabilities?: ToolCapabilityRecord[] };
          return {
            workerConfigured: true,
            workerReachable: true,
            isolationSummary: `Docker Scanner Worker (${this.workerUrl})`,
            capabilities: Array.isArray(data.capabilities) ? data.capabilities : [],
          };
        }
      } catch {
        // Worker unreachable — report truthfully, NEVER mark OPERATIONAL
      }
    }

    const probe = SandboxExecutor.probeHostIsolation();
    const now = new Date().toISOString();
    const capabilities: ToolCapabilityRecord[] = SCANNER_TOOL_CATALOG.map((spec) => ({
      toolId: spec.toolId,
      displayName: spec.displayName,
      purpose: spec.purpose,
      binaryNames: [...spec.binaryNames],
      installed: false,
      version: null,
      executionEnvironment: 'UNAVAILABLE',
      isolationAvailable: probe.dockerAvailable || probe.bwrapAvailable,
      executionPerformed: false,
      outputValidated: false,
      limitations: [
        this.workerUrl
          ? `Serviço winhood-scanner-worker (${this.workerUrl}) inacessível.`
          : 'Serviço dedicado winhood-scanner-worker não configurado; execução direta no host bloqueada por política P0.',
      ],
      finalState: 'BLOCKED',
      checkedAt: now,
    }));

    return {
      workerConfigured: Boolean(this.workerUrl),
      workerReachable: false,
      isolationSummary: probe.isolationProvider,
      capabilities,
    };
  }

  public enqueueJob(request: ScannerJobRequest): ScannerJobRecord {
    const requestedTools = (request.toolIds || []).filter((id): id is ScannerToolId =>
      ALLOWED_SCANNER_TOOL_IDS.has(id)
    );
    if (requestedTools.length === 0) {
      throw new Error(
        'SCANNER_JOB_INVALID_TOOLS: Informe ao menos uma ferramenta permitida no catálogo oficial.'
      );
    }

    const filesMap = request.filesMap || {};
    const jobId = `wh-scan-${crypto.randomUUID()}`;
    const timeoutMs = Math.max(2_000, Math.min(300_000, request.timeoutMs ?? this.defaultTimeoutMs));
    const maxRetries = Math.max(0, Math.min(2, request.maxRetries ?? 1));
    const inputSha256 = computeCanonicalFilesSha256(filesMap);

    const record: ScannerJobRecord = {
      jobId,
      projectId: request.projectId ?? null,
      softwareId: request.softwareId ?? null,
      toolIds: requestedTools,
      state: 'QUEUED',
      executionBackend:
        this.remoteExecutor || this.workerUrl ? 'DOCKER_SCANNER_WORKER' : 'BLOCKED_NO_ISOLATION',
      inputSha256,
      outputSha256: null,
      fileCount: Object.keys(filesMap).length,
      attemptCount: 0,
      maxRetries,
      timeoutMs,
      createdAt: new Date().toISOString(),
      startedAt: null,
      completedAt: null,
      durationMs: null,
      cancelRequested: false,
      recoveredFromInterruption: false,
      results: [],
      errorMessage: null,
    };

    this.jobs.set(jobId, record);
    this.pendingPayloads.set(jobId, filesMap);
    this.queue.push(jobId);
    this.persistJobs();
    this.drainQueue();
    return record;
  }

  public cancelJob(jobId: string): ScannerJobRecord | null {
    const job = this.jobs.get(jobId);
    if (!job) return null;
    if (job.state === 'COMPLETED' || job.state === 'FAILED' || job.state === 'CANCELLED' || job.state === 'BLOCKED') {
      return job;
    }

    job.cancelRequested = true;
    const queuedIdx = this.queue.indexOf(jobId);
    if (queuedIdx >= 0) {
      this.queue.splice(queuedIdx, 1);
      job.state = 'CANCELLED';
      job.completedAt = new Date().toISOString();
      job.errorMessage = 'Job cancelado antes do início da execução.';
      this.pendingPayloads.delete(jobId);
      this.persistJobs();
      return job;
    }

    const ctrl = this.activeAbortControllers.get(jobId);
    if (ctrl) {
      ctrl.abort();
    }
    job.state = 'CANCELLED';
    job.completedAt = new Date().toISOString();
    job.errorMessage = 'Cancelamento solicitado durante execução.';
    this.persistJobs();
    return job;
  }

  public async waitForJob(jobId: string, maxWaitMs = 30_000): Promise<ScannerJobRecord | null> {
    const deadline = Date.now() + maxWaitMs;
    while (Date.now() < deadline) {
      const job = this.jobs.get(jobId);
      if (!job) return null;
      if (job.state !== 'QUEUED' && job.state !== 'RUNNING') {
        return job;
      }
      await new Promise((r) => setTimeout(r, 25));
    }
    return this.jobs.get(jobId) ?? null;
  }

  public cancelAllPendingAndRunning(): void {
    for (const jobId of Array.from(this.queue)) {
      this.cancelJob(jobId);
    }
    for (const [jobId, ctrl] of this.activeAbortControllers.entries()) {
      ctrl.abort();
      const job = this.jobs.get(jobId);
      if (job && job.state === 'RUNNING') {
        job.state = 'CANCELLED';
        job.completedAt = new Date().toISOString();
        job.errorMessage = 'Job cancelado por encerramento gracioso do servidor.';
      }
    }
    this.activeAbortControllers.clear();
    this.pendingPayloads.clear();
    this.persistJobs();
  }

  private drainQueue(): void {
    while (this.activeCount < this.maxConcurrency && this.queue.length > 0) {
      const nextJobId = this.queue.shift()!;
      const job = this.jobs.get(nextJobId);
      if (!job || job.cancelRequested || job.state === 'CANCELLED') {
        this.pendingPayloads.delete(nextJobId);
        continue;
      }
      this.activeCount += 1;
      void this.executeSingleJob(job).finally(() => {
        this.activeCount = Math.max(0, this.activeCount - 1);
        this.pendingPayloads.delete(nextJobId);
        this.activeAbortControllers.delete(nextJobId);
        this.persistJobs();
        this.drainQueue();
      });
    }
  }

  private async executeSingleJob(job: ScannerJobRecord): Promise<void> {
    const startMs = performance.now();
    job.state = 'RUNNING';
    job.startedAt = new Date().toISOString();
    this.persistJobs();

    const filesMap = this.pendingPayloads.get(job.jobId) || {};

    // Fail-closed: if no dedicated scanner worker is configured, mark BLOCKED instead of insecure host fallback
    if (!this.remoteExecutor && !this.workerUrl) {
      job.state = 'BLOCKED';
      job.completedAt = new Date().toISOString();
      job.durationMs = Math.max(1, Math.round(performance.now() - startMs));
      job.results = job.toolIds.map((toolId) => ({
        toolId,
        state: 'BLOCKED',
        version: null,
        exitCode: null,
        durationMs: 0,
        outputFormat: 'JSON',
        outputValidated: false,
        findingsCount: 0,
        rawOutputSha256: sha256Json({ toolId, blocked: true }),
        limitations: [
          'Serviço winhood-scanner-worker não configurado. Execução direta de binários externos no host é bloqueada por política de isolamento P0.',
        ],
        errorMessage: 'ISOLATED_SCANNER_WORKER_UNAVAILABLE',
      }));
      job.outputSha256 = sha256Json(job.results);
      job.errorMessage =
        'Execução bloqueada: serviço dedicado winhood-scanner-worker não configurado.';
      return;
    }

    let lastError: unknown = null;
    for (let attempt = 1; attempt <= job.maxRetries + 1; attempt++) {
      if (job.cancelRequested) {
        job.state = 'CANCELLED';
        job.completedAt = new Date().toISOString();
        job.durationMs = Math.max(1, Math.round(performance.now() - startMs));
        return;
      }

      job.attemptCount = attempt;
      const controller = new AbortController();
      this.activeAbortControllers.set(job.jobId, controller);
      const timeoutHandle = setTimeout(() => {
        controller.abort(new Error(`SCANNER_JOB_TIMEOUT_${job.timeoutMs}ms`));
      }, job.timeoutMs);
      timeoutHandle.unref();

      try {
        const results = await this.invokeWorker({
          jobId: job.jobId,
          toolIds: job.toolIds,
          filesMap,
          timeoutMs: job.timeoutMs,
          signal: controller.signal,
        });
        clearTimeout(timeoutHandle);

        if (job.cancelRequested) {
          job.state = 'CANCELLED';
          job.completedAt = new Date().toISOString();
          job.durationMs = Math.max(1, Math.round(performance.now() - startMs));
          return;
        }

        job.results = results;
        job.outputSha256 = sha256Json(results);
        job.completedAt = new Date().toISOString();
        job.durationMs = Math.max(1, Math.round(performance.now() - startMs));
        const allBlocked = results.length > 0 && results.every((r) => r.state === 'BLOCKED');
        job.state = allBlocked ? 'BLOCKED' : 'COMPLETED';
        job.errorMessage = null;
        return;
      } catch (err: unknown) {
        clearTimeout(timeoutHandle);
        lastError = err;
        const isTimedOut =
          controller.signal.aborted &&
          String(controller.signal.reason || err).includes('SCANNER_JOB_TIMEOUT');
        if (job.cancelRequested) {
          job.state = 'CANCELLED';
          job.completedAt = new Date().toISOString();
          job.durationMs = Math.max(1, Math.round(performance.now() - startMs));
          return;
        }
        if (isTimedOut) {
          job.state = 'TIMED_OUT';
          job.completedAt = new Date().toISOString();
          job.durationMs = Math.max(1, Math.round(performance.now() - startMs));
          job.errorMessage = `Tempo limite excedido (${job.timeoutMs}ms) na tentativa ${attempt}.`;
          return;
        }
        if (attempt <= job.maxRetries) {
          await new Promise((r) => setTimeout(r, 150 * attempt));
        }
      }
    }

    job.state = 'FAILED';
    job.completedAt = new Date().toISOString();
    job.durationMs = Math.max(1, Math.round(performance.now() - startMs));
    job.errorMessage =
      lastError instanceof Error ? lastError.message : String(lastError || 'Falha no scanner worker');
  }

  private async invokeWorker(params: {
    jobId: string;
    toolIds: ScannerToolId[];
    filesMap: Record<string, string>;
    timeoutMs: number;
    signal: AbortSignal;
  }): Promise<ScannerToolJobOutput[]> {
    if (this.remoteExecutor) {
      return this.remoteExecutor.executeJob(params);
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-WinHood-Job-Id': params.jobId,
    };
    if (this.workerToken) {
      headers.Authorization = `Bearer ${this.workerToken}`;
    }

    const res = await fetch(`${this.workerUrl}/worker/execute`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        jobId: params.jobId,
        toolIds: params.toolIds,
        filesMap: params.filesMap,
        timeoutMs: params.timeoutMs,
      }),
      signal: params.signal,
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`SCANNER_WORKER_HTTP_${res.status}: ${errText.slice(0, 300)}`);
    }

    const body = (await res.json()) as { results?: ScannerToolJobOutput[] };
    if (!Array.isArray(body?.results)) {
      throw new Error('SCANNER_WORKER_INVALID_RESPONSE: Campo results ausente na resposta do worker.');
    }
    return body.results;
  }
}
