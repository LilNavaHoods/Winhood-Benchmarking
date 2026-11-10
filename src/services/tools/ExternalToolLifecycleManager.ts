import type { SonarConnectionState, SonarExecutionLogRecord, SonarInstallationMode } from '../../types/benchmark';
import { ToolResourceMonitor, type HostResourceCheckResult } from './ToolResourceMonitor';

export interface LifecycleExecutionLimits {
  maxConcurrentSonarAnalyses: number;
  maxWorkersCount: number;
  analysisTimeoutSeconds: number;
  scannerMemoryLimitMb: number;
  cpuCoresLimit: number;
  maxFilesAnalyzed: number;
  maxTempStorageMb: number;
  maxReportSizeMb: number;
  idleShutdownMinutes: number;
}

/**
 * ExternalToolLifecycleManager (Seção 11.2, 11.3 e 11.5)
 * Controla inicialização sob demanda, pré-verificação de recursos, fila de execução
 * controlada (concorrência = 1 para SonarQube em máquinas pequenas) e encerramento
 * automático por inatividade.
 */
export class ExternalToolLifecycleManager {
  private localServerRunning = false;
  private activeAnalysesCount = 0;
  private queuedTasksCount = 0;
  private lastActivityTimestamp: number = Date.now();
  private idleTimer: NodeJS.Timeout | null = null;
  private limits: LifecycleExecutionLimits = {
    maxConcurrentSonarAnalyses: 1,
    maxWorkersCount: 2,
    analysisTimeoutSeconds: 300,
    scannerMemoryLimitMb: 1024,
    cpuCoresLimit: 2,
    maxFilesAnalyzed: 10000,
    maxTempStorageMb: 2048,
    maxReportSizeMb: 50,
    idleShutdownMinutes: 15,
  };
  private logs: SonarExecutionLogRecord[] = [];

  public getLimits(): LifecycleExecutionLimits {
    return { ...this.limits };
  }

  public updateLimits(partial: Partial<LifecycleExecutionLimits>): LifecycleExecutionLimits {
    this.limits = {
      ...this.limits,
      ...partial,
      maxConcurrentSonarAnalyses: Math.max(1, Math.min(4, partial.maxConcurrentSonarAnalyses ?? this.limits.maxConcurrentSonarAnalyses)),
    };
    this.appendLog(
      'LIFECYCLE_MANAGER',
      'INFO',
      'LIMITS_UPDATED',
      `Limites de execução atualizados: concorrência=${this.limits.maxConcurrentSonarAnalyses}, timeout=${this.limits.analysisTimeoutSeconds}s, idleShutdown=${this.limits.idleShutdownMinutes}min.`
    );
    return this.getLimits();
  }

  public isLocalServerRunning(): boolean {
    return this.localServerRunning;
  }

  public getActiveAnalysesCount(): number {
    return this.activeAnalysesCount;
  }

  public getQueuedTasksCount(): number {
    return this.queuedTasksCount;
  }

  public getLogs(): SonarExecutionLogRecord[] {
    return this.logs;
  }

  public appendLog(
    component: SonarExecutionLogRecord['component'],
    level: SonarExecutionLogRecord['level'],
    action: string,
    message: string
  ): SonarExecutionLogRecord {
    // Redact any accidental token string
    const sanitizedMessage = message.replace(
      /(squ_[a-zA-Z0-9]+|sqp_[a-zA-Z0-9]+|sqa_[a-zA-Z0-9]+|Bearer\s+[a-zA-Z0-9._-]+)/gi,
      '[TOKEN_REDACTED]'
    );
    const entry: SonarExecutionLogRecord = {
      id: `slog-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: new Date().toISOString(),
      component,
      level,
      action,
      message: sanitizedMessage,
      redactedTokenSafe: true,
    };
    this.logs.unshift(entry);
    if (this.logs.length > 200) {
      this.logs.length = 200;
    }
    return entry;
  }

  /**
   * Pré-verificação obrigatória antes de iniciar instância local do SonarQube (Seção 11.2 & 11.3)
   */
  public requestOnDemandStart(mode: SonarInstallationMode): {
    started: boolean;
    state: SonarConnectionState;
    hostCheck: HostResourceCheckResult;
    message: string;
  } {
    const hostCheck = ToolResourceMonitor.inspectHostResources();

    if (mode !== 'LOCAL') {
      this.appendLog(
        'LIFECYCLE_MANAGER',
        'INFO',
        'SKIP_LOCAL_START_FOR_REMOTE_MODE',
        `Modo ${mode} configurado: nenhum processo local do SonarQube foi iniciado (economia de recursos).`
      );
      return {
        started: false,
        state: 'READY',
        hostCheck,
        message: `Modo ${mode} ativo. Processos locais não são iniciados quando uma instância remota ou SonarQube Cloud está em uso.`,
      };
    }

    if (!hostCheck.meetsSonarQubeLocalRequirements) {
      const reason = hostCheck.blockingReasons.join(' ');
      this.appendLog(
        'LIFECYCLE_MANAGER',
        'WARN',
        'LOCAL_START_BLOCKED_PREFLIGHT',
        `Inicialização local bloqueada pela pré-verificação de recursos: ${reason}`
      );
      return {
        started: false,
        state: 'NOT_INSTALLED',
        hostCheck,
        message: `Inicialização local bloqueada para preservar estabilidade: ${reason} Conecte uma instância remota (Modo 2) ou SonarQube Cloud, ou execute o script de instalação em seu servidor host com JDK 21 e 4 GB+ RAM.`,
      };
    }

    this.localServerRunning = true;
    this.touchActivity();
    this.appendLog(
      'LIFECYCLE_MANAGER',
      'INFO',
      'LOCAL_SERVER_STARTED_ON_DEMAND',
      'SonarQube Community Build iniciado sob demanda após validação de recursos (RAM >= 4 GB, CPU >= 2 cores, Disco >= 30 GB, JDK 21).'
    );

    return {
      started: true,
      state: 'READY',
      hostCheck,
      message: 'Instância local iniciada sob demanda.',
    };
  }

  public stopLocalInstance(reason = 'SOLICITADO_PELO_USUARIO'): {
    stopped: boolean;
    message: string;
  } {
    if (this.activeAnalysesCount > 0) {
      return {
        stopped: false,
        message: `Encerramento adiado: existem ${this.activeAnalysesCount} análise(s) em andamento.`,
      };
    }
    this.localServerRunning = false;
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
    this.appendLog(
      'LIFECYCLE_MANAGER',
      'INFO',
      'LOCAL_SERVER_STOPPED',
      `Instância local encerrada de forma controlada (motivo: ${reason}). Memória e processos liberados.`
    );
    return {
      stopped: true,
      message: 'Instância local do SonarQube encerrada com segurança.',
    };
  }

  public async executeInControlledQueue<T>(taskName: string, fn: () => Promise<T>): Promise<T> {
    this.queuedTasksCount += 1;
    while (this.activeAnalysesCount >= this.limits.maxConcurrentSonarAnalyses) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    this.queuedTasksCount = Math.max(0, this.queuedTasksCount - 1);
    this.activeAnalysesCount += 1;
    this.touchActivity();
    this.appendLog(
      'LIFECYCLE_MANAGER',
      'INFO',
      'WORKER_TASK_STARTED',
      `Tarefa "${taskName}" iniciada na fila controlada (ativas: ${this.activeAnalysesCount}/${this.limits.maxConcurrentSonarAnalyses}).`
    );

    try {
      const result = await fn();
      this.touchActivity();
      return result;
    } finally {
      this.activeAnalysesCount = Math.max(0, this.activeAnalysesCount - 1);
      this.touchActivity();
      this.appendLog(
        'LIFECYCLE_MANAGER',
        'INFO',
        'WORKER_TASK_FINISHED',
        `Tarefa "${taskName}" finalizada (ativas: ${this.activeAnalysesCount}).`
      );
    }
  }

  private touchActivity(): void {
    this.lastActivityTimestamp = Date.now();
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
    }
    if (this.localServerRunning && this.limits.idleShutdownMinutes > 0) {
      this.idleTimer = setTimeout(() => {
        if (this.activeAnalysesCount === 0 && this.localServerRunning) {
          this.stopLocalInstance(`INATIVIDADE_${this.limits.idleShutdownMinutes}_MIN`);
        }
      }, this.limits.idleShutdownMinutes * 60 * 1000);
    }
  }
}
