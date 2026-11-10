import type { SonarTaskRecord } from '../../types/benchmark';
import { computeSha256 } from '../../engine/scoringEngine';
import { SonarQubeApiClient } from './SonarQubeApiClient';

export interface WaitForTaskOptions {
  executionId: string;
  ceTaskId: string;
  instanceId: string;
  projectKey: string;
  softwareId: string;
  apiClient: SonarQubeApiClient;
  initialIntervalMs?: number;
  maxAttempts?: number;
}

/**
 * SonarAnalysisRunner (Seção 5.1)
 * Acompanha o processamento assíncrono da tarefa no Compute Engine do SonarQube (/api/ce/task).
 * - Nunca presume que a análise terminou apenas porque o scanner encerrou.
 * - Utiliza polling com intervalo controlado e exponential backoff para evitar requisições contínuas desnecessárias.
 */
export class SonarAnalysisRunner {
  public static async waitForComputeEngineTask(
    options: WaitForTaskOptions
  ): Promise<SonarTaskRecord> {
    const submittedAt = new Date().toISOString();
    const maxAttempts = options.maxAttempts ?? 8;
    let delayMs = options.initialIntervalMs ?? 120;
    let pollAttempts = 0;

    let lastStatus: SonarTaskRecord['status'] = 'PENDING';
    let startedAt: string | null = null;
    let completedAt: string | null = null;
    let executionTimeMs = 0;
    let analysisId: string | null = null;
    let errorCode: string | null = null;
    let errorMessage: string | null = null;

    while (pollAttempts < maxAttempts) {
      pollAttempts += 1;
      const res = await options.apiClient.getComputeEngineTask(options.ceTaskId);

      if (!res.ok || !res.data?.task) {
        errorCode = `HTTP_${res.status || 'ERR'}`;
        errorMessage = res.error || 'Falha ao consultar tarefa no Compute Engine (/api/ce/task).';
        lastStatus = 'FAILED';
        break;
      }

      const task = res.data.task;
      lastStatus = task.status;
      if (task.startedAt) startedAt = task.startedAt;
      if (task.executionTimeMs !== undefined) executionTimeMs = task.executionTimeMs;
      if (task.analysisId) analysisId = task.analysisId;

      if (task.status === 'SUCCESS') {
        completedAt = task.executedAt || new Date().toISOString();
        break;
      }

      if (task.status === 'FAILED' || task.status === 'CANCELED') {
        completedAt = task.executedAt || new Date().toISOString();
        errorCode = task.errorType || `CE_${task.status}`;
        errorMessage =
          task.errorMessage || `Processamento no Compute Engine terminou com estado ${task.status}.`;
        break;
      }

      // Backoff controlado (Seção 5.1 e 11.6)
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      delayMs = Math.min(2000, Math.round(delayMs * 1.6));
    }

    if (
      lastStatus === 'PENDING' ||
      lastStatus === 'IN_PROGRESS'
    ) {
      lastStatus = 'FAILED';
      errorCode = 'CE_POLLING_TIMEOUT';
      errorMessage = `Timeout aguardando conclusão da tarefa Compute Engine (${options.ceTaskId}) após ${pollAttempts} tentativas com backoff.`;
      completedAt = new Date().toISOString();
    }

    const evidenceSha256 = computeSha256(
      `${options.executionId}|${options.ceTaskId}|${lastStatus}|${analysisId || 'NONE'}|${completedAt || submittedAt}`
    );

    return {
      id: `stask-${options.ceTaskId}`,
      executionId: options.executionId,
      ceTaskId: options.ceTaskId,
      instanceId: options.instanceId,
      projectKey: options.projectKey,
      softwareId: options.softwareId,
      status: lastStatus,
      submittedAt,
      startedAt,
      completedAt,
      executionTimeMs,
      pollAttempts,
      backoffStrategy: `Exponential Backoff (1.6x, ${pollAttempts} consultas realizadas)`,
      errorCode,
      errorMessage,
      analysisId,
      evidenceSha256,
    };
  }
}
