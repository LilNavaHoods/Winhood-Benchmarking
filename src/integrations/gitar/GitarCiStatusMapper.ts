import type { GitarCiFailureRecord } from '../../types/benchmark';
import { computeSha256 } from '../../engine/scoringEngine';

/**
 * GitarCiStatusMapper (Seção 9.1 e 9.4)
 * Mapeia falhas de pipeline de CI diagnosticadas pelo agente Gitar AI (GitHub Actions, GitLab CI,
 * Bitbucket Pipelines, Azure DevOps Pipelines) e correlaciona com o diff do Pull Request.
 */
export class GitarCiStatusMapper {
  public static mapCiFailures(params: {
    softwareId: string;
    softwareName: string;
    repository: string;
    commitHash: string;
    rawFailures: Array<{
      pipelineId: string;
      ciPlatform: GitarCiFailureRecord['ciPlatform'];
      branch: string;
      failedStage: string;
      rootCauseSummary: string;
      correlatedFilePath: string;
      remediationSuggested: string;
    }>;
  }): GitarCiFailureRecord[] {
    const nowIso = new Date().toISOString();
    return params.rawFailures.map((f) => {
      const hash = computeSha256(
        `GITAR_CI|${params.softwareId}|${f.pipelineId}|${f.failedStage}|${params.commitHash}`
      );
      return {
        id: `gitar-ci-${hash.slice(0, 10)}`,
        softwareId: params.softwareId,
        softwareName: params.softwareName,
        repository: params.repository,
        pipelineId: f.pipelineId,
        ciPlatform: f.ciPlatform,
        branch: f.branch,
        commitHash: params.commitHash,
        failedStage: f.failedStage,
        rootCauseSummary: f.rootCauseSummary,
        correlatedFilePath: f.correlatedFilePath,
        remediationSuggested: f.remediationSuggested,
        status: 'FIX_PROPOSED_IN_ISOLATED_BRANCH',
        detectedAt: nowIso,
      };
    });
  }
}
