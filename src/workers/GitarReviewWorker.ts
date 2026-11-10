import type {
  IntegrationTestStepResult,
  Software,
  SonarAndToolsDatabaseBundle,
} from '../types/benchmark';
import { GitarAdapter } from '../integrations/gitar/GitarAdapter';

/**
 * GitarReviewWorker (Seção 9 e Seção 12)
 * Worker em segundo plano para processar revisões de Pull Request, diagnósticos de falha de CI
 * e validações pós-aprovação humana em branch isolada sem bloquear o processo principal.
 */
export class GitarReviewWorker {
  private gitarAdapter: GitarAdapter;

  constructor(gitarAdapter: GitarAdapter) {
    this.gitarAdapter = gitarAdapter;
  }

  public async executeAuthorizedValidationJob(params: {
    softwareA: Software;
    softwareB: Software;
    actorName: string;
    toolsDb: SonarAndToolsDatabaseBundle;
  }): Promise<{
    steps: IntegrationTestStepResult[];
    reviewsImported: number;
    ciFailuresImported: number;
  }> {
    return this.gitarAdapter.runAuthorizedGitarContractValidation(params);
  }
}
