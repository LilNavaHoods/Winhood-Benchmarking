import type {
  GitarReviewFinding,
  IntegrationTestStepResult,
  NormalizedFinding,
  Software,
  SonarAndToolsDatabaseBundle,
} from '../types/benchmark';
import { enrichLegacyOrExternalFinding } from '../engine/scoringEngine';
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

  public static mapGitarFindingToNormalizedFinding(
    review: GitarReviewFinding,
    runId = 'run-gitar-worker'
  ): NormalizedFinding {
    const category: NormalizedFinding['category'] =
      review.category === 'SECURITY'
        ? 'SAST'
        : review.category === 'CROSS_REPO_IMPACT'
          ? 'ARCHITECTURE'
          : 'CODE_QUALITY';

    return enrichLegacyOrExternalFinding({
      id: review.id,
      runId,
      softwareId: review.softwareId,
      softwareName: review.softwareName,
      softwareVersion: '1.0.0',
      toolId: 'gitar-pr-agent',
      toolName: 'Gitar AI PR & CI Correlator',
      toolVersion: '2026.11',
      category,
      originalRuleId: `gitar.${review.category.toLowerCase()}`,
      title: review.title,
      description: review.description,
      severity: review.severity,
      confidence: 'HIGH',
      filePath: review.filePath,
      lineNumber: review.lineNumber,
      snippet: review.proposedFix?.beforeSnippet || `${review.filePath}:${review.lineNumber}`,
      compliantCodeExample: review.proposedFix?.afterSnippet,
      remediation: review.proposedFix?.explanation || 'Aplicar patch proposto na branch isolada após aprovação humana.',
      evidenceSha256: review.evidenceSha256,
      validationStatus:
        review.proposedFix?.humanApprovalStatus === 'REJECTED_BY_HUMAN'
          ? 'FALSE_POSITIVE_REVIEWED'
          : 'VALIDATED',
      collectedAt: review.createdAt,
    });
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

