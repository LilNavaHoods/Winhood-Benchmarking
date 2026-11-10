import type { GitarReviewFinding, SonarIssueRecord } from '../../types/benchmark';
import { computeSha256 } from '../../engine/scoringEngine';

/**
 * GitarReviewMapper (Seção 9.3 e 9.4)
 * Mapeia revisões de Pull Request e patches propostos pelo Gitar AI em branch isolada,
 * deduplicando contra achados existentes do SonarQube para não somar duas vezes o mesmo problema.
 */
export class GitarReviewMapper {
  public static mapAndDeduplicateReviews(params: {
    softwareId: string;
    softwareName: string;
    repository: string;
    commitHash: string;
    rawReviews: Array<{
      pullRequestNumber: number;
      branchName: string;
      category: GitarReviewFinding['category'];
      severity: GitarReviewFinding['severity'];
      title: string;
      description: string;
      filePath: string;
      lineNumber: number;
      beforeSnippet: string;
      afterSnippet: string;
      patchExplanation: string;
    }>;
    existingSonarIssues: SonarIssueRecord[];
  }): GitarReviewFinding[] {
    const nowIso = new Date().toISOString();

    return params.rawReviews.map((rev, idx) => {
      // Verificar se o SonarQube já reportou um achado na mesma linha/arquivo
      const matchedSonar = params.existingSonarIssues.find(
        (si) =>
          si.softwareId === params.softwareId &&
          si.filePath === rev.filePath &&
          Math.abs(si.lineNumber - rev.lineNumber) <= 3
      );

      const isolatedBranch = `gitar/remediation-isolated-${params.commitHash.slice(0, 8)}-pr${rev.pullRequestNumber}`;
      const evidenceSha256 = computeSha256(
        `GITAR_REV|${params.softwareId}|${rev.filePath}:${rev.lineNumber}|${rev.title}|${params.commitHash}`
      );

      return {
        id: `gitar-rev-${evidenceSha256.slice(0, 10)}-${idx}`,
        softwareId: params.softwareId,
        softwareName: params.softwareName,
        repository: params.repository,
        pullRequestNumber: rev.pullRequestNumber,
        branchName: rev.branchName,
        originalCommitHash: params.commitHash,
        category: rev.category,
        severity: rev.severity,
        title: rev.title,
        description: rev.description,
        filePath: rev.filePath,
        lineNumber: rev.lineNumber,
        originMethodology:
          rev.category === 'CI_FAILURE'
            ? 'GITAR_CI_LOG_CORRELATOR'
            : 'GITAR_AST_PR_AGENT',
        deduplicatedWithSonarIssueKey: matchedSonar ? matchedSonar.issueKey : null,
        proposedFix: {
          patchId: `patch-${evidenceSha256.slice(0, 8)}`,
          isolatedBranch,
          explanation: rev.patchExplanation,
          beforeSnippet: rev.beforeSnippet,
          afterSnippet: rev.afterSnippet,
          // Aprovação automática, merge automático e aplicação automática DESABILITADOS por padrão (Seção 9.3)
          humanApprovalStatus: 'PENDING_HUMAN_APPROVAL',
          approvedBy: null,
          approvedAt: null,
          retestExecuted: false,
          retestResultSummary: null,
        },
        createdAt: nowIso,
        evidenceSha256,
      };
    });
  }
}
