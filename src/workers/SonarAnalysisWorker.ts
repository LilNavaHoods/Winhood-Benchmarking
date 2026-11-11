import type {
  NormalizedFinding,
  SeverityLevel,
  Software,
  SonarABComparisonResult,
  SonarAndToolsDatabaseBundle,
  SonarIssueRecord,
} from '../types/benchmark';
import { enrichLegacyOrExternalFinding } from '../engine/scoringEngine';
import { SonarQubeIntegrationService } from '../integrations/sonarqube/SonarQubeAdapter';

/**
 * SonarAnalysisWorker (Seção 11.8 e Seção 12)
 * Worker assíncrono controlado pelo backend para executar análises A/B do SonarQube
 * fora do ciclo síncrono bloqueante, respeitando a fila de concorrência do ExternalToolLifecycleManager.
 */
export class SonarAnalysisWorker {
  private sonarService: SonarQubeIntegrationService;

  constructor(sonarService: SonarQubeIntegrationService) {
    this.sonarService = sonarService;
  }

  public static mapSonarIssueToNormalizedFinding(
    issue: SonarIssueRecord,
    runId = 'run-sonar-worker'
  ): NormalizedFinding {
    const mappedSeverity: SeverityLevel =
      issue.severity === 'BLOCKER'
        ? 'BLOCKER'
        : issue.severity === 'CRITICAL'
          ? 'CRITICAL'
          : issue.severity === 'MAJOR'
            ? 'HIGH'
            : issue.severity === 'MINOR'
              ? 'MEDIUM'
              : 'INFO';

    const category: NormalizedFinding['category'] =
      issue.type === 'VULNERABILITY' || issue.type === 'SECURITY_HOTSPOT'
        ? 'SAST'
        : 'CODE_QUALITY';

    return enrichLegacyOrExternalFinding({
      id: issue.id,
      runId,
      softwareId: issue.softwareId,
      softwareName: issue.softwareName,
      softwareVersion: '1.0.0',
      toolId: issue.isExternalImportedRule ? 'external-sarif' : 'sonarqube-quality',
      toolName: issue.externalOriginTool || 'SonarQube Server (MQR)',
      toolVersion: issue.externalOriginVersion || '26.11.0.134175',
      category,
      originalRuleId: issue.originalRuleId || issue.ruleKey,
      title: issue.ruleName,
      description: issue.message,
      severity: mappedSeverity,
      confidence: issue.confidence,
      filePath: issue.filePath,
      lineNumber: issue.lineNumber,
      snippet: issue.evidenceSnippet,
      remediation: issue.remediationGuidance,
      remediationEffortMinutes: issue.effortMinutes,
      evidenceSha256: issue.evidenceSha256,
      validationStatus:
        issue.hotspotReviewStatus === 'REVIEWED_SAFE'
          ? 'FALSE_POSITIVE_REVIEWED'
          : issue.hotspotReviewStatus === 'REVIEWED_ACKNOWLEDGED'
            ? 'ACCEPTED'
            : 'VALIDATED',
    });
  }

  public async enqueueABComparisonJob(params: {
    softwareA: Software;
    softwareB: Software;
    runId: string;
    toolsDb: SonarAndToolsDatabaseBundle;
    compositeScoreA: number;
    compositeScoreB: number;
  }): Promise<SonarABComparisonResult> {
    return this.sonarService.runStandardizedABComparison(params);
  }
}

