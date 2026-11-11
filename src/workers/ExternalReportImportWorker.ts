import type {
  NormalizedFinding,
  SonarAndToolsDatabaseBundle,
  SonarIssueRecord,
} from '../types/benchmark';
import { computeSha256, enrichLegacyOrExternalFinding } from '../engine/scoringEngine';

export interface SarifExternalReportPayload {
  toolId:
    | 'semgrep'
    | 'codeql'
    | 'gitleaks'
    | 'trivy'
    | 'bandit'
    | 'ruff'
    | 'eslint'
    | 'spotbugs'
    | 'pmd'
    | 'checkstyle';
  toolName: string;
  toolVersion: string;
  softwareId: string;
  softwareName: string;
  projectKey: string;
  sarifFindings: Array<{
    ruleId: string;
    message: string;
    severity: 'BLOCKER' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    confidence: 'HIGH' | 'MEDIUM' | 'LOW';
    filePath: string;
    lineNumber: number;
    snippet: string;
  }>;
}

/**
 * ExternalReportImportWorker (Seção 7 e Seção 12)
 * Importa relatórios externos compatíveis (SARIF 2.1.0 / sensores nativos) para o SonarQube
 * e para o mecanismo nativo do Benchmark Analyzer usando enrichLegacyOrExternalFinding.
 * CRÍTICO: Nunca apresenta achados externos importados como regras próprias do SonarQube
 * ou como integrantes automáticos dos Quality Profiles.
 */
export class ExternalReportImportWorker {
  public static enrichExternalSarifToNormalizedFinding(params: {
    payload: SarifExternalReportPayload;
    item: SarifExternalReportPayload['sarifFindings'][number];
    runId?: string;
  }): NormalizedFinding {
    const { payload, item } = params;
    const isCodeSmellTool =
      payload.toolId === 'eslint' ||
      payload.toolId === 'pmd' ||
      payload.toolId === 'checkstyle' ||
      payload.toolId === 'ruff';

    const category: NormalizedFinding['category'] =
      payload.toolId === 'gitleaks'
        ? 'SECRETS'
        : payload.toolId === 'trivy'
          ? 'SCA'
          : isCodeSmellTool
            ? 'CODE_QUALITY'
            : 'SAST';

    return enrichLegacyOrExternalFinding({
      runId: params.runId || 'run-external-sarif',
      softwareId: payload.softwareId,
      softwareName: payload.softwareName,
      softwareVersion: '1.0.0',
      toolId: payload.toolId,
      toolName: payload.toolName,
      toolVersion: payload.toolVersion,
      category,
      originalRuleId: item.ruleId,
      title: `[SARIF ${payload.toolName}] ${item.ruleId}`,
      description: item.message,
      severity: item.severity,
      confidence: item.confidence,
      filePath: item.filePath,
      lineNumber: item.lineNumber,
      snippet: item.snippet,
      remediation: `Achado importado via SARIF da ferramenta externa ${payload.toolName} (v${payload.toolVersion}). Aplicar correção na regra ${item.ruleId}.`,
      validationStatus: 'VALIDATED',
    });
  }

  public static importExternalSarifFindings(params: {
    payload: SarifExternalReportPayload;
    analysisId: string;
    toolsDb: SonarAndToolsDatabaseBundle;
    existingNormalizedFindings: NormalizedFinding[];
  }): {
    importedToSonarIssues: SonarIssueRecord[];
    normalizedFindingsAdded: NormalizedFinding[];
    deduplicatedSkippedCount: number;
    message: string;
  } {
    const imported: SonarIssueRecord[] = [];
    const normalizedAdded: NormalizedFinding[] = [];
    let skipped = 0;

    for (const item of params.payload.sarifFindings) {
      // Deduplicar contra achados já importados na mesma linha/arquivo/regra
      const alreadyExists = params.toolsDb.sonar_issues.some(
        (si) =>
          si.softwareId === params.payload.softwareId &&
          si.filePath === item.filePath &&
          si.lineNumber === item.lineNumber &&
          si.originalRuleId === item.ruleId
      );

      if (alreadyExists) {
        skipped += 1;
        continue;
      }

      const evidenceSha256 = computeSha256(
        `EXT_SARIF|${params.payload.toolId}|${params.payload.toolVersion}|${params.payload.softwareId}|${item.filePath}:${item.lineNumber}|${item.ruleId}`
      );

      const sonarSeverity: SonarIssueRecord['severity'] =
        item.severity === 'BLOCKER' || item.severity === 'CRITICAL'
          ? 'BLOCKER'
          : item.severity === 'HIGH'
            ? 'CRITICAL'
            : item.severity === 'MEDIUM'
              ? 'MAJOR'
              : item.severity === 'LOW'
                ? 'MINOR'
                : 'INFO';

      const enrichedNormalized = ExternalReportImportWorker.enrichExternalSarifToNormalizedFinding({
        payload: params.payload,
        item,
        runId: params.analysisId,
      });

      const issueRec: SonarIssueRecord = {
        id: `sext-${evidenceSha256.slice(0, 12)}`,
        issueKey: `ext-${params.payload.toolId}-${evidenceSha256.slice(0, 8)}`,
        analysisId: params.analysisId,
        projectKey: params.payload.projectKey,
        softwareId: params.payload.softwareId,
        softwareName: params.payload.softwareName,
        type:
          params.payload.toolId === 'eslint' ||
          params.payload.toolId === 'pmd' ||
          params.payload.toolId === 'checkstyle' ||
          params.payload.toolId === 'ruff'
            ? 'CODE_SMELL'
            : 'VULNERABILITY',
        severity: sonarSeverity,
        ruleKey: `external_${params.payload.toolId}:${item.ruleId}`,
        ruleName: `[Externo Importado via SARIF: ${params.payload.toolName} v${params.payload.toolVersion}] ${item.ruleId}`,
        isExternalImportedRule: true,
        externalOriginTool: params.payload.toolName,
        externalOriginVersion: params.payload.toolVersion,
        originalRuleId: item.ruleId,
        confidence: item.confidence,
        filePath: item.filePath,
        lineNumber: item.lineNumber,
        message: item.message,
        effortMinutes: enrichedNormalized.remediationEffortMinutes,
        remediationGuidance: `Achado importado via SARIF da ferramenta externa ${params.payload.toolName} (v${params.payload.toolVersion}). Não pertence ao Quality Profile nativo do SonarQube.`,
        evidenceSnippet: item.snippet,
        evidenceSha256,
      };

      imported.push(issueRec);
      normalizedAdded.push(enrichedNormalized);
      params.toolsDb.sonar_issues.unshift(issueRec);
      params.existingNormalizedFindings.push(enrichedNormalized);
    }

    const toolCatalogEntry =
      params.toolsDb.sonar_integrations.externalToolsSupported.find(
        (t) => t.toolId === params.payload.toolId
      );
    if (toolCatalogEntry) {
      toolCatalogEntry.importedIssuesCount += imported.length;
    }

    return {
      importedToSonarIssues: imported,
      normalizedFindingsAdded: normalizedAdded,
      deduplicatedSkippedCount: skipped,
      message: `${imported.length} achado(s) SARIF de ${params.payload.toolName} v${params.payload.toolVersion} importados com origem e impactos MQR preservados (${skipped} duplicado(s) ignorado(s)).`,
    };
  }
}

