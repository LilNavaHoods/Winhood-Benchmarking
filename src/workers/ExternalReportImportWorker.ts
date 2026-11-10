import type {
  NormalizedFinding,
  SonarAndToolsDatabaseBundle,
  SonarIssueRecord,
} from '../types/benchmark';
import { computeSha256 } from '../engine/scoringEngine';

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
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    confidence: 'HIGH' | 'MEDIUM' | 'LOW';
    filePath: string;
    lineNumber: number;
    snippet: string;
  }>;
}

/**
 * ExternalReportImportWorker (Seção 7 e Seção 12)
 * Importa relatórios externos compatíveis (SARIF 2.1.0 / sensores nativos) para o SonarQube
 * e para o mecanismo nativo do Benchmark Analyzer.
 * CRÍTICO: Nunca apresenta achados externos importados como regras próprias do SonarQube
 * ou como integrantes automáticos dos Quality Profiles.
 */
export class ExternalReportImportWorker {
  public static importExternalSarifFindings(params: {
    payload: SarifExternalReportPayload;
    analysisId: string;
    toolsDb: SonarAndToolsDatabaseBundle;
    existingNormalizedFindings: NormalizedFinding[];
  }): {
    importedToSonarIssues: SonarIssueRecord[];
    deduplicatedSkippedCount: number;
    message: string;
  } {
    const imported: SonarIssueRecord[] = [];
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
        item.severity === 'CRITICAL'
          ? 'BLOCKER'
          : item.severity === 'HIGH'
            ? 'CRITICAL'
            : item.severity === 'MEDIUM'
              ? 'MAJOR'
              : item.severity === 'LOW'
                ? 'MINOR'
                : 'INFO';

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
        effortMinutes: 15,
        remediationGuidance: `Achado importado via SARIF da ferramenta externa ${params.payload.toolName} (v${params.payload.toolVersion}). Não pertence ao Quality Profile nativo do SonarQube.`,
        evidenceSnippet: item.snippet,
        evidenceSha256,
      };

      imported.push(issueRec);
      params.toolsDb.sonar_issues.unshift(issueRec);
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
      deduplicatedSkippedCount: skipped,
      message: `${imported.length} achado(s) SARIF de ${params.payload.toolName} v${params.payload.toolVersion} importados com origem preservada (${skipped} duplicado(s) ignorado(s)).`,
    };
  }
}
