import type { SonarIssueRecord } from '../../types/benchmark';
import { computeSha256 } from '../../engine/scoringEngine';

const EXTERNAL_ENGINE_META: Record<string, { name: string; defaultVersion: string }> = {
  semgrep: { name: 'Semgrep / Opengrep SARIF', defaultVersion: '1.9.2' },
  opengrep: { name: 'Opengrep SAST SARIF', defaultVersion: '1.9.2' },
  codeql: { name: 'GitHub CodeQL SARIF', defaultVersion: '2.19.0' },
  gitleaks: { name: 'Gitleaks Secret Scanner SARIF', defaultVersion: '8.21.2' },
  trivy: { name: 'Aqua Trivy SARIF', defaultVersion: '0.57.1' },
  bandit: { name: 'PyCQA Bandit SARIF', defaultVersion: '1.7.10' },
  ruff: { name: 'Astral Ruff SARIF', defaultVersion: '0.7.3' },
  eslint: { name: 'ESLint Static Report', defaultVersion: '9.14.0' },
  spotbugs: { name: 'SpotBugs Bytecode Analyzer', defaultVersion: '4.8.6' },
  pmd: { name: 'PMD Source Code Analyzer', defaultVersion: '7.7.0' },
  checkstyle: { name: 'Checkstyle Java Auditor', defaultVersion: '10.20.1' },
};

/**
 * SonarResultParser (Seção 6.2 e Seção 7)
 * Converte issues e Security Hotspots da Web API do SonarQube para o formato auditável do Benchmark Analyzer.
 * CRÍTICO (Seção 7): Distingue explicitamente achados nativos das regras do SonarQube de achados externos
 * importados via SARIF (`externalRuleEngine` / prefixo `external_*`), preservando ferramenta de origem,
 * versão, regra original e evitando duplicação.
 */
export class SonarResultParser {
  public static parseEffortToMinutes(effortStr?: string): number {
    if (!effortStr) return 10;
    let total = 0;
    const hMatch = effortStr.match(/(\d+)h/);
    const mMatch = effortStr.match(/(\d+)min/);
    const dMatch = effortStr.match(/(\d+)d/);
    if (dMatch) total += parseInt(dMatch[1], 10) * 480;
    if (hMatch) total += parseInt(hMatch[1], 10) * 60;
    if (mMatch) total += parseInt(mMatch[1], 10);
    return total > 0 ? total : 10;
  }

  public static parseIssuesAndHotspots(params: {
    analysisId: string;
    projectKey: string;
    softwareId: string;
    softwareName: string;
    rawIssues: Array<{
      key: string;
      rule: string;
      severity: 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';
      component: string;
      project: string;
      line?: number;
      message: string;
      effort?: string;
      type: 'BUG' | 'VULNERABILITY' | 'CODE_SMELL';
      externalRuleEngine?: string;
    }>;
    rawHotspots?: Array<{
      key: string;
      component: string;
      project: string;
      securityCategory: string;
      vulnerabilityProbability: 'HIGH' | 'MEDIUM' | 'LOW';
      status: 'TO_REVIEW' | 'REVIEWED';
      resolution?: 'FIXED' | 'SAFE' | 'ACKNOWLEDGED';
      line?: number;
      message: string;
      ruleKey?: string;
    }>;
  }): SonarIssueRecord[] {
    const records: SonarIssueRecord[] = [];
    const seenFingerprints = new Set<string>();

    for (const item of params.rawIssues) {
      const filePath = item.component.includes(':')
        ? item.component.split(':').slice(1).join(':')
        : item.component;
      const lineNumber = item.line || 1;

      const isExternal =
        Boolean(item.externalRuleEngine) || item.rule.startsWith('external_');
      const engineKey = (
        item.externalRuleEngine ||
        (item.rule.startsWith('external_')
          ? item.rule.replace(/^external_/, '').split(':')[0]
          : '')
      ).toLowerCase();

      const externalMeta = EXTERNAL_ENGINE_META[engineKey];
      const originalRuleId = item.rule.includes(':')
        ? item.rule.split(':').slice(1).join(':')
        : item.rule;

      // Deduplicação determinística por (softwareId, filePath, lineNumber, originalRuleId)
      const dedupKey = `${params.softwareId}|${filePath}|${lineNumber}|${originalRuleId}`;
      if (seenFingerprints.has(dedupKey)) {
        continue;
      }
      seenFingerprints.add(dedupKey);

      const evidenceSha256 = computeSha256(
        `${params.analysisId}|${item.key}|${item.rule}|${filePath}:${lineNumber}|${item.message}`
      );

      records.push({
        id: `siss-${evidenceSha256.slice(0, 12)}`,
        issueKey: item.key,
        analysisId: params.analysisId,
        projectKey: params.projectKey,
        softwareId: params.softwareId,
        softwareName: params.softwareName,
        type: item.type,
        severity: item.severity,
        ruleKey: item.rule,
        ruleName: isExternal
          ? `[Importado via SARIF: ${externalMeta?.name || engineKey.toUpperCase()}] ${originalRuleId}`
          : `Regra Nativa SonarQube (${item.rule})`,
        isExternalImportedRule: isExternal,
        externalOriginTool: isExternal
          ? externalMeta?.name || engineKey.toUpperCase()
          : 'SonarQube Community Build (Nativo)',
        externalOriginVersion: isExternal
          ? externalMeta?.defaultVersion || 'SARIF 2.1.0'
          : '26.11.0.134175',
        originalRuleId,
        confidence:
          item.severity === 'BLOCKER' || item.severity === 'CRITICAL'
            ? 'HIGH'
            : 'MEDIUM',
        filePath,
        lineNumber,
        message: item.message,
        effortMinutes: SonarResultParser.parseEffortToMinutes(item.effort),
        remediationGuidance: isExternal
          ? 'Achado importado de relatório externo (SARIF). Regras externas não fazem parte do Quality Profile nativo do SonarQube; valide a correção na ferramenta de origem.'
          : 'Consulte a orientação Clean as You Code da regra nativa no perfil de qualidade Sonar way.',
        evidenceSnippet: `${filePath}:${lineNumber} — ${item.message}`,
        evidenceSha256,
      });
    }

    for (const hs of params.rawHotspots || []) {
      const filePath = hs.component.includes(':')
        ? hs.component.split(':').slice(1).join(':')
        : hs.component;
      const lineNumber = hs.line || 1;
      const ruleKey = hs.ruleKey || `hotspot:${hs.securityCategory}`;
      const evidenceSha256 = computeSha256(
        `${params.analysisId}|HOTSPOT|${hs.key}|${filePath}:${lineNumber}|${hs.message}`
      );

      let reviewStatus: SonarIssueRecord['hotspotReviewStatus'] = 'TO_REVIEW';
      if (hs.status === 'REVIEWED') {
        if (hs.resolution === 'SAFE') reviewStatus = 'REVIEWED_SAFE';
        else if (hs.resolution === 'FIXED') reviewStatus = 'REVIEWED_FIXED';
        else reviewStatus = 'REVIEWED_ACKNOWLEDGED';
      }

      records.push({
        id: `shs-${evidenceSha256.slice(0, 12)}`,
        issueKey: hs.key,
        analysisId: params.analysisId,
        projectKey: params.projectKey,
        softwareId: params.softwareId,
        softwareName: params.softwareName,
        type: 'SECURITY_HOTSPOT',
        severity:
          hs.vulnerabilityProbability === 'HIGH'
            ? 'CRITICAL'
            : hs.vulnerabilityProbability === 'MEDIUM'
              ? 'MAJOR'
              : 'MINOR',
        ruleKey,
        ruleName: `Security Hotspot (${hs.securityCategory})`,
        isExternalImportedRule: false,
        externalOriginTool: 'SonarQube Security Hotspot Engine (Estático)',
        externalOriginVersion: '26.11.0.134175',
        originalRuleId: ruleKey,
        confidence: hs.vulnerabilityProbability,
        filePath,
        lineNumber,
        message: hs.message,
        effortMinutes: 20,
        remediationGuidance:
          'Security Hotspot estático requer revisão humana para determinar se o contexto de execução expõe uma vulnerabilidade real.',
        hotspotReviewStatus: reviewStatus,
        evidenceSnippet: `${filePath}:${lineNumber} [${hs.securityCategory}]`,
        evidenceSha256,
      });
    }

    return records;
  }
}
