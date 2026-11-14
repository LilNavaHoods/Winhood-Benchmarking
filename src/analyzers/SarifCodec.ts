import crypto from 'node:crypto';
import type { NormalizedFinding, SeverityLevel } from '../types/benchmark';
import { enrichLegacyOrExternalFinding } from '../engine/scoringEngine';
import type { AnalysisScope } from './types';
import { RULE_ENGINE_VERSION, RuleRegistry } from './RuleRegistry';

export interface SarifExportOptions {
  toolName?: string;
  toolVersion?: string;
  informationUri?: string;
  softwareArtifacts?: Array<{ name: string; version: string }>;
}

function severityToSarifLevel(sev: SeverityLevel): 'error' | 'warning' | 'note' {
  if (sev === 'BLOCKER' || sev === 'CRITICAL' || sev === 'HIGH') return 'error';
  if (sev === 'MEDIUM') return 'warning';
  return 'note';
}

function sarifLevelToSeverity(level: unknown, props?: Record<string, any>): SeverityLevel {
  const rank = Number(props?.['security-severity']);
  if (!Number.isNaN(rank)) {
    if (rank >= 9.0) return 'CRITICAL';
    if (rank >= 7.0) return 'HIGH';
    if (rank >= 4.0) return 'MEDIUM';
    return 'LOW';
  }
  const norm = String(level || 'warning').toLowerCase();
  if (norm === 'error') return 'HIGH';
  if (norm === 'warning') return 'MEDIUM';
  return 'LOW';
}

export class SarifCodec {
  /**
   * Exports NormalizedFindings into canonical SARIF 2.1.0 with data-flow codeFlows,
   * CWE/OWASP tags, and independent open-standard positioning.
   */
  public static exportSarif210(
    findings: NormalizedFinding[],
    options: SarifExportOptions = {}
  ): Record<string, unknown> {
    const rulesMap = new Map<string, Record<string, unknown>>();

    const results = findings.map((f) => {
      const ruleMeta = RuleRegistry.findRule(f.originalRuleId);
      if (!rulesMap.has(f.originalRuleId)) {
        rulesMap.set(f.originalRuleId, {
          id: f.originalRuleId,
          name: f.originalRuleId.replace(/[^a-zA-Z0-9]/g, '_'),
          shortDescription: { text: f.title },
          fullDescription: { text: f.whyItIsAnIssue || f.description || f.title },
          defaultConfiguration: {
            level: severityToSarifLevel(f.severity),
          },
          properties: {
            version: ruleMeta?.version || '1.0.0',
            cwe: f.cwe ? [f.cwe] : [],
            owaspTop10: ruleMeta?.owaspTop10 || null,
            cvss: f.cvss ?? ruleMeta?.cvssBase ?? null,
            'security-severity': String(f.cvss ?? ruleMeta?.cvssBase ?? (f.severity === 'BLOCKER' ? 9.5 : 5.0)),
            category: f.category,
            cleanCodeAttribute: f.cleanCodeAttribute,
            mqrImpacts: f.mqrImpacts || [],
          },
        });
      }

      const codeFlows =
        f.executionFlows && f.executionFlows.length > 0
          ? [
              {
                threadFlows: [
                  {
                    locations: f.executionFlows.map((step) => ({
                      location: {
                        physicalLocation: {
                          artifactLocation: {
                            uri: step.filePath.replace(/\\/g, '/'),
                            uriBaseId: '%SRCROOT%',
                          },
                          region: {
                            startLine: step.lineNumber > 0 ? step.lineNumber : 1,
                            snippet: { text: step.codeSnippet || step.snippet || '' },
                          },
                        },
                        message: { text: `[${step.nodeType}] ${step.explanation}` },
                      },
                    })),
                  },
                ],
              },
            ]
          : undefined;

      return {
        ruleId: f.originalRuleId,
        level: severityToSarifLevel(f.severity),
        message: { text: `[${f.softwareName}] ${f.title} — ${f.whyItIsAnIssue || f.description}` },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: f.filePath.replace(/\\/g, '/'),
                uriBaseId: '%SRCROOT%',
              },
              region: {
                startLine: f.lineNumber > 0 ? f.lineNumber : 1,
                endLine: f.endLineNumber && f.endLineNumber > 0 ? f.endLineNumber : f.lineNumber > 0 ? f.lineNumber : 1,
                startColumn: f.columnStart ?? 1,
                endColumn: f.columnEnd ?? 80,
                snippet: { text: f.snippet || '' },
              },
            },
          },
        ],
        ...(codeFlows ? { codeFlows } : {}),
        properties: {
          softwareId: f.softwareId,
          softwareName: f.softwareName,
          softwareVersion: f.softwareVersion,
          cwe: f.cwe,
          cvss: f.cvss,
          evidenceSha256: f.evidenceSha256,
          remediation: f.remediation,
          remediationEffortMinutes: f.remediationEffortMinutes,
        },
      };
    });

    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Sarif-2.1.0/rc2/Schemas/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: options.toolName || 'WinHood Independent Audit & Benchmarking Engine',
              version: options.toolVersion || RULE_ENGINE_VERSION,
              informationUri: options.informationUri || 'https://github.com/LilNavaHoods/Winhood-Benchmarking',
              rules: Array.from(rulesMap.values()),
            },
          },
          artifacts: (options.softwareArtifacts || []).map((a) => ({
            location: { uri: `package:${a.name}@${a.version}` },
          })),
          results,
        },
      ],
    };
  }

  /**
   * Validates and imports external SARIF 2.1.0 documents without runtime coupling.
   */
  public static importSarif210(
    rawPayload: unknown,
    scope: Pick<AnalysisScope, 'runId' | 'softwareId' | 'softwareName' | 'softwareVersion'>
  ): {
    valid: boolean;
    errors: string[];
    importedToolNames: string[];
    findings: NormalizedFinding[];
    payloadSha256: string;
  } {
    const errors: string[] = [];
    if (!rawPayload || typeof rawPayload !== 'object') {
      return {
        valid: false,
        errors: ['SARIF payload deve ser um objeto JSON válido.'],
        importedToolNames: [],
        findings: [],
        payloadSha256: '',
      };
    }

    const doc = rawPayload as Record<string, any>;
    if (doc.version !== '2.1.0') {
      errors.push(`Versão SARIF esperada "2.1.0", recebida "${String(doc.version)}".`);
    }
    if (!Array.isArray(doc.runs)) {
      errors.push('Campo obrigatório "runs" ausente ou não é array.');
    }

    if (errors.length > 0) {
      return {
        valid: false,
        errors,
        importedToolNames: [],
        findings: [],
        payloadSha256: '',
      };
    }

    const findings: NormalizedFinding[] = [];
    const importedToolNames: string[] = [];
    const nowIso = new Date().toISOString();

    for (let rIdx = 0; rIdx < doc.runs.length; rIdx++) {
      const run = doc.runs[rIdx] || {};
      const driver = run.tool?.driver || {};
      const toolName = String(driver.name || `External SARIF Tool #${rIdx + 1}`);
      const toolVersion = String(driver.version || 'unknown');
      importedToolNames.push(toolName);

      const rulesById = new Map<string, Record<string, any>>();
      for (const rule of Array.isArray(driver.rules) ? driver.rules : []) {
        if (rule?.id) rulesById.set(String(rule.id), rule);
      }

      const results = Array.isArray(run.results) ? run.results : [];
      for (let idx = 0; idx < results.length; idx++) {
        const res = results[idx] || {};
        const ruleId = String(res.ruleId || 'external-sarif-rule');
        const ruleMeta = rulesById.get(ruleId);
        const loc = res.locations?.[0]?.physicalLocation || {};
        const filePath = String(loc.artifactLocation?.uri || 'unknown').replace(/^file:\/\//, '');
        const startLine = Number(loc.region?.startLine || 1);
        const endLine = Number(loc.region?.endLine || startLine);
        const snippet = String(loc.region?.snippet?.text || '');
        const cweList = res.properties?.cwe || ruleMeta?.properties?.cwe || [];
        const cwe = Array.isArray(cweList) && cweList[0] ? String(cweList[0]) : undefined;
        const severity = sarifLevelToSeverity(res.level, ruleMeta?.properties || res.properties);

        const codeFlowSteps = Array.isArray(res.codeFlows?.[0]?.threadFlows?.[0]?.locations)
          ? res.codeFlows[0].threadFlows[0].locations.map((tl: any, sIdx: number) => ({
              stepOrder: sIdx + 1,
              nodeType: sIdx === 0 ? 'SOURCE' : sIdx === res.codeFlows[0].threadFlows[0].locations.length - 1 ? 'SINK' : 'PROPAGATOR',
              filePath: String(tl.location?.physicalLocation?.artifactLocation?.uri || filePath),
              lineNumber: Number(tl.location?.physicalLocation?.region?.startLine || startLine),
              symbolName: ruleId,
              codeSnippet: String(tl.location?.physicalLocation?.region?.snippet?.text || ''),
              snippet: String(tl.location?.physicalLocation?.region?.snippet?.text || ''),
              explanation: String(tl.location?.message?.text || 'Imported SARIF flow step'),
            }))
          : undefined;

        const categoryRaw = String(res.properties?.category || ruleMeta?.properties?.category || '').toUpperCase();
        const category: NormalizedFinding['category'] =
          categoryRaw === 'SECRETS' || categoryRaw === 'SCA' || categoryRaw === 'IAC' || categoryRaw === 'DATABASE' || categoryRaw === 'CODE_QUALITY'
            ? (categoryRaw as NormalizedFinding['category'])
            : 'SAST';

        findings.push(
          enrichLegacyOrExternalFinding({
            id: `sarif-imp-${scope.runId}-${rIdx}-${idx}-${crypto.createHash('sha256').update(`${toolName}:${ruleId}:${filePath}:${startLine}`).digest('hex').slice(0, 8)}`,
            runId: scope.runId,
            softwareId: scope.softwareId,
            softwareName: scope.softwareName,
            softwareVersion: scope.softwareVersion,
            toolName,
            toolVersion,
            originType: 'IMPORTED_REPORT',
            detectionMethod: 'EXTERNAL_SARIF_IMPORT',
            originalRuleId: ruleId,
            category,
            cwe,
            cvss: typeof res.properties?.cvss === 'number' ? res.properties.cvss : undefined,
            severity,
            confidence: 'HIGH',
            validationStatus: 'VALIDATED',
            lifecycleState: 'CONFIRMED',
            title: String(ruleMeta?.shortDescription?.text || res.message?.text || ruleId).slice(0, 180),
            description: String(res.message?.text || ruleMeta?.fullDescription?.text || ''),
            filePath,
            lineNumber: startLine,
            endLineNumber: endLine,
            snippet,
            remediation: String(res.properties?.remediation || 'Revisar achado importado via padrão SARIF 2.1.0.'),
            remediationEffortMinutes: Number(res.properties?.remediationEffortMinutes || 20),
            executionFlows: codeFlowSteps,
            collectedAt: nowIso,
          })
        );
      }
    }

    const payloadSha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(doc))
      .digest('hex');

    return {
      valid: true,
      errors: [],
      importedToolNames: Array.from(new Set(importedToolNames)),
      findings,
      payloadSha256,
    };
  }
}
