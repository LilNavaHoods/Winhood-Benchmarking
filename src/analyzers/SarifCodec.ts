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

export interface SarifImportOptions {
  originType?: NormalizedFinding['originType'];
  fallbackToolName?: string;
}

function severityToSarifLevel(sev: SeverityLevel): 'error' | 'warning' | 'note' {
  if (sev === 'BLOCKER' || sev === 'CRITICAL' || sev === 'HIGH') return 'error';
  if (sev === 'MEDIUM') return 'warning';
  return 'note';
}

function parseFiniteCvss(...candidates: unknown[]): number | undefined {
  for (const raw of candidates) {
    if (raw === null || raw === undefined || raw === '') continue;
    const n = Number(raw);
    if (Number.isFinite(n) && n >= 0 && n <= 10) {
      return Number(n.toFixed(1));
    }
  }
  return undefined;
}

function sarifLevelToSeverity(
  level: unknown,
  resultProps?: Record<string, any>,
  ruleProps?: Record<string, any>
): SeverityLevel {
  const rank = parseFiniteCvss(
    resultProps?.['security-severity'],
    ruleProps?.['security-severity'],
    resultProps?.cvss,
    ruleProps?.cvss
  );
  if (rank !== undefined) {
    if (rank >= 9.0) return 'CRITICAL';
    if (rank >= 7.0) return 'HIGH';
    if (rank >= 4.0) return 'MEDIUM';
    return 'LOW';
  }
  const norm = String(level ?? '').trim().toLowerCase();
  if (norm === 'error') return 'HIGH';
  if (norm === 'warning') return 'MEDIUM';
  if (norm === 'note' || norm === 'none') return 'LOW';
  // Unrecognized or omitted SARIF level defaults conservatively to MEDIUM without crashing
  return 'MEDIUM';
}

function extractCweFromSarif(
  resultProps?: Record<string, any>,
  ruleProps?: Record<string, any>
): string | undefined {
  const directLists = [resultProps?.cwe, ruleProps?.cwe];
  for (const candidate of directLists) {
    if (typeof candidate === 'string' && candidate.trim()) {
      const m = candidate.match(/CWE-\d+/i);
      return m ? m[0].toUpperCase() : candidate.trim();
    }
    if (Array.isArray(candidate) && candidate[0]) {
      const m = String(candidate[0]).match(/CWE-\d+/i);
      return m ? m[0].toUpperCase() : String(candidate[0]).trim();
    }
  }
  const tags = [
    ...(Array.isArray(resultProps?.tags) ? resultProps.tags : []),
    ...(Array.isArray(ruleProps?.tags) ? ruleProps.tags : []),
  ];
  for (const tag of tags) {
    const m = String(tag || '').match(/cwe[-_/]?(\d+)/i);
    if (m?.[1]) {
      return `CWE-${m[1]}`;
    }
  }
  return undefined;
}

function resolveConfidenceFromSarif(
  hasPhysicalLocation: boolean,
  hasRuleMeta: boolean,
  resultProps?: Record<string, any>,
  ruleProps?: Record<string, any>
): 'HIGH' | 'MEDIUM' | 'LOW' {
  const precision = String(
    resultProps?.precision || ruleProps?.precision || resultProps?.confidence || ''
  )
    .trim()
    .toLowerCase();
  if (!hasPhysicalLocation) return 'LOW';
  if (precision === 'very-high' || precision === 'high') return 'HIGH';
  if (precision === 'low') return 'LOW';
  return hasRuleMeta ? 'MEDIUM' : 'LOW';
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
   * External SARIF findings are NEVER automatically marked as independently verified by WinHood;
   * they preserve UNVERIFIED (or ACCEPTED_RISK when explicitly suppressed in SARIF) provenance.
   */
  public static importSarif210(
    rawPayload: unknown,
    scope: Pick<AnalysisScope, 'runId' | 'softwareId' | 'softwareName' | 'softwareVersion'>,
    options: SarifImportOptions = {}
  ): {
    valid: boolean;
    errors: string[];
    warnings: string[];
    importedToolNames: string[];
    findings: NormalizedFinding[];
    deduplicatedCount: number;
    payloadSha256: string;
  } {
    const errors: string[] = [];
    const warnings: string[] = [];
    if (!rawPayload || typeof rawPayload !== 'object' || Array.isArray(rawPayload)) {
      return {
        valid: false,
        errors: ['SARIF payload deve ser um objeto JSON válido.'],
        warnings,
        importedToolNames: [],
        findings: [],
        deduplicatedCount: 0,
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
        warnings,
        importedToolNames: [],
        findings: [],
        deduplicatedCount: 0,
        payloadSha256: '',
      };
    }

    const findings: NormalizedFinding[] = [];
    const importedToolNames: string[] = [];
    const seenDedupKeys = new Set<string>();
    let deduplicatedCount = 0;
    const nowIso = new Date().toISOString();
    const originType: NormalizedFinding['originType'] = options.originType || 'IMPORTED_REPORT';

    for (let rIdx = 0; rIdx < doc.runs.length; rIdx++) {
      const run = doc.runs[rIdx];
      if (!run || typeof run !== 'object' || Array.isArray(run)) {
        errors.push(`Entrada runs[${rIdx}] inválida: esperado objeto SARIF run.`);
        continue;
      }
      const driver = run.tool?.driver && typeof run.tool.driver === 'object' ? run.tool.driver : {};
      const toolName = String(
        driver.name || options.fallbackToolName || `External SARIF Tool #${rIdx + 1}`
      ).trim();
      const toolVersion = String(driver.version || driver.semanticVersion || 'unknown').trim();
      importedToolNames.push(toolName);

      const rulesById = new Map<string, Record<string, any>>();
      const ruleArrays = [
        ...(Array.isArray(driver.rules) ? driver.rules : []),
        ...(Array.isArray(run.tool?.extensions)
          ? run.tool.extensions.flatMap((ext: any) => (Array.isArray(ext?.rules) ? ext.rules : []))
          : []),
      ];
      for (const rule of ruleArrays) {
        if (rule?.id) rulesById.set(String(rule.id), rule);
      }

      const results = Array.isArray(run.results) ? run.results : [];
      for (let idx = 0; idx < results.length; idx++) {
        const res = results[idx];
        if (!res || typeof res !== 'object') {
          warnings.push(`runs[${rIdx}].results[${idx}] ignorado por não ser objeto.`);
          continue;
        }

        const ruleId = String(
          res.ruleId ||
            (typeof res.ruleIndex === 'number' && Array.isArray(driver.rules)
              ? driver.rules[res.ruleIndex]?.id
              : '') ||
            'external-sarif-rule'
        ).trim();
        const ruleMeta = rulesById.get(ruleId);
        const rawLoc = Array.isArray(res.locations) ? res.locations[0] : undefined;
        const physicalLoc = rawLoc?.physicalLocation;
        const hasPhysicalLocation = Boolean(
          physicalLoc && typeof physicalLoc === 'object' && physicalLoc.artifactLocation?.uri
        );
        const filePath = hasPhysicalLocation
          ? String(physicalLoc.artifactLocation.uri).replace(/^file:\/\//, '').replace(/\\/g, '/')
          : 'unknown';
        const region = physicalLoc?.region && typeof physicalLoc.region === 'object' ? physicalLoc.region : {};
        const parsedStartLine = Number(region.startLine);
        const startLine = Number.isFinite(parsedStartLine) && parsedStartLine > 0 ? Math.floor(parsedStartLine) : 1;
        const parsedEndLine = Number(region.endLine);
        const endLine =
          Number.isFinite(parsedEndLine) && parsedEndLine >= startLine ? Math.floor(parsedEndLine) : startLine;
        const parsedStartCol = Number(region.startColumn);
        const columnStart =
          Number.isFinite(parsedStartCol) && parsedStartCol > 0 ? Math.floor(parsedStartCol) : undefined;
        const parsedEndCol = Number(region.endColumn);
        const columnEnd =
          Number.isFinite(parsedEndCol) && parsedEndCol > 0 ? Math.floor(parsedEndCol) : undefined;
        const snippet = String(region.snippet?.text || '');

        if (!hasPhysicalLocation) {
          warnings.push(`SARIF result ${ruleId} em runs[${rIdx}].results[${idx}] sem physicalLocation; atribuído filePath="unknown".`);
        }

        const rawLevel = res.level ?? ruleMeta?.defaultConfiguration?.level;
        const normalizedLevel = String(rawLevel ?? '').trim().toLowerCase();
        if (
          rawLevel !== undefined &&
          !['error', 'warning', 'note', 'none'].includes(normalizedLevel)
        ) {
          warnings.push(`Severidade SARIF não reconhecida "${String(rawLevel)}" para regra ${ruleId}; aplicada severidade conservadora.`);
        }

        const cwe = extractCweFromSarif(res.properties, ruleMeta?.properties);
        const cvss = parseFiniteCvss(
          res.properties?.cvss,
          ruleMeta?.properties?.cvss,
          res.properties?.['security-severity'],
          ruleMeta?.properties?.['security-severity']
        );
        const severity = sarifLevelToSeverity(rawLevel, res.properties, ruleMeta?.properties);
        const confidence = resolveConfidenceFromSarif(
          hasPhysicalLocation,
          Boolean(ruleMeta),
          res.properties,
          ruleMeta?.properties
        );

        const messageText = String(
          res.message?.text || res.message?.markdown || ruleMeta?.fullDescription?.text || ruleMeta?.shortDescription?.text || ruleId
        ).trim();

        // Deterministic deduplication per tool/rule/location/message
        const dedupKey = `${toolName.toLowerCase()}|${ruleId}|${filePath}|${startLine}|${columnStart ?? 0}|${messageText.slice(0, 120)}`;
        if (seenDedupKeys.has(dedupKey)) {
          deduplicatedCount += 1;
          continue;
        }
        seenDedupKeys.add(dedupKey);

        const codeFlowSteps = Array.isArray(res.codeFlows?.[0]?.threadFlows?.[0]?.locations)
          ? res.codeFlows[0].threadFlows[0].locations.map((tl: any, sIdx: number) => ({
              stepOrder: sIdx + 1,
              nodeType:
                sIdx === 0
                  ? 'SOURCE'
                  : sIdx === res.codeFlows[0].threadFlows[0].locations.length - 1
                    ? 'SINK'
                    : 'PROPAGATOR',
              filePath: String(tl.location?.physicalLocation?.artifactLocation?.uri || filePath)
                .replace(/^file:\/\//, '')
                .replace(/\\/g, '/'),
              lineNumber: Math.max(1, Number(tl.location?.physicalLocation?.region?.startLine || startLine)),
              symbolName: ruleId,
              codeSnippet: String(tl.location?.physicalLocation?.region?.snippet?.text || ''),
              snippet: String(tl.location?.physicalLocation?.region?.snippet?.text || ''),
              explanation: String(tl.location?.message?.text || 'Imported SARIF flow step'),
            }))
          : undefined;

        const categoryRaw = String(res.properties?.category || ruleMeta?.properties?.category || '').toUpperCase();
        const category: NormalizedFinding['category'] =
          categoryRaw === 'SECRETS' ||
          categoryRaw === 'SCA' ||
          categoryRaw === 'IAC' ||
          categoryRaw === 'DATABASE' ||
          categoryRaw === 'CODE_QUALITY' ||
          categoryRaw === 'ARCHITECTURE'
            ? (categoryRaw as NormalizedFinding['category'])
            : 'SAST';

        const isSuppressed = Array.isArray(res.suppressions) && res.suppressions.length > 0;
        // CRITICAL: External SARIF findings are NEVER auto-promoted to VALIDATED/CONFIRMED.
        const validationStatus: NormalizedFinding['validationStatus'] = isSuppressed
          ? 'ACCEPTED_RISK'
          : 'UNVERIFIED';

        findings.push(
          enrichLegacyOrExternalFinding({
            id: `sarif-imp-${scope.runId}-${rIdx}-${idx}-${crypto
              .createHash('sha256')
              .update(`${toolName}:${ruleId}:${filePath}:${startLine}:${columnStart ?? 0}`)
              .digest('hex')
              .slice(0, 8)}`,
            runId: scope.runId,
            softwareId: scope.softwareId,
            softwareName: scope.softwareName,
            softwareVersion: scope.softwareVersion,
            toolName,
            toolVersion,
            originType,
            detectionMethod: 'EXTERNAL_SARIF_IMPORT',
            originalRuleId: ruleId,
            category,
            cwe,
            cvss,
            severity,
            confidence,
            validationStatus,
            lifecycleState: validationStatus,
            title: String(ruleMeta?.shortDescription?.text || messageText || ruleId).slice(0, 180),
            description: messageText,
            filePath,
            lineNumber: startLine,
            endLineNumber: endLine,
            columnStart,
            columnEnd,
            snippet,
            remediation: String(
              res.properties?.remediation ||
                ruleMeta?.help?.text ||
                'Revisar achado externo importado via padrão SARIF 2.1.0 (pendente de verificação independente no WinHood).'
            ),
            remediationEffortMinutes: Number(res.properties?.remediationEffortMinutes || 20),
            executionFlows: codeFlowSteps,
            collectedAt: nowIso,
          })
        );
      }
    }

    if (errors.length > 0) {
      return {
        valid: false,
        errors,
        warnings,
        importedToolNames: Array.from(new Set(importedToolNames)),
        findings: [],
        deduplicatedCount,
        payloadSha256: '',
      };
    }

    const payloadSha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(doc))
      .digest('hex');

    return {
      valid: true,
      errors: [],
      warnings,
      importedToolNames: Array.from(new Set(importedToolNames)),
      findings,
      deduplicatedCount,
      payloadSha256,
    };
  }
}
