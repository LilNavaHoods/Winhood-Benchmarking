import { execFileSync } from 'node:child_process';
import fs from 'node:fs';

export interface NormalizedExternalFinding {
  ruleId: string;
  engine: 'semgrep' | 'opengrep' | 'sarif-import';
  filePath: string;
  lineNumber: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  message: string;
  cweIds: string[];
}

const ALLOWED_ENGINES = new Set(['semgrep', 'opengrep']);

function mapSarifLevelToSeverity(level?: string): NormalizedExternalFinding['severity'] {
  switch ((level || '').toLowerCase()) {
    case 'error':
      return 'HIGH';
    case 'warning':
      return 'MEDIUM';
    case 'note':
      return 'LOW';
    default:
      return 'INFO';
  }
}

export function parseSarifToNormalizedFindings(
  sarifRaw: string,
  engine: NormalizedExternalFinding['engine'] = 'sarif-import'
): NormalizedExternalFinding[] {
  const doc = JSON.parse(sarifRaw) as { runs?: Array<{ results?: any[]; tool?: any }> };
  const output: NormalizedExternalFinding[] = [];

  for (const run of doc.runs || []) {
    const ruleTags = new Map<string, string[]>();
    for (const rule of run.tool?.driver?.rules || []) {
      const tags: string[] = Array.isArray(rule?.properties?.tags) ? rule.properties.tags : [];
      const cwes = tags.filter((t) => /CWE-\d+/i.test(t)).map((t) => t.toUpperCase());
      if (rule?.id) ruleTags.set(String(rule.id), cwes);
    }

    for (const res of run.results || []) {
      const loc = res?.locations?.[0]?.physicalLocation;
      const filePath = String(loc?.artifactLocation?.uri || 'unknown');
      const lineNumber = Number(loc?.region?.startLine || 1);
      const ruleId = String(res?.ruleId || 'external:unknown');
      output.push({
        ruleId,
        engine,
        filePath,
        lineNumber,
        severity: mapSarifLevelToSeverity(res?.level),
        message: String(res?.message?.text || 'Achado reportado por motor SARIF externo.'),
        cweIds: ruleTags.get(ruleId) || [],
      });
    }
  }
  return output;
}

export function runLocalRulesPack(params: {
  engine: 'semgrep' | 'opengrep';
  targetDir: string;
  localRulesConfigPath: string;
  timeoutMs?: number;
}): NormalizedExternalFinding[] {
  if (!ALLOWED_ENGINES.has(params.engine)) {
    throw new Error(`EXTERNAL_ENGINE_FORBIDDEN: Motor "${params.engine}" não permitido.`);
  }
  if (!fs.existsSync(params.localRulesConfigPath)) {
    throw new Error(`RULES_CONFIG_NOT_FOUND: Pacote local não encontrado em ${params.localRulesConfigPath}`);
  }

  const stdout = execFileSync(
    params.engine,
    [
      'scan',
      '--config',
      params.localRulesConfigPath,
      '--sarif',
      '--metrics=off',
      '--quiet',
      params.targetDir,
    ],
    {
      encoding: 'utf8',
      shell: false,
      timeout: params.timeoutMs ?? 120_000,
      maxBuffer: 30 * 1024 * 1024,
    }
  );

  return parseSarifToNormalizedFindings(stdout, params.engine);
}
