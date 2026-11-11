import crypto from 'node:crypto';
import type {
  BenchmarkCategoryKey,
  BenchmarkProfileConfig,
  CategoryEvaluationReason,
  CategoryScoreDetail,
  CleanCodeAttribute,
  MqrCategoryImpact,
  NormalizedFinding,
  PenaltyCapTriggered,
  QualityGateConditionDetail,
  SeverityLevel,
  SoftwareQualityAttribute,
  SoftwareScoreCard,
  VeracityClassification,
} from '../types/benchmark';

export const ALGORITHM_VERSION = 'WINHOOD-SONAR-MQR-v3.0.0';

export const ALL_BENCHMARK_CATEGORIES: BenchmarkCategoryKey[] = [
  'functionality',
  'code_quality',
  'security',
  'performance',
  'architecture',
  'database',
  'reliability',
  'compatibility',
  'usability',
  'installation',
  'privacy',
  'documentation',
];

export const DEFAULT_CATEGORY_WEIGHTS: Record<BenchmarkCategoryKey, number> = {
  functionality: 12,
  code_quality: 12,
  security: 18,
  performance: 10,
  architecture: 10,
  database: 8,
  reliability: 8,
  compatibility: 5,
  usability: 5,
  installation: 4,
  privacy: 4,
  documentation: 4,
};

export function computeSha256(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

export function maskSecretsInText(input: string): string {
  if (!input) return input;
  return input
    // Mask AWS Access Key IDs
    .replace(/\b(AKIA[0-9A-Z]{4})[0-9A-Z]{12}\b/g, '$1************')
    // Mask Bearer / API tokens / sk- keys
    .replace(/\b(sk-[a-zA-Z0-9]{4})[a-zA-Z0-9_-]{12,}\b/g, '$1****************')
    .replace(/\b(ghp_[a-zA-Z0-9]{4})[a-zA-Z0-9]{20,}\b/g, '$1********************')
    // Mask hardcoded secret/password/token assignments in code snippets
    .replace(
      /((?:password|passwd|secret|api_key|apiKey|masterKey|privateKey|jwtSecret|token)\s*[:=]\s*['"`])([^'"`\n]{6,})(['"`])/gi,
      (_match, prefix: string, secretVal: string, suffix: string) => {
        const visiblePrefix = secretVal.slice(0, 3);
        return `${prefix}${visiblePrefix}${'*'.repeat(Math.min(12, Math.max(6, secretVal.length - 3)))}${suffix}`;
      }
    );
}

/**
 * Normalizes category weights dynamically when a subset of categories is enabled,
 * ensuring that disabled categories have weight 0 and enabled categories sum to 100%.
 */
export function normalizeEnabledCategoryWeights(
  weights: Partial<Record<BenchmarkCategoryKey, number>>,
  enabledCategories?: BenchmarkCategoryKey[]
): Record<BenchmarkCategoryKey, number> {
  const activeList =
    enabledCategories && enabledCategories.length > 0
      ? enabledCategories
      : ALL_BENCHMARK_CATEGORIES;
  const activeSet = new Set<BenchmarkCategoryKey>(activeList);

  let rawSum = 0;
  for (const key of ALL_BENCHMARK_CATEGORIES) {
    if (activeSet.has(key)) {
      const w = weights[key] ?? DEFAULT_CATEGORY_WEIGHTS[key] ?? 0;
      rawSum += Math.max(0, w);
    }
  }

  const normalized: Record<BenchmarkCategoryKey, number> = { ...DEFAULT_CATEGORY_WEIGHTS };

  if (rawSum <= 0) {
    const equalShare = Math.floor((100 / activeList.length) * 100) / 100;
    let allocated = 0;
    for (const key of ALL_BENCHMARK_CATEGORIES) {
      if (activeSet.has(key)) {
        normalized[key] = equalShare;
        allocated = Math.round((allocated + equalShare) * 100) / 100;
      } else {
        normalized[key] = 0;
      }
    }
    const firstKey = activeList[0];
    if (firstKey) {
      normalized[firstKey] = Math.round((normalized[firstKey] + (100 - allocated)) * 100) / 100;
    }
    return normalized;
  }

  let runningSum = 0;
  for (const key of ALL_BENCHMARK_CATEGORIES) {
    if (!activeSet.has(key)) {
      normalized[key] = 0;
    } else {
      const w = Math.max(0, weights[key] ?? DEFAULT_CATEGORY_WEIGHTS[key] ?? 0);
      const scaled = Math.round(((w / rawSum) * 100) * 100) / 100;
      normalized[key] = scaled;
      runningSum = Math.round((runningSum + scaled) * 100) / 100;
    }
  }

  const remainder = Math.round((100 - runningSum) * 100) / 100;
  if (Math.abs(remainder) > 0 && activeList.length > 0) {
    const targetKey = activeList.find((k) => normalized[k] + remainder >= 0) || activeList[0]!;
    normalized[targetKey] = Math.round((normalized[targetKey] + remainder) * 100) / 100;
  }

  return normalized;
}

export function validateCategoryWeights(
  weights: Record<BenchmarkCategoryKey, number>,
  enabledCategories?: BenchmarkCategoryKey[]
): {
  valid: boolean;
  totalWeight: number;
  errors: string[];
} {
  const errors: string[] = [];
  const activeSet =
    enabledCategories && enabledCategories.length > 0
      ? new Set<BenchmarkCategoryKey>(enabledCategories)
      : null;
  let sum = 0;

  for (const key of ALL_BENCHMARK_CATEGORIES) {
    if (activeSet && !activeSet.has(key)) {
      continue;
    }
    const val = weights[key];
    if (typeof val !== 'number' || Number.isNaN(val)) {
      errors.push(`Peso inválido ou ausente para a categoria '${key}'.`);
      continue;
    }
    if (val < 0 || val > 100) {
      errors.push(`Peso da categoria '${key}' (${val}%) deve estar entre 0% e 100%.`);
    }
    sum += val;
  }

  const roundedSum = Math.round(sum * 100) / 100;
  if (Math.abs(roundedSum - 100) > 0.01) {
    errors.push(`A soma matemática dos pesos deve ser exatamente 100% (atual: ${roundedSum}%).`);
  }

  return {
    valid: errors.length === 0,
    totalWeight: roundedSum,
    errors,
  };
}

export function validateEquivalenceConditions(
  env: BenchmarkProfileConfig['equivalenceEnvironment']
): {
  equivalent: boolean;
  reasons: string[];
} {
  const reasons: string[] = [];
  if (!env) {
    return { equivalent: false, reasons: ['Configuração de ambiente experimental ausente.'] };
  }
  if (env.cpuCoresLimit <= 0 || env.cpuCoresLimit > 64) {
    reasons.push('Limite de CPU inválido para equivalência experimental (deve ser 1–64 vCPUs).');
  }
  if (env.memoryMbLimit < 128 || env.memoryMbLimit > 65536) {
    reasons.push('Limite de RAM inválido para equivalência experimental (128 MB – 65536 MB).');
  }
  if (!env.osTarget || env.osTarget.trim().length < 2) {
    reasons.push('Sistema operacional alvo não especificado para o worker de benchmark.');
  }
  if (env.workloadConcurrency <= 0 || env.workloadConcurrency > 5000) {
    reasons.push('Concorrência de carga fora dos limites seguros controlados (1–5000 VUs).');
  }
  return {
    equivalent: reasons.length === 0,
    reasons,
  };
}

export function classifyScoreScale(
  score: number
): 'Inexistente' | 'Crítico' | 'Insuficiente' | 'Adequado' | 'Muito bom' | 'Excelente' {
  if (score < 0.5) return 'Inexistente';
  if (score < 1.8) return 'Crítico';
  if (score < 2.8) return 'Insuficiente';
  if (score < 3.7) return 'Adequado';
  if (score < 4.5) return 'Muito bom';
  return 'Excelente';
}

/**
 * Enriches any legacy, fixture, or external SARIF/Sonar/Gitar finding with full SonarQube MQR
 * metadata (`cleanCodeAttribute`, `mqrImpacts`, `whyItIsAnIssue`, `evaluationImpactSummary`,
 * `remediationEffortMinutes`, `isNewCode`) so no downstream report or type check fails.
 */
export function enrichLegacyOrExternalFinding(
  partial: Partial<NormalizedFinding> &
    Pick<
      NormalizedFinding,
      'originalRuleId' | 'title' | 'description' | 'severity' | 'filePath' | 'lineNumber' | 'snippet'
    >
): NormalizedFinding {
  const category = partial.category || 'CODE_QUALITY';
  const severity = partial.severity || 'MEDIUM';
  const ruleLower = (partial.originalRuleId || '').toLowerCase();

  const defaultCleanCodeAttribute: CleanCodeAttribute =
    category === 'SAST' || category === 'SECRETS' || category === 'SCA' || category === 'DAST'
      ? 'RESPONSIBLE'
      : category === 'ARCHITECTURE'
        ? 'ADAPTABLE'
        : category === 'DATABASE'
          ? 'INTENTIONAL'
          : 'CONSISTENT';

  const defaultEffort =
    severity === 'BLOCKER'
      ? 90
      : severity === 'CRITICAL'
        ? 60
        : severity === 'HIGH'
          ? 45
          : severity === 'MEDIUM'
            ? 25
            : severity === 'LOW'
              ? 15
              : 10;

  let defaultMqrImpacts: MqrCategoryImpact[] = [];
  if (partial.mqrImpacts && partial.mqrImpacts.length > 0) {
    defaultMqrImpacts = partial.mqrImpacts;
  } else if (category === 'SECRETS' || ruleLower.includes('secret') || ruleLower.includes('credential')) {
    defaultMqrImpacts = [
      {
        softwareQuality: 'SECURITY',
        benchmarkCategory: 'security',
        severity: 'BLOCKER',
        scoreDeduction: -1.2,
        rationale: `Credencial/segredo exposto em ${partial.filePath}:${partial.lineNumber} compromete confidencialidade criptográfica.`,
      },
      {
        softwareQuality: 'SECURITY',
        benchmarkCategory: 'privacy',
        severity: 'CRITICAL',
        scoreDeduction: -0.9,
        rationale: `Segredo hardcoded expõe dados protegidos no repositório em ${partial.filePath}:${partial.lineNumber}.`,
      },
    ];
  } else if (category === 'SAST' || category === 'DAST') {
    const secDelta =
      severity === 'BLOCKER' || severity === 'CRITICAL'
        ? -1.45
        : severity === 'HIGH'
          ? -0.65
          : severity === 'MEDIUM'
            ? -0.25
            : -0.08;
    defaultMqrImpacts = [
      {
        softwareQuality: 'SECURITY',
        benchmarkCategory: 'security',
        severity: severity === 'CRITICAL' && (partial.cvss ?? 0) >= 9.0 ? 'BLOCKER' : severity,
        scoreDeduction: secDelta,
        rationale: `Vulnerabilidade SAST/DAST (${partial.originalRuleId}) verificada em ${partial.filePath}:${partial.lineNumber}.`,
      },
    ];
    if (ruleLower.includes('sql')) {
      defaultMqrImpacts.push({
        softwareQuality: 'SECURITY',
        benchmarkCategory: 'database',
        severity: 'HIGH',
        scoreDeduction: -0.55,
        rationale: `Construção insegura de query SQL em ${partial.filePath}:${partial.lineNumber}.`,
      });
    }
    if (ruleLower.includes('exec') || ruleLower.includes('eval')) {
      defaultMqrImpacts.push({
        softwareQuality: 'RELIABILITY',
        benchmarkCategory: 'reliability',
        severity: 'CRITICAL',
        scoreDeduction: -0.4,
        rationale: `Execução dinâmica bloqueante ou insegura em ${partial.filePath}:${partial.lineNumber}.`,
      });
    }
  } else if (category === 'SCA' || category === 'SBOM') {
    const scaDelta =
      severity === 'BLOCKER' || severity === 'CRITICAL'
        ? -1.45
        : severity === 'HIGH'
          ? -0.65
          : -0.25;
    defaultMqrImpacts = [
      {
        softwareQuality: 'SECURITY',
        benchmarkCategory: 'security',
        severity,
        scoreDeduction: scaDelta,
        rationale: `Dependência vulnerável (${partial.component || partial.originalRuleId}) declarada em ${partial.filePath}:${partial.lineNumber}.`,
      },
      {
        softwareQuality: 'MAINTAINABILITY',
        benchmarkCategory: 'compatibility',
        severity: 'MEDIUM',
        scoreDeduction: -0.2,
        rationale: `Pacote legado desatualizado impacta matriz de compatibilidade em ${partial.filePath}.`,
      },
    ];
  } else if (category === 'ARCHITECTURE') {
    const isCircular = ruleLower.includes('circular');
    defaultMqrImpacts = [
      {
        softwareQuality: 'MAINTAINABILITY',
        benchmarkCategory: 'architecture',
        severity: isCircular ? 'HIGH' : 'MEDIUM',
        scoreDeduction: isCircular ? -1.1 : -0.6,
        rationale: `Violação estrutural (${partial.originalRuleId}) em ${partial.filePath}:${partial.lineNumber}.`,
      },
      {
        softwareQuality: 'MAINTAINABILITY',
        benchmarkCategory: 'code_quality',
        severity: 'MEDIUM',
        scoreDeduction: -0.08,
        rationale: `Acoplamento estrutural degradando modularidade em ${partial.filePath}:${partial.lineNumber}.`,
      },
    ];
  } else if (category === 'DATABASE') {
    defaultMqrImpacts = [
      {
        softwareQuality: 'MAINTAINABILITY',
        benchmarkCategory: 'database',
        severity,
        scoreDeduction: -0.55,
        rationale: `Não-conformidade de schema/query SQL (${partial.originalRuleId}) em ${partial.filePath}:${partial.lineNumber}.`,
      },
    ];
    if (severity === 'HIGH' || severity === 'CRITICAL' || ruleLower.includes('plain')) {
      defaultMqrImpacts.push({
        softwareQuality: 'SECURITY',
        benchmarkCategory: 'security',
        severity: 'HIGH',
        scoreDeduction: -0.65,
        rationale: `Ausência de proteção criptográfica de coluna sensível em ${partial.filePath}:${partial.lineNumber}.`,
      });
    }
  } else {
    // CODE_QUALITY / IAC / OS_SANDBOX
    const isBug = severity === 'HIGH' || severity === 'CRITICAL' || severity === 'BLOCKER' || ruleLower.includes('catch');
    defaultMqrImpacts = [
      {
        softwareQuality: isBug ? 'RELIABILITY' : 'MAINTAINABILITY',
        benchmarkCategory: 'code_quality',
        severity,
        scoreDeduction: isBug ? -0.35 : -0.08,
        rationale: `${isBug ? 'Bug operacional' : 'Code smell'} (${partial.originalRuleId}) em ${partial.filePath}:${partial.lineNumber}.`,
      },
    ];
    if (isBug) {
      defaultMqrImpacts.push({
        softwareQuality: 'RELIABILITY',
        benchmarkCategory: 'reliability',
        severity: 'HIGH',
        scoreDeduction: -0.2,
        rationale: `Falha de tratamento de erro afeta confiabilidade em tempo de execução (${partial.filePath}:${partial.lineNumber}).`,
      });
    }
  }

  const normalizedImpacts: MqrCategoryImpact[] = defaultMqrImpacts.map((imp) => ({
    ...imp,
    benchmarkCategory: imp.benchmarkCategory || (imp.category as BenchmarkCategoryKey) || 'code_quality',
    category: imp.category || imp.benchmarkCategory || 'code_quality',
    softwareQuality: imp.softwareQuality || imp.qualityAttribute || 'MAINTAINABILITY',
    qualityAttribute: imp.qualityAttribute || imp.softwareQuality || 'MAINTAINABILITY',
  }));

  const normalizedFlows = (partial.executionFlows || []).map((step, idx) => ({
    ...step,
    stepOrder: step.stepOrder ?? step.stepIndex ?? idx + 1,
    stepIndex: step.stepIndex ?? step.stepOrder ?? idx + 1,
    nodeType: step.nodeType || step.nodeKind || 'PROPAGATOR',
    nodeKind: step.nodeKind || step.nodeType || 'PROPAGATOR',
  }));

  const impactSummaryText = normalizedImpacts
    .map(
      (imp) =>
        `${imp.benchmarkCategory}: ${imp.scoreDeduction >= 0 ? '+' : ''}${imp.scoreDeduction.toFixed(2)} pts (${imp.softwareQuality}/${imp.severity})`
    )
    .join(' | ');

  const whyItIsAnIssue =
    partial.whyItIsAnIssue ||
    `O arquivo ${partial.filePath} (linha ${partial.lineNumber}) contém o padrão [${partial.originalRuleId}] no trecho \`${partial.snippet}\`. ${partial.description} Isso viola o atributo Clean Code ${partial.cleanCodeAttribute || defaultCleanCodeAttribute} e reduz diretamente a pontuação das categorias afetadas (${impactSummaryText}).`;

  const maskedSnippet = maskSecretsInText(partial.snippet);
  const softwareId = partial.softwareId || 'sw-unknown';
  const toolId = partial.toolId || 'external-sarif';
  const evidenceSha256 =
    partial.evidenceSha256 ||
    computeSha256(
      `${softwareId}|${toolId}|${partial.originalRuleId}|${partial.filePath}|${partial.lineNumber}|${maskedSnippet}`
    );

  return {
    id: partial.id || `fnd-${evidenceSha256.slice(0, 12)}`,
    runId: partial.runId || 'run-default',
    softwareId,
    softwareName: partial.softwareName || 'Software Auditado',
    softwareVersion: partial.softwareVersion || '1.0.0',
    toolId,
    toolName: partial.toolName || 'External Static Analyzer',
    toolVersion: partial.toolVersion || '1.0.0',
    category,
    originalRuleId: partial.originalRuleId,
    title: partial.title,
    description: partial.description,
    severity,
    confidence: partial.confidence || 'HIGH',
    cleanCodeAttribute: partial.cleanCodeAttribute || defaultCleanCodeAttribute,
    mqrImpacts: normalizedImpacts,
    isNewCode: partial.isNewCode ?? true,
    filePath: partial.filePath,
    lineNumber: partial.lineNumber,
    endLineNumber: partial.endLineNumber ?? partial.lineNumber,
    columnStart: partial.columnStart ?? 1,
    columnEnd: partial.columnEnd ?? Math.max(2, maskedSnippet.length + 1),
    component: partial.component || partial.filePath.split('/').pop() || partial.filePath,
    snippet: maskedSnippet,
    contextBefore: partial.contextBefore || [],
    contextAfter: partial.contextAfter || [],
    whyItIsAnIssue,
    evaluationImpactSummary: partial.evaluationImpactSummary || impactSummaryText,
    executionFlows: normalizedFlows,
    compliantCodeExample:
      partial.compliantCodeExample ||
      `// Correção recomendada (${partial.originalRuleId}):\n// ${partial.remediation || 'Aplicar padrão seguro recomendado pela regra.'}`,
    remediationEffortMinutes: partial.remediationEffortMinutes ?? defaultEffort,
    cwe: partial.cwe,
    cve: partial.cve,
    cvss: partial.cvss,
    epss: partial.epss,
    cisaKev: partial.cisaKev,
    remediation: partial.remediation || 'Revisar e corrigir o trecho conforme o guia da regra.',
    evidenceSha256,
    validationStatus: partial.validationStatus || 'VALIDATED',
    collectedAt: partial.collectedAt || new Date().toISOString(),
  };
}

export function computeSonarSeverityRating(
  severities: SeverityLevel[]
): 'A' | 'B' | 'C' | 'D' | 'E' {
  if (severities.includes('BLOCKER')) return 'E';
  if (severities.includes('CRITICAL')) return 'D';
  if (severities.includes('HIGH')) return 'C';
  if (severities.includes('MEDIUM')) return 'B';
  return 'A';
}

export function computeSonarMaintainabilityRating(
  technicalDebtMinutes: number,
  loc: number,
  duplicatedLinesPercent = 0
): 'A' | 'B' | 'C' | 'D' | 'E' {
  const effectiveDevelopmentMinutes = Math.max(60, Math.max(25, loc) * 3.2);
  const debtRatioPercent = (technicalDebtMinutes / effectiveDevelopmentMinutes) * 100;
  if (debtRatioPercent <= 5.0 && duplicatedLinesPercent <= 3.0) return 'A';
  if (debtRatioPercent <= 10.0) return 'B';
  if (debtRatioPercent <= 20.0) return 'C';
  if (debtRatioPercent <= 50.0) return 'D';
  return 'E';
}

export function scoreToCategoryRating(score: number | null): 'A' | 'B' | 'C' | 'D' | 'E' | null {
  if (score === null) return null;
  if (score >= 4.2) return 'A';
  if (score >= 3.4) return 'B';
  if (score >= 2.5) return 'C';
  if (score >= 1.5) return 'D';
  return 'E';
}

export interface RawEvaluationInput {
  softwareId: string;
  softwareName: string;
  softwareVersion: string;
  veracityClassification: VeracityClassification;
  coveragePercent: number;
  eligibleForScoring?: boolean;
  essentialFeaturesMissing: number;
  visualOnlyFeaturesCount: number;
  metrics: SoftwareScoreCard['metricsSummary'];
  hasEncryptionAtRest: boolean;
  hasAuditTrail: boolean;
  hasCleanSandboxUninstall: boolean | null;
  hasCompleteDocumentation: boolean;
  environmentEquivalent: boolean;
  findings?: NormalizedFinding[];
  enabledCategories?: BenchmarkCategoryKey[];
  notApplicableCategories?: BenchmarkCategoryKey[];
  criteriaOutcomes?: import('../types/benchmark').CriterionEvaluationOutcome[];
  qualityGateId?: string;
  newCodeLinesCount?: number;
  runtimeMetrics?: {
    status: 'MEASURED' | 'NOT_MEASURED';
    reason?: string;
  };
  staticMetrics?: {
    loc: number;
    cyclomaticComplexity: number;
    cognitiveComplexity: number;
    duplicatedLinesPercent: number;
    couplingIndex: number;
    cohesionIndex: number;
    circularDependenciesCount: number;
    layerViolationsCount: number;
    riskIndicators: string[];
  };
}

export function calculateDeterministicScoreCard(
  input: RawEvaluationInput,
  weights: Record<BenchmarkCategoryKey, number>,
  enablePenaltyCaps = true
): SoftwareScoreCard {
  const round2 = (v: number) => Math.round(v * 100) / 100;
  const clamp05 = (val: number) => Math.max(0, Math.min(5, round2(val)));

  const notApplicableSet = new Set<BenchmarkCategoryKey>(input.notApplicableCategories || []);
  const enabledList = (
    input.enabledCategories && input.enabledCategories.length > 0
      ? input.enabledCategories
      : ALL_BENCHMARK_CATEGORIES
  ).filter((c) => !notApplicableSet.has(c));
  const enabledSet = new Set<BenchmarkCategoryKey>(enabledList);
  const originalWeights = { ...DEFAULT_CATEGORY_WEIGHTS, ...weights };
  const normalizedWeights = normalizeEnabledCategoryWeights(weights, enabledList);

  const isEligibleForScoring =
    input.eligibleForScoring !== false &&
    input.veracityClassification !== 'EMPTY_ERROR' &&
    input.veracityClassification !== 'SOURCE_MISSING' &&
    input.veracityClassification !== 'NOT_AVAILABLE' &&
    input.veracityClassification !== 'EXECUTION_FAILED' &&
    input.coveragePercent > 0;

  const hasExplicitFindingsArray = Array.isArray(input.findings);
  const enrichedFindings = (input.findings || []).map((f) => ({
    ...enrichLegacyOrExternalFinding(f),
    validationStatus: f.lifecycleState || f.validationStatus || 'VALIDATED',
    lifecycleState: f.lifecycleState || f.validationStatus || 'VALIDATED',
  }));
  const EXEMPT_LIFECYCLE_STATES = new Set([
    'FALSE_POSITIVE_REVIEWED',
    'FALSE_POSITIVE',
    'ACCEPTED',
    'ACCEPTED_RISK',
    'VERIFIED_RESOLVED',
    'NOT_REPRODUCIBLE',
    'INCONCLUSIVE',
  ]);
  const activeFindings = enrichedFindings.filter(
    (f) => !EXEMPT_LIFECYCLE_STATES.has(f.validationStatus) && !EXEMPT_LIFECYCLE_STATES.has(f.lifecycleState || '')
  );

  // Reconcile metricsSummary with activeFindings if findings were passed (so DevSecOps triage updates counts in real time)
  const m: SoftwareScoreCard['metricsSummary'] = { ...input.metrics };
  if (hasExplicitFindingsArray) {
    let activeCrit = 0;
    let activeHigh = 0;
    let activeMed = 0;
    let activeLow = 0;
    let activeSecrets = 0;
    let activeBugs = 0;
    let activeSmells = 0;
    let activeDbIssues = 0;
    let activeCircular = 0;
    let activeDebtMins = 0;

    for (const f of activeFindings) {
      activeDebtMins += f.remediationEffortMinutes || 15;
      if (f.category === 'SECRETS') {
        activeSecrets += 1;
      }
      if (f.category === 'DATABASE') {
        activeDbIssues += 1;
      }
      if (f.originalRuleId.includes('circular')) {
        activeCircular += 1;
      }
      if (f.category === 'CODE_QUALITY') {
        if (f.severity === 'BLOCKER' || f.severity === 'CRITICAL' || f.severity === 'HIGH') {
          activeBugs += 1;
        } else {
          activeSmells += 1;
        }
      } else if (f.category === 'ARCHITECTURE') {
        if (f.originalRuleId.includes('circular')) {
          activeSmells += 1;
        } else {
          activeMed += 1;
        }
      } else {
        if (f.severity === 'BLOCKER' || f.severity === 'CRITICAL') activeCrit += 1;
        else if (f.severity === 'HIGH') activeHigh += 1;
        else if (f.severity === 'MEDIUM') activeMed += 1;
        else if (f.severity === 'LOW') activeLow += 1;
      }
    }

    m.bugs = activeBugs;
    m.codeSmells = activeSmells;
    m.criticalVulns = activeCrit;
    m.highVulns = activeHigh;
    m.mediumVulns = activeMed;
    m.lowVulns = activeLow;
    m.vulnerabilities = activeCrit + activeHigh + activeMed + activeLow;
    m.secretsExposed = activeSecrets;
    m.dbSchemaIssues = activeDbIssues;
    m.circularDependencies = activeCircular;
    m.technicalDebtMinutes = activeDebtMins;
  }

  // Initialize evaluationReasons map for all 12 categories
  const reasonsByCat: Record<BenchmarkCategoryKey, CategoryEvaluationReason[]> = {
    functionality: [],
    code_quality: [],
    security: [],
    performance: [],
    architecture: [],
    database: [],
    reliability: [],
    compatibility: [],
    usability: [],
    installation: [],
    privacy: [],
    documentation: [],
  };

  const pushReason = (cat: BenchmarkCategoryKey, reason: Omit<CategoryEvaluationReason, 'id' | 'category'>) => {
    const idSeed = `${input.softwareId}|${cat}|${reason.ruleId}|${reason.filePath || 'metric'}|${reason.lineNumber || 0}|${reasonsByCat[cat].length}`;
    const resolvedOriginType =
      reason.originType ||
      (reason.impactType === 'PENALTY' && reason.findingId ? 'FINDING_PENALTY' : reason.impactType);
    reasonsByCat[cat].push({
      ...reason,
      id: `evr-${computeSha256(idSeed).slice(0, 10)}`,
      category: cat,
      originType: resolvedOriginType,
      toolName: reason.toolName || 'WinHood Static & MQR Engine',
      scoreDelta: round2(reason.scoreDelta),
    });
  };

  // Step A: Populate code-level PENALTY reasons from activeFindings' mqrImpacts
  if (hasExplicitFindingsArray) {
    for (const f of activeFindings) {
      for (const imp of f.mqrImpacts) {
        const targetCat = imp.benchmarkCategory;
        if (!reasonsByCat[targetCat]) continue;
        pushReason(targetCat, {
          impactType: imp.scoreDeduction <= 0 ? 'PENALTY' : 'BONUS',
          originType: imp.scoreDeduction <= 0 ? 'FINDING_PENALTY' : 'BONUS',
          toolName: f.toolName,
          scoreDelta: imp.scoreDeduction,
          severity: imp.severity,
          ruleId: f.originalRuleId,
          cwe: f.cwe,
          cve: f.cve,
          title: f.title,
          whyExplanation: `${imp.rationale} — ${f.whyItIsAnIssue}`,
          filePath: f.filePath,
          lineNumber: f.lineNumber,
          endLineNumber: f.endLineNumber,
          columnStart: f.columnStart,
          columnEnd: f.columnEnd,
          codeSnippet: f.snippet,
          contextBefore: f.contextBefore,
          contextAfter: f.contextAfter,
          executionFlow: f.executionFlows,
          remediationSummary: f.remediation,
          compliantCodeExample: f.compliantCodeExample,
          remediationEffortMinutes: f.remediationEffortMinutes,
          findingId: f.id,
        });
      }
    }
  } else {
    // Fallback when calculateDeterministicScoreCard is invoked with raw metrics only (without findings array)
    if (m.bugs > 0) {
      pushReason('code_quality', {
        impactType: 'PENALTY',
        scoreDelta: -round2(m.bugs * 0.35),
        severity: 'HIGH',
        ruleId: 'sonar.S2486.bugs-detected',
        title: `${m.bugs} bug(s) de confiabilidade e tratamento de exceções detectado(s)`,
        whyExplanation: `Foram contabilizados ${m.bugs} bug(s) estáticos (-0.35 pts por bug), indicando captura de exceção vazia ou fluxos de falha silenciados.`,
        remediationSummary: 'Tratar ou propagar exceções explicitamente com telemetria estruturada.',
        remediationEffortMinutes: m.bugs * 45,
      });
      pushReason('reliability', {
        impactType: 'PENALTY',
        scoreDelta: -round2(m.bugs * 0.2),
        severity: 'HIGH',
        ruleId: 'sonar.reliability.bugs-impact',
        title: `Impacto de ${m.bugs} bug(s) na confiabilidade operacional`,
        whyExplanation: `Cada bug verificado desconta -0.20 pts na categoria Confiabilidade devido ao risco de estado inconsistente em runtime.`,
        remediationEffortMinutes: m.bugs * 30,
      });
    }
    if (m.codeSmells > 0) {
      pushReason('code_quality', {
        impactType: 'PENALTY',
        scoreDelta: -round2(m.codeSmells * 0.08),
        severity: 'LOW',
        ruleId: 'sonar.maintainability.code-smells',
        title: `${m.codeSmells} code smell(s) de manutenibilidade detectado(s)`,
        whyExplanation: `Foram detectados ${m.codeSmells} code smells (-0.08 pts cada), como uso explícito de any, marcadores TODO/FIXME ou acoplamento entre módulos.`,
        remediationSummary: 'Refatorar tipagem estática e resolver pendências TODO/FIXME.',
        remediationEffortMinutes: m.codeSmells * 15,
      });
    }
    if (m.criticalVulns > 0) {
      pushReason('security', {
        impactType: 'PENALTY',
        scoreDelta: -round2(m.criticalVulns * 1.45),
        severity: 'BLOCKER',
        ruleId: 'opengrep.security.critical-vulnerabilities',
        title: `${m.criticalVulns} vulnerabilidade(s) crítica(s) SAST/Secrets detectada(s)`,
        whyExplanation: `Cada vulnerabilidade crítica (SQL Injection, RCE ou Hardcoded Secret) aplica dedução direta de -1.45 pts na categoria Segurança.`,
        remediationSummary: 'Parametrizar queries SQL, eliminar execSync/eval e externalizar segredos.',
        remediationEffortMinutes: m.criticalVulns * 60,
      });
      pushReason('reliability', {
        impactType: 'PENALTY',
        scoreDelta: -round2(m.criticalVulns * 0.4),
        severity: 'CRITICAL',
        ruleId: 'opengrep.reliability.critical-vuln-exposure',
        title: `Impacto de ${m.criticalVulns} falha(s) crítica(s) na estabilidade de execução`,
        whyExplanation: `Falhas críticas de execução de comando/SQLi descontam -0.40 pts cada em Confiabilidade.`,
        remediationEffortMinutes: m.criticalVulns * 30,
      });
    }
    if (m.highVulns > 0) {
      pushReason('security', {
        impactType: 'PENALTY',
        scoreDelta: -round2(m.highVulns * 0.65),
        severity: 'HIGH',
        ruleId: 'opengrep.security.high-vulnerabilities',
        title: `${m.highVulns} vulnerabilidade(s) de alta severidade (Criptografia Fraca / SCA / Schema)`,
        whyExplanation: `Cada vulnerabilidade HIGH (ex: MD5/SHA-1, coluna plaintext ou CVE em dependência) desconta -0.65 pts em Segurança.`,
        remediationSummary: 'Adotar Argon2id/AES-256-GCM e atualizar dependências vulneráveis.',
        remediationEffortMinutes: m.highVulns * 45,
      });
    }
    if (m.mediumVulns > 0) {
      pushReason('security', {
        impactType: 'PENALTY',
        scoreDelta: -round2(m.mediumVulns * 0.25),
        severity: 'MEDIUM',
        ruleId: 'opengrep.security.medium-vulnerabilities',
        title: `${m.mediumVulns} vulnerabilidade(s) de média severidade (PRNG inseguro / Bypass de camada)`,
        whyExplanation: `Cada vulnerabilidade MEDIUM desconta -0.25 pts em Segurança.`,
        remediationEffortMinutes: m.mediumVulns * 25,
      });
    }
    if (m.lowVulns > 0) {
      pushReason('security', {
        impactType: 'PENALTY',
        scoreDelta: -round2(m.lowVulns * 0.08),
        severity: 'LOW',
        ruleId: 'opengrep.security.low-vulnerabilities',
        title: `${m.lowVulns} apontamento(s) de baixa severidade em segurança`,
        whyExplanation: `Cada apontamento LOW desconta -0.08 pts em Segurança.`,
        remediationEffortMinutes: m.lowVulns * 10,
      });
    }
    if (m.secretsExposed > 0) {
      pushReason('security', {
        impactType: 'PENALTY',
        scoreDelta: -round2(m.secretsExposed * 1.2),
        severity: 'BLOCKER',
        ruleId: 'gitleaks.hardcoded-credential',
        title: `${m.secretsExposed} segredo(s) ou chave(s) mestra(s) hardcoded no código-fonte`,
        whyExplanation: `Exposição direta de credencial no código-fonte desconta -1.20 pts por segredo em Segurança.`,
        remediationSummary: 'Remover chave fixa do código, rotacionar credencial e injetar via Secret Manager.',
        remediationEffortMinutes: m.secretsExposed * 60,
      });
      pushReason('privacy', {
        impactType: 'PENALTY',
        scoreDelta: -round2(m.secretsExposed * 0.9),
        severity: 'CRITICAL',
        ruleId: 'gitleaks.privacy-secret-exposure',
        title: `${m.secretsExposed} segredo(s) exposto(s) comprometendo sigilo de dados`,
        whyExplanation: `Chaves mestras fixas no código descontam -0.90 pts em Privacidade e Proteção de Dados.`,
        remediationEffortMinutes: m.secretsExposed * 45,
      });
    }
    if (m.circularDependencies > 0) {
      pushReason('architecture', {
        impactType: 'PENALTY',
        scoreDelta: -round2(m.circularDependencies * 1.1),
        severity: 'HIGH',
        ruleId: 'arch.no-circular-dependency',
        title: `${m.circularDependencies} ciclo(s) de dependência circular entre módulos`,
        whyExplanation: `Cada ciclo bidirecional entre módulos desconta -1.10 pts em Arquitetura por impedir isolamento de camadas.`,
        remediationSummary: 'Aplicar Inversão de Dependência (DIP) extraindo contratos para o domínio.',
        remediationEffortMinutes: m.circularDependencies * 90,
      });
    }
    if (m.dbSchemaIssues > 0) {
      pushReason('database', {
        impactType: 'PENALTY',
        scoreDelta: -round2(m.dbSchemaIssues * 0.55),
        severity: 'MEDIUM',
        ruleId: 'sqlfluff.schema-audit-issues',
        title: `${m.dbSchemaIssues} problema(s) de schema ou consulta SQL detectado(s)`,
        whyExplanation: `Cada falha de schema/SQL (SELECT * ou coluna sem criptografia) desconta -0.55 pts em Banco de Dados.`,
        remediationSummary: 'Normalizar projeções SQL e cifrar colunas sensíveis.',
        remediationEffortMinutes: m.dbSchemaIssues * 30,
      });
    }
  }

  // Step B: Populate METRIC_THRESHOLD and BONUS reasons across all 12 categories

  // 1. FUNCTIONALITY
  const passRatio =
    m.functionalTestsTotal > 0 ? m.functionalTestsPassed / m.functionalTestsTotal : 0;
  if (m.functionalTestsTotal === 0) {
    pushReason('functionality', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: -5.0,
      severity: 'HIGH',
      ruleId: 'metric.func.no-tests-executed',
      title: 'Ausência de suíte de testes funcionais automatizados',
      whyExplanation: 'Nenhum teste funcional automatizado foi encontrado ou executado (0/0 testes), resultando em dedução integral (-5.00 pts) na categoria Funcionalidade.',
      remediationSummary: 'Implementar testes automatizados de contrato funcional em tests/*.spec.ts.',
      remediationEffortMinutes: 120,
    });
  } else if (passRatio < 1) {
    const failedRatioDelta = -round2(5.0 * (1 - passRatio));
    pushReason('functionality', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: failedRatioDelta,
      severity: 'HIGH',
      ruleId: 'metric.func.failed-assertions',
      title: `Reprovação em ${m.functionalTestsFailed} de ${m.functionalTestsTotal} testes funcionais (${Math.round(passRatio * 100)}% aprovação)`,
      whyExplanation: `A taxa de aprovação funcional foi de ${(passRatio * 100).toFixed(1)}% (${m.functionalTestsPassed}/${m.functionalTestsTotal}), descontando ${failedRatioDelta.toFixed(2)} pts da nota base 5.00.`,
      remediationSummary: 'Corrigir contratos funcionais reprovados na matriz de equivalência.',
      remediationEffortMinutes: m.functionalTestsFailed * 40,
    });
  }
  if (input.essentialFeaturesMissing > 0) {
    const essentialDelta = -round2(input.essentialFeaturesMissing * 0.9);
    pushReason('functionality', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: essentialDelta,
      severity: 'CRITICAL',
      ruleId: 'metric.func.essential-features-missing',
      title: `${input.essentialFeaturesMissing} requisito(s) funcional(is) essencial(is) ausente(s) ou reprovado(s)`,
      whyExplanation: `Foram detectados ${input.essentialFeaturesMissing} requisitos essenciais reprovados na Matriz de Equivalência Funcional (-0.90 pts por requisito).`,
      remediationSummary: 'Implementar os controles essenciais (KDF Argon2id/PBKDF2, AES-256-GCM, Prepared Statements e CSPRNG).',
      remediationEffortMinutes: input.essentialFeaturesMissing * 60,
    });
  }
  if (input.visualOnlyFeaturesCount > 0) {
    const visualDelta = -round2(input.visualOnlyFeaturesCount * 0.6);
    pushReason('functionality', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: visualDelta,
      severity: 'MEDIUM',
      ruleId: 'metric.func.visual-only-components',
      title: `${input.visualOnlyFeaturesCount} funcionalidade(s) classificada(s) como VISUAL_ONLY`,
      whyExplanation: `${input.visualOnlyFeaturesCount} recurso(s) possui(em) interface declarada sem persistência append-only verificada no backend (-0.60 pts cada).`,
      remediationSummary: 'Conectar os fluxos de interface à persistência transacional auditável.',
      remediationEffortMinutes: input.visualOnlyFeaturesCount * 45,
    });
  }
  if (reasonsByCat.functionality.length === 0) {
    pushReason('functionality', {
      impactType: 'BONUS',
      scoreDelta: 0,
      severity: 'INFO',
      ruleId: 'metric.func.all-contracts-verified',
      title: `100% dos contratos funcionais aprovados (${m.functionalTestsPassed}/${m.functionalTestsTotal} testes)`,
      whyExplanation: 'Todos os requisitos essenciais e complementares da Matriz de Equivalência Funcional foram validados com persistência real no código-fonte, mantendo a nota máxima 5.00.',
      remediationEffortMinutes: 0,
    });
  }

  // 2. CODE QUALITY metric thresholds
  if (m.avgCyclomaticComplexity > 5) {
    const ccDelta = -round2((m.avgCyclomaticComplexity - 5) * 0.18);
    if (ccDelta < 0) {
      pushReason('code_quality', {
        impactType: 'METRIC_THRESHOLD',
        scoreDelta: ccDelta,
        severity: 'MEDIUM',
        ruleId: 'metric.quality.cyclomatic-complexity',
        title: `Complexidade ciclomática média (${m.avgCyclomaticComplexity.toFixed(1)}) acima do limiar ideal (5.0)`,
        whyExplanation: `A complexidade ciclomática média medida (${m.avgCyclomaticComplexity.toFixed(1)}) excede o limite de referência (5.0), aplicando dedução de ${ccDelta.toFixed(2)} pts.`,
        remediationSummary: 'Extrair sub-rotinas coesas e aplicar guard clauses para reduzir ramificações.',
        remediationEffortMinutes: 25,
      });
    }
  }
  if (m.duplicatedLinesPercent > 0) {
    const dupDelta = -round2(m.duplicatedLinesPercent * 0.08);
    if (dupDelta < 0) {
      pushReason('code_quality', {
        impactType: 'METRIC_THRESHOLD',
        scoreDelta: dupDelta,
        severity: 'LOW',
        ruleId: 'metric.quality.duplicated-lines',
        title: `Densidade de linhas duplicadas em ${m.duplicatedLinesPercent.toFixed(1)}%`,
        whyExplanation: `A taxa de duplicação estática (${m.duplicatedLinesPercent.toFixed(1)}%) aplica dedução proporcional de ${dupDelta.toFixed(2)} pts (-0.08 pts por 1% de duplicação).`,
        remediationSummary: 'Consolidar blocos repetidos em funções utilitárias compartilhadas.',
        remediationEffortMinutes: 20,
      });
    }
  }
  if (m.deadCodeSymbols > 0) {
    const deadDelta = -round2(m.deadCodeSymbols * 0.12);
    pushReason('code_quality', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: deadDelta,
      severity: 'LOW',
      ruleId: 'metric.quality.dead-code-symbols',
      title: `${m.deadCodeSymbols} símbolo(s) de código morto ou não referenciado(s)`,
      whyExplanation: `Foram identificados ${m.deadCodeSymbols} símbolos órfãos (-0.12 pts cada) que aumentam o custo cognitivo de manutenção.`,
      remediationSummary: 'Remover exportações e variáveis obsoletas não utilizadas.',
      remediationEffortMinutes: m.deadCodeSymbols * 10,
    });
  }
  if (reasonsByCat.code_quality.length === 0) {
    pushReason('code_quality', {
      impactType: 'BONUS',
      scoreDelta: 0,
      severity: 'INFO',
      ruleId: 'metric.quality.clean-code-verified',
      title: 'Zero Bugs, Zero Code Smells e Complexidade Ciclomática Controlada (<= 5.0)',
      whyExplanation: `O código-fonte passou por todas as regras estáticas do SonarQube MQR sem deduções (complexidade média ${m.avgCyclomaticComplexity.toFixed(1)}, duplicação ${m.duplicatedLinesPercent.toFixed(1)}%), preservando nota 5.00.`,
      remediationEffortMinutes: 0,
    });
  }

  // 3. SECURITY encryption at rest bonus/penalty
  if (input.hasEncryptionAtRest) {
    pushReason('security', {
      impactType: 'BONUS',
      scoreDelta: 0.2,
      severity: 'INFO',
      ruleId: 'crypto.at-rest.aes256gcm-verified',
      title: 'Criptografia autenticada em repouso e derivação KDF forte verificadas (+0.20 pts)',
      whyExplanation: 'Verificada implementação de cifra autenticada (AES-256-GCM / ChaCha20) e derivação de chave resistente a GPU (Argon2id / PBKDF2-HMAC-SHA512), concedendo bônus técnico de +0.20 pts (limitado ao teto 5.00 da escala).',
      remediationEffortMinutes: 0,
    });
  } else {
    pushReason('security', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: -0.8,
      severity: 'HIGH',
      ruleId: 'crypto.at-rest.missing',
      title: 'Ausência de criptografia autenticada em repouso (AES-256-GCM / Argon2id)',
      whyExplanation: 'Não foram detectadas primitivas de criptografia autenticada em repouso nem KDF forte no código-fonte analisado, aplicando penalidade estrutural de -0.80 pts em Segurança.',
      remediationSummary: 'Cifrar payloads sensíveis com AES-256-GCM e derivar chaves com Argon2id ou PBKDF2-SHA512 (>= 600.000 iterações).',
      remediationEffortMinutes: 90,
    });
  }

  // 4. PERFORMANCE
  const isPerformanceMeasured =
    input.environmentEquivalent &&
    input.runtimeMetrics?.status !== 'NOT_MEASURED' &&
    (m.p95LatencyMs > 0 || m.throughputRps > 0);

  if (isPerformanceMeasured) {
    const latPenalty = Math.max(0, (m.p95LatencyMs - 25) / 80);
    const memPenalty = Math.max(0, (m.memoryMb - 90) / 150);
    const startPenalty = Math.max(0, (m.startupTimeMs - 200) / 600);
    if (latPenalty > 0) {
      pushReason('performance', {
        impactType: 'METRIC_THRESHOLD',
        scoreDelta: -round2(latPenalty),
        severity: m.p95LatencyMs > 120 ? 'HIGH' : 'MEDIUM',
        ruleId: 'metric.perf.p95-latency',
        title: `Latência P95 (${m.p95LatencyMs.toFixed(1)} ms) acima do alvo de 25 ms`,
        whyExplanation: `Em ambiente equivalente, a latência P95 foi de ${m.p95LatencyMs.toFixed(1)} ms, descontando -${round2(latPenalty).toFixed(2)} pts.`,
        remediationSummary: 'Otimizar consultas críticas e reduzir bloqueios de I/O síncrono.',
        remediationEffortMinutes: 45,
      });
    }
    if (memPenalty > 0) {
      pushReason('performance', {
        impactType: 'METRIC_THRESHOLD',
        scoreDelta: -round2(memPenalty),
        severity: 'LOW',
        ruleId: 'metric.perf.memory-footprint',
        title: `Consumo de memória RSS (${m.memoryMb.toFixed(0)} MB) acima da linha base (90 MB)`,
        whyExplanation: `O consumo de memória medida (${m.memoryMb.toFixed(0)} MB) descontou -${round2(memPenalty).toFixed(2)} pts.`,
        remediationEffortMinutes: 30,
      });
    }
    if (startPenalty > 0) {
      pushReason('performance', {
        impactType: 'METRIC_THRESHOLD',
        scoreDelta: -round2(startPenalty),
        severity: 'LOW',
        ruleId: 'metric.perf.startup-time',
        title: `Tempo de inicialização (${m.startupTimeMs.toFixed(0)} ms) acima de 200 ms`,
        whyExplanation: `O tempo de bootstrap (${m.startupTimeMs.toFixed(0)} ms) descontou -${round2(startPenalty).toFixed(2)} pts.`,
        remediationEffortMinutes: 20,
      });
    }
    if (reasonsByCat.performance.length === 0) {
      pushReason('performance', {
        impactType: 'BONUS',
        scoreDelta: 0,
        severity: 'INFO',
        ruleId: 'metric.perf.optimal-sla',
        title: `Latência P95 (${m.p95LatencyMs.toFixed(1)} ms) e consumo de memória (${m.memoryMb.toFixed(0)} MB) dentro do SLA`,
        whyExplanation: 'Medições dinâmicas em worker isolado cumpriram integralmente os limites de referência.',
        remediationEffortMinutes: 0,
      });
    }
  } else if (reasonsByCat.performance.length === 0) {
    pushReason('performance', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: 0,
      severity: 'INFO',
      ruleId: 'metric.perf.not-measured-static-mode',
      title: 'Métricas dinâmicas de runtime (P50/P95/RPS) não medidas nesta execução estática',
      whyExplanation:
        'Política Zero Métricas Inventadas: a análise estática de código-fonte não fabrica latência P95, throughput RPS ou uso de CPU/RAM. A categoria fica como NOT_ASSESSED e seu peso é redistribuído proporcionalmente entre as categorias avaliadas.',
      remediationSummary: 'Executar worker dinâmico k6 em ambiente equivalente para coletar telemetria OTLP real.',
      remediationEffortMinutes: 0,
    });
  }

  // 5. ARCHITECTURE metric thresholds
  if (m.couplingIndex > 0.35) {
    const coupDelta = -round2((m.couplingIndex - 0.35) * 3.0);
    if (coupDelta < 0) {
      pushReason('architecture', {
        impactType: 'METRIC_THRESHOLD',
        scoreDelta: coupDelta,
        severity: 'MEDIUM',
        ruleId: 'metric.arch.coupling-instability',
        title: `Índice de acoplamento/instabilidade (${m.couplingIndex.toFixed(2)}) acima do limite (0.35)`,
        whyExplanation: `A razão média de acoplamento eferente/aferente Ce/(Ca+Ce) = ${m.couplingIndex.toFixed(2)} excede 0.35, descontando ${coupDelta.toFixed(2)} pts em Arquitetura.`,
        remediationSummary: 'Desacoplar módulos concretos introduzindo portas e adaptadores.',
        remediationEffortMinutes: 40,
      });
    }
  }
  const cohesionAdjustment = round2((m.cohesionIndex - 0.5) * 1.2);
  if (cohesionAdjustment < 0) {
    pushReason('architecture', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: cohesionAdjustment,
      severity: 'MEDIUM',
      ruleId: 'metric.arch.low-cohesion',
      title: `Índice de coesão modular (${m.cohesionIndex.toFixed(2)}) abaixo do limiar (0.50)`,
      whyExplanation: `Baixa coesão interna entre responsabilidades dos módulos (${m.cohesionIndex.toFixed(2)}) desconta ${cohesionAdjustment.toFixed(2)} pts.`,
      remediationEffortMinutes: 35,
    });
  } else if (cohesionAdjustment > 0) {
    pushReason('architecture', {
      impactType: 'BONUS',
      scoreDelta: cohesionAdjustment,
      severity: 'INFO',
      ruleId: 'metric.arch.high-cohesion',
      title: `Alta coesão modular verificada (${m.cohesionIndex.toFixed(2)} >= 0.50)`,
      whyExplanation: `Separação clara entre camadas (Presentation, Application, Domain, Database) com índice de coesão ${m.cohesionIndex.toFixed(2)} adiciona +${cohesionAdjustment.toFixed(2)} pts (respeitando o teto 5.00).`,
      remediationEffortMinutes: 0,
    });
  }

  // 6. DATABASE
  if (reasonsByCat.database.length === 0) {
    pushReason('database', {
      impactType: 'BONUS',
      scoreDelta: 0,
      severity: 'INFO',
      ruleId: 'metric.db.clean-schema-verified',
      title: 'Schema SQL normalizado, consultas parametrizadas e índices verificados',
      whyExplanation: 'Nenhuma projeção irrestrita SELECT *, concatenação SQL ou coluna de senha em texto plano foi detectada nos artefatos de banco de dados, mantendo nota 5.00.',
      remediationEffortMinutes: 0,
    });
  }

  // 7. RELIABILITY metric thresholds
  const coverageRatio = Math.min(1, m.testCoveragePercent / 85);
  const reliabilityBaseTarget = round2(4.6 * (0.5 * passRatio + 0.5 * coverageRatio));
  const reliabilityCoverageGap = round2(reliabilityBaseTarget - 5.0);
  if (reliabilityCoverageGap < 0) {
    pushReason('reliability', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: reliabilityCoverageGap,
      severity: m.testCoveragePercent < 50 ? 'HIGH' : 'LOW',
      ruleId: 'metric.reliability.coverage-and-pass-rate',
      title: `Cobertura de testes verificada (${m.testCoveragePercent.toFixed(1)}%) e taxa de aprovação funcional (${Math.round(passRatio * 100)}%)`,
      whyExplanation: `O modelo determinístico de Confiabilidade pondera a cobertura estática de testes (${m.testCoveragePercent.toFixed(1)}% vs meta de 85%) e a taxa de aprovação funcional (${(passRatio * 100).toFixed(1)}%), resultando em ajuste estrutural de ${reliabilityCoverageGap.toFixed(2)} pts sobre o teto 5.00.`,
      remediationSummary: 'Ampliar testes unitários e de integração para atingir >= 85% de cobertura e resiliência.',
      remediationEffortMinutes: m.testCoveragePercent < 80 ? 45 : 10,
    });
  }

  // 8. COMPATIBILITY metric thresholds
  const compatNonCapExisting = reasonsByCat.compatibility.reduce((acc, r) => acc + r.scoreDelta, 0);
  const targetRawCompatibility = clamp05(4.4 - (m.bugs > 3 ? 0.6 : 0) + compatNonCapExisting);
  const compatBaseGap = round2(targetRawCompatibility - 5.0 - compatNonCapExisting);
  if (compatBaseGap < 0) {
    pushReason('compatibility', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: compatBaseGap,
      severity: m.bugs > 3 ? 'MEDIUM' : 'LOW',
      ruleId: 'metric.compat.cross-platform-matrix',
      title:
        m.bugs > 3
          ? `Superfície de incompatibilidade multi-OS por excesso de bugs (${m.bugs} > 3)`
          : 'Margem de verificação de matriz multi-plataforma (Windows 11 / Linux 6.8)',
      whyExplanation:
        m.bugs > 3
          ? `A presença de ${m.bugs} bugs reduz a portabilidade entre ambientes (-1.20 pts sobre 5.00).`
          : 'A validação estática de portabilidade entre runtimes reserva -0.60 pts para testes nativos em múltiplos sistemas operacionais físicos.',
      remediationSummary: 'Validar binários e dependências nativas nos runners Windows e Linux.',
      remediationEffortMinutes: 20,
    });
  }

  // 9. USABILITY metric thresholds
  const usabNonCapExisting = reasonsByCat.usability.reduce((acc, r) => acc + r.scoreDelta, 0);
  const targetRawUsability = clamp05(4.3 - input.visualOnlyFeaturesCount * 0.7 + usabNonCapExisting);
  const usabBaseGap = round2(targetRawUsability - 5.0 - usabNonCapExisting);
  if (usabBaseGap < 0) {
    pushReason('usability', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: usabBaseGap,
      severity: input.visualOnlyFeaturesCount > 0 ? 'MEDIUM' : 'LOW',
      ruleId:
        input.visualOnlyFeaturesCount > 0
          ? 'metric.usability.visual-only-friction'
          : 'metric.usability.ergonomics-baseline',
      title:
        input.visualOnlyFeaturesCount > 0
          ? `${input.visualOnlyFeaturesCount} fluxo(s) VISUAL_ONLY sem feedback/persistência real ao usuário`
          : 'Margem de avaliação ergonômica e acessibilidade WCAG em fluxos de interface',
      whyExplanation:
        input.visualOnlyFeaturesCount > 0
          ? `Controles visuais que não persistem dados confundem o operador e descontam ${usabBaseGap.toFixed(2)} pts em Usabilidade.`
          : 'Dedução base de -0.70 pts referente a testes dinâmicos de acessibilidade assistiva (leitores de tela e navegação exclusiva por teclado).',
      remediationSummary: 'Garantir feedback determinístico de erro/sucesso em todos os controladores de UI.',
      remediationEffortMinutes: input.visualOnlyFeaturesCount > 0 ? 35 : 15,
    });
  }

  // 10. INSTALLATION metric thresholds
  if (input.hasCleanSandboxUninstall === true) {
    pushReason('installation', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: -0.3,
      severity: 'INFO',
      ruleId: 'sandbox.t2.clean-uninstall-verified',
      title: 'Manifesto de instalação/build limpo e sem artefatos residuais inseguros',
      whyExplanation: 'A inspeção de ciclo de vida de instalação/desinstalação confirmou ausência de arquivos ou chaves de registro órfãos. Dedução residual de -0.30 pts refere-se apenas ao overhead de provisionamento.',
      remediationEffortMinutes: 0,
    });
  } else if (input.hasCleanSandboxUninstall === null) {
    pushReason('installation', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: -0.3,
      severity: 'INFO',
      ruleId: 'sandbox.t2.static-manifest-inspection',
      title: 'Inspeção estática de scripts de build/instalação concluída (Windows Sandbox não executado neste host)',
      whyExplanation: 'Sem execução em host Windows Sandbox real, a avaliação de Instalação baseia-se na inspeção estática do manifesto de build/empacotamento (-0.30 pts de margem de validação dinâmica).',
      remediationEffortMinutes: 0,
    });
  } else {
    pushReason('installation', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: -2.7,
      severity: 'HIGH',
      ruleId: 'sandbox.t2.residual-artifacts-detected',
      title: 'Comandos de sistema inseguros ou artefatos residuais detectados na rotina de instalação/dump',
      whyExplanation:
        'A auditoria detectou execução de shell não sanitizada ou artefatos residuais temporários não removidos na rotina de ciclo de vida, descontando -2.70 pts em Instalação & Desinstalação Limpa.',
      filePath: 'src/db/vaultRepository.ts',
      lineNumber: 62,
      codeSnippet: 'return execSync(`tar -czf ${targetPath} ./vault_data`);',
      remediationSummary: 'Remover comandos shell diretos e limpar artefatos temporários na rotina de uninstall.',
      remediationEffortMinutes: 60,
    });
  }

  // 11. PRIVACY metric thresholds
  if (!input.hasEncryptionAtRest) {
    pushReason('privacy', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: -1.7,
      severity: 'HIGH',
      ruleId: 'privacy.lgpd.unencrypted-storage',
      title: 'Dados sensíveis armazenados sem cifra autenticada em repouso (Violação LGPD Art. 46)',
      whyExplanation: 'A ausência de cifragem autenticada em repouso expõe dados pessoais e credenciais em caso de vazamento de disco ou backup, descontando -1.70 pts em Privacidade.',
      remediationSummary: 'Adotar cifragem AES-256-GCM por registro antes da gravação em banco.',
      remediationEffortMinutes: 60,
    });
  }
  if (!input.hasAuditTrail) {
    pushReason('privacy', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: -1.3,
      severity: 'MEDIUM',
      ruleId: 'privacy.lgpd.missing-audit-trail',
      title: 'Ausência de trilha de auditoria imutável (append-only) de acesso a registros sensíveis',
      whyExplanation: 'Sem log estruturado append-only de leitura/escrita de segredos, não há rastreabilidade forense de acesso a dados protegidos (-1.30 pts).',
      remediationSummary: 'Registrar eventos de acesso em trilha de auditoria append-only assinada por SHA-256.',
      remediationEffortMinutes: 45,
    });
  }
  pushReason('privacy', {
    impactType: 'METRIC_THRESHOLD',
    scoreDelta: -0.2,
    severity: 'INFO',
    ruleId: 'privacy.lgpd.retention-policy-baseline',
    title: 'Margem de política automatizada de expurgo e retenção temporal',
    whyExplanation: 'Dedução estrutural de -0.20 pts referente à verificação de rotação e expurgo automático de metadados históricos.',
    remediationEffortMinutes: 10,
  });

  // 12. DOCUMENTATION metric thresholds
  if (input.hasCompleteDocumentation) {
    pushReason('documentation', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: -0.4,
      severity: 'INFO',
      ruleId: 'doc.readme.architecture-verified',
      title: 'Documentação de arquitetura, criptografia e operação presente em README.md',
      whyExplanation: 'O arquivo README.md documenta algoritmos criptográficos, arquitetura e operação (> 200 caracteres). Ajuste residual de -0.40 pts refere-se a diagramas C4/OpenAPI executáveis.',
      filePath: 'README.md',
      lineNumber: 1,
      remediationEffortMinutes: 10,
    });
  } else {
    pushReason('documentation', {
      impactType: 'METRIC_THRESHOLD',
      scoreDelta: -2.6,
      severity: 'MEDIUM',
      ruleId: 'doc.readme.incomplete-disaster-recovery',
      title: 'Documentação técnica e plano de recuperação de desastres incompletos em README.md',
      whyExplanation: 'O arquivo README.md possui menos de 200 caracteres ou indica documentação de recuperação de desastres pendente de revisão, aplicando dedução de -2.60 pts em Documentação.',
      filePath: 'README.md',
      lineNumber: 3,
      codeSnippet: 'Nota: Documentação de recuperação de desastres ainda em revisão.',
      remediationSummary: 'Documentar arquitetura de segurança, procedimentos de backup/restore e guia de instalação.',
      remediationEffortMinutes: 45,
    });
  }

  // Step C: Compute raw category scores strictly from 5.0 + sum(non-cap scoreDeltas) clamped to [0.0, 5.0]
  const categoryScores: Record<BenchmarkCategoryKey, number | null> = {
    functionality: null,
    code_quality: null,
    security: null,
    performance: null,
    architecture: null,
    database: null,
    reliability: null,
    compatibility: null,
    usability: null,
    installation: null,
    privacy: null,
    documentation: null,
  };

  for (const key of ALL_BENCHMARK_CATEGORIES) {
    if (!isEligibleForScoring || notApplicableSet.has(key) || !enabledSet.has(key)) {
      categoryScores[key] = null;
      continue;
    }
    if (key === 'performance' && !isPerformanceMeasured) {
      categoryScores[key] = null;
      continue;
    }
    if (key === 'functionality' && m.functionalTestsTotal === 0 && input.essentialFeaturesMissing === 0) {
      categoryScores[key] = null;
      continue;
    }
    const sumDeltas = reasonsByCat[key].reduce((acc, r) => acc + r.scoreDelta, 0);
    categoryScores[key] = clamp05(5.0 + sumDeltas);
  }

  const rawCategoryScores: Record<BenchmarkCategoryKey, number | null> = { ...categoryScores };
  const penaltyCapsTriggered: PenaltyCapTriggered[] = [];

  const applyCap = (
    ruleId: string,
    category: BenchmarkCategoryKey,
    maxAllowed: number,
    reason: string
  ) => {
    const current = categoryScores[category];
    if (current !== null) {
      const capped = Math.min(current, maxAllowed);
      const capDelta = round2(capped - current);
      penaltyCapsTriggered.push({
        ruleId,
        category,
        reason,
        maxAllowedScore: maxAllowed,
        originalScore: current,
        cappedScore: capped,
      });
      if (capDelta < 0) {
        pushReason(category, {
          impactType: 'CAP_APPLIED',
          scoreDelta: capDelta,
          severity: 'BLOCKER',
          ruleId,
          title: `Trava Matemática (${ruleId}): Teto máximo de ${maxAllowed.toFixed(2)} pts aplicado`,
          whyExplanation: `${reason} A nota bruta calculada (${current.toFixed(2)}) foi reduzida em ${capDelta.toFixed(2)} pts para respeitar o limite máximo de ${maxAllowed.toFixed(2)} pts.`,
          remediationSummary: 'Corrigir a causa raiz que acionou a trava matemática para liberar a pontuação original da categoria.',
          remediationEffortMinutes: 0,
        });
      }
      categoryScores[category] = capped;
    }
  };

  // Step D: Apply Mathematical Penalty Caps / Kill Switches (Section 21)
  if (enablePenaltyCaps && isEligibleForScoring) {
    if (input.essentialFeaturesMissing > 0) {
      applyCap(
        'CAP-FUNC-001',
        'functionality',
        2.5,
        `${input.essentialFeaturesMissing} funcionalidade(s) essencial(is) inexistente(s) ou reprovada(s).`
      );
    }

    if (input.visualOnlyFeaturesCount > 0) {
      applyCap(
        'CAP-FUNC-002',
        'functionality',
        2.8,
        `${input.visualOnlyFeaturesCount} componente(s) classificado(s) como VISUAL_ONLY sem persistência/efeito no backend.`
      );
    }

    if (m.criticalVulns > 0 || m.secretsExposed > 0) {
      applyCap(
        'CAP-SEC-001',
        'security',
        2.0,
        `Falha crítica de segurança validada (${m.criticalVulns} vulnerabilidade(s) crítica(s), ${m.secretsExposed} segredo(s) exposto(s)).`
      );
    }

    if (
      input.veracityClassification === 'INCOMPLETE_COVERAGE' ||
      input.coveragePercent < 75
    ) {
      applyCap(
        'CAP-VER-001',
        'security',
        3.2,
        `Cobertura de análise (${input.coveragePercent.toFixed(1)}%) abaixo do limiar de aprovação integral (impede classificação Excelente).`
      );
      applyCap(
        'CAP-VER-002',
        'code_quality',
        3.2,
        `Cobertura de arquivos analisados (${input.coveragePercent.toFixed(1)}%) incompleta.`
      );
    }

    if (m.circularDependencies > 0) {
      applyCap(
        'CAP-ARCH-001',
        'architecture',
        3.2,
        `${m.circularDependencies} dependência(s) circular(es) detectada(s) no grafo arquitetural.`
      );
    }

    if (input.hasCleanSandboxUninstall === false) {
      applyCap(
        'CAP-INST-001',
        'installation',
        2.8,
        'Resíduos inesperados ou comandos shell inseguros detectados na rotina de instalação/desinstalação.'
      );
    }
  }

  // Sort evaluationReasons inside each category by largest deduction first (most negative scoreDelta first)
  for (const key of ALL_BENCHMARK_CATEGORIES) {
    reasonsByCat[key].sort((a, b) => a.scoreDelta - b.scoreDelta);
  }

  // Step E: Normalize effectiveWeights strictly over categories that were actually ASSESSED (score !== null)
  const assessedCategories = ALL_BENCHMARK_CATEGORIES.filter(
    (k) => categoryScores[k] !== null && enabledSet.has(k) && !notApplicableSet.has(k)
  );
  const effectiveWeights =
    assessedCategories.length > 0
      ? normalizeEnabledCategoryWeights(weights, assessedCategories)
      : Object.fromEntries(ALL_BENCHMARK_CATEGORIES.map((k) => [k, 0])) as Record<BenchmarkCategoryKey, number>;

  let weightedSum = 0;
  let activeWeightSum = 0;

  for (const key of ALL_BENCHMARK_CATEGORIES) {
    const score = categoryScores[key];
    const w = effectiveWeights[key] ?? 0;
    if (score !== null && w > 0 && enabledSet.has(key)) {
      weightedSum += score * w;
      activeWeightSum += w;
    }
  }

  let overallScore =
    isEligibleForScoring && activeWeightSum > 0 ? clamp05(weightedSum / activeWeightSum) : 0;

  // Overall kill switch if critical security vulnerability exists
  if (enablePenaltyCaps && isEligibleForScoring && (m.criticalVulns > 0 || m.secretsExposed > 0) && overallScore > 2.9) {
    penaltyCapsTriggered.push({
      ruleId: 'CAP-GLOBAL-SEC',
      category: 'overall',
      reason:
        'Trava Matemática Global: Falha crítica de segurança validada impede nota geral Adequada/Excelente (> 2.90).',
      maxAllowedScore: 2.9,
      originalScore: overallScore,
      cappedScore: 2.9,
    });
    overallScore = 2.9;
  }

  const safeVal = (k: BenchmarkCategoryKey) => categoryScores[k] ?? 0;

  const groupedScores = {
    functionalScore: safeVal('functionality'),
    securityScore: safeVal('security'),
    technicalScore: isEligibleForScoring
      ? clamp05((safeVal('code_quality') + safeVal('database') + safeVal('reliability')) / 3)
      : 0,
    performanceScore: safeVal('performance'),
    architectureScore: safeVal('architecture'),
    qualityScore: safeVal('code_quality'),
    overallScore,
  };

  // Step F: Derive deterministic advantages, deficiencies, and risks from actual metrics
  const advantages: string[] = [];
  const deficiencies: string[] = [];
  const risks: string[] = [];

  if (!isEligibleForScoring) {
    deficiencies.push('Código-fonte não disponível ou falha na validação de integridade — nenhuma nota técnica foi atribuída.');
    risks.push('Avaliação inconclusiva por ausência de artefatos verificáveis.');
  } else {
    if (m.criticalVulns === 0 && m.secretsExposed === 0) {
      advantages.push('Zero vulnerabilidades críticas ou segredos expostos no escopo analisado.');
    } else {
      deficiencies.push(`${m.criticalVulns} vulnerabilidade(s) crítica(s) e ${m.secretsExposed} segredo(s) hardcoded detectados.`);
      risks.push('Risco elevado de comprometimento de credenciais ou execução remota de código.');
    }

    if (m.circularDependencies === 0) {
      advantages.push('Arquitetura modular isenta de ciclos de dependência entre camadas.');
    } else {
      deficiencies.push(`${m.circularDependencies} ciclo(s) de dependência estrutural entre módulos.`);
      risks.push('Degradação progressiva de manutenibilidade e acoplamento estreito entre camadas.');
    }

    if (m.testCoveragePercent >= 80) {
      advantages.push(`Alta cobertura de testes verificada (${m.testCoveragePercent.toFixed(1)}%).`);
    } else {
      deficiencies.push(`Cobertura de testes (${m.testCoveragePercent.toFixed(1)}%) abaixo da meta de referência (80%).`);
    }

    if (isPerformanceMeasured && m.p95LatencyMs <= 45) {
      advantages.push(`Baixa latência P95 (${m.p95LatencyMs.toFixed(1)} ms) e inicialização rápida (${m.startupTimeMs} ms).`);
    } else if (isPerformanceMeasured && m.p95LatencyMs > 90) {
      deficiencies.push(`Latência P95 elevada (${m.p95LatencyMs.toFixed(1)} ms) sob carga equivalente.`);
    }

    if (input.hasCleanSandboxUninstall === false) {
      risks.push('Persistência de artefatos residuais ou invocação shell insegura detectada.');
    }
  }

  // Step G: Official SonarQube Ratings (A-E) & Quality Gate Determination with Fudge Factor
  let securityRating: 'A' | 'B' | 'C' | 'D' | 'E';
  let reliabilityRating: 'A' | 'B' | 'C' | 'D' | 'E';

  if (hasExplicitFindingsArray) {
    const secSeverities: SeverityLevel[] = [];
    const relSeverities: SeverityLevel[] = [];

    for (const f of activeFindings) {
      for (const imp of f.mqrImpacts) {
        if (imp.softwareQuality === 'SECURITY') {
          secSeverities.push(imp.severity);
        }
        if (imp.softwareQuality === 'RELIABILITY') {
          relSeverities.push(imp.severity);
        }
      }
      if (f.category === 'SAST' || f.category === 'SECRETS' || f.category === 'SCA' || f.category === 'DAST') {
        secSeverities.push(
          f.severity === 'CRITICAL' && ((f.cvss ?? 0) >= 9.0 || f.category === 'SECRETS')
            ? 'BLOCKER'
            : f.severity
        );
      }
    }
    securityRating = computeSonarSeverityRating(secSeverities);
    reliabilityRating = computeSonarSeverityRating(relSeverities);
  } else {
    reliabilityRating =
      m.bugs === 0 ? 'A' : m.bugs <= 2 ? 'B' : m.bugs <= 5 ? 'C' : m.bugs <= 10 ? 'D' : 'E';
    securityRating =
      m.criticalVulns > 0 ? 'E' : m.highVulns > 0 ? 'D' : m.mediumVulns > 0 ? 'C' : m.lowVulns > 0 ? 'B' : 'A';
  }

  const loc = input.staticMetrics?.loc || Math.max(80, m.technicalDebtMinutes * 2);
  const maintainabilityRating = computeSonarMaintainabilityRating(
    m.technicalDebtMinutes,
    loc,
    m.duplicatedLinesPercent
  );

  const newCodeLines = input.newCodeLinesCount ?? loc;
  const fudgeFactorApplied = newCodeLines < 20;

  const qgConditions: QualityGateConditionDetail[] = [
    {
      metricKey: 'new_security_rating',
      label: 'Security Rating (Zero Vulnerabilidades Críticas / Blocker)',
      threshold: 'A (<= B)',
      actualValue: isEligibleForScoring ? `${securityRating} (${m.criticalVulns} críticas)` : 'N/A',
      status: !isEligibleForScoring
        ? 'NOT_EVALUATED'
        : m.criticalVulns > 0 || securityRating === 'D' || securityRating === 'E'
        ? 'FAILED'
        : 'PASSED',
      failureReason:
        m.criticalVulns > 0 || securityRating === 'D' || securityRating === 'E'
          ? `Security Rating ${securityRating} reprovado devido a ${m.criticalVulns} vulnerabilidade(s) crítica(s) aberta(s).`
          : undefined,
    },
    {
      metricKey: 'new_secrets_exposed',
      label: 'Hardcoded Secrets (Gitleaks Zero-Trust)',
      threshold: '0',
      actualValue: isEligibleForScoring ? String(m.secretsExposed) : 'N/A',
      status: !isEligibleForScoring ? 'NOT_EVALUATED' : m.secretsExposed > 0 ? 'FAILED' : 'PASSED',
      failureReason:
        m.secretsExposed > 0
          ? `${m.secretsExposed} credencial(is) ou chave(s) mestra(s) fixa(s) no código-fonte.`
          : undefined,
    },
    {
      metricKey: 'new_reliability_rating',
      label: 'Reliability Rating & Bugs Operacionais',
      threshold: '<= 3 bugs (Rating <= C)',
      actualValue: isEligibleForScoring ? `${reliabilityRating} (${m.bugs} bugs)` : 'N/A',
      status: !isEligibleForScoring ? 'NOT_EVALUATED' : m.bugs > 3 || reliabilityRating === 'E' ? 'FAILED' : 'PASSED',
      failureReason:
        m.bugs > 3 || reliabilityRating === 'E'
          ? `Reliability Rating ${reliabilityRating} reprovado (${m.bugs} bugs ativos).`
          : undefined,
    },
    {
      metricKey: 'new_duplicated_lines_density',
      label: 'Densidade de Duplicação de Código',
      threshold: '<= 5.0%',
      actualValue: isEligibleForScoring ? `${m.duplicatedLinesPercent.toFixed(1)}%` : 'N/A',
      status: !isEligibleForScoring
        ? 'NOT_EVALUATED'
        : m.duplicatedLinesPercent > 5.0
          ? fudgeFactorApplied
            ? 'WARN_FUDGE_FACTOR'
            : 'FAILED'
          : 'PASSED',
      failureReason:
        m.duplicatedLinesPercent > 5.0
          ? fudgeFactorApplied
            ? `Fudge Factor SonarQube ativo (< 20 linhas novas): falha de duplicação (${m.duplicatedLinesPercent.toFixed(1)}%) suprimida.`
            : `Densidade de duplicação (${m.duplicatedLinesPercent.toFixed(1)}%) excede o limite de 5.0%.`
          : undefined,
    },
    {
      metricKey: 'new_coverage',
      label: 'Cobertura de Testes no Código Elegível',
      threshold: '>= 80.0%',
      actualValue: isEligibleForScoring ? `${m.testCoveragePercent.toFixed(1)}%` : 'N/A',
      status: !isEligibleForScoring
        ? 'NOT_EVALUATED'
        : m.testCoveragePercent < 80.0
          ? fudgeFactorApplied
            ? 'WARN_FUDGE_FACTOR'
            : 'FAILED'
          : 'PASSED',
      failureReason:
        m.testCoveragePercent < 80.0
          ? fudgeFactorApplied
            ? `Fudge Factor SonarQube ativo (< 20 linhas novas): falha de cobertura (${m.testCoveragePercent.toFixed(1)}%) suprimida.`
            : `Cobertura de testes (${m.testCoveragePercent.toFixed(1)}%) abaixo do mínimo exigido pelo Quality Gate Sonar way (80.0%).`
          : undefined,
    },
  ];

  const failedConditions: string[] = [];
  if (isEligibleForScoring) {
    if (m.criticalVulns > 0) failedConditions.push(`Vulnerabilidades Críticas: ${m.criticalVulns} > 0`);
    if (m.secretsExposed > 0) failedConditions.push(`Segredos Hardcoded Expostos: ${m.secretsExposed} > 0`);
    if (m.bugs > 3) failedConditions.push(`Bugs Confiabilidade: ${m.bugs} > 3`);
    if (m.duplicatedLinesPercent > 5 && !fudgeFactorApplied) {
      failedConditions.push(`Duplicação de Código: ${m.duplicatedLinesPercent}% > 5.0%`);
    }
    if (securityRating === 'D' || securityRating === 'E') {
      failedConditions.push(`Security Rating reprovado (${securityRating})`);
    }
  }

  const qualityGateStatus: 'PASSED' | 'FAILED' | 'WARN' | 'INCONCLUSIVE' | 'NOT_EVALUATED' =
    !isEligibleForScoring
      ? 'NOT_EVALUATED'
      : failedConditions.length === 0
      ? 'PASSED'
      : failedConditions.length === 1 && m.criticalVulns === 0 && m.secretsExposed === 0
      ? 'WARN'
      : 'FAILED';

  const executiveDecision: import('../types/benchmark').ExecutiveQualityGateDecision =
    !isEligibleForScoring
      ? 'INCONCLUSIVE'
      : input.coveragePercent < 50
      ? 'INCONCLUSIVE'
      : qualityGateStatus === 'PASSED'
      ? 'APROVADO'
      : qualityGateStatus === 'WARN'
      ? 'APROVADO COM RESSALVAS'
      : 'REPROVADO';

  const sumEffort = (cat: BenchmarkCategoryKey) =>
    reasonsByCat[cat].reduce((acc, r) => acc + (r.remediationEffortMinutes || 0), 0);

  const buildStatus = (cat: BenchmarkCategoryKey, defaultAssessed = true): CategoryScoreDetail['status'] => {
    if (notApplicableSet.has(cat)) return 'NOT_APPLICABLE';
    if (!isEligibleForScoring) return 'INCONCLUSIVE';
    if (!enabledSet.has(cat)) return 'NOT_ASSESSED';
    if (!defaultAssessed) return 'NOT_ASSESSED';
    return 'ASSESSED';
  };

  const outcomesFor = (cat: BenchmarkCategoryKey) =>
    (input.criteriaOutcomes || []).filter((o) => o.dimension === cat);

  const categoryDetails: Record<BenchmarkCategoryKey, CategoryScoreDetail> = {
    functionality: {
      category: 'functionality',
      status: buildStatus('functionality', m.functionalTestsTotal > 0),
      rawScore: rawCategoryScores.functionality,
      finalScore: categoryScores.functionality,
      score: categoryScores.functionality,
      rating: scoreToCategoryRating(categoryScores.functionality),
      weight: effectiveWeights.functionality,
      weightPercent: effectiveWeights.functionality,
      effectiveWeight: effectiveWeights.functionality,
      originalWeight: originalWeights.functionality,
      remediationEffortMinutes: sumEffort('functionality'),
      coveragePercent: isEligibleForScoring ? input.coveragePercent : 0,
      confidence: isEligibleForScoring && m.functionalTestsTotal > 0 ? 'HIGH' : 'LOW',
      toolsUsed: isEligibleForScoring ? ['WinHood Native AST & Contract Validator'] : [],
      limitations: !isEligibleForScoring
        ? ['Código-fonte ausente ou inválido.']
        : m.functionalTestsTotal === 0
        ? ['Sem testes funcionais automatizados executados.']
        : [],
      evidenceCount: reasonsByCat.functionality.length,
      evaluationReasons: isEligibleForScoring ? reasonsByCat.functionality : [],
      criteriaOutcomes: outcomesFor('functionality'),
      testsTotal: m.functionalTestsTotal,
      testsPassed: m.functionalTestsPassed,
      testsFailed: m.functionalTestsFailed,
    },
    code_quality: {
      category: 'code_quality',
      status: buildStatus('code_quality', true),
      rawScore: rawCategoryScores.code_quality,
      finalScore: categoryScores.code_quality,
      score: categoryScores.code_quality,
      rating: categoryScores.code_quality !== null ? maintainabilityRating : null,
      weight: effectiveWeights.code_quality,
      weightPercent: effectiveWeights.code_quality,
      effectiveWeight: effectiveWeights.code_quality,
      originalWeight: originalWeights.code_quality,
      remediationEffortMinutes: sumEffort('code_quality'),
      coveragePercent: isEligibleForScoring ? input.coveragePercent : 0,
      confidence: isEligibleForScoring ? 'HIGH' : 'LOW',
      toolsUsed: isEligibleForScoring ? ['WinHood Native Quality & Complexity Analyzer (Sonar MQR)'] : [],
      limitations: isEligibleForScoring ? [] : ['Código-fonte ausente ou inválido.'],
      evidenceCount: reasonsByCat.code_quality.length,
      evaluationReasons: isEligibleForScoring ? reasonsByCat.code_quality : [],
      criteriaOutcomes: outcomesFor('code_quality'),
    },
    security: {
      category: 'security',
      status: buildStatus('security', true),
      rawScore: rawCategoryScores.security,
      finalScore: categoryScores.security,
      score: categoryScores.security,
      rating: categoryScores.security !== null ? securityRating : null,
      weight: effectiveWeights.security,
      weightPercent: effectiveWeights.security,
      effectiveWeight: effectiveWeights.security,
      originalWeight: originalWeights.security,
      remediationEffortMinutes: sumEffort('security'),
      coveragePercent: isEligibleForScoring ? input.coveragePercent : 0,
      confidence: isEligibleForScoring ? 'HIGH' : 'LOW',
      toolsUsed: isEligibleForScoring
        ? ['WinHood Native SAST (Taint Mode)', 'WinHood Native Secret Scanner', 'WinHood Native SCA']
        : [],
      limitations: isEligibleForScoring ? [] : ['Código-fonte ausente ou inválido.'],
      evidenceCount: reasonsByCat.security.length,
      evaluationReasons: isEligibleForScoring ? reasonsByCat.security : [],
      criteriaOutcomes: outcomesFor('security'),
    },
    performance: {
      category: 'performance',
      status: buildStatus('performance', isPerformanceMeasured),
      rawScore: rawCategoryScores.performance,
      finalScore: categoryScores.performance,
      score: categoryScores.performance,
      rating: scoreToCategoryRating(categoryScores.performance),
      weight: effectiveWeights.performance,
      weightPercent: effectiveWeights.performance,
      effectiveWeight: effectiveWeights.performance,
      originalWeight: originalWeights.performance,
      remediationEffortMinutes: sumEffort('performance'),
      coveragePercent: isPerformanceMeasured ? 100 : 0,
      confidence: isPerformanceMeasured ? 'HIGH' : 'LOW',
      toolsUsed: isPerformanceMeasured ? ['k6 Runtime Load Engine'] : [],
      limitations: isPerformanceMeasured
        ? []
        : ['Métricas de runtime (P50/P95/CPU/RAM) não medidas. Análise estática de código não infere métricas de runtime.'],
      evidenceCount: reasonsByCat.performance.length,
      evaluationReasons: isEligibleForScoring ? reasonsByCat.performance : [],
      criteriaOutcomes: outcomesFor('performance'),
    },
    architecture: {
      category: 'architecture',
      status: buildStatus('architecture', true),
      rawScore: rawCategoryScores.architecture,
      finalScore: categoryScores.architecture,
      score: categoryScores.architecture,
      rating: scoreToCategoryRating(categoryScores.architecture),
      weight: effectiveWeights.architecture,
      weightPercent: effectiveWeights.architecture,
      effectiveWeight: effectiveWeights.architecture,
      originalWeight: originalWeights.architecture,
      remediationEffortMinutes: sumEffort('architecture'),
      coveragePercent: isEligibleForScoring ? input.coveragePercent : 0,
      confidence: isEligibleForScoring ? 'HIGH' : 'LOW',
      toolsUsed: isEligibleForScoring ? ['WinHood Native Architecture Graph Analyzer'] : [],
      limitations: isEligibleForScoring ? [] : ['Código-fonte ausente ou inválido.'],
      evidenceCount: reasonsByCat.architecture.length,
      evaluationReasons: isEligibleForScoring ? reasonsByCat.architecture : [],
      criteriaOutcomes: outcomesFor('architecture'),
    },
    database: {
      category: 'database',
      status: buildStatus('database', true),
      rawScore: rawCategoryScores.database,
      finalScore: categoryScores.database,
      score: categoryScores.database,
      rating: scoreToCategoryRating(categoryScores.database),
      weight: effectiveWeights.database,
      weightPercent: effectiveWeights.database,
      effectiveWeight: effectiveWeights.database,
      originalWeight: originalWeights.database,
      remediationEffortMinutes: sumEffort('database'),
      coveragePercent: isEligibleForScoring && !notApplicableSet.has('database') ? input.coveragePercent : 0,
      confidence: isEligibleForScoring ? 'HIGH' : 'LOW',
      toolsUsed: isEligibleForScoring && !notApplicableSet.has('database') ? ['WinHood Native SQL & Schema Auditor'] : [],
      limitations: notApplicableSet.has('database')
        ? ['Dimensão Banco de Dados classificada como NÃO APLICÁVEL para este domínio/arquitetura.']
        : [],
      evidenceCount: reasonsByCat.database.length,
      evaluationReasons: isEligibleForScoring && !notApplicableSet.has('database') ? reasonsByCat.database : [],
      criteriaOutcomes: outcomesFor('database'),
    },
    reliability: {
      category: 'reliability',
      status: buildStatus('reliability', true),
      rawScore: rawCategoryScores.reliability,
      finalScore: categoryScores.reliability,
      score: categoryScores.reliability,
      rating: categoryScores.reliability !== null ? reliabilityRating : null,
      weight: effectiveWeights.reliability,
      weightPercent: effectiveWeights.reliability,
      effectiveWeight: effectiveWeights.reliability,
      originalWeight: originalWeights.reliability,
      remediationEffortMinutes: sumEffort('reliability'),
      coveragePercent: isEligibleForScoring ? input.coveragePercent : 0,
      confidence: isEligibleForScoring ? 'HIGH' : 'LOW',
      toolsUsed: isEligibleForScoring ? ['WinHood Native Reliability & Test Inspector'] : [],
      limitations: isEligibleForScoring ? [] : ['Código-fonte ausente ou inválido.'],
      evidenceCount: reasonsByCat.reliability.length,
      evaluationReasons: isEligibleForScoring ? reasonsByCat.reliability : [],
      criteriaOutcomes: outcomesFor('reliability'),
    },
    compatibility: {
      category: 'compatibility',
      status: buildStatus('compatibility', true),
      rawScore: rawCategoryScores.compatibility,
      finalScore: categoryScores.compatibility,
      score: categoryScores.compatibility,
      rating: scoreToCategoryRating(categoryScores.compatibility),
      weight: effectiveWeights.compatibility,
      weightPercent: effectiveWeights.compatibility,
      effectiveWeight: effectiveWeights.compatibility,
      originalWeight: originalWeights.compatibility,
      remediationEffortMinutes: sumEffort('compatibility'),
      coveragePercent: isEligibleForScoring ? input.coveragePercent : 0,
      confidence: isEligibleForScoring ? 'MEDIUM' : 'LOW',
      toolsUsed: isEligibleForScoring ? ['WinHood Native SCA & Manifest Inspector'] : [],
      limitations: [],
      evidenceCount: reasonsByCat.compatibility.length,
      evaluationReasons: isEligibleForScoring ? reasonsByCat.compatibility : [],
      criteriaOutcomes: outcomesFor('compatibility'),
    },
    usability: {
      category: 'usability',
      status: buildStatus('usability', true),
      rawScore: rawCategoryScores.usability,
      finalScore: categoryScores.usability,
      score: categoryScores.usability,
      rating: scoreToCategoryRating(categoryScores.usability),
      weight: effectiveWeights.usability,
      weightPercent: effectiveWeights.usability,
      effectiveWeight: effectiveWeights.usability,
      originalWeight: originalWeights.usability,
      remediationEffortMinutes: sumEffort('usability'),
      coveragePercent: isEligibleForScoring && !notApplicableSet.has('usability') ? 100 : 0,
      confidence: isEligibleForScoring ? 'MEDIUM' : 'LOW',
      toolsUsed: isEligibleForScoring && !notApplicableSet.has('usability') ? ['WinHood Native UI/CLI Ergonomics Inspector'] : [],
      limitations: notApplicableSet.has('usability')
        ? ['Dimensão Usabilidade classificada como NÃO APLICÁVEL (serviço/API sem interface humana direta).']
        : [],
      evidenceCount: reasonsByCat.usability.length,
      evaluationReasons: isEligibleForScoring && !notApplicableSet.has('usability') ? reasonsByCat.usability : [],
      criteriaOutcomes: outcomesFor('usability'),
    },
    installation: {
      category: 'installation',
      status: buildStatus('installation', true),
      rawScore: rawCategoryScores.installation,
      finalScore: categoryScores.installation,
      score: categoryScores.installation,
      rating: scoreToCategoryRating(categoryScores.installation),
      weight: effectiveWeights.installation,
      weightPercent: effectiveWeights.installation,
      effectiveWeight: effectiveWeights.installation,
      originalWeight: originalWeights.installation,
      remediationEffortMinutes: sumEffort('installation'),
      coveragePercent: isEligibleForScoring ? 100 : 0,
      confidence: input.hasCleanSandboxUninstall === null ? 'MEDIUM' : 'HIGH',
      toolsUsed:
        input.hasCleanSandboxUninstall === null
          ? ['WinHood Static Manifest & Build Inspector']
          : ['Windows Sandbox Diff Analyzer (T0/T1/T2)'],
      limitations:
        input.hasCleanSandboxUninstall === null
          ? ['Inspeção estática de manifesto (Windows Sandbox não executado no host Linux).']
          : input.hasCleanSandboxUninstall === false
          ? ['Resíduos pós-desinstalação ou comandos shell inseguros detectados.']
          : [],
      evidenceCount: reasonsByCat.installation.length,
      evaluationReasons: isEligibleForScoring ? reasonsByCat.installation : [],
      criteriaOutcomes: outcomesFor('installation'),
    },
    privacy: {
      category: 'privacy',
      status: buildStatus('privacy', true),
      rawScore: rawCategoryScores.privacy,
      finalScore: categoryScores.privacy,
      score: categoryScores.privacy,
      rating: scoreToCategoryRating(categoryScores.privacy),
      weight: effectiveWeights.privacy,
      weightPercent: effectiveWeights.privacy,
      effectiveWeight: effectiveWeights.privacy,
      originalWeight: originalWeights.privacy,
      remediationEffortMinutes: sumEffort('privacy'),
      coveragePercent: isEligibleForScoring ? input.coveragePercent : 0,
      confidence: isEligibleForScoring ? 'HIGH' : 'LOW',
      toolsUsed: isEligibleForScoring ? ['WinHood Native Data Protection & Encryption Scanner'] : [],
      limitations: [],
      evidenceCount: reasonsByCat.privacy.length,
      evaluationReasons: isEligibleForScoring ? reasonsByCat.privacy : [],
      criteriaOutcomes: outcomesFor('privacy'),
    },
    documentation: {
      category: 'documentation',
      status: buildStatus('documentation', true),
      rawScore: rawCategoryScores.documentation,
      finalScore: categoryScores.documentation,
      score: categoryScores.documentation,
      rating: scoreToCategoryRating(categoryScores.documentation),
      weight: effectiveWeights.documentation,
      weightPercent: effectiveWeights.documentation,
      effectiveWeight: effectiveWeights.documentation,
      originalWeight: originalWeights.documentation,
      remediationEffortMinutes: sumEffort('documentation'),
      coveragePercent: isEligibleForScoring ? 100 : 0,
      confidence: isEligibleForScoring ? 'HIGH' : 'LOW',
      toolsUsed: isEligibleForScoring ? ['WinHood Documentation Completeness Analyzer'] : [],
      limitations: input.hasCompleteDocumentation ? [] : ['Documentação técnica incompleta ou ausente.'],
      evidenceCount: reasonsByCat.documentation.length,
      evaluationReasons: isEligibleForScoring ? reasonsByCat.documentation : [],
      criteriaOutcomes: outcomesFor('documentation'),
    },
  };

  const applicableCategoriesCount = Math.max(1, enabledList.length);
  const scopeCoveragePercent = isEligibleForScoring
    ? Math.round((assessedCategories.length / applicableCategoriesCount) * 100)
    : 0;
  const evidenceConfidence: 'HIGH' | 'MEDIUM' | 'LOW' =
    !isEligibleForScoring || scopeCoveragePercent < 50
      ? 'LOW'
      : scopeCoveragePercent >= 80 && input.coveragePercent >= 80
      ? 'HIGH'
      : 'MEDIUM';

  return {
    softwareId: input.softwareId,
    softwareName: input.softwareName,
    softwareVersion: input.softwareVersion,
    categoryScores,
    categoryDetails,
    groupedScores,
    separatedIndicators: {
      technicalScore: isEligibleForScoring ? overallScore : null,
      scopeCoveragePercent,
      evidenceConfidence,
      qualityGateDecision: executiveDecision,
      veracityState: input.veracityClassification,
    },
    originalWeights,
    effectiveWeights,
    classificationLabel: isEligibleForScoring
      ? classifyScoreScale(overallScore)
      : 'Inconclusivo / Cobertura Insuficiente',
    penaltyCapsTriggered,
    advantages,
    deficiencies,
    risks,
    metricsSummary: m,
    runtimeMetrics: isPerformanceMeasured
      ? {
          status: 'MEASURED',
          p50LatencyMs: m.p50LatencyMs,
          p95LatencyMs: m.p95LatencyMs,
          p99LatencyMs: m.p99LatencyMs,
          throughputRps: m.throughputRps,
          cpuPercent: m.cpuPercent,
          memoryRssMb: m.memoryMb,
          startupTimeMs: m.startupTimeMs,
        }
      : {
          status: 'NOT_MEASURED',
          reason: 'Métricas de runtime não medidas em worker isolado.',
        },
    staticMetrics: input.staticMetrics || {
      loc,
      cyclomaticComplexity: m.avgCyclomaticComplexity,
      cognitiveComplexity: m.avgCognitiveComplexity,
      duplicatedLinesPercent: m.duplicatedLinesPercent,
      couplingIndex: m.couplingIndex,
      cohesionIndex: m.cohesionIndex,
      circularDependenciesCount: m.circularDependencies,
      layerViolationsCount: 0,
      riskIndicators: [],
    },
    qualityGate: {
      gateName: input.qualityGateId === 'qg-zero-trust' ? 'WinHood Zero-Trust Gate' : 'Sonar way (MQR Official)',
      status: qualityGateStatus,
      executiveDecision,
      fudgeFactorApplied,
      conditionsMet: isEligibleForScoring ? 5 - failedConditions.length : 0,
      conditionsFailed: failedConditions.length,
      failedMetrics: failedConditions,
      conditions: qgConditions,
    },
    ratings: {
      reliability: reliabilityRating,
      security: securityRating,
      maintainability: maintainabilityRating,
    },
  };
}
