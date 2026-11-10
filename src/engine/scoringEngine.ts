import crypto from 'node:crypto';
import type {
  BenchmarkCategoryKey,
  BenchmarkProfileConfig,
  PenaltyCapTriggered,
  SoftwareScoreCard,
  VeracityClassification,
} from '../types/benchmark';

export const ALGORITHM_VERSION = 'WINHOOD-DET-SCORE-v2.4.0';

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

export function validateCategoryWeights(weights: Record<BenchmarkCategoryKey, number>): {
  valid: boolean;
  totalWeight: number;
  errors: string[];
} {
  const errors: string[] = [];
  const keys = Object.keys(DEFAULT_CATEGORY_WEIGHTS) as BenchmarkCategoryKey[];
  let sum = 0;

  for (const key of keys) {
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

export interface RawEvaluationInput {
  softwareId: string;
  softwareName: string;
  softwareVersion: string;
  veracityClassification: VeracityClassification;
  coveragePercent: number;
  essentialFeaturesMissing: number;
  visualOnlyFeaturesCount: number;
  metrics: SoftwareScoreCard['metricsSummary'];
  hasEncryptionAtRest: boolean;
  hasAuditTrail: boolean;
  hasCleanSandboxUninstall: boolean;
  hasCompleteDocumentation: boolean;
  environmentEquivalent: boolean;
}

export function calculateDeterministicScoreCard(
  input: RawEvaluationInput,
  weights: Record<BenchmarkCategoryKey, number>,
  enablePenaltyCaps = true
): SoftwareScoreCard {
  const m = input.metrics;
  const clamp05 = (val: number) => Math.max(0, Math.min(5, Math.round(val * 100) / 100));

  // 1. Raw category calculations on 0.00 - 5.00 scale
  const passRatio =
    m.functionalTestsTotal > 0 ? m.functionalTestsPassed / m.functionalTestsTotal : 0;
  const rawFunctionality = clamp05(
    5.0 * passRatio - input.essentialFeaturesMissing * 0.9 - input.visualOnlyFeaturesCount * 0.6
  );

  const rawCodeQuality = clamp05(
    5.0 -
      m.bugs * 0.35 -
      m.codeSmells * 0.08 -
      Math.max(0, m.avgCyclomaticComplexity - 5) * 0.18 -
      m.duplicatedLinesPercent * 0.08 -
      m.deadCodeSymbols * 0.12
  );

  const rawSecurity = clamp05(
    5.0 -
      m.criticalVulns * 1.45 -
      m.highVulns * 0.65 -
      m.mediumVulns * 0.25 -
      m.lowVulns * 0.08 -
      m.secretsExposed * 1.2 +
      (input.hasEncryptionAtRest ? 0.2 : -0.8)
  );

  // If experimental environment is not equivalent, performance cannot be scored
  const rawPerformance = input.environmentEquivalent
    ? clamp05(
        5.0 -
          Math.max(0, (m.p95LatencyMs - 25) / 80) -
          Math.max(0, (m.memoryMb - 90) / 150) -
          Math.max(0, (m.startupTimeMs - 200) / 600)
      )
    : null;

  const rawArchitecture = clamp05(
    5.0 -
      m.circularDependencies * 1.1 -
      Math.max(0, m.couplingIndex - 0.35) * 3.0 +
      (m.cohesionIndex - 0.5) * 1.2
  );

  const rawDatabase = clamp05(5.0 - m.dbSchemaIssues * 0.55);

  const rawReliability = clamp05(
    4.6 * (0.5 * passRatio + 0.5 * Math.min(1, m.testCoveragePercent / 85)) -
      m.criticalVulns * 0.4 -
      m.bugs * 0.2
  );

  const rawCompatibility = clamp05(4.4 - (m.bugs > 3 ? 0.6 : 0));
  const rawUsability = clamp05(4.3 - input.visualOnlyFeaturesCount * 0.7);
  const rawInstallation = clamp05(input.hasCleanSandboxUninstall ? 4.7 : 2.3);
  const rawPrivacy = clamp05(
    (input.hasEncryptionAtRest ? 2.5 : 0.8) +
      (input.hasAuditTrail ? 2.3 : 1.0) -
      m.secretsExposed * 0.9
  );
  const rawDocumentation = clamp05(input.hasCompleteDocumentation ? 4.6 : 2.4);

  const categoryScores: Record<BenchmarkCategoryKey, number | null> = {
    functionality: rawFunctionality,
    code_quality: rawCodeQuality,
    security: rawSecurity,
    performance: rawPerformance,
    architecture: rawArchitecture,
    database: rawDatabase,
    reliability: rawReliability,
    compatibility: rawCompatibility,
    usability: rawUsability,
    installation: rawInstallation,
    privacy: rawPrivacy,
    documentation: rawDocumentation,
  };

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
      penaltyCapsTriggered.push({
        ruleId,
        category,
        reason,
        maxAllowedScore: maxAllowed,
        originalScore: current,
        cappedScore: capped,
      });
      categoryScores[category] = capped;
    }
  };

  // 2. Apply Mathematical Penalty Caps / Kill Switches (Section 21)
  if (enablePenaltyCaps) {
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

    if (!input.hasCleanSandboxUninstall) {
      applyCap(
        'CAP-INST-001',
        'installation',
        2.8,
        'Resíduos inesperados detectados no snapshot T2 pós-desinstalação (arquivos/chaves de registro órfãos).'
      );
    }
  }

  // 3. Calculate weighted overall score (excluding null / non-evaluated categories so they aren't treated as 0)
  let weightedSum = 0;
  let activeWeightSum = 0;

  for (const key of Object.keys(categoryScores) as BenchmarkCategoryKey[]) {
    const score = categoryScores[key];
    const w = weights[key] ?? 0;
    if (score !== null && w > 0) {
      weightedSum += score * w;
      activeWeightSum += w;
    }
  }

  let overallScore =
    activeWeightSum > 0 ? clamp05(weightedSum / activeWeightSum) : 0;

  // Overall kill switch if critical security vulnerability exists
  if (enablePenaltyCaps && (m.criticalVulns > 0 || m.secretsExposed > 0) && overallScore > 2.9) {
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
    technicalScore: clamp05((safeVal('code_quality') + safeVal('database') + safeVal('reliability')) / 3),
    performanceScore: safeVal('performance'),
    architectureScore: safeVal('architecture'),
    qualityScore: safeVal('code_quality'),
    overallScore,
  };

  // 4. Derive deterministic advantages, deficiencies, and risks from actual metrics
  const advantages: string[] = [];
  const deficiencies: string[] = [];
  const risks: string[] = [];

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

  if (m.p95LatencyMs <= 45) {
    advantages.push(`Baixa latência P95 (${m.p95LatencyMs.toFixed(1)} ms) e inicialização rápida (${m.startupTimeMs} ms).`);
  } else if (m.p95LatencyMs > 90) {
    deficiencies.push(`Latência P95 elevada (${m.p95LatencyMs.toFixed(1)} ms) sob carga equivalente.`);
  }

  if (!input.hasCleanSandboxUninstall) {
    risks.push('Persistência de artefatos residuais no sistema operacional após rotina de desinstalação (Snapshot T2).');
  }

  // 5. Formal SonarQube Ratings (A-E) & Quality Gate Determination
  const reliabilityRating: 'A' | 'B' | 'C' | 'D' | 'E' =
    m.bugs === 0 ? 'A' : m.bugs <= 2 ? 'B' : m.bugs <= 5 ? 'C' : m.bugs <= 10 ? 'D' : 'E';

  const securityRating: 'A' | 'B' | 'C' | 'D' | 'E' =
    m.criticalVulns > 0 ? 'E' : m.highVulns > 0 ? 'D' : m.mediumVulns > 0 ? 'C' : m.lowVulns > 0 ? 'B' : 'A';

  const debtRatio = m.technicalDebtMinutes / Math.max(60, (m.bugs * 30 + m.codeSmells * 15 + 100));
  const maintainabilityRating: 'A' | 'B' | 'C' | 'D' | 'E' =
    debtRatio <= 1.2 && m.duplicatedLinesPercent <= 3.0
      ? 'A'
      : debtRatio <= 2.5
        ? 'B'
        : debtRatio <= 5.0
          ? 'C'
          : debtRatio <= 10.0
            ? 'D'
            : 'E';

  const failedConditions: string[] = [];
  if (m.criticalVulns > 0) failedConditions.push(`Vulnerabilidades Críticas: ${m.criticalVulns} > 0`);
  if (m.secretsExposed > 0) failedConditions.push(`Segredos Hardcoded Expostos: ${m.secretsExposed} > 0`);
  if (m.bugs > 3) failedConditions.push(`Bugs Confiabilidade: ${m.bugs} > 3`);
  if (m.duplicatedLinesPercent > 5) failedConditions.push(`Duplicação de Código: ${m.duplicatedLinesPercent}% > 5.0%`);
  if (securityRating === 'D' || securityRating === 'E') failedConditions.push(`Security Rating reprovado (${securityRating})`);

  const qualityGateStatus: 'PASSED' | 'FAILED' | 'WARN' =
    failedConditions.length === 0
      ? 'PASSED'
      : failedConditions.length === 1 && m.criticalVulns === 0 && m.secretsExposed === 0
        ? 'WARN'
        : 'FAILED';

  return {
    softwareId: input.softwareId,
    softwareName: input.softwareName,
    softwareVersion: input.softwareVersion,
    categoryScores,
    groupedScores,
    classificationLabel: classifyScoreScale(overallScore),
    penaltyCapsTriggered,
    advantages,
    deficiencies,
    risks,
    metricsSummary: m,
    qualityGate: {
      status: qualityGateStatus,
      conditionsMet: 5 - failedConditions.length,
      conditionsFailed: failedConditions.length,
      failedMetrics: failedConditions,
    },
    ratings: {
      reliability: reliabilityRating,
      security: securityRating,
      maintainability: maintainabilityRating,
    },
  };
}
