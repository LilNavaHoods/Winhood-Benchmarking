import type {
  FindingValidationLifecycleState,
  NormalizedFinding,
  SeverityLevel,
  VulnerabilityValidationState,
} from '../types/benchmark';

export type CoreSeverityFilter = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type RemediationStatusBucket =
  | 'ALL'
  | 'OPEN_PENDING'
  | 'IN_REMEDIATION'
  | 'REMEDIATED'
  | 'RISK_ACCEPTED'
  | 'DISMISSED_FP'
  | 'CONFIRMED'
  | 'PROBABLE'
  | 'FIXED_PENDING_RETEST'
  | 'VERIFIED_RESOLVED'
  | 'ACCEPTED_RISK'
  | 'FALSE_POSITIVE'
  | 'NOT_REPRODUCIBLE'
  | 'INCONCLUSIVE'
  | 'NOT_TESTED';

export interface SecuritySuiteFilterState {
  /** Selected severities (empty array = Todas as gravidades: Critical, High, Medium, Low) */
  severities: CoreSeverityFilter[];
  /** Selected remediation status bucket or specific lifecycle state */
  remediationStatus: RemediationStatusBucket;
  /** Selected validation state (6-state matrix filter) */
  validationState: 'ALL' | VulnerabilityValidationState;
  /** Selected software ID ('ALL' or specific softwareId) */
  softwareId: string;
  /** Selected finding category ('ALL' or SAST, SCA, SECRETS, etc.) */
  category: string;
  /** Free-text search across title, ruleId, filePath, CWE, CVE, SHA-256 */
  searchQuery: string;
}

export const DEFAULT_SECURITY_SUITE_FILTERS: SecuritySuiteFilterState = {
  severities: [],
  remediationStatus: 'ALL',
  validationState: 'ALL',
  softwareId: 'ALL',
  category: 'ALL',
  searchQuery: '',
};

export interface ResolvedFindingRemediationInfo {
  validationState6: VulnerabilityValidationState;
  lifecycleState: FindingValidationLifecycleState;
  remediationBucket:
    | 'OPEN_PENDING'
    | 'IN_REMEDIATION'
    | 'REMEDIATED'
    | 'RISK_ACCEPTED'
    | 'DISMISSED_FP';
  remediationLabel: string;
  isExempt: boolean;
}

/**
 * Normalizes a benchmark SeverityLevel into one of the 4 canonical severity buckets
 * (Critical, High, Medium, Low) for consistent filtering and aggregation.
 */
export function normalizeFindingSeverityBucket(severity: SeverityLevel): CoreSeverityFilter {
  switch (severity) {
    case 'BLOCKER':
    case 'CRITICAL':
      return 'CRITICAL';
    case 'HIGH':
      return 'HIGH';
    case 'MEDIUM':
      return 'MEDIUM';
    case 'LOW':
    case 'INFO':
    default:
      return 'LOW';
  }
}

/**
 * Resolves the 6-state validation state, 9-state lifecycle state, and high-level
 * remediation bucket for a NormalizedFinding.
 */
export function resolveFindingRemediationInfo(
  finding: Pick<NormalizedFinding, 'validationStatus' | 'lifecycleState'>,
  validationOverride?: VulnerabilityValidationState,
  lifecycleOverride?: FindingValidationLifecycleState
): ResolvedFindingRemediationInfo {
  const effectiveLifecycle: FindingValidationLifecycleState = (() => {
    if (lifecycleOverride) return lifecycleOverride;
    if (validationOverride) {
      switch (validationOverride) {
        case 'CONFIRMADA':
          return 'CONFIRMED';
        case 'PROVAVEL':
          return 'PROBABLE';
        case 'FALSO_POSITIVO':
          return 'FALSE_POSITIVE';
        case 'NAO_REPRODUZIVEL':
          return 'NOT_REPRODUCIBLE';
        case 'INCONCLUSIVA':
          return 'INCONCLUSIVE';
        case 'NAO_TESTADA':
          return 'NOT_TESTED';
      }
    }
    if (finding.lifecycleState) {
      if (finding.lifecycleState === 'VALIDATED') return 'CONFIRMED';
      if (finding.lifecycleState === 'ACCEPTED') return 'ACCEPTED_RISK';
      if (finding.lifecycleState === 'FALSE_POSITIVE_REVIEWED') return 'FALSE_POSITIVE';
      return finding.lifecycleState;
    }
    switch (finding.validationStatus) {
      case 'ACCEPTED':
      case 'ACCEPTED_RISK':
        return 'ACCEPTED_RISK';
      case 'FALSE_POSITIVE_REVIEWED':
      case 'FALSE_POSITIVE':
        return 'FALSE_POSITIVE';
      case 'FIXED_PENDING_RETEST':
        return 'FIXED_PENDING_RETEST';
      case 'VERIFIED_RESOLVED':
        return 'VERIFIED_RESOLVED';
      case 'NOT_REPRODUCIBLE':
        return 'NOT_REPRODUCIBLE';
      case 'INCONCLUSIVE':
        return 'INCONCLUSIVE';
      case 'NOT_TESTED':
      case 'UNVERIFIED':
        return 'NOT_TESTED';
      case 'PROBABLE':
        return 'PROBABLE';
      case 'CONFIRMED':
      case 'VALIDATED':
      default:
        return 'CONFIRMED';
    }
  })();

  const validationState6: VulnerabilityValidationState = (() => {
    if (validationOverride) return validationOverride;
    switch (effectiveLifecycle) {
      case 'CONFIRMED':
      case 'FIXED_PENDING_RETEST':
      case 'VERIFIED_RESOLVED':
      case 'ACCEPTED_RISK':
        return 'CONFIRMADA';
      case 'PROBABLE':
        return 'PROVAVEL';
      case 'FALSE_POSITIVE':
        return 'FALSO_POSITIVO';
      case 'NOT_REPRODUCIBLE':
        return 'NAO_REPRODUZIVEL';
      case 'INCONCLUSIVE':
        return 'INCONCLUSIVA';
      case 'NOT_TESTED':
      default:
        return 'NAO_TESTADA';
    }
  })();

  const remediationBucket: ResolvedFindingRemediationInfo['remediationBucket'] = (() => {
    switch (effectiveLifecycle) {
      case 'FIXED_PENDING_RETEST':
        return 'IN_REMEDIATION';
      case 'VERIFIED_RESOLVED':
        return 'REMEDIATED';
      case 'ACCEPTED_RISK':
        return 'RISK_ACCEPTED';
      case 'FALSE_POSITIVE':
      case 'NOT_REPRODUCIBLE':
      case 'INCONCLUSIVE':
        return 'DISMISSED_FP';
      case 'CONFIRMED':
      case 'PROBABLE':
      case 'NOT_TESTED':
      default:
        return 'OPEN_PENDING';
    }
  })();

  const remediationLabel: string = (() => {
    switch (effectiveLifecycle) {
      case 'FIXED_PENDING_RETEST':
        return 'Em Remediação (Aguardando Reteste)';
      case 'VERIFIED_RESOLVED':
        return 'Remediado & Verificado (Resolvido)';
      case 'ACCEPTED_RISK':
        return 'Risco Aceito (Exceção Governança)';
      case 'FALSE_POSITIVE':
        return 'Descartado (Falso Positivo)';
      case 'NOT_REPRODUCIBLE':
        return 'Não Reproduzível';
      case 'INCONCLUSIVE':
        return 'Inconclusivo';
      case 'NOT_TESTED':
        return 'Pendente de Triagem (Não Testado)';
      case 'PROBABLE':
        return 'Aberto / Pendente (Provável)';
      case 'CONFIRMED':
      default:
        return 'Aberto / Pendente de Remediação';
    }
  })();

  const isExempt =
    effectiveLifecycle === 'VERIFIED_RESOLVED' ||
    effectiveLifecycle === 'ACCEPTED_RISK' ||
    effectiveLifecycle === 'FALSE_POSITIVE' ||
    effectiveLifecycle === 'NOT_REPRODUCIBLE' ||
    effectiveLifecycle === 'INCONCLUSIVE';

  return {
    validationState6,
    lifecycleState: effectiveLifecycle,
    remediationBucket,
    remediationLabel,
    isExempt,
  };
}

export function matchesRemediationStatusFilter(
  info: ResolvedFindingRemediationInfo,
  filter: RemediationStatusBucket
): boolean {
  if (filter === 'ALL') return true;
  if (
    filter === 'OPEN_PENDING' ||
    filter === 'IN_REMEDIATION' ||
    filter === 'REMEDIATED' ||
    filter === 'RISK_ACCEPTED' ||
    filter === 'DISMISSED_FP'
  ) {
    return info.remediationBucket === filter;
  }
  return info.lifecycleState === filter;
}

export function filterSecuritySuiteFindings(
  findings: NormalizedFinding[],
  filters: SecuritySuiteFilterState,
  overrides?: {
    validationMap?: Record<string, VulnerabilityValidationState>;
    lifecycleMap?: Record<string, FindingValidationLifecycleState>;
  }
): NormalizedFinding[] {
  const activeSeverities = filters.severities;
  const query = filters.searchQuery.trim().toLowerCase();

  return findings.filter((f) => {
    if (filters.softwareId !== 'ALL' && f.softwareId !== filters.softwareId) {
      return false;
    }

    if (filters.category !== 'ALL' && f.category !== filters.category) {
      return false;
    }

    if (activeSeverities.length > 0) {
      const bucket = normalizeFindingSeverityBucket(f.severity);
      if (!activeSeverities.includes(bucket)) {
        return false;
      }
    }

    const remInfo = resolveFindingRemediationInfo(
      f,
      overrides?.validationMap?.[f.id],
      overrides?.lifecycleMap?.[f.id]
    );

    if (!matchesRemediationStatusFilter(remInfo, filters.remediationStatus)) {
      return false;
    }

    if (filters.validationState !== 'ALL' && remInfo.validationState6 !== filters.validationState) {
      return false;
    }

    if (query.length > 0) {
      const matchesText =
        f.title.toLowerCase().includes(query) ||
        f.filePath.toLowerCase().includes(query) ||
        f.originalRuleId.toLowerCase().includes(query) ||
        f.toolName.toLowerCase().includes(query) ||
        f.softwareName.toLowerCase().includes(query) ||
        f.evidenceSha256.toLowerCase().includes(query) ||
        Boolean(f.cwe && f.cwe.toLowerCase().includes(query)) ||
        Boolean(f.cve && f.cve.toLowerCase().includes(query)) ||
        Boolean(f.remediation && f.remediation.toLowerCase().includes(query));

      if (!matchesText) {
        return false;
      }
    }

    return true;
  });
}

export interface SecurityFindingsFilterMetrics {
  totalFindings: number;
  filteredCount: number;
  bySeverity: Record<CoreSeverityFilter, number>;
  byRemediationBucket: {
    OPEN_PENDING: number;
    IN_REMEDIATION: number;
    REMEDIATED: number;
    RISK_ACCEPTED: number;
    DISMISSED_FP: number;
  };
  filteredEffortMinutes: number;
  hasActiveFilters: boolean;
}

export function computeSecurityFindingsFilterMetrics(
  allFindings: NormalizedFinding[],
  filteredFindings: NormalizedFinding[],
  filters: SecuritySuiteFilterState,
  overrides?: {
    validationMap?: Record<string, VulnerabilityValidationState>;
    lifecycleMap?: Record<string, FindingValidationLifecycleState>;
  }
): SecurityFindingsFilterMetrics {
  const bySeverity: Record<CoreSeverityFilter, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };

  const byRemediationBucket = {
    OPEN_PENDING: 0,
    IN_REMEDIATION: 0,
    REMEDIATED: 0,
    RISK_ACCEPTED: 0,
    DISMISSED_FP: 0,
  };

  for (const f of allFindings) {
    const sevBucket = normalizeFindingSeverityBucket(f.severity);
    bySeverity[sevBucket] += 1;

    const remInfo = resolveFindingRemediationInfo(
      f,
      overrides?.validationMap?.[f.id],
      overrides?.lifecycleMap?.[f.id]
    );
    byRemediationBucket[remInfo.remediationBucket] += 1;
  }

  const filteredEffortMinutes = filteredFindings.reduce(
    (sum, f) => sum + (f.remediationEffortMinutes || 15),
    0
  );

  const hasActiveFilters =
    filters.severities.length > 0 ||
    filters.remediationStatus !== 'ALL' ||
    filters.validationState !== 'ALL' ||
    filters.softwareId !== 'ALL' ||
    filters.category !== 'ALL' ||
    filters.searchQuery.trim().length > 0;

  return {
    totalFindings: allFindings.length,
    filteredCount: filteredFindings.length,
    bySeverity,
    byRemediationBucket,
    filteredEffortMinutes,
    hasActiveFilters,
  };
}
