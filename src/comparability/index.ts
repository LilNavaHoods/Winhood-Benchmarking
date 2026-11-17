export type ComparisonModality = 'SAME_ENGINE' | 'CROSS_TOOL';

export type ComparabilityClassification =
  | 'STRICTLY_COMPARABLE'
  | 'QUALIFIED_COMPARISON'
  | 'NOT_COMPARABLE';

export interface CandidateScopeDescriptor {
  softwareId: string;
  engineVersion: string;
  ruleCatalogSha256: string;
  scopeCoveragePercent: number;
  evidenceConfidence: 'HIGH' | 'MEDIUM' | 'LOW';
  functionalCategory: string;
  commitHash?: string;
  normalizedFindingCategories?: string[];
  toolIdentifier?: string;
}

export interface ComparabilityValidationOptions {
  modality?: ComparisonModality;
  sameCommitVerified?: boolean;
  normalizedTaxonomyApplied?: boolean;
}

export interface ComparabilityValidationResult {
  comparable: boolean;
  status: 'COMPATIBLE' | 'INCOMPATIBLE_SCOPE' | 'INCONCLUSIVE';
  comparisonModality: ComparisonModality;
  comparabilityClassification: ComparabilityClassification;
  reasons: string[];
  qualifications: string[];
  coverageDeltaPercent: number;
}

/**
 * Validates A/B comparability premises documented in docs/LIMITATIONS.md across two modalities:
 * - SAME_ENGINE (Modalidade 1): Comparação sob a mesma versão do motor e catálogo de regras.
 * - CROSS_TOOL (Modalidade 2): Comparação entre ferramentas distintas sobre o mesmo projeto/commit,
 *   com escopo equivalente e taxonomia de categorias normalizada.
 * Never allows a winner declaration when classification is NOT_COMPARABLE.
 */
export function validatePairComparability(
  candidateA: CandidateScopeDescriptor,
  candidateB: CandidateScopeDescriptor,
  options?: ComparabilityValidationOptions
): ComparabilityValidationResult {
  const reasons: string[] = [];
  const qualifications: string[] = [];
  const modality: ComparisonModality = options?.modality || 'SAME_ENGINE';
  const coverageDeltaPercent = Math.abs(
    candidateA.scopeCoveragePercent - candidateB.scopeCoveragePercent
  );

  if (modality === 'SAME_ENGINE') {
    if (candidateA.engineVersion !== candidateB.engineVersion) {
      reasons.push(
        `Engine version mismatch: ${candidateA.engineVersion} vs ${candidateB.engineVersion}`
      );
    }
    if (candidateA.ruleCatalogSha256 !== candidateB.ruleCatalogSha256) {
      reasons.push('Rule catalog SHA-256 digest mismatch between candidates.');
    }
  } else {
    // Modalidade 2 (CROSS_TOOL): tools/engines can differ, provided same commit/project and normalized categories
    const sameCommit =
      options?.sameCommitVerified ??
      Boolean(
        candidateA.commitHash &&
          candidateB.commitHash &&
          candidateA.commitHash === candidateB.commitHash
      );
    if (!sameCommit) {
      reasons.push(
        'Cross-tool comparison requires identical project commit baseline between executions.'
      );
    }
    if (options?.normalizedTaxonomyApplied === false) {
      reasons.push(
        'Cross-tool comparison requires normalized CWE/MQR category taxonomy mapping.'
      );
    }
    if (candidateA.engineVersion !== candidateB.engineVersion) {
      qualifications.push(
        `Comparação Cross-Tool qualificada entre motores distintos (${candidateA.engineVersion} vs ${candidateB.engineVersion}) sobre escopo normalizado.`
      );
    }
  }

  if (candidateA.functionalCategory !== candidateB.functionalCategory) {
    reasons.push(
      `Functional category mismatch: ${candidateA.functionalCategory} vs ${candidateB.functionalCategory}`
    );
  }
  if (coverageDeltaPercent > 30) {
    reasons.push(
      `Scope coverage disparity (${coverageDeltaPercent}%) exceeds maximum 30% threshold.`
    );
  } else if (coverageDeltaPercent > 10) {
    qualifications.push(
      `Diferença moderada de cobertura de escopo (${coverageDeltaPercent}%) dentro da tolerância máxima de 30%.`
    );
  }

  if (
    candidateA.evidenceConfidence === 'LOW' ||
    candidateB.evidenceConfidence === 'LOW'
  ) {
    return {
      comparable: false,
      status: 'INCONCLUSIVE',
      comparisonModality: modality,
      comparabilityClassification: 'NOT_COMPARABLE',
      reasons: [
        ...reasons,
        'At least one candidate has LOW evidence confidence.',
      ],
      qualifications,
      coverageDeltaPercent,
    };
  }

  if (
    candidateA.evidenceConfidence === 'MEDIUM' ||
    candidateB.evidenceConfidence === 'MEDIUM'
  ) {
    qualifications.push('Pelo menos um candidato possui confiança de evidência MEDIUM.');
  }

  if (reasons.length > 0) {
    return {
      comparable: false,
      status: 'INCOMPATIBLE_SCOPE',
      comparisonModality: modality,
      comparabilityClassification: 'NOT_COMPARABLE',
      reasons,
      qualifications,
      coverageDeltaPercent,
    };
  }

  const comparabilityClassification: ComparabilityClassification =
    modality === 'CROSS_TOOL' || qualifications.length > 0
      ? 'QUALIFIED_COMPARISON'
      : 'STRICTLY_COMPARABLE';

  return {
    comparable: true,
    status: 'COMPATIBLE',
    comparisonModality: modality,
    comparabilityClassification,
    reasons: [],
    qualifications,
    coverageDeltaPercent,
  };
}
