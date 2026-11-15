export interface CandidateScopeDescriptor {
  softwareId: string;
  engineVersion: string;
  ruleCatalogSha256: string;
  scopeCoveragePercent: number;
  evidenceConfidence: 'HIGH' | 'MEDIUM' | 'LOW';
  functionalCategory: string;
}

export interface ComparabilityValidationResult {
  comparable: boolean;
  status: 'COMPATIBLE' | 'INCOMPATIBLE_SCOPE' | 'INCONCLUSIVE';
  reasons: string[];
  coverageDeltaPercent: number;
}

/**
 * Validates A/B comparability premises documented in docs/LIMITATIONS.md.
 * Never allows a winner declaration when scopes or rule catalogs are incompatible.
 */
export function validatePairComparability(
  candidateA: CandidateScopeDescriptor,
  candidateB: CandidateScopeDescriptor
): ComparabilityValidationResult {
  const reasons: string[] = [];
  const coverageDeltaPercent = Math.abs(
    candidateA.scopeCoveragePercent - candidateB.scopeCoveragePercent
  );

  if (candidateA.engineVersion !== candidateB.engineVersion) {
    reasons.push(
      `Engine version mismatch: ${candidateA.engineVersion} vs ${candidateB.engineVersion}`
    );
  }
  if (candidateA.ruleCatalogSha256 !== candidateB.ruleCatalogSha256) {
    reasons.push('Rule catalog SHA-256 digest mismatch between candidates.');
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
  }
  if (
    candidateA.evidenceConfidence === 'LOW' ||
    candidateB.evidenceConfidence === 'LOW'
  ) {
    return {
      comparable: false,
      status: 'INCONCLUSIVE',
      reasons: [
        ...reasons,
        'At least one candidate has LOW evidence confidence.',
      ],
      coverageDeltaPercent,
    };
  }

  if (reasons.length > 0) {
    return {
      comparable: false,
      status: 'INCOMPATIBLE_SCOPE',
      reasons,
      coverageDeltaPercent,
    };
  }

  return {
    comparable: true,
    status: 'COMPATIBLE',
    reasons: [],
    coverageDeltaPercent,
  };
}
