export interface EvidenceConfidenceInputs {
  scopeCoverageRatio: number; // [0, 1]
  astDepthRatio: number; // [0, 1]
  measuredDimensionsRatio: number; // [0, 1]
  executionDeterminismRatio: number; // [0, 1]
  cryptographicSignatureValid: boolean;
}

export interface EvidenceConfidenceEvaluation {
  score: number; // 0..100
  level: 'HIGH' | 'MEDIUM' | 'LOW';
  cryptographicSignatureValid: boolean;
}

/**
 * Implements the formal mathematical model documented in docs/CONFIDENCE_MODEL.md.
 */
export function evaluateEvidenceConfidence(
  input: EvidenceConfidenceInputs
): EvidenceConfidenceEvaluation {
  const cScope = Math.max(0, Math.min(1, input.scopeCoverageRatio));
  const dAst = Math.max(0, Math.min(1, input.astDepthRatio));
  const mDim = Math.max(0, Math.min(1, input.measuredDimensionsRatio));
  const rDet = Math.max(0, Math.min(1, input.executionDeterminismRatio));

  if (!input.cryptographicSignatureValid) {
    const capped = Math.min(30, Math.round(100 * (0.4 * cScope + 0.2 * mDim)));
    return {
      score: capped,
      level: 'LOW',
      cryptographicSignatureValid: false,
    };
  }

  const score = Math.round(
    100 * (0.4 * cScope + 0.25 * dAst + 0.2 * mDim + 0.15 * rDet)
  );

  const level: 'HIGH' | 'MEDIUM' | 'LOW' =
    score >= 80 && cScope >= 0.85
      ? 'HIGH'
      : score >= 50 && cScope >= 0.5
        ? 'MEDIUM'
        : 'LOW';

  return {
    score,
    level,
    cryptographicSignatureValid: true,
  };
}
