export interface DimensionMeasurement {
  dimensionId: string;
  weight: number;
  score: number | null;
  state: 'MEASURED' | 'STATIC_DERIVED' | 'NOT_MEASURED' | 'INCONCLUSIVE';
}

export interface NormalizedScoreResult {
  technicalScore: number | null;
  eligibleDimensionsCount: number;
  excludedNotMeasuredCount: number;
  killSwitchTriggered: boolean;
  normalizedWeights: Record<string, number>;
}

/**
 * Deterministic MQR scoring engine that never penalizes or rewards NOT_MEASURED
 * dimensions, renormalizes weights strictly across measured dimensions, and
 * enforces critical security kill-switch caps.
 */
export function computeDeterministicMqrScore(params: {
  dimensions: DimensionMeasurement[];
  criticalConfirmedFindings: number;
  secretsExposed: number;
}): NormalizedScoreResult {
  const valid = params.dimensions.filter(
    (d) =>
      (d.state === 'MEASURED' || d.state === 'STATIC_DERIVED') &&
      d.score !== null &&
      d.weight > 0
  );
  const excludedNotMeasuredCount = params.dimensions.length - valid.length;

  if (valid.length === 0) {
    return {
      technicalScore: null,
      eligibleDimensionsCount: 0,
      excludedNotMeasuredCount,
      killSwitchTriggered: false,
      normalizedWeights: {},
    };
  }

  const totalWeight = valid.reduce((acc, d) => acc + d.weight, 0);
  const normalizedWeights: Record<string, number> = {};
  let weightedSum = 0;

  for (const d of valid) {
    const normW = d.weight / totalWeight;
    normalizedWeights[d.dimensionId] = Number(normW.toFixed(4));
    const clampedScore = Math.max(0, Math.min(5, d.score as number));
    weightedSum += clampedScore * normW;
  }

  const killSwitchTriggered =
    params.criticalConfirmedFindings > 0 || params.secretsExposed > 0;
  const finalScore = killSwitchTriggered
    ? Math.min(2.2, weightedSum)
    : weightedSum;

  return {
    technicalScore: Number(finalScore.toFixed(2)),
    eligibleDimensionsCount: valid.length,
    excludedNotMeasuredCount,
    killSwitchTriggered,
    normalizedWeights,
  };
}

/**
 * Mitigates size bias by normalizing non-critical maintainability findings per KLOC.
 */
export function computeSizeNormalizedMaintainabilityScore(params: {
  nonCriticalFindingsCount: number;
  eligibleLinesOfCode: number;
}): number {
  const kloc = Math.max(0.5, params.eligibleLinesOfCode / 1000);
  const densityPerKloc = params.nonCriticalFindingsCount / kloc;
  const penalty = Math.min(4.0, Math.log1p(densityPerKloc) * 0.85);
  return Number(Math.max(1.0, 5.0 - penalty).toFixed(2));
}
