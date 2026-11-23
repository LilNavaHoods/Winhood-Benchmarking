export interface DimensionMeasurement {
  dimensionId: string;
  weight: number;
  score: number | null;
  state: 'MEASURED' | 'STATIC_DERIVED' | 'IMPORTED' | 'NOT_MEASURED' | 'UNAVAILABLE' | 'NOT_APPLICABLE' | 'INCONCLUSIVE';
}

export interface NormalizedScoreResult {
  technicalScore: number | null;
  eligibleDimensionsCount: number;
  excludedNotMeasuredCount: number;
  excludedUnavailableCount: number;
  measuredCoveragePercent: number;
  renormalizationApplied: boolean;
  killSwitchTriggered: boolean;
  normalizedWeights: Record<string, number>;
}

/**
 * Deterministic MQR scoring engine that never penalizes or rewards NOT_MEASURED / UNAVAILABLE
 * dimensions, renormalizes weights strictly across measured dimensions, exposes
 * Effective Measurement Coverage (`measuredCoveragePercent`), and enforces critical security kill-switch caps.
 */
export function computeDeterministicMqrScore(params: {
  dimensions: DimensionMeasurement[];
  criticalConfirmedFindings: number;
  secretsExposed: number;
}): NormalizedScoreResult {
  const applicable = params.dimensions.filter(
    (d) => d.state !== 'NOT_APPLICABLE' && d.weight > 0
  );
  const valid = applicable.filter(
    (d) =>
      (d.state === 'MEASURED' || d.state === 'STATIC_DERIVED' || d.state === 'IMPORTED') &&
      d.score !== null &&
      d.weight > 0
  );
  const excludedNotMeasuredCount = applicable.length - valid.length;
  const excludedUnavailableCount = applicable.filter((d) => d.state === 'UNAVAILABLE').length;
  const applicableTotalWeight = applicable.reduce((acc, d) => acc + d.weight, 0);
  const totalWeight = valid.reduce((acc, d) => acc + d.weight, 0);
  const measuredCoveragePercent =
    applicableTotalWeight > 0
      ? Number(((totalWeight / applicableTotalWeight) * 100).toFixed(1))
      : 0;

  if (valid.length === 0) {
    return {
      technicalScore: null,
      eligibleDimensionsCount: 0,
      excludedNotMeasuredCount,
      excludedUnavailableCount,
      measuredCoveragePercent: 0,
      renormalizationApplied: false,
      killSwitchTriggered: false,
      normalizedWeights: {},
    };
  }

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
    excludedUnavailableCount,
    measuredCoveragePercent,
    renormalizationApplied: excludedNotMeasuredCount > 0,
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
