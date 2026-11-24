import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeDeterministicMqrScore,
  computeSizeNormalizedMaintainabilityScore,
} from './index';

test('computeDeterministicMqrScore handles empty, NOT_APPLICABLE, zero-weight, and all-unmeasured dimensions without fabricating scores', () => {
  // 1. Empty dimensions list -> applicableTotalWeight === 0 branch (covered!)
  const emptyRes = computeDeterministicMqrScore({
    dimensions: [],
    criticalConfirmedFindings: 0,
    secretsExposed: 0,
  });
  assert.equal(emptyRes.technicalScore, null);
  assert.equal(emptyRes.eligibleDimensionsCount, 0);
  assert.equal(emptyRes.excludedNotMeasuredCount, 0);
  assert.equal(emptyRes.excludedUnavailableCount, 0);
  assert.equal(emptyRes.measuredCoveragePercent, 0);
  assert.equal(emptyRes.renormalizationApplied, false);
  assert.equal(emptyRes.killSwitchTriggered, false);
  assert.deepEqual(emptyRes.normalizedWeights, {});

  // 2. Only NOT_APPLICABLE or zero-weight dimensions -> applicableTotalWeight === 0 branch
  const notApplicableRes = computeDeterministicMqrScore({
    dimensions: [
      { dimensionId: 'privacy', weight: 20, score: 4.5, state: 'NOT_APPLICABLE' },
      { dimensionId: 'documentation', weight: 0, score: 5.0, state: 'MEASURED' },
    ],
    criticalConfirmedFindings: 2,
    secretsExposed: 1,
  });
  assert.equal(notApplicableRes.technicalScore, null);
  assert.equal(notApplicableRes.measuredCoveragePercent, 0);
  assert.equal(notApplicableRes.eligibleDimensionsCount, 0);
  assert.equal(notApplicableRes.killSwitchTriggered, false);

  // 3. Applicable dimensions exist, but all are NOT_MEASURED / UNAVAILABLE / INCONCLUSIVE / null score
  const allMissingRes = computeDeterministicMqrScore({
    dimensions: [
      { dimensionId: 'security', weight: 40, score: null, state: 'NOT_MEASURED' },
      { dimensionId: 'performance', weight: 30, score: null, state: 'UNAVAILABLE' },
      { dimensionId: 'reliability', weight: 30, score: null, state: 'INCONCLUSIVE' },
    ],
    criticalConfirmedFindings: 0,
    secretsExposed: 0,
  });
  assert.equal(allMissingRes.technicalScore, null);
  assert.equal(allMissingRes.eligibleDimensionsCount, 0);
  assert.equal(allMissingRes.excludedNotMeasuredCount, 3);
  assert.equal(allMissingRes.excludedUnavailableCount, 1);
  assert.equal(allMissingRes.measuredCoveragePercent, 0);
  assert.equal(allMissingRes.renormalizationApplied, false);
});

test('computeDeterministicMqrScore renormalizes weights across MEASURED, STATIC_DERIVED, and IMPORTED states and clamps out-of-range scores', () => {
  const res = computeDeterministicMqrScore({
    dimensions: [
      { dimensionId: 'security', weight: 40, score: 6.5, state: 'MEASURED' }, // clamped to 5.0
      { dimensionId: 'code_quality', weight: 20, score: -1.0, state: 'STATIC_DERIVED' }, // clamped to 0.0
      { dimensionId: 'architecture', weight: 20, score: 4.0, state: 'IMPORTED' },
      { dimensionId: 'performance', weight: 20, score: null, state: 'UNAVAILABLE' },
      { dimensionId: 'usability', weight: 10, score: 5.0, state: 'NOT_APPLICABLE' },
    ],
    criticalConfirmedFindings: 0,
    secretsExposed: 0,
  });

  // Valid weights sum = 40 + 20 + 20 = 80; applicable weights sum = 100 -> measuredCoveragePercent = 80.0
  // Weighted sum = (5.0 * 0.5) + (0.0 * 0.25) + (4.0 * 0.25) = 2.5 + 0 + 1.0 = 3.5
  assert.equal(res.technicalScore, 3.5);
  assert.equal(res.eligibleDimensionsCount, 3);
  assert.equal(res.excludedNotMeasuredCount, 1);
  assert.equal(res.excludedUnavailableCount, 1);
  assert.equal(res.measuredCoveragePercent, 80);
  assert.equal(res.renormalizationApplied, true);
  assert.equal(res.killSwitchTriggered, false);
  assert.equal(res.normalizedWeights.security, 0.5);
  assert.equal(res.normalizedWeights.code_quality, 0.25);
  assert.equal(res.normalizedWeights.architecture, 0.25);
});

test('computeDeterministicMqrScore applies kill-switch cap (2.20) for criticalConfirmedFindings or secretsExposed without altering lower scores', () => {
  const cappedByCritical = computeDeterministicMqrScore({
    dimensions: [{ dimensionId: 'security', weight: 100, score: 4.8, state: 'MEASURED' }],
    criticalConfirmedFindings: 1,
    secretsExposed: 0,
  });
  assert.equal(cappedByCritical.killSwitchTriggered, true);
  assert.equal(cappedByCritical.technicalScore, 2.2);
  assert.equal(cappedByCritical.renormalizationApplied, false);

  const cappedBySecret = computeDeterministicMqrScore({
    dimensions: [{ dimensionId: 'security', weight: 100, score: 4.5, state: 'MEASURED' }],
    criticalConfirmedFindings: 0,
    secretsExposed: 2,
  });
  assert.equal(cappedBySecret.killSwitchTriggered, true);
  assert.equal(cappedBySecret.technicalScore, 2.2);

  const alreadyLow = computeDeterministicMqrScore({
    dimensions: [{ dimensionId: 'security', weight: 100, score: 1.4, state: 'MEASURED' }],
    criticalConfirmedFindings: 1,
    secretsExposed: 1,
  });
  assert.equal(alreadyLow.killSwitchTriggered, true);
  assert.equal(alreadyLow.technicalScore, 1.4);
});

test('computeSizeNormalizedMaintainabilityScore enforces KLOC floor (0.5), log penalty scaling, and [1.0, 5.0] bounds', () => {
  assert.equal(
    computeSizeNormalizedMaintainabilityScore({
      nonCriticalFindingsCount: 0,
      eligibleLinesOfCode: 100,
    }),
    5
  );

  const mediumScore = computeSizeNormalizedMaintainabilityScore({
    nonCriticalFindingsCount: 10,
    eligibleLinesOfCode: 2000,
  });
  assert.ok(mediumScore > 1.0 && mediumScore < 5.0, `Expected bounded intermediate score, got ${mediumScore}`);

  const flooredScore = computeSizeNormalizedMaintainabilityScore({
    nonCriticalFindingsCount: 10_000,
    eligibleLinesOfCode: 50,
  });
  assert.equal(flooredScore, 1);
});
