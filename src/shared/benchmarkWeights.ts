/**
 * WinHood Canonical Benchmark Weight Normalization & Validation (Browser-Safe)
 *
 * Single canonical mathematical implementation shared between frontend wizard
 * and backend scoring engine. Guarantees identical weight math and experimental
 * equivalence validation across client and server without Node.js dependencies.
 */

import type { BenchmarkCategoryKey } from '../types/benchmark';
import { ALL_BENCHMARK_CATEGORIES, DEFAULT_CATEGORY_WEIGHTS } from './benchmarkCategories';

export {
  validateCategoryWeights,
  validateEquivalenceConditions,
  classifyScoreScale,
  type WeightValidationResult,
  type EquivalenceValidationResult,
} from './benchmarkValidation';

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
      const candidate = weights[key];
      const w =
        typeof candidate === 'number' && Number.isFinite(candidate)
          ? candidate
          : DEFAULT_CATEGORY_WEIGHTS[key] ?? 0;
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
      const candidate = weights[key];
      const rawWeight =
        typeof candidate === 'number' && Number.isFinite(candidate)
          ? candidate
          : DEFAULT_CATEGORY_WEIGHTS[key] ?? 0;
      const w = Math.max(0, rawWeight);
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
