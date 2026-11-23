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

export interface WeightRenormalizationSummary {
  originalWeights: Record<BenchmarkCategoryKey, number>;
  effectiveWeights: Record<BenchmarkCategoryKey, number>;
  assessedCategories: BenchmarkCategoryKey[];
  excludedCategories: BenchmarkCategoryKey[];
  totalEnabledWeightSum: number;
  measuredWeightSum: number;
  redistributedWeightPercent: number;
  measuredCoveragePercent: number;
  applied: boolean;
  explanation: string;
}

/**
 * Excludes NOT_MEASURED / UNAVAILABLE / INCONCLUSIVE categories from the weighted average
 * and explicitly renormalizes remaining measured category weights to 100%, returning
 * the exact Effective Measurement Coverage percentage (`measuredCoveragePercent`).
 */
export function computeRenormalizedCategoryWeights(
  weights: Partial<Record<BenchmarkCategoryKey, number>>,
  enabledCategories: BenchmarkCategoryKey[],
  assessedCategories: BenchmarkCategoryKey[]
): WeightRenormalizationSummary {
  const enabledList =
    enabledCategories.length > 0 ? enabledCategories : [...ALL_BENCHMARK_CATEGORIES];
  const originalWeights = normalizeEnabledCategoryWeights(weights, enabledList);
  const assessedSet = new Set<BenchmarkCategoryKey>(assessedCategories);
  const effectiveAssessed = enabledList.filter((k) => assessedSet.has(k));
  const excludedCategories = enabledList.filter((k) => !assessedSet.has(k));

  const totalEnabledWeightSum =
    Math.round(enabledList.reduce((acc, k) => acc + (originalWeights[k] ?? 0), 0) * 100) / 100;
  const measuredWeightSum =
    Math.round(effectiveAssessed.reduce((acc, k) => acc + (originalWeights[k] ?? 0), 0) * 100) / 100;
  const redistributedWeightPercent =
    Math.round(Math.max(0, totalEnabledWeightSum - measuredWeightSum) * 100) / 100;

  const measuredCoveragePercent =
    totalEnabledWeightSum > 0
      ? Math.round((measuredWeightSum / totalEnabledWeightSum) * 1000) / 10
      : 0;

  const effectiveWeights =
    effectiveAssessed.length > 0
      ? normalizeEnabledCategoryWeights(originalWeights, effectiveAssessed)
      : (Object.fromEntries(
          ALL_BENCHMARK_CATEGORIES.map((k) => [k, 0])
        ) as Record<BenchmarkCategoryKey, number>);

  const applied = excludedCategories.length > 0;
  const explanation =
    effectiveAssessed.length === 0
      ? `Nenhuma das ${enabledList.length} categoria(s) habilitada(s) possui medição válida (Cobertura de Medição Efetiva: 0%). Nenhuma nota foi fabricada.`
      : applied
        ? `${excludedCategories.length} categoria(s) não medida(s)/indisponível(is) [${excludedCategories.join(', ')}] (${redistributedWeightPercent.toFixed(1)}% do peso original) excluída(s) da média ponderada; os ${measuredWeightSum.toFixed(1)}% restantes foram renormalizados proporcionalmente para 100.0% (Cobertura de Medição Efetiva: ${measuredCoveragePercent.toFixed(1)}%).`
        : `100% do peso habilitado (${effectiveAssessed.length}/${enabledList.length} categorias) foi efetivamente medido; nenhuma renormalização necessária.`;

  return {
    originalWeights,
    effectiveWeights,
    assessedCategories: effectiveAssessed,
    excludedCategories,
    totalEnabledWeightSum,
    measuredWeightSum,
    redistributedWeightPercent,
    measuredCoveragePercent,
    applied,
    explanation,
  };
}

