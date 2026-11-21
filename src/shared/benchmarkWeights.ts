/**
 * WinHood Canonical Benchmark Weight Normalization & Validation (Browser-Safe)
 *
 * Single canonical mathematical implementation shared between frontend wizard
 * and backend scoring engine. Guarantees identical weight math and experimental
 * equivalence validation across client and server without Node.js dependencies.
 */

import type { BenchmarkCategoryKey, BenchmarkProfileConfig } from '../types/benchmark';
import { ALL_BENCHMARK_CATEGORIES, DEFAULT_CATEGORY_WEIGHTS } from './benchmarkCategories';

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

export function validateCategoryWeights(
  weights: Record<BenchmarkCategoryKey, number>,
  enabledCategories?: BenchmarkCategoryKey[]
): {
  valid: boolean;
  totalWeight: number;
  errors: string[];
} {
  const errors: string[] = [];
  const activeSet =
    enabledCategories && enabledCategories.length > 0
      ? new Set<BenchmarkCategoryKey>(enabledCategories)
      : null;
  let sum = 0;

  for (const key of ALL_BENCHMARK_CATEGORIES) {
    if (activeSet && !activeSet.has(key)) {
      continue;
    }
    const val = weights[key];
    if (typeof val !== 'number' || !Number.isFinite(val)) {
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
  env: BenchmarkProfileConfig['equivalenceEnvironment'] | null | undefined
): {
  equivalent: boolean;
  reasons: string[];
} {
  const reasons: string[] = [];
  if (!env) {
    return { equivalent: false, reasons: ['Configuração de ambiente experimental ausente.'] };
  }
  if (
    typeof env.cpuCoresLimit !== 'number' ||
    !Number.isFinite(env.cpuCoresLimit) ||
    env.cpuCoresLimit <= 0 ||
    env.cpuCoresLimit > 64
  ) {
    reasons.push('Limite de CPU inválido para equivalência experimental (deve ser 1–64 vCPUs).');
  }
  if (
    typeof env.memoryMbLimit !== 'number' ||
    !Number.isFinite(env.memoryMbLimit) ||
    env.memoryMbLimit < 128 ||
    env.memoryMbLimit > 65536
  ) {
    reasons.push('Limite de RAM inválido para equivalência experimental (128 MB – 65536 MB).');
  }
  if (!env.osTarget || env.osTarget.trim().length < 2) {
    reasons.push('Sistema operacional alvo não especificado para o worker de benchmark.');
  }
  if (
    typeof env.workloadConcurrency !== 'number' ||
    !Number.isFinite(env.workloadConcurrency) ||
    env.workloadConcurrency <= 0 ||
    env.workloadConcurrency > 5000
  ) {
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
