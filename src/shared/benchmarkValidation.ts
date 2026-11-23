/**
 * WinHood Canonical Benchmark Validation & Score Classification (Browser-Safe)
 *
 * Single canonical validation implementation shared between frontend wizard
 * and backend scoring/orchestration engines. Guarantees identical weight sum
 * validation, experimental equivalence verification, and score scale mapping
 * across browser and Node.js runtimes with zero Node-only dependencies.
 */

import type { BenchmarkCategoryKey, BenchmarkProfileConfig } from '../types/benchmark';
import { ALL_BENCHMARK_CATEGORIES } from './benchmarkCategories';

export interface WeightValidationResult {
  valid: boolean;
  totalWeight: number;
  errors: string[];
}

export interface EquivalenceValidationResult {
  equivalent: boolean;
  reasons: string[];
}

export function validateCategoryWeights(
  weights: Record<BenchmarkCategoryKey, number>,
  enabledCategories?: BenchmarkCategoryKey[]
): WeightValidationResult {
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
): EquivalenceValidationResult {
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
