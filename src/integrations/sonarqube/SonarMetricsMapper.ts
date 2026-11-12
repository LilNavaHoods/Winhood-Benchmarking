import type { SonarMeasuresRecord } from '../../types/benchmark';

/**
 * SonarMetricsMapper (Seção 5, 6.1, 6.2 e 6.3)
 * Normaliza as métricas retornadas pela Web API (/api/measures/component).
 * IMPORTANTE (Seção 6.3): Não afirma que o SonarQube executou testes unitários;
 * identifica explicitamente se a cobertura provém de relatórios reais importados
 * de frameworks de teste (LCOV, JaCoCo, Cobertura) ou se não foi fornecida.
 */
export class SonarMetricsMapper {
  public static mapNumericToRating(val?: string | number): 'A' | 'B' | 'C' | 'D' | 'E' {
    const n = typeof val === 'number' ? val : Number.parseFloat(val || '1');
    if (n <= 1.0) return 'A';
    if (n <= 2.0) return 'B';
    if (n <= 3.0) return 'C';
    if (n <= 4.0) return 'D';
    return 'E';
  }

  public static mapMeasuresPayload(params: {
    analysisId: string;
    projectKey: string;
    softwareId: string;
    softwareName: string;
    commitHash: string;
    rawMeasures: Array<{ metric: string; value?: string; period?: { value?: string } }>;
    rawApiResponseHash: string;
    coverageReportSource?: string;
  }): SonarMeasuresRecord {
    const map = new Map<string, { value?: string; periodValue?: string }>();
    for (const m of params.rawMeasures) {
      map.set(m.metric, { value: m.value, periodValue: m.period?.value });
    }

    const getInt = (key: string, fallback = 0): number => {
      const v = map.get(key)?.value;
      const parsed = Number.parseInt(v || '', 10);
      return Number.isNaN(parsed) ? fallback : parsed;
    };

    const getFloat = (key: string): number | null => {
      const v = map.get(key)?.value ?? map.get(key)?.periodValue;
      if (v === undefined) return null;
      const parsed = Number.parseFloat(v);
      return Number.isNaN(parsed) ? null : Math.round(parsed * 100) / 100;
    };

    const coverageVal = getFloat('coverage');
    const newCoverageVal = getFloat('new_coverage');

    return {
      id: `smeas-${params.analysisId}`,
      analysisId: params.analysisId,
      projectKey: params.projectKey,
      softwareId: params.softwareId,
      softwareName: params.softwareName,
      commitHash: params.commitHash,
      measuredAt: new Date().toISOString(),
      metrics: {
        bugs: getInt('bugs', 0),
        vulnerabilities: getInt('vulnerabilities', 0),
        securityHotspots: getInt('security_hotspots', 0),
        securityHotspotsReviewedPercent: getFloat('security_hotspots_reviewed') ?? 0,
        codeSmells: getInt('code_smells', 0),
        cyclomaticComplexity: getInt('complexity', 0),
        cognitiveComplexity: getInt('cognitive_complexity', 0),
        duplicatedLinesDensityPercent: getFloat('duplicated_lines_density') ?? 0,
        duplicatedBlocks: getInt('duplicated_blocks', 0),
        duplicatedLines: getInt('duplicated_lines', 0),
        ncloc: getInt('ncloc', 0),
        technicalDebtMinutes: getInt('sqale_index', 0),
        maintainabilityRating: SonarMetricsMapper.mapNumericToRating(
          map.get('sqale_rating')?.value
        ),
        reliabilityRating: SonarMetricsMapper.mapNumericToRating(
          map.get('reliability_rating')?.value
        ),
        securityRating: SonarMetricsMapper.mapNumericToRating(
          map.get('security_rating')?.value
        ),
        coveragePercent: coverageVal,
        linesToCover: getInt('lines_to_cover', 0),
        uncoveredLines: getInt('uncovered_lines', 0),
        conditionsToCover: getInt('conditions_to_cover', 0),
        newCodeCoveragePercent: newCoverageVal,
        coverageReportSource:
          params.coverageReportSource ||
          (coverageVal !== null
            ? 'Relatório de cobertura importado do framework de testes (LCOV / JUnit / Cobertura) — O SonarQube não executa testes unitários diretamente.'
            : 'Nenhum relatório de cobertura importado pelo framework de testes nesta execução.'),
      },
      rawApiResponseHash: params.rawApiResponseHash,
    };
  }

  /**
   * Calcula a pontuação nativa do SonarQube (0.00 a 5.00) exclusivamente a partir
   * dos ratings oficiais A-E (Reliability, Security, Maintainability) obtidos da API.
   */
  public static computeNativeSonarScoreFromRatings(
    metrics: SonarMeasuresRecord['metrics']
  ): number {
    const ratingToFive = (r: 'A' | 'B' | 'C' | 'D' | 'E'): number => {
      switch (r) {
        case 'A':
          return 5.0;
        case 'B':
          return 4.0;
        case 'C':
          return 3.0;
        case 'D':
          return 2.0;
        case 'E':
        default:
          return 1.0;
      }
    };

    const rel = ratingToFive(metrics.reliabilityRating);
    const sec = ratingToFive(metrics.securityRating);
    const maint = ratingToFive(metrics.maintainabilityRating);
    const dupPenalty = Math.min(1.0, metrics.duplicatedLinesDensityPercent / 25);

    const raw = rel * 0.35 + sec * 0.4 + maint * 0.25 - dupPenalty;
    return Math.max(0, Math.min(5, Math.round(raw * 100) / 100));
  }
}
