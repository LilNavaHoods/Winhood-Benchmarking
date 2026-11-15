import type {
  SonarMeasuresRecord,
  SonarNewCodeMetrics,
  SonarNormalizedMetricItem,
  SonarOverallCodeMetrics,
  SonarQualityModelMode,
  SonarRatingGrade,
  SonarStandardMeasurementState,
} from '../../types/benchmark';

interface MetricMetaCatalogEntry {
  originalName: string;
  normalizedName: string;
  qualityModel: 'MQR' | 'STANDARD';
  unit: SonarNormalizedMetricItem['unit'];
  scope: 'OVERALL_CODE' | 'NEW_CODE';
}

const METRIC_CATALOG: Record<string, MetricMetaCatalogEntry> = {
  // Traditional / Standard Experience Metrics (Overall Code)
  bugs: {
    originalName: 'Bugs',
    normalizedName: 'reliability_bugs_overall',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'OVERALL_CODE',
  },
  vulnerabilities: {
    originalName: 'Vulnerabilities',
    normalizedName: 'security_vulnerabilities_overall',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'OVERALL_CODE',
  },
  code_smells: {
    originalName: 'Code Smells',
    normalizedName: 'maintainability_code_smells_overall',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'OVERALL_CODE',
  },
  security_hotspots: {
    originalName: 'Security Hotspots',
    normalizedName: 'security_hotspots_overall',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'OVERALL_CODE',
  },
  security_hotspots_reviewed: {
    originalName: 'Security Hotspots Reviewed (%)',
    normalizedName: 'security_hotspots_reviewed_pct_overall',
    qualityModel: 'STANDARD',
    unit: 'PERCENT',
    scope: 'OVERALL_CODE',
  },
  reliability_rating: {
    originalName: 'Reliability Rating',
    normalizedName: 'reliability_rating_overall',
    qualityModel: 'STANDARD',
    unit: 'RATING',
    scope: 'OVERALL_CODE',
  },
  security_rating: {
    originalName: 'Security Rating',
    normalizedName: 'security_rating_overall',
    qualityModel: 'STANDARD',
    unit: 'RATING',
    scope: 'OVERALL_CODE',
  },
  sqale_rating: {
    originalName: 'Maintainability Rating',
    normalizedName: 'maintainability_rating_overall',
    qualityModel: 'STANDARD',
    unit: 'RATING',
    scope: 'OVERALL_CODE',
  },
  security_review_rating: {
    originalName: 'Security Review Rating',
    normalizedName: 'security_review_rating_overall',
    qualityModel: 'STANDARD',
    unit: 'RATING',
    scope: 'OVERALL_CODE',
  },
  sqale_index: {
    originalName: 'Technical Debt (Minutes)',
    normalizedName: 'technical_debt_minutes_overall',
    qualityModel: 'STANDARD',
    unit: 'MINUTES',
    scope: 'OVERALL_CODE',
  },
  coverage: {
    originalName: 'Coverage (%)',
    normalizedName: 'coverage_pct_overall',
    qualityModel: 'STANDARD',
    unit: 'PERCENT',
    scope: 'OVERALL_CODE',
  },
  line_coverage: {
    originalName: 'Line Coverage (%)',
    normalizedName: 'line_coverage_pct_overall',
    qualityModel: 'STANDARD',
    unit: 'PERCENT',
    scope: 'OVERALL_CODE',
  },
  branch_coverage: {
    originalName: 'Branch / Condition Coverage (%)',
    normalizedName: 'branch_coverage_pct_overall',
    qualityModel: 'STANDARD',
    unit: 'PERCENT',
    scope: 'OVERALL_CODE',
  },
  lines_to_cover: {
    originalName: 'Lines to Cover',
    normalizedName: 'lines_to_cover_overall',
    qualityModel: 'STANDARD',
    unit: 'LINES',
    scope: 'OVERALL_CODE',
  },
  uncovered_lines: {
    originalName: 'Uncovered Lines',
    normalizedName: 'uncovered_lines_overall',
    qualityModel: 'STANDARD',
    unit: 'LINES',
    scope: 'OVERALL_CODE',
  },
  conditions_to_cover: {
    originalName: 'Conditions to Cover',
    normalizedName: 'conditions_to_cover_overall',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'OVERALL_CODE',
  },
  uncovered_conditions: {
    originalName: 'Uncovered Conditions',
    normalizedName: 'uncovered_conditions_overall',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'OVERALL_CODE',
  },
  duplicated_lines_density: {
    originalName: 'Duplicated Lines (%)',
    normalizedName: 'duplicated_lines_density_pct_overall',
    qualityModel: 'STANDARD',
    unit: 'PERCENT',
    scope: 'OVERALL_CODE',
  },
  duplicated_lines: {
    originalName: 'Duplicated Lines',
    normalizedName: 'duplicated_lines_overall',
    qualityModel: 'STANDARD',
    unit: 'LINES',
    scope: 'OVERALL_CODE',
  },
  duplicated_blocks: {
    originalName: 'Duplicated Blocks',
    normalizedName: 'duplicated_blocks_overall',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'OVERALL_CODE',
  },
  complexity: {
    originalName: 'Cyclomatic Complexity',
    normalizedName: 'cyclomatic_complexity_overall',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'OVERALL_CODE',
  },
  cognitive_complexity: {
    originalName: 'Cognitive Complexity',
    normalizedName: 'cognitive_complexity_overall',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'OVERALL_CODE',
  },
  ncloc: {
    originalName: 'Lines of Code (NCLOC)',
    normalizedName: 'ncloc_overall',
    qualityModel: 'STANDARD',
    unit: 'LINES',
    scope: 'OVERALL_CODE',
  },
  // MQR (Multi-Quality Rule) Software Quality Metrics
  software_quality_reliability_issues: {
    originalName: 'Software Quality Reliability Issues',
    normalizedName: 'mqr_reliability_issues_overall',
    qualityModel: 'MQR',
    unit: 'COUNT',
    scope: 'OVERALL_CODE',
  },
  software_quality_security_issues: {
    originalName: 'Software Quality Security Issues',
    normalizedName: 'mqr_security_issues_overall',
    qualityModel: 'MQR',
    unit: 'COUNT',
    scope: 'OVERALL_CODE',
  },
  software_quality_maintainability_issues: {
    originalName: 'Software Quality Maintainability Issues',
    normalizedName: 'mqr_maintainability_issues_overall',
    qualityModel: 'MQR',
    unit: 'COUNT',
    scope: 'OVERALL_CODE',
  },
  software_quality_reliability_rating: {
    originalName: 'Software Quality Reliability Rating',
    normalizedName: 'mqr_reliability_rating_overall',
    qualityModel: 'MQR',
    unit: 'RATING',
    scope: 'OVERALL_CODE',
  },
  software_quality_security_rating: {
    originalName: 'Software Quality Security Rating',
    normalizedName: 'mqr_security_rating_overall',
    qualityModel: 'MQR',
    unit: 'RATING',
    scope: 'OVERALL_CODE',
  },
  software_quality_maintainability_rating: {
    originalName: 'Software Quality Maintainability Rating',
    normalizedName: 'mqr_maintainability_rating_overall',
    qualityModel: 'MQR',
    unit: 'RATING',
    scope: 'OVERALL_CODE',
  },
  // New Code Metrics
  new_bugs: {
    originalName: 'New Bugs',
    normalizedName: 'reliability_bugs_new_code',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'NEW_CODE',
  },
  new_vulnerabilities: {
    originalName: 'New Vulnerabilities',
    normalizedName: 'security_vulnerabilities_new_code',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'NEW_CODE',
  },
  new_code_smells: {
    originalName: 'New Code Smells',
    normalizedName: 'maintainability_code_smells_new_code',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'NEW_CODE',
  },
  new_security_hotspots: {
    originalName: 'New Security Hotspots',
    normalizedName: 'security_hotspots_new_code',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'NEW_CODE',
  },
  new_security_hotspots_reviewed: {
    originalName: 'New Security Hotspots Reviewed (%)',
    normalizedName: 'security_hotspots_reviewed_pct_new_code',
    qualityModel: 'STANDARD',
    unit: 'PERCENT',
    scope: 'NEW_CODE',
  },
  new_reliability_rating: {
    originalName: 'New Reliability Rating',
    normalizedName: 'reliability_rating_new_code',
    qualityModel: 'STANDARD',
    unit: 'RATING',
    scope: 'NEW_CODE',
  },
  new_security_rating: {
    originalName: 'New Security Rating',
    normalizedName: 'security_rating_new_code',
    qualityModel: 'STANDARD',
    unit: 'RATING',
    scope: 'NEW_CODE',
  },
  new_maintainability_rating: {
    originalName: 'New Maintainability Rating',
    normalizedName: 'maintainability_rating_new_code',
    qualityModel: 'STANDARD',
    unit: 'RATING',
    scope: 'NEW_CODE',
  },
  new_coverage: {
    originalName: 'New Code Coverage (%)',
    normalizedName: 'coverage_pct_new_code',
    qualityModel: 'STANDARD',
    unit: 'PERCENT',
    scope: 'NEW_CODE',
  },
  new_lines_to_cover: {
    originalName: 'New Lines to Cover',
    normalizedName: 'lines_to_cover_new_code',
    qualityModel: 'STANDARD',
    unit: 'LINES',
    scope: 'NEW_CODE',
  },
  new_uncovered_lines: {
    originalName: 'New Uncovered Lines',
    normalizedName: 'uncovered_lines_new_code',
    qualityModel: 'STANDARD',
    unit: 'LINES',
    scope: 'NEW_CODE',
  },
  new_conditions_to_cover: {
    originalName: 'New Conditions to Cover',
    normalizedName: 'conditions_to_cover_new_code',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'NEW_CODE',
  },
  new_uncovered_conditions: {
    originalName: 'New Uncovered Conditions',
    normalizedName: 'uncovered_conditions_new_code',
    qualityModel: 'STANDARD',
    unit: 'COUNT',
    scope: 'NEW_CODE',
  },
  new_duplicated_lines_density: {
    originalName: 'New Duplicated Lines (%)',
    normalizedName: 'duplicated_lines_density_pct_new_code',
    qualityModel: 'STANDARD',
    unit: 'PERCENT',
    scope: 'NEW_CODE',
  },
  new_lines: {
    originalName: 'New Lines',
    normalizedName: 'new_lines_new_code',
    qualityModel: 'STANDARD',
    unit: 'LINES',
    scope: 'NEW_CODE',
  },
  new_technical_debt: {
    originalName: 'New Technical Debt (Minutes)',
    normalizedName: 'technical_debt_minutes_new_code',
    qualityModel: 'STANDARD',
    unit: 'MINUTES',
    scope: 'NEW_CODE',
  },
};

/**
 * SonarMetricsMapper (Seção 3.2, 3.3, 3.6 e 3.8)
 * - Elimina qualquer fallback "1" -> "A", "0" ou "100" quando uma métrica ou classificação está ausente.
 * - Registra zero exclusivamente quando a API retornar explicitamente zero ("0" ou "0.0").
 * - Separa Overall Code e New Code em estruturas independentes.
 * - Reconhece e preserva a origem de métricas do modelo tradicional (Standard Experience) e MQR (Software Quality).
 */
export class SonarMetricsMapper {
  /**
   * Converte classificação numérica do MqrBridge (1.0 a 5.0) ou literal ('A' a 'E')
   * de forma estrita: retorna null quando ausente ou fora do intervalo válido [1..5].
   * NUNCA converte ausência de informação em classificação 'A'.
   */
  public static mapNumericToRating(
    val?: string | number | null
  ): 'A' | 'B' | 'C' | 'D' | 'E' | null {
    if (val === undefined || val === null) {
      return null;
    }
    if (typeof val === 'string') {
      const trimmed = val.trim().toUpperCase();
      if (!trimmed) return null;
      if (
        trimmed === 'A' ||
        trimmed === 'B' ||
        trimmed === 'C' ||
        trimmed === 'D' ||
        trimmed === 'E'
      ) {
        return trimmed;
      }
    }
    const n = typeof val === 'number' ? val : Number.parseFloat(String(val).trim());
    if (Number.isNaN(n) || !Number.isFinite(n) || n < 1.0 || n > 5.0) {
      return null;
    }
    const rounded = Math.round(n);
    if (rounded === 1) return 'A';
    if (rounded === 2) return 'B';
    if (rounded === 3) return 'C';
    if (rounded === 4) return 'D';
    if (rounded === 5) return 'E';
    return null;
  }

  public static mapNumericToRatingOrNotMeasured(
    val?: string | number | null
  ): SonarRatingGrade {
    return SonarMetricsMapper.mapNumericToRating(val) ?? 'NOT_MEASURED';
  }

  public static parseStrictInt(raw?: string | number | null): number | null {
    if (raw === undefined || raw === null) return null;
    const str = String(raw).trim();
    if (!str || !/^-?\d+$/.test(str)) return null;
    const parsed = Number.parseInt(str, 10);
    return Number.isNaN(parsed) ? null : parsed;
  }

  public static parseStrictFloat(raw?: string | number | null): number | null {
    if (raw === undefined || raw === null) return null;
    const str = String(raw).trim();
    if (!str || !/^-?\d+(\.\d+)?$/.test(str)) return null;
    const parsed = Number.parseFloat(str);
    return Number.isNaN(parsed) || !Number.isFinite(parsed)
      ? null
      : Math.round(parsed * 100) / 100;
  }

  public static mapMeasuresPayload(params: {
    analysisId: string;
    projectKey: string;
    softwareId: string;
    softwareName: string;
    commitHash: string;
    rawMeasures: Array<{
      metric: string;
      value?: string;
      period?: { value?: string; index?: number; mode?: string; date?: string; parameter?: string };
      periods?: Array<{ value?: string; index?: number; mode?: string; date?: string; parameter?: string }>;
    }>;
    rawApiResponseHash: string;
    coverageReportSource?: string;
    sonarVersion?: string;
    apiError?: boolean;
    notComputed?: boolean;
    newCodePeriodInfo?: {
      mode?: string;
      parameter?: string;
      date?: string;
      scmLimitationNote?: string | null;
    };
  }): SonarMeasuresRecord {
    const sourceVersion = params.sonarVersion || 'MqrBridge Web API';
    const map = new Map<
      string,
      {
        value?: string;
        periodValue?: string;
        periodMode?: string;
        periodParam?: string;
        periodDate?: string;
      }
    >();

    for (const m of params.rawMeasures || []) {
      const p = m.period || (Array.isArray(m.periods) ? m.periods[0] : undefined);
      map.set(m.metric, {
        value: m.value,
        periodValue: p?.value,
        periodMode: p?.mode,
        periodParam: p?.parameter,
        periodDate: p?.date,
      });
    }

    const baseStateWhenMissing: SonarStandardMeasurementState = params.apiError
      ? 'API_ERROR'
      : params.notComputed
        ? 'NOT_COMPUTED'
        : 'NOT_MEASURED';

    const metricStates: Record<string, SonarStandardMeasurementState> = {};
    const normalizedMetrics: SonarNormalizedMetricItem[] = [];

    const resolveRaw = (key: string): string | undefined => {
      const entry = map.get(key);
      if (!entry) return undefined;
      if (key.startsWith('new_')) {
        return entry.periodValue !== undefined ? entry.periodValue : entry.value;
      }
      return entry.value !== undefined ? entry.value : entry.periodValue;
    };

    const getStrictInt = (key: string): number | null => {
      const raw = resolveRaw(key);
      if (raw === undefined) {
        metricStates[key] = baseStateWhenMissing;
        return null;
      }
      const val = SonarMetricsMapper.parseStrictInt(raw);
      metricStates[key] = val !== null ? 'MEASURED' : 'INCONCLUSIVE';
      return val;
    };

    const getStrictFloat = (key: string): number | null => {
      const raw = resolveRaw(key);
      if (raw === undefined) {
        metricStates[key] = baseStateWhenMissing;
        return null;
      }
      const val = SonarMetricsMapper.parseStrictFloat(raw);
      metricStates[key] = val !== null ? 'MEASURED' : 'INCONCLUSIVE';
      return val;
    };

    const getStrictRating = (key: string): 'A' | 'B' | 'C' | 'D' | 'E' | null => {
      const raw = resolveRaw(key);
      if (raw === undefined) {
        metricStates[key] = baseStateWhenMissing;
        return null;
      }
      const rating = SonarMetricsMapper.mapNumericToRating(raw);
      metricStates[key] = rating !== null ? 'MEASURED' : 'INCONCLUSIVE';
      return rating;
    };

    // Build normalized catalog items
    let hasMqr = false;
    let hasStandard = false;
    for (const [key, meta] of Object.entries(METRIC_CATALOG)) {
      const raw = resolveRaw(key);
      const isPresent = raw !== undefined;
      if (isPresent) {
        if (meta.qualityModel === 'MQR') hasMqr = true;
        else hasStandard = true;
      }
      const ratingVal =
        meta.unit === 'RATING' ? SonarMetricsMapper.mapNumericToRating(raw) : null;
      const numVal =
        meta.unit !== 'RATING' ? SonarMetricsMapper.parseStrictFloat(raw) : null;
      const availabilityState: SonarStandardMeasurementState = !isPresent
        ? baseStateWhenMissing
        : meta.unit === 'RATING'
          ? ratingVal !== null
            ? 'MEASURED'
            : 'INCONCLUSIVE'
          : numVal !== null
            ? 'MEASURED'
            : 'INCONCLUSIVE';

      metricStates[key] = availabilityState;
      normalizedMetrics.push({
        originalKey: key,
        originalName: meta.originalName,
        normalizedName: meta.normalizedName,
        qualityModel: meta.qualityModel,
        sourceVersion,
        rawValue: raw ?? null,
        numericValue: numVal,
        ratingValue: ratingVal,
        availabilityState,
        unit: meta.unit,
        scope: meta.scope,
      });
    }

    const qualityModel: SonarQualityModelMode =
      hasMqr && hasStandard
        ? 'HYBRID'
        : hasMqr
          ? 'MQR'
          : 'STANDARD_EXPERIENCE';

    // Overall Code metrics (preserve separation of MQR vs Standard, fallback to MQR rating only when standard is absent and MQR is present)
    const bugs = getStrictInt('bugs');
    const vulnerabilities = getStrictInt('vulnerabilities');
    const codeSmells = getStrictInt('code_smells');
    const securityHotspots = getStrictInt('security_hotspots');
    const securityHotspotsReviewedPercent = getStrictFloat('security_hotspots_reviewed');

    const stdReliabilityRating = getStrictRating('reliability_rating');
    const mqrReliabilityRating = getStrictRating('software_quality_reliability_rating');
    const reliabilityRating = stdReliabilityRating ?? mqrReliabilityRating;

    const stdSecurityRating = getStrictRating('security_rating');
    const mqrSecurityRating = getStrictRating('software_quality_security_rating');
    const securityRating = stdSecurityRating ?? mqrSecurityRating;

    const stdMaintainabilityRating = getStrictRating('sqale_rating');
    const mqrMaintainabilityRating = getStrictRating('software_quality_maintainability_rating');
    const maintainabilityRating = stdMaintainabilityRating ?? mqrMaintainabilityRating;

    const securityReviewRating = getStrictRating('security_review_rating');

    const coveragePercent = getStrictFloat('coverage');
    const lineCoveragePercent = getStrictFloat('line_coverage');
    const branchCoveragePercent = getStrictFloat('branch_coverage');
    const linesToCover = getStrictInt('lines_to_cover');
    const uncoveredLines = getStrictInt('uncovered_lines');
    const conditionsToCover = getStrictInt('conditions_to_cover');
    const uncoveredConditions = getStrictInt('uncovered_conditions');
    const coveredConditions =
      conditionsToCover !== null && uncoveredConditions !== null
        ? Math.max(0, conditionsToCover - uncoveredConditions)
        : null;
    const conditionCoveragePercent =
      branchCoveragePercent !== null
        ? branchCoveragePercent
        : conditionsToCover !== null &&
            conditionsToCover > 0 &&
            coveredConditions !== null
          ? Math.round((coveredConditions / conditionsToCover) * 10000) / 100
          : null;

    const duplicatedLinesDensityPercent = getStrictFloat('duplicated_lines_density');
    const duplicatedLines = getStrictInt('duplicated_lines');
    const duplicatedBlocks = getStrictInt('duplicated_blocks');
    const technicalDebtMinutes = getStrictInt('sqale_index');
    const cyclomaticComplexity = getStrictInt('complexity');
    const cognitiveComplexity = getStrictInt('cognitive_complexity');
    const ncloc = getStrictInt('ncloc');

    const overallCode: SonarOverallCodeMetrics = {
      bugs,
      vulnerabilities,
      codeSmells,
      securityHotspots,
      securityHotspotsReviewedPercent,
      reliabilityRating,
      securityRating,
      maintainabilityRating,
      securityReviewRating,
      coveragePercent,
      lineCoveragePercent,
      branchCoveragePercent,
      conditionCoveragePercent,
      linesToCover,
      uncoveredLines,
      conditionsToCover,
      uncoveredConditions,
      coveredConditions,
      duplicatedLinesDensityPercent,
      duplicatedLines,
      duplicatedBlocks,
      technicalDebtMinutes,
      cyclomaticComplexity,
      cognitiveComplexity,
      ncloc,
      softwareQualityReliabilityIssues: getStrictInt('software_quality_reliability_issues'),
      softwareQualitySecurityIssues: getStrictInt('software_quality_security_issues'),
      softwareQualityMaintainabilityIssues: getStrictInt('software_quality_maintainability_issues'),
    };

    // New Code metrics
    const newConditionsToCover = getStrictInt('new_conditions_to_cover');
    const newUncoveredConditions = getStrictInt('new_uncovered_conditions');
    const newCoveredConditions =
      newConditionsToCover !== null && newUncoveredConditions !== null
        ? Math.max(0, newConditionsToCover - newUncoveredConditions)
        : null;

    const firstPeriodEntry = Array.from(map.values()).find((e) => e.periodMode || e.periodDate);
    const rawPeriodMode = (
      params.newCodePeriodInfo?.mode ||
      firstPeriodEntry?.periodMode ||
      ''
    ).toUpperCase();

    let definitionType: SonarNewCodeMetrics['definitionType'] = 'UNKNOWN';
    if (rawPeriodMode.includes('PREVIOUS_VERSION')) definitionType = 'PREVIOUS_VERSION';
    else if (rawPeriodMode.includes('DAYS') || rawPeriodMode.includes('NUMBER_OF_DAYS'))
      definitionType = 'NUMBER_OF_DAYS';
    else if (rawPeriodMode.includes('SPECIFIC_VERSION')) definitionType = 'SPECIFIC_VERSION';
    else if (rawPeriodMode.includes('DATE')) definitionType = 'SPECIFIC_DATE';
    else if (rawPeriodMode.includes('PULL_REQUEST')) definitionType = 'PULL_REQUEST';
    else if (rawPeriodMode.includes('REFERENCE_BRANCH') || rawPeriodMode.includes('BRANCH'))
      definitionType = 'REFERENCE_BRANCH';

    const newCode: SonarNewCodeMetrics = {
      definitionType,
      definitionValue:
        params.newCodePeriodInfo?.parameter ?? firstPeriodEntry?.periodParam ?? null,
      periodDate: params.newCodePeriodInfo?.date ?? firstPeriodEntry?.periodDate ?? null,
      scmLimitationNote: params.newCodePeriodInfo?.scmLimitationNote ?? null,
      newBugs: getStrictInt('new_bugs'),
      newVulnerabilities: getStrictInt('new_vulnerabilities'),
      newCodeSmells: getStrictInt('new_code_smells'),
      newSecurityHotspots: getStrictInt('new_security_hotspots'),
      newSecurityHotspotsReviewedPercent: getStrictFloat('new_security_hotspots_reviewed'),
      newReliabilityRating: getStrictRating('new_reliability_rating'),
      newSecurityRating: getStrictRating('new_security_rating'),
      newMaintainabilityRating: getStrictRating('new_maintainability_rating'),
      newCoveragePercent: getStrictFloat('new_coverage'),
      newLinesToCover: getStrictInt('new_lines_to_cover'),
      newUncoveredLines: getStrictInt('new_uncovered_lines'),
      newConditionsToCover,
      newUncoveredConditions,
      newCoveredConditions,
      newDuplicatedLinesDensityPercent: getStrictFloat('new_duplicated_lines_density'),
      newLines: getStrictInt('new_lines'),
      newTechnicalDebtMinutes: getStrictInt('new_technical_debt'),
    };

    const measuredCount = Object.values(metricStates).filter((s) => s === 'MEASURED').length;
    const overallMeasurementState: SonarStandardMeasurementState = params.apiError
      ? 'API_ERROR'
      : params.notComputed
        ? 'NOT_COMPUTED'
        : (params.rawMeasures || []).length === 0 || measuredCount === 0
          ? 'NOT_MEASURED'
          : measuredCount < 5
            ? 'PARTIAL'
            : 'MEASURED';

    const coverageMeasurementState: SonarStandardMeasurementState =
      coveragePercent !== null || lineCoveragePercent !== null
        ? 'MEASURED'
        : linesToCover !== null
          ? 'PARTIAL'
          : baseStateWhenMissing;

    return {
      id: `smeas-${params.analysisId}`,
      analysisId: params.analysisId,
      projectKey: params.projectKey,
      softwareId: params.softwareId,
      softwareName: params.softwareName,
      commitHash: params.commitHash,
      measuredAt: new Date().toISOString(),
      measurementState: overallMeasurementState,
      qualityModel,
      metricStates,
      normalizedMetrics,
      overallCode,
      newCode,
      metrics: {
        bugs,
        vulnerabilities,
        securityHotspots,
        securityHotspotsReviewedPercent,
        codeSmells,
        cyclomaticComplexity,
        cognitiveComplexity,
        duplicatedLinesDensityPercent,
        duplicatedBlocks,
        duplicatedLines,
        ncloc,
        technicalDebtMinutes,
        maintainabilityRating: maintainabilityRating ?? 'NOT_MEASURED',
        reliabilityRating: reliabilityRating ?? 'NOT_MEASURED',
        securityRating: securityRating ?? 'NOT_MEASURED',
        securityReviewRating: securityReviewRating ?? 'NOT_MEASURED',
        coveragePercent,
        lineCoveragePercent,
        branchCoveragePercent,
        conditionCoveragePercent,
        linesToCover,
        uncoveredLines,
        conditionsToCover,
        uncoveredConditions,
        coveredConditions,
        newCodeCoveragePercent: newCode.newCoveragePercent,
        coverageMeasurementState,
        coverageReportSource:
          params.coverageReportSource ||
          (coveragePercent !== null || lineCoveragePercent !== null
            ? 'Relatório de cobertura importado do framework de testes (LCOV / JaCoCo / Cobertura) — O MqrBridge/SonarCloud não executa testes unitários diretamente.'
            : 'NOT_MEASURED: Nenhum relatório de cobertura importado pelo framework de testes nesta execução.'),
      },
      rawApiResponseHash: params.rawApiResponseHash,
    };
  }

  /**
   * Calcula a pontuação resumida (0.00 a 5.00) derivada dos ratings do Sonar
   * SOMENTE quando os três ratings principais (Reliability, Security, Maintainability)
   * foram efetivamente medidos ('A'..'E').
   * Se qualquer rating estiver ausente ('NOT_MEASURED' ou null), retorna null.
   * IMPORTANTE: Esta pontuação é identificada como um índice derivado pelo WinHood,
   * nunca como uma nota oficial única da SonarSource.
   */
  public static computeNativeSonarScoreFromRatings(
    metrics: SonarMeasuresRecord['metrics']
  ): number | null {
    const ratingToFive = (r?: SonarRatingGrade | null): number | null => {
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
          return 1.0;
        default:
          return null;
      }
    };

    const rel = ratingToFive(metrics.reliabilityRating);
    const sec = ratingToFive(metrics.securityRating);
    const maint = ratingToFive(metrics.maintainabilityRating);

    if (rel === null || sec === null || maint === null) {
      return null;
    }

    const dupDensity = metrics.duplicatedLinesDensityPercent ?? 0;
    const dupPenalty = Math.min(1.0, dupDensity / 25);

    const raw = rel * 0.35 + sec * 0.4 + maint * 0.25 - dupPenalty;
    return Math.max(0, Math.min(5, Math.round(raw * 100) / 100));
  }
}
