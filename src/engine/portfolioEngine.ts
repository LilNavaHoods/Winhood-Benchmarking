import type { BenchmarkRun, Software } from '../types/benchmark';

export interface PortfolioReleasePoint {
  runId: string;
  projectId: string;
  projectName: string;
  softwareId: string;
  softwareName: string;
  softwareVersion: string;
  completedAt: string;
  overallScore: number | null;
  totalFindings: number;
  criticalOrBlockerFindings: number;
  highFindings: number;
  technicalDebtMinutes: number;
  scopeCoveragePercent: number;
  uncoveredCategoriesCount: number;
  evidenceConfidence: 'HIGH' | 'MEDIUM' | 'LOW';
  gateDecision: string;
  evidenceVerified: boolean;
  deltaFindingsFromPrevious: number | null;
  deltaScoreFromPrevious: number | null;
}

export interface PortfolioSummary {
  generatedAt: string;
  totalProjects: number;
  totalSoftwares: number;
  totalRuns: number;
  verifiedRunsCount: number;
  verifiedRunsRatePercent: number | null;
  avgScopeCoveragePercent: number | null;
  totalTechnicalDebtMinutes: number;
  confidenceDistribution: {
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  findingTrends: Array<{
    runId: string;
    label: string;
    completedAt: string;
    blockerOrCritical: number;
    high: number;
    mediumOrLow: number;
    total: number;
    technicalDebtMinutes: number;
  }>;
  releaseProgression: PortfolioReleasePoint[];
  uncoveredDimensionsSummary: Array<{
    category: string;
    unmeasuredRunsCount: number;
  }>;
}

export class PortfolioEngine {
  public static buildSummary(params: {
    runs: BenchmarkRun[];
    softwares: Software[];
    deterministicTimestamp?: string;
  }): PortfolioSummary {
    const sortedRuns = [...params.runs].sort((a, b) =>
      (a.completedAt || a.startedAt).localeCompare(b.completedAt || b.startedAt)
    );

    const projectIds = new Set<string>();
    const softwareIds = new Set<string>(params.softwares.map((s) => s.id));
    const confidenceDist = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    const unmeasuredCountMap = new Map<string, number>();

    let verifiedCount = 0;
    let totalTechDebtMinutes = 0;
    const coverageValues: number[] = [];

    const previousBySoftwareName = new Map<string, { findings: number; score: number | null }>();
    const releaseProgression: PortfolioReleasePoint[] = [];
    const findingTrends: PortfolioSummary['findingTrends'] = [];

    for (const run of sortedRuns) {
      projectIds.add(run.projectId);
      run.softwareIds.forEach((id) => softwareIds.add(id));

      const verified = Boolean(run.evidenceVerification?.valid);
      if (verified) verifiedCount += 1;

      const runActiveFindings = (run.findings || []).filter((f) => {
        const st = f.lifecycleState || f.validationStatus;
        return st !== 'FALSE_POSITIVE' && st !== 'FALSE_POSITIVE_REVIEWED' && st !== 'VERIFIED_RESOLVED';
      });
      const runBlockCrit = runActiveFindings.filter(
        (f) => f.severity === 'BLOCKER' || f.severity === 'CRITICAL'
      ).length;
      const runHigh = runActiveFindings.filter((f) => f.severity === 'HIGH').length;
      const runMedLow = runActiveFindings.length - runBlockCrit - runHigh;
      const runTechDebt = runActiveFindings.reduce((acc, f) => acc + (f.remediationEffortMinutes || 0), 0);

      findingTrends.push({
        runId: run.id,
        label: `${run.projectName} (${(run.completedAt || run.startedAt).slice(0, 10)})`,
        completedAt: run.completedAt || run.startedAt,
        blockerOrCritical: runBlockCrit,
        high: runHigh,
        mediumOrLow: runMedLow,
        total: runActiveFindings.length,
        technicalDebtMinutes: runTechDebt,
      });

      for (const card of run.scoreCards || []) {
        const swFindings = runActiveFindings.filter((f) => f.softwareId === card.softwareId);
        const blockCrit = swFindings.filter(
          (f) => f.severity === 'BLOCKER' || f.severity === 'CRITICAL'
        ).length;
        const high = swFindings.filter((f) => f.severity === 'HIGH').length;
        const debtMin =
          card.metricsSummary?.technicalDebtMinutes ??
          swFindings.reduce((acc, f) => acc + (f.remediationEffortMinutes || 0), 0);
        totalTechDebtMinutes += debtMin;

        const cov = card.separatedIndicators?.scopeCoveragePercent ?? 0;
        coverageValues.push(cov);

        const conf = card.separatedIndicators?.evidenceConfidence ?? 'LOW';
        confidenceDist[conf] += 1;

        for (const cat of card.unmeasuredCategories || []) {
          unmeasuredCountMap.set(cat, (unmeasuredCountMap.get(cat) || 0) + 1);
        }

        const techScore = card.separatedIndicators?.technicalScore ?? card.groupedScores?.overallScore ?? null;
        const prevKey = card.softwareName.toLowerCase();
        const prev = previousBySoftwareName.get(prevKey);

        const deltaFindingsFromPrevious = prev ? swFindings.length - prev.findings : null;
        const deltaScoreFromPrevious =
          prev && techScore !== null && prev.score !== null
            ? Number((techScore - prev.score).toFixed(2))
            : null;

        previousBySoftwareName.set(prevKey, { findings: swFindings.length, score: techScore });

        releaseProgression.push({
          runId: run.id,
          projectId: run.projectId,
          projectName: run.projectName,
          softwareId: card.softwareId,
          softwareName: card.softwareName,
          softwareVersion: card.softwareVersion,
          completedAt: run.completedAt || run.startedAt,
          overallScore: techScore,
          totalFindings: swFindings.length,
          criticalOrBlockerFindings: blockCrit,
          highFindings: high,
          technicalDebtMinutes: debtMin,
          scopeCoveragePercent: cov,
          uncoveredCategoriesCount: (card.unmeasuredCategories || []).length,
          evidenceConfidence: conf,
          gateDecision:
            card.separatedIndicators?.qualityGateDecision ||
            card.qualityGate?.executiveDecision ||
            card.qualityGate?.status ||
            'NOT_EVALUATED',
          evidenceVerified: verified,
          deltaFindingsFromPrevious,
          deltaScoreFromPrevious,
        });
      }
    }

    const avgScopeCoveragePercent =
      coverageValues.length > 0
        ? Number((coverageValues.reduce((a, b) => a + b, 0) / coverageValues.length).toFixed(1))
        : null;

    const verifiedRunsRatePercent =
      sortedRuns.length > 0 ? Number(((verifiedCount / sortedRuns.length) * 100).toFixed(1)) : null;

    const uncoveredDimensionsSummary = Array.from(unmeasuredCountMap.entries())
      .map(([category, unmeasuredRunsCount]) => ({ category, unmeasuredRunsCount }))
      .sort((a, b) => b.unmeasuredRunsCount - a.unmeasuredRunsCount || a.category.localeCompare(b.category));

    return {
      generatedAt: params.deterministicTimestamp || new Date().toISOString(),
      totalProjects: projectIds.size,
      totalSoftwares: softwareIds.size,
      totalRuns: sortedRuns.length,
      verifiedRunsCount: verifiedCount,
      verifiedRunsRatePercent,
      avgScopeCoveragePercent,
      totalTechnicalDebtMinutes: totalTechDebtMinutes,
      confidenceDistribution: confidenceDist,
      findingTrends,
      releaseProgression,
      uncoveredDimensionsSummary,
    };
  }
}
