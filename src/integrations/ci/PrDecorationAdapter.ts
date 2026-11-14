import { QualityGateEngine, type QualityGateEvaluationResult } from '../../gate/QualityGateEngine';
import type { BenchmarkRun, NormalizedFinding } from '../../types/benchmark';

export type PrCiProvider = 'GITHUB' | 'GITLAB' | 'JENKINS';

export interface PrDecorationPayload {
  provider: PrCiProvider;
  repository: string;
  pullRequestOrMrId: string | number;
  gateDecision: QualityGateEvaluationResult['decision'];
  cliExitCode: 0 | 1 | 2;
  shouldBlockMerge: boolean;
  gateVersion: string;
  findingsDelta: {
    newCriticalOrBlocker: number;
    newHigh: number;
    totalCurrent: number;
    totalBaseline: number | null;
    netDelta: number | null;
  };
  markdownComment: string;
  generatedAt: string;
}

export class PrDecorationAdapter {
  public static buildDecoration(params: {
    provider: PrCiProvider;
    repository: string;
    pullRequestOrMrId: string | number;
    run: BenchmarkRun;
    baselineRun?: BenchmarkRun | null;
    gateId?: string;
    deterministicTimestamp?: string;
  }): PrDecorationPayload {
    const { provider, repository, pullRequestOrMrId, run, baselineRun, gateId, deterministicTimestamp } = params;
    const gateEval = QualityGateEngine.evaluateFromRun(run, gateId, deterministicTimestamp);
    const currentFindings = run.findings || [];
    const baselineFindings = baselineRun?.findings || null;

    const fingerprint = (f: NormalizedFinding) => `${f.originalRuleId}|${f.filePath}|${f.lineNumber}`;
    const baselineSet = baselineFindings ? new Set(baselineFindings.map(fingerprint)) : null;

    const newFindings = baselineSet
      ? currentFindings.filter((f) => !baselineSet.has(fingerprint(f)))
      : currentFindings;

    const newCriticalOrBlocker = newFindings.filter(
      (f) => f.severity === 'BLOCKER' || f.severity === 'CRITICAL'
    ).length;
    const newHigh = newFindings.filter((f) => f.severity === 'HIGH').length;
    const netDelta = baselineFindings ? currentFindings.length - baselineFindings.length : null;
    const shouldBlockMerge = gateEval.cliExitCode === 1;

    const statusBadge =
      gateEval.decision === 'APPROVED'
        ? 'APPROVED'
        : gateEval.decision === 'APPROVED_WITH_RESERVATIONS'
          ? 'APPROVED WITH RESERVATIONS'
          : gateEval.decision === 'INCONCLUSIVE'
            ? 'INCONCLUSIVE (VERIFICATION REQUIRED)'
            : 'BLOCKED / REJECTED';

    const topItems = [...newFindings]
      .sort((a, b) => {
        const order: Record<string, number> = { BLOCKER: 0, CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, INFO: 5 };
        return (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
      })
      .slice(0, 10);

    const lines: string[] = [
      `## WinHood Independent Audit — Quality Gate: **${statusBadge}**`,
      '',
      `- **Repository**: \`${repository}\` | **PR/MR**: \`#${pullRequestOrMrId}\` (${provider})`,
      `- **Gate Applied**: \`${gateEval.gateId}\` v\`${gateEval.gateVersion}\` (hash \`${gateEval.gateHash.slice(0, 12)}\`)`,
      `- **CLI Exit Code**: \`${gateEval.cliExitCode}\` (${shouldBlockMerge ? 'Merge/Pipeline Blocked' : 'Merge Allowed'})`,
      `- **Findings Delta**: Current=\`${currentFindings.length}\`${netDelta !== null ? ` | Baseline=\`${baselineFindings!.length}\` | Net Delta=\`${netDelta >= 0 ? `+${netDelta}` : netDelta}\`` : ''} | New BLOCKER/CRITICAL=\`${newCriticalOrBlocker}\` | New HIGH=\`${newHigh}\``,
      `- **Evidence Manifest**: \`${run.signedManifest?.manifestId || 'UNSIGNED'}\` (Verified=\`${Boolean(run.evidenceVerification?.valid)}\`)`,
      '',
      '### Gate Conditions',
      '| Condition | Actual | Threshold | Result |',
      '|---|---:|---:|---|',
      ...gateEval.conditions.map(
        (c) =>
          `| ${c.label} | ${c.actualValue ?? 'NOT_MEASURED'} | ${c.operator} ${c.threshold} | ${c.passed ? 'PASS' : c.inconclusive ? 'INCONCLUSIVE' : 'FAIL'} |`
      ),
    ];

    if (topItems.length > 0) {
      lines.push(
        '',
        '### Top Findings in Scope',
        '| Severity | Rule | CWE | Location | Title |',
        '|---|---|---|---|---|',
        ...topItems.map(
          (f) =>
            `| ${f.severity} | \`${f.originalRuleId}\` | ${f.cwe || '-'} | \`${f.filePath}:${f.lineNumber}\` | ${f.title.replace(/\|/g, '\\|')} |`
        )
      );
    }

    lines.push(
      '',
      '> *WinHood provides independent, evidence-backed software auditing speaking open standards (SARIF 2.1.0, CWE, OWASP Top 10, CycloneDX 1.5, SPDX 2.3).*'
    );

    return {
      provider,
      repository,
      pullRequestOrMrId,
      gateDecision: gateEval.decision,
      cliExitCode: gateEval.cliExitCode,
      shouldBlockMerge,
      gateVersion: gateEval.gateVersion,
      findingsDelta: {
        newCriticalOrBlocker,
        newHigh,
        totalCurrent: currentFindings.length,
        totalBaseline: baselineFindings ? baselineFindings.length : null,
        netDelta,
      },
      markdownComment: lines.join('\n'),
      generatedAt: deterministicTimestamp || new Date().toISOString(),
    };
  }
}
