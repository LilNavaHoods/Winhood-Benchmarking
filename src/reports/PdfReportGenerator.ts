import crypto from 'node:crypto';
import { ComplianceMapper } from '../evidence/ComplianceMapper';
import { QualityGateEngine } from '../gate/QualityGateEngine';
import { RULE_ENGINE_VERSION, RuleRegistry } from '../analyzers/RuleRegistry';
import { SarifCodec } from '../analyzers/SarifCodec';
import {
  computeEvidenceChainHash,
  verifyEvidenceChainAndManifest,
} from '../engine/evidenceProvenanceEngine';
import type { BenchmarkCategoryKey, BenchmarkRun } from '../types/benchmark';

const REPORT_CATEGORY_LABELS: Record<BenchmarkCategoryKey, string> = {
  functionality: 'Funcionalidade',
  code_quality: 'Qualidade de Código',
  security: 'Segurança',
  performance: 'Desempenho',
  architecture: 'Arquitetura',
  database: 'Banco de Dados',
  reliability: 'Confiabilidade',
  compatibility: 'Compatibilidade',
  usability: 'Usabilidade & UX',
  installation: 'Instalação & SO',
  privacy: 'Privacidade & LGPD',
  documentation: 'Documentação',
};

export const WINHOOD_PLATFORM_VERSION = '4.4.0';

export interface VeracityAdapterSummary {
  toolId: string;
  toolName: string;
  toolVersion: string;
  executionStatus: 'MEASURED' | 'NOT_INSTALLED' | 'NOT_MEASURED' | 'FAILED';
  scopeExecuted: string | null;
  durationMs: number | null;
  rawOutputSha256: string | null;
  reason: string | null;
}

export interface VeracityEpistemicSeparation {
  measuredEvidenceFacts: string[];
  inferencesAndHeuristics: string[];
  unmeasuredDimensions: string[];
}

export interface VeracityReportBlock {
  winhoodVersion: string;
  generatedAtUtc: string;
  evidenceChainHash: string;
  evidenceChainRecordsCount: number;
  evidenceChainVerified: boolean;
  evidenceVerificationState: string;
  analyzedFilesSha256: Record<string, string>;
  adaptersExecuted: VeracityAdapterSummary[];
  adaptersUnavailable: VeracityAdapterSummary[];
  measuredCoveragePercent: number;
  measuredCoverageBySoftware: Array<{
    softwareId: string;
    softwareName: string;
    measuredCoveragePercent: number;
    weightRenormalizationApplied: boolean;
    excludedCategories: BenchmarkCategoryKey[];
    renormalizationExplanation: string;
  }>;
  epistemicSeparation: VeracityEpistemicSeparation;
  scopeLimitationsDisclaimer: string;
}

export interface ReportProvenanceFooter {
  winhoodVersion: string;
  engineVersion: string;
  ruleCatalogVersion: string;
  ruleCatalogSha256: string;
  codeHashSha256: string;
  evidenceChainHash: string;
  measuredCoveragePercent: number;
  artifactHashes: Record<string, string>;
  appliedGateId: string;
  appliedGateVersion: string;
  appliedGateHashSha256: string;
  reportContentSha256: string;
  hmacAlgorithm: 'HMAC-SHA256';
  hmacSignature: string;
  generatedAt: string;
  veracityBlock: VeracityReportBlock;
}

const DEFAULT_REPORT_HMAC_KEY =
  process.env.WINHOOD_REPORT_HMAC_KEY || 'winhood-deterministic-audit-report-hmac-key-v4';

function sha256Hex(input: string | Buffer): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function computeHmacSha256(payload: string, secret = DEFAULT_REPORT_HMAC_KEY): string {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function timingSafeHexEqual(aHex: string, bHex: string): boolean {
  if (!aHex || !bHex || aHex.length !== bHex.length) return false;
  try {
    const a = Buffer.from(aHex, 'hex');
    const b = Buffer.from(bHex, 'hex');
    return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeCsvCell(value: unknown): string {
  const str = String(value ?? '');
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function toPdfAscii(text: string): string {
  const normalized = text
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^\x20-\x7e]/g, ' ');
  return normalized
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

function wrapText(line: string, maxChars = 88): string[] {
  if (line.length <= maxChars) return [line];
  const out: string[] = [];
  let remaining = line;
  while (remaining.length > maxChars) {
    let splitIdx = remaining.lastIndexOf(' ', maxChars);
    if (splitIdx <= 10) splitIdx = maxChars;
    out.push(remaining.slice(0, splitIdx).trimEnd());
    remaining = remaining.slice(splitIdx).trimStart();
  }
  if (remaining.length > 0) out.push(remaining);
  return out;
}

export class PdfReportGenerator {
  public static buildVeracityReportBlock(run: BenchmarkRun): VeracityReportBlock {
    const generatedAtUtc = run.completedAt || run.startedAt || '2026-11-14T00:00:00.000Z';
    const evidenceChain = run.evidenceChain || [];
    const evidenceChainHash =
      run.signedManifest?.rootChainSha256 ||
      run.signedManifest?.merkleOrChainRootSha256 ||
      computeEvidenceChainHash(evidenceChain);

    const liveVerification =
      evidenceChain.length > 0 || run.signedManifest
        ? verifyEvidenceChainAndManifest(evidenceChain, run.signedManifest)
        : null;
    const evidenceChainVerified =
      typeof run.evidenceVerification?.valid === 'boolean'
        ? run.evidenceVerification.valid
        : Boolean(liveVerification?.valid);
    const evidenceVerificationState =
      run.evidenceVerification?.verificationState ||
      liveVerification?.verificationState ||
      run.signedManifest?.verificationState ||
      'UNVERIFIABLE';

    const analyzedFilesSha256: Record<string, string> = {};
    for (const vr of run.veracityResults || []) {
      const hashFromExec = (run.toolExecutions || []).find(
        (te) => te.softwareId === vr.softwareId && (te.inputArtifactsSha256 || te.sourceHash)
      );
      const hashFromChain = evidenceChain.find(
        (ev) => ev.softwareId === vr.softwareId && ev.sourceHash && ev.sourceHash !== 'UNVERIFIED'
      );
      const resolvedHash =
        hashFromExec?.inputArtifactsSha256 ||
        hashFromExec?.sourceHash ||
        hashFromChain?.sourceHash ||
        'UNAVAILABLE';
      analyzedFilesSha256[`${vr.softwareName} (${vr.softwareId})`] = resolvedHash;
    }
    if (Object.keys(analyzedFilesSha256).length === 0 && run.signedManifest?.sourceHashes?.length) {
      run.signedManifest.sourceHashes.forEach((h, idx) => {
        analyzedFilesSha256[`sourceArtifact_${idx + 1}`] = h;
      });
    }

    const adaptersExecuted: VeracityAdapterSummary[] = [];
    const adaptersUnavailable: VeracityAdapterSummary[] = [];
    const seenToolKeys = new Set<string>();

    for (const te of run.toolExecutions || []) {
      const dedupeKey = `${te.softwareId}:${te.toolId}`;
      if (seenToolKeys.has(dedupeKey)) continue;
      seenToolKeys.add(dedupeKey);

      const execStatus: VeracityAdapterSummary['executionStatus'] =
        te.executionStatus ||
        (te.exitCode === 0 && te.veracityStatus !== 'EMPTY_ERROR'
          ? 'MEASURED'
          : te.exitCode !== null && te.exitCode !== 0
            ? 'FAILED'
            : 'NOT_MEASURED');

      const summary: VeracityAdapterSummary = {
        toolId: te.toolId,
        toolName: te.toolName,
        toolVersion: te.toolVersion || 'UNAVAILABLE',
        executionStatus: execStatus,
        scopeExecuted:
          te.scopeExecuted ||
          `${te.analyzedFilesCount}/${te.eligibleFilesCount} arquivos (${te.workingDirectory || 'workspace'})`,
        durationMs: te.durationMs ?? null,
        rawOutputSha256: te.rawOutputSha256 || null,
        reason:
          te.unavailableReason ||
          (te.failureReasons && te.failureReasons.length > 0 ? te.failureReasons.join('; ') : null),
      };

      if (execStatus === 'MEASURED') {
        adaptersExecuted.push(summary);
      } else {
        adaptersUnavailable.push(summary);
      }
    }

    // Also include unified dynamic executions that were not executed / unavailable
    for (const ue of run.unifiedExecutions || []) {
      const toolId = ue.kind || 'dynamic-runner';
      if (ue.state === 'MEASURED') {
        adaptersExecuted.push({
          toolId,
          toolName: `WinHood Dynamic Runner (${toolId})`,
          toolVersion: WINHOOD_PLATFORM_VERSION,
          executionStatus: 'MEASURED',
          scopeExecuted: ue.summary ?? null,
          durationMs: null,
          rawOutputSha256: ue.evidenceHash || null,
          reason: null,
        });
      } else {
        adaptersUnavailable.push({
          toolId,
          toolName: `WinHood Dynamic Runner (${toolId})`,
          toolVersion: 'UNAVAILABLE',
          executionStatus: ue.state === 'FAILED' ? 'FAILED' : 'NOT_MEASURED',
          scopeExecuted: null,
          durationMs: null,
          rawOutputSha256: ue.evidenceHash || null,
          reason: ue.summary || 'Execução dinâmica não realizada neste ciclo.',
        });
      }
    }

    const scoreCards = run.scoreCards || [];
    const measuredCoverageBySoftware = scoreCards.map((sc) => {
      const assessedCount = sc.categoryDetails
        ? Object.values(sc.categoryDetails).filter((cd) => cd.status === 'ASSESSED').length
        : Object.values(sc.categoryScores || {}).filter((v) => v !== null && v !== undefined).length;
      const enabledCount = Math.max(
        1,
        (run.enabledCategories && run.enabledCategories.length) ||
          (sc.categoryDetails ? Object.keys(sc.categoryDetails).length : 12)
      );
      const fallbackCoverage = Number(((assessedCount / enabledCount) * 100).toFixed(1));
      const measuredCov =
        typeof sc.measuredCoveragePercent === 'number'
          ? sc.measuredCoveragePercent
          : typeof sc.separatedIndicators?.measuredCoveragePercent === 'number'
            ? sc.separatedIndicators.measuredCoveragePercent
            : fallbackCoverage;
      const excludedCategories =
        sc.weightRenormalization?.excludedCategories ||
        (sc.categoryDetails
          ? (Object.values(sc.categoryDetails)
              .filter((cd) => cd.status === 'NOT_ASSESSED')
              .map((cd) => cd.category) as BenchmarkCategoryKey[])
          : []);
      const weightRenormalizationApplied = Boolean(
        sc.weightRenormalization?.applied ?? excludedCategories.length > 0
      );
      const renormalizationExplanation =
        sc.weightRenormalization?.explanation ||
        (weightRenormalizationApplied
          ? `Categorias não medidas (${excludedCategories.join(', ')}) excluídas da média ponderada com renormalização proporcional dos pesos restantes.`
          : 'Todas as categorias habilitadas foram medidas com evidência direta.');

      return {
        softwareId: sc.softwareId,
        softwareName: sc.softwareName,
        measuredCoveragePercent: measuredCov,
        weightRenormalizationApplied,
        excludedCategories,
        renormalizationExplanation,
      };
    });

    const measuredCoveragePercent =
      measuredCoverageBySoftware.length > 0
        ? Number(
            (
              measuredCoverageBySoftware.reduce((acc, s) => acc + s.measuredCoveragePercent, 0) /
              measuredCoverageBySoftware.length
            ).toFixed(1)
          )
        : 0;

    // 3-Way Epistemic Separation: Fato Medido vs Inferência/Heurística vs Não Medido
    const measuredEvidenceFacts: string[] = [];
    const inferencesAndHeuristics: string[] = [];
    const unmeasuredDimensions: string[] = [];

    measuredEvidenceFacts.push(
      `Total de achados estáticos/AST registrados com evidência verificável: ${(run.findings || []).length}.`
    );
    measuredEvidenceFacts.push(
      `Adaptadores executados com saída validada: ${adaptersExecuted.length} | Cadeia de evidências SHA-256: ${evidenceChain.length} registros (Root=${evidenceChainHash.slice(0, 16)}...).`
    );

    for (const sc of scoreCards) {
      const techScore =
        sc.separatedIndicators?.technicalScore !== null &&
        sc.separatedIndicators?.technicalScore !== undefined
          ? `${sc.separatedIndicators.technicalScore.toFixed(2)} / 5.00`
          : 'NOT_MEASURED';
      measuredEvidenceFacts.push(
        `${sc.softwareName} (v${sc.softwareVersion}): Nota Técnica=${techScore} | Bugs=${sc.metricsSummary?.bugs ?? 0} | Vulnerabilidades=${sc.metricsSummary?.vulnerabilities ?? 0} | Segredos=${sc.metricsSummary?.secretsExposed ?? 0} | Cobertura Efetiva=${measuredCoverageBySoftware.find((m) => m.softwareId === sc.softwareId)?.measuredCoveragePercent ?? measuredCoveragePercent}%.`
      );

      if (sc.runtimeMetrics?.status === 'MEASURED') {
        measuredEvidenceFacts.push(
          `${sc.softwareName}: Desempenho Runtime MEDIDO (P95=${Number(sc.metricsSummary?.p95LatencyMs ?? 0).toFixed(1)} ms, Throughput=${Number(sc.metricsSummary?.throughputRps ?? 0)} RPS).`
        );
      } else {
        unmeasuredDimensions.push(
          `${sc.softwareName} — Desempenho em Runtime (P50/P95/P99/RPS): NOT_MEASURED (${sc.runtimeMetrics?.reason || 'Requer carga controlada via ControlledTestAndPerfRunner'}).`
        );
      }

      if (sc.staticMetrics?.testCoveragePercent !== null && sc.staticMetrics?.testCoveragePercent !== undefined) {
        measuredEvidenceFacts.push(
          `${sc.softwareName}: Cobertura de Testes importada de relatório real=${sc.staticMetrics.testCoveragePercent.toFixed(1)}%.`
        );
      } else {
        unmeasuredDimensions.push(
          `${sc.softwareName} — Cobertura de Testes (LCOV/JaCoCo/Cobertura): NOT_MEASURED (nenhum relatório real de cobertura encontrado no snapshot).`
        );
      }

      if (sc.categoryDetails) {
        for (const cd of Object.values(sc.categoryDetails)) {
          const catLabel = REPORT_CATEGORY_LABELS[cd.category] || cd.category;
          if (cd.status === 'NOT_ASSESSED' || cd.finalScore === null) {
            unmeasuredDimensions.push(
              `${sc.softwareName} — Categoria ${catLabel} (${cd.category}): ${cd.measurementState || 'NOT_MEASURED'} (excluída da média ponderada; peso original ${cd.originalWeight ?? cd.weight}% renormalizado).`
            );
          } else if (cd.measurementState === 'INFERRED') {
            inferencesAndHeuristics.push(
              `${sc.softwareName} — Categoria ${catLabel} (${cd.category}): inferida estaticamente (${cd.measurementState}) com nota ${cd.finalScore.toFixed(2)} / 5.00 e peso efetivo ${cd.effectiveWeight ?? cd.weight}%.`
            );
          }
        }
      }

      if (sc.weightRenormalization?.applied) {
        inferencesAndHeuristics.push(
          `${sc.softwareName} — Renormalização de Pesos: ${sc.weightRenormalization.explanation}`
        );
      }
    }

    if (adaptersUnavailable.length > 0) {
      for (const ad of adaptersUnavailable) {
        unmeasuredDimensions.push(
          `Adaptador ${ad.toolName} (${ad.toolId}): ${ad.executionStatus} — ${ad.reason || 'Não executado ou indisponível no host.'}`
        );
      }
    }

    if (inferencesAndHeuristics.length === 0) {
      inferencesAndHeuristics.push(
        'Nenhuma heurística auxiliar adicional aplicada além das regras determinísticas AST/MQR.'
      );
    }
    if (unmeasuredDimensions.length === 0) {
      unmeasuredDimensions.push('Todas as dimensões habilitadas no perfil foram medidas com evidência direta.');
    }

    const scopeLimitationsDisclaimer =
      'ESCOPO E LIMITAÇÕES (POLÍTICA ANTI-MOCK): Este relatório reflete exclusivamente evidências efetivamente medidas no snapshot analisado. Dimensões sem execução dinâmica ou ferramentas externas ausentes no host são marcadas explicitamente como NOT_MEASURED ou UNAVAILABLE, excluídas da média ponderada com renormalização documentada dos pesos restantes. Este laudo técnico não constitui certificação regulatória formal (ISO/SOC2/PCI-DSS).';

    return {
      winhoodVersion: WINHOOD_PLATFORM_VERSION,
      generatedAtUtc,
      evidenceChainHash,
      evidenceChainRecordsCount: evidenceChain.length,
      evidenceChainVerified,
      evidenceVerificationState,
      analyzedFilesSha256,
      adaptersExecuted,
      adaptersUnavailable,
      measuredCoveragePercent,
      measuredCoverageBySoftware,
      epistemicSeparation: {
        measuredEvidenceFacts,
        inferencesAndHeuristics,
        unmeasuredDimensions,
      },
      scopeLimitationsDisclaimer,
    };
  }

  public static buildProvenanceFooter(
    run: BenchmarkRun,
    hmacSecret = DEFAULT_REPORT_HMAC_KEY
  ): ReportProvenanceFooter {
    const gateEval = QualityGateEngine.evaluateFromRun(run);
    const catalogSnapshot = RuleRegistry.getCatalogSnapshot();
    const sm = run.signedManifest;
    const veracityBlock = this.buildVeracityReportBlock(run);

    const engineVersion = sm?.engineVersion || run.algorithmVersion || RULE_ENGINE_VERSION;
    const ruleCatalogVersion = sm?.rulePackVersions?.core || catalogSnapshot.engineVersion || RULE_ENGINE_VERSION;
    const ruleCatalogSha256 = sm?.ruleCatalogSha256 || catalogSnapshot.catalogSha256;

    const findingsDigest = sha256Hex(
      JSON.stringify(
        (run.findings || []).map((f) => ({
          id: f.originalRuleId,
          file: f.filePath,
          line: f.lineNumber,
          sev: f.severity,
        }))
      )
    );
    const codeHashSha256 =
      sm?.artifactHashes?.workspaceCodeSha256 ||
      sm?.merkleOrChainRootSha256 ||
      sha256Hex(`${run.id}:${run.projectId}:${findingsDigest}`);

    const artifactHashes: Record<string, string> = {
      findingsDigestSha256: findingsDigest,
      gateDecisionSha256: gateEval.gateHash,
      evidenceChainSha256: veracityBlock.evidenceChainHash,
      ...(sm?.artifactHashes || {}),
    };

    const generatedAt = veracityBlock.generatedAtUtc;
    const canonicalPayload = JSON.stringify({
      winhoodVersion: WINHOOD_PLATFORM_VERSION,
      runId: run.id,
      projectName: run.projectName,
      engineVersion,
      ruleCatalogVersion,
      ruleCatalogSha256,
      codeHashSha256,
      evidenceChainHash: veracityBlock.evidenceChainHash,
      measuredCoveragePercent: veracityBlock.measuredCoveragePercent,
      artifactHashes,
      appliedGateId: gateEval.gateId,
      appliedGateVersion: gateEval.gateVersion,
      appliedGateHashSha256: gateEval.gateHash,
      decision: gateEval.decision,
      findingsCount: (run.findings || []).length,
      generatedAt,
    });

    const reportContentSha256 = sha256Hex(canonicalPayload);
    const hmacSignature = computeHmacSha256(
      `${reportContentSha256}:${engineVersion}:${ruleCatalogSha256}:${codeHashSha256}:${gateEval.gateHash}`,
      hmacSecret
    );

    return {
      winhoodVersion: WINHOOD_PLATFORM_VERSION,
      engineVersion,
      ruleCatalogVersion,
      ruleCatalogSha256,
      codeHashSha256,
      evidenceChainHash: veracityBlock.evidenceChainHash,
      measuredCoveragePercent: veracityBlock.measuredCoveragePercent,
      artifactHashes,
      appliedGateId: gateEval.gateId,
      appliedGateVersion: gateEval.gateVersion,
      appliedGateHashSha256: gateEval.gateHash,
      reportContentSha256,
      hmacAlgorithm: 'HMAC-SHA256',
      hmacSignature,
      generatedAt,
      veracityBlock,
    };
  }

  /**
   * Verifies the cryptographic integrity (Report SHA-256 and HMAC-SHA256 signature)
   * embedded inside a generated PDF buffer using constant-time comparison.
   */
  public static verifyPdfIntegrity(
    pdfBuffer: Buffer,
    hmacSecret = DEFAULT_REPORT_HMAC_KEY
  ): {
    valid: boolean;
    reportContentSha256: string | null;
    hmacSignature: string | null;
    engineVersion: string | null;
    ruleCatalogSha256: string | null;
    codeHashSha256: string | null;
    appliedGateHashSha256: string | null;
    evidenceChainHash: string | null;
    winhoodVersion: string | null;
  } {
    const raw = pdfBuffer.toString('latin1');
    const extract = (label: string): string | null => {
      const re = new RegExp(`${label}:\\s*([a-f0-9A-Za-z._-]+)`);
      const m = raw.match(re);
      return m ? m[1]! : null;
    };

    const reportContentSha256 = extract('Report-SHA256');
    const hmacSignature = extract('Report-HMAC-SHA256');
    const engineVersion = extract('Provenance-Engine-Version');
    const ruleCatalogSha256 = extract('Provenance-RuleCatalog-SHA256');
    const codeHashSha256 = extract('Provenance-Code-SHA256');
    const appliedGateHashSha256 = extract('Provenance-Gate-SHA256');
    const evidenceChainHash = extract('Provenance-EvidenceChain-SHA256');
    const winhoodVersion = extract('Provenance-WinHood-Version');

    if (
      !reportContentSha256 ||
      !hmacSignature ||
      !engineVersion ||
      !ruleCatalogSha256 ||
      !codeHashSha256 ||
      !appliedGateHashSha256
    ) {
      return {
        valid: false,
        reportContentSha256,
        hmacSignature,
        engineVersion,
        ruleCatalogSha256,
        codeHashSha256,
        appliedGateHashSha256,
        evidenceChainHash,
        winhoodVersion,
      };
    }

    const expectedHmac = computeHmacSha256(
      `${reportContentSha256}:${engineVersion}:${ruleCatalogSha256}:${codeHashSha256}:${appliedGateHashSha256}`,
      hmacSecret
    );

    const hmacMatched = timingSafeHexEqual(expectedHmac, hmacSignature);

    return {
      valid:
        raw.startsWith('%PDF-1.4') &&
        hmacMatched &&
        reportContentSha256.length === 64,
      reportContentSha256,
      hmacSignature,
      engineVersion,
      ruleCatalogSha256,
      codeHashSha256,
      appliedGateHashSha256,
      evidenceChainHash,
      winhoodVersion,
    };
  }

  /**
   * Generates a self-contained HTML5 report (100% inline CSS, zero external requests)
   * with full parity against PDF/JSON/CSV/SARIF: executive summary, scorecards without
   * fabricated zeroes, 3-way epistemic separation, adapters executed vs unavailable,
   * findings table, evidence chain, and cryptographic provenance footer.
   */
  public static generateSelfContainedHtml(
    run: BenchmarkRun,
    hmacSecret = DEFAULT_REPORT_HMAC_KEY
  ): string {
    const gateEval = QualityGateEngine.evaluateFromRun(run);
    const provenance = this.buildProvenanceFooter(run, hmacSecret);
    const vb = provenance.veracityBlock;
    const findings = run.findings || [];
    const chain = run.evidenceChain || [];

    const decisionColor =
      gateEval.decision === 'APPROVED'
        ? '#10b981'
        : gateEval.decision === 'APPROVED_WITH_RESERVATIONS'
          ? '#f59e0b'
          : gateEval.decision === 'INCONCLUSIVE'
            ? '#94a3b8'
            : '#ef4444';

    const scoreCardRows = (run.scoreCards || [])
      .map((sc) => {
        const covInfo = vb.measuredCoverageBySoftware.find((m) => m.softwareId === sc.softwareId);
        const scoreLabel =
          sc.separatedIndicators?.technicalScore !== null &&
          sc.separatedIndicators?.technicalScore !== undefined
            ? `${sc.separatedIndicators.technicalScore.toFixed(2)} / 5.00`
            : 'NOT_MEASURED';
        const perfLabel =
          sc.runtimeMetrics?.status === 'MEASURED'
            ? `P95 ${Number(sc.metricsSummary?.p95LatencyMs ?? 0).toFixed(1)} ms (${Number(sc.metricsSummary?.throughputRps ?? 0)} RPS)`
            : 'NOT_MEASURED (Análise Estática)';
        const catBreakdown = sc.categoryDetails
          ? Object.values(sc.categoryDetails)
              .map((cd) => {
                const scoreStr =
                  cd.status === 'ASSESSED' && cd.finalScore !== null
                    ? `${cd.finalScore.toFixed(2)} / 5.00`
                    : cd.measurementState || 'NOT_MEASURED';
                return `<li><code>${escapeHtml(cd.category)}</code> [${escapeHtml(cd.status)}]: <strong>${escapeHtml(scoreStr)}</strong> (Peso Original: ${cd.originalWeight ?? cd.weight}% → Efetivo: ${cd.effectiveWeight ?? cd.weight}%)</li>`;
              })
              .join('\n')
          : '<li>Sem detalhamento categórico disponível.</li>';

        return `<div class="card">
          <div style="display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:8px;">
            <h3 style="margin:0;color:#f8fafc;">${escapeHtml(sc.softwareName)} (v${escapeHtml(sc.softwareVersion)})</h3>
            <strong style="color:#38bdf8;font-size:16px;">${escapeHtml(scoreLabel)}</strong>
          </div>
          <div style="font-size:12px;color:#94a3b8;margin:6px 0 10px 0;">
            Classificação: <strong>${escapeHtml(sc.classificationLabel)}</strong> |
            Quality Gate: <strong>${escapeHtml(sc.separatedIndicators?.qualityGateDecision || sc.qualityGate?.status || 'INCONCLUSIVE')}</strong> |
            Cobertura de Medição Efetiva: <strong>${covInfo?.measuredCoveragePercent ?? vb.measuredCoveragePercent}%</strong> |
            Desempenho Runtime: <strong>${escapeHtml(perfLabel)}</strong>
          </div>
          ${
            covInfo?.weightRenormalizationApplied
              ? `<div style="font-size:12px;color:#fbbf24;margin-bottom:8px;">Renormalização de Pesos Aplicada: ${escapeHtml(covInfo.renormalizationExplanation)}</div>`
              : ''
          }
          <ul style="margin:6px 0 0 18px;font-size:12px;">${catBreakdown}</ul>
        </div>`;
      })
      .join('\n');

    const findingsRows =
      findings.length === 0
        ? '<tr><td colspan="6" style="text-align:center;color:#94a3b8;">Nenhum apontamento detectado no escopo analisado.</td></tr>'
        : findings
            .slice(0, 100)
            .map(
              (f) => `<tr>
          <td><span class="sev sev-${escapeHtml(f.severity.toLowerCase())}">${escapeHtml(f.severity)}</span></td>
          <td><code>${escapeHtml(f.originalRuleId)}</code></td>
          <td>${escapeHtml(f.cwe || f.category || 'N/A')}</td>
          <td>${escapeHtml((f as { owaspCategory?: string; owasp?: string }).owaspCategory || (f as { owasp?: string }).owasp || 'N/A')}</td>
          <td><code>${escapeHtml(f.filePath)}:${f.lineNumber}</code></td>
          <td>${escapeHtml(f.title)}</td>
        </tr>`
            )
            .join('\n');

    const chainRows =
      chain.length === 0
        ? '<tr><td colspan="4" style="text-align:center;color:#94a3b8;">Trilha resumida no manifesto assinado abaixo.</td></tr>'
        : chain
            .slice(0, 25)
            .map(
              (b, idx) => `<tr>
          <td>#${idx + 1}</td>
          <td>${escapeHtml((b as { title?: string }).title || b.toolName || 'STEP')}</td>
          <td><code>${escapeHtml((b.previousRecordSha256 || 'GENESIS').slice(0, 20))}...</code></td>
          <td><code>${escapeHtml((b.sha256 || '').slice(0, 32))}...</code></td>
        </tr>`
            )
            .join('\n');

    const adaptersTableRows = [...vb.adaptersExecuted, ...vb.adaptersUnavailable]
      .map(
        (ad) => `<tr>
        <td><code>${escapeHtml(ad.toolId)}</code></td>
        <td>${escapeHtml(ad.toolName)}</td>
        <td><code>${escapeHtml(ad.toolVersion)}</code></td>
        <td><strong>${escapeHtml(ad.executionStatus)}</strong></td>
        <td>${escapeHtml(ad.scopeExecuted || ad.reason || 'N/A')}</td>
      </tr>`
      )
      .join('\n');

    const analyzedFilesRows = Object.entries(vb.analyzedFilesSha256)
      .map(([k, v]) => `<li><strong>${escapeHtml(k)}:</strong> <code>${escapeHtml(v)}</code></li>`)
      .join('\n');

    const artifactRows = Object.entries(provenance.artifactHashes)
      .map(
        ([k, v]) =>
          `<li><strong>${escapeHtml(k)}:</strong> <code>${escapeHtml(v)}</code></li>`
      )
      .join('\n');

    return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>WinHood Audit Report v${escapeHtml(vb.winhoodVersion)} — ${escapeHtml(run.projectName)} (${escapeHtml(run.id)})</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 32px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Ubuntu, monospace;
      background: #080b10;
      color: #e2e8f0;
      line-height: 1.5;
    }
    .container { max-width: 1180px; margin: 0 auto; }
    header {
      border: 1px solid #1e293b;
      background: #0f172a;
      padding: 24px;
      border-radius: 8px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 16px;
    }
    h1 { margin: 0 0 8px 0; font-size: 22px; color: #f8fafc; }
    h2 {
      font-size: 16px;
      color: #38bdf8;
      border-bottom: 1px solid #1e293b;
      padding-bottom: 8px;
      margin-top: 28px;
    }
    .gate-badge {
      display: inline-block;
      padding: 8px 16px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 14px;
      background: ${decisionColor}22;
      color: ${decisionColor};
      border: 1px solid ${decisionColor};
    }
    .card {
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 18px;
      margin-bottom: 16px;
    }
    .epistemic-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 16px;
    }
    .epistemic-box {
      background: #0b1220;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 14px;
      font-size: 12px;
    }
    .epistemic-box h3 { margin: 0 0 8px 0; font-size: 13px; }
    .ep-fact h3 { color: #10b981; }
    .ep-heur h3 { color: #f59e0b; }
    .ep-unm h3 { color: #f87171; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      background: #0f172a;
      border: 1px solid #1e293b;
    }
    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid #1e293b;
      text-align: left;
      vertical-align: top;
    }
    th { background: #1e293b; color: #cbd5e1; font-weight: 600; }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      background: #1e293b;
      padding: 2px 5px;
      border-radius: 4px;
      color: #38bdf8;
    }
    .sev {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
    }
    .sev-blocker, .sev-critical { background: #7f1d1d; color: #fecaca; }
    .sev-high { background: #7c2d12; color: #fed7aa; }
    .sev-medium { background: #78350f; color: #fde68a; }
    .sev-low, .sev-info { background: #1e3a8a; color: #bfdbfe; }
    footer.provenance-footer {
      margin-top: 36px;
      padding: 20px;
      border: 1px solid #334155;
      background: #090d16;
      border-radius: 8px;
      font-size: 12px;
      color: #94a3b8;
    }
    footer.provenance-footer ul { margin: 8px 0; padding-left: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>WINHOOD BENCHMARKING v${escapeHtml(vb.winhoodVersion)} — RELATÓRIO DE AUDITORIA INDEPENDENTE (MODO MQR)</h1>
        <div>Execução: <code>${escapeHtml(run.id)}</code> | Projeto: <strong>${escapeHtml(run.projectName)}</strong> | Cobertura Efetiva: <strong>${vb.measuredCoveragePercent}%</strong></div>
        <div>Timestamp UTC: <code>${escapeHtml(vb.generatedAtUtc)}</code> | Evidence Chain Hash: <code>${escapeHtml(vb.evidenceChainHash)}</code></div>
      </div>
      <div>
        <div class="gate-badge">QUALITY GATE: ${escapeHtml(gateEval.decision)} (Exit Code ${gateEval.cliExitCode})</div>
      </div>
    </header>

    <section>
      <h2>1. Sumário Executivo &amp; ScoreCards</h2>
      <div class="card">
        <p>${escapeHtml(run.executiveSummary || 'Auditoria estática, fluxo de dados (Taint Analysis), segredos, IaC e composição de software (SCA/SBOM) concluída de forma determinística.')}</p>
      </div>
      ${scoreCardRows}
    </section>

    <section>
      <h2>2. Separação Epistêmica (Evidência Medida vs. Heurística vs. Não Medido)</h2>
      <div class="epistemic-grid">
        <div class="epistemic-box ep-fact">
          <h3>Evidência Medida (Fato)</h3>
          <ul>${vb.epistemicSeparation.measuredEvidenceFacts.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>
        </div>
        <div class="epistemic-box ep-heur">
          <h3>Inferência / Heurística</h3>
          <ul>${vb.epistemicSeparation.inferencesAndHeuristics.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>
        </div>
        <div class="epistemic-box ep-unm">
          <h3>Não Medido (NOT_MEASURED / UNAVAILABLE)</h3>
          <ul>${vb.epistemicSeparation.unmeasuredDimensions.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>
        </div>
      </div>
    </section>

    <section>
      <h2>3. Estado do Quality Gate (${escapeHtml(gateEval.gateName)} — v${escapeHtml(gateEval.gateVersion)})</h2>
      <table>
        <thead>
          <tr>
            <th>Condição</th>
            <th>Operador / Limite</th>
            <th>Valor Medido</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${gateEval.conditions
            .map(
              (c) => `<tr>
            <td>${escapeHtml(c.label)}</td>
            <td><code>${escapeHtml(c.operator)} ${escapeHtml(String(c.threshold))}</code></td>
            <td><code>${escapeHtml(String(c.actualValue ?? 'NOT_MEASURED'))}</code></td>
            <td><strong>${c.passed ? 'PASS' : c.inconclusive ? 'INCONCLUSIVE' : 'FAIL'}</strong></td>
          </tr>`
            )
            .join('\n')}
        </tbody>
      </table>
    </section>

    <section>
      <h2>4. Adaptadores Executados vs. Indisponíveis (${vb.adaptersExecuted.length} executados / ${vb.adaptersUnavailable.length} indisponíveis)</h2>
      <table>
        <thead>
          <tr>
            <th>Adapter ID</th>
            <th>Ferramenta</th>
            <th>Versão Real</th>
            <th>Status</th>
            <th>Escopo / Motivo</th>
          </tr>
        </thead>
        <tbody>
          ${adaptersTableRows || '<tr><td colspan="5" style="text-align:center;color:#94a3b8;">Nenhum adaptador registrado nesta execução.</td></tr>'}
        </tbody>
      </table>
    </section>

    <section>
      <h2>5. Tabela de Achados (${findings.length} total)</h2>
      <table>
        <thead>
          <tr>
            <th>Severidade</th>
            <th>Regra</th>
            <th>CWE</th>
            <th>OWASP</th>
            <th>Localização</th>
            <th>Descrição</th>
          </tr>
        </thead>
        <tbody>
          ${findingsRows}
        </tbody>
      </table>
    </section>

    <section>
      <h2>6. Trilha Criptográfica de Evidência</h2>
      <table>
        <thead>
          <tr>
            <th>Bloco</th>
            <th>Etapa</th>
            <th>Hash Anterior (SHA-256)</th>
            <th>Hash do Elo (SHA-256)</th>
          </tr>
        </thead>
        <tbody>
          ${chainRows}
        </tbody>
      </table>
    </section>

    <footer class="provenance-footer" id="winhood-provenance-footer">
      <strong>BLOCO DE PROVENIÊNCIA, VERACIDADE E ASSINATURA CRIPTOGRÁFICA DO RELATÓRIO</strong>
      <p>${escapeHtml(vb.scopeLimitationsDisclaimer)}</p>
      <ul>
        <li><strong>Versão do WinHood:</strong> <code>${escapeHtml(provenance.winhoodVersion)}</code> | <strong>Timestamp UTC:</strong> <code>${escapeHtml(provenance.generatedAt)}</code></li>
        <li><strong>Versão do Motor (Engine Version):</strong> <code>${escapeHtml(provenance.engineVersion)}</code></li>
        <li><strong>Cobertura de Medição Efetiva (measuredCoveragePercent):</strong> <code>${provenance.measuredCoveragePercent}%</code></li>
        <li><strong>Hash da Cadeia de Evidências (evidenceChainHash):</strong> <code>${escapeHtml(provenance.evidenceChainHash)}</code> (Estado: <code>${escapeHtml(vb.evidenceVerificationState)}</code> | Verificado: <code>${String(vb.evidenceChainVerified)}</code>)</li>
        <li><strong>Versão do Catálogo de Regras:</strong> <code>${escapeHtml(provenance.ruleCatalogVersion)}</code> (SHA-256: <code>${escapeHtml(provenance.ruleCatalogSha256)}</code>)</li>
        <li><strong>Hash do Código Analisado (Code SHA-256):</strong> <code>${escapeHtml(provenance.codeHashSha256)}</code></li>
        <li><strong>Versão do Quality Gate Aplicado:</strong> <code>${escapeHtml(provenance.appliedGateId)} v${escapeHtml(provenance.appliedGateVersion)}</code> (Gate SHA-256: <code>${escapeHtml(provenance.appliedGateHashSha256)}</code>)</li>
        <li><strong>Hash Canônico do Relatório (Report SHA-256):</strong> <code>${escapeHtml(provenance.reportContentSha256)}</code></li>
        <li><strong>Assinatura Criptográfica (${escapeHtml(provenance.hmacAlgorithm)}):</strong> <code>${escapeHtml(provenance.hmacSignature)}</code></li>
      </ul>
      ${
        analyzedFilesRows
          ? `<div><strong>SHA-256 dos Pacotes/Arquivos Analisados:</strong></div><ul>${analyzedFilesRows}</ul>`
          : ''
      }
      <div><strong>Hashes dos Artefatos Vinculados:</strong></div>
      <ul>
        ${artifactRows}
      </ul>
    </footer>
  </div>
</body>
</html>`;
  }

  /**
   * Generates a deterministic, audit-grade binary PDF 1.4 document (%PDF-1.4)
   * with valid byte-accurate xref offsets, multi-page pagination, Veracity & Provenance
   * Block, 3-way epistemic separation, embedded Report SHA-256, and HMAC-SHA256 signature.
   */
  public static generateFromRun(
    run: BenchmarkRun,
    hmacSecret = DEFAULT_REPORT_HMAC_KEY
  ): Buffer {
    const gateEval = QualityGateEngine.evaluateFromRun(run);
    const provenance = this.buildProvenanceFooter(run, hmacSecret);
    const vb = provenance.veracityBlock;
    const compliance = ComplianceMapper.buildTraceabilityMatrix({
      runId: run.id,
      findings: run.findings || [],
      deterministicTimestamp: run.completedAt || run.startedAt,
    });

    const rawLines: Array<{ text: string; bold?: boolean; size?: number }> = [];
    const pushSection = (title: string) => {
      rawLines.push({ text: '' });
      rawLines.push({ text: title, bold: true, size: 12 });
      rawLines.push({ text: '-'.repeat(84) });
    };
    const pushLine = (text: string, bold = false, size = 10) => {
      for (const w of wrapText(text, 88)) {
        rawLines.push({ text: w, bold, size });
      }
    };

    pushLine(`WINHOOD INDEPENDENT SOFTWARE AUDIT & BENCHMARKING REPORT (MQR MODE) v${vb.winhoodVersion}`, true, 13);
    pushLine(`Run ID: ${run.id} | Project: ${run.projectName} | Algorithm: ${run.algorithmVersion}`);
    pushLine(`Timestamp UTC: ${vb.generatedAtUtc} | Measured Coverage: ${vb.measuredCoveragePercent}%`);
    pushLine(`Evidence Chain Hash: ${vb.evidenceChainHash}`);

    pushSection('1. QUALITY GATE DECISION & VERSIONING');
    pushLine(`Gate: ${gateEval.gateName} (${gateEval.gateId} v${gateEval.gateVersion})`, true);
    pushLine(`Decision: ${gateEval.decision} | CLI Exit Code: ${gateEval.cliExitCode}`);
    pushLine(`Gate Hash (SHA-256): ${gateEval.gateHash}`);
    for (const cond of gateEval.conditions) {
      pushLine(
        `  [${cond.passed ? 'PASS' : cond.inconclusive ? 'INCONCLUSIVE' : 'FAIL'}] ${cond.label}: actual=${cond.actualValue ?? 'NOT_MEASURED'} (${cond.operator} ${cond.threshold})`
      );
    }

    pushSection('2. EXECUTIVE SUMMARY & SCORECARDS');
    pushLine(run.executiveSummary || 'No executive summary provided.');
    for (const sc of run.scoreCards || []) {
      const covInfo = vb.measuredCoverageBySoftware.find((m) => m.softwareId === sc.softwareId);
      const scoreStr =
        sc.separatedIndicators?.technicalScore !== null && sc.separatedIndicators?.technicalScore !== undefined
          ? `${sc.separatedIndicators.technicalScore.toFixed(2)} / 5.00`
          : 'NOT_MEASURED';
      pushLine(
        `- ${sc.softwareName} (${sc.softwareVersion}): Score=${scoreStr} | MeasuredCov=${covInfo?.measuredCoveragePercent ?? vb.measuredCoveragePercent}% | ScopeCov=${sc.separatedIndicators?.scopeCoveragePercent ?? 0}% | Confidence=${sc.separatedIndicators?.evidenceConfidence ?? 'LOW'} | Vulns=${sc.metricsSummary?.vulnerabilities ?? 0} | Secrets=${sc.metricsSummary?.secretsExposed ?? 0}`
      );
      if (covInfo?.weightRenormalizationApplied) {
        pushLine(`  Weight Renormalization: ${covInfo.renormalizationExplanation}`);
      }
    }

    pushSection('3. EPISTEMIC SEPARATION (MEASURED FACT vs HEURISTIC vs NOT_MEASURED)');
    pushLine('3.1 Evidencia Medida (Fato):', true);
    for (const fact of vb.epistemicSeparation.measuredEvidenceFacts.slice(0, 12)) {
      pushLine(`  [FACT] ${fact}`);
    }
    pushLine('3.2 Inferencia / Heuristica:', true);
    for (const heur of vb.epistemicSeparation.inferencesAndHeuristics.slice(0, 12)) {
      pushLine(`  [HEURISTIC] ${heur}`);
    }
    pushLine('3.3 Nao Medido (NOT_MEASURED / UNAVAILABLE):', true);
    for (const unm of vb.epistemicSeparation.unmeasuredDimensions.slice(0, 14)) {
      pushLine(`  [NOT_MEASURED] ${unm}`);
    }

    pushSection('4. ADAPTERS EXECUTED VS UNAVAILABLE & ANALYZED ARTIFACTS SHA-256');
    pushLine(
      `Executed Adapters: ${vb.adaptersExecuted.length} | Unavailable/Not Measured Adapters: ${vb.adaptersUnavailable.length}`,
      true
    );
    for (const ad of vb.adaptersExecuted.slice(0, 15)) {
      pushLine(`  [EXECUTED:${ad.executionStatus}] ${ad.toolId} (${ad.toolName} v${ad.toolVersion})`);
    }
    for (const ad of vb.adaptersUnavailable.slice(0, 15)) {
      pushLine(`  [${ad.executionStatus}] ${ad.toolId} (${ad.toolName}): ${ad.reason || 'UNAVAILABLE'}`);
    }
    for (const [k, v] of Object.entries(vb.analyzedFilesSha256)) {
      pushLine(`  Analyzed Artifact [${k}]: ${v}`);
    }

    pushSection('5. SIGNED EVIDENCE PROVENANCE & COMPLIANCE TRACEABILITY');
    pushLine(`Scope & Limitations: ${vb.scopeLimitationsDisclaimer}`);
    if (run.signedManifest) {
      const sm = run.signedManifest;
      pushLine(`Manifest ID: ${sm.manifestId} | Signature Algorithm: ${sm.signatureAlgorithm || 'HMAC-SHA256'}`);
      pushLine(`Verification State: ${vb.evidenceVerificationState} | Valid: ${vb.evidenceChainVerified}`);
      pushLine(`Root Chain SHA-256: ${sm.merkleOrChainRootSha256}`);
      pushLine(`Manifest Payload SHA-256: ${sm.manifestPayloadSha256}`);
    }
    pushLine(compliance.disclaimer);
    for (const [fw, entries] of Object.entries(compliance.byFramework)) {
      const detected = entries.filter((e) => e.findingsCount > 0);
      pushLine(`Framework ${fw}: ${detected.length}/${entries.length} controls with findings in analyzed scope`, true);
      for (const e of detected.slice(0, 6)) {
        pushLine(
          `  - ${e.controlId} (${e.controlTitle}): ${e.findingsCount} finding(s), CWEs=[${e.matchedCwes.join(', ')}]`
        );
      }
    }

    pushSection('6. FINDINGS SUMMARY (TOP 30 BY SEVERITY)');
    const sevOrder: Record<string, number> = {
      BLOCKER: 0,
      CRITICAL: 1,
      HIGH: 2,
      MEDIUM: 3,
      LOW: 4,
      INFO: 5,
    };
    const topFindings = [...(run.findings || [])]
      .sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9))
      .slice(0, 30);

    if (topFindings.length === 0) {
      pushLine('No active findings detected in analyzed scope.');
    } else {
      for (const f of topFindings) {
        pushLine(
          `[${f.severity}] ${f.originalRuleId} (${f.cwe || f.category}) - ${f.filePath}:${f.lineNumber} | ${f.title}`
        );
      }
    }

    pushSection('7. PROVENANCE FOOTER & CRYPTOGRAPHIC REPORT SIGNATURE');
    rawLines.push({ text: `Provenance-WinHood-Version: ${provenance.winhoodVersion}`, bold: true, size: 10 });
    rawLines.push({ text: `Provenance-Engine-Version: ${provenance.engineVersion}`, bold: true, size: 10 });
    rawLines.push({ text: `Provenance-Measured-Coverage-Percent: ${provenance.measuredCoveragePercent}`, size: 10 });
    rawLines.push({ text: `Provenance-EvidenceChain-SHA256: ${provenance.evidenceChainHash}`, bold: true, size: 10 });
    rawLines.push({ text: `Provenance-RuleCatalog-Version: ${provenance.ruleCatalogVersion}`, size: 10 });
    rawLines.push({ text: `Provenance-RuleCatalog-SHA256: ${provenance.ruleCatalogSha256}`, size: 10 });
    rawLines.push({ text: `Provenance-Code-SHA256: ${provenance.codeHashSha256}`, size: 10 });
    rawLines.push({
      text: `Provenance-Applied-Gate: ${provenance.appliedGateId} v${provenance.appliedGateVersion}`,
      size: 10,
    });
    rawLines.push({ text: `Provenance-Gate-SHA256: ${provenance.appliedGateHashSha256}`, size: 10 });
    for (const [k, v] of Object.entries(provenance.artifactHashes)) {
      rawLines.push({ text: `Provenance-Artifact-${k}: ${v}`, size: 10 });
    }
    rawLines.push({ text: `Report-SHA256: ${provenance.reportContentSha256}`, bold: true, size: 10 });
    rawLines.push({ text: `Report-HMAC-SHA256: ${provenance.hmacSignature}`, bold: true, size: 10 });

    const linesPerPage = 48;
    const pages: Array<typeof rawLines> = [];
    for (let i = 0; i < rawLines.length; i += linesPerPage) {
      pages.push(rawLines.slice(i, i + linesPerPage));
    }
    if (pages.length === 0) {
      pages.push([{ text: 'WinHood Empty Report' }]);
    }

    const objects: string[] = [];
    const pageObjIds: number[] = [];

    for (let p = 0; p < pages.length; p++) {
      const pageObjId = 5 + p * 2;
      const contentObjId = pageObjId + 1;
      pageObjIds.push(pageObjId);

      const pageLines = pages[p]!;
      const streamLines: string[] = ['BT', '/F1 10 Tf', '42 752 Td'];
      let currentY = 752;
      for (const item of pageLines) {
        const fontRef = item.bold ? '/F2' : '/F1';
        const fontSize = item.size || 10;
        const step = fontSize >= 12 ? 15 : 13;
        streamLines.push(`${fontRef} ${fontSize} Tf`);
        streamLines.push(`(${toPdfAscii(item.text)}) Tj`);
        streamLines.push(`0 -${step} Td`);
        currentY -= step;
        if (currentY < 45) break;
      }
      streamLines.push(
        `(${toPdfAscii(`WinHood v${WINHOOD_PLATFORM_VERSION} Signed Audit Report - Page ${p + 1}/${pages.length} | SHA256:${provenance.reportContentSha256.slice(0, 16)}`)}) Tj`
      );
      streamLines.push('ET');
      const streamContent = streamLines.join('\n');

      objects[pageObjId - 1] =
        `${pageObjId} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentObjId} 0 R >>\nendobj\n`;
      objects[contentObjId - 1] =
        `${contentObjId} 0 obj\n<< /Length ${Buffer.byteLength(streamContent, 'latin1')} >>\nstream\n${streamContent}\nendstream\nendobj\n`;
    }

    objects[0] = `1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n`;
    objects[1] = `2 0 obj\n<< /Type /Pages /Kids [${pageObjIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${pageObjIds.length} >>\nendobj\n`;
    objects[2] = `3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n`;
    objects[3] = `4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n`;

    const chunks: string[] = ['%PDF-1.4\n'];
    const offsets: number[] = [0];
    let byteCursor = Buffer.byteLength(chunks[0]!, 'latin1');

    for (let i = 0; i < objects.length; i++) {
      offsets.push(byteCursor);
      const objStr = objects[i]!;
      chunks.push(objStr);
      byteCursor += Buffer.byteLength(objStr, 'latin1');
    }

    const xrefOffset = byteCursor;
    const xrefLines: string[] = [`xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`];
    for (let i = 1; i <= objects.length; i++) {
      xrefLines.push(`${String(offsets[i]).padStart(10, '0')} 00000 n \n`);
    }
    const trailer = `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;

    chunks.push(xrefLines.join(''), trailer);
    return Buffer.from(chunks.join(''), 'latin1');
  }

  public static generateCsvReport(
    run: BenchmarkRun,
    hmacSecret = DEFAULT_REPORT_HMAC_KEY
  ): string {
    const provenance = this.buildProvenanceFooter(run, hmacSecret);
    const vb = provenance.veracityBlock;
    const lines: string[] = [
      `# WinHoodVersion=${vb.winhoodVersion},RunId=${run.id},GeneratedAtUTC=${vb.generatedAtUtc},MeasuredCoveragePercent=${vb.measuredCoveragePercent},EvidenceChainHash=${vb.evidenceChainHash},EvidenceVerified=${vb.evidenceChainVerified},ReportSHA256=${provenance.reportContentSha256},ReportHMAC=${provenance.hmacSignature}`,
      `# AdaptersExecuted=${vb.adaptersExecuted.map((a) => `${a.toolId}@${a.toolVersion}`).join(';') || 'NONE'},AdaptersUnavailable=${vb.adaptersUnavailable.map((a) => `${a.toolId}:${a.executionStatus}`).join(';') || 'NONE'}`,
      `# ScopeDisclaimer=${vb.scopeLimitationsDisclaimer}`,
    ];

    const headers = [
      'RecordType',
      'EpistemicClass',
      'FindingID',
      'Software',
      'Version',
      'Category',
      'Severity',
      'ValidationStatus',
      'Tool',
      'RuleID',
      'File',
      'Line',
      'CWE',
      'CVE',
      'CVSS',
      'MeasuredCoveragePercent',
      'EvidenceSHA256',
      'Title',
      'Details',
    ];
    lines.push(headers.join(','));

    for (const sc of run.scoreCards || []) {
      const covInfo = vb.measuredCoverageBySoftware.find((m) => m.softwareId === sc.softwareId);
      const scoreVal =
        sc.separatedIndicators?.technicalScore !== null &&
        sc.separatedIndicators?.technicalScore !== undefined
          ? sc.separatedIndicators.technicalScore.toFixed(2)
          : 'NOT_MEASURED';
      lines.push(
        [
          'SCORECARD',
          'MEASURED_FACT',
          `score-${sc.softwareId}`,
          sc.softwareName,
          sc.softwareVersion,
          'OVERALL',
          'INFO',
          sc.separatedIndicators?.qualityGateDecision || sc.qualityGate?.status || 'INCONCLUSIVE',
          'WinHood Scoring Engine',
          run.algorithmVersion,
          'SCORECARD',
          0,
          '',
          '',
          scoreVal,
          covInfo?.measuredCoveragePercent ?? vb.measuredCoveragePercent,
          vb.evidenceChainHash,
          `OverallScore=${scoreVal}/5.00 (${sc.classificationLabel})`,
          covInfo?.renormalizationExplanation || '',
        ]
          .map(escapeCsvCell)
          .join(',')
      );
    }

    for (const f of run.findings || []) {
      lines.push(
        [
          'FINDING',
          'MEASURED_FACT',
          f.id,
          f.softwareName,
          f.softwareVersion,
          f.category,
          f.severity,
          f.validationStatus,
          f.toolName,
          f.originalRuleId,
          f.filePath,
          f.lineNumber,
          f.cwe || '',
          f.cve || '',
          f.cvss ?? '',
          vb.measuredCoveragePercent,
          f.evidenceSha256,
          f.title,
          f.whyItIsAnIssue || f.description || '',
        ]
          .map(escapeCsvCell)
          .join(',')
      );
    }

    for (const heur of vb.epistemicSeparation.inferencesAndHeuristics) {
      lines.push(
        [
          'EPISTEMIC_NOTE',
          'INFERENCE_HEURISTIC',
          '',
          run.projectName,
          vb.winhoodVersion,
          'HEURISTIC',
          'INFO',
          'DOCUMENTED',
          'WinHood Veracity Engine',
          'EPISTEMIC_HEURISTIC',
          '',
          0,
          '',
          '',
          '',
          vb.measuredCoveragePercent,
          vb.evidenceChainHash,
          'Inferência / Heurística',
          heur,
        ]
          .map(escapeCsvCell)
          .join(',')
      );
    }

    for (const unm of vb.epistemicSeparation.unmeasuredDimensions) {
      lines.push(
        [
          'EPISTEMIC_NOTE',
          'NOT_MEASURED_OR_UNAVAILABLE',
          '',
          run.projectName,
          vb.winhoodVersion,
          'UNMEASURED',
          'INFO',
          'NOT_MEASURED',
          'WinHood Veracity Engine',
          'EPISTEMIC_UNMEASURED',
          '',
          0,
          '',
          '',
          '',
          vb.measuredCoveragePercent,
          vb.evidenceChainHash,
          'Não Medido (NOT_MEASURED / UNAVAILABLE)',
          unm,
        ]
          .map(escapeCsvCell)
          .join(',')
      );
    }

    return lines.join('\n');
  }

  /**
   * Unified multi-format ReportExporter supporting pdf, html, sarif, json, and csv.
   */
  public static exportReport(
    run: BenchmarkRun,
    format: 'pdf' | 'html' | 'sarif' | 'json' | 'csv',
    hmacSecret = DEFAULT_REPORT_HMAC_KEY
  ): { contentType: string; buffer: Buffer; provenance: ReportProvenanceFooter } {
    const provenance = this.buildProvenanceFooter(run, hmacSecret);
    const gateEval = QualityGateEngine.evaluateFromRun(run);

    if (format === 'pdf') {
      const buf = this.generateFromRun(run, hmacSecret);
      return { contentType: 'application/pdf', buffer: buf, provenance };
    }

    if (format === 'html') {
      const html = this.generateSelfContainedHtml(run, hmacSecret);
      return {
        contentType: 'text/html; charset=utf-8',
        buffer: Buffer.from(html, 'utf8'),
        provenance,
      };
    }

    if (format === 'csv') {
      const csv = this.generateCsvReport(run, hmacSecret);
      return {
        contentType: 'text/csv; charset=utf-8',
        buffer: Buffer.from(csv, 'utf8'),
        provenance,
      };
    }

    if (format === 'sarif') {
      const sarif = SarifCodec.exportSarif210(run.findings || [], {
        toolVersion: provenance.engineVersion,
      }) as unknown as Record<string, unknown>;
      const runs = (sarif.runs as Array<Record<string, unknown>>) || [];
      if (runs[0]) {
        runs[0].properties = {
          ...((runs[0].properties as Record<string, unknown>) || {}),
          winhoodVersion: WINHOOD_PLATFORM_VERSION,
          gateDecision: gateEval.decision,
          gateVersion: gateEval.gateVersion,
          evidenceChainHash: provenance.evidenceChainHash,
          measuredCoveragePercent: provenance.measuredCoveragePercent,
          veracityBlock: provenance.veracityBlock,
          provenanceFooter: provenance,
        };
      }
      return {
        contentType: 'application/sarif+json; charset=utf-8',
        buffer: Buffer.from(JSON.stringify(sarif, null, 2), 'utf8'),
        provenance,
      };
    }

    const jsonReport = {
      schemaVersion: 'winhood-audit-report/v4.4.0',
      winhoodVersion: WINHOOD_PLATFORM_VERSION,
      runId: run.id,
      projectName: run.projectName,
      startedAt: run.startedAt,
      completedAt: run.completedAt || provenance.generatedAt,
      executiveSummary: run.executiveSummary,
      measuredCoveragePercent: provenance.measuredCoveragePercent,
      evidenceChainHash: provenance.evidenceChainHash,
      qualityGate: gateEval,
      scoreCards: run.scoreCards,
      findingsCount: (run.findings || []).length,
      findings: run.findings || [],
      evidenceVerification: run.evidenceVerification,
      signedManifest: run.signedManifest,
      veracityBlock: provenance.veracityBlock,
      epistemicSeparation: provenance.veracityBlock.epistemicSeparation,
      provenanceFooter: provenance,
    };

    return {
      contentType: 'application/json; charset=utf-8',
      buffer: Buffer.from(JSON.stringify(jsonReport, null, 2), 'utf8'),
      provenance,
    };
  }
}

export const ReportExporter = PdfReportGenerator;
