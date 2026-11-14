import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { SsrfGuard } from '../execution/SsrfGuard';
import { KeyManagementService } from '../security/KeyManagementService';
import type {
  BenchmarkRun,
  ExecutiveQualityGateDecision,
  NormalizedFinding,
  SoftwareScoreCard,
} from '../types/benchmark';

export type GateOperator = 'EQ' | 'LTE' | 'GTE' | 'LT' | 'GT';

export type GateMetricKey =
  | 'blocker_findings'
  | 'critical_findings'
  | 'high_findings'
  | 'secrets_exposed'
  | 'iac_critical_findings'
  | 'sca_critical_findings'
  | 'scope_coverage_percent'
  | 'evidence_confidence_score'
  | 'overall_score';

export interface QualityGateConditionRule {
  id: string;
  metricKey: GateMetricKey;
  label: string;
  operator: GateOperator;
  threshold: number;
  severityOnFail: 'BLOCKER' | 'RESERVATION';
}

export interface QualityGateDefinition {
  id: string;
  name: string;
  version: string;
  description: string;
  requireVerifiedEvidence: boolean;
  createdAt: string;
  conditions: QualityGateConditionRule[];
}

export interface EvaluatedGateCondition {
  id: string;
  metricKey: GateMetricKey;
  label: string;
  operator: GateOperator;
  threshold: number;
  actualValue: number | null;
  passed: boolean;
  inconclusive: boolean;
  severityOnFail: 'BLOCKER' | 'RESERVATION';
  reason: string;
}

export type CanonicalGateDecision =
  | 'APPROVED'
  | 'APPROVED_WITH_RESERVATIONS'
  | 'BLOCKED'
  | 'INCONCLUSIVE'
  | 'REJECTED';

export interface QualityGateEvaluationResult {
  gateId: string;
  gateName: string;
  gateVersion: string;
  gateHash: string;
  decision: CanonicalGateDecision;
  cliExitCode: 0 | 1 | 2;
  evaluatedAt: string;
  conditionsMet: number;
  conditionsFailed: number;
  conditionsInconclusive: number;
  conditions: EvaluatedGateCondition[];
  summary: string;
}

export const BUILTIN_QUALITY_GATES: QualityGateDefinition[] = [
  {
    id: 'winhood-standard-v2',
    name: 'WinHood Standard Engineering Gate',
    version: '2.1.0',
    description:
      'Gate padrão independente: bloqueia achados BLOCKER/CRITICAL e segredos expostos; exige cobertura mínima de escopo >= 50%.',
    requireVerifiedEvidence: true,
    createdAt: '2026-11-14T00:00:00Z',
    conditions: [
      {
        id: 'cond-no-blocker',
        metricKey: 'blocker_findings',
        label: 'Achados BLOCKER',
        operator: 'EQ',
        threshold: 0,
        severityOnFail: 'BLOCKER',
      },
      {
        id: 'cond-no-critical',
        metricKey: 'critical_findings',
        label: 'Achados CRITICAL',
        operator: 'EQ',
        threshold: 0,
        severityOnFail: 'BLOCKER',
      },
      {
        id: 'cond-no-secrets',
        metricKey: 'secrets_exposed',
        label: 'Segredos Expostos',
        operator: 'EQ',
        threshold: 0,
        severityOnFail: 'BLOCKER',
      },
      {
        id: 'cond-min-coverage',
        metricKey: 'scope_coverage_percent',
        label: 'Cobertura de Escopo (%)',
        operator: 'GTE',
        threshold: 50,
        severityOnFail: 'RESERVATION',
      },
      {
        id: 'cond-min-confidence',
        metricKey: 'evidence_confidence_score',
        label: 'Confiança Mínima da Evidência (1=LOW,2=MED,3=HIGH)',
        operator: 'GTE',
        threshold: 2,
        severityOnFail: 'RESERVATION',
      },
    ],
  },
  {
    id: 'winhood-zero-trust-v2',
    name: 'WinHood Zero-Trust Security Audit Gate',
    version: '2.2.0',
    description:
      'Gate rigoroso para due diligence e pipelines críticos: 0 críticos/segredos/IaC críticos, <= 2 HIGH e cobertura >= 70%.',
    requireVerifiedEvidence: true,
    createdAt: '2026-11-14T00:00:00Z',
    conditions: [
      {
        id: 'zt-no-blocker',
        metricKey: 'blocker_findings',
        label: 'Achados BLOCKER',
        operator: 'EQ',
        threshold: 0,
        severityOnFail: 'BLOCKER',
      },
      {
        id: 'zt-no-critical',
        metricKey: 'critical_findings',
        label: 'Achados CRITICAL',
        operator: 'EQ',
        threshold: 0,
        severityOnFail: 'BLOCKER',
      },
      {
        id: 'zt-max-high',
        metricKey: 'high_findings',
        label: 'Achados HIGH',
        operator: 'LTE',
        threshold: 2,
        severityOnFail: 'BLOCKER',
      },
      {
        id: 'zt-no-secrets',
        metricKey: 'secrets_exposed',
        label: 'Segredos Expostos',
        operator: 'EQ',
        threshold: 0,
        severityOnFail: 'BLOCKER',
      },
      {
        id: 'zt-no-iac-crit',
        metricKey: 'iac_critical_findings',
        label: 'Achados IaC Críticos',
        operator: 'EQ',
        threshold: 0,
        severityOnFail: 'BLOCKER',
      },
      {
        id: 'zt-min-coverage',
        metricKey: 'scope_coverage_percent',
        label: 'Cobertura de Escopo (%)',
        operator: 'GTE',
        threshold: 70,
        severityOnFail: 'BLOCKER',
      },
      {
        id: 'zt-high-confidence',
        metricKey: 'evidence_confidence_score',
        label: 'Confiança da Evidência (HIGH=3)',
        operator: 'GTE',
        threshold: 3,
        severityOnFail: 'RESERVATION',
      },
    ],
  },
  {
    id: 'winhood-release-audit-v1',
    name: 'WinHood Release Comparative Gate',
    version: '1.0.0',
    description:
      'Gate de release comparativo exigindo pontuação técnica >= 3.00/5.00, 0 BLOCKERS e cobertura >= 60%.',
    requireVerifiedEvidence: true,
    createdAt: '2026-11-14T00:00:00Z',
    conditions: [
      {
        id: 'rel-no-blocker',
        metricKey: 'blocker_findings',
        label: 'Achados BLOCKER',
        operator: 'EQ',
        threshold: 0,
        severityOnFail: 'BLOCKER',
      },
      {
        id: 'rel-min-score',
        metricKey: 'overall_score',
        label: 'Nota Técnica Geral (0-5)',
        operator: 'GTE',
        threshold: 3.0,
        severityOnFail: 'BLOCKER',
      },
      {
        id: 'rel-min-coverage',
        metricKey: 'scope_coverage_percent',
        label: 'Cobertura de Escopo (%)',
        operator: 'GTE',
        threshold: 60,
        severityOnFail: 'RESERVATION',
      },
    ],
  },
];

function evaluateOperator(actual: number, op: GateOperator, threshold: number): boolean {
  switch (op) {
    case 'EQ':
      return actual === threshold;
    case 'LTE':
      return actual <= threshold;
    case 'GTE':
      return actual >= threshold;
    case 'LT':
      return actual < threshold;
    case 'GT':
      return actual > threshold;
    default:
      return false;
  }
}

function confidenceToNumeric(conf?: 'HIGH' | 'MEDIUM' | 'LOW'): number | null {
  if (conf === 'HIGH') return 3;
  if (conf === 'MEDIUM') return 2;
  if (conf === 'LOW') return 1;
  return null;
}

export class QualityGateEngine {
  private static readonly customGates = new Map<string, QualityGateDefinition>();

  public static listGates(): QualityGateDefinition[] {
    return [...BUILTIN_QUALITY_GATES, ...Array.from(QualityGateEngine.customGates.values())];
  }

  public static registerGate(gate: QualityGateDefinition): QualityGateDefinition {
    QualityGateEngine.customGates.set(gate.id, gate);
    return gate;
  }

  public static getGateById(gateId?: string): QualityGateDefinition {
    if (!gateId) return BUILTIN_QUALITY_GATES[0]!;
    return (
      QualityGateEngine.listGates().find((g) => g.id === gateId) || BUILTIN_QUALITY_GATES[0]!
    );
  }

  public static computeGateHash(gate: QualityGateDefinition): string {
    return crypto
      .createHash('sha256')
      .update(
        JSON.stringify({
          id: gate.id,
          version: gate.version,
          requireVerifiedEvidence: gate.requireVerifiedEvidence,
          conditions: gate.conditions,
        }),
        'utf8'
      )
      .digest('hex');
  }

  public static exitCodeForDecision(
    decision: CanonicalGateDecision | ExecutiveQualityGateDecision | string | undefined
  ): 0 | 1 | 2 | 3 {
    switch (decision) {
      case 'APPROVED':
      case 'APPROVED_WITH_RESERVATIONS':
      case 'APROVADO':
      case 'APROVADO COM RESSALVAS':
        return 0;
      case 'BLOCKED':
      case 'REJECTED':
      case 'REPROVADO':
        return 1;
      case 'INCONCLUSIVE':
      case 'INCONCLUSIVO':
      case 'NÃO AVALIADO':
        return 2;
      default:
        return 3;
    }
  }

  public static evaluate(params: {
    gate?: QualityGateDefinition;
    gateId?: string;
    findings: NormalizedFinding[];
    scoreCard?: SoftwareScoreCard | null;
    scopeCoveragePercent?: number | null;
    evidenceConfidence?: 'HIGH' | 'MEDIUM' | 'LOW';
    evidenceVerified?: boolean;
    deterministicTimestamp?: string;
  }): QualityGateEvaluationResult {
    const gate = params.gate || QualityGateEngine.getGateById(params.gateId);
    const gateHash = QualityGateEngine.computeGateHash(gate);
    const evaluatedAt = params.deterministicTimestamp || new Date().toISOString();

    const activeFindings = params.findings.filter((f) => {
      const st = f.lifecycleState || f.validationStatus;
      return (
        st !== 'FALSE_POSITIVE' &&
        st !== 'FALSE_POSITIVE_REVIEWED' &&
        st !== 'ACCEPTED' &&
        st !== 'ACCEPTED_RISK' &&
        st !== 'VERIFIED_RESOLVED' &&
        st !== 'NOT_REPRODUCIBLE'
      );
    });

    const blockerCount = activeFindings.filter((f) => f.severity === 'BLOCKER').length;
    const criticalCount = activeFindings.filter((f) => f.severity === 'CRITICAL').length;
    const highCount = activeFindings.filter((f) => f.severity === 'HIGH').length;
    const secretsCount = activeFindings.filter((f) => f.category === 'SECRETS').length;
    const iacCriticalCount = activeFindings.filter(
      (f) => f.category === 'IAC' && (f.severity === 'BLOCKER' || f.severity === 'CRITICAL')
    ).length;
    const scaCriticalCount = activeFindings.filter(
      (f) => f.category === 'SCA' && (f.severity === 'BLOCKER' || f.severity === 'CRITICAL')
    ).length;

    const coverageVal =
      params.scopeCoveragePercent ??
      params.scoreCard?.separatedIndicators?.scopeCoveragePercent ??
      null;
    const confScore = confidenceToNumeric(
      params.evidenceConfidence ?? params.scoreCard?.separatedIndicators?.evidenceConfidence
    );
    const overallScore = params.scoreCard?.separatedIndicators?.technicalScore ?? null;

    const metricsMap: Record<GateMetricKey, number | null> = {
      blocker_findings: blockerCount,
      critical_findings: criticalCount,
      high_findings: highCount,
      secrets_exposed: secretsCount,
      iac_critical_findings: iacCriticalCount,
      sca_critical_findings: scaCriticalCount,
      scope_coverage_percent: coverageVal,
      evidence_confidence_score: confScore,
      overall_score: overallScore,
    };

    const evaluatedConditions: EvaluatedGateCondition[] = gate.conditions.map((cond) => {
      const actual = metricsMap[cond.metricKey];
      if (actual === null || actual === undefined || Number.isNaN(actual)) {
        return {
          id: cond.id,
          metricKey: cond.metricKey,
          label: cond.label,
          operator: cond.operator,
          threshold: cond.threshold,
          actualValue: null,
          passed: false,
          inconclusive: true,
          severityOnFail: cond.severityOnFail,
          reason: `Métrica "${cond.label}" não foi mensurada (NOT_MEASURED).`,
        };
      }
      const passed = evaluateOperator(actual, cond.operator, cond.threshold);
      return {
        id: cond.id,
        metricKey: cond.metricKey,
        label: cond.label,
        operator: cond.operator,
        threshold: cond.threshold,
        actualValue: actual,
        passed,
        inconclusive: false,
        severityOnFail: cond.severityOnFail,
        reason: passed
          ? `${cond.label}: ${actual} atende ${cond.operator} ${cond.threshold}.`
          : `${cond.label}: ${actual} viola ${cond.operator} ${cond.threshold}.`,
      };
    });

    const conditionsMet = evaluatedConditions.filter((c) => c.passed).length;
    const conditionsFailed = evaluatedConditions.filter((c) => !c.passed && !c.inconclusive).length;
    const conditionsInconclusive = evaluatedConditions.filter((c) => c.inconclusive).length;

    const hasBlockerFailure = evaluatedConditions.some(
      (c) => !c.passed && !c.inconclusive && c.severityOnFail === 'BLOCKER'
    );
    const hasReservationFailure = evaluatedConditions.some(
      (c) => !c.passed && !c.inconclusive && c.severityOnFail === 'RESERVATION'
    );

    let decision: CanonicalGateDecision;
    if (gate.requireVerifiedEvidence && params.evidenceVerified === false) {
      decision = 'INCONCLUSIVE';
    } else if (hasBlockerFailure) {
      decision = blockerCount > 0 && criticalCount > 0 ? 'REJECTED' : 'BLOCKED';
    } else if (conditionsInconclusive > 0) {
      decision = 'INCONCLUSIVE';
    } else if (hasReservationFailure) {
      decision = 'APPROVED_WITH_RESERVATIONS';
    } else {
      decision = 'APPROVED';
    }

    const cliExitCode = QualityGateEngine.exitCodeForDecision(decision);
    const exitCodeNormalized: 0 | 1 | 2 = cliExitCode === 3 ? 2 : cliExitCode;

    return {
      gateId: gate.id,
      gateName: gate.name,
      gateVersion: gate.version,
      gateHash,
      decision,
      cliExitCode: exitCodeNormalized,
      evaluatedAt,
      conditionsMet,
      conditionsFailed,
      conditionsInconclusive,
      conditions: evaluatedConditions,
      summary: `Gate "${gate.name}" v${gate.version} => ${decision} (exit=${exitCodeNormalized}; ${conditionsMet}/${evaluatedConditions.length} condições atendidas).`,
    };
  }

  public static evaluateFromRun(
    run: BenchmarkRun,
    gateId?: string,
    deterministicTimestamp?: string
  ): QualityGateEvaluationResult {
    const primaryCard =
      run.scoreCards.find((s) => s.softwareId === run.winnerSoftwareId) || run.scoreCards[0] || null;
    const activeFindings = primaryCard
      ? run.findings.filter((f) => f.softwareId === primaryCard.softwareId)
      : run.findings;
    return QualityGateEngine.evaluate({
      gateId: gateId || run.qualityGateId,
      findings: activeFindings,
      scoreCard: primaryCard,
      scopeCoveragePercent: primaryCard?.separatedIndicators?.scopeCoveragePercent ?? null,
      evidenceConfidence: primaryCard?.separatedIndicators?.evidenceConfidence,
      evidenceVerified: run.evidenceVerification?.valid ?? undefined,
      deterministicTimestamp,
    });
  }

  public static signWebhookPayload(params: {
    event: 'quality_gate.evaluated';
    runId?: string;
    evaluation: QualityGateEvaluationResult;
    secret?: string;
    timestampEpochSec?: number;
  }): {
    bodyJson: string;
    signatureHeader: string;
    timestampEpochSec: number;
    keyId: string;
    payloadSha256: string;
  } {
    const activeKey = KeyManagementService.getActiveEvidenceHmacKey();
    const secret = params.secret || activeKey.secret;
    const timestampEpochSec = params.timestampEpochSec ?? Math.floor(Date.now() / 1000);
    const bodyObj = {
      schemaVersion: '1.0.0',
      event: params.event,
      runId: params.runId || null,
      timestampEpochSec,
      gate: {
        id: params.evaluation.gateId,
        name: params.evaluation.gateName,
        version: params.evaluation.gateVersion,
        hash: params.evaluation.gateHash,
        decision: params.evaluation.decision,
        cliExitCode: params.evaluation.cliExitCode,
        conditionsMet: params.evaluation.conditionsMet,
        conditionsFailed: params.evaluation.conditionsFailed,
        conditionsInconclusive: params.evaluation.conditionsInconclusive,
        summary: params.evaluation.summary,
      },
    };
    const bodyJson = JSON.stringify(bodyObj);
    const signedInput = `${timestampEpochSec}.${bodyJson}`;
    const hmacHex = crypto.createHmac('sha256', secret).update(signedInput, 'utf8').digest('hex');
    const payloadSha256 = crypto.createHash('sha256').update(bodyJson, 'utf8').digest('hex');
    return {
      bodyJson,
      signatureHeader: `t=${timestampEpochSec},v1=${hmacHex}`,
      timestampEpochSec,
      keyId: params.secret ? 'CUSTOM_WEBHOOK_SECRET' : activeKey.keyId,
      payloadSha256,
    };
  }

  public static verifyWebhookSignature(params: {
    bodyJson: string;
    signatureHeader: string;
    secret: string;
    maxSkewSeconds?: number;
    nowEpochSec?: number;
  }): { valid: boolean; reason: string } {
    const parts = Object.fromEntries(
      params.signatureHeader.split(',').map((kv) => {
        const idx = kv.indexOf('=');
        return idx > 0 ? [kv.slice(0, idx).trim(), kv.slice(idx + 1).trim()] : ['', ''];
      })
    );
    const ts = Number.parseInt(parts.t || '', 10);
    const sig = parts.v1 || '';
    if (!Number.isFinite(ts) || !sig) {
      return { valid: false, reason: 'INVALID_SIGNATURE_HEADER_FORMAT' };
    }
    if (params.maxSkewSeconds !== undefined) {
      const nowSec = params.nowEpochSec ?? Math.floor(Date.now() / 1000);
      if (Math.abs(nowSec - ts) > params.maxSkewSeconds) {
        return { valid: false, reason: 'WEBHOOK_TIMESTAMP_OUT_OF_WINDOW' };
      }
    }
    const expected = crypto
      .createHmac('sha256', params.secret)
      .update(`${ts}.${params.bodyJson}`, 'utf8')
      .digest('hex');
    const a = Buffer.from(expected, 'hex');
    const b = Buffer.from(sig, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return { valid: false, reason: 'WEBHOOK_HMAC_MISMATCH' };
    }
    return { valid: true, reason: 'WEBHOOK_SIGNATURE_VERIFIED' };
  }

  public static async dispatchSignedWebhook(params: {
    targetUrl: string;
    evaluation: QualityGateEvaluationResult;
    runId?: string;
    secret?: string;
    timeoutMs?: number;
  }): Promise<{
    delivered: boolean;
    blockedBySsrf: boolean;
    statusCode: number | null;
    signatureHeader: string;
    payloadSha256: string;
    message: string;
  }> {
    const signed = QualityGateEngine.signWebhookPayload({
      event: 'quality_gate.evaluated',
      runId: params.runId,
      evaluation: params.evaluation,
      secret: params.secret,
    });

    const ssrfCheck = await SsrfGuard.validateUrl({
      targetUrl: params.targetUrl,
      allowExplicitLoopback: false,
    });

    if (!ssrfCheck.allowed || !ssrfCheck.parsedUrl || !ssrfCheck.pinnedIp) {
      return {
        delivered: false,
        blockedBySsrf: true,
        statusCode: null,
        signatureHeader: signed.signatureHeader,
        payloadSha256: signed.payloadSha256,
        message: `SSRF_BLOCKED: ${ssrfCheck.reason}`,
      };
    }

    const parsed = ssrfCheck.parsedUrl;
    const pinnedIp = ssrfCheck.pinnedIp;
    const family = net.isIPv6(pinnedIp) ? 6 : 4;
    const timeoutMs = params.timeoutMs ?? 5000;

    try {
      const statusCode = await new Promise<number>((resolve, reject) => {
        const transport = parsed.protocol === 'https:' ? https : http;
        const req = transport.request(
          {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: `${parsed.pathname}${parsed.search}`,
            method: 'POST',
            timeout: timeoutMs,
            lookup: (_h, _o, cb) => cb(null, pinnedIp, family),
            headers: {
              Host: parsed.host,
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(signed.bodyJson, 'utf8'),
              'User-Agent': 'WinHood-QualityGate-Webhook/1.0',
              'X-WinHood-Event': 'quality_gate.evaluated',
              'X-WinHood-Signature': signed.signatureHeader,
              'X-WinHood-Key-Id': signed.keyId,
            },
          },
          (res) => {
            res.on('data', () => {});
            res.on('end', () => resolve(res.statusCode || 0));
          }
        );
        req.on('timeout', () => req.destroy(new Error(`Timeout after ${timeoutMs}ms`)));
        req.on('error', reject);
        req.write(signed.bodyJson);
        req.end();
      });

      return {
        delivered: statusCode >= 200 && statusCode < 300,
        blockedBySsrf: false,
        statusCode,
        signatureHeader: signed.signatureHeader,
        payloadSha256: signed.payloadSha256,
        message:
          statusCode >= 200 && statusCode < 300
            ? `Webhook entregue com assinatura HMAC-SHA256 (HTTP ${statusCode}).`
            : `Webhook respondido com HTTP ${statusCode}.`,
      };
    } catch (err: any) {
      return {
        delivered: false,
        blockedBySsrf: false,
        statusCode: null,
        signatureHeader: signed.signatureHeader,
        payloadSha256: signed.payloadSha256,
        message: `Falha ao entregar webhook: ${err?.message || String(err)}`,
      };
    }
  }
}
