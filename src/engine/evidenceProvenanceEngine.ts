import crypto from 'crypto';
import { KeyManagementService } from '../security/KeyManagementService';
import {
  EvidenceRecord,
  NormalizedFinding,
  SignedEvidenceManifest,
  Software,
  ToolExecutionRecord,
  VeracityCheckResult,
} from '../types/benchmark';

export const GENESIS_EVIDENCE_HASH = '0'.repeat(64);

function sha256Hex(payload: string): string {
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

function hmacSha256Hex(payload: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
}

export function computeCanonicalEvidenceHash(
  record: Omit<EvidenceRecord, 'sha256'>,
  previousRecordSha256: string
): string {
  const canonicalPayload = JSON.stringify({
    id: record.id,
    runId: record.runId,
    softwareId: record.softwareId,
    softwareName: record.softwareName,
    version: record.version,
    commitHash: record.commitHash || '',
    sourceHash: record.sourceHash || '',
    criterionId: record.criterionId || '',
    evidenceType: record.evidenceType || 'STATIC_AST_FINDING',
    origin: record.origin || 'WINHOOD_ENGINE',
    responsibleActor: record.responsibleActor || 'system',
    category: record.category,
    toolName: record.toolName,
    toolVersion: record.toolVersion,
    timestamp: record.timestamp,
    resultSummary: record.resultSummary,
    severity: record.severity,
    fileOrComponent: record.fileOrComponent,
    validationStatus: record.validationStatus,
    rawPayloadPreview: record.rawPayloadPreview,
    immutableIndex: record.immutableIndex,
    previousRecordSha256,
  });
  return sha256Hex(canonicalPayload);
}

export function buildVerifiableEvidenceChain(params: {
  runId: string;
  softwares: Software[];
  findings: NormalizedFinding[];
  toolExecutions: ToolExecutionRecord[];
  veracityResults: VeracityCheckResult[];
  responsibleActor?: string;
}): EvidenceRecord[] {
  const {
    runId,
    softwares,
    findings,
    toolExecutions,
    veracityResults,
    responsibleActor = 'winhood-audit-engine',
  } = params;

  const softwareById = new Map<string, Software>();
  for (const sw of softwares) {
    softwareById.set(sw.id, sw);
  }

  const evidenceChain: EvidenceRecord[] = [];
  let previousHash = GENESIS_EVIDENCE_HASH;
  let immutableIndex = 0;

  // 1. Record Veracity Attestations for each Software
  for (const vr of veracityResults) {
    const sw = softwareById.get(vr.softwareId);
    const baseRecord: Omit<EvidenceRecord, 'sha256'> = {
      id: `ev-veracity-${runId}-${vr.softwareId}-${immutableIndex}`,
      runId,
      softwareId: vr.softwareId,
      softwareName: vr.softwareName,
      version: sw?.version || 'unknown',
      commitHash: sw?.commitHash || 'NOT_DECLARED',
      sourceHash: sw?.packageSha256 || 'UNVERIFIED',
      criterionId: 'VERACITY-19-CHECKS',
      evidenceType: 'VERACITY_ATTESTATION',
      origin: sw?.dataOrigin || 'USER_SOURCE',
      responsibleActor,
      category: 'VERACITY_AUDIT',
      toolName: 'WinHood Veracity & Provenance Auditor',
      toolVersion: '4.0.0',
      timestamp: vr.auditedAt,
      resultSummary: `Classificação=${vr.overallClassification} | Cobertura=${vr.overallCoveragePercent}% | Elegível=${vr.checks.eligibleForScoring}`,
      severity: vr.checks.eligibleForScoring ? 'INFO' : 'HIGH',
      fileOrComponent: 'SOURCE_MANIFEST',
      validationStatus: vr.overallClassification,
      rawPayloadPreview: JSON.stringify({
        overallClassification: vr.overallClassification,
        eligibleForScoring: vr.checks.eligibleForScoring,
        warnings: vr.warnings,
        blockingReasons: vr.blockingReasons,
      }),
      immutableIndex,
      previousRecordSha256: previousHash,
    };
    const recordHash = computeCanonicalEvidenceHash(baseRecord, previousHash);
    evidenceChain.push({
      ...baseRecord,
      sha256: recordHash,
    });
    previousHash = recordHash;
    immutableIndex += 1;
  }

  // 2. Record Tool Execution Proofs
  for (const exec of toolExecutions) {
    const sw = softwareById.get(exec.softwareId);
    const baseRecord: Omit<EvidenceRecord, 'sha256'> = {
      id: `ev-exec-${runId}-${exec.id}-${immutableIndex}`,
      runId,
      softwareId: exec.softwareId,
      softwareName: sw?.name || exec.softwareId,
      version: sw?.version || 'unknown',
      commitHash: exec.commitHash || sw?.commitHash || 'NOT_DECLARED',
      sourceHash: exec.sourceHash || sw?.packageSha256 || 'UNVERIFIED',
      criterionId: `TOOL-${exec.toolId}`,
      evidenceType: 'TOOL_RAW_OUTPUT',
      origin: exec.executionMethod || 'NATIVE_AST_ENGINE',
      responsibleActor,
      category: exec.canonicalFormat,
      toolName: exec.toolName,
      toolVersion: exec.toolVersion,
      timestamp: exec.completedAt,
      resultSummary: `Status=${exec.veracityStatus} | Método=${exec.executionMethod || 'NATIVE_AST_ENGINE'} | Arquivos=${exec.analyzedFilesCount}/${exec.eligibleFilesCount} | Exit=${exec.exitCode} | Duração=${exec.durationMs}ms`,
      severity: exec.veracityStatus === 'SUCCESS_VALIDATED' ? 'INFO' : 'LOW',
      fileOrComponent: exec.workingDirectory || sw?.inventory?.isolatedStoragePath || 'workspace',
      validationStatus: exec.veracityStatus,
      rawPayloadPreview: (exec.stdout || exec.logs.join(' | ')).slice(0, 400),
      immutableIndex,
      previousRecordSha256: previousHash,
    };
    const recordHash = computeCanonicalEvidenceHash(baseRecord, previousHash);
    evidenceChain.push({
      ...baseRecord,
      sha256: recordHash,
    });
    previousHash = recordHash;
    immutableIndex += 1;
  }

  // 3. Record Individual Findings with Code Location & Hash
  for (const f of findings) {
    const sw = softwareById.get(f.softwareId);
    const baseRecord: Omit<EvidenceRecord, 'sha256'> = {
      id: `ev-finding-${runId}-${f.id}-${immutableIndex}`,
      runId,
      softwareId: f.softwareId,
      softwareName: f.softwareName,
      version: f.softwareVersion,
      commitHash: sw?.commitHash || 'NOT_DECLARED',
      sourceHash: sw?.packageSha256 || 'UNVERIFIED',
      criterionId: f.originalRuleId,
      evidenceType: 'STATIC_AST_FINDING',
      origin: f.originType || 'WINHOOD_NATIVE_STATIC',
      responsibleActor,
      category: f.category,
      toolName: f.toolName,
      toolVersion: f.toolVersion,
      timestamp: f.collectedAt,
      resultSummary: `[${f.severity}] ${f.originalRuleId}: ${f.title} (${f.filePath}:${f.lineNumber})`,
      severity: f.severity,
      fileOrComponent: `${f.filePath}:${f.lineNumber}`,
      validationStatus: 'SUCCESS_VALIDATED',
      rawPayloadPreview: f.snippet.slice(0, 320),
      immutableIndex,
      previousRecordSha256: previousHash,
    };
    const recordHash = computeCanonicalEvidenceHash(baseRecord, previousHash);
    evidenceChain.push({
      ...baseRecord,
      sha256: recordHash,
    });
    previousHash = recordHash;
    immutableIndex += 1;
  }

  return evidenceChain;
}

export function signEvidenceManifestHmacSha256(params: {
  runId: string;
  algorithmVersion: string;
  evidenceChain: EvidenceRecord[];
  signingKeyId?: string;
  generatedAt?: string;
  secret?: string;
}): SignedEvidenceManifest {
  const activeKey = KeyManagementService.getActiveEvidenceHmacKey();
  const {
    runId,
    algorithmVersion,
    evidenceChain,
    signingKeyId = activeKey.keyId,
    generatedAt = new Date().toISOString(),
    secret = activeKey.secret,
  } = params;

  const merkleOrChainRootSha256 =
    evidenceChain.length > 0
      ? evidenceChain[evidenceChain.length - 1].sha256
      : GENESIS_EVIDENCE_HASH;

  const manifestCanonicalBody = JSON.stringify({
    runId,
    algorithmVersion,
    recordsCount: evidenceChain.length,
    genesisHash: GENESIS_EVIDENCE_HASH,
    merkleOrChainRootSha256,
    recordHashes: evidenceChain.map((r) => ({
      index: r.immutableIndex,
      id: r.id,
      sha256: r.sha256,
      prev: r.previousRecordSha256,
    })),
  });

  const manifestPayloadSha256 = sha256Hex(manifestCanonicalBody);
  const digitalSignatureHmacSha256 = hmacSha256Hex(manifestPayloadSha256, secret);

  return {
    manifestId: `manifest-${runId}`,
    runId,
    algorithmVersion,
    generatedAt,
    recordsCount: evidenceChain.length,
    genesisHash: GENESIS_EVIDENCE_HASH,
    merkleOrChainRootSha256,
    rootChainSha256: merkleOrChainRootSha256,
    manifestPayloadSha256,
    digitalSignatureHmacSha256,
    hmacSignature: digitalSignatureHmacSha256,
    signatureAlgorithm: 'HMAC-SHA256',
    signingKeyId,
    keyId: signingKeyId,
    authenticityProofType: 'HMAC_SHA256_PROTECTED_SERVER_KEY',
    integrityNote:
      'Hash SHA-256 encadeado garante integridade imutável da cadeia de evidências; assinatura HMAC-SHA256 com chave protegida do servidor garante autenticidade do manifesto de execução.',
    verified: true,
  };
}

export interface EvidenceChainVerificationResult {
  valid: boolean;
  chainIntegrityValid: boolean;
  manifestSignatureValid: boolean;
  signatureValid: boolean;
  recordsChecked: number;
  tamperedRecordIds: string[];
  tamperedIndices: number[];
  brokenLinkIndices: number[];
  expectedRootHash: string;
  actualRootHash: string;
  verificationTimestamp: string;
  message: string;
  details: string[];
}

export function verifyEvidenceChainAndManifest(
  evidenceChain: EvidenceRecord[],
  signedManifest?: SignedEvidenceManifest,
  secret?: string
): EvidenceChainVerificationResult {
  const tamperedRecordIds: string[] = [];
  const tamperedIndicesSet = new Set<number>();
  const brokenLinkIndices: number[] = [];
  const details: string[] = [];

  let expectedPrevHash = GENESIS_EVIDENCE_HASH;

  for (let i = 0; i < evidenceChain.length; i++) {
    const rec = evidenceChain[i];
    if (rec.immutableIndex !== i) {
      brokenLinkIndices.push(i);
      tamperedIndicesSet.add(i);
      tamperedIndicesSet.add(i + 1);
      details.push(
        `Índice fora de sequência na posição ${i}: esperado ${i}, encontrado ${rec.immutableIndex}.`
      );
    }
    if (rec.previousRecordSha256 !== expectedPrevHash) {
      brokenLinkIndices.push(i);
      tamperedIndicesSet.add(i);
      tamperedIndicesSet.add(i + 1);
      details.push(
        `Quebra de encadeamento no registro ${rec.id} (índice ${i}): previousRecordSha256 diverge do hash anterior.`
      );
    }

    const { sha256, ...rest } = rec;
    const recomputedHash = computeCanonicalEvidenceHash(rest, rec.previousRecordSha256);
    if (recomputedHash !== sha256) {
      tamperedRecordIds.push(rec.id);
      tamperedIndicesSet.add(i);
      tamperedIndicesSet.add(i + 1);
      details.push(
        `Adulteração detectada no registro ${rec.id} (índice ${i}): SHA-256 recalculado (${recomputedHash.slice(0, 12)}...) difere do armazenado (${sha256.slice(0, 12)}...).`
      );
    }

    expectedPrevHash = sha256;
  }

  const actualRootHash =
    evidenceChain.length > 0
      ? evidenceChain[evidenceChain.length - 1].sha256
      : GENESIS_EVIDENCE_HASH;

  const chainIntegrityValid =
    tamperedRecordIds.length === 0 && brokenLinkIndices.length === 0;

  let manifestSignatureValid = false;
  let expectedRootHash = actualRootHash;

  if (!signedManifest) {
    details.push('Manifesto assinado ausente na execução.');
  } else {
    expectedRootHash = signedManifest.merkleOrChainRootSha256;
    if (signedManifest.recordsCount !== evidenceChain.length) {
      details.push(
        `Divergência na contagem de registros do manifesto: manifesto=${signedManifest.recordsCount}, cadeia=${evidenceChain.length}.`
      );
    }
    if (signedManifest.merkleOrChainRootSha256 !== actualRootHash) {
      details.push(
        `Raiz da cadeia no manifesto (${signedManifest.merkleOrChainRootSha256.slice(0, 12)}...) difere da raiz atual da cadeia (${actualRootHash.slice(0, 12)}...).`
      );
    }

    const resolvedSecret =
      secret ||
      KeyManagementService.getEvidenceSecretByKeyId(signedManifest.signingKeyId) ||
      KeyManagementService.getActiveEvidenceHmacKey().secret;

    const recomputedManifest = signEvidenceManifestHmacSha256({
      runId: signedManifest.runId,
      algorithmVersion: signedManifest.algorithmVersion,
      evidenceChain,
      signingKeyId: signedManifest.signingKeyId,
      generatedAt: signedManifest.generatedAt,
      secret: resolvedSecret,
    });

    if (
      recomputedManifest.manifestPayloadSha256 === signedManifest.manifestPayloadSha256 &&
      recomputedManifest.digitalSignatureHmacSha256 === signedManifest.digitalSignatureHmacSha256 &&
      signedManifest.merkleOrChainRootSha256 === actualRootHash &&
      signedManifest.recordsCount === evidenceChain.length &&
      chainIntegrityValid
    ) {
      manifestSignatureValid = true;
      details.push(
        'Assinatura HMAC-SHA256 e cadeia de custódia SHA-256 verificadas com sucesso (0 adulterações).'
      );
    } else {
      details.push(
        'Assinatura HMAC-SHA256 ou payload do manifesto inválido — falha de autenticidade/integridade.'
      );
    }
  }

  const valid = chainIntegrityValid && manifestSignatureValid;
  const tamperedIndices = Array.from(tamperedIndicesSet).sort((a, b) => a - b);

  return {
    valid,
    chainIntegrityValid,
    manifestSignatureValid,
    signatureValid: manifestSignatureValid,
    recordsChecked: evidenceChain.length,
    tamperedRecordIds,
    tamperedIndices,
    brokenLinkIndices,
    expectedRootHash,
    actualRootHash,
    verificationTimestamp: new Date().toISOString(),
    message: details.join(' '),
    details,
  };
}
