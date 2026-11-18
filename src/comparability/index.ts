import crypto from 'node:crypto';
import type { ComparabilityManifest } from '../types/benchmark';

export type { ComparabilityManifest };

export type ComparisonModality = 'SAME_ENGINE' | 'CROSS_TOOL';

export type ComparabilityClassification =
  | 'STRICTLY_COMPARABLE'
  | 'QUALIFIED_COMPARISON'
  | 'NOT_COMPARABLE';

export const CANONICAL_TAXONOMY_VERSION = 'WINHOOD-CWE-MQR-TAXONOMY-v1.0.0';

const CANONICAL_TAXONOMY_MAPPING_SPEC = {
  version: CANONICAL_TAXONOMY_VERSION,
  domains: ['SECURITY', 'RELIABILITY', 'MAINTAINABILITY', 'ARCHITECTURE', 'PERFORMANCE', 'DATABASE'],
  cweSeverityMap: {
    'CWE-89': 'BLOCKER',
    'CWE-78': 'BLOCKER',
    'CWE-95': 'BLOCKER',
    'CWE-798': 'BLOCKER',
    'CWE-327': 'CRITICAL',
    'CWE-328': 'CRITICAL',
    'CWE-390': 'HIGH',
    'CWE-119': 'MEDIUM',
  },
};

export const CANONICAL_TAXONOMY_MAPPING_SHA256 = crypto
  .createHash('sha256')
  .update(JSON.stringify(CANONICAL_TAXONOMY_MAPPING_SPEC), 'utf8')
  .digest('hex');

export function isValidSha256Hex(value: string | undefined | null): boolean {
  return typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value.trim());
}

export function sha256Canonical(payload: unknown): string {
  return crypto
    .createHash('sha256')
    .update(typeof payload === 'string' ? payload : JSON.stringify(payload), 'utf8')
    .digest('hex');
}

export function buildComparabilityManifest(
  input: Partial<ComparabilityManifest> & {
    projectId: string;
    commitSha: string;
    engineVersion: string;
    ruleCatalogSha256: string;
    analyticalProfile: string;
  }
): ComparabilityManifest {
  return {
    projectId: input.projectId,
    sourceRepository: input.sourceRepository || `project://${input.projectId}`,
    commitSha: input.commitSha,
    workingTreeClean: input.workingTreeClean ?? true,
    configHashSha256: input.configHashSha256 || sha256Canonical({ profile: input.analyticalProfile, engine: input.engineVersion }),
    analyticalProfile: input.analyticalProfile,
    engineVersion: input.engineVersion,
    ruleCatalogSha256: input.ruleCatalogSha256,
    weightsHashSha256: input.weightsHashSha256 || sha256Canonical({ defaultWeights: true }),
    analyticalDepth: input.analyticalDepth || 'FULL_AST_AND_TAINT',
    osPlatform: input.osPlatform || process.platform,
    cpuArch: input.cpuArch || process.arch,
    runtimeVersion: input.runtimeVersion || process.version,
    eligibleFilesScopeHash: input.eligibleFilesScopeHash || sha256Canonical({ scope: input.projectId, commit: input.commitSha }),
    taxonomyVersion: input.taxonomyVersion || CANONICAL_TAXONOMY_VERSION,
    taxonomyMappingSha256: input.taxonomyMappingSha256 ?? CANONICAL_TAXONOMY_MAPPING_SHA256,
    executedAt: input.executedAt || new Date().toISOString(),
    evidenceIntegrityVerified: input.evidenceIntegrityVerified ?? true,
  };
}

export interface CandidateScopeDescriptor {
  softwareId: string;
  engineVersion: string;
  ruleCatalogSha256: string;
  scopeCoveragePercent: number;
  evidenceConfidence: 'HIGH' | 'MEDIUM' | 'LOW';
  functionalCategory: string;
  commitHash?: string;
  normalizedFindingCategories?: string[];
  toolIdentifier?: string;
  toolExecuted?: boolean;
  manifest?: ComparabilityManifest;
}

export interface ComparabilityValidationOptions {
  modality?: ComparisonModality;
  sameCommitVerified?: boolean;
  normalizedTaxonomyApplied?: boolean;
  allowDistinctRepositoriesInSameProject?: boolean;
}

export interface ComparabilityValidationResult {
  comparable: boolean;
  status: 'COMPATIBLE' | 'INCOMPATIBLE_SCOPE' | 'INCONCLUSIVE';
  comparisonModality: ComparisonModality;
  comparabilityClassification: ComparabilityClassification;
  reasons: string[];
  qualifications: string[];
  coverageDeltaPercent: number;
  manifestsVerified: boolean;
  comparabilityManifests?: {
    candidateA: ComparabilityManifest | null;
    candidateB: ComparabilityManifest | null;
  };
}

function validateManifestPresenceAndIntegrity(
  label: string,
  manifest: ComparabilityManifest | undefined,
  reasons: string[]
): boolean {
  if (!manifest) {
    reasons.push(`${label}: Manifesto de Comparabilidade verificável ausente (proibido aceitar comparação sem manifesto).`);
    return false;
  }
  if (!manifest.projectId || !manifest.engineVersion || !manifest.analyticalProfile) {
    reasons.push(`${label}: Manifesto incompleto (projectId, engineVersion ou analyticalProfile ausente).`);
  }
  if (!manifest.commitSha || manifest.commitSha.trim().length < 7) {
    reasons.push(`${label}: Manifesto sem commitSha válido (>= 7 caracteres).`);
  }
  if (!isValidSha256Hex(manifest.configHashSha256)) {
    reasons.push(`${label}: configHashSha256 ausente ou inválido no manifesto.`);
  }
  if (!isValidSha256Hex(manifest.weightsHashSha256)) {
    reasons.push(`${label}: weightsHashSha256 ausente ou inválido no manifesto.`);
  }
  if (!isValidSha256Hex(manifest.eligibleFilesScopeHash)) {
    reasons.push(`${label}: eligibleFilesScopeHash ausente ou inválido no manifesto.`);
  }
  if (!manifest.evidenceIntegrityVerified) {
    reasons.push(`${label}: Integridade criptográfica da evidência não comprovada (evidenceIntegrityVerified=false).`);
  }
  return true;
}

/**
 * Validates A/B comparability premises across SAME_ENGINE and CROSS_TOOL modalities.
 * Strictly requires verifiable ComparabilityManifest records and cryptographic digests;
 * rejects bare boolean flags (sameCommitVerified / normalizedTaxonomyApplied) without manifest proof.
 */
export function validatePairComparability(
  candidateA: CandidateScopeDescriptor,
  candidateB: CandidateScopeDescriptor,
  options?: ComparabilityValidationOptions
): ComparabilityValidationResult {
  const reasons: string[] = [];
  const qualifications: string[] = [];
  const modality: ComparisonModality = options?.modality || 'SAME_ENGINE';
  const coverageDeltaPercent = Math.abs(
    candidateA.scopeCoveragePercent - candidateB.scopeCoveragePercent
  );

  const mA = candidateA.manifest;
  const mB = candidateB.manifest;
  const hasA = validateManifestPresenceAndIntegrity('Candidato A', mA, reasons);
  const hasB = validateManifestPresenceAndIntegrity('Candidato B', mB, reasons);

  if (candidateA.toolExecuted === false || candidateB.toolExecuted === false) {
    reasons.push('Execução real de uma ou mais ferramentas ausente (toolExecuted=false).');
  }

  if (options?.sameCommitVerified === true && (!mA?.commitSha || !mB?.commitSha || mA.commitSha !== mB.commitSha)) {
    reasons.push('Flag booleana sameCommitVerified=true rejeitada: commitSha ausente ou divergente no manifesto.');
  }
  if (
    options?.normalizedTaxonomyApplied === true &&
    (!isValidSha256Hex(mA?.taxonomyMappingSha256) || !isValidSha256Hex(mB?.taxonomyMappingSha256))
  ) {
    reasons.push('Flag booleana normalizedTaxonomyApplied=true rejeitada: taxonomyMappingSha256 ausente ou inválido no manifesto.');
  }

  if (modality === 'SAME_ENGINE') {
    if (candidateA.engineVersion !== candidateB.engineVersion) {
      reasons.push(
        `Engine version mismatch: ${candidateA.engineVersion} vs ${candidateB.engineVersion}`
      );
    }
    if (candidateA.ruleCatalogSha256 !== candidateB.ruleCatalogSha256) {
      reasons.push('Rule catalog SHA-256 digest mismatch between candidates.');
    }
    if (hasA && hasB && mA && mB) {
      if (mA.projectId !== mB.projectId) {
        reasons.push(`Manifest projectId mismatch: ${mA.projectId} vs ${mB.projectId}.`);
      }
      if (mA.analyticalProfile !== mB.analyticalProfile) {
        reasons.push(`Analytical profile mismatch: ${mA.analyticalProfile} vs ${mB.analyticalProfile}.`);
      }
      if (mA.weightsHashSha256 !== mB.weightsHashSha256) {
        reasons.push('Weights SHA-256 hash mismatch between candidates.');
      }
      if (mA.configHashSha256 !== mB.configHashSha256) {
        reasons.push('Configuration SHA-256 hash mismatch between candidates.');
      }
      if (!mA.workingTreeClean || !mB.workingTreeClean) {
        qualifications.push('Árvore de trabalho não limpa (workingTreeClean=false) em ao menos um candidato.');
      }
      if (mA.osPlatform !== mB.osPlatform || mA.cpuArch !== mB.cpuArch || mA.runtimeVersion !== mB.runtimeVersion) {
        qualifications.push('Ambiente/runtime distinto entre execuções SAME_ENGINE.');
      }
      if (mA.analyticalDepth !== mB.analyticalDepth) {
        qualifications.push(`Profundidade analítica distinta (${mA.analyticalDepth} vs ${mB.analyticalDepth}).`);
      }
      if (!options?.allowDistinctRepositoriesInSameProject) {
        if (mA.commitSha !== mB.commitSha) {
          qualifications.push(`Commit SHA distinto (${mA.commitSha} vs ${mB.commitSha}).`);
        }
        if (mA.eligibleFilesScopeHash !== mB.eligibleFilesScopeHash) {
          qualifications.push('Escopo de arquivos elegíveis distinto (eligibleFilesScopeHash).');
        }
      }
    }
  } else {
    if (hasA && hasB && mA && mB) {
      if (mA.projectId !== mB.projectId) {
        reasons.push(`Cross-tool comparison requires matching projectId (${mA.projectId} vs ${mB.projectId}).`);
      }
      if (mA.commitSha !== mB.commitSha) {
        reasons.push(
          `Cross-tool comparison requires identical verified commitSha in manifests (${mA.commitSha} vs ${mB.commitSha}).`
        );
      }
      if (!isValidSha256Hex(mA.taxonomyMappingSha256) || !isValidSha256Hex(mB.taxonomyMappingSha256)) {
        reasons.push('Cross-tool comparison requires valid taxonomyMappingSha256 digest in both manifests.');
      } else if (mA.taxonomyMappingSha256 !== mB.taxonomyMappingSha256) {
        reasons.push('Taxonomy mapping SHA-256 mismatch between tools.');
      }
      if (mA.eligibleFilesScopeHash !== mB.eligibleFilesScopeHash) {
        qualifications.push('Escopo de arquivos elegíveis distinto entre ferramentas; manter ressalva qualificada.');
      }
    }
    if (options?.normalizedTaxonomyApplied === false) {
      reasons.push(
        'Cross-tool comparison requires normalized CWE/MQR category taxonomy mapping.'
      );
    }
    if (candidateA.engineVersion !== candidateB.engineVersion) {
      qualifications.push(
        `Comparação Cross-Tool qualificada entre motores distintos (${candidateA.engineVersion} vs ${candidateB.engineVersion}) sobre manifesto verificado.`
      );
    }
  }

  if (candidateA.functionalCategory !== candidateB.functionalCategory) {
    reasons.push(
      `Functional category mismatch: ${candidateA.functionalCategory} vs ${candidateB.functionalCategory}`
    );
  }
  if (coverageDeltaPercent > 30) {
    reasons.push(
      `Scope coverage disparity (${coverageDeltaPercent}%) exceeds maximum 30% threshold.`
    );
  } else if (coverageDeltaPercent > 10) {
    qualifications.push(
      `Diferença moderada de cobertura de escopo (${coverageDeltaPercent}%) dentro da tolerância máxima de 30%.`
    );
  }

  if (
    candidateA.evidenceConfidence === 'LOW' ||
    candidateB.evidenceConfidence === 'LOW'
  ) {
    return {
      comparable: false,
      status: 'INCONCLUSIVE',
      comparisonModality: modality,
      comparabilityClassification: 'NOT_COMPARABLE',
      reasons: [
        ...reasons,
        'At least one candidate has LOW evidence confidence.',
      ],
      qualifications,
      coverageDeltaPercent,
      manifestsVerified: false,
      comparabilityManifests: {
        candidateA: mA || null,
        candidateB: mB || null,
      },
    };
  }

  if (
    candidateA.evidenceConfidence === 'MEDIUM' ||
    candidateB.evidenceConfidence === 'MEDIUM'
  ) {
    qualifications.push('Pelo menos um candidato possui confiança de evidência MEDIUM.');
  }

  if (reasons.length > 0) {
    return {
      comparable: false,
      status: 'INCOMPATIBLE_SCOPE',
      comparisonModality: modality,
      comparabilityClassification: 'NOT_COMPARABLE',
      reasons,
      qualifications,
      coverageDeltaPercent,
      manifestsVerified: false,
      comparabilityManifests: {
        candidateA: mA || null,
        candidateB: mB || null,
      },
    };
  }

  const comparabilityClassification: ComparabilityClassification =
    modality === 'CROSS_TOOL' || qualifications.length > 0
      ? 'QUALIFIED_COMPARISON'
      : 'STRICTLY_COMPARABLE';

  return {
    comparable: true,
    status: 'COMPATIBLE',
    comparisonModality: modality,
    comparabilityClassification,
    reasons: [],
    qualifications,
    coverageDeltaPercent,
    manifestsVerified: true,
    comparabilityManifests: {
      candidateA: mA!,
      candidateB: mB!,
    },
  };
}
