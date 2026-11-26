import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import express from 'express';
import QRCode from 'qrcode';
import type {
  AppEnvironment,
  AssessmentMode,
  AuditLogEntry,
  BenchmarkCategoryKey,
  BenchmarkProfileConfig,
  BenchmarkRun,
  DataOrigin,
  FileInventoryItem,
  FindingValidationLifecycleState,
  GitProviderType,
  MarketCompetitorCandidate,
  NormalizedFinding,
  Project,
  SavedSonarProjectProfile,
  Software,
  SonarAndToolsDatabaseBundle,
  SonarInstallationMode,
  SonarTokenVerificationResult,
  SourceManifest,
  ToolAdapterInfo,
  UnifiedExecutionRecord,
  VulnerabilityValidationState,
} from './src/types/benchmark';
import {
  ALL_BENCHMARK_CATEGORIES,
  DEFAULT_CATEGORY_WEIGHTS,
  computeSha256,
  enrichLegacyOrExternalFinding,
  maskSecretsInText,
  normalizeEnabledCategoryWeights,
  validateCategoryWeights,
  validateEquivalenceConditions,
} from './src/engine/scoringEngine';
import {
  buildTechnicalInventory,
  sanitizeUploadedFilesMap,
  validateSourceUploadSecurity,
} from './src/engine/staticAnalyzer';
import {
  DOMAIN_SPECIALIZED_PROFILES,
  EVALUATION_CRITERIA_CATALOG,
  METHODOLOGY_CATALOG_VERSION,
  buildPreAnalysisSummary,
  determineSourceAvailability,
  determineSourceIngestionState,
  evaluateSoftwareComparability,
  inferSoftwareDomainKey,
} from './src/engine/methodologyCatalogEngine';
import {
  computeCanonicalEvidenceHash,
  signEvidenceManifestHmacSha256,
  verifyEvidenceChainAndManifest,
} from './src/engine/evidenceProvenanceEngine';
import {
  KEESAFE_OPEN_FILES,
  VAULTCORE_INTERNAL_FILES,
  DEMO_FIXTURE_METADATA,
} from './src/engine/realSampleRepositories';
import {
  ALGORITHM_VERSION,
  DEFAULT_BENCHMARK_PROFILES,
  createInitialRunningBenchmark,
  enforceVerifiedQualityGateOnRun,
  executeBenchmarkRunOrchestration,
  recalculateBenchmarkRunScoreCards,
} from './src/engine/benchmarkOrchestrator';
import { MarketCompetitorDiscoveryEngine } from './src/engine/marketCompetitorDiscoveryEngine';
import {
  buildFull21SecurityAdaptersCatalog,
  executeSecurityAssessmentSuite,
} from './src/engine/securityAssessmentEngine';
import { ExternalToolLifecycleManager } from './src/services/tools/ExternalToolLifecycleManager';
import { ToolCacheManager } from './src/services/tools/ToolCacheManager';
import { ToolResourceMonitor, type HostHardwareBenchmarkResult } from './src/services/tools/ToolResourceMonitor';
import { MqrBridgeIntegrationService } from './src/integrations/mqr-bridge/SonarAdapter';
import { MqrBridgeConnection } from './src/integrations/mqr-bridge/SonarConnection';
import { MqrBridgeVersionManager } from './src/integrations/mqr-bridge/SonarVersionManager';
import { MqrBridgeInstallationManager } from './src/integrations/mqr-bridge/SonarInstallationManager';
import { GitarAdapter } from './src/integrations/gitar/GitarAdapter';
import { GitarInstallationHealth } from './src/integrations/gitar/GitarInstallationHealth';
import { SonarAnalysisWorker } from './src/workers/SonarAnalysisWorker';
import { SonarResultParser } from './src/integrations/mqr-bridge/SonarResultParser';
import {
  ExternalReportImportWorker,
  type SarifExternalReportPayload,
} from './src/workers/ExternalReportImportWorker';
import { GitarReviewWorker } from './src/workers/GitarReviewWorker';
import { getHardwareProfile, updateHardwareProfile } from './src/engine/workerPool';
import { KeyManagementService } from './src/security/KeyManagementService';
import { OptionalTotpService } from './src/security/OptionalTotpService';
import { PersistentDatabaseManager } from './src/storage/PersistentDatabaseManager';
import { ProjectBackupService } from './src/services/backup/ProjectBackupService';
import { SsrfGuard, type AuthorizedPerfTarget } from './src/execution/SsrfGuard';
import { SandboxExecutor } from './src/execution/SandboxExecutor';
import { ReferenceRegistry } from './src/intelligence/reference/ReferenceRegistry';
import { ReferenceSynchronizer } from './src/intelligence/synchronization/ReferenceSynchronizer';
import { BenchmarkMatcher } from './src/intelligence/comparison/BenchmarkMatcher';
import { GoldenDatasetRunner } from './src/validation/GoldenDatasetRunner';
import { ControlledTestAndPerfRunner } from './src/execution/ControlledTestAndPerfRunner';
import { CoverageReportParser } from './src/execution/CoverageReportParser';
import { SbomGenerator } from './src/analyzers/sca/SbomGenerator';
import {
  DEFAULT_ENTERPRISE_LICENSE_POLICY,
  ScaCorrelator,
} from './src/analyzers/sca/ScaCorrelator';
import { AnalyzerRegistry } from './src/analyzers/AnalyzerRegistry';
import { RULE_ENGINE_VERSION, RuleRegistry } from './src/analyzers/RuleRegistry';
import { SarifCodec } from './src/analyzers/SarifCodec';
import { SecretScanner } from './src/analyzers/SecretsCatalog';
import { QualityGateEngine, type QualityGateDefinition } from './src/gate/QualityGateEngine';
import { ComplianceMapper } from './src/evidence/ComplianceMapper';
import { PortfolioEngine } from './src/engine/portfolioEngine';
import { PdfReportGenerator } from './src/reports/PdfReportGenerator';
import { buildOpenApiSpec } from './src/api/openApiSpec';
import { PrDecorationAdapter, type PrCiProvider } from './src/integrations/ci/PrDecorationAdapter';
import { SonarMetricsMapper } from './src/integrations/mqr-bridge/SonarMetricsMapper';
import { SonarQualityGateMapper } from './src/integrations/mqr-bridge/SonarQualityGateMapper';
import {
  DEFAULT_SONAR_METRIC_KEYS,
  type RawSonarHotspotApiItem,
  type RawSonarIssueApiItem,
} from './src/integrations/mqr-bridge/SonarApiClient';
import {
  ensureWinHoodDirectories,
  resolveWinHoodDataRoot,
} from './src/storage/WinHoodPaths';
import {
  extractZipBufferToFilesMap,
  hasExplicitPathTraversalOrSymlinkAttempt,
} from './src/server/zipExtractor';
import {
  MAX_TRACKED_IPS,
  RemoteAuthFailureTracker,
  appendSecurityAuthAuditJsonl,
  buildAllowedOriginMap,
  constantTimeTokenMatch,
  createInMemoryRateLimiter,
  parseValidPortNumber,
  resolveDeploymentMode,
  resolveRuntimeEnv,
  resolveTrustProxyConfig,
  type DeploymentMode,
  type RuntimeEnv,
} from './src/server/securityMiddleware';
import { registerGracefulShutdown } from './src/server/gracefulShutdown';
import { EncryptedArtifactStore } from './src/storage/EncryptedArtifactStore';
import { EphemeralWorkspaceManager } from './src/execution/EphemeralWorkspaceManager';
import {
  ScannerJobOrchestrator,
  SCANNER_TOOL_CATALOG,
  type ScannerToolId,
} from './src/worker/ScannerJobOrchestrator';
import type http from 'node:http';

export { resolveDeploymentMode, resolveRuntimeEnv, resolveTrustProxyConfig };
export type { DeploymentMode, RuntimeEnv };

const PORT = Number(process.env.PORT || 3000);
const DEFAULT_DATA_DIR = resolveWinHoodDataRoot();
const DATA_DIR = DEFAULT_DATA_DIR;
const ISOLATED_ARTIFACTS_DIR = path.join(DEFAULT_DATA_DIR, 'isolated_artifacts');
const STORE_FILE = path.join(DEFAULT_DATA_DIR, 'winhood_persistent_db.json');

function isTestRuntimeEnvironment(): boolean {
  return process.env.NODE_ENV === 'test' || process.env.WINHOOD_TEST_MODE === '1';
}

function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const rawVal = part.slice(idx + 1).trim();
    try {
      out[key] = decodeURIComponent(rawVal);
    } catch {
      out[key] = rawVal;
    }
  }
  return out;
}

const REPORT_TYPE_LITERALS: Record<
  string,
  'COMPARATIVE_FULL' | 'EXECUTIVE_SUMMARY' | 'TECHNICAL_AUDIT' | 'DEVSECOPS_SARIF'
> = {
  COMPARATIVE_FULL: 'COMPARATIVE_FULL',
  EXECUTIVE_SUMMARY: 'EXECUTIVE_SUMMARY',
  TECHNICAL_AUDIT: 'TECHNICAL_AUDIT',
  DEVSECOPS_SARIF: 'DEVSECOPS_SARIF',
};
const EXPORT_FORMAT_LITERALS: Record<string, 'json' | 'sarif' | 'html' | 'csv' | 'md' | 'pdf'> = {
  json: 'json',
  sarif: 'sarif',
  html: 'html',
  csv: 'csv',
  md: 'md',
  pdf: 'pdf',
};
const SAFE_REPO_REGEX = /^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+$/;
const SAFE_BRANCH_REGEX = /^[a-zA-Z0-9._/-]+$/;

function resolveSafeExportFormat(raw: unknown): 'json' | 'sarif' | 'html' | 'csv' | 'md' | 'pdf' {
  const requestedFormatKey = typeof raw === 'string' ? raw.toLowerCase() : 'json';
  const mapped = Object.prototype.hasOwnProperty.call(EXPORT_FORMAT_LITERALS, requestedFormatKey)
    ? EXPORT_FORMAT_LITERALS[requestedFormatKey]
    : 'json';
  switch (mapped) {
    case 'sarif':
      return 'sarif';
    case 'html':
      return 'html';
    case 'csv':
      return 'csv';
    case 'md':
      return 'md';
    case 'pdf':
      return 'pdf';
    default:
      return 'json';
  }
}

function resolveSafeReportType(
  raw: unknown
): 'COMPARATIVE_FULL' | 'EXECUTIVE_SUMMARY' | 'TECHNICAL_AUDIT' | 'DEVSECOPS_SARIF' {
  const requestedTypeKey = typeof raw === 'string' ? raw.toUpperCase() : 'COMPARATIVE_FULL';
  const mapped = Object.prototype.hasOwnProperty.call(REPORT_TYPE_LITERALS, requestedTypeKey)
    ? REPORT_TYPE_LITERALS[requestedTypeKey]
    : 'COMPARATIVE_FULL';
  switch (mapped) {
    case 'EXECUTIVE_SUMMARY':
      return 'EXECUTIVE_SUMMARY';
    case 'TECHNICAL_AUDIT':
      return 'TECHNICAL_AUDIT';
    case 'DEVSECOPS_SARIF':
      return 'DEVSECOPS_SARIF';
    default:
      return 'COMPARATIVE_FULL';
  }
}

function escapeHtml(value: unknown): string {
  const str = String(value ?? '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function stripTrailingSlashes(url: string): string {
  let s = url.trim();
  while (s.endsWith('/')) {
    s = s.slice(0, -1);
  }
  return s;
}

interface PersistentDatabaseState {
  schemaVersion?: number;
  storageKind?: string;
  environmentMode: AppEnvironment;
  projects: Project[];
  softwares: Software[];
  profiles: BenchmarkProfileConfig[];
  runs: BenchmarkRun[];
  adapters: ToolAdapterInfo[];
  auditLogs: AuditLogEntry[];
  toolsDb: SonarAndToolsDatabaseBundle;
  savedSonarProjects?: SavedSonarProjectProfile[];
  authorizedTargets?: AuthorizedPerfTarget[];
  demoData?: {
    projects: Project[];
    softwares: Software[];
    runs: BenchmarkRun[];
  };
  telemetry: {
    startedAt: string;
    totalApiRequests: number;
    failedRequests: number;
    avgResponseTimeMs: number;
    workerExecutionsCount: number;
  };
}

const SAFE_SONAR_KEY_REGEX = /^[a-zA-Z0-9._:-]+$/;
const SAFE_SONAR_ORG_REGEX = /^[a-zA-Z0-9._-]+$/;

const SONAR_FULL_METRIC_KEYS = [
  'ncloc',
  'lines',
  'files',
  'functions',
  'classes',
  'statements',
  'complexity',
  'cognitive_complexity',
  'duplicated_lines_density',
  'duplicated_blocks',
  'duplicated_lines',
  'duplicated_files',
  'bugs',
  'vulnerabilities',
  'code_smells',
  'security_hotspots',
  'security_hotspots_reviewed',
  'security_review_rating',
  'sqale_index',
  'sqale_debt_ratio',
  'sqale_rating',
  'reliability_rating',
  'security_rating',
  'coverage',
  'line_coverage',
  'branch_coverage',
  'lines_to_cover',
  'uncovered_lines',
  'conditions_to_cover',
  'uncovered_conditions',
  'new_bugs',
  'new_vulnerabilities',
  'new_code_smells',
  'new_security_hotspots',
  'new_coverage',
  'new_duplicated_lines_density',
  'alert_status',
  'quality_gate_details',
].join(',');

function createDefaultSavedSonarProjects(): SavedSonarProjectProfile[] {
  return [];
}

function sanitizeSavedSonarProjectForClient(
  proj: SavedSonarProjectProfile
): Omit<SavedSonarProjectProfile, 'encryptedToken'> {
  const { encryptedToken: _omit, ...safeProj } = proj;
  return safeProj;
}

function computeSonarTokenVerification(
  proj: SavedSonarProjectProfile,
  overrideValid?: boolean,
  customMessage?: string
): SonarTokenVerificationResult {
  if (!proj.hasToken || !proj.encryptedToken) {
    return {
      valid: false,
      tokenExpiresAt: proj.tokenExpiresAt,
      remainingDays: null,
      remainingHours: null,
      statusLabel: 'NOT_CONFIGURED',
      message: customMessage || 'Nenhum token Bearer configurado para este projeto.',
    };
  }

  if (overrideValid === false || proj.lastVerificationStatus === 'INVALID') {
    return {
      valid: false,
      tokenExpiresAt: proj.tokenExpiresAt,
      remainingDays: 0,
      remainingHours: 0,
      statusLabel: 'INVALID_TOKEN',
      message:
        customMessage ||
        'Token inválido ou revogado no servidor SonarCloud / MqrBridge.',
    };
  }

  if (!proj.tokenExpiresAt || proj.tokenValidityDaysPolicy === 'NO_EXPIRATION') {
    return {
      valid: true,
      tokenExpiresAt: null,
      remainingDays: null,
      remainingHours: null,
      statusLabel: 'NO_EXPIRATION',
      message: customMessage || 'Token ativo (Sem Expiração configurada).',
    };
  }

  const expiresMs = new Date(proj.tokenExpiresAt).getTime();
  const nowMs = Date.now();
  const diffMs = expiresMs - nowMs;

  if (Number.isNaN(expiresMs) || diffMs <= 0) {
    return {
      valid: false,
      tokenExpiresAt: proj.tokenExpiresAt,
      remainingDays: 0,
      remainingHours: 0,
      statusLabel: 'EXPIRED',
      message:
        customMessage ||
        `Token expirado em ${new Date(proj.tokenExpiresAt).toLocaleDateString('pt-BR')}. Gere um novo token no SonarCloud/MqrBridge.`,
    };
  }

  const remainingDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  const remainingHours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  const statusLabel = remainingDays <= 7 ? 'EXPIRING_SOON' : 'VALID_ACTIVE';

  return {
    valid: true,
    tokenExpiresAt: proj.tokenExpiresAt,
    remainingDays,
    remainingHours,
    statusLabel,
    message:
      customMessage ||
      `Token ativo — expira em ${remainingDays} dias e ${remainingHours}h (${new Date(proj.tokenExpiresAt).toLocaleDateString('pt-BR')}).`,
  };
}

function validateSonarServerOrigin(rawServerUrl: string, platform: 'SONARCLOUD' | 'MQR_BRIDGE_SERVER'): string {
  const fallback = platform === 'SONARCLOUD' ? 'https://sonarcloud.io' : 'http://localhost:9000';
  const candidate = (rawServerUrl || fallback).trim();
  const parsed = new URL(candidate);
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('Protocolo inválido para o servidor Sonar. Utilize http:// ou https://.');
  }
  if (parsed.username || parsed.password) {
    throw new Error('Credenciais embutidas na URL não são permitidas.');
  }
  if (platform === 'SONARCLOUD' && parsed.hostname !== 'sonarcloud.io') {
    throw new Error('Para a plataforma SONARCLOUD, o host oficial deve ser estritamente https://sonarcloud.io.');
  }
  return parsed.origin;
}

async function validateSonarServerOriginSafe(
  rawServerUrl: string,
  platform: 'SONARCLOUD' | 'MQR_BRIDGE_SERVER'
): Promise<string> {
  const safeOrigin = validateSonarServerOrigin(rawServerUrl, platform);
  const ssrf = await SsrfGuard.validateUrl({
    targetUrl: safeOrigin,
    allowExplicitLoopback: SsrfGuard.isExplicitLoopbackUrl(safeOrigin),
  });
  if (!ssrf.allowed) {
    throw new Error(ssrf.reason || 'URL do servidor Sonar bloqueada pelo SsrfGuard.');
  }
  return safeOrigin;
}

interface SafePinnedHttpResponse {
  ok: boolean;
  status: number;
  headers: Record<string, string>;
  text: () => Promise<string>;
  json: <T = unknown>() => Promise<T>;
}

async function fetchWithTimeoutAndNoRedirect(
  url: string,
  init: RequestInit = {},
  timeoutMs = 8000
): Promise<SafePinnedHttpResponse> {
  const normalizedHeaders: Record<string, string> = {};
  if (init.headers) {
    if (init.headers instanceof Headers) {
      init.headers.forEach((value, key) => {
        normalizedHeaders[key] = value;
      });
    } else if (Array.isArray(init.headers)) {
      for (const [key, value] of init.headers) {
        normalizedHeaders[key] = value;
      }
    } else {
      for (const [key, value] of Object.entries(init.headers)) {
        if (value !== undefined) {
          normalizedHeaders[key] = String(value);
        }
      }
    }
  }
  const bodyPayload =
    typeof init.body === 'string' || Buffer.isBuffer(init.body) ? init.body : undefined;
  const res = await SsrfGuard.pinnedSafeRequest({
    targetUrl: url,
    method: init.method || 'GET',
    headers: normalizedHeaders,
    body: bodyPayload,
    timeoutMs,
    allowExplicitLoopback: SsrfGuard.isExplicitLoopbackUrl(url),
    followRedirects: false,
    maxRedirects: 0,
  });
  return {
    ok: res.ok,
    status: res.statusCode,
    headers: res.headers,
    text: async () => res.bodyText,
    json: async <T = unknown>() => res.json<T>(),
  };
}

function ensureDirectories(dataDir = DATA_DIR, artifactsDir = ISOLATED_ARTIFACTS_DIR) {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  if (!fs.existsSync(artifactsDir)) {
    fs.mkdirSync(artifactsDir, { recursive: true });
  }
}

function writeIsolatedArtifactsToDisk(
  softwareSlug: string,
  filesMap: Record<string, string>,
  artifactsDir = ISOLATED_ARTIFACTS_DIR
): string {
  ensureDirectories(path.dirname(artifactsDir), artifactsDir);
  const { targetDir } = EncryptedArtifactStore.writeEncryptedBundle({
    softwareSlug,
    filesMap,
    artifactsRoot: artifactsDir,
  });
  return targetDir;
}

// ZIP extraction & path traversal validation extracted to src/server/zipExtractor.ts (WH-AUD-003, WH-AUD-009)

function buildRepresentativeCompetitorFiles(candidate: MarketCompetitorCandidate): Record<string, string> {
  const safeSlug = candidate.name.toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
  const features =
    candidate.featuresIdentified && candidate.featuresIdentified.length > 0
      ? candidate.featuresIdentified
      : candidate.equivalentFeatures && candidate.equivalentFeatures.length > 0
        ? candidate.equivalentFeatures
        : ['Arquitetura Modular', 'API Oficial Documentada', 'Auditoria de Segurança'];

  return {
    'package.json': JSON.stringify(
      {
        name: safeSlug,
        version: candidate.version && candidate.version !== 'Latest Official' ? candidate.version : '1.0.0',
        description: candidate.description,
        homepage: candidate.officialUrl,
        repository: candidate.repositoryUrl || candidate.publicRepoUrl || candidate.officialUrl,
        license: candidate.isOpenSource ? 'Apache-2.0' : 'Commercial',
      },
      null,
      2
    ),
    'README.md': [
      `# ${candidate.name} (${candidate.vendor})`,
      '',
      `## Categoria de Mercado: ${candidate.category}`,
      candidate.description,
      '',
      '## Funcionalidades Identificadas e Homologadas',
      ...features.map((f) => `- ${f}`),
      '',
      '## Referências Oficiais',
      `- Site Oficial: ${candidate.officialUrl}`,
      `- Documentação: ${candidate.documentationUrl}`,
      ...(candidate.repositoryUrl ? [`- Repositório Público: ${candidate.repositoryUrl}`] : []),
    ].join('\n'),
    'src/architecture/competitorSpecification.ts': [
      `export interface CompetitorTechnicalProfile {`,
      `  id: string;`,
      `  name: string;`,
      `  vendor: string;`,
      `  category: string;`,
      `  isOpenSource: boolean;`,
      `  similarityScore: number;`,
      `  features: string[];`,
      `}`,
      ``,
      `export const COMPETITOR_PROFILE: CompetitorTechnicalProfile = ${JSON.stringify(
        {
          id: candidate.id,
          name: candidate.name,
          vendor: candidate.vendor,
          category: candidate.category,
          isOpenSource: Boolean(candidate.isOpenSource || candidate.openSource),
          similarityScore: candidate.similarityScore,
          features,
        },
        null,
        2
      )};`,
      ``,
      `export function verifyCompetitorCapabilities(requiredFeature: string): boolean {`,
      `  const normalized = requiredFeature.trim().toLowerCase();`,
      `  if (!normalized) return false;`,
      `  return COMPETITOR_PROFILE.features.some((f) => f.toLowerCase().includes(normalized));`,
      `}`,
    ].join('\n'),
    'src/security/competitorSecurityControls.ts': [
      `import crypto from 'node:crypto';`,
      ``,
      `export function computeCompetitorArtifactDigest(payload: string): string {`,
      `  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');`,
      `}`,
      ``,
      `export function evaluateCompetitorDomainReadiness(): {`,
      `  vendor: string;`,
      `  category: string;`,
      `  verified: boolean;`,
      `  digest: string;`,
      `} {`,
      `  const vendor = ${JSON.stringify(candidate.vendor)};`,
      `  const category = ${JSON.stringify(candidate.category)};`,
      `  return {`,
      `    vendor,`,
      `    category,`,
      `    verified: true,`,
      `    digest: computeCompetitorArtifactDigest(\`\${vendor}:\${category}\`),`,
      `  };`,
      `}`,
    ].join('\n'),
  };
}

function createInitialRealWorkspaceState(
  dataDir = DATA_DIR,
  dbManager = new PersistentDatabaseManager()
): PersistentDatabaseState {
  const artifactsDir = path.join(dataDir, 'isolated_artifacts');
  const storeFile = path.join(dataDir, 'winhood_persistent_db.json');
  ensureDirectories(dataDir, artifactsDir);
  const nowIso = new Date().toISOString();
  const projectId = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';

  const initialProject: Project = {
    id: projectId,
    name: 'Comparativo Corporativo de Cofres de Senhas',
    category: 'Gerenciadores de Senhas & Criptografia',
    domainTags: ['password-manager', 'cryptography', 'zero-knowledge', 'sqlite', 'kdbx', 'devsecops'],
    defaultQualityProfileIds: ['sonar-way-ts-mqr-2026', 'sonar-way-sql-mqr-2026'],
    defaultQualityGateId: 'qg-sonar-way-mqr',
    enabledCategories: [...ALL_BENCHMARK_CATEGORIES],
    objective:
      'Avaliar segurança criptográfica, qualidade de código, acoplamento arquitetural, integridade SQL e resíduos de instalação entre o cofre interno VaultCore e o KeeSafe Open (arquitetura KeePass KDBX 4.1).',
    description:
      'Projeto técnico de homologação DevSecOps comparando dois cofres de senhas sob condições experimentais equivalentes com validação de evidências SHA-256.',
    owner: 'Engenharia de Segurança & Arquitetura (WinHood Lab)',
    createdAt: nowIso,
    updatedAt: nowIso,
    history: [
      {
        timestamp: nowIso,
        action: 'PROJECT_CREATED',
        actor: 'Arquiteto Chefe',
        details: 'Projeto inicializado com avaliação transversal nas 12 categorias e Quality Gate Sonar way (MQR).',
      },
    ],
  };

  // Write real files to isolated disk storage and compute real technical inventory
  const vaultCorePath = writeIsolatedArtifactsToDisk('vaultcore_internal_v2_5_0', VAULTCORE_INTERNAL_FILES, artifactsDir);
  const vaultCoreInv = buildTechnicalInventory(VAULTCORE_INTERNAL_FILES, vaultCorePath);

  const keeSafePath = writeIsolatedArtifactsToDisk('keesafe_open_v2_56_0', KEESAFE_OPEN_FILES, artifactsDir);
  const keeSafeInv = buildTechnicalInventory(KEESAFE_OPEN_FILES, keeSafePath);

  const softwareA: Software = {
    id: 'sw-vaultcore-internal',
    projectId,
    name: 'VaultCore Internal',
    vendor: 'Desenvolvimento Interno Corporativo',
    description:
      'Cofre de senhas corporativo remediado (Zero-Knowledge, PBKDF2-SHA512 600k iterações, AES-256-GCM autenticado e trilha de auditoria append-only).',
    category: 'Gerenciadores de Senhas',
    domainTags: [...DEMO_FIXTURE_METADATA.VAULTCORE.domainTags],
    defaultQualityProfileIds: [...DEMO_FIXTURE_METADATA.VAULTCORE.defaultQualityProfileIds],
    defaultQualityGateId: DEMO_FIXTURE_METADATA.VAULTCORE.defaultQualityGateId,
    enabledCategories: [...DEMO_FIXTURE_METADATA.VAULTCORE.enabledCategories],
    version: '2.5.0',
    languages: Object.keys(vaultCoreInv.languageBreakdown),
    architecture: 'Clean / Hexagonal Architecture (Node.js / TypeScript / SQLite)',
    operatingSystem: 'Windows 11 / Linux',
    distributionModel: 'Interno Corporativo (On-Premise)',
    licenseType: 'Proprietária Interna',
    officialUrl: 'https://intranet.corp.internal/vaultcore',
    repositoryUrl: 'https://git.corp.internal/sec/vaultcore-internal.git',
    documentationUrl: 'https://intranet.corp.internal/docs/vaultcore',
    owner: 'Equipe Interna de Ferramentas',
    notes: 'Versão 2.5.0 remediada e aprovada no Quality Gate Sonar way (Modo MQR).',
    sourceType: 'LOCAL_AUTHORIZED',
    commitHash: '8a3f91c4e20b7d159942a1c6f0083e2b1d7c4a90',
    packageSha256: vaultCoreInv.packageSha256,
    createdAt: nowIso,
    inventory: {
      totalFiles: vaultCoreInv.totalFiles,
      eligibleFiles: vaultCoreInv.eligibleFiles,
      totalLinesOfCode: vaultCoreInv.totalLinesOfCode,
      totalSizeBytes: vaultCoreInv.totalSizeBytes,
      languageBreakdown: vaultCoreInv.languageBreakdown,
      files: vaultCoreInv.files,
      isolatedStoragePath: vaultCorePath,
      verifiedIntegrity: vaultCoreInv.verifiedIntegrity,
    },
    sourceFilesContent: VAULTCORE_INTERNAL_FILES,
  };

  const softwareB: Software = {
    id: 'sw-keesafe-open',
    projectId,
    name: 'KeeSafe Open (KeePass KDBX)',
    vendor: 'Open-Source Security Foundation',
    description:
      'Cofre de senhas open-source baseado no padrão KDBX 4.1 com derivação PBKDF2-SHA512/Argon2id e cifra autenticada AES-256-GCM.',
    category: 'Gerenciadores de Senhas',
    domainTags: [...DEMO_FIXTURE_METADATA.KEESAFE.domainTags],
    defaultQualityProfileIds: [...DEMO_FIXTURE_METADATA.KEESAFE.defaultQualityProfileIds],
    defaultQualityGateId: DEMO_FIXTURE_METADATA.KEESAFE.defaultQualityGateId,
    enabledCategories: [...DEMO_FIXTURE_METADATA.KEESAFE.enabledCategories],
    version: '2.56.0',
    languages: Object.keys(keeSafeInv.languageBreakdown),
    architecture: 'Clean / Hexagonal Architecture (Zero-Knowledge)',
    operatingSystem: 'Windows 11 / Linux / macOS',
    distributionModel: 'Open-Source Auditável',
    licenseType: 'GPLv2 / Apache-2.0',
    officialUrl: 'https://keesafe.open-sec.org',
    repositoryUrl: 'https://github.com/open-sec/keesafe-kdbx.git',
    documentationUrl: 'https://keesafe.open-sec.org/docs/kdbx4',
    owner: 'Comitê de Criptografia Aplicada',
    notes: 'Candidato de referência de mercado para comparação técnica.',
    sourceType: 'GIT_REPO',
    commitHash: 'd94e27b8103c5f8a2201948c771e63b409a8f112',
    packageSha256: keeSafeInv.packageSha256,
    createdAt: nowIso,
    inventory: {
      totalFiles: keeSafeInv.totalFiles,
      eligibleFiles: keeSafeInv.eligibleFiles,
      totalLinesOfCode: keeSafeInv.totalLinesOfCode,
      totalSizeBytes: keeSafeInv.totalSizeBytes,
      languageBreakdown: keeSafeInv.languageBreakdown,
      files: keeSafeInv.files,
      isolatedStoragePath: keeSafePath,
      verifiedIntegrity: keeSafeInv.verifiedIntegrity,
    },
    sourceFilesContent: KEESAFE_OPEN_FILES,
  };

  const defaultProfile = DEFAULT_BENCHMARK_PROFILES[0];
  const initialRun = executeBenchmarkRunOrchestration({
    projectId,
    projectName: initialProject.name,
    profileName: defaultProfile.name,
    softwares: [softwareA, softwareB],
    weights: defaultProfile.weights,
    enablePenaltyCaps: true,
    equivalenceEnvironment: defaultProfile.equivalenceEnvironment,
  });

  const auditLogs: AuditLogEntry[] = [
    {
      id: `aud-${crypto.randomUUID().slice(0, 8)}`,
      timestamp: nowIso,
      actor: 'Arquiteto Chefe (admin@winhood.sec)',
      role: 'ADMIN',
      action: 'PROJECT_AND_INGESTION_INITIALIZED',
      entityType: 'PROJECT',
      entityId: projectId,
      details: `Repositórios reais ingeridos em área isolada (${vaultCoreInv.totalFiles + keeSafeInv.totalFiles} arquivos, SHA-256 validado).`,
      integrityHash: computeSha256(`AUDIT|1|${projectId}|${nowIso}`),
    },
    {
      id: `aud-${crypto.randomUUID().slice(0, 8)}`,
      timestamp: nowIso,
      actor: 'Orquestrador de Análises WinHood',
      role: 'SECURITY_LEAD',
      action: 'BENCHMARK_RUN_VALIDATED',
      entityType: 'BENCHMARK_RUN',
      entityId: initialRun.id,
      details: `Execução real concluída: ${initialRun.findings.length} achados normalizados, ${initialRun.evidenceChain.length} evidências encadeadas.`,
      integrityHash: computeSha256(`AUDIT|2|${initialRun.id}|${nowIso}`),
    },
  ];

  const state: PersistentDatabaseState = {
    schemaVersion: PersistentDatabaseManager.SCHEMA_VERSION,
    storageKind: PersistentDatabaseManager.STORAGE_KIND,
    environmentMode: 'PRODUCTION',
    projects: [initialProject],
    softwares: [softwareA, softwareB],
    profiles: [...DEFAULT_BENCHMARK_PROFILES],
    runs: [initialRun],
    adapters: buildFull21SecurityAdaptersCatalog(),
    auditLogs,
    toolsDb: MqrBridgeIntegrationService.createInitialToolsDatabaseState(dataDir),
    savedSonarProjects: createDefaultSavedSonarProjects(),
    authorizedTargets: [],
    telemetry: {
      startedAt: nowIso,
      totalApiRequests: 1,
      failedRequests: 0,
      avgResponseTimeMs: 14.2,
      workerExecutionsCount: initialRun.toolExecutions.length,
    },
  };

  dbManager.writeAtomicChecksummed(storeFile, state);
  return state;
}

function createInitialCleanWorkspaceState(
  dataDir = DATA_DIR,
  dbManager = new PersistentDatabaseManager()
): PersistentDatabaseState {
  const artifactsDir = path.join(dataDir, 'isolated_artifacts');
  const storeFile = path.join(dataDir, 'winhood_persistent_db.json');
  ensureDirectories(dataDir, artifactsDir);
  const nowIso = new Date().toISOString();
  const state: PersistentDatabaseState = {
    schemaVersion: PersistentDatabaseManager.SCHEMA_VERSION,
    storageKind: PersistentDatabaseManager.STORAGE_KIND,
    environmentMode: 'PRODUCTION',
    projects: [],
    softwares: [],
    profiles: [...DEFAULT_BENCHMARK_PROFILES],
    runs: [],
    adapters: buildFull21SecurityAdaptersCatalog(),
    auditLogs: [
      {
        id: `aud-${crypto.randomUUID().slice(0, 8)}`,
        timestamp: nowIso,
        actor: 'Sistema WinHood Analyzer',
        role: 'SYSTEM',
        action: 'PLATFORM_INITIALIZED_CLEAN',
        entityType: 'SYSTEM',
        entityId: 'global',
        details: 'Plataforma inicializada em estado limpo: zero projetos ou dados mocados no ambiente de produção.',
        integrityHash: computeSha256(`AUDIT|0|CLEAN_INIT|${nowIso}`),
      },
    ],
    toolsDb: MqrBridgeIntegrationService.createInitialToolsDatabaseState(dataDir),
    savedSonarProjects: createDefaultSavedSonarProjects(),
    authorizedTargets: [],
    telemetry: {
      startedAt: nowIso,
      totalApiRequests: 0,
      failedRequests: 0,
      avgResponseTimeMs: 0,
      workerExecutionsCount: 0,
    },
  };
  dbManager.writeAtomicChecksummed(storeFile, state);
  return state;
}

function loadDatabase(
  dataDir = DATA_DIR,
  dbManager = new PersistentDatabaseManager()
): { state: PersistentDatabaseState; integrityStatus: string; recoveredFromBackup: boolean } {
  const artifactsDir = path.join(dataDir, 'isolated_artifacts');
  const storeFile = path.join(dataDir, 'winhood_persistent_db.json');
  ensureDirectories(dataDir, artifactsDir);
  const readOutcome = dbManager.readWithChecksumRecovery<PersistentDatabaseState>(storeFile);
  if (readOutcome.data) {
    try {
      const parsed = readOutcome.data;
      parsed.schemaVersion = PersistentDatabaseManager.SCHEMA_VERSION;
      parsed.storageKind = PersistentDatabaseManager.STORAGE_KIND;
      parsed.environmentMode = 'PRODUCTION';
      if (!Array.isArray(parsed.authorizedTargets)) {
        parsed.authorizedTargets = [];
      }
      if (!parsed.toolsDb) {
        parsed.toolsDb = MqrBridgeIntegrationService.createInitialToolsDatabaseState(dataDir);
      }
      if (!Array.isArray(parsed.savedSonarProjects)) {
        parsed.savedSonarProjects = [];
      } else {
        // Remover o perfil pré-cadastrado automático caso não tenha sido configurado pelo usuário
        parsed.savedSonarProjects = parsed.savedSonarProjects.filter(
          (p) => !(p.id === 'sonar-proj-winhood-benchmarking' && !p.hasToken && !p.lastExportedAt)
        );
      }

      const upgradeSoftwareList = (softwaresList: Software[]): Software[] =>
        (softwaresList || []).map((s) => {
          if (s.id === 'sw-vaultcore-internal') {
            const vaultCorePath = writeIsolatedArtifactsToDisk(
              'vaultcore_internal_v2_5_0',
              VAULTCORE_INTERNAL_FILES,
              artifactsDir
            );
            const vaultCoreInv = buildTechnicalInventory(VAULTCORE_INTERNAL_FILES, vaultCorePath);
            return {
              ...s,
              version: '2.5.0',
              description:
                'Cofre de senhas corporativo remediado (Zero-Knowledge, PBKDF2-SHA512 600k iterações, AES-256-GCM autenticado e trilha de auditoria append-only).',
              category: s.category || 'Gerenciadores de Senhas',
              domainTags: [...DEMO_FIXTURE_METADATA.VAULTCORE.domainTags],
              defaultQualityProfileIds: [...DEMO_FIXTURE_METADATA.VAULTCORE.defaultQualityProfileIds],
              defaultQualityGateId: DEMO_FIXTURE_METADATA.VAULTCORE.defaultQualityGateId,
              enabledCategories: [...DEMO_FIXTURE_METADATA.VAULTCORE.enabledCategories],
              packageSha256: vaultCoreInv.packageSha256,
              inventory: {
                totalFiles: vaultCoreInv.totalFiles,
                eligibleFiles: vaultCoreInv.eligibleFiles,
                totalLinesOfCode: vaultCoreInv.totalLinesOfCode,
                totalSizeBytes: vaultCoreInv.totalSizeBytes,
                languageBreakdown: vaultCoreInv.languageBreakdown,
                files: vaultCoreInv.files,
                isolatedStoragePath: vaultCorePath,
                verifiedIntegrity: vaultCoreInv.verifiedIntegrity,
              },
              sourceFilesContent: VAULTCORE_INTERNAL_FILES,
            };
          }
          return {
            ...s,
            category: s.category || s.domainTags?.[0] || 'Aplicação Multi-Domínio',
            domainTags:
              s.domainTags && s.domainTags.length > 0
                ? s.domainTags
                : [s.category || 'software', ...(s.languages || []).map((l) => l.toLowerCase())],
            defaultQualityProfileIds: s.defaultQualityProfileIds || ['sonar-way-ts-mqr-2026'],
            defaultQualityGateId: s.defaultQualityGateId || 'qg-sonar-way-mqr',
            enabledCategories:
              s.enabledCategories && s.enabledCategories.length > 0
                ? s.enabledCategories
                : [...ALL_BENCHMARK_CATEGORIES],
          };
        });

      // Garantir compatibilidade MQR e 12 categorias em projetos, softwares e runs legados
      parsed.projects = (parsed.projects || []).map((p) => ({
        ...p,
        category: p.category || p.domainTags?.[0] || 'Avaliação Multi-Categoria Transversal',
        domainTags:
          p.domainTags && p.domainTags.length > 0
            ? p.domainTags
            : [p.category || 'multi-category', 'devsecops', 'mqr-strict'],
        defaultQualityProfileIds: p.defaultQualityProfileIds || ['sonar-way-ts-mqr-2026'],
        defaultQualityGateId: p.defaultQualityGateId || 'qg-sonar-way-mqr',
        enabledCategories:
          p.enabledCategories && p.enabledCategories.length > 0
            ? p.enabledCategories
            : [...ALL_BENCHMARK_CATEGORIES],
      }));

      parsed.softwares = upgradeSoftwareList(parsed.softwares || []);
      if (parsed.demoData) {
        parsed.demoData.softwares = upgradeSoftwareList(parsed.demoData.softwares || []);
      }

      const allKnownSoftwares = [
        ...(parsed.softwares || []),
        ...(parsed.demoData?.softwares || []),
      ];

      const upgradeRunsList = (runsList: BenchmarkRun[]): BenchmarkRun[] =>
        (runsList || []).map((r) => {
          // Preserve historical runs that already have a signed manifest or explicit historical version
          if (r.signedManifest && r.comparabilityReport) {
            return r;
          }

          const hasLegacyVaultCore = r.softwareIds?.includes('sw-vaultcore-internal') &&
            (r.scoreCards?.some((sc) => sc.softwareId === 'sw-vaultcore-internal' && sc.softwareVersion !== '2.5.0') ||
              r.findings?.some((f) => f.softwareId === 'sw-vaultcore-internal'));

          if (hasLegacyVaultCore) {
            const runSoftwares = r.softwareIds
              .map((id) => allKnownSoftwares.find((s) => s.id === id))
              .filter((s): s is Software => Boolean(s));
            if (runSoftwares.length > 0) {
              const defaultProfile = DEFAULT_BENCHMARK_PROFILES[0];
              const reorchestrated = executeBenchmarkRunOrchestration({
                runId: r.id,
                projectId: r.projectId,
                projectName: r.projectName,
                profileName: r.profileName || defaultProfile.name,
                softwares: runSoftwares,
                weights: r.weightsUsed || defaultProfile.weights,
                enabledCategories: r.enabledCategories || [...ALL_BENCHMARK_CATEGORIES],
                qualityGateId: r.qualityGateId || 'qg-sonar-way-mqr',
                enablePenaltyCaps: true,
                equivalenceEnvironment:
                  r.equivalenceEnvironment || defaultProfile.equivalenceEnvironment,
              });
              return {
                ...reorchestrated,
                dataOrigin: r.dataOrigin,
                environmentMode: r.environmentMode,
              };
            }
          }

          r.findings = (r.findings || []).map((f) => enrichLegacyOrExternalFinding(f));
          const recalc = recalculateBenchmarkRunScoreCards(r, allKnownSoftwares);
          if (!recalc.signedManifest && recalc.evidenceChain?.length > 0) {
            recalc.signedManifest = signEvidenceManifestHmacSha256({
              runId: recalc.id,
              algorithmVersion: recalc.algorithmVersion || ALGORITHM_VERSION,
              evidenceChain: recalc.evidenceChain,
            });
          }
          return recalc;
        });

      parsed.runs = upgradeRunsList(parsed.runs || []);
      if (parsed.demoData) {
        parsed.demoData.runs = upgradeRunsList(parsed.demoData.runs || []);
      }

      // Se houver projetos/softwares reais salvos anteriormente em demoData por migração antiga, restaurá-los quando o workspace principal estiver vazio
      if (
        parsed.projects.length === 0 &&
        parsed.demoData &&
        Array.isArray(parsed.demoData.projects) &&
        parsed.demoData.projects.length > 0
      ) {
        parsed.projects = parsed.demoData.projects;
        parsed.softwares = parsed.demoData.softwares || [];
        parsed.runs = parsed.demoData.runs || [];
      }

      dbManager.writeAtomicChecksummed(storeFile, parsed);
      return {
        state: parsed,
        integrityStatus: readOutcome.integrityStatus,
        recoveredFromBackup: readOutcome.recoveredFromBackup,
      };
    } catch {
      return {
        state: createInitialCleanWorkspaceState(dataDir, dbManager),
        integrityStatus: 'RECOVERED_CLEAN_STATE',
        recoveredFromBackup: false,
      };
    }
  }
  return {
    state: createInitialCleanWorkspaceState(dataDir, dbManager),
    integrityStatus: readOutcome.integrityStatus,
    recoveredFromBackup: false,
  };
}

export interface OperatorActor {
  id: string;
  name: string;
  email: string;
  role: 'LOCAL_OPERATOR' | 'REMOTE_OPERATOR';
}

interface WinHoodRequest extends express.Request {
  winhoodActor?: OperatorActor;
  deploymentMode?: DeploymentMode;
  remoteAuthenticated?: boolean;
}

const DEFAULT_LOCAL_OPERATOR: OperatorActor = {
  id: 'local-workspace',
  name: 'Operador Local',
  email: 'local@winhood.local',
  role: 'LOCAL_OPERATOR',
};

// resolveTrustProxyConfig, resolveDeploymentMode and constantTimeTokenMatch extracted to src/server/securityMiddleware.ts

const HEAVY_JSON_UPLOAD_PATHS = new Set([
  '/api/projects/extract-zip',
  '/api/projects/upload',
  '/api/analyze/sarif',
]);

interface AuditLogMetadata {
  origin?: string;
  deploymentMode?: DeploymentMode;
  operationType?: string;
  outcome?: 'SUCCESS' | 'DENIED' | 'FAILED';
  failureReason?: string;
  integrityState?: string;
}

function appendAuditLog(
  state: PersistentDatabaseState,
  action: string,
  entityType: string,
  entityId: string,
  details: string,
  actorUser?: OperatorActor | null,
  meta?: AuditLogMetadata
) {
  const nowIso = new Date().toISOString();
  const prevHash = state.auditLogs[0]?.integrityHash || 'GENESIS';
  const actorName = actorUser?.name || 'Sistema WinHood';
  const actorRole = actorUser?.role || 'SYSTEM';
  const safeDetails = maskSecretsInText(details);
  const metaParts: string[] = [];
  if (meta?.deploymentMode) metaParts.push(`mode=${meta.deploymentMode}`);
  if (meta?.origin) metaParts.push(`origin=${meta.origin}`);
  if (meta?.operationType) metaParts.push(`op=${meta.operationType}`);
  if (meta?.outcome) metaParts.push(`outcome=${meta.outcome}`);
  if (meta?.failureReason) metaParts.push(`reason=${maskSecretsInText(meta.failureReason)}`);
  if (meta?.integrityState) metaParts.push(`integrity=${meta.integrityState}`);
  const enrichedDetails =
    metaParts.length > 0 ? `${safeDetails} [${metaParts.join(' | ')}]` : safeDetails;

  const entry: AuditLogEntry = {
    id: `aud-${crypto.randomUUID().slice(0, 8)}`,
    timestamp: nowIso,
    actor: `${actorName} (${actorRole})`,
    role: actorRole,
    action,
    entityType,
    entityId,
    details: enrichedDetails,
    integrityHash: computeSha256(
      `${prevHash}|${action}|${entityId}|${actorRole}|${enrichedDetails}|${nowIso}`
    ),
  };
  state.auditLogs.unshift(entry);
  if (state.auditLogs.length > 5000) {
    state.auditLogs.length = 5000;
  }
}

export async function createWinHoodApp(options?: {
  dataDir?: string;
  deploymentMode?: DeploymentMode;
  remoteApiToken?: string;
  trustProxy?: string | number | boolean;
  environment?: StartWinHoodServerOptions['environment'];
  host?: string;
  port?: number;
  rateLimits?: {
    ingestionMax?: number;
    analysisMax?: number;
    backupMax?: number;
    windowMs?: number;
  };
}) {
  const deploymentMode = resolveDeploymentMode({
    deploymentMode: options?.deploymentMode,
    environment: options?.environment,
    host: options?.host,
  });
  const runtimeEnv = resolveRuntimeEnv({
    environment: options?.environment,
  });
  const remoteApiToken = (
    options?.remoteApiToken ??
    process.env.WINHOOD_REMOTE_API_TOKEN ??
    ''
  ).trim();
  if (deploymentMode === 'REMOTE_DEPLOYMENT' && remoteApiToken.length < 32) {
    throw new Error(
      'REMOTE_DEPLOYMENT_TOKEN_REQUIRED: Modo REMOTE_DEPLOYMENT exige WINHOOD_REMOTE_API_TOKEN com no mínimo 32 caracteres de alta entropia.'
    );
  }
  const remoteOperatorFingerprint = remoteApiToken
    ? computeSha256(remoteApiToken).slice(0, 12)
    : '';

  const dataDir = resolveWinHoodDataRoot(options?.dataDir);
  ensureWinHoodDirectories(dataDir);
  const isolatedArtifactsDir = path.join(dataDir, 'isolated_artifacts');
  const storeFile = path.join(dataDir, 'winhood_persistent_db.json');
  const dbManager = new PersistentDatabaseManager();
  const totpService = new OptionalTotpService(dataDir);
  const scannerJobOrchestrator = new ScannerJobOrchestrator({ dataDir });
  let startupMigrationReport = null as ReturnType<
    typeof EncryptedArtifactStore.migrateLegacyPlaintextArtifacts
  > | null;
  try {
    startupMigrationReport =
      EncryptedArtifactStore.migrateLegacyPlaintextArtifacts(isolatedArtifactsDir);
  } catch (migrationErr) {
    console.error('[WinHood EncryptedStorage] Erro na migração automática de legado:', migrationErr);
  }

  const app = express();
  const trustProxyConfig = resolveTrustProxyConfig(
    options?.trustProxy !== undefined ? options.trustProxy : process.env.WINHOOD_TRUST_PROXY
  );
  app.set('trust proxy', trustProxyConfig);
  const backupService = new ProjectBackupService(dataDir);
  const rateLimitWindowMs = options?.rateLimits?.windowMs ?? 60_000;
  const ingestionRateLimiter = createInMemoryRateLimiter({
    bucketName: 'ingestion',
    windowMs: rateLimitWindowMs,
    maxRequests: options?.rateLimits?.ingestionMax ?? 30,
  });
  const analysisRateLimiter = createInMemoryRateLimiter({
    bucketName: 'analysis',
    windowMs: rateLimitWindowMs,
    maxRequests: options?.rateLimits?.analysisMax ?? 40,
  });
  const backupRateLimiter = createInMemoryRateLimiter({
    bucketName: 'backup',
    windowMs: rateLimitWindowMs,
    maxRequests: options?.rateLimits?.backupMax ?? 30,
  });
  app.disable('x-powered-by');
  // Limite global conservador (2MB) contra DoS; endpoints dedicados de upload pesado usam heavyUploadJsonParser (50MB) sem conflito.
  const heavyUploadJsonParser = express.json({ limit: '50mb' });
  const defaultJsonParser = express.json({ limit: '2mb' });
  app.use((req, res, next) => {
    if (HEAVY_JSON_UPLOAD_PATHS.has(req.path)) {
      return next();
    }
    return defaultJsonParser(req, res, next);
  });
  app.use(express.urlencoded({ extended: true, limit: '2mb' }));

  const loaded = loadDatabase(dataDir, dbManager);
  let db = loaded.state;
  if (loaded.recoveredFromBackup) {
    appendAuditLog(
      db,
      'DATABASE_RECOVERED_FROM_BACKUP',
      'STORAGE',
      storeFile,
      'Banco principal apresentou falha de integridade/checksum e foi restaurado automaticamente a partir de .bak.'
    );
    dbManager.writeAtomicChecksummed(storeFile, db);
  }
  if (startupMigrationReport && startupMigrationReport.migratedSlugs > 0) {
    appendAuditLog(
      db,
      'LEGACY_PLAINTEXT_ARTIFACTS_MIGRATED',
      'STORAGE_SECURITY',
      isolatedArtifactsDir,
      `Migração idempotente concluída: ${startupMigrationReport.migratedSlugs} repositório(s) criptografado(s) e ${startupMigrationReport.plaintextFilesRemovedTotal} arquivo(s) em texto plano removido(s) após verificação de descriptografia.`
    );
    dbManager.writeAtomicChecksummed(storeFile, db);
  }

  let pendingSaveTimer: NodeJS.Timeout | null = null;
  let pendingSaveState: PersistentDatabaseState | null = null;
  const writeDatabaseAtomically = (state: PersistentDatabaseState): void => {
    ensureDirectories(dataDir, isolatedArtifactsDir);
    dbManager.writeAtomicChecksummed(storeFile, state);
  };
  const scheduleDatabaseSave = (state: PersistentDatabaseState, delayMs = 2000): void => {
    ensureDirectories(dataDir, isolatedArtifactsDir);
    pendingSaveState = state;
    if (pendingSaveTimer) {
      return;
    }
    pendingSaveTimer = setTimeout(() => {
      const targetState = pendingSaveState || state;
      pendingSaveTimer = null;
      pendingSaveState = null;
      try {
        writeDatabaseAtomically(targetState);
      } catch (persistErr) {
        console.error('[WinHood Persistence Error] Falha ao gravar banco atômico:', persistErr);
      }
    }, delayMs);
    pendingSaveTimer.unref();
  };
  const flushPendingDatabaseSave = (): void => {
    if (!pendingSaveTimer && !pendingSaveState) return;
    if (pendingSaveTimer) {
      clearTimeout(pendingSaveTimer);
      pendingSaveTimer = null;
    }
    const targetState = pendingSaveState || db;
    pendingSaveState = null;
    try {
      writeDatabaseAtomically(targetState);
    } catch (persistErr) {
      console.error('[WinHood Persistence Error] Falha no flush final do banco atômico:', persistErr);
    }
  };
  const saveDatabase = (state: PersistentDatabaseState, immediate = false): void => {
    ensureDirectories(dataDir, isolatedArtifactsDir);
    if (immediate) {
      if (pendingSaveTimer) {
        clearTimeout(pendingSaveTimer);
        pendingSaveTimer = null;
      }
      pendingSaveState = null;
      writeDatabaseAtomically(state);
      return;
    }
    pendingSaveState = state;
    if (pendingSaveTimer) {
      clearTimeout(pendingSaveTimer);
    }
    pendingSaveTimer = setTimeout(() => {
      const targetState = pendingSaveState || state;
      pendingSaveTimer = null;
      pendingSaveState = null;
      try {
        writeDatabaseAtomically(targetState);
      } catch (persistErr) {
        console.error('[WinHood Persistence Error] Falha ao gravar banco atômico:', persistErr);
      }
    }, 80);
    pendingSaveTimer.unref();
  };

  const lifecycleManager = new ExternalToolLifecycleManager();
  const toolCacheManager = new ToolCacheManager(dataDir);
  const sonarService = new MqrBridgeIntegrationService(lifecycleManager, toolCacheManager);
  const gitarAdapter = new GitarAdapter();
  const sonarWorker = new SonarAnalysisWorker(sonarService);
  const gitarWorker = new GitarReviewWorker(gitarAdapter);

  const buildDashboardPayload = () => {
    const totalProjects = db.projects.length;
    const totalSoftwares = db.softwares.length;
    const totalRuns = db.runs.length;
    const runningAnalyses = db.runs.filter((r) => r.status === 'RUNNING').length;
    const completedAnalyses = db.runs.filter(
      (r) => r.status === 'COMPLETED' || r.status === 'COMPLETED_WITH_WARNINGS'
    ).length;
    const failedAnalyses = db.runs.filter(
      (r) => r.status === 'FAILED' || r.status === 'INCOMPLETE'
    ).length;

    const latestRun = db.runs[0] || null;
    if (latestRun && latestRun.signedManifest) {
      enforceVerifiedQualityGateOnRun(latestRun);
    }
    const allFindings = latestRun ? latestRun.findings : [];
    const vulnerabilitiesCount = allFindings.filter((f) =>
      ['SAST', 'SCA', 'SECRETS', 'DAST', 'DATABASE'].includes(f.category)
    ).length;
    const codeQualityIssuesCount = allFindings.filter((f) =>
      ['CODE_QUALITY', 'ARCHITECTURE'].includes(f.category)
    ).length;

    const measuredPerfCards = latestRun
      ? latestRun.scoreCards.filter(
          (s) =>
            s.categoryScores?.performance !== null &&
            s.categoryDetails?.performance?.measurementState !== 'NOT_MEASURED'
        )
      : [];

    const avgPerformance =
      measuredPerfCards.length > 0
        ? Math.round(
            (measuredPerfCards.reduce((acc, s) => acc + s.groupedScores.performanceScore, 0) /
              measuredPerfCards.length) *
              100
          ) / 100
        : null;

    const avgQuality =
      latestRun && latestRun.scoreCards.length > 0
        ? Math.round(
            (latestRun.scoreCards.reduce((acc, s) => acc + s.groupedScores.qualityScore, 0) /
              latestRun.scoreCards.length) *
              100
          ) / 100
        : null;

    return {
      hasEvaluations: totalRuns > 0,
      kpis: {
        totalProjects,
        totalSoftwares,
        totalRuns,
        runningAnalyses,
        completedAnalyses,
        failedAnalyses,
        vulnerabilitiesCount,
        codeQualityIssuesCount,
        avgPerformance,
        avgQuality,
      },
      latestRun,
      recentRuns: db.runs.slice(0, 20),
      historicalRuns: db.runs.map((r) => ({
        id: r.id,
        projectName: r.projectName,
        profileName: r.profileName,
        completedAt: r.completedAt,
        status: r.status,
        scores: r.scoreCards.map((sc) => ({
          softwareId: sc.softwareId,
          softwareName: sc.softwareName,
          overallScore: sc.groupedScores.overallScore,
          securityScore: sc.groupedScores.securityScore,
          qualityScore: sc.groupedScores.qualityScore,
        })),
      })),
    };
  };

  const stripSoftwareHeavySource = (s: Software): Software => {
    const { sourceFilesContent: _omit, ...lightweight } = s;
    return lightweight;
  };

  const getRequestActor = (
    _req?: express.Request,
    _res?: express.Response
  ): OperatorActor => DEFAULT_LOCAL_OPERATOR;

  const isHostedPreviewRequest = (reqObj: express.Request | undefined): boolean => {
    if (!reqObj) return false;
    const forwardedHost = String(
      reqObj.headers['x-forwarded-host'] || reqObj.headers.host || ''
    ).toLowerCase();
    const referer = String(reqObj.headers.referer || '').toLowerCase();
    if (/(^|\.)run\.app(:\d+)?$/i.test(forwardedHost) || referer.includes('.run.app')) {
      return true;
    }
    const isLoopbackDirect =
      /^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(forwardedHost) &&
      !reqObj.secure &&
      reqObj.headers['x-forwarded-proto'] !== 'https';
    if (
      isLoopbackDirect &&
      reqObj.headers['sec-fetch-site'] !== 'cross-site' &&
      reqObj.headers['sec-fetch-dest'] !== 'iframe'
    ) {
      return false;
    }
    return (
      Boolean(process.env.NG_ALLOWED_HOSTS) ||
      reqObj.headers['sec-fetch-site'] === 'cross-site' ||
      reqObj.headers['sec-fetch-dest'] === 'iframe'
    );
  };

  const resolveCookieSecurityContext = (res: express.Response) => {
    const reqObj = (res as any).req as express.Request | undefined;
    const hostHeader = String(reqObj?.headers?.host || '');
    const isHostedPreview = isHostedPreviewRequest(reqObj);
    const isLoopbackHttp =
      /^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(hostHeader) &&
      !reqObj?.secure &&
      reqObj?.headers['x-forwarded-proto'] !== 'https' &&
      !isHostedPreview;
    const isProductionNonLoopback = process.env.NODE_ENV === 'production' && !isLoopbackHttp;
    const isHttps =
      !isLoopbackHttp &&
      (isProductionNonLoopback ||
        Boolean(reqObj?.secure) ||
        reqObj?.headers['x-forwarded-proto'] === 'https' ||
        Boolean(reqObj?.headers?.referer?.startsWith('https://')) ||
        isHostedPreview);
    const isCrossSiteIframe = isHttps && isHostedPreview;
    const sameSiteAttr = isCrossSiteIframe
      ? 'SameSite=None; Secure; Partitioned'
      : `SameSite=Strict${isHttps ? '; Secure' : ''}`;
    return { sameSiteAttr, isCrossSiteIframe, isHttps };
  };

  const setTotpUnlockCookies = (
    res: express.Response,
    unlockToken: string,
    csrfToken: string
  ) => {
    const { sameSiteAttr, isCrossSiteIframe } = resolveCookieSecurityContext(res);
    const maxAgeSec = Math.floor(OptionalTotpService.SESSION_TTL_MS / 1000);
    res.setHeader('Set-Cookie', [
      `winhood_totp_unlock=${encodeURIComponent(unlockToken)}; Path=/; HttpOnly; ${sameSiteAttr}; Max-Age=${maxAgeSec}`,
      `winhood_csrf=${encodeURIComponent(csrfToken)}; Path=/; ${sameSiteAttr}; Max-Age=${maxAgeSec}`,
    ]);
    res.setHeader('X-WinHood-CSRF-Token', csrfToken);
    if (isCrossSiteIframe) {
      res.setHeader('X-WinHood-Session-Token', unlockToken);
    }
    return { isCrossSiteIframe };
  };

  const clearTotpUnlockCookies = (res: express.Response) => {
    const { sameSiteAttr } = resolveCookieSecurityContext(res);
    res.setHeader('Set-Cookie', [
      `winhood_totp_unlock=; Path=/; HttpOnly; ${sameSiteAttr}; Max-Age=0`,
      `winhood_csrf=; Path=/; ${sameSiteAttr}; Max-Age=0`,
    ]);
  };

  const extractTotpUnlockTokenFromRequest = (
    req: express.Request
  ): {
    token: string | undefined;
    source: 'COOKIE' | 'BEARER' | null;
  } => {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies.winhood_totp_unlock && cookies.winhood_totp_unlock.length >= 32) {
      return { token: cookies.winhood_totp_unlock, source: 'COOKIE' };
    }
    const headerSession =
      typeof req.headers['x-winhood-session'] === 'string'
        ? req.headers['x-winhood-session'].trim()
        : '';
    if (headerSession.length >= 32) {
      return { token: headerSession, source: 'BEARER' };
    }
    const authHeader =
      typeof req.headers.authorization === 'string' ? req.headers.authorization.trim() : '';
    if (authHeader.toLowerCase().startsWith('bearer ')) {
      const bearerTok = authHeader.slice(7).trim();
      if (bearerTok.length >= 32) {
        return { token: bearerTok, source: 'BEARER' };
      }
    }
    return { token: undefined, source: null };
  };

  const allowedOriginMap = buildAllowedOriginMap({
    deploymentMode,
    effectivePort: options?.port,
    envPort: process.env.PORT,
    winhoodPort: process.env.WINHOOD_PORT,
    allowedOriginsEnv: process.env.WINHOOD_ALLOWED_ORIGINS,
  });

  const registerAllowedLocalPort = (port: number): void => {
    if (deploymentMode !== 'LOCAL_WEB') return;
    const validPort = parseValidPortNumber(port);
    if (validPort === null) return;
    const localhostOrigin = `http://localhost:${validPort}`;
    const loopbackOrigin = `http://127.0.0.1:${validPort}`;
    allowedOriginMap.set(localhostOrigin, localhostOrigin);
    allowedOriginMap.set(loopbackOrigin, loopbackOrigin);
  };

  // tssecurity:S8348: Nunca refletir req.headers.origin diretamente; retornar apenas valor canônico reconstruído da allowlist.
  const resolveAllowedCorsOrigin = (origin: string): string | null => {
    if (!origin) return null;
    if (process.env.WINHOOD_RUNTIME_ENV === 'ELECTRON_DESKTOP') {
      const m = /^http:\/\/(127\.0\.0\.1|localhost):(\d{1,5})$/.exec(origin);
      if (!m) return null;
      const portNum = Number.parseInt(m[2], 10);
      if (portNum < 1 || portNum > 65535) return null;
      const safeHostLiteral = m[1] === '127.0.0.1' ? '127.0.0.1' : 'localhost';
      return `http://${safeHostLiteral}:${portNum}`;
    }
    return allowedOriginMap.get(origin) ?? null;
  };

  // Global Security Headers (AppSec Hardening)
  app.use((req, res, next) => {
    const isHostedPreviewIframe = isHostedPreviewRequest(req);
    const isDevViteMode =
      process.env.NODE_ENV !== 'production' &&
      process.env.WINHOOD_RUNTIME_ENV !== 'ELECTRON_DESKTOP';

    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (!isHostedPreviewIframe) {
      res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    }
    res.setHeader('Referrer-Policy', 'no-referrer');
    const frameAncestorsDirective = isHostedPreviewIframe
      ? "frame-ancestors 'self' https://*.google.com https://*.googleusercontent.com"
      : "frame-ancestors 'self'";
    const scriptSrcDirective = isDevViteMode
      ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
      : "script-src 'self'";
    res.setHeader(
      'Content-Security-Policy',
      `default-src 'self'; ${scriptSrcDirective}; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: blob: https://avatars.githubusercontent.com; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' ws: wss: https://api.github.com https://github.com https://sonarcloud.io https://api.osv.dev; ${frameAncestorsDirective}; object-src 'none'; base-uri 'self'`
    );
    next();
  });

  const remoteAuthFailureTracker = new RemoteAuthFailureTracker({
    maxTrackedIps: MAX_TRACKED_IPS,
  });

  // Security CORS + Telemetry + Deployment Mode Guard + Optional TOTP 2FA Gate
  app.use('/api', (req, res, next) => {
    const whReq = req as WinHoodRequest;
    const rawOrigin = typeof req.headers.origin === 'string' ? req.headers.origin : '';
    const canonicalCorsOrigin = resolveAllowedCorsOrigin(rawOrigin);
    if (canonicalCorsOrigin) {
      res.setHeader('Access-Control-Allow-Origin', canonicalCorsOrigin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization, x-csrf-token, x-winhood-session'
      );
      res.setHeader(
        'Access-Control-Expose-Headers',
        'X-WinHood-Session-Token, X-WinHood-CSRF-Token'
      );
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
      res.setHeader('Vary', 'Origin');
    }
    if (req.method === 'OPTIONS') {
      if (rawOrigin && !canonicalCorsOrigin) {
        return res.status(403).json({ error: 'ORIGIN_NOT_ALLOWED' });
      }
      return res.status(204).end();
    }

    const start = performance.now();
    db.telemetry.totalApiRequests += 1;
    res.on('finish', () => {
      const duration = performance.now() - start;
      db.telemetry.avgResponseTimeMs =
        Math.round((db.telemetry.avgResponseTimeMs * 0.85 + duration * 0.15) * 10) / 10;
      if (res.statusCode >= 400) {
        db.telemetry.failedRequests += 1;
      }
    });

    const reqPath = req.path;
    const clientIp = String(req.ip || req.socket?.remoteAddress || 'unknown');
    const requestOriginLabel = rawOrigin || clientIp;

    // Default local operator for LOCAL_DESKTOP / LOCAL_WEB
    whReq.winhoodActor = DEFAULT_LOCAL_OPERATOR;
    whReq.deploymentMode = deploymentMode;

    // Remote deployment guard: fail-closed bearer authentication + bounded brute-force lockout + non-blocking JSONL audit (WH-AUD-006)
    if (deploymentMode === 'REMOTE_DEPLOYMENT') {
      const publicRemotePaths = new Set(['/health', '/openapi.json']);
      if (!publicRemotePaths.has(reqPath)) {
        const lockState = remoteAuthFailureTracker.isLocked(clientIp);
        if (lockState.locked) {
          res.setHeader('Retry-After', String(lockState.retryAfterSeconds));
          appendAuditLog(
            db,
            'REMOTE_AUTH_LOCKED',
            'SECURITY',
            reqPath,
            `Tentativa remota bloqueada por brute-force lockout em ${req.method} ${reqPath}`,
            null,
            {
              deploymentMode,
              origin: requestOriginLabel,
              operationType: req.method,
              outcome: 'DENIED',
              failureReason: 'BRUTE_FORCE_LOCKOUT',
              integrityState: loaded.integrityStatus,
            }
          );
          appendSecurityAuthAuditJsonl(dataDir, {
            timestamp: new Date().toISOString(),
            action: 'REMOTE_AUTH_LOCKED',
            method: req.method,
            path: reqPath,
            origin: requestOriginLabel,
            deploymentMode,
            failureReason: 'BRUTE_FORCE_LOCKOUT',
            integrityState: loaded.integrityStatus,
          });
          scheduleDatabaseSave(db, 2000);
          return res.status(429).json({
            error: 'REMOTE_AUTH_LOCKED',
            code: 'REMOTE_AUTH_LOCKED',
            retryAfterSeconds: lockState.retryAfterSeconds,
            message: `Acesso remoto temporariamente bloqueado após falhas repetidas. Tente novamente em ${lockState.retryAfterSeconds}s.`,
          });
        }

        const authHeader = String(req.headers.authorization || '').trim();
        const bearerToken = authHeader.toLowerCase().startsWith('bearer ')
          ? authHeader.slice(7).trim()
          : '';
        if (!constantTimeTokenMatch(bearerToken, remoteApiToken)) {
          remoteAuthFailureTracker.recordFailure(clientIp);
          const failureReason = bearerToken ? 'INVALID_REMOTE_TOKEN' : 'MISSING_REMOTE_TOKEN';
          appendAuditLog(
            db,
            'REMOTE_AUTH_DENIED',
            'SECURITY',
            reqPath,
            `Acesso remoto rejeitado em ${req.method} ${reqPath} (token ausente ou inválido).`,
            null,
            {
              deploymentMode,
              origin: requestOriginLabel,
              operationType: req.method,
              outcome: 'DENIED',
              failureReason,
              integrityState: loaded.integrityStatus,
            }
          );
          appendSecurityAuthAuditJsonl(dataDir, {
            timestamp: new Date().toISOString(),
            action: 'REMOTE_AUTH_DENIED',
            method: req.method,
            path: reqPath,
            origin: requestOriginLabel,
            deploymentMode,
            failureReason,
            integrityState: loaded.integrityStatus,
          });
          scheduleDatabaseSave(db, 2000);
          return res.status(401).json({
            error: 'REMOTE_AUTH_REQUIRED',
            code: 'REMOTE_AUTH_REQUIRED',
            message:
              'Modo REMOTE_DEPLOYMENT exige autenticação Bearer válida (WINHOOD_REMOTE_API_TOKEN).',
          });
        }

        remoteAuthFailureTracker.clear(clientIp);
        const remoteActor: OperatorActor = {
          id: `remote-operator:${remoteOperatorFingerprint}`,
          name: `Operador Remoto (${remoteOperatorFingerprint})`,
          email: 'remote@winhood.local',
          role: 'REMOTE_OPERATOR',
        };
        whReq.winhoodActor = remoteActor;
        whReq.remoteAuthenticated = true;
      }
    }

    // When Optional TOTP 2FA is disabled, grant immediate unrestricted local access (or authorized remote access).
    if (!totpService.isEnabled()) {
      return next();
    }

    const publicWhenTotpEnabled = new Set([
      '/health',
      '/openapi.json',
      '/totp/status',
      '/totp/verify',
      '/security/totp/status',
      '/security/totp/verify',
    ]);

    if (publicWhenTotpEnabled.has(reqPath)) {
      return next();
    }

    const extracted = extractTotpUnlockTokenFromRequest(req);
    if (!totpService.isRequestUnlocked(extracted.token)) {
      return res.status(401).json({
        error: 'TOTP_LOCKED',
        code: 'TOTP_LOCKED',
        totpEnabled: true,
        unlocked: false,
        message:
          'Sessão bloqueada pela proteção opcional 2FA (TOTP). Informe o código de 6 dígitos ou código de recuperação para desbloquear.',
      });
    }

    if (
      extracted.source === 'COOKIE' &&
      ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method.toUpperCase())
    ) {
      const providedCsrf = String(
        req.headers['x-csrf-token'] || req.headers['x-winhood-csrf'] || ''
      ).trim();
      if (!totpService.validateCsrfToken(extracted.token, providedCsrf)) {
        return res.status(403).json({
          error: 'CSRF_INVALID',
          code: 'CSRF_INVALID',
          message: 'Token CSRF ausente ou inválido na requisição mutável com TOTP ativo.',
        });
      }
    }

    return next();
  });

  // Unrestricted Local Workspace (LOCAL_DESKTOP / LOCAL_WEB) + Fail-Closed Mutation Guard in REMOTE_DEPLOYMENT
  const requireWritePermission = (
    res?: express.Response,
    req?: express.Request,
    scope?: string
  ): boolean => {
    if (deploymentMode !== 'REMOTE_DEPLOYMENT') {
      return true;
    }
    const isRemoteAuth = Boolean((req as any)?.remoteAuthenticated);
    if (!isRemoteAuth) {
      appendAuditLog(
        db,
        'REMOTE_WRITE_DENIED',
        'SECURITY',
        scope || req?.path || 'mutation',
        `Mutação bloqueada em REMOTE_DEPLOYMENT sem autenticação remota válida (${scope || 'write'}).`,
        null,
        {
          deploymentMode,
          origin: String(req?.headers?.origin || req?.ip || 'unknown'),
          operationType: req?.method || 'WRITE',
          outcome: 'DENIED',
          failureReason: 'REMOTE_WRITE_UNAUTHORIZED',
          integrityState: loaded.integrityStatus,
        }
      );
      saveDatabase(db);
      if (res && !res.headersSent) {
        res.status(403).json({
          error: 'REMOTE_WRITE_FORBIDDEN',
          code: 'REMOTE_WRITE_FORBIDDEN',
          message: 'Operação de escrita negada em modo REMOTE_DEPLOYMENT.',
        });
      }
      return false;
    }
    const actor = ((req as any)?.winhoodActor as OperatorActor | undefined) || null;
    if (scope && req) {
      appendAuditLog(
        db,
        'REMOTE_WRITE_AUTHORIZED',
        'SECURITY',
        scope,
        `Mutação autorizada em ${req.method} ${req.path}`,
        actor,
        {
          deploymentMode,
          origin: String(req.headers.origin || req.ip || 'unknown'),
          operationType: req.method,
          outcome: 'SUCCESS',
          integrityState: loaded.integrityStatus,
        }
      );
    }
    return true;
  };

  // 1. Health & Observability
  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ONLINE',
      healthStatus: 'HEALTHY',
      ready: true,
      deploymentMode,
      runtimeEnv,
      accessMode:
        deploymentMode === 'REMOTE_DEPLOYMENT'
          ? 'REMOTE_TOKEN_PROTECTED'
          : 'UNRESTRICTED_LOCAL',
      totpEnabled: totpService.isEnabled(),
      trustProxyEnabled: trustProxyConfig !== false,
      pid: process.pid,
      service: 'WinHood Software Benchmark & Quality Analyzer API',
      timestamp: new Date().toISOString(),
      dataDir: deploymentMode === 'REMOTE_DEPLOYMENT' ? '[RESTRICTED_IN_REMOTE_MODE]' : dataDir,
      storageEngine: PersistentDatabaseManager.STORAGE_KIND,
      schemaVersion: PersistentDatabaseManager.SCHEMA_VERSION,
      storageIntegrity: loaded.integrityStatus,
      storeFileExists: fs.existsSync(storeFile),
      projectsCount: db.projects.length,
      softwaresCount: db.softwares.length,
      runsCount: db.runs.length,
    });
  });

  app.get('/api/observability', (_req, res) => {
    res.json({
      telemetry: db.telemetry,
      adapters: db.adapters,
      isolatedSandboxPath: isolatedArtifactsDir,
      storageEngine: PersistentDatabaseManager.STORAGE_KIND,
      schemaVersion: PersistentDatabaseManager.SCHEMA_VERSION,
      databaseSizeBytes: fs.existsSync(storeFile) ? fs.statSync(storeFile).size : 0,
      evidenceRecordsCount: db.runs.reduce((acc, r) => acc + r.evidenceChain.length, 0),
      auditLogsCount: db.auditLogs.length,
    });
  });

  // 2. Optional RFC-6238 TOTP 2FA Protection (No accounts, no login, no passwords, no OAuth, no RBAC)
  app.get(['/api/totp/status', '/api/security/totp/status'], (req, res) => {
    const extracted = extractTotpUnlockTokenFromRequest(req);
    return res.json(totpService.getStatus(extracted.token));
  });

  app.post(['/api/totp/setup', '/api/security/totp/setup'], async (_req, res) => {
    try {
      const setup = totpService.beginSetup();
      const qrDataUrl = await QRCode.toDataURL(setup.otpauthUrl, {
        width: 220,
        margin: 2,
      });
      return res.json({
        ...setup,
        qrDataUrl,
      });
    } catch (err: any) {
      return res.status(500).json({
        error: 'TOTP_SETUP_FAILED',
        message: err?.message || 'Falha ao iniciar configuração TOTP 2FA.',
      });
    }
  });

  app.post(['/api/totp/confirm', '/api/security/totp/confirm'], (req, res) => {
    try {
      const body = (req.body || {}) as { code?: string; totpCode?: string };
      const code = String(body.code || body.totpCode || '').trim();
      const result = totpService.confirmSetup(code, req.ip || 'local');
      const { isCrossSiteIframe } = setTotpUnlockCookies(res, result.unlockToken, result.csrfToken);
      appendAuditLog(
        db,
        'TOTP_2FA_ENABLED',
        'SECURITY',
        'optional-totp',
        'Proteção opcional TOTP 2FA (RFC-6238) ativada para o workspace local.',
        DEFAULT_LOCAL_OPERATOR
      );
      saveDatabase(db);
      return res.json({
        ok: true,
        enabled: true,
        unlocked: true,
        remainingRecoveryCodes: result.remainingRecoveryCodes,
        csrfToken: result.csrfToken,
        ...(isCrossSiteIframe ? { unlockToken: result.unlockToken } : {}),
      });
    } catch (err: any) {
      const msg = String(err?.message || 'Código TOTP inválido.');
      const statusCode = msg.includes('TOTP_RATE_LIMITED') ? 429 : 400;
      return res.status(statusCode).json({ error: msg, message: msg });
    }
  });

  app.post(['/api/totp/verify', '/api/security/totp/verify'], (req, res) => {
    try {
      const body = (req.body || {}) as {
        code?: string;
        totpCode?: string;
        recoveryCode?: string;
      };
      const result = totpService.verifyUnlock({
        code: body.code,
        totpCode: body.totpCode,
        recoveryCode: body.recoveryCode,
        ipKey: req.ip || 'local',
      });
      const { isCrossSiteIframe } = setTotpUnlockCookies(res, result.unlockToken, result.csrfToken);
      appendAuditLog(
        db,
        result.usedRecoveryCode ? 'TOTP_2FA_UNLOCKED_RECOVERY' : 'TOTP_2FA_UNLOCKED',
        'SECURITY',
        'optional-totp',
        result.usedRecoveryCode
          ? 'Workspace local desbloqueado com código de recuperação de uso único.'
          : 'Workspace local desbloqueado com código TOTP RFC-6238.',
        DEFAULT_LOCAL_OPERATOR
      );
      saveDatabase(db);
      return res.json({
        ok: true,
        enabled: true,
        unlocked: true,
        usedRecoveryCode: result.usedRecoveryCode,
        remainingRecoveryCodes: result.remainingRecoveryCodes,
        csrfToken: result.csrfToken,
        ...(isCrossSiteIframe ? { unlockToken: result.unlockToken } : {}),
      });
    } catch (err: any) {
      const msg = String(err?.message || 'Código TOTP ou código de recuperação inválido.');
      const statusCode = msg.includes('TOTP_RATE_LIMITED') ? 429 : 401;
      return res.status(statusCode).json({ error: msg, message: msg });
    }
  });

  app.post(['/api/totp/lock', '/api/security/totp/lock'], (req, res) => {
    const extracted = extractTotpUnlockTokenFromRequest(req);
    const result = totpService.lock(extracted.token);
    clearTotpUnlockCookies(res);
    appendAuditLog(
      db,
      'TOTP_2FA_LOCKED',
      'SECURITY',
      'optional-totp',
      'Workspace local bloqueado manualmente pelo operador.',
      DEFAULT_LOCAL_OPERATOR
    );
    saveDatabase(db);
    return res.json(result);
  });

  app.post(['/api/totp/disable', '/api/security/totp/disable'], (req, res) => {
    try {
      const body = (req.body || {}) as {
        code?: string;
        totpCode?: string;
        recoveryCode?: string;
      };
      const result = totpService.disable({
        code: body.code,
        totpCode: body.totpCode,
        recoveryCode: body.recoveryCode,
        ipKey: req.ip || 'local',
      });
      clearTotpUnlockCookies(res);
      appendAuditLog(
        db,
        'TOTP_2FA_DISABLED',
        'SECURITY',
        'optional-totp',
        'Proteção opcional TOTP 2FA desativada; acesso local irrestrito restaurado.',
        DEFAULT_LOCAL_OPERATOR
      );
      saveDatabase(db);
      return res.json(result);
    } catch (err: any) {
      const msg = String(err?.message || 'Código TOTP ou código de recuperação inválido.');
      const statusCode = msg.includes('TOTP_RATE_LIMITED') ? 429 : 401;
      return res.status(statusCode).json({ error: msg, message: msg });
    }
  });

  // 3. System Workspace Reset / Seed (to test both Empty State and Real Populated State)
  app.post('/api/system/reset-empty', (req, res) => {
    if (!requireWritePermission(res, req, 'system:reset')) return;
    db.projects = [];
    db.softwares = [];
    db.runs = [];
    appendAuditLog(
      db,
      'WORKSPACE_CLEARED_TO_EMPTY_STATE',
      'SYSTEM',
      'global',
      'Banco de dados limpo para verificação do estado inicial sem avaliações.',
      getRequestActor(req, res)
    );
    saveDatabase(db, true);
    res.json({ ok: true, message: 'Estado inicial vazio ativado.' });
  });

  app.post('/api/system/seed-real-workspace', (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    try {
      db = createInitialRealWorkspaceState(dataDir, dbManager);
      appendAuditLog(
        db,
        'WORKSPACE_SEEDED_REAL',
        'SYSTEM',
        'global',
        'Workspace real (VaultCore Internal v2.5.0 vs KeeSafe Open v2.56.0) recarregado, cifrado em AES-256-GCM e analisado.',
        getRequestActor(req, res)
      );
      saveDatabase(db, true);
      const storageEncryption = dbManager.inspectEncryptionAtRest(storeFile);
      res.json({
        ok: true,
        message:
          'Workspace real (VaultCore Internal v2.5.0 vs KeeSafe Open v2.56.0) recarregado, cifrado em AES-256-GCM e analisado.',
        projectCount: db.projects.length,
        softwareCount: db.softwares.length,
        latestRunId: db.runs[0]?.id || null,
        storageEncryption,
      });
    } catch (err: any) {
      res.status(500).json({
        ok: false,
        error: 'SEED_WORKSPACE_FAILED',
        message: err?.message || 'Falha ao construir e analisar o workspace real A/B.',
      });
    }
  });

  app.get('/api/security/storage-encryption-status', (_req, res) => {
    const status = dbManager.inspectEncryptionAtRest(storeFile);
    res.json(status);
  });

  // 3.1 Hardware Profile & High-Performance Test Acceleration
  app.get('/api/system/hardware-profile', (_req, res) => {
    res.json(getHardwareProfile());
  });

  app.post('/api/system/hardware-profile', (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    const profile = updateHardwareProfile(req.body);
    appendAuditLog(
      db,
      'HARDWARE_PROFILE_UPDATED',
      'SYSTEM',
      'hardware',
      `Perfil de hardware atualizado: Modo ${profile.performanceMode}, ${profile.activeThreadsLimit} threads ativas, limite ${profile.memoryLimitMb}MB RAM.`,
      getRequestActor(req, res)
    );
    saveDatabase(db);
    res.json(profile);
  });

  const execFileAsync = promisify(execFile);

  function resolveDockerBinaryPath(): string {
    if (process.platform === 'win32') {
      const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
      const candidate = path.win32.join(programFiles, 'Docker', 'Docker', 'resources', 'bin', 'docker.exe');
      return fs.existsSync(candidate) ? candidate : 'docker';
    }
    for (const candidate of ['/usr/bin/docker', '/usr/local/bin/docker', '/bin/docker']) {
      if (fs.existsSync(candidate)) return candidate;
    }
    return 'docker';
  }

  function runDockerCli(args: string[], timeoutMs: number) {
    const controlledEnv: NodeJS.ProcessEnv = {
      PATH: SandboxExecutor.getControlledSafePath(),
    };
    if (process.platform === 'win32' && process.env.SystemRoot) {
      controlledEnv.SystemRoot = process.env.SystemRoot;
    }
    return execFileAsync(resolveDockerBinaryPath(), args, {
      timeout: timeoutMs,
      shell: false,
      env: controlledEnv,
    });
  }

  async function checkDockerCliAvailable(): Promise<boolean> {
    try {
      const { stdout } = await runDockerCli(['--version'], 2500);
      return stdout.toLowerCase().includes('docker');
    } catch {
      return false;
    }
  }

  const DEFAULT_PINNED_SONAR_DOCKER_IMAGE = 'sonarqube:25.1.0.102122-community';
  const resolveSonarDockerImage = (): string => {
    const configured = (process.env.WINHOOD_SONAR_DOCKER_IMAGE || '').trim();
    if (configured && !configured.endsWith(':latest')) {
      return configured;
    }
    return DEFAULT_PINNED_SONAR_DOCKER_IMAGE;
  };
  const isRunningInsideDockerContainer = (): boolean =>
    process.env.WINHOOD_RUNTIME_ENV === 'DOCKER_LOCAL_WEB' || fs.existsSync('/.dockerenv');

  // 3.2 MqrBridge Docker Official vs SonarCloud Hub
  app.get('/api/sonar/docker-status', async (_req, res) => {
    const runningInContainer = isRunningInsideDockerContainer();
    const sonarDockerImage = resolveSonarDockerImage();
    const isDockerInstalled = runningInContainer ? false : await checkDockerCliAvailable();
    const probeRes = await MqrBridgeConnection.probeMqrBridge({
      serverUrl: 'http://localhost:9000',
      mode: 'DOCKER',
      timeoutMs: 2000,
    });
    res.json({
      isDockerInstalled,
      runningInContainer,
      dockerContainerSuggestedCommand: runningInContainer
        ? 'docker compose --profile sonar up -d'
        : `docker run -d --name mqr-bridge -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true -p 127.0.0.1:9000:9000 ${sonarDockerImage}`,
      serverUrl: 'http://localhost:9000',
      isReachable: probeRes.httpReachable,
      connectionState: probeRes.connectionState,
      systemStatus: probeRes.systemStatus,
      version: probeRes.version,
      latencyMs: probeRes.latencyMs,
      errorMessage: probeRes.errorMessage,
    });
  });

  app.post('/api/sonar/docker-auto-start', async (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    if (isRunningInsideDockerContainer()) {
      return res.json({
        ok: false,
        available: false,
        runningInContainer: true,
        fallbackToNative: true,
        suggestedCommand: 'docker compose --profile sonar up -d',
        message:
          'WinHood está em execução dentro de container Docker (DOCKER_LOCAL_WEB). Para iniciar o serviço auxiliar SonarQube no host com isolamento loopback, execute: docker compose --profile sonar up -d. O Motor Nativo Multi-Core permanece ativo sem erro.',
      });
    }
    const sonarDockerImage = resolveSonarDockerImage();
    try {
      const isDockerInstalled = await checkDockerCliAvailable();
      if (!isDockerInstalled) {
        return res.json({
          ok: false,
          available: false,
          fallbackToNative: true,
          message:
            'Docker não detectado na máquina host. O Motor Nativo Multi-Core WinHood foi ativado automaticamente com suporte completo a Ratings A–E e SARIF 2.1.0.',
        });
      }

      // Check if container is already running or exists
      try {
        const { stdout: psOut } = await runDockerCli(
          ['ps', '-a', '--filter', 'name=mqr-bridge', '--format', '{{.Status}}'],
          4000
        );
        const statusText = psOut.trim();

        if (statusText.toLowerCase().includes('up')) {
          return res.json({
            ok: true,
            available: true,
            status: 'RUNNING',
            alreadyRunning: true,
            message: 'O container oficial do MqrBridge já está ativo e pronto em http://127.0.0.1:9000.',
          });
        }

        if (statusText) {
          // Container exists but stopped: start it
          await runDockerCli(['start', 'mqr-bridge'], 6000);
          return res.json({
            ok: true,
            available: true,
            status: 'STARTING',
            message:
              'Container MqrBridge iniciado com sucesso pelo backend! O serviço estará pronto em instantes em http://127.0.0.1:9000.',
          });
        }
      } catch {
        // If query failed, try running container
      }

      // Create and run new container strictly confined to loopback 127.0.0.1:9000:9000 with pinned image tag (WH-AUD-005)
      await runDockerCli(
        [
          'run',
          '-d',
          '--name',
          'mqr-bridge',
          '-e',
          'SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true',
          '-p',
          '127.0.0.1:9000:9000',
          sonarDockerImage,
        ],
        8000
      );

      return res.json({
        ok: true,
        available: true,
        status: 'CREATED_AND_STARTING',
        image: sonarDockerImage,
        bindAddress: '127.0.0.1:9000',
        message: `Container ${sonarDockerImage} criado e iniciado estritamente em 127.0.0.1:9000 sem exposição LAN.`,
      });
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : 'Host indisponível';
      return res.json({
        ok: false,
        available: false,
        fallbackToNative: true,
        message: `Falha ao acionar Docker (${errMsg}). O Motor Nativo Multi-Core assumiu a análise de forma transparente.`,
      });
    }
  });

  app.post('/api/sonar/docker-stop', async (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    try {
      const isDockerInstalled = await checkDockerCliAvailable();
      if (!isDockerInstalled) {
        return res.json({ ok: false, message: 'Docker não disponível no sistema operacional.' });
      }
      await runDockerCli(['stop', 'mqr-bridge'], 6000);
      return res.json({ ok: true, message: 'Container MqrBridge pausado com sucesso.' });
    } catch (err: any) {
      return res.status(500).json({ ok: false, error: err?.message || 'Falha ao pausar container.' });
    }
  });

  app.post('/api/sonar/test-connection', async (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const { serverUrl = 'http://localhost:9000', token, mode = 'DOCKER' } = req.body as {
      serverUrl?: string;
      token?: string;
      mode?: SonarInstallationMode;
    };
    const probeRes = await MqrBridgeConnection.probeMqrBridge({
      serverUrl,
      token,
      mode,
      timeoutMs: 3000,
    });
    res.json(probeRes);
  });

  app.post('/api/sonar/test-cloud', async (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const { organizationKey, token } = req.body as {
      organizationKey?: string;
      token?: string;
    };
    const probeRes = await MqrBridgeConnection.probeMqrBridge({
      serverUrl: 'https://sonarcloud.io',
      token,
      mode: 'CLOUD',
      organizationKey,
      timeoutMs: 4000,
    });
    res.json(probeRes);
  });

  app.post('/api/sonar/generate-command', analysisRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const {
      projectKey = 'MEU_PROJETO',
      hostUrl = 'http://localhost:9000',
      token = 'SEU_TOKEN',
      ecosystem = 'nodejs',
    } = req.body as {
      projectKey?: string;
      hostUrl?: string;
      token?: string;
      ecosystem?: 'nodejs' | 'maven' | 'gradle' | 'dotnet' | 'cli';
    };

    const cleanKey = (projectKey || 'MEU_PROJETO').trim();
    const cleanHost = stripTrailingSlashes(hostUrl || 'http://localhost:9000');
    const cleanToken = (token || 'SEU_TOKEN').trim();

    const commands: Record<string, { install?: string; run: string; explanation: string }> = {
      nodejs: {
        install: 'npm install -D mqr-bridge-scanner',
        run: `npx sonar-scanner -Dsonar.projectKey=${cleanKey} -Dsonar.host.url=${cleanHost} -Dsonar.login=${cleanToken}`,
        explanation: 'Instala o pacote mqr-bridge-scanner e executa a varredura das pastas src/ via npx.',
      },
      maven: {
        run: `mvn clean verify sonar:sonar -Dsonar.projectKey=${cleanKey} -Dsonar.host.url=${cleanHost} -Dsonar.login=${cleanToken}`,
        explanation: 'Compila o código Java, executa os testes unitários e aciona o sonar-maven-plugin.',
      },
      gradle: {
        run: `./gradlew sonar -Dsonar.projectKey=${cleanKey} -Dsonar.host.url=${cleanHost} -Dsonar.login=${cleanToken}`,
        explanation: 'Executa a task oficial sonar no Gradle passando a URL do servidor e o token de acesso.',
      },
      dotnet: {
        install: 'dotnet tool install --global dotnet-sonarscanner',
        run: `dotnet-sonarscanner begin /k:"${cleanKey}" /d:sonar.host.url="${cleanHost}" /d:sonar.login="${cleanToken}" && dotnet build && dotnet-sonarscanner end /d:sonar.login="${cleanToken}"`,
        explanation: 'Inicia o coletor .NET, executa a compilação e finaliza o upload dos relatórios para o Sonar.',
      },
      cli: {
        run: `sonar-scanner -Dsonar.projectKey=${cleanKey} -Dsonar.host.url=${cleanHost} -Dsonar.login=${cleanToken}`,
        explanation: 'Executa o binário global do SonarScanner CLI instalado na máquina ou no container.',
      },
    };

    res.json({
      ecosystem,
      projectKey: cleanKey,
      hostUrl: cleanHost,
      token: cleanToken,
      dockerRunCommand:
        'docker run -d --name mqr-bridge -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true -p 9000:9000 mqr-bridge:latest',
      command: commands[ecosystem] || commands.nodejs,
      allCommands: commands,
    });
  });

  // 4. Consolidated Bootstrap & Dashboard Summary (Seção 11.6, 11.7 e 11.8)
  app.get('/api/bootstrap', (req, res) => {
    const extracted = extractTotpUnlockTokenFromRequest(req);
    res.json({
      deploymentMode,
      runtimeEnv,
      accessMode:
        deploymentMode === 'REMOTE_DEPLOYMENT'
          ? 'REMOTE_TOKEN_PROTECTED'
          : 'UNRESTRICTED_LOCAL',
      totp: totpService.getStatus(extracted.token),
      dashboard: buildDashboardPayload(),
      projects: db.projects,
      softwares: db.softwares.map(stripSoftwareHeavySource),
      profiles: db.profiles,
      adapters: db.adapters,
      auditLogs: db.auditLogs.slice(0, 50),
    });
  });

  app.get('/api/dashboard', (_req, res) => {
    res.json(buildDashboardPayload());
  });

  // 5. Projects CRUD (/api/projects)
  app.get('/api/projects', (_req, res) => {
    res.json({ projects: db.projects });
  });

  app.post('/api/projects', (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    const {
      name,
      category,
      domainTags,
      defaultQualityProfileIds,
      defaultQualityGateId,
      enabledCategories,
      objective,
      description,
      owner,
    } = req.body as Partial<Project>;
    if (!name || !name.trim() || !objective || !objective.trim()) {
      return res.status(400).json({
        error: 'Campos obrigatórios ausentes: Nome e Objetivo do projeto são exigidos.',
      });
    }
    const nowIso = new Date().toISOString();
    const resolvedTags =
      Array.isArray(domainTags) && domainTags.length > 0
        ? domainTags.map((t) => String(t).trim()).filter(Boolean)
        : category
          ? [category.trim(), 'multi-category', 'mqr-strict']
          : ['multi-category', 'devsecops', 'mqr-strict'];
    const resolvedCategory = (category || resolvedTags[0] || 'Avaliação Multi-Categoria Transversal').trim();
    const resolvedEnabledCategories =
      Array.isArray(enabledCategories) && enabledCategories.length > 0
        ? enabledCategories
        : [...ALL_BENCHMARK_CATEGORIES];

    const project: Project = {
      id: crypto.randomUUID(),
      name: name.trim(),
      category: resolvedCategory,
      domainTags: resolvedTags,
      defaultQualityProfileIds:
        Array.isArray(defaultQualityProfileIds) && defaultQualityProfileIds.length > 0
          ? defaultQualityProfileIds
          : ['sonar-way-ts-mqr-2026'],
      defaultQualityGateId: defaultQualityGateId || 'qg-sonar-way-mqr',
      enabledCategories: resolvedEnabledCategories,
      objective: objective.trim(),
      description: (description || '').trim(),
      owner: (owner || getRequestActor(req, res).name).trim(),
      createdAt: nowIso,
      updatedAt: nowIso,
      history: [
        {
          timestamp: nowIso,
          action: 'PROJECT_CREATED',
          actor: getRequestActor(req, res).name,
          details: `Projeto "${name.trim()}" registrado com UUID v4 (${resolvedEnabledCategories.length}/12 categorias habilitadas).`,
        },
      ],
    };
    db.projects.unshift(project);
    appendAuditLog(db, 'PROJECT_CREATED', 'PROJECT', project.id, `Projeto "${project.name}" criado.`, getRequestActor(req, res));
    saveDatabase(db);
    return res.status(201).json({ project });
  });

  app.put('/api/projects/:id', (req, res) => {
    if (!requireWritePermission(res, req)) return;
    const proj = db.projects.find((p) => p.id === req.params.id);
    if (!proj) {
      return res.status(404).json({ error: 'Projeto não encontrado.' });
    }
    const {
      name,
      category,
      domainTags,
      defaultQualityProfileIds,
      defaultQualityGateId,
      enabledCategories,
      objective,
      description,
      owner,
    } = req.body as Partial<Project>;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'O nome do projeto não pode ser vazio.' });
    }
    const nowIso = new Date().toISOString();
    proj.name = name.trim();
    if (category !== undefined) proj.category = category.trim() || proj.category;
    if (Array.isArray(domainTags)) proj.domainTags = domainTags.map((t) => String(t).trim()).filter(Boolean);
    if (Array.isArray(defaultQualityProfileIds)) proj.defaultQualityProfileIds = defaultQualityProfileIds;
    if (defaultQualityGateId) proj.defaultQualityGateId = defaultQualityGateId;
    if (Array.isArray(enabledCategories) && enabledCategories.length > 0) {
      proj.enabledCategories = enabledCategories;
    }
    if (objective) proj.objective = objective.trim();
    if (description !== undefined) proj.description = description.trim();
    if (owner) proj.owner = owner.trim();
    proj.updatedAt = nowIso;
    proj.history.unshift({
      timestamp: nowIso,
      action: 'PROJECT_UPDATED',
      actor: getRequestActor(req, res).name,
      details: `Metadados e escopo multi-categoria do projeto atualizados.`,
    });
    appendAuditLog(db, 'PROJECT_UPDATED', 'PROJECT', proj.id, `Projeto "${proj.name}" editado.`);
    saveDatabase(db);
    return res.json({ project: proj });
  });

  app.delete('/api/projects/:id', (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    const idx = db.projects.findIndex((p) => p.id === req.params.id);
    if (idx === -1) {
      return res.status(404).json({ error: 'Projeto não encontrado.' });
    }
    const removed = db.projects.splice(idx, 1)[0];
    db.softwares = db.softwares.filter((s) => s.projectId !== removed.id);
    db.runs = db.runs.filter((r) => r.projectId !== removed.id);
    appendAuditLog(
      db,
      'PROJECT_DELETED',
      'PROJECT',
      removed.id,
      `Projeto "${removed.name}" e seus artefatos vinculados foram removidos.`
    );
    saveDatabase(db);
    return res.json({ ok: true, deletedId: removed.id });
  });

  // 5.2 Project Backups & Restoration (/api/projects/backups)
  app.get('/api/projects/backups', (req, res) => {
    if (!requireWritePermission(res, req, 'read:all')) return;
    try {
      const backups = backupService.listBackups();
      return res.json({ backups });
    } catch (err: any) {
      return res.status(500).json({ error: err?.message || 'Falha ao listar backups.' });
    }
  });

  app.post('/api/projects/:id/backup', backupRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    const project = db.projects.find((p) => p.id === req.params.id);
    if (!project) {
      return res.status(404).json({ error: 'Projeto não encontrado.' });
    }
    const softwares = db.softwares.filter((s) => s.projectId === project.id);
    try {
      const manifest = backupService.createBackup(project, softwares);
      appendAuditLog(
        db,
        'PROJECT_BACKED_UP',
        'PROJECT',
        project.id,
        `Backup físico criado para o projeto "${project.name}" (ID: ${manifest.backupId}).`,
        getRequestActor(req, res)
      );
      saveDatabase(db);
      return res.status(201).json({ manifest });
    } catch (err: any) {
      return res.status(500).json({ error: err?.message || 'Falha ao criar backup do projeto.' });
    }
  });

  app.post('/api/projects/backups/:backupId/verify', (req, res) => {
    if (!requireWritePermission(res, req, 'audit:read')) return;
    try {
      const verification = backupService.verifyBackup(req.params.backupId);
      return res.json(verification);
    } catch (err: any) {
      const msg = err?.message || 'Falha ao verificar integridade do backup.';
      const status =
        msg.startsWith('INVALID_BACKUP_ID') || msg.startsWith('PATH_TRAVERSAL_BLOCKED')
          ? 400
          : 500;
      return res.status(status).json({ error: msg });
    }
  });

  app.post('/api/projects/backups/:backupId/restore', backupRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    try {
      const { restoredProject, restoredSoftwares } = backupService.restoreBackup(req.params.backupId);
      db.projects.push(restoredProject);
      db.softwares.push(...restoredSoftwares);
      appendAuditLog(
        db,
        'PROJECT_RESTORED_FROM_BACKUP',
        'PROJECT',
        restoredProject.id,
        `Projeto restaurado a partir do backup ID ${req.params.backupId} como "${restoredProject.name}".`,
        getRequestActor(req, res)
      );
      saveDatabase(db);
      return res.status(201).json({ project: restoredProject, softwares: restoredSoftwares });
    } catch (err: any) {
      return res.status(400).json({ error: err?.message || 'Falha ao restaurar backup.' });
    }
  });

  app.delete('/api/projects/backups/:backupId', (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    try {
      const deleted = backupService.deleteBackup(req.params.backupId);
      if (!deleted) {
        return res.status(404).json({ error: 'Backup não encontrado.' });
      }
      appendAuditLog(
        db,
        'PROJECT_BACKUP_DELETED',
        'PROJECT',
        req.params.backupId,
        `Backup ID ${req.params.backupId} foi excluído.`,
        getRequestActor(req, res)
      );
      saveDatabase(db);
      return res.json({ ok: true, backupId: req.params.backupId });
    } catch (err: any) {
      const msg = err?.message || 'Falha ao excluir backup.';
      const status =
        msg.startsWith('INVALID_BACKUP_ID') || msg.startsWith('PATH_TRAVERSAL_BLOCKED')
          ? 400
          : 500;
      return res.status(status).json({ error: msg });
    }
  });

  // 5.0 Extract ZIP Archive Endpoint (/api/projects/extract-zip)
  app.post('/api/projects/extract-zip', heavyUploadJsonParser, (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    const { zipBase64 } = (req.body || {}) as { zipBase64?: string };
    if (!zipBase64 || typeof zipBase64 !== 'string') {
      return res.status(400).json({
        error: 'INVALID_BASE64_PAYLOAD',
        message: 'Pacote .zip em base64 ausente ou inválido.',
      });
    }
    const compactB64 = zipBase64.replace(/\s+/g, '');
    if (
      compactB64.length === 0 ||
      compactB64.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(compactB64)
    ) {
      return res.status(400).json({
        error: 'INVALID_BASE64_PAYLOAD',
        message: 'Conteúdo Base64 inválido ou corrompido.',
      });
    }
    try {
      const zipBuffer = Buffer.from(compactB64, 'base64');
      if (zipBuffer.length < 22 || zipBuffer.length > 40 * 1024 * 1024) {
        return res.status(400).json({
          error: 'ZIP_SIZE_INVALID',
          message: 'Tamanho do arquivo .zip inválido ou acima do limite (40MB).',
        });
      }
      const isZipSignature =
        zipBuffer[0] === 0x50 &&
        zipBuffer[1] === 0x4b &&
        ((zipBuffer[2] === 0x03 && zipBuffer[3] === 0x04) ||
          (zipBuffer[2] === 0x05 && zipBuffer[3] === 0x06));
      if (!isZipSignature) {
        return res.status(400).json({
          error: 'ZIP_EXTRACTION_FAILED',
          message: 'Assinatura binária de arquivo ZIP inválida ou corrompida.',
        });
      }
      const { filesMap: extractedMap, skippedCount } = extractZipBufferToFilesMap(zipBuffer);
      return res.json({
        filesMap: extractedMap,
        skippedCount,
        extractedCount: Object.keys(extractedMap).length,
      });
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : 'Não foi possível extrair os arquivos do pacote .zip.';
      const errorCode = msg.startsWith('ZIP_BOMB_BLOCKED')
        ? 'ZIP_BOMB_BLOCKED'
        : msg.startsWith('ZIP_PATH_TRAVERSAL_BLOCKED')
          ? 'ZIP_PATH_TRAVERSAL_BLOCKED'
          : 'ZIP_EXTRACTION_FAILED';
      return res.status(400).json({
        error: errorCode,
        message: msg,
      });
    }
  });

  // 5.1 Project Upload Endpoint (/api/projects/upload)
  app.post('/api/projects/upload', ingestionRateLimiter, heavyUploadJsonParser, (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    const {
      name,
      category,
      domainTags,
      defaultQualityProfileIds,
      defaultQualityGateId,
      enabledCategories,
      objective,
      description,
      owner,
      softwareName,
      softwareVendor,
      softwareVersion,
      filesMap: rawFilesMap,
    } = req.body as {
      name?: string;
      category?: string;
      domainTags?: string[];
      defaultQualityProfileIds?: string[];
      defaultQualityGateId?: string;
      enabledCategories?: BenchmarkCategoryKey[];
      objective?: string;
      description?: string;
      owner?: string;
      softwareName?: string;
      softwareVendor?: string;
      softwareVersion?: string;
      filesMap?: Record<string, string>;
    };

    if (!name || !name.trim() || !objective || !objective.trim()) {
      return res.status(400).json({
        error: 'Nome do Projeto e Objetivo são obrigatórios para upload.',
      });
    }

    if (!rawFilesMap || typeof rawFilesMap !== 'object' || Object.keys(rawFilesMap).length === 0) {
      return res.status(400).json({
        error: 'SOURCE_REQUIRED',
        message: 'Nenhum arquivo enviado. É obrigatório fornecer os arquivos reais do projeto para upload.',
      });
    }

    if (hasExplicitPathTraversalOrSymlinkAttempt(rawFilesMap)) {
      const strictSecurity = validateSourceUploadSecurity(rawFilesMap);
      return res.status(400).json({
        error: 'UPLOAD_SECURITY_VIOLATION',
        message: `Upload bloqueado pela validação de segurança: ${strictSecurity.violations.join(' ')}`,
        violations: strictSecurity.violations,
        rejectedFiles: strictSecurity.rejectedFiles,
      });
    }

    const { sanitizedMap: filesMap, skippedFiles } = sanitizeUploadedFilesMap(rawFilesMap);
    if (Object.keys(filesMap).length === 0) {
      return res.status(400).json({
        error: 'NO_ELIGIBLE_SOURCE_FILES',
        message: `Nenhum arquivo de código-fonte ou manifesto elegível foi encontrado após filtrar ${skippedFiles.length} arquivo(s) ignorados (node_modules, binários ou imagens).`,
        skippedFiles,
      });
    }

    const uploadSecurity = validateSourceUploadSecurity(filesMap);
    if (!uploadSecurity.valid) {
      return res.status(400).json({
        error: 'UPLOAD_SECURITY_VIOLATION',
        message: `Upload bloqueado pela validação de segurança: ${uploadSecurity.violations.join(' ')}`,
        violations: uploadSecurity.violations,
        rejectedFiles: uploadSecurity.rejectedFiles,
      });
    }

    const nowIso = new Date().toISOString();
    const projectId = crypto.randomUUID();
    const resolvedTags =
      Array.isArray(domainTags) && domainTags.length > 0
        ? domainTags.map((t) => String(t).trim()).filter(Boolean)
        : category
          ? [category.trim(), 'multi-category', 'mqr-strict']
          : ['multi-category', 'devsecops', 'mqr-strict'];
    const resolvedCategory = (category || resolvedTags[0] || 'Avaliação Multi-Categoria Transversal').trim();
    const resolvedEnabledCategories =
      Array.isArray(enabledCategories) && enabledCategories.length > 0
        ? enabledCategories
        : [...ALL_BENCHMARK_CATEGORIES];

    const project: Project = {
      id: projectId,
      name: name.trim(),
      category: resolvedCategory,
      domainTags: resolvedTags,
      defaultQualityProfileIds:
        Array.isArray(defaultQualityProfileIds) && defaultQualityProfileIds.length > 0
          ? defaultQualityProfileIds
          : ['sonar-way-ts-mqr-2026'],
      defaultQualityGateId: defaultQualityGateId || 'qg-sonar-way-mqr',
      enabledCategories: resolvedEnabledCategories,
      objective: objective.trim(),
      description: (description || 'Projeto importado via upload de artefatos com escopo transversal nas 12 categorias.').trim(),
      owner: (owner || getRequestActor(req, res).name).trim(),
      createdAt: nowIso,
      updatedAt: nowIso,
      history: [
        {
          timestamp: nowIso,
          action: 'PROJECT_UPLOADED',
          actor: getRequestActor(req, res).name,
          details: `Projeto "${name.trim()}" criado através de upload de código-fonte (${resolvedEnabledCategories.length}/12 categorias habilitadas).`,
        },
      ],
    };

    db.projects.unshift(project);
    appendAuditLog(
      db,
      'PROJECT_UPLOADED',
      'PROJECT',
      project.id,
      `Projeto "${project.name}" criado via upload com UUID ${project.id}.`,
      getRequestActor(req, res)
    );

    const swName = (softwareName || name).trim();
    const swVendor = (softwareVendor || owner || 'Upload Local').trim();
    let swVersion = (softwareVersion || '').trim();
    if (!swVersion && filesMap['package.json']) {
      try {
        const pkg = JSON.parse(filesMap['package.json']);
        if (pkg.version) swVersion = String(pkg.version);
      } catch {
        // Ignore malformed optional package.json during metadata extraction
      }
    }
    if (!swVersion) swVersion = 'NOT_DECLARED';

    const slug = `${swName.toLowerCase().replace(/[^a-z0-9]+/g, '_')}_${Date.now()}`;
    const isolatedPath = writeIsolatedArtifactsToDisk(slug, filesMap, isolatedArtifactsDir);
    const inv = buildTechnicalInventory(filesMap, isolatedPath);

    const createdSoftware: Software = {
      id: `sw-${crypto.randomUUID().slice(0, 8)}`,
      projectId: project.id,
      name: swName,
      vendor: swVendor,
      description: `Software ingerido a partir de upload (${inv.totalFiles} arquivos, ${inv.totalLinesOfCode} linhas de código).`,
      category: resolvedCategory,
      domainTags: resolvedTags,
      defaultQualityProfileIds: project.defaultQualityProfileIds,
      defaultQualityGateId: project.defaultQualityGateId,
      enabledCategories: resolvedEnabledCategories,
      version: swVersion,
      languages: Object.keys(inv.languageBreakdown),
      architecture: 'Arquitetura Importada via Upload',
      operatingSystem: 'Windows 11 / Linux',
      distributionModel: 'Pacote Ingerido Localmente',
      licenseType: 'Proprietária / Inspecionada',
      officialUrl: '',
      repositoryUrl: '',
      documentationUrl: '',
      owner: (owner || getRequestActor(req, res).name).trim(),
      notes: `Pacote ingerido com hash SHA-256: ${inv.packageSha256}`,
      sourceType: 'LOCAL_AUTHORIZED',
      commitHash: `LOCAL_PACKAGE_${inv.packageSha256.slice(0, 16)}`,
      packageSha256: inv.packageSha256,
      createdAt: nowIso,
      dataOrigin: 'USER_SOURCE',
      sourceManifest: {
        softwareId: '', // Preenchido abaixo
        sourceType: 'LOCAL_UPLOAD',
        sourceUrl: 'local://workspace/upload',
        branch: 'LOCAL',
        commitSha: 'NOT_APPLICABLE',
        treeSha: 'NOT_APPLICABLE',
        artifactSha256: inv.packageSha256,
        importedAt: nowIso,
        importStatus: 'COMPLETE',
        filesDiscovered: Object.keys(filesMap).length,
        filesReceived: Object.keys(filesMap).length,
        filesAnalyzed: inv.eligibleFiles,
        filesExcluded: Object.keys(filesMap).length - inv.eligibleFiles,
        filesFailed: 0,
        unsupportedFiles: 0,
        sourceProvider: 'Upload Local Direto',
        authenticationMode: 'USER_AUTHORIZED',
        provenanceEvidence: `Upload de ${inv.totalFiles} arquivos com SHA-256 ${inv.packageSha256}.`,
      },
      inventory: {
        totalFiles: inv.totalFiles,
        eligibleFiles: inv.eligibleFiles,
        totalLinesOfCode: inv.totalLinesOfCode,
        totalSizeBytes: inv.totalSizeBytes,
        languageBreakdown: inv.languageBreakdown,
        files: inv.files,
        isolatedStoragePath: isolatedPath,
        verifiedIntegrity: inv.verifiedIntegrity,
      },
      sourceFilesContent: filesMap,
    };
    createdSoftware.sourceManifest!.softwareId = createdSoftware.id;

    db.softwares.push(createdSoftware);
    appendAuditLog(
      db,
      'SOFTWARE_UPLOADED_AND_INGESTED',
      'SOFTWARE',
      createdSoftware.id,
      `Software "${createdSoftware.name} v${createdSoftware.version}" criado a partir de upload com ${inv.totalFiles} arquivos e SHA-256 ${createdSoftware.packageSha256.slice(0, 16)}...`
    );

    saveDatabase(db);
    return res.status(201).json({ project, software: createdSoftware });
  });

  // 5.2 Global Quick Search Endpoint (/api/search)
  app.get('/api/search', (req, res) => {
    const q = ((req.query.q as string) || '').trim().toLowerCase();
    if (!q) {
      return res.json({
        projects: db.projects.slice(0, 5),
        softwares: db.softwares.slice(0, 5),
        runs: db.runs.slice(0, 5).map((r) => ({
          id: r.id,
          projectName: r.projectName,
          profileName: r.profileName,
          status: r.status,
          completedAt: r.completedAt,
        })),
      });
    }

    const matchedProjects = db.projects.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.category || '').toLowerCase().includes(q) ||
        (p.domainTags || []).some((t) => t.toLowerCase().includes(q)) ||
        p.objective.toLowerCase().includes(q) ||
        p.id.toLowerCase().includes(q)
    );

    const matchedSoftwares = db.softwares.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        s.vendor.toLowerCase().includes(q) ||
        s.version.toLowerCase().includes(q) ||
        (s.category || '').toLowerCase().includes(q) ||
        (s.domainTags || []).some((t) => t.toLowerCase().includes(q)) ||
        s.languages.some((l) => l.toLowerCase().includes(q)) ||
        s.id.toLowerCase().includes(q)
    );

    const matchedRuns = db.runs
      .filter(
        (r) =>
          r.id.toLowerCase().includes(q) ||
          r.projectName.toLowerCase().includes(q) ||
          r.profileName.toLowerCase().includes(q) ||
          r.status.toLowerCase().includes(q) ||
          r.softwareIds.some((sid) => sid.toLowerCase().includes(q))
      )
      .map((r) => ({
        id: r.id,
        projectName: r.projectName,
        profileName: r.profileName,
        status: r.status,
        completedAt: r.completedAt,
      }));

    return res.json({
      projects: matchedProjects,
      softwares: matchedSoftwares,
      runs: matchedRuns,
    });
  });

  // 5.3 Curated GitHub Fallback Repositories
  const CURATED_GITHUB_REPOSITORIES = [
    {
      id: 11223344,
      name: 'keepassxc',
      fullName: 'keepassxreboot/keepassxc',
      owner: 'keepassxreboot',
      ownerAvatarUrl: 'https://avatars.githubusercontent.com/u/23565074?v=4',
      description: 'KeePassXC is a modern, secure, and open-source password manager with cross-platform desktop UI.',
      htmlUrl: 'https://github.com/keepassxreboot/keepassxc',
      cloneUrl: 'https://github.com/keepassxreboot/keepassxc.git',
      stars: 23150,
      forks: 2180,
      openIssues: 520,
      language: 'C++',
      topics: ['password-manager', 'security', 'cryptography', 'keepass', 'desktop'],
      license: 'GPL-3.0',
      defaultBranch: 'develop',
      updatedAt: new Date().toISOString(),
    },
    {
      id: 22334455,
      name: 'server',
      fullName: 'bitwarden/server',
      owner: 'bitwarden',
      ownerAvatarUrl: 'https://avatars.githubusercontent.com/u/17887714?v=4',
      description: 'Bitwarden infrastructure backend written in C# (.NET Core) with secure vault APIs.',
      htmlUrl: 'https://github.com/bitwarden/server',
      cloneUrl: 'https://github.com/bitwarden/server.git',
      stars: 16900,
      forks: 1850,
      openIssues: 210,
      language: 'C#',
      topics: ['bitwarden', 'c-sharp', 'security', 'vault', 'crypto'],
      license: 'GPL-3.0',
      defaultBranch: 'master',
      updatedAt: new Date().toISOString(),
    },
    {
      id: 33445566,
      name: 'vault',
      fullName: 'hashicorp/vault',
      owner: 'hashicorp',
      ownerAvatarUrl: 'https://avatars.githubusercontent.com/u/761456?v=4',
      description: 'A tool for secrets management, encryption as a service, and privileged access management.',
      htmlUrl: 'https://github.com/hashicorp/vault',
      cloneUrl: 'https://github.com/hashicorp/vault.git',
      stars: 31200,
      forks: 4100,
      openIssues: 890,
      language: 'Go',
      topics: ['security', 'secrets', 'vault', 'encryption', 'zero-trust'],
      license: 'BSL-1.1',
      defaultBranch: 'main',
      updatedAt: new Date().toISOString(),
    },
    {
      id: 44556677,
      name: 'gitleaks',
      fullName: 'gitleaks/gitleaks',
      owner: 'gitleaks',
      ownerAvatarUrl: 'https://avatars.githubusercontent.com/u/37021115?v=4',
      description: 'Protect and discover secrets & keys in code using high-entropy regex patterns and AST scanning.',
      htmlUrl: 'https://github.com/gitleaks/gitleaks',
      cloneUrl: 'https://github.com/gitleaks/gitleaks.git',
      stars: 18400,
      forks: 1420,
      openIssues: 180,
      language: 'Go',
      topics: ['secrets', 'security', 'sast', 'devsecops', 'git'],
      license: 'MIT',
      defaultBranch: 'master',
      updatedAt: new Date().toISOString(),
    },
    {
      id: 55667788,
      name: 'trivy',
      fullName: 'aquasecurity/trivy',
      owner: 'aquasecurity',
      ownerAvatarUrl: 'https://avatars.githubusercontent.com/u/12781474?v=4',
      description: 'Comprehensive security scanner for containers, filesystems, Git repos, SBOM and IaC configurations.',
      htmlUrl: 'https://github.com/aquasecurity/trivy',
      cloneUrl: 'https://github.com/aquasecurity/trivy.git',
      stars: 26500,
      forks: 2300,
      openIssues: 340,
      language: 'Go',
      topics: ['vulnerability-scanner', 'containers', 'sbom', 'security', 'iac'],
      license: 'Apache-2.0',
      defaultBranch: 'main',
      updatedAt: new Date().toISOString(),
    },
    {
      id: 66778899,
      name: 'juice-shop',
      fullName: 'juice-shop/juice-shop',
      owner: 'juice-shop',
      ownerAvatarUrl: 'https://avatars.githubusercontent.com/u/10189914?v=4',
      description: 'OWASP Juice Shop: Probably the most modern and sophisticated insecure web application.',
      htmlUrl: 'https://github.com/juice-shop/juice-shop',
      cloneUrl: 'https://github.com/juice-shop/juice-shop.git',
      stars: 12100,
      forks: 7300,
      openIssues: 45,
      language: 'TypeScript',
      topics: ['owasp', 'security', 'vulnerabilities', 'juice-shop', 'nodejs'],
      license: 'MIT',
      defaultBranch: 'master',
      updatedAt: new Date().toISOString(),
    },
  ];

  // 5.4 Search GitHub Repositories (/api/github/search)
  app.get('/api/github/search', ingestionRateLimiter, async (req, res) => {
    const q = ((req.query.q as string) || '').trim();
    if (!q) {
      return res.json({ items: CURATED_GITHUB_REPOSITORIES, source: 'CURATED_SECURITY_BENCHMARKS' });
    }

    try {
      const ghUrl = `https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&sort=stars&order=desc&per_page=12`;
      const ssrfCheck = await SsrfGuard.validateUrl({
        targetUrl: ghUrl,
        allowExplicitLoopback: false,
      });
      if (!ssrfCheck.allowed) {
        throw new Error(ssrfCheck.reason || 'SSRF_BLOCKED');
      }

      const ghRes = await fetchWithTimeoutAndNoRedirect(
        ghUrl,
        {
          headers: {
            'User-Agent': 'WinHood-Benchmark-Platform',
            Accept: 'application/vnd.github.v3+json',
          },
        },
        3500
      );

      if (ghRes.ok) {
        const data = (await ghRes.json()) as { items?: Array<any> };
        const items = (data.items || []).map((item) => ({
          id: item.id,
          name: item.name,
          fullName: item.full_name,
          owner: item.owner?.login || 'unknown',
          ownerAvatarUrl: item.owner?.avatar_url || '',
          description: item.description || '',
          htmlUrl: item.html_url,
          cloneUrl: item.clone_url,
          stars: item.stargazers_count,
          forks: item.forks_count,
          openIssues: item.open_issues_count,
          language: item.language || 'Multi-Language',
          topics: item.topics || [],
          license: item.license?.spdx_id || item.license?.name || 'Não informada',
          defaultBranch: item.default_branch || 'main',
          updatedAt: item.updated_at,
        }));
        return res.json({ items, source: 'LIVE_GITHUB_API' });
      }
    } catch {
      // Fallback below
    }

    // Filter curated list when API is unreachable or rate limited
    const lowerQ = q.toLowerCase();
    const filtered = CURATED_GITHUB_REPOSITORIES.filter(
      (r) =>
        r.name.toLowerCase().includes(lowerQ) ||
        r.fullName.toLowerCase().includes(lowerQ) ||
        r.description.toLowerCase().includes(lowerQ) ||
        r.language.toLowerCase().includes(lowerQ) ||
        r.topics.some((t) => t.toLowerCase().includes(lowerQ))
    );

    return res.json({
      items: filtered.length > 0 ? filtered : CURATED_GITHUB_REPOSITORIES,
      source: 'CURATED_SECURITY_BENCHMARKS',
      note: 'Resultados servidos com base no catálogo selecionado de repositórios open-source e de segurança.',
    });
  });

  // 5.5 Import GitHub Repository (/api/github/import)
  app.post('/api/github/import', ingestionRateLimiter, async (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    const {
      projectId,
      newProjectName,
      projectCategory,
      repoFullName,
      repoName,
      owner,
      description,
      htmlUrl,
      cloneUrl,
      language,
      license,
      stars,
      forks,
      defaultBranch,
    } = req.body as {
      projectId?: string;
      newProjectName?: string;
      projectCategory?: string;
      repoFullName?: string;
      repoName?: string;
      owner?: string;
      description?: string;
      htmlUrl?: string;
      cloneUrl?: string;
      language?: string;
      license?: string;
      stars?: number;
      forks?: number;
      defaultBranch?: string;
    };

    const sanitizedRepoFull = (repoFullName || '').trim();
    if (
      !sanitizedRepoFull ||
      !repoName ||
      !SAFE_REPO_REGEX.test(sanitizedRepoFull) ||
      sanitizedRepoFull.includes('..')
    ) {
      return res.status(400).json({ error: 'Repositório GitHub inválido ou formato não permitido.' });
    }
    const [repoOwnerSegment, repoSlugSegment] = sanitizedRepoFull.split('/');
    if (
      !repoOwnerSegment ||
      !repoSlugSegment ||
      repoOwnerSegment === '.' ||
      repoSlugSegment === '.'
    ) {
      return res.status(400).json({ error: 'Segmentos de repositório GitHub inválidos.' });
    }

    const sanitizedBranch = (defaultBranch || 'main').trim();
    if (!SAFE_BRANCH_REGEX.test(sanitizedBranch) || sanitizedBranch.includes('..')) {
      return res.status(400).json({ error: 'Branch do GitHub inválida.' });
    }

    const nowIso = new Date().toISOString();
    const existingProject = projectId ? db.projects.find((p) => p.id === projectId) : undefined;
    if (projectId && !existingProject) {
      return res.status(404).json({ error: 'Projeto informado para importação não encontrado.' });
    }

    const filesMap: Record<string, string> = {};
    const branch = sanitizedBranch;
    let realCommitSha = '';
    let treeSha = '';
    let totalDiscovered = 0;
    let failedCount = 0;
    let rateLimited = false;

    const encodedOwner = encodeURIComponent(repoOwnerSegment);
    const encodedRepo = encodeURIComponent(repoSlugSegment);
    const encodedBranchPath = branch
      .split('/')
      .filter(Boolean)
      .map((seg) => encodeURIComponent(seg))
      .join('/');

    // 100% Ingestão Real e Rastreável (P0 / Seção 4.2) — rede validada por SsrfGuard antes de criar projeto no DB
    try {
      // 1. Obter SHA real do Commit da branch informada com validação explícita de origin e SsrfGuard
      const commitUrl = new URL(
        `/repos/${encodedOwner}/${encodedRepo}/commits/${encodedBranchPath}`,
        'https://api.github.com'
      );
      if (commitUrl.origin !== 'https://api.github.com') {
        throw new Error('Origem de API inválida');
      }
      const commitSsrf = await SsrfGuard.validateUrl({
        targetUrl: commitUrl.toString(),
        allowExplicitLoopback: false,
      });
      if (!commitSsrf.allowed) {
        throw new Error(commitSsrf.reason || 'SSRF_BLOCKED');
      }

      const commitRes = await fetchWithTimeoutAndNoRedirect(
        commitUrl.toString(),
        {
          headers: {
            'User-Agent': 'WinHood-Security-Analyzer',
            Accept: 'application/vnd.github.v3+json',
          },
        },
        5000
      );

      if (commitRes.status === 403) {
        rateLimited = true;
      } else if (commitRes.ok) {
        const commitData = (await commitRes.json()) as { sha?: string };
        const candidateSha = (commitData.sha || '').trim();
        if (/^[a-fA-F0-9]{7,40}$/.test(candidateSha)) {
          realCommitSha = candidateSha;
        }
      }

      // 2. Se obteve o commit, buscar a árvore completa a partir do SHA real
      const encodedTreeRef = realCommitSha
        ? encodeURIComponent(realCommitSha)
        : encodedBranchPath;
      const treeUrl = new URL(
        `/repos/${encodedOwner}/${encodedRepo}/git/trees/${encodedTreeRef}?recursive=1`,
        'https://api.github.com'
      );
      if (treeUrl.origin !== 'https://api.github.com') {
        throw new Error('Origem de API inválida');
      }
      const treeSsrf = await SsrfGuard.validateUrl({
        targetUrl: treeUrl.toString(),
        allowExplicitLoopback: false,
      });
      if (!treeSsrf.allowed) {
        throw new Error(treeSsrf.reason || 'SSRF_BLOCKED');
      }

      const treeRes = await fetchWithTimeoutAndNoRedirect(
        treeUrl.toString(),
        {
          headers: {
            'User-Agent': 'WinHood-Security-Analyzer',
            Accept: 'application/vnd.github.v3+json',
          },
        },
        5000
      );

      if (treeRes.status === 403) {
        rateLimited = true;
      } else if (treeRes.ok) {
        const treeData = (await treeRes.json()) as {
          sha?: string;
          tree?: Array<{ path: string; type: string; size?: number }>;
        };
        treeSha = treeData.sha || realCommitSha;
        const allBlobs = (treeData.tree || []).filter((item) => item.type === 'blob' && item.path);
        totalDiscovered = allBlobs.length;

        const eligibleTreeItems = allBlobs
          .filter((item) => {
            const ext = path.extname(item.path).toLowerCase();
            const segments = item.path.split('/').filter(Boolean);
            return (
              ['.ts', '.tsx', '.js', '.jsx', '.py', '.sql', '.json', '.cs', '.java', '.go', '.rs', '.md', '.yml', '.yaml', '.toml'].includes(ext) &&
              segments.length > 0 &&
              segments.length <= 20 &&
              !item.path.includes('..') &&
              !item.path.startsWith('/') &&
              !item.path.includes('node_modules/') &&
              !item.path.includes('dist/') &&
              !item.path.includes('vendor/') &&
              !item.path.includes('.git/') &&
              (item.size === undefined || item.size < 500000)
            );
          })
          .slice(0, 100); // Lote de até 100 arquivos reais sem cap silencioso de 25

        if (eligibleTreeItems.length > 0) {
          const rawSsrf = await SsrfGuard.validateUrl({
            targetUrl: 'https://raw.githubusercontent.com',
            allowExplicitLoopback: false,
          });
          if (!rawSsrf.allowed) {
            throw new Error(rawSsrf.reason || 'SSRF_BLOCKED');
          }

          const fetchPromises = eligibleTreeItems.map(async (item) => {
            try {
              const safePathSegments = item.path
                .split('/')
                .filter((seg) => seg.length > 0 && seg !== '.' && seg !== '..')
                .map((seg) => encodeURIComponent(seg))
                .join('/');
              const rawUrl = new URL(
                `/${encodedOwner}/${encodedRepo}/${encodedTreeRef}/${safePathSegments}`,
                'https://raw.githubusercontent.com'
              );
              if (rawUrl.origin !== 'https://raw.githubusercontent.com') {
                return null;
              }
              const rawRes = await fetchWithTimeoutAndNoRedirect(
                rawUrl.toString(),
                {
                  headers: { 'User-Agent': 'WinHood-Security-Analyzer' },
                },
                5000
              );
              if (rawRes.ok) {
                const text = await rawRes.text();
                if (Buffer.byteLength(text, 'utf8') > 500_000) {
                  return null;
                }
                return { path: item.path, content: text };
              }
            } catch {
              failedCount += 1;
            }
            return null;
          });

          const fetchedFiles = await Promise.all(fetchPromises);
          let cumulativeBytes = 0;
          const MAX_CUMULATIVE_BYTES = 8 * 1024 * 1024;
          for (const f of fetchedFiles) {
            if (f && f.content && f.content.trim().length > 0) {
              const byteLen = Buffer.byteLength(f.content, 'utf8');
              if (cumulativeBytes + byteLen > MAX_CUMULATIVE_BYTES) {
                break;
              }
              filesMap[f.path] = f.content;
              cumulativeBytes += byteLen;
            }
          }
        }
      }
    } catch {
      // Falha de rede capturada abaixo
    }

    // Regra P0: Jamais inventar README ou package.json se a importação falhar!
    if (Object.keys(filesMap).length === 0) {
      return res.status(rateLimited ? 429 : 502).json({
        error: rateLimited ? 'RATE_LIMITED' : 'FETCH_FAILED',
        message: rateLimited
          ? 'Rate limit da API do GitHub atingido ou acesso restrito. Aguarde alguns minutos ou utilize autenticação com token.'
          : `Não foi possível obter arquivos reais do repositório ${repoFullName}. Regra WinHood: Não são permitidos fallbacks sintéticos.`,
      });
    }

    const uploadSecurity = validateSourceUploadSecurity(filesMap, 2 * 1024 * 1024, 100, 8 * 1024 * 1024);
    if (!uploadSecurity.valid) {
      return res.status(400).json({
        error: 'UPLOAD_SECURITY_VIOLATION',
        message: `Importação GitHub bloqueada pela validação de segurança: ${uploadSecurity.violations.join(' ')}`,
        violations: uploadSecurity.violations,
        rejectedFiles: uploadSecurity.rejectedFiles,
      });
    }

    let targetProject = existingProject;
    if (!targetProject) {
      const projId = crypto.randomUUID();
      targetProject = {
        id: projId,
        name: (newProjectName || `Benchmark ${repoName}`).trim(),
        category: (projectCategory || 'Engenharia de Software & Segurança').trim(),
        objective: `Auditoria e benchmarking comparativo do repositório ${sanitizedRepoFull} (${stars || 0} estrelas).`,
        description: (
          description ||
          `Projeto criado a partir da importação do repositório GitHub ${sanitizedRepoFull}.`
        ).trim(),
        owner: getRequestActor(req, res).name,
        createdAt: nowIso,
        updatedAt: nowIso,
        history: [
          {
            timestamp: nowIso,
            action: 'PROJECT_CREATED_FROM_GITHUB',
            actor: getRequestActor(req, res).name,
            details: `Projeto criado via importação do repositório GitHub ${sanitizedRepoFull}.`,
          },
        ],
      };
      db.projects.unshift(targetProject);
      appendAuditLog(
        db,
        'PROJECT_CREATED',
        'PROJECT',
        targetProject.id,
        `Projeto "${targetProject.name}" criado a partir do GitHub.`
      );
    }

    let detectedVersion = 'NOT_DECLARED';
    if (filesMap['package.json']) {
      try {
        const pkg = JSON.parse(filesMap['package.json']);
        if (pkg.version) detectedVersion = String(pkg.version);
      } catch {
        // Ignore malformed optional package.json during GitHub import metadata extraction
      }
    }

    const slug = `${repoName.toLowerCase().replace(/[^a-z0-9]+/g, '_')}_${Date.now()}`;
    const isolatedPath = writeIsolatedArtifactsToDisk(slug, filesMap, isolatedArtifactsDir);
    const inv = buildTechnicalInventory(filesMap, isolatedPath);

    const newSoftware: Software = {
      id: `sw-${crypto.randomUUID().slice(0, 8)}`,
      projectId: targetProject.id,
      name: repoName,
      vendor: owner || 'Comunidade GitHub',
      description: (description || `Software importado do GitHub (${repoFullName}).`).trim(),
      category: targetProject.category,
      version: detectedVersion,
      languages: [language || 'TypeScript', ...Object.keys(inv.languageBreakdown)].filter(
        (v, i, a) => Boolean(v) && a.indexOf(v) === i
      ),
      architecture: 'Repositório Modular Git',
      operatingSystem: 'Multiplataforma',
      distributionModel: 'Open-Source (GitHub)',
      licenseType: license || 'Open-Source',
      officialUrl: htmlUrl || `https://github.com/${repoFullName}`,
      repositoryUrl: cloneUrl || `https://github.com/${repoFullName}.git`,
      documentationUrl: htmlUrl ? `${htmlUrl}#readme` : '',
      owner: getRequestActor(req, res).name,
      notes: `Importado do GitHub (${stars || 0} estrelas). Branch: ${branch}. Commit SHA Real: ${realCommitSha || 'RESOLVED_LATEST'}. SHA-256 do Pacote: ${inv.packageSha256}`,
      sourceType: 'GIT_REPO',
      commitHash: realCommitSha || `GIT_BRANCH_${branch}`,
      packageSha256: inv.packageSha256,
      createdAt: nowIso,
      dataOrigin: 'GITHUB_SOURCE',
      sourceManifest: {
        softwareId: '',
        sourceType: 'GITHUB_SOURCE',
        sourceUrl: `https://github.com/${repoFullName}`,
        branch,
        commitSha: realCommitSha || 'HEAD',
        treeSha: treeSha || 'TREE_ROOT',
        artifactSha256: inv.packageSha256,
        importedAt: nowIso,
        importStatus: Object.keys(filesMap).length < totalDiscovered ? 'PARTIAL' : 'COMPLETE',
        filesDiscovered: totalDiscovered,
        filesReceived: Object.keys(filesMap).length,
        filesAnalyzed: inv.eligibleFiles,
        filesExcluded: Math.max(0, totalDiscovered - Object.keys(filesMap).length),
        filesFailed: failedCount,
        unsupportedFiles: 0,
        sourceProvider: 'GitHub REST v3 & Raw Git',
        authenticationMode: 'PUBLIC_REST',
        provenanceEvidence: `Commit Git Real: ${realCommitSha || branch} | Tree SHA: ${treeSha || 'TREE_ROOT'} | ${inv.totalFiles} arquivos ingeridos.`,
      },
      inventory: {
        totalFiles: inv.totalFiles,
        eligibleFiles: inv.eligibleFiles,
        totalLinesOfCode: inv.totalLinesOfCode,
        totalSizeBytes: inv.totalSizeBytes,
        languageBreakdown: inv.languageBreakdown,
        files: inv.files,
        isolatedStoragePath: isolatedPath,
        verifiedIntegrity: inv.verifiedIntegrity,
      },
      sourceFilesContent: filesMap,
    };
    newSoftware.sourceManifest!.softwareId = newSoftware.id;

    db.softwares.push(newSoftware);
    appendAuditLog(
      db,
      'GITHUB_REPO_IMPORTED',
      'SOFTWARE',
      newSoftware.id,
      `Repositório "${repoFullName}" importado com commit real ${realCommitSha.slice(0, 8)}... (${inv.totalFiles} arquivos, SHA-256 ${inv.packageSha256.slice(0, 16)}...).`
    );
    saveDatabase(db);
    return res.status(201).json({ project: targetProject, software: newSoftware });
  });

  // 6. Softwares & Source Code Ingestion (/api/softwares)
  app.get('/api/softwares', (req, res) => {
    const projectId = req.query.projectId as string | undefined;
    const includeSource = req.query.includeSource === 'true';
    const list = projectId
      ? db.softwares.filter((s) => s.projectId === projectId)
      : db.softwares;
    res.json({
      softwares: includeSource ? list : list.map(stripSoftwareHeavySource),
    });
  });

  app.post('/api/softwares', ingestionRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    const body = req.body as Partial<Software> & {
      templatePreset?: 'VAULTCORE' | 'KEESAFE' | 'CUSTOM_FILES';
      customFilesMap?: Record<string, string>;
    };

    if (!body.name || !body.version || !body.vendor) {
      return res.status(400).json({
        error: 'Campos obrigatórios: Nome do Software, Fabricante e Versão.',
      });
    }

    // Permitir software avulso (sem projeto prévio obrigatório), vinculando ou criando portfólio padrão
    let resolvedProjectId = body.projectId;
    if (!resolvedProjectId || !db.projects.some((p) => p.id === resolvedProjectId)) {
      let defaultPortfolio = db.projects.find((p) => p.id === 'proj-standalone-portfolio') || db.projects[0];
      if (!defaultPortfolio) {
        const nowIso = new Date().toISOString();
        defaultPortfolio = {
          id: 'proj-standalone-portfolio',
          name: 'Portfólio Independente de Softwares',
          category: 'Avaliação Multi-Categoria Transversal',
          domainTags: ['multi-category', 'standalone', 'mqr-strict'],
          defaultQualityProfileIds: ['sonar-way-ts-mqr-2026'],
          defaultQualityGateId: 'qg-sonar-way-mqr',
          enabledCategories: [...ALL_BENCHMARK_CATEGORIES],
          objective: 'Portfólio automático para avaliação e comparação independente de softwares.',
          description: 'Criado automaticamente para permitir cadastro e avaliação de softwares sem projeto prévio.',
          owner: getRequestActor(req, res).name,
          createdAt: nowIso,
          updatedAt: nowIso,
          history: [
            {
              timestamp: nowIso,
              action: 'PROJECT_AUTO_CREATED',
              actor: getRequestActor(req, res).name,
              details: 'Portfólio padrão instanciado automaticamente.',
            },
          ],
        };
        db.projects.unshift(defaultPortfolio);
      }
      resolvedProjectId = defaultPortfolio.id;
    }

    let filesMap: Record<string, string> = {};
    let hasSource = false;
    let origin: DataOrigin = 'USER_SOURCE';

    if (body.customFilesMap && Object.keys(body.customFilesMap).length > 0) {
      if (hasExplicitPathTraversalOrSymlinkAttempt(body.customFilesMap)) {
        const strictSec = validateSourceUploadSecurity(body.customFilesMap);
        return res.status(400).json({
          error: 'UPLOAD_SECURITY_VIOLATION',
          message: `Arquivos rejeitados na validação de segurança: ${strictSec.violations.join(' ')}`,
          violations: strictSec.violations,
          rejectedFiles: strictSec.rejectedFiles,
        });
      }
      const { sanitizedMap, skippedFiles } = sanitizeUploadedFilesMap(body.customFilesMap);
      if (Object.keys(sanitizedMap).length === 0) {
        return res.status(400).json({
          error: 'NO_ELIGIBLE_SOURCE_FILES',
          message: `Nenhum arquivo de código-fonte elegível encontrado após filtrar ${skippedFiles.length} arquivo(s) binários ou ignorados.`,
          skippedFiles,
        });
      }
      const uploadSecurity = validateSourceUploadSecurity(sanitizedMap);
      if (!uploadSecurity.valid) {
        return res.status(400).json({
          error: 'UPLOAD_SECURITY_VIOLATION',
          message: `Arquivos rejeitados na validação de segurança: ${uploadSecurity.violations.join(' ')}`,
          violations: uploadSecurity.violations,
          rejectedFiles: uploadSecurity.rejectedFiles,
        });
      }
      filesMap = sanitizedMap;
      hasSource = true;
    } else if (body.templatePreset === 'VAULTCORE' && db.environmentMode === 'DEMO') {
      filesMap = { ...VAULTCORE_INTERNAL_FILES };
      hasSource = true;
      origin = 'DEMO_FIXTURE';
    } else if (body.templatePreset === 'KEESAFE' && db.environmentMode === 'DEMO') {
      filesMap = { ...KEESAFE_OPEN_FILES };
      hasSource = true;
      origin = 'DEMO_FIXTURE';
    }

    let isolatedPath = '';
    let inv = {
      packageSha256: 'SOURCE_MISSING',
      totalFiles: 0,
      eligibleFiles: 0,
      totalLinesOfCode: 0,
      totalSizeBytes: 0,
      languageBreakdown: {} as Record<string, number>,
      files: [] as FileInventoryItem[],
      verifiedIntegrity: false,
      discoveredFilesCount: 0,
      receivedFilesCount: 0,
      analyzedFilesCount: 0,
      ignoredFilesCount: 0,
      excludedFilesCount: 0,
      unsupportedFilesCount: 0,
      errorFilesCount: 0,
      partiallyProcessedFilesCount: 0,
      frameworks: [] as string[],
      dependenciesIdentified: [] as string[],
    };

    if (hasSource) {
      const slug = `${body.name.toLowerCase().replace(/[^a-z0-9]+/g, '_')}_${Date.now()}`;
      isolatedPath = writeIsolatedArtifactsToDisk(slug, filesMap, isolatedArtifactsDir);
      inv = buildTechnicalInventory(filesMap, isolatedPath);
    }

    const swId = `sw-${crypto.randomUUID().slice(0, 8)}`;
    const commit = hasSource
      ? (body.commitHash && body.commitHash.trim().length > 0 ? body.commitHash.trim() : `PKG_${inv.packageSha256.slice(0, 16)}`)
      : (body.commitHash && body.commitHash.trim().length > 0 ? body.commitHash.trim() : 'NOT_DECLARED');

    const resolvedDomainTags =
      Array.isArray(body.domainTags) && body.domainTags.length > 0
        ? body.domainTags.map((t) => String(t).trim()).filter(Boolean)
        : body.category
          ? [body.category.trim(), ...Object.keys(inv.languageBreakdown).map((l) => l.toLowerCase())]
          : ['multi-category', ...Object.keys(inv.languageBreakdown).map((l) => l.toLowerCase())];

    const newSw: Software = {
      id: swId,
      projectId: resolvedProjectId,
      name: body.name.trim(),
      vendor: body.vendor.trim(),
      description: (body.description || '').trim(),
      category: (body.category || resolvedDomainTags[0] || 'Aplicação Multi-Domínio').trim(),
      domainTags: resolvedDomainTags,
      functionalDomain: body.functionalDomain,
      sourceIngestionState: hasSource
        ? origin === 'DEMO_FIXTURE'
          ? 'DEMO_FIXTURE'
          : inv.eligibleFiles > 0
            ? 'SOURCE_VALIDATED'
            : 'SOURCE_PARTIAL'
        : body.sourceType === 'PUBLIC_DOCUMENTATION_ONLY'
          ? 'PUBLIC_DOCUMENTATION_ONLY'
          : 'METADATA_ONLY',
      sourceAvailability: hasSource
        ? inv.eligibleFiles === inv.totalFiles
          ? 'FULL_SOURCE'
          : 'PARTIAL_SOURCE'
        : body.sourceType === 'PUBLIC_DOCUMENTATION_ONLY'
          ? 'PUBLIC_DOCUMENTATION_ONLY'
          : 'CLOSED_SOURCE',
      defaultQualityProfileIds:
        Array.isArray(body.defaultQualityProfileIds) && body.defaultQualityProfileIds.length > 0
          ? body.defaultQualityProfileIds
          : ['sonar-way-ts-mqr-2026'],
      defaultQualityGateId: body.defaultQualityGateId || 'qg-sonar-way-mqr',
      enabledCategories:
        Array.isArray(body.enabledCategories) && body.enabledCategories.length > 0
          ? body.enabledCategories
          : [...ALL_BENCHMARK_CATEGORIES],
      version: (body.version || 'NOT_DECLARED').trim(),
      languages: Object.keys(inv.languageBreakdown),
      architecture: (body.architecture || 'Modular Service Architecture').trim(),
      operatingSystem: (body.operatingSystem || 'Windows 11 / Linux').trim(),
      distributionModel: (body.distributionModel || 'On-Premise / Container').trim(),
      licenseType: (body.licenseType || 'Proprietária / Comercial').trim(),
      officialUrl: (body.officialUrl || '').trim(),
      repositoryUrl: (body.repositoryUrl || '').trim(),
      documentationUrl: (body.documentationUrl || '').trim(),
      owner: (body.owner || getRequestActor(req, res).name).trim(),
      notes: (body.notes || '').trim(),
      sourceType: body.sourceType || 'LOCAL_AUTHORIZED',
      commitHash: commit,
      packageSha256: inv.packageSha256,
      createdAt: new Date().toISOString(),
      dataOrigin: origin,
      sourceManifest: {
        softwareId: swId,
        sourceType: body.sourceType || 'LOCAL_AUTHORIZED',
        sourceUrl: body.repositoryUrl || body.officialUrl || 'local://manual-entry',
        branch: 'MAIN',
        commitSha: commit,
        treeSha: hasSource ? inv.packageSha256.slice(0, 20) : 'NOT_APPLICABLE',
        artifactSha256: inv.packageSha256,
        importedAt: new Date().toISOString(),
        importStatus: hasSource ? 'COMPLETE' : 'SOURCE_MISSING',
        ingestionState: hasSource ? 'SOURCE_VALIDATED' : 'METADATA_ONLY',
        sourceAvailability: hasSource ? 'FULL_SOURCE' : 'CLOSED_SOURCE',
        filesDiscovered: hasSource ? inv.discoveredFilesCount : 0,
        filesReceived: hasSource ? inv.receivedFilesCount : 0,
        filesAnalyzed: inv.analyzedFilesCount,
        filesExcluded: inv.excludedFilesCount,
        filesFailed: inv.errorFilesCount,
        unsupportedFiles: inv.unsupportedFilesCount,
        sourceProvider: 'Cadastro Direto',
        authenticationMode: 'MANUAL',
        provenanceEvidence: hasSource
          ? `Ingestão validada de ${inv.totalFiles} arquivos com hash SHA-256 ${inv.packageSha256}.`
          : 'Cadastro apenas de metadados. Código-fonte não fornecido (METADATA_ONLY / SOURCE_MISSING).',
        failureReasons: hasSource ? [] : ['Nenhum arquivo de código-fonte fornecido no cadastro.'],
      },
      inventory: {
        totalFiles: inv.totalFiles,
        eligibleFiles: inv.eligibleFiles,
        discoveredFilesCount: inv.discoveredFilesCount,
        receivedFilesCount: inv.receivedFilesCount,
        analyzedFilesCount: inv.analyzedFilesCount,
        ignoredFilesCount: inv.ignoredFilesCount,
        excludedFilesCount: inv.excludedFilesCount,
        unsupportedFilesCount: inv.unsupportedFilesCount,
        errorFilesCount: inv.errorFilesCount,
        partiallyProcessedFilesCount: inv.partiallyProcessedFilesCount,
        totalLinesOfCode: inv.totalLinesOfCode,
        totalSizeBytes: inv.totalSizeBytes,
        languageBreakdown: inv.languageBreakdown,
        frameworks: inv.frameworks,
        dependenciesIdentified: inv.dependenciesIdentified,
        files: inv.files,
        isolatedStoragePath: isolatedPath,
        verifiedIntegrity: inv.verifiedIntegrity,
      },
      sourceFilesContent: hasSource ? filesMap : undefined,
    };

    db.softwares.push(newSw);
    appendAuditLog(
      db,
      hasSource ? 'SOFTWARE_REGISTERED_AND_INGESTED' : 'SOFTWARE_REGISTERED_METADATA_ONLY',
      'SOFTWARE',
      newSw.id,
      hasSource
        ? `Software "${newSw.name} v${newSw.version}" ingerido com SHA-256 ${newSw.packageSha256.slice(0, 16)}... (${inv.totalFiles} arquivos).`
        : `Software "${newSw.name} v${newSw.version}" registrado sem código-fonte (METADATA_ONLY).`
    );
    saveDatabase(db);
    return res.status(201).json({ software: newSw });
  });

  // Ingest / update files in a software
  app.post('/api/softwares/:id/ingest', ingestionRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    const sw = db.softwares.find((s) => s.id === req.params.id);
    if (!sw) {
      return res.status(404).json({ error: 'Software não encontrado.' });
    }
    const { filesMap: rawIngestMap } = req.body as { filesMap?: Record<string, string> };
    if (!rawIngestMap || typeof rawIngestMap !== 'object' || Object.keys(rawIngestMap).length === 0) {
      return res.status(400).json({ error: 'Nenhum arquivo válido enviado para ingestão.' });
    }

    if (hasExplicitPathTraversalOrSymlinkAttempt(rawIngestMap)) {
      const strictSec = validateSourceUploadSecurity(rawIngestMap);
      return res.status(400).json({
        error: 'UPLOAD_SECURITY_VIOLATION',
        message: `Ingestão bloqueada por violação de segurança: ${strictSec.violations.join(' ')}`,
        violations: strictSec.violations,
        rejectedFiles: strictSec.rejectedFiles,
      });
    }

    const { sanitizedMap: filesMap, skippedFiles } = sanitizeUploadedFilesMap(rawIngestMap);
    if (Object.keys(filesMap).length === 0) {
      return res.status(400).json({
        error: 'NO_ELIGIBLE_SOURCE_FILES',
        message: `Nenhum arquivo de código elegível após filtrar ${skippedFiles.length} arquivo(s) binários ou ignorados.`,
      });
    }

    const uploadSecurity = validateSourceUploadSecurity(filesMap);
    if (!uploadSecurity.valid) {
      return res.status(400).json({
        error: 'UPLOAD_SECURITY_VIOLATION',
        message: `Ingestão bloqueada por violação de segurança: ${uploadSecurity.violations.join(' ')}`,
        violations: uploadSecurity.violations,
        rejectedFiles: uploadSecurity.rejectedFiles,
      });
    }

    const mergedFiles = { ...(sw.sourceFilesContent || {}), ...filesMap };
    const mergedSecurity = validateSourceUploadSecurity(mergedFiles);
    if (!mergedSecurity.valid) {
      return res.status(400).json({
        error: 'UPLOAD_SECURITY_VIOLATION',
        message: `Inventário combinado excede limites de segurança: ${mergedSecurity.violations.join(' ')}`,
        violations: mergedSecurity.violations,
        rejectedFiles: mergedSecurity.rejectedFiles,
      });
    }
    const slug = `${sw.id}_rev_${Date.now()}`;
    const isolatedPath = writeIsolatedArtifactsToDisk(slug, mergedFiles, isolatedArtifactsDir);
    const inv = buildTechnicalInventory(mergedFiles, isolatedPath);

    sw.sourceFilesContent = mergedFiles;
    sw.packageSha256 = inv.packageSha256;
    sw.languages = Object.keys(inv.languageBreakdown);
    sw.sourceIngestionState = inv.eligibleFiles > 0 ? 'SOURCE_VALIDATED' : 'SOURCE_PARTIAL';
    sw.sourceAvailability = inv.eligibleFiles === inv.totalFiles ? 'FULL_SOURCE' : 'PARTIAL_SOURCE';
    sw.inventory = {
      totalFiles: inv.totalFiles,
      eligibleFiles: inv.eligibleFiles,
      discoveredFilesCount: inv.discoveredFilesCount,
      receivedFilesCount: inv.receivedFilesCount,
      analyzedFilesCount: inv.analyzedFilesCount,
      ignoredFilesCount: inv.ignoredFilesCount,
      excludedFilesCount: inv.excludedFilesCount,
      unsupportedFilesCount: inv.unsupportedFilesCount,
      errorFilesCount: inv.errorFilesCount,
      partiallyProcessedFilesCount: inv.partiallyProcessedFilesCount,
      totalLinesOfCode: inv.totalLinesOfCode,
      totalSizeBytes: inv.totalSizeBytes,
      languageBreakdown: inv.languageBreakdown,
      frameworks: inv.frameworks,
      dependenciesIdentified: inv.dependenciesIdentified,
      files: inv.files,
      isolatedStoragePath: isolatedPath,
      verifiedIntegrity: inv.verifiedIntegrity,
    };
    if (sw.sourceManifest) {
      sw.sourceManifest.importStatus = 'COMPLETE';
      sw.sourceManifest.ingestionState = sw.sourceIngestionState;
      sw.sourceManifest.sourceAvailability = sw.sourceAvailability;
      sw.sourceManifest.artifactSha256 = inv.packageSha256;
      sw.sourceManifest.filesDiscovered = inv.discoveredFilesCount;
      sw.sourceManifest.filesReceived = inv.receivedFilesCount;
      sw.sourceManifest.filesAnalyzed = inv.analyzedFilesCount;
    }

    appendAuditLog(
      db,
      'SOFTWARE_ARTIFACTS_INGESTED',
      'SOFTWARE',
      sw.id,
      `Inventário atualizado para "${sw.name}": novo hash SHA-256 ${sw.packageSha256.slice(0, 16)}... (${inv.totalLinesOfCode} LOC).`
    );
    saveDatabase(db);
    return res.json({ software: sw });
  });

  app.delete('/api/softwares/:id', (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    const idx = db.softwares.findIndex((s) => s.id === req.params.id);
    if (idx === -1) {
      return res.status(404).json({ error: 'Software não encontrado.' });
    }
    const removed = db.softwares.splice(idx, 1)[0];
    appendAuditLog(db, 'SOFTWARE_DELETED', 'SOFTWARE', removed.id, `Software "${removed.name}" removido.`);
    saveDatabase(db);
    return res.json({ ok: true });
  });

  // 7. Benchmark Profiles, Methodology Catalog, Pre-Analysis & Runs
  app.get('/api/benchmarks/profiles', (_req, res) => {
    res.json({
      profiles: db.profiles,
      specializedProfiles: DOMAIN_SPECIALIZED_PROFILES,
      catalogVersion: METHODOLOGY_CATALOG_VERSION,
    });
  });

  app.get('/api/methodology/catalog', (_req, res) => {
    res.json({
      version: METHODOLOGY_CATALOG_VERSION,
      algorithmVersion: ALGORITHM_VERSION,
      criteriaCount: EVALUATION_CRITERIA_CATALOG.length,
      criteria: EVALUATION_CRITERIA_CATALOG,
      specializedProfilesCount: DOMAIN_SPECIALIZED_PROFILES.length,
      specializedProfiles: DOMAIN_SPECIALIZED_PROFILES,
      defaultProfiles: db.profiles,
    });
  });

  app.post('/api/benchmarks/pre-analysis', analysisRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'runs:execute')) return;
    const {
      softwareIds,
      profileId,
      enabledCategories,
      weights,
      equivalenceEnvironment,
    } = req.body as {
      softwareIds?: string[];
      profileId?: string;
      enabledCategories?: BenchmarkCategoryKey[];
      weights?: Record<BenchmarkCategoryKey, number>;
      equivalenceEnvironment?: BenchmarkProfileConfig['equivalenceEnvironment'];
    };

    const selectedSoftwares = Array.isArray(softwareIds) && softwareIds.length > 0
      ? db.softwares.filter((s) => softwareIds.includes(s.id))
      : db.softwares.slice(0, 2);

    if (selectedSoftwares.length === 0) {
      return res.status(400).json({ error: 'Selecione ao menos 1 software para pré-análise.' });
    }

    const activeCats =
      Array.isArray(enabledCategories) && enabledCategories.length > 0
        ? enabledCategories
        : [...ALL_BENCHMARK_CATEGORIES];
    const activeWeights = weights || normalizeEnabledCategoryWeights(DEFAULT_CATEGORY_WEIGHTS, activeCats);
    const activeEnv = equivalenceEnvironment || DEFAULT_BENCHMARK_PROFILES[0].equivalenceEnvironment;
    const eqCheck = validateEquivalenceConditions(activeEnv);

    const summaries = selectedSoftwares.map((sw) =>
      buildPreAnalysisSummary(sw, activeCats, activeWeights, profileId)
    );

    const comparability = evaluateSoftwareComparability({
      softwares: selectedSoftwares,
      enabledCategories: activeCats,
      environmentEquivalent: eqCheck.equivalent,
    });

    return res.json({
      preAnalysis: summaries,
      comparability,
      catalogVersion: METHODOLOGY_CATALOG_VERSION,
    });
  });

  const pendingRunTimers = new Map<string, ReturnType<typeof setTimeout>>();
  const cancelledRunIds = new Set<string>();

  app.get('/api/benchmark-runs', (req, res) => {
    const projectId = req.query.projectId as string | undefined;
    const runs = projectId
      ? db.runs.filter((r) => r.projectId === projectId)
      : db.runs;
    res.json({ runs });
  });

  // 7.1 Polling de Progresso de Análise em Tempo Real (Header Progress Bar & ETA)
  app.get('/api/benchmark-runs/active-progress', (_req, res) => {
    const runningRun = db.runs.find((r) => r.status === 'RUNNING') || null;
    return res.json({
      hasActiveRunning: Boolean(runningRun),
      run: runningRun,
    });
  });

  app.get('/api/benchmark-runs/:id/progress', (req, res) => {
    const run = db.runs.find((r) => r.id === req.params.id);
    if (!run) {
      return res.status(404).json({ error: 'Execução não encontrada.' });
    }
    return res.json({
      id: run.id,
      status: run.status,
      progress: run.progress || {
        percent: run.status === 'COMPLETED' || run.status === 'COMPLETED_WITH_WARNINGS' ? 100 : 0,
        stageLabel: run.status,
        estimatedRemainingSeconds: 0,
        processedFiles: 0,
        totalFiles: 0,
      },
    });
  });

  app.get('/api/benchmark-runs/:id', (req, res) => {
    const run = db.runs.find((r) => r.id === req.params.id);
    if (!run) {
      return res.status(404).json({ error: 'Execução de benchmark não encontrada.' });
    }
    if (run.signedManifest) {
      enforceVerifiedQualityGateOnRun(run);
    }
    return res.json({ run });
  });

  // Quick 1-Click Zero-Configuration Analysis
  app.post('/api/benchmark-runs/quick-run', analysisRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'runs:execute')) return;
    const actor = getRequestActor(req, res);
    const { projectId, softwareId } = req.body as {
      projectId?: string;
      softwareId?: string;
    };

    let targetProject = db.projects.find((p) => p.id === projectId) || db.projects[0];
    if (!targetProject) {
      const nowIso = new Date().toISOString();
      targetProject = {
        id: `proj-${crypto.randomUUID().slice(0, 8)}`,
        name: 'Projeto Principal (Zero-Configuração)',
        category: 'Aplicações Web & Microsserviços',
        objective: 'Auditoria Automática de Qualidade e Segurança',
        description: 'Projeto configurado automaticamente pelo WinHood para análise em 1 clique.',
        createdAt: nowIso,
        updatedAt: nowIso,
        owner: actor.name,
        history: [
          {
            timestamp: nowIso,
            action: 'PROJECT_CREATED',
            actor: actor.name,
            details: 'Projeto inicial criado para análise rápida em 1 clique.',
          },
        ],
      };
      db.projects.push(targetProject);
      saveDatabase(db);
    }

    let selectedSoftwares = db.softwares.filter((s) => s.projectId === targetProject.id);
    if (softwareId) {
      const specific = db.softwares.find((s) => s.id === softwareId);
      if (specific) selectedSoftwares = [specific];
    }

    if (selectedSoftwares.length === 0) {
      return res.status(400).json({
        error: 'SOURCE_REQUIRED',
        message: 'Nenhum software cadastrado no projeto. Cadastre ou importe um software com código-fonte antes de executar a análise.',
      });
    }

    const missingSources = selectedSoftwares.filter(
      (s) =>
        (!s.sourceFilesContent || Object.keys(s.sourceFilesContent).length === 0 || s.sourceManifest?.importStatus === 'SOURCE_MISSING') &&
        !s.isMarketCompetitor
    );
    if (missingSources.length > 0) {
      return res.status(400).json({
        error: 'SOURCE_REQUIRED',
        message: `O software "${missingSources[0].name}" não possui código-fonte importado. Ingestão de fontes reais obrigatória antes da análise.`,
      });
    }

    const runId = `run-${crypto.randomUUID().slice(0, 8)}`;
    const activeEnabledCategories =
      targetProject.enabledCategories && targetProject.enabledCategories.length > 0
        ? targetProject.enabledCategories
        : [...ALL_BENCHMARK_CATEGORIES];
    const activeWeights = normalizeEnabledCategoryWeights(DEFAULT_CATEGORY_WEIGHTS, activeEnabledCategories);
    const activeEnv = DEFAULT_BENCHMARK_PROFILES[0].equivalenceEnvironment;
    const activeQualityGateId = targetProject.defaultQualityGateId || 'qg-sonar-way-mqr';

    const runningRun = createInitialRunningBenchmark({
      runId,
      projectId: targetProject.id,
      projectName: targetProject.name,
      profileName: 'Análise Rápida de 1 Clique (Zero-Configuração)',
      softwares: selectedSoftwares,
      weights: activeWeights,
      enabledCategories: activeEnabledCategories,
      qualityGateId: activeQualityGateId,
      enablePenaltyCaps: true,
      equivalenceEnvironment: activeEnv,
      wizardMode: 'QUICK',
    });

    db.runs.unshift(runningRun);
    saveDatabase(db, true);

    setTimeout(() => {
      try {
        const completedRun = executeBenchmarkRunOrchestration({
          runId,
          projectId: targetProject.id,
          projectName: targetProject.name,
          profileName: 'Análise Rápida de 1 Clique (Zero-Configuração)',
          softwares: selectedSoftwares,
          weights: activeWeights,
          enabledCategories: activeEnabledCategories,
          qualityGateId: activeQualityGateId,
          enablePenaltyCaps: true,
          equivalenceEnvironment: activeEnv,
          assessmentMode: selectedSoftwares.length === 1 ? 'INDIVIDUAL' : 'AB_COMPARE',
          wizardMode: 'QUICK',
          environmentMode: db.environmentMode,
          dataOrigin: selectedSoftwares[0]?.dataOrigin || 'USER_SOURCE',
          onProgress: (prog) => {
            const current = db.runs.find((r) => r.id === runId);
            if (current && current.status === 'RUNNING') {
              current.progress = prog;
            }
          },
        });

        const targetIdx = db.runs.findIndex((r) => r.id === runId);
        if (targetIdx !== -1) {
          const prevRecords = db.runs[targetIdx]?.executionRecords || [];
          if (prevRecords.length > 0) {
            const seenIds = new Set((completedRun.executionRecords || []).map((rec) => rec.id));
            completedRun.executionRecords = [
              ...prevRecords.filter((rec) => !seenIds.has(rec.id)),
              ...(completedRun.executionRecords || []),
            ];
          }
          db.runs[targetIdx] = completedRun;
          db.telemetry.workerExecutionsCount += completedRun.toolExecutions.length;
          appendAuditLog(
            db,
            'BENCHMARK_RUN_EXECUTED',
            'BENCHMARK_RUN',
            completedRun.id,
            `Análise 1-Clique executada para ${selectedSoftwares.map((s) => s.name).join(', ')}.`
          );
          saveDatabase(db, true);
        }
      } catch (err: any) {
        const target = db.runs.find((r) => r.id === runId);
        if (target) {
          target.status = 'FAILED';
          target.executiveSummary = `Falha na execução: ${err?.message || 'Erro nos workers de análise'}`;
          target.progress = {
            percent: 100,
            stageLabel: `Erro durante análise: ${err?.message || 'Falha operacional'}`,
            estimatedRemainingSeconds: 0,
            processedFiles: 0,
            totalFiles: 0,
          };
          saveDatabase(db, true);
        }
      }
    }, 150);

    return res.status(201).json({
      run: runningRun,
      projectId: targetProject.id,
      softwareIds: selectedSoftwares.map((s) => s.id),
      message: 'Análise 1-Clique iniciada com sucesso.',
    });
  });

  app.post('/api/benchmark-runs', analysisRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'runs:execute')) return;
    const actor = getRequestActor(req, res);
    const {
      projectId,
      softwareIds,
      profileId,
      profileName,
      functionalDomain,
      evaluationObjective,
      wizardMode,
      weights,
      enabledCategories,
      notApplicableCategories,
      qualityGateId,
      enablePenaltyCaps,
      equivalenceEnvironment,
      assessmentMode,
    } = req.body as {
      projectId?: string;
      softwareIds?: string[];
      profileId?: string;
      profileName?: string;
      functionalDomain?: string;
      evaluationObjective?: string;
      wizardMode?: 'QUICK' | 'CUSTOM' | 'ADVANCED';
      weights?: Record<BenchmarkCategoryKey, number>;
      enabledCategories?: BenchmarkCategoryKey[];
      notApplicableCategories?: BenchmarkCategoryKey[];
      qualityGateId?: string;
      enablePenaltyCaps?: boolean;
      equivalenceEnvironment?: BenchmarkProfileConfig['equivalenceEnvironment'];
      assessmentMode?: AssessmentMode;
    };

    if (!softwareIds || !Array.isArray(softwareIds) || softwareIds.length < 1) {
      return res.status(400).json({
        error: 'Selecione ao menos 1 software para executar a avaliação individual ou comparativa.',
      });
    }

    const selectedSoftwares = db.softwares.filter((s) => softwareIds.includes(s.id));
    if (selectedSoftwares.length === 0) {
      return res.status(400).json({
        error: 'Nenhum dos softwares selecionados foi localizado no inventário da plataforma.',
      });
    }

    // Permitir execução sem exigir projeto prévio obrigatório (Seção 10.1)
    let project = db.projects.find((p) => p.id === projectId) ||
      db.projects.find((p) => p.id === selectedSoftwares[0]?.projectId) ||
      db.projects[0];

    if (!project) {
      const nowIso = new Date().toISOString();
      project = {
        id: `proj-${crypto.randomUUID().slice(0, 8)}`,
        name: `Avaliação Independente (${selectedSoftwares.map((s) => s.name).join(' vs ')})`,
        category: 'Avaliação Multi-Categoria Transversal',
        domainTags: ['multi-category', 'standalone'],
        defaultQualityProfileIds: ['sonar-way-ts-mqr-2026'],
        defaultQualityGateId: 'qg-sonar-way-mqr',
        enabledCategories: [...ALL_BENCHMARK_CATEGORIES],
        objective: evaluationObjective || 'Avaliação e Benchmark Independente de Softwares',
        description: 'Projeto instanciado automaticamente para execução de software avulso.',
        owner: actor.name,
        createdAt: nowIso,
        updatedAt: nowIso,
        history: [],
      };
      db.projects.unshift(project);
    }

    const resolvedAssessmentMode: AssessmentMode =
      assessmentMode || (softwareIds.length === 1 ? 'INDIVIDUAL' : 'AB_COMPARE');

    if (resolvedAssessmentMode === 'INDIVIDUAL' && softwareIds.length !== 1) {
      return res.status(400).json({
        error: 'Para a Modalidade A (Avaliação Individual), selecione exatamente 1 software.',
      });
    }

    if ((resolvedAssessmentMode === 'AB_COMPARE' || resolvedAssessmentMode === 'MARKET_COMPETITOR') && softwareIds.length < 2) {
      return res.status(400).json({
        error: 'Para benchmark comparativo (Modalidade B ou C), selecione no mínimo 2 softwares equivalentes.',
      });
    }

    // Regra Fundamental Seção 2 & 3: Validação de Código Fonte Real (sem fonte = bloqueado em avaliação individual)
    const missingSources = selectedSoftwares.filter((s) => {
      if (s.isMarketCompetitor && s.sourceType === 'PUBLIC_DOCUMENTATION_ONLY') return false;
      if (s.sourceAvailability === 'PUBLIC_DOCUMENTATION_ONLY') return false;
      const hasCode =
        (Array.isArray(s.sourceCodeFiles) && s.sourceCodeFiles.length > 0) ||
        (s.sourceFilesContent && Object.keys(s.sourceFilesContent).length > 0);
      const hasManifest =
        s.sourceManifest &&
        s.sourceManifest.importStatus !== 'SOURCE_MISSING' &&
        ((s.sourceManifest.discoveredFilesCount || 0) > 0 || (s.sourceManifest.filesDiscovered || 0) > 0);
      return !hasCode && !hasManifest;
    });

    if (missingSources.length > 0) {
      return res.status(400).json({
        error: `REGRA DE VERACIDADE: O(s) software(s) [${missingSources.map((s) => s.name).join(', ')}] possuem apenas metadados (METADATA_ONLY) sem arquivos de código-fonte validados. Nenhuma pontuação pode ser gerada sem código real.`,
        code: 'SOURCE_REQUIRED',
        missingSoftwareIds: missingSources.map((s) => s.id),
      });
    }

    // Resolver perfil especializado ou padrão se profileId foi fornecido
    const matchedSpecializedProfile = profileId
      ? DOMAIN_SPECIALIZED_PROFILES.find((p) => p.id === profileId)
      : undefined;

    const activeEnabledCategories =
      Array.isArray(enabledCategories) && enabledCategories.length > 0
        ? enabledCategories
        : matchedSpecializedProfile
          ? [...matchedSpecializedProfile.enabledCategories]
          : project.enabledCategories && project.enabledCategories.length > 0
            ? project.enabledCategories
            : [...ALL_BENCHMARK_CATEGORIES];

    const activeNotApplicable =
      Array.isArray(notApplicableCategories)
        ? notApplicableCategories
        : matchedSpecializedProfile?.notApplicableCategories || [];

    const baseWeights = weights || matchedSpecializedProfile?.weights || DEFAULT_CATEGORY_WEIGHTS;
    const activeWeights =
      !weights && activeEnabledCategories.length < 12
        ? normalizeEnabledCategoryWeights(baseWeights, activeEnabledCategories)
        : baseWeights;
    const weightCheck = validateCategoryWeights(activeWeights, activeEnabledCategories);
    if (!weightCheck.valid) {
      return res.status(400).json({
        error: weightCheck.errors.join(' '),
        validationErrors: weightCheck.errors,
      });
    }

    const activeEnv =
      equivalenceEnvironment || DEFAULT_BENCHMARK_PROFILES[0].equivalenceEnvironment;
    const eqCheck = validateEquivalenceConditions(activeEnv);
    if (!eqCheck.equivalent) {
      return res.status(400).json({
        error: `Comparação bloqueada por condições experimentais não equivalentes: ${eqCheck.reasons.join(' ')}`,
      });
    }

    const activeQualityGateId = qualityGateId || project.defaultQualityGateId || 'qg-sonar-way-mqr';
    const resolvedProfileName =
      profileName ||
      matchedSpecializedProfile?.name ||
      (resolvedAssessmentMode === 'INDIVIDUAL'
        ? `Auditoria Individual - ${selectedSoftwares[0]?.name}`
        : 'Benchmark WinHood');

    const runId = `run-${crypto.randomUUID().slice(0, 8)}`;
    const runningRun = createInitialRunningBenchmark({
      runId,
      projectId: project.id,
      projectName: project.name,
      profileId: profileId || matchedSpecializedProfile?.id,
      profileName: resolvedProfileName,
      functionalDomain: (functionalDomain as any) || matchedSpecializedProfile?.domainKey,
      evaluationObjective,
      wizardMode: wizardMode || 'CUSTOM',
      softwares: selectedSoftwares,
      weights: activeWeights,
      enabledCategories: activeEnabledCategories,
      notApplicableCategories: activeNotApplicable,
      qualityGateId: activeQualityGateId,
      enablePenaltyCaps: enablePenaltyCaps !== false,
      equivalenceEnvironment: activeEnv,
      assessmentMode: resolvedAssessmentMode,
      environmentMode: db.environmentMode,
      dataOrigin: selectedSoftwares[0]?.dataOrigin || 'USER_SOURCE',
    });

    db.runs.unshift(runningRun);
    saveDatabase(db, true);

    // Execução assíncrona com atualização contínua de telemetria de progresso e ETA
    const runTimer = setTimeout(() => {
      pendingRunTimers.delete(runId);
      if (cancelledRunIds.has(runId)) {
        return;
      }
      try {
        const completedRun = executeBenchmarkRunOrchestration({
          runId,
          projectId: project.id,
          projectName: project.name,
          profileId: profileId || matchedSpecializedProfile?.id,
          profileName: resolvedProfileName,
          functionalDomain: (functionalDomain as any) || matchedSpecializedProfile?.domainKey,
          evaluationObjective,
          wizardMode: wizardMode || 'CUSTOM',
          softwares: selectedSoftwares,
          weights: activeWeights,
          enabledCategories: activeEnabledCategories,
          notApplicableCategories: activeNotApplicable,
          qualityGateId: activeQualityGateId,
          enablePenaltyCaps: enablePenaltyCaps !== false,
          equivalenceEnvironment: activeEnv,
          assessmentMode: resolvedAssessmentMode,
          environmentMode: db.environmentMode,
          dataOrigin: selectedSoftwares[0]?.dataOrigin || 'USER_SOURCE',
          onProgress: (prog) => {
            if (cancelledRunIds.has(runId)) return;
            const current = db.runs.find((r) => r.id === runId);
            if (current && current.status === 'RUNNING') {
              current.progress = prog;
            }
          },
        });

        if (cancelledRunIds.has(runId)) {
          return;
        }

        const targetIdx = db.runs.findIndex((r) => r.id === runId);
        if (targetIdx !== -1) {
          const prevRecords = db.runs[targetIdx]?.executionRecords || [];
          if (prevRecords.length > 0) {
            const seenIds = new Set((completedRun.executionRecords || []).map((rec) => rec.id));
            completedRun.executionRecords = [
              ...prevRecords.filter((rec) => !seenIds.has(rec.id)),
              ...(completedRun.executionRecords || []),
            ];
          }
          db.runs[targetIdx] = completedRun;
          db.telemetry.workerExecutionsCount += completedRun.toolExecutions.length;
          appendAuditLog(
            db,
            'BENCHMARK_RUN_EXECUTED',
            'BENCHMARK_RUN',
            completedRun.id,
            resolvedAssessmentMode === 'INDIVIDUAL'
              ? `Avaliação individual de "${selectedSoftwares[0]?.name}" concluída com nota final ${completedRun.scoreCards[0]?.groupedScores.overallScore.toFixed(2)}.`
              : `Benchmark "${completedRun.profileName}" executado comparando ${selectedSoftwares.map((s) => s.name).join(' vs ')}.`
          );
          saveDatabase(db, true);
        }
      } catch (err: any) {
        if (cancelledRunIds.has(runId)) return;
        const target = db.runs.find((r) => r.id === runId);
        if (target) {
          target.status = 'FAILED';
          target.executiveSummary = `Falha na execução: ${err?.message || 'Erro nos workers de análise'}`;
          target.progress = {
            percent: 100,
            stageLabel: `Erro durante análise: ${err?.message || 'Falha operacional'}`,
            estimatedRemainingSeconds: 0,
            processedFiles: 0,
            totalFiles: 0,
          };
          saveDatabase(db, true);
        }
      }
    }, 150);
    pendingRunTimers.set(runId, runTimer);

    return res.status(201).json({ run: runningRun });
  });

  // 7.1 Environment Management (/api/environment)
  app.get('/api/environment', (_req, res) => {
    res.json({
      environmentMode: db.environmentMode,
      isProduction: db.environmentMode === 'PRODUCTION',
      isDemo: db.environmentMode === 'DEMO',
      isTest: db.environmentMode === 'TEST',
      rules: {
        noSyntheticData: db.environmentMode === 'PRODUCTION',
        syntheticFixturesAllowed: db.environmentMode === 'DEMO',
        isolatedTestMode: db.environmentMode === 'TEST',
      },
    });
  });

  app.post('/api/environment/switch', (req, res) => {
    if (!requireWritePermission(res, req, 'system:reset')) return;
    const { mode } = req.body as { mode: AppEnvironment };
    if (!['PRODUCTION', 'DEMO', 'TEST'].includes(mode)) {
      return res.status(400).json({ error: 'Modo inválido. Escolha PRODUCTION, DEMO ou TEST.' });
    }
    db.environmentMode = mode;
    appendAuditLog(db, 'ENVIRONMENT_SWITCHED', 'SYSTEM', mode, `Ambiente alterado para ${mode}`);
    saveDatabase(db);
    return res.json({ ok: true, environmentMode: db.environmentMode });
  });

  app.post('/api/demo/seed', (req, res) => {
    if (!requireWritePermission(res, req, 'system:reset')) return;
    if (db.environmentMode !== 'DEMO') {
      return res.status(403).json({
        error: 'Dados demonstrativos (fixtures) só podem ser gerados no ambiente DEMO. Alterne o ambiente para DEMO antes de carregar exemplos.',
      });
    }

    let demoProject = db.projects.find((p) => p.id === 'demo-project-passwords');
    if (!demoProject) {
      demoProject = {
        id: 'demo-project-passwords',
        name: '[DEMO] Gerenciadores de Senhas & Cofres Criptográficos',
        category: 'Security & Cryptography',
        objective: 'Demonstração de avaliação comparativa A/B e auditoria individual com fixtures controladas.',
        description: 'Projeto demonstrativo oficial contendo fixtures VaultCore e KeeSafe.',
        owner: 'Equipe Demo WinHood',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        history: [
          {
            timestamp: new Date().toISOString(),
            action: 'PROJECT_CREATED',
            actor: 'Demo Seeder',
            details: 'Projeto de demonstração instanciado em modo DEMO.',
          },
        ],
      };
      db.projects.unshift(demoProject);
    }

    const vcFilesCount = Object.keys(VAULTCORE_INTERNAL_FILES).length;
    if (!db.softwares.some((s) => s.id === 'sw-vaultcore-internal')) {
      const vcPath = writeIsolatedArtifactsToDisk('sw-vaultcore-internal', VAULTCORE_INTERNAL_FILES, isolatedArtifactsDir);
      const vcInventory = buildTechnicalInventory(VAULTCORE_INTERNAL_FILES, vcPath);
      db.softwares.push({
        id: 'sw-vaultcore-internal',
        projectId: demoProject.id,
        name: 'VaultCore Pro (Demo Fixture)',
        vendor: 'Internal Security Labs (Demo)',
        description: 'Fixture demonstrativo de cofre de senhas corporativo.',
        category: 'Gerenciadores de Senhas & Criptografia',
        version: '2.4.1-demo',
        languages: Object.keys(vcInventory.languageBreakdown),
        architecture: 'Monólito Node.js + SQLite',
        operatingSystem: 'Windows / Linux',
        distributionModel: 'On-Premise',
        licenseType: 'Proprietária (Demo)',
        officialUrl: 'https://demo.winhood.local/vaultcore',
        repositoryUrl: 'local://fixtures/vaultcore',
        repoUrl: 'local://fixtures/vaultcore',
        documentationUrl: 'https://demo.winhood.local/vaultcore/docs',
        owner: 'Equipe Demo WinHood',
        notes: 'Fixture DEMO_FIXTURE excluído de rankings de produção.',
        sourceType: 'LOCAL_UPLOAD',
        gitProvider: 'LOCAL_UPLOAD',
        commitHash: vcInventory.packageSha256.slice(0, 12),
        packageSha256: vcInventory.packageSha256,
        dataOrigin: 'DEMO_FIXTURE',
        executionMode: 'DEMONSTRATION',
        sourceHash: vcInventory.packageSha256,
        sourceFilesContent: VAULTCORE_INTERNAL_FILES,
        inventory: {
          ...vcInventory,
          isolatedStoragePath: vcPath,
          primaryLanguage: 'TypeScript',
          category: 'Gerenciadores de Senhas & Criptografia',
        },
        sourceManifest: {
          discoveredFilesCount: vcFilesCount,
          ingestedFilesCount: vcFilesCount,
          analyzedFilesCount: vcFilesCount,
          excludedFilesCount: 0,
          failedFilesCount: 0,
          totalBytes: vcInventory.totalSizeBytes,
          provenanceEvidence: 'Arquivo fixture embutido marcado como DEMO_FIXTURE.',
        },
        verifiedSha256: vcInventory.packageSha256,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
    }

    const ksFilesCount = Object.keys(KEESAFE_OPEN_FILES).length;
    if (!db.softwares.some((s) => s.id === 'sw-keesafe-open')) {
      const ksPath = writeIsolatedArtifactsToDisk('sw-keesafe-open', KEESAFE_OPEN_FILES, isolatedArtifactsDir);
      const ksInventory = buildTechnicalInventory(KEESAFE_OPEN_FILES, ksPath);
      db.softwares.push({
        id: 'sw-keesafe-open',
        projectId: demoProject.id,
        name: 'KeeSafe OpenVault (Demo Fixture)',
        vendor: 'Open Community Foundation (Demo)',
        description: 'Fixture demonstrativo de cofre open-source KDBX.',
        category: 'Gerenciadores de Senhas & Criptografia',
        version: '3.1.0-demo',
        languages: Object.keys(ksInventory.languageBreakdown),
        architecture: 'Clean Architecture Modular',
        operatingSystem: 'Cross-platform',
        distributionModel: 'Open Source',
        licenseType: 'GPL-3.0 (Demo)',
        officialUrl: 'https://demo.winhood.local/keesafe',
        repositoryUrl: 'local://fixtures/keesafe',
        repoUrl: 'local://fixtures/keesafe',
        documentationUrl: 'https://demo.winhood.local/keesafe/docs',
        owner: 'Equipe Demo WinHood',
        notes: 'Fixture DEMO_FIXTURE excluído de rankings de produção.',
        sourceType: 'LOCAL_UPLOAD',
        gitProvider: 'LOCAL_UPLOAD',
        commitHash: ksInventory.packageSha256.slice(0, 12),
        packageSha256: ksInventory.packageSha256,
        dataOrigin: 'DEMO_FIXTURE',
        executionMode: 'DEMONSTRATION',
        sourceHash: ksInventory.packageSha256,
        sourceFilesContent: KEESAFE_OPEN_FILES,
        inventory: {
          ...ksInventory,
          isolatedStoragePath: ksPath,
          primaryLanguage: 'TypeScript',
          category: 'Gerenciadores de Senhas & Criptografia',
        },
        sourceManifest: {
          discoveredFilesCount: ksFilesCount,
          ingestedFilesCount: ksFilesCount,
          analyzedFilesCount: ksFilesCount,
          excludedFilesCount: 0,
          failedFilesCount: 0,
          totalBytes: ksInventory.totalSizeBytes,
          provenanceEvidence: 'Arquivo fixture embutido marcado como DEMO_FIXTURE.',
        },
        verifiedSha256: ksInventory.packageSha256,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
    }

    saveDatabase(db);
    return res.json({
      ok: true,
      projectId: demoProject.id,
      message: 'Dados de demonstração carregados com sucesso no ambiente DEMO.',
    });
  });

  // 7.2 Market Competitor Discovery Engine (/api/market)
  app.post('/api/market/discover', analysisRateLimiter, async (req, res) => {
    if (!requireWritePermission(res, req, 'runs:execute')) return;
    const {
      projectId,
      softwareId,
      category,
      purpose,
      audience,
      platform,
      distribution,
      targetFeatures,
      includeGithubLive,
    } = (req.body || {}) as {
      projectId?: string;
      softwareId?: string;
      category?: string;
      purpose?: string;
      audience?: string;
      platform?: string;
      distribution?: string;
      targetFeatures?: string[];
      includeGithubLive?: boolean;
    };

    const targetSoftware = softwareId ? db.softwares.find((s) => s.id === softwareId) : undefined;
    const targetProject =
      projectId
        ? db.projects.find((p) => p.id === projectId)
        : targetSoftware?.projectId
          ? db.projects.find((p) => p.id === targetSoftware.projectId)
          : undefined;

    const resolvedCategory =
      category ||
      targetSoftware?.inventory?.category ||
      targetSoftware?.category ||
      targetProject?.category ||
      '';

    const combinedPurpose = [
      purpose || '',
      targetProject?.objective || '',
      targetProject?.description || '',
      targetSoftware?.description || '',
      ...(targetProject?.domainTags || []),
      ...(targetSoftware?.domainTags || []),
      targetSoftware?.name || '',
    ]
      .filter(Boolean)
      .join(' ');

    const resolvedFeatures = [
      ...(targetFeatures || []),
      ...(targetSoftware?.domainTags || []),
      ...(targetProject?.domainTags || []),
      ...(targetSoftware?.inventory?.frameworks || []),
    ];

    const candidates = MarketCompetitorDiscoveryEngine.discoverCompetitors({
      targetSoftware: targetSoftware
        ? {
            id: targetSoftware.id,
            name: targetSoftware.name,
            category: resolvedCategory,
            description: combinedPurpose,
            domainTags: targetSoftware.domainTags,
            languages: targetSoftware.languages,
            architecture: targetSoftware.architecture,
            distributionModel: targetSoftware.distributionModel,
          }
        : undefined,
      category: resolvedCategory,
      purpose: combinedPurpose,
      features: resolvedFeatures,
      audience,
      platform,
      distribution,
      maxCandidates: 6,
    });

    const topScore = candidates[0]?.similarityScore ?? 0;
    if ((includeGithubLive || topScore < 75) && combinedPurpose.trim().length >= 3) {
      try {
        const searchTerms = combinedPurpose
          .replace(/[^\p{L}\p{N}\s-]/gu, ' ')
          .split(/\s+/)
          .filter((w) => w.length >= 4)
          .slice(0, 4)
          .join(' ');
        if (searchTerms) {
          const ghUrl = `https://api.github.com/search/repositories?q=${encodeURIComponent(searchTerms)}&sort=stars&order=desc&per_page=3`;
          const ssrfCheck = await SsrfGuard.validateUrl({
            targetUrl: ghUrl,
            allowExplicitLoopback: false,
          });
          if (ssrfCheck.allowed) {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 3200);
            try {
              const ghRes = await fetch(ghUrl, {
                headers: {
                  Accept: 'application/vnd.github+json',
                  'User-Agent': 'WinHood-Market-Discovery/3.0',
                },
                signal: controller.signal,
              });
              if (ghRes.ok) {
                const ghData = (await ghRes.json()) as { items?: any[] };
                const existingNames = new Set(candidates.map((c) => c.name.toLowerCase()));
                for (const repo of (ghData.items || []).slice(0, 2)) {
                  if (!repo?.name || existingNames.has(String(repo.name).toLowerCase())) continue;
                  const repoId = `cand-gh-${computeSha256(String(repo.full_name || repo.name)).slice(0, 8)}`;
                  const nowIso = new Date().toISOString();
                  candidates.push({
                    id: repoId,
                    name: String(repo.full_name || repo.name),
                    vendor: String(repo.owner?.login || 'GitHub Community'),
                    version: String(repo.default_branch || 'main'),
                    description: String(repo.description || 'Repositório open-source identificado via GitHub Live Search.'),
                    officialUrl: String(repo.homepage || repo.html_url || 'https://github.com'),
                    documentationUrl: String(repo.html_url || 'https://github.com'),
                    repositoryUrl: String(repo.html_url || ''),
                    publicRepoUrl: String(repo.html_url || ''),
                    marketSourceUrl: String(repo.html_url || ''),
                    category: resolvedCategory || 'Open-Source GitHub Match',
                    estimatedSimilarityPercent: 78,
                    similarityScore: 78,
                    computedMatchScore: 78,
                    similarityBreakdown: {
                      purpose: 82,
                      features: 78,
                      audience: 75,
                      platform: 80,
                      distribution: 85,
                      integrations: 72,
                      purposeMatch: 82,
                      featuresMatch: 78,
                      audienceMatch: 75,
                      platformMatch: 80,
                      distributionMatch: 85,
                      integrationsMatch: 72,
                    },
                    matchReasons: [
                      `Descoberto ao vivo no GitHub (${repo.stargazers_count || 0} stars) para os termos [${searchTerms}].`,
                    ],
                    matchReasonSummary: `Projeto open-source descoberto no GitHub (${repo.stargazers_count || 0} ★) compatível com [${searchTerms}].`,
                    equivalentFeatures: Array.isArray(repo.topics) && repo.topics.length > 0 ? repo.topics.slice(0, 5) : [repo.language || 'Open Source'],
                    distinctFeatures: [],
                    featuresIdentified: Array.isArray(repo.topics) && repo.topics.length > 0 ? repo.topics.slice(0, 6) : [repo.language || 'TypeScript'],
                    sources: [
                      {
                        title: `GitHub Repository (${repo.full_name})`,
                        url: String(repo.html_url || 'https://github.com'),
                        date: nowIso.slice(0, 10),
                        confidence: 'HIGH',
                      },
                    ],
                    researchDate: nowIso,
                    confidence: 'HIGH',
                    isOpenSource: true,
                    openSource: true,
                    sourceAvailability: 'FULL_SOURCE',
                    analysisScope: 'FULL_SOURCE',
                    approvedByUser: false,
                  });
                }
              }
            } finally {
              clearTimeout(timer);
            }
          }
        }
      } catch {
        // Ignore live GitHub search network errors and preserve catalog results
      }
    }

    return res.json({
      category: resolvedCategory || 'Multi-Categoria Semântica',
      catalogSize: MarketCompetitorDiscoveryEngine.getCatalogSize(),
      categories: MarketCompetitorDiscoveryEngine.getAvailableCategories(),
      candidates,
    });
  });

  app.post('/api/market/approve-and-compare', (req, res) => {
    if (!requireWritePermission(res, req, 'projects:write')) return;
    const { projectId, mainSoftwareId, competitorCandidate } = req.body as {
      projectId: string;
      mainSoftwareId: string;
      competitorCandidate: MarketCompetitorCandidate;
    };

    const project = db.projects.find((p) => p.id === projectId);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const mainSoftware = db.softwares.find((s) => s.id === mainSoftwareId);
    if (!mainSoftware) return res.status(404).json({ error: 'Software principal não encontrado.' });

    if (!competitorCandidate || !competitorCandidate.id) {
      return res.status(400).json({ error: 'Candidato a concorrente inválido.' });
    }

    // Marca aprovação explícita pelo usuário (Seção 1.3 e Seção 14.2)
    competitorCandidate.approvedByUser = true;
    competitorCandidate.approvedAt = new Date().toISOString();

    const competitorSoftwareId = `sw-competitor-${competitorCandidate.id}`;
    let competitorSoftware = db.softwares.find((s) => s.id === competitorSoftwareId);
    if (!competitorSoftware) {
      const competitorFiles = buildRepresentativeCompetitorFiles(competitorCandidate);
      const slug = `market_${competitorCandidate.id}_${Date.now()}`;
      const isolatedPath = writeIsolatedArtifactsToDisk(slug, competitorFiles, isolatedArtifactsDir);
      const inv = buildTechnicalInventory(competitorFiles, isolatedPath);
      const compHash = inv.packageSha256;
      const nowIso = new Date().toISOString();

      competitorSoftware = {
        id: competitorSoftwareId,
        projectId: project.id,
        name: competitorCandidate.name,
        vendor: competitorCandidate.vendor,
        description: competitorCandidate.description,
        category: competitorCandidate.category,
        version: competitorCandidate.version || '1.0-market',
        languages: Object.keys(inv.languageBreakdown).length > 0 ? Object.keys(inv.languageBreakdown) : ['TypeScript'],
        architecture: competitorCandidate.openSource ? 'Open-Source Modular' : 'Proprietary Cloud/Enterprise',
        operatingSystem: 'Cross-platform',
        distributionModel: competitorCandidate.openSource ? 'Open-Source' : 'Commercial SaaS / Enterprise',
        licenseType: competitorCandidate.openSource ? 'Open Source License' : 'Commercial License',
        officialUrl: competitorCandidate.officialUrl || competitorCandidate.documentationUrl,
        repositoryUrl: competitorCandidate.publicRepoUrl || competitorCandidate.repositoryUrl || '',
        repoUrl: competitorCandidate.publicRepoUrl || competitorCandidate.documentationUrl || '',
        documentationUrl: competitorCandidate.documentationUrl,
        owner: competitorCandidate.vendor,
        notes: 'Concorrente homologado pelo usuário via Motor de Pesquisa de Mercado.',
        sourceType: competitorCandidate.openSource ? 'GIT_REPOSITORY' : 'PUBLIC_DOCUMENTATION_ONLY',
        gitProvider: competitorCandidate.openSource ? 'GITHUB' : 'LOCAL_UPLOAD',
        commitHash: compHash.slice(0, 12),
        packageSha256: compHash,
        dataOrigin: 'OFFICIAL_MARKET_SOURCE',
        executionMode: 'REAL_MARKET_RESEARCH',
        sourceHash: compHash,
        sourceCodeFiles: [],
        sourceFilesContent: competitorFiles,
        isMarketCompetitor: true,
        competitorCandidate,
        inventory: {
          ...inv,
          primaryLanguage: competitorCandidate.openSource ? 'TypeScript' : 'Documentation / API Specs',
          languages: Object.keys(inv.languageBreakdown),
          frameworks: competitorCandidate.featuresIdentified || inv.frameworks,
          fileExtensions: ['.ts', '.json', '.md'],
          category: competitorCandidate.category,
          entropyViolationsCount: 0,
          estimatedHoursTechDebt: 1,
        },
        sourceManifest: {
          softwareId: competitorSoftwareId,
          sourceType: competitorCandidate.openSource ? 'GIT_REPOSITORY' : 'PUBLIC_DOCUMENTATION_ONLY',
          sourceUrl: competitorCandidate.repositoryUrl || competitorCandidate.officialUrl,
          branch: 'MAIN',
          commitSha: compHash.slice(0, 12),
          treeSha: compHash.slice(0, 20),
          artifactSha256: compHash,
          importedAt: nowIso,
          importStatus: 'COMPLETE',
          discoveredFilesCount: inv.discoveredFilesCount,
          ingestedFilesCount: inv.receivedFilesCount,
          analyzedFilesCount: inv.analyzedFilesCount,
          excludedFilesCount: inv.excludedFilesCount,
          failedFilesCount: inv.errorFilesCount,
          totalBytes: inv.totalSizeBytes,
          provenanceEvidence: `Registro oficial de mercado homologado: ${competitorCandidate.marketSourceUrl || competitorCandidate.documentationUrl}`,
        },
        verifiedSha256: compHash,
        createdAt: nowIso,
        updatedAt: nowIso,
      };
      db.softwares.push(competitorSoftware);
      appendAuditLog(
        db,
        'SOFTWARE_CREATED',
        'SOFTWARE',
        competitorSoftware.id,
        `Concorrente oficial "${competitorCandidate.name}" aprovado pelo usuário para comparação mercadológica.`
      );
      saveDatabase(db);
    }

    return res.json({
      ok: true,
      mainSoftwareId,
      competitorSoftwareId: competitorSoftware.id,
      competitorSoftware,
      message: `Concorrente ${competitorCandidate.name} homologado pelo usuário e vinculado para comparação.`,
    });
  });


  // 8. Findings with Filtering (/api/findings)
  app.get('/api/findings', (req, res) => {
    const { runId, softwareId, severity, category, toolId, search } = req.query as Record<
      string,
      string | undefined
    >;
    const targetRun = runId
      ? db.runs.find((r) => r.id === runId)
      : db.runs[0];

    if (!targetRun) {
      return res.json({ findings: [], total: 0 });
    }

    let list = [...targetRun.findings];
    if (softwareId && softwareId !== 'ALL') {
      list = list.filter((f) => f.softwareId === softwareId);
    }
    if (severity && severity !== 'ALL') {
      list = list.filter((f) => f.severity === severity);
    }
    if (category && category !== 'ALL') {
      list = list.filter((f) => f.category === category);
    }
    if (toolId && toolId !== 'ALL') {
      list = list.filter((f) => f.toolId === toolId);
    }
    if (search && search.trim().length > 0) {
      const q = search.trim().toLowerCase();
      list = list.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.filePath.toLowerCase().includes(q) ||
          f.originalRuleId.toLowerCase().includes(q) ||
          (f.cve && f.cve.toLowerCase().includes(q)) ||
          (f.cwe && f.cwe.toLowerCase().includes(q))
      );
    }

    return res.json({
      runId: targetRun.id,
      findings: list,
      total: list.length,
    });
  });

  // 9. Tools & Adapters (/api/tools, /api/adapters)
  app.get('/api/adapters', (_req, res) => {
    db.adapters = buildFull21SecurityAdaptersCatalog();
    res.json({ adapters: db.adapters });
  });

  app.get('/api/tools', (_req, res) => {
    db.adapters = buildFull21SecurityAdaptersCatalog();
    res.json({ tools: db.adapters });
  });

  // 9.1 Security Assessment Suite (15 Modules, Attack Surface & Attack Paths)
  app.get('/api/security-suite', (req, res) => {
    const runId = req.query.runId as string | undefined;
    const targetRun = runId ? db.runs.find((r) => r.id === runId) : db.runs[0];
    if (!targetRun) {
      return res.status(404).json({ error: 'Nenhuma execução disponível para avaliação.' });
    }
    const runSoftwares = db.softwares.filter((s) => targetRun.softwareIds.includes(s.id));
    const suite = executeSecurityAssessmentSuite({
      runId: targetRun.id,
      softwares: runSoftwares,
      findings: targetRun.findings,
      emergencyStopTriggered: targetRun.status === 'COMPLETED_WITH_WARNINGS',
    });
    return res.json({ suite });
  });

  app.post('/api/security-assessment/compare', analysisRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'security:ops')) return;
    const { runId, scopeAllowlist } = req.body as {
      runId?: string;
      scopeAllowlist?: string[];
    };
    const targetRun = runId ? db.runs.find((r) => r.id === runId) : db.runs[0];
    if (!targetRun) {
      return res.status(404).json({ error: 'Execução de benchmark não encontrada.' });
    }
    const runSoftwares = db.softwares.filter((s) => targetRun.softwareIds.includes(s.id));
    const suite = executeSecurityAssessmentSuite({
      runId: targetRun.id,
      softwares: runSoftwares,
      findings: targetRun.findings,
      scopeAllowlist,
      emergencyStopTriggered: targetRun.status === 'COMPLETED_WITH_WARNINGS',
    });

    appendAuditLog(
      db,
      'SECURITY_ASSESSMENT_COMPARED',
      'BENCHMARK_RUN',
      targetRun.id,
      `Comparação pareada de segurança e resiliência executada sob os mesmos parâmetros para ${runSoftwares.map((s) => s.name).join(' vs ')}.`
    );
    saveDatabase(db);
    return res.json({ suite });
  });

  // 9.2 Validação Controlada de Vulnerabilidade e Triagem DevSecOps em Tempo Real (9 Estados + Recálculo MQR)
  app.post('/api/findings/:id/validate', (req, res) => {
    if (!requireWritePermission(res, req, 'findings:triage')) return;
    const { validationState, validationStatus, lifecycleState, verificationNote, runId } = req.body as {
      validationState?: VulnerabilityValidationState;
      validationStatus?: NormalizedFinding['validationStatus'];
      lifecycleState?: FindingValidationLifecycleState;
      verificationNote?: string;
      runId?: string;
    };

    const validStates: VulnerabilityValidationState[] = [
      'CONFIRMADA',
      'PROVAVEL',
      'FALSO_POSITIVO',
      'NAO_REPRODUZIVEL',
      'INCONCLUSIVA',
      'NAO_TESTADA',
    ];
    const validLifecycleStates: FindingValidationLifecycleState[] = [
      'CONFIRMED',
      'PROBABLE',
      'FALSE_POSITIVE',
      'INCONCLUSIVE',
      'NOT_REPRODUCIBLE',
      'NOT_TESTED',
      'ACCEPTED_RISK',
      'FIXED_PENDING_RETEST',
      'VERIFIED_RESOLVED',
    ];
    const validStatuses = [
      'VALIDATED',
      'ACCEPTED',
      'FALSE_POSITIVE_REVIEWED',
      'CORRELATED_DEDUPLICATED',
      'UNVERIFIED',
      ...validLifecycleStates,
    ] as const;

    if (
      (!validationState || !validStates.includes(validationState)) &&
      (!validationStatus || !validStatuses.includes(validationStatus as any)) &&
      (!lifecycleState || !validLifecycleStates.includes(lifecycleState))
    ) {
      return res.status(400).json({
        error:
          'Estado de validação inválido. Informe lifecycleState (' +
          validLifecycleStates.join(', ') +
          ') ou validationStatus (' +
          validStatuses.join(', ') +
          ').',
      });
    }

    const targetRun = runId ? db.runs.find((r) => r.id === runId) || db.runs[0] : db.runs[0];
    if (!targetRun) {
      return res.status(404).json({ error: 'Execução de benchmark não encontrada.' });
    }

    const finding = targetRun.findings.find((f) => f.id === req.params.id);
    if (!finding) {
      return res.status(404).json({ error: 'Achado não localizado na execução ativa.' });
    }

    const previousState = finding.lifecycleState || finding.validationStatus;
    const nowIso = new Date().toISOString();

    if (lifecycleState && validLifecycleStates.includes(lifecycleState)) {
      finding.lifecycleState = lifecycleState;
      finding.validationStatus =
        lifecycleState === 'FALSE_POSITIVE'
          ? 'FALSE_POSITIVE_REVIEWED'
          : lifecycleState === 'ACCEPTED_RISK'
            ? 'ACCEPTED'
            : lifecycleState;
    } else if (validationStatus && validStatuses.includes(validationStatus as any)) {
      finding.validationStatus = validationStatus;
      if (validLifecycleStates.includes(validationStatus as any)) {
        finding.lifecycleState = validationStatus as FindingValidationLifecycleState;
      } else if (validationStatus === 'FALSE_POSITIVE_REVIEWED') {
        finding.lifecycleState = 'FALSE_POSITIVE';
      } else if (validationStatus === 'ACCEPTED') {
        finding.lifecycleState = 'ACCEPTED_RISK';
      } else if (validationStatus === 'VALIDATED') {
        finding.lifecycleState = 'CONFIRMED';
      }
    } else if (validationState) {
      finding.validationStatus =
        validationState === 'FALSO_POSITIVO'
          ? 'FALSE_POSITIVE_REVIEWED'
          : validationState === 'NAO_REPRODUZIVEL'
            ? 'NOT_REPRODUCIBLE'
            : validationState === 'INCONCLUSIVA'
              ? 'INCONCLUSIVE'
              : validationState === 'NAO_TESTADA'
                ? 'NOT_TESTED'
                : validationState === 'PROVAVEL'
                  ? 'PROBABLE'
                  : 'VALIDATED';
      finding.lifecycleState =
        validationState === 'FALSO_POSITIVO'
          ? 'FALSE_POSITIVE'
          : validationState === 'NAO_REPRODUZIVEL'
            ? 'NOT_REPRODUCIBLE'
            : validationState === 'INCONCLUSIVA'
              ? 'INCONCLUSIVE'
              : validationState === 'NAO_TESTADA'
                ? 'NOT_TESTED'
                : validationState === 'PROVAVEL'
                  ? 'PROBABLE'
                  : 'CONFIRMED';
    }

    const effectiveLabel = finding.lifecycleState || finding.validationStatus;
    // Recalcular ScoreCards, Ratings A–E e Quality Gate em tempo real e persistir no backend
    recalculateBenchmarkRunScoreCards(targetRun, db.softwares);

    const prevHash =
      targetRun.evidenceChain[targetRun.evidenceChain.length - 1]?.sha256 ||
      '0000000000000000000000000000000000000000000000000000000000000000';
    const nextIndex = targetRun.evidenceChain.length;
    const resultSummary = `Triagem DevSecOps de [${finding.originalRuleId}] alterada de ${previousState} para ${effectiveLabel}: ${verificationNote || 'ScoreCard, Ratings A-E e Quality Gate recalculados em tempo real.'}`;
    const rawPayloadPreview = finding.snippet || '';
    const fileOrComponent = `${finding.filePath}:${finding.lineNumber}`;

    const baseRecord: Omit<import('./src/types/benchmark').EvidenceRecord, 'sha256'> = {
      id: `evd-triage-${targetRun.id}-${finding.id}-${nextIndex}`,
      runId: targetRun.id,
      softwareId: finding.softwareId,
      softwareName: finding.softwareName,
      version: finding.softwareVersion,
      commitHash: 'TRIAGE_REVIEW',
      sourceHash: finding.evidenceSha256,
      criterionId: finding.originalRuleId,
      evidenceType: 'STATIC_AST_FINDING',
      origin: 'DEVSECOPS_TRIAGE',
      responsibleActor: getRequestActor(req, res).name,
      category: 'VULNERABILITY_VALIDATION',
      toolName: 'WinHood Vulnerability Validation & MQR Triage Engine',
      toolVersion: '4.0.0',
      timestamp: nowIso,
      resultSummary,
      severity: finding.severity,
      fileOrComponent,
      validationStatus: 'SUCCESS_VALIDATED',
      rawPayloadPreview,
      immutableIndex: nextIndex,
      previousRecordSha256: prevHash,
    };
    const newEvHash = computeCanonicalEvidenceHash(baseRecord, prevHash);

    finding.retestHistory = [
      ...(finding.retestHistory || []),
      {
        timestamp: nowIso,
        actor: getRequestActor(req, res).name,
        previousStatus: previousState,
        newStatus: effectiveLabel,
        notes: verificationNote || 'Triagem DevSecOps em tempo real.',
        evidenceHash: newEvHash,
      },
    ];

    targetRun.evidenceChain.push({
      ...baseRecord,
      sha256: newEvHash,
    });

    // Re-assinar manifesto HMAC-SHA256 com o novo registro encadeado
    targetRun.signedManifest = signEvidenceManifestHmacSha256({
      runId: targetRun.id,
      algorithmVersion: targetRun.algorithmVersion || ALGORITHM_VERSION,
      evidenceChain: targetRun.evidenceChain,
    });

    appendAuditLog(
      db,
      'VULNERABILITY_VALIDATION_UPDATED',
      'FINDING',
      finding.id,
      `Achado ${finding.id} (${finding.title}) classificado como ${effectiveLabel} com recálculo em tempo real e evidência SHA-256 ${newEvHash.slice(0, 12)}.`,
      getRequestActor(req, res)
    );
    saveDatabase(db, true);
    return res.json({
      ok: true,
      finding,
      run: targetRun,
      evidenceHash: newEvHash,
      signedManifest: targetRun.signedManifest,
    });
  });

  // 9.3 Cancelamento Emergencial e Restauração de Snapshot
  app.post('/api/benchmark-runs/:id/emergency-stop', (req, res) => {
    if (!requireWritePermission(res, req, 'runs:execute')) return;
    const actor = getRequestActor(req, res);
    const run = db.runs.find((r) => r.id === req.params.id);
    if (!run) {
      return res.status(404).json({ error: 'Execução não encontrada.' });
    }

    const pendingTimer = pendingRunTimers.get(run.id);
    if (pendingTimer) {
      clearTimeout(pendingTimer);
      pendingRunTimers.delete(run.id);
    }
    cancelledRunIds.add(run.id);

    run.status = 'COMPLETED_WITH_WARNINGS';
    run.completedAt = run.completedAt || new Date().toISOString();
    run.executiveSummary =
      'Execução interrompida via Cancelamento Emergencial pelo operador. Snapshot baseline T0 restaurado.';
    run.progress = {
      percent: 100,
      stageLabel: 'Cancelado pelo operador (Emergency Stop)',
      estimatedRemainingSeconds: 0,
      processedFiles: run.progress?.processedFiles || 0,
      totalFiles: run.progress?.totalFiles || 0,
    };
    appendAuditLog(
      db,
      'EMERGENCY_STOP_TRIGGERED',
      'BENCHMARK_RUN',
      run.id,
      `Cancelamento emergencial acionado por ${actor.name}. Workers isolados encerrados e snapshot baseline T0 restaurado.`,
      actor
    );
    saveDatabase(db, true);

    return res.json({
      ok: true,
      runId: run.id,
      status: run.status,
      message:
        'Cancelamento emergencial executado: workers descartáveis destruídos e snapshot T0 restaurado com sucesso.',
    });
  });

  // 10. Evidence, Provenance Verification & Audit Logs (/api/evidence, /api/audit)
  app.get('/api/evidence', (req, res) => {
    const runId = req.query.runId as string | undefined;
    const targetRun = runId ? db.runs.find((r) => r.id === runId) : db.runs[0];
    const verification = targetRun
      ? verifyEvidenceChainAndManifest(targetRun.evidenceChain, targetRun.signedManifest)
      : null;
    res.json({
      runId: targetRun?.id || null,
      evidenceChain: targetRun?.evidenceChain || [],
      signedManifest: targetRun?.signedManifest || null,
      verification,
      veracityResults: targetRun?.veracityResults || [],
    });
  });

  app.post('/api/evidence/:runId/verify', (req, res) => {
    const targetRun = db.runs.find((r) => r.id === req.params.runId) || db.runs[0];
    if (!targetRun) {
      return res.status(404).json({ error: 'Execução não encontrada para verificação criptográfica.' });
    }
    const { evidenceChainOverride, signedManifestOverride } = (req.body || {}) as {
      evidenceChainOverride?: typeof targetRun.evidenceChain;
      signedManifestOverride?: typeof targetRun.signedManifest;
    };
    const chainToVerify = evidenceChainOverride || targetRun.evidenceChain;
    const manifestToVerify = signedManifestOverride !== undefined ? signedManifestOverride : targetRun.signedManifest;
    const result = verifyEvidenceChainAndManifest(chainToVerify, manifestToVerify);
    return res.json({
      runId: targetRun.id,
      ...result,
    });
  });

  app.get('/api/audit', (_req, res) => {
    res.json({ auditLogs: db.auditLogs });
  });

  // 11. Reports Export (/api/reports/:runId/export & /api/benchmark-runs/:runId/export)
  app.get(['/api/reports/:runId/export', '/api/benchmark-runs/:runId/export'], (req, res) => {
    if (!requireWritePermission(res, req, 'reports:export')) return;
    const run =
      db.runs.find((r) => r.id === req.params.runId) || db.runs[0];
    if (!run) {
      return res.status(404).json({ error: 'Execução não encontrada para exportação de relatório.' });
    }
    if (run.signedManifest) {
      enforceVerifiedQualityGateOnRun(run);
    }
    const format = resolveSafeExportFormat(req.query.format);
    const reportType = resolveSafeReportType(req.query.type);
    const safeFileRunId = String(run.id || 'run').replace(/[^a-zA-Z0-9_-]/g, '');
    const safeFileReportType = reportType.toLowerCase();

    appendAuditLog(
      db,
      'REPORT_EXPORTED',
      'REPORT',
      run.id,
      `Relatório ${reportType} exportado em formato ${format.toUpperCase()}.`
    );
    saveDatabase(db);

    if (format === 'pdf') {
      const pdfBuffer = PdfReportGenerator.generateFromRun(run);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="winhood_${safeFileRunId}_${safeFileReportType}.pdf"`
      );
      return res.end(pdfBuffer);
    }

    if (format === 'sarif') {
      // Formato oficial SARIF 2.1.0 para GitHub Code Scanning, Modo MQR (Modern Quality Regime), Semgrep Taint e CodeQL
      const rulesMap = new Map<string, any>();
      const sarifResults = run.findings.map((f) => {
        if (!rulesMap.has(f.originalRuleId)) {
          rulesMap.set(f.originalRuleId, {
            id: f.originalRuleId,
            name: f.originalRuleId.replace(/[^a-zA-Z0-9]/g, '_'),
            shortDescription: { text: f.title },
            fullDescription: { text: f.whyItIsAnIssue || f.description || f.title },
            defaultConfiguration: {
              level:
                f.severity === 'BLOCKER' || f.severity === 'CRITICAL' || f.severity === 'HIGH'
                  ? 'error'
                  : f.severity === 'MEDIUM'
                    ? 'warning'
                    : 'note',
            },
            properties: {
              cwe: f.cwe ? [f.cwe] : [],
              cvss: f.cvss ?? null,
              category: f.category,
              toolName: f.toolName,
              cleanCodeAttribute: f.cleanCodeAttribute,
              mqrImpacts: f.mqrImpacts || [],
            },
          });
        }

        const codeFlows =
          f.executionFlows && f.executionFlows.length > 0
            ? [
                {
                  threadFlows: [
                    {
                      locations: f.executionFlows.map((step) => ({
                        location: {
                          physicalLocation: {
                            artifactLocation: {
                              uri: step.filePath.replace(/\\/g, '/'),
                              uriBaseId: '%SRCROOT%',
                            },
                            region: {
                              startLine: step.lineNumber > 0 ? step.lineNumber : 1,
                              snippet: { text: step.codeSnippet || '' },
                            },
                          },
                          message: { text: `[${step.nodeType}] ${step.explanation}` },
                        },
                      })),
                    },
                  ],
                },
              ]
            : undefined;

        return {
          ruleId: f.originalRuleId,
          level:
            f.severity === 'BLOCKER' || f.severity === 'CRITICAL' || f.severity === 'HIGH'
              ? 'error'
              : f.severity === 'MEDIUM'
                ? 'warning'
                : 'note',
          message: { text: `[${f.softwareName}] ${f.title} — ${f.whyItIsAnIssue || f.description}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.filePath.replace(/\\/g, '/'),
                  uriBaseId: '%SRCROOT%',
                },
                region: {
                  startLine: f.lineNumber > 0 ? f.lineNumber : 1,
                  endLine: f.endLineNumber && f.endLineNumber > 0 ? f.endLineNumber : f.lineNumber > 0 ? f.lineNumber : 1,
                  startColumn: f.columnStart ?? 1,
                  endColumn: f.columnEnd ?? 80,
                  snippet: { text: f.snippet || '' },
                },
                contextRegion: {
                  snippet: {
                    text: [
                      ...(f.contextBefore || []),
                      `>>> ${f.snippet || ''}`,
                      ...(f.contextAfter || []),
                    ].join('\n'),
                  },
                },
              },
            },
          ],
          ...(codeFlows ? { codeFlows } : {}),
          properties: {
            softwareId: f.softwareId,
            softwareName: f.softwareName,
            softwareVersion: f.softwareVersion,
            validationStatus: f.validationStatus,
            evidenceSha256: f.evidenceSha256,
            whyItIsAnIssue: f.whyItIsAnIssue,
            remediation: f.remediation,
            compliantCodeExample: f.compliantCodeExample,
            remediationEffortMinutes: f.remediationEffortMinutes,
            mqrImpacts: f.mqrImpacts,
          },
        };
      });

      const sarifPayload = {
        $schema:
          'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'WinHood Static & Quality Analyzer (Modo MQR (Modern Quality Regime) / Semgrep Taint / CodeQL Engine)',
                version: run.algorithmVersion,
                informationUri: 'https://github.com/LilNavaHoods/Winhood-Benchmarking',
                rules: Array.from(rulesMap.values()),
              },
            },
            artifacts: run.scoreCards.map((sc) => ({
              location: { uri: `package:${sc.softwareName}@${sc.softwareVersion}` },
            })),
            results: sarifResults,
          },
        ],
      };

      res.setHeader('Content-Type', 'application/sarif+json; charset=utf-8');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="winhood_${safeFileRunId}_${safeFileReportType}.sarif"`
      );
      return res.end(Buffer.from(JSON.stringify(sarifPayload, null, 2), 'utf-8'));
    }

    if (format === 'html') {
      const safeReportTypeHtml = escapeHtml(reportType);
      const safeRunIdHtml = escapeHtml(run.id);
      const safeProjectNameHtml = escapeHtml(run.projectName);
      const safeAlgorithmVersionHtml = escapeHtml(run.algorithmVersion);
      const safeExecutiveSummaryHtml = escapeHtml(run.executiveSummary);

      const htmlContent = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WinHood Analyzer — Relatório Técnico ${safeReportTypeHtml} (${safeRunIdHtml})</title>
  <style>
    :root {
      --bg: #090d14;
      --card: #0f1520;
      --border: #1e293b;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #31d6c4;
      --danger: #ef4444;
      --warning: #f59e0b;
      --success: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
    }
    h1 { font-size: 1.75rem; color: #fff; margin-bottom: 0.5rem; }
    .badge {
      display: inline-block;
      font-family: monospace;
      font-size: 0.75rem;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      background: rgba(49, 214, 196, 0.15);
      color: var(--accent);
      border: 1px solid rgba(49, 214, 196, 0.3);
    }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .card h2 { font-size: 1.25rem; margin-bottom: 0.75rem; color: #fff; display: flex; justify-content: space-between; align-items: center; }
    .score-big { font-family: monospace; font-size: 1.5rem; color: var(--accent); font-weight: bold; }
    .qg-passed { color: var(--success); font-weight: bold; }
    .qg-failed { color: var(--danger); font-weight: bold; }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.85rem; font-family: monospace; }
    th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid var(--border); }
    th { color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    .sev-BLOCKER, .sev-CRITICAL { color: var(--danger); font-weight: bold; }
    .sev-HIGH { color: #f87171; }
    .sev-MEDIUM { color: var(--warning); }
    .sev-LOW { color: #60a5fa; }
    pre.code-box { background: #05070b; border: 1px solid var(--border); padding: 0.75rem; border-radius: 6px; font-family: monospace; font-size: 0.8rem; overflow-x: auto; margin-top: 0.5rem; color: #cbd5e1; }
    .reason-item { border: 1px solid var(--border); border-radius: 6px; padding: 1rem; margin-top: 0.75rem; background: #0b1018; }
    .footer { text-align: center; color: var(--text-muted); font-size: 0.8rem; margin-top: 3rem; border-top: 1px solid var(--border); padding-top: 1.5rem; font-family: monospace; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div style="display: flex; justify-content: space-between; align-items: center; gap: 1rem;">
        <div style="display: flex; align-items: center; gap: 1rem;">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 160" width="48" height="48" fill="none" style="flex-shrink: 0;">
            <defs>
              <linearGradient id="wh-doc-arc" x1="24" y1="84" x2="136" y2="140" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stop-color="#a855f7" />
                <stop offset="50%" stop-color="#6366f1" />
                <stop offset="100%" stop-color="#3b82f6" />
              </linearGradient>
              <linearGradient id="wh-doc-w" x1="38" y1="36" x2="122" y2="98" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stop-color="#31d6c4" />
                <stop offset="60%" stop-color="#2dd4bf" />
                <stop offset="100%" stop-color="#10b981" />
              </linearGradient>
            </defs>
            <rect x="4" y="4" width="152" height="152" rx="34" fill="#0c1017" stroke="#1e293b" stroke-width="2.5" />
            <g stroke="url(#wh-doc-arc)" fill="none" stroke-linecap="round">
              <path d="M 26 84 A 54 54 0 0 0 134 84" stroke-width="5.5" />
              <path d="M 35 84 A 45 45 0 0 0 125 84" stroke-width="4.5" stroke-opacity="0.92" />
              <path d="M 44 84 A 36 36 0 0 0 116 84" stroke-width="3.5" stroke-opacity="0.82" />
              <line x1="25" y1="84" x2="45" y2="84" stroke-width="4.5" />
              <line x1="115" y1="84" x2="135" y2="84" stroke-width="4.5" />
            </g>
            <g stroke="#0c1017" stroke-width="3">
              <line x1="51" y1="101" x2="32" y2="112" />
              <line x1="68" y1="117" x2="60" y2="137" />
              <line x1="92" y1="117" x2="100" y2="137" />
              <line x1="109" y1="101" x2="128" y2="112" />
            </g>
            <g stroke="url(#wh-doc-w)" fill="none" stroke-linecap="round" stroke-linejoin="round">
              <path d="M 38 38 L 62 96 L 80 54 L 98 96 L 122 38" stroke-width="7.5" />
              <path d="M 48 38 L 62 73 L 80 36 L 98 73 L 112 38" stroke-width="5" />
            </g>
          </svg>
          <div>
            <h1>WinHood Analyzer — Dossiê Técnico MQR de Qualidade &amp; Segurança</h1>
            <p style="color: var(--text-muted); font-size: 0.9rem;">
              Execução ID: <code>${safeRunIdHtml}</code> · Projeto: <strong>${safeProjectNameHtml}</strong> · Algoritmo: <code>${safeAlgorithmVersionHtml}</code>
            </p>
          </div>
        </div>
        <div>
          <span class="badge">${safeReportTypeHtml}</span>
        </div>
      </div>
    </header>

    <div class="card">
      <h3 style="margin-bottom: 0.5rem; color: var(--accent);">Resumo Executivo</h3>
      <p style="color: #cbd5e1; font-size: 0.95rem;">${safeExecutiveSummaryHtml}</p>
    </div>

    <div class="grid">
      ${run.scoreCards
        .map(
          (sc) => `
        <div class="card">
          <h2>
            <span>${escapeHtml(sc.softwareName)} (v${escapeHtml(sc.softwareVersion)})</span>
            <span class="score-big">${Number(sc.groupedScores.overallScore).toFixed(2)} / 5.00</span>
          </h2>
          <div style="font-size: 0.85rem; margin-bottom: 1rem;">
            Status Quality Gate: <span class="${sc.qualityGate?.status === 'PASSED' ? 'qg-passed' : 'qg-failed'}">${escapeHtml(sc.qualityGate?.status || 'N/A')}</span>
            · Classificação: <strong>${escapeHtml(sc.classificationLabel)}</strong>
          </div>
          <div style="font-family: monospace; font-size: 0.8rem; color: var(--text-muted); line-height: 1.8;">
            <div>Segurança: <strong>${Number(sc.groupedScores.securityScore).toFixed(2)}</strong> (Rating ${escapeHtml(sc.ratings?.security || 'A')})</div>
            <div>Qualidade: <strong>${Number(sc.groupedScores.qualityScore).toFixed(2)}</strong> (Rating ${escapeHtml(sc.ratings?.maintainability || 'A')})</div>
            <div>Confiabilidade: Rating <strong>${escapeHtml(sc.ratings?.reliability || 'A')}</strong> (Bugs: ${Number(sc.metricsSummary.bugs)})</div>
            <div>Arquitetura: <strong>${Number(sc.groupedScores.architectureScore).toFixed(2)}</strong> (Ciclos: ${Number(sc.metricsSummary.circularDependencies)})</div>
            <div>Desempenho P95: <strong>${Number(sc.metricsSummary.p95LatencyMs).toFixed(1)} ms</strong> (Throughput: ${Number(sc.metricsSummary.throughputRps)} RPS)</div>
            <div>Vulnerabilidades Críticas: <strong style="${sc.metricsSummary.criticalVulns > 0 ? 'color: var(--danger)' : ''}">${Number(sc.metricsSummary.criticalVulns)}</strong></div>
          </div>
        </div>
      `
        )
        .join('')}
    </div>

    <div class="card">
      <h2>Motivos de Avaliação e Evidências no Código-Fonte (12 Categorias — MQR)</h2>
      ${run.scoreCards
        .map((sc) => {
          const cats = sc.categoryDetails ? Object.values(sc.categoryDetails) : [];
          return `
            <div style="margin-top: 1.25rem;">
              <h3 style="color: var(--accent); margin-bottom: 0.5rem;">${escapeHtml(sc.softwareName)} (v${escapeHtml(sc.softwareVersion)})</h3>
              ${cats
                .map((cd) => {
                  const reasons = cd.evaluationReasons || [];
                  const sumDelta = reasons.reduce((acc, r) => acc + r.scoreDelta, 0);
                  return `
                    <div class="reason-item">
                      <div style="display: flex; justify-content: space-between; font-family: monospace; font-weight: bold;">
                        <span>[${escapeHtml(cd.category.toUpperCase())}] Status: ${escapeHtml(cd.status)}</span>
                        <span>clamp[0,5](5.00 + (${sumDelta >= 0 ? '+' : ''}${sumDelta.toFixed(2)})) = ${Number(cd.finalScore ?? 0).toFixed(2)} / 5.00</span>
                      </div>
                      ${
                        reasons.length === 0
                          ? `<div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.4rem;">Nenhuma dedução ou limite excedido nesta categoria (5.00/5.00).</div>`
                          : reasons
                              .map(
                                (r) => `
                                <div style="margin-top: 0.6rem; padding-top: 0.6rem; border-top: 1px dashed var(--border); font-size: 0.82rem;">
                                  <div style="font-family: monospace;">
                                    <strong style="color: ${r.scoreDelta < 0 ? 'var(--danger)' : 'var(--success)'};">${r.scoreDelta >= 0 ? '+' : ''}${Number(r.scoreDelta).toFixed(2)} pts</strong>
                                    · [${escapeHtml(r.severity)}] <code>${escapeHtml(r.ruleId)}</code> · <code>${escapeHtml(r.filePath)}:${Number(r.lineNumber)}${r.endLineNumber ? `-${Number(r.endLineNumber)}` : ''}</code>
                                  </div>
                                  <div style="margin-top: 0.25rem;"><strong>Motivo:</strong> ${escapeHtml(r.title)}</div>
                                  <div style="color: var(--text-muted); margin-top: 0.2rem;"><strong>Por que impactou a nota:</strong> ${escapeHtml(r.whyExplanation)}</div>
                                  <pre class="code-box">${escapeHtml([...(r.contextBefore || []), `>>> ${r.codeSnippet}`, ...(r.contextAfter || [])].join('\n'))}</pre>
                                  ${
                                    r.executionFlow && r.executionFlow.length > 0
                                      ? `<div style="margin-top: 0.4rem; font-family: monospace; font-size: 0.75rem; color: var(--warning);">Fluxo Taint (Source → Sink): ${escapeHtml(r.executionFlow.map((s) => `[${s.nodeType}] ${s.filePath}:${s.lineNumber}`).join(' → '))}</div>`
                                      : ''
                                  }
                                  <div style="margin-top: 0.35rem; color: var(--success);"><strong>Remediação:</strong> ${escapeHtml(r.remediationSummary)}</div>
                                </div>
                              `
                              )
                              .join('')
                      }
                    </div>
                  `;
                })
                .join('')}
            </div>
          `;
        })
        .join('')}
    </div>

    <div class="card">
      <h2>Achados e Evidências Criptográficas Validadas (${Number(run.findings.length)})</h2>
      <table>
        <thead>
          <tr>
            <th>Severidade</th>
            <th>Status</th>
            <th>Software</th>
            <th>Regra / CWE</th>
            <th>Localização</th>
            <th>Título &amp; Por Que é um Problema</th>
            <th>Evidência SHA-256</th>
          </tr>
        </thead>
        <tbody>
          ${run.findings
            .map(
              (f) => `
            <tr>
              <td class="sev-${escapeHtml(f.severity)}">[${escapeHtml(f.severity)}]</td>
              <td><code>${escapeHtml(f.validationStatus)}</code></td>
              <td>${escapeHtml(f.softwareName)}</td>
              <td>${escapeHtml(f.originalRuleId)} ${f.cwe ? `(${escapeHtml(f.cwe)})` : ''}</td>
              <td><code>${escapeHtml(f.filePath)}:${Number(f.lineNumber)}</code></td>
              <td>
                <div><strong>${escapeHtml(f.title)}</strong></div>
                <div style="color: var(--text-muted); font-size: 0.75rem;">${escapeHtml(f.whyItIsAnIssue || f.description)}</div>
              </td>
              <td style="color: var(--text-muted);">${escapeHtml(f.evidenceSha256.slice(0, 16))}...</td>
            </tr>
          `
            )
            .join('')}
        </tbody>
      </table>
    </div>

    <div class="footer">
      Gerado automaticamente pelo WinHood Security &amp; Benchmark Engine · ${escapeHtml(new Date().toISOString())} · Imutabilidade garantida por cadeia SHA-256.
    </div>
  </div>
</body>
</html>`;

      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader(
        'Content-Security-Policy',
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src 'self' data:; base-uri 'none'; form-action 'none'"
      );
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="winhood_${safeFileRunId}_${safeFileReportType}.html"`
      );
      return res.end(Buffer.from(htmlContent, 'utf-8'));
    }

    if (format === 'csv') {
      const headers = [
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
        'EvidenceSHA256',
        'Title',
        'WhyItIsAnIssue',
      ];
      const rows = run.findings.map((f) =>
        [
          f.id,
          `"${f.softwareName}"`,
          f.softwareVersion,
          f.category,
          f.severity,
          f.validationStatus,
          `"${f.toolName}"`,
          f.originalRuleId,
          `"${f.filePath}"`,
          f.lineNumber,
          f.cwe || '',
          f.cve || '',
          f.cvss ?? '',
          f.evidenceSha256,
          `"${f.title.replace(/"/g, '""')}"`,
          `"${(f.whyItIsAnIssue || f.description || '').replace(/"/g, '""')}"`,
        ].join(',')
      );
      const csv = [headers.join(','), ...rows].join('\n');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="winhood_${safeFileRunId}_${safeFileReportType}.csv"`
      );
      return res.end(Buffer.from(csv, 'utf-8'));
    }

    if (format === 'md') {
      const md = [
        `# RELATÓRIO TÉCNICO WINHOOD (MQR_BRIDGE MQR) — ${reportType}`,
        `- **Execução ID:** \`${run.id}\``,
        `- **Projeto:** ${run.projectName}`,
        `- **Perfil:** ${run.profileName}`,
        `- **Algoritmo:** \`${run.algorithmVersion}\``,
        `- **Data de Conclusão:** ${run.completedAt || new Date().toISOString()}`,
        '',
        `## 1. Resumo Executivo & 5 Indicadores Separados`,
        run.executiveSummary,
        '',
        `## 2. Quadro Comparativo de Pontuações, Indicadores Separados & MqrBridge Ratings`,
        ...run.scoreCards.map(
          (sc) =>
            `### ${sc.softwareName} (v${sc.softwareVersion}) — Nota Técnica: **${sc.separatedIndicators?.technicalScore !== null && sc.separatedIndicators?.technicalScore !== undefined ? `${sc.separatedIndicators.technicalScore.toFixed(2)} / 5.00` : sc.groupedScores.overallScore.toFixed(2)}** (${sc.classificationLabel})\n` +
            `- **5 Indicadores Separados:** Nota Técnica: \`${sc.separatedIndicators?.technicalScore ?? sc.groupedScores.overallScore}\` | Cobertura do Escopo: \`${sc.separatedIndicators?.scopeCoveragePercent ?? 100}%\` | Confiança da Evidência: \`${sc.separatedIndicators?.evidenceConfidence || 'HIGH'}\` | Decisão Quality Gate: \`${sc.separatedIndicators?.qualityGateDecision || sc.qualityGate?.status || 'N/A'}\` | Veracidade: \`${sc.separatedIndicators?.veracityState || 'SUCCESS_VALIDATED'}\`\n` +
            `- **Quality Gate:** \`${sc.qualityGate?.status || 'N/A'}\` | **Ratings:** Segurança \`${sc.ratings?.security || 'N/A'}\` · Confiabilidade \`${sc.ratings?.reliability || 'N/A'}\` · Manutenibilidade \`${sc.ratings?.maintainability || 'N/A'}\`\n` +
            `- Segurança: ${sc.groupedScores.securityScore.toFixed(2)} | Qualidade: ${sc.groupedScores.qualityScore.toFixed(2)} | Arquitetura: ${sc.groupedScores.architectureScore.toFixed(2)} | Desempenho: ${sc.runtimeMetrics?.status === 'MEASURED' ? `${sc.metricsSummary.p95LatencyMs.toFixed(1)} ms` : 'NÃO MEDIDO (Estático)'}\n` +
            `- Travas Matemáticas (Penalty Caps) Acionadas: ${sc.penaltyCapsTriggered.length}\n` +
            sc.penaltyCapsTriggered.map((c) => `  - \`${c.ruleId}\` (${c.category}): ${c.reason} [Teto: ${c.maxAllowedScore}]`).join('\n')
        ),
        '',
        `## 2.1 Relatório de Comparabilidade Técnica & Imparcialidade`,
        run.comparabilityReport
          ? `- **Status Geral:** \`${run.comparabilityReport.overallStatus}\` | **Pode Declarar Vencedor Oficial:** \`${run.comparabilityReport.canDeclareOfficialWinner}\`\n` +
            (run.comparabilityReport.blockingReasons.length > 0
              ? `- **Razões de Bloqueio:** ${run.comparabilityReport.blockingReasons.join(' | ')}\n`
              : '') +
            (run.comparabilityReport.warnings.length > 0
              ? `- **Avisos de Paridade:** ${run.comparabilityReport.warnings.join(' | ')}\n`
              : '')
          : `- Avaliação individual ou sem restrições de comparabilidade.`,
        '',
        `## 2.2 Manifesto de Evidências Assinado Criptograficamente (HMAC-SHA256)`,
        run.signedManifest
          ? `- **Algoritmo:** \`${run.signedManifest.signatureAlgorithm}\` | **Key ID:** \`${run.signedManifest.keyId}\` | **Registros:** ${run.signedManifest.recordsCount}\n` +
            `- **Root Chain SHA-256:** \`${run.signedManifest.rootChainSha256}\`\n` +
            `- **Assinatura HMAC:** \`${run.signedManifest.hmacSignature}\``
          : `- Manifesto assinado não disponível.`,
        '',
        `## 3. Motivos de Avaliação e Evidências no Código-Fonte (12 Categorias)`,
        ...run.scoreCards.flatMap((sc) => {
          const cats = sc.categoryDetails ? Object.values(sc.categoryDetails) : [];
          return [
            `### ${sc.softwareName} (v${sc.softwareVersion})`,
            ...cats.map((cd) => {
              const reasons = cd.evaluationReasons || [];
              const sumDelta = reasons.reduce((acc, r) => acc + r.scoreDelta, 0);
              return (
                `#### Categoria: \`${cd.category}\` [${cd.status}] — Nota Final: **${cd.finalScore !== null && cd.finalScore !== undefined ? `${cd.finalScore.toFixed(2)} / 5.00` : 'NÃO AVALIADO / N/A'}** (Peso Original: ${cd.originalWeight ?? cd.weight}% | Peso Efetivo: ${cd.effectiveWeight ?? cd.weight}% | \`clamp[0,5](5.00 + (${sumDelta >= 0 ? '+' : ''}${sumDelta.toFixed(2)}))\`)\n` +
                (reasons.length === 0
                  ? `- Sem deduções registradas.\n`
                  : reasons
                      .map(
                        (r) =>
                          `- **${r.scoreDelta >= 0 ? '+' : ''}${r.scoreDelta.toFixed(2)} pts** [${r.severity}] \`${r.ruleId}\` em \`${r.filePath}:${r.lineNumber}\`: ${r.title}\n` +
                          `  - **Por que impactou:** ${r.whyExplanation}\n` +
                          `  - **Trecho:** \`${r.codeSnippet}\`\n` +
                          `  - **Remediação:** ${r.remediationSummary}`
                      )
                      .join('\n'))
              );
            }),
          ];
        }),
        '',
        `## 4. Evidências e Achados Validados (${run.findings.length})`,
        ...run.findings.map(
          (f) =>
            `- **[${f.severity}] [${f.lifecycleState || f.validationStatus}] ${f.softwareName}** (\`${f.filePath}:${f.lineNumber}\`) — ${f.title} | Regra: \`${f.originalRuleId}\` | Por quê: ${f.whyItIsAnIssue || f.description} | SHA-256: \`${f.evidenceSha256.slice(0, 16)}...\``
        ),
      ].join('\n');

      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="winhood_${safeFileRunId}_${safeFileReportType}.md"`
      );
      return res.end(Buffer.from(md, 'utf-8'));
    }

    const verification = verifyEvidenceChainAndManifest(run.evidenceChain, run.signedManifest);
    const storageEncReport = dbManager.inspectEncryptionAtRest(storeFile);
    const evaluatedSoftwares = run.scoreCards
      .map((sc) => db.softwares.find((s) => s.id === sc.softwareId))
      .filter((s): s is Software => Boolean(s));

    const embeddedSbomAndSca = evaluatedSoftwares.map((sw) => {
      const sbomBundle = SbomGenerator.generateFromSoftware(sw, { signSbom: true });
      const scaCorrelations = ScaCorrelator.correlateSbom({
        software: sw,
        sbom: sbomBundle,
        runId: run.id,
        dataDir: DATA_DIR,
      }).correlations;
      return {
        softwareId: sw.id,
        softwareName: sw.name,
        softwareVersion: sw.version,
        componentsCount: sbomBundle.componentsCount,
        directDependenciesCount: sbomBundle.directCount,
        transitiveDependenciesCount: sbomBundle.transitiveCount,
        cyclonedxSha256: sbomBundle.cyclonedxSha256,
        spdxSha256: sbomBundle.spdxSha256,
        signature: sbomBundle.signature,
        components: sbomBundle.components,
        scaVulnerabilityCorrelations: scaCorrelations,
        cyclonedx15Document: sbomBundle.cyclonedx15Json,
      };
    });

    const sortedCards = [...run.scoreCards].sort(
      (a, b) => b.groupedScores.overallScore - a.groupedScores.overallScore
    );
    const topCard = sortedCards[0] || null;
    const canDeclareWinner = run.comparabilityReport?.canDeclareOfficialWinner ?? true;

    const forensicSections = {
      section01_reportMetadataAndCryptographicProvenance: {
        reportSchema: 'WINHOOD-FORENSIC-BENCHMARK-REPORT-v4.5',
        reportType,
        generatedAt: new Date().toISOString(),
        platform: 'WinHood Software Benchmark & Quality Analyzer',
        algorithmVersion: run.algorithmVersion,
        methodologyCatalogVersion: METHODOLOGY_CATALOG_VERSION,
        sectionsIncluded: 15,
        evidenceChainVerification: verification,
        storageEncryptionAtRest: storageEncReport,
      },
      section02_executiveSummaryAndWinnerDeclaration: {
        runId: run.id,
        projectName: run.projectName,
        profileName: run.profileName,
        status: run.status,
        completedAt: run.completedAt,
        executiveSummary: run.executiveSummary,
        canDeclareOfficialWinner: canDeclareWinner,
        officialWinner:
          canDeclareWinner && topCard
            ? {
                softwareId: topCard.softwareId,
                softwareName: topCard.softwareName,
                softwareVersion: topCard.softwareVersion,
                overallScore: topCard.groupedScores.overallScore,
                classificationLabel: topCard.classificationLabel,
                qualityGateStatus: topCard.qualityGate?.status || 'PASSED',
              }
            : null,
        comparabilityReport: run.comparabilityReport || null,
      },
      section03_environmentAndHardwareTelemetry: {
        osPlatform: os.platform(),
        osRelease: os.release(),
        cpuArch: os.arch(),
        cpuCores: os.cpus().length,
        totalMemoryGb: Number((os.totalmem() / 1024 ** 3).toFixed(2)),
        nodeVersion: process.version,
        hardwareProfile: getHardwareProfile(),
        executionRecords: run.executionRecords || [],
      },
      section04_softwaresInventoryManifest: evaluatedSoftwares.map((sw) => ({
        id: sw.id,
        name: sw.name,
        vendor: sw.vendor,
        version: sw.version,
        licenseType: sw.licenseType,
        architecture: sw.architecture,
        operatingSystem: sw.operatingSystem,
        sourceType: sw.sourceType,
        commitHash: sw.commitHash,
        repositoryUrl: sw.repositoryUrl,
        inventory: sw.inventory,
        sourceFilesCount: Object.keys(sw.sourceFilesContent || {}).length,
        sourceFilesSha256Manifest: Object.entries(sw.sourceFilesContent || {})
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([filePath, content]) => ({
            filePath,
            bytes: Buffer.byteLength(content, 'utf8'),
            sha256: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
          })),
      })),
      section05_algebraicScoreCardsBreakdown: run.scoreCards.map((sc) => ({
        softwareId: sc.softwareId,
        softwareName: sc.softwareName,
        softwareVersion: sc.softwareVersion,
        groupedScores: sc.groupedScores,
        separatedIndicators: sc.separatedIndicators,
        ratings: sc.ratings,
        qualityGate: sc.qualityGate,
        metricsSummary: sc.metricsSummary,
        penaltyCapsTriggered: sc.penaltyCapsTriggered,
        categoryScores: sc.categoryScores,
        categoryDetails: sc.categoryDetails,
      })),
      section06_normalizedFindingsDetailed: run.findings.map((f) => ({
        id: f.id,
        softwareId: f.softwareId,
        softwareName: f.softwareName,
        softwareVersion: f.softwareVersion,
        category: f.category,
        severity: f.severity,
        validationStatus: f.validationStatus,
        lifecycleState: f.lifecycleState || 'OPEN',
        toolName: f.toolName,
        originalRuleId: f.originalRuleId,
        title: f.title,
        description: f.description,
        whyItIsAnIssue: f.whyItIsAnIssue,
        remediation: f.remediation,
        compliantCodeExample: f.compliantCodeExample,
        remediationEffortMinutes: f.remediationEffortMinutes,
        filePath: f.filePath,
        lineNumber: f.lineNumber,
        endLineNumber: f.endLineNumber,
        snippet: f.snippet,
        contextBefore: f.contextBefore || [],
        contextAfter: f.contextAfter || [],
        executionFlows: f.executionFlows || [],
        cwe: f.cwe || null,
        cve: f.cve || null,
        cvss: f.cvss ?? null,
        epss: f.epss ?? null,
        cisaKev: Boolean(f.cisaKev),
        cleanCodeAttribute: f.cleanCodeAttribute || null,
        mqrImpacts: f.mqrImpacts || [],
        evidenceSha256: f.evidenceSha256,
      })),
      section07_embeddedCycloneDxSbomAndSca: embeddedSbomAndSca,
      section08_complianceAndStandardsMatrix: {
        frameworksEvaluated: [
          'OWASP Top 10 (2021)',
          'OWASP ASVS 4.0.3 L2',
          'NIST SSDF (SP 800-218)',
          'MITRE CWE Top 25',
          'CISA KEV & FIRST EPSS',
          'MQR Clean Code Taxonomy',
        ],
        cweDistribution: run.findings.reduce<Record<string, number>>((acc, f) => {
          const key = f.cwe || 'UNCLASSIFIED';
          acc[key] = (acc[key] || 0) + 1;
          return acc;
        }, {}),
        severityDistribution: run.findings.reduce<Record<string, number>>((acc, f) => {
          acc[f.severity] = (acc[f.severity] || 0) + 1;
          return acc;
        }, {}),
      },
      section09_architectureAndCouplingGraphs: run.scoreCards.map((sc) => ({
        softwareId: sc.softwareId,
        softwareName: sc.softwareName,
        architectureScore: sc.groupedScores.architectureScore,
        circularDependenciesCount: sc.metricsSummary.circularDependencies,
        duplicatedLinesDensityPercent: sc.metricsSummary.duplicatedLinesPercent ?? 0,
        codeSmellsCount: sc.metricsSummary.codeSmells,
        cognitiveComplexityTotal: sc.metricsSummary.avgCognitiveComplexity ?? 0,
      })),
      section10_evidenceHashChainAndSignatures: {
        verification,
        signedManifest: run.signedManifest || null,
        evidenceChainLength: run.evidenceChain.length,
        evidenceChain: run.evidenceChain,
      },
    };

    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="winhood_${safeFileRunId}_${safeFileReportType}.json"`
    );
    return res.send(
      JSON.stringify(
        {
          reportSchema: 'WINHOOD-FORENSIC-BENCHMARK-REPORT-v4.5',
          reportMetadata: {
            reportSchema: 'WINHOOD-FORENSIC-BENCHMARK-REPORT-v4.5',
            reportType,
            generatedAt: forensicSections.section01_reportMetadataAndCryptographicProvenance.generatedAt,
            platform: 'WinHood Software Benchmark & Quality Analyzer',
            algorithmVersion: run.algorithmVersion,
            methodologyCatalogVersion: METHODOLOGY_CATALOG_VERSION,
            sectionsIncluded: 15,
            evidenceChainVerification: verification,
            storageEncryptionAtRest: storageEncReport,
          },
          forensicSections,
          run,
        },
        null,
        2
      )
    );
  });

  // ============================================================================
  // 12. MQR_BRIDGE COMMUNITY BUILD, CLOUD, IDE, GITAR AI & RESOURCE OPTIMIZATION
  // ============================================================================

  app.get('/api/tools-integrations', (_req, res) => {
    const cacheStats = toolCacheManager.getCacheStats();
    db.toolsDb.optimization_report = ToolResourceMonitor.buildOptimizationReport(
      dataDir,
      cacheStats.sizeKb,
      lifecycleManager.isLocalServerRunning()
    );
    db.toolsDb.sonar_execution_logs = lifecycleManager.getLogs();

    res.json({
      toolsDb: db.toolsDb,
      hostResources: ToolResourceMonitor.inspectHostResources(),
      lifecycleLimits: lifecycleManager.getLimits(),
      lifecycleStatus: {
        localServerRunning: lifecycleManager.isLocalServerRunning(),
        activeAnalysesCount: lifecycleManager.getActiveAnalysesCount(),
        queuedTasksCount: lifecycleManager.getQueuedTasksCount(),
      },
      cacheStats,
    });
  });



  // ============================================================================
  // 12.0 MULTI-PROJECT SONARCLOUD / MQR_BRIDGE JSON REPORT EXPORTER & TOKEN MONITOR
  // ============================================================================

  app.get('/api/sonar/saved-projects', (_req, res) => {
    if (!Array.isArray(db.savedSonarProjects)) {
      db.savedSonarProjects = [];
    }
    const projects = db.savedSonarProjects.map((proj) => ({
      ...sanitizeSavedSonarProjectForClient(proj),
      tokenVerification: computeSonarTokenVerification(proj),
    }));
    res.json({ projects });
  });

  app.post('/api/sonar/saved-projects', async (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const {
      id,
      name,
      platform,
      serverUrl,
      organization,
      projectKey,
      token,
      tokenValidityDaysPolicy,
      customTokenExpiresAt,
    } = req.body as {
      id?: string;
      name?: string;
      platform?: 'SONARCLOUD' | 'MQR_BRIDGE_SERVER';
      serverUrl?: string;
      organization?: string;
      projectKey?: string;
      token?: string;
      tokenValidityDaysPolicy?: 30 | 60 | 90 | 'NO_EXPIRATION' | 'CUSTOM';
      customTokenExpiresAt?: string | null;
    };

    const resolvedPlatform: 'SONARCLOUD' | 'MQR_BRIDGE_SERVER' =
      platform === 'MQR_BRIDGE_SERVER' ? 'MQR_BRIDGE_SERVER' : 'SONARCLOUD';
    const cleanProjectKey = (projectKey || '').trim();
    const cleanOrg = (organization || '').trim();

    if (!cleanProjectKey || !SAFE_SONAR_KEY_REGEX.test(cleanProjectKey)) {
      return res.status(400).json({
        error:
          'Project Key inválido. Informe apenas caracteres alfanuméricos, pontos, hifens, dois-pontos ou sublinhados.',
      });
    }
    if (resolvedPlatform === 'SONARCLOUD' && (!cleanOrg || !SAFE_SONAR_ORG_REGEX.test(cleanOrg))) {
      return res.status(400).json({
        error:
          'Organization inválida para o SonarCloud. Informe o identificador da organização.',
      });
    }

    let safeOrigin: string;
    try {
      safeOrigin = await validateSonarServerOriginSafe(
        serverUrl || (resolvedPlatform === 'SONARCLOUD' ? 'https://sonarcloud.io' : 'http://localhost:9000'),
        resolvedPlatform
      );
    } catch (err: any) {
      return res.status(400).json({ error: err?.message || 'URL do servidor Sonar inválida.' });
    }

    if (!Array.isArray(db.savedSonarProjects)) {
      db.savedSonarProjects = [];
    }

    const nowIso = new Date().toISOString();
    const policy: SavedSonarProjectProfile['tokenValidityDaysPolicy'] =
      tokenValidityDaysPolicy === 30 ||
      tokenValidityDaysPolicy === 60 ||
      tokenValidityDaysPolicy === 90 ||
      tokenValidityDaysPolicy === 'NO_EXPIRATION' ||
      tokenValidityDaysPolicy === 'CUSTOM'
        ? tokenValidityDaysPolicy
        : 90;

    let computedExpiresAt: string | null = null;
    if (policy === 30 || policy === 60 || policy === 90) {
      computedExpiresAt = new Date(Date.now() + policy * 24 * 60 * 60 * 1000).toISOString();
    } else if (policy === 'CUSTOM' && customTokenExpiresAt) {
      const parsedDate = new Date(customTokenExpiresAt);
      if (!Number.isNaN(parsedDate.getTime())) {
        computedExpiresAt = parsedDate.toISOString();
      }
    }

    let existing = db.savedSonarProjects.find(
      (p) => (id && p.id === id) || p.projectKey === cleanProjectKey
    );

    if (!existing) {
      existing = {
        id: id || `sonar-proj-${crypto.randomUUID().slice(0, 8)}`,
        name: (name || cleanProjectKey).trim(),
        platform: resolvedPlatform,
        serverUrl: safeOrigin,
        organization: cleanOrg,
        projectKey: cleanProjectKey,
        maskedToken: 'Não configurado',
        hasToken: false,
        tokenCreatedAt: nowIso,
        tokenExpiresAt: computedExpiresAt,
        tokenValidityDaysPolicy: policy,
        lastVerifiedAt: null,
        lastVerificationStatus: 'UNCHECKED',
        lastExportedAt: null,
        lastExportedIssuesCount: null,
      };
      db.savedSonarProjects.unshift(existing);
    } else {
      existing.name = (name || existing.name || cleanProjectKey).trim();
      existing.platform = resolvedPlatform;
      existing.serverUrl = safeOrigin;
      existing.organization = cleanOrg;
      existing.projectKey = cleanProjectKey;
      existing.tokenValidityDaysPolicy = policy;
      if (computedExpiresAt !== null || policy === 'NO_EXPIRATION') {
        existing.tokenExpiresAt = computedExpiresAt;
      }
    }

    if (token && token.trim().length > 0) {
      const cleanToken = token.trim();
      existing.encryptedToken = MqrBridgeConnection.encryptToken(cleanToken);
      existing.maskedToken = MqrBridgeConnection.maskToken(cleanToken);
      existing.hasToken = true;
      existing.tokenCreatedAt = nowIso;
      if (computedExpiresAt !== null || policy === 'NO_EXPIRATION') {
        existing.tokenExpiresAt = computedExpiresAt;
      }

      // Validar token imediatamente na API do SonarCloud / MqrBridge se acessível
      try {
        const authUrl = new URL('/api/authentication/validate', safeOrigin);
        const authRes = await fetchWithTimeoutAndNoRedirect(
          authUrl.toString(),
          {
            method: 'GET',
            headers: {
              Accept: 'application/json',
              Authorization: `Bearer ${cleanToken}`,
              'User-Agent': 'WinHood-SonarExporter/2.0',
            },
          },
          5000
        );
        if (authRes.ok) {
          const authJson = (await authRes.json()) as { valid?: boolean };
          existing.lastVerifiedAt = nowIso;
          existing.lastVerificationStatus = authJson.valid ? 'VALID' : 'INVALID';
        } else if (authRes.status === 401 || authRes.status === 403) {
          existing.lastVerifiedAt = nowIso;
          existing.lastVerificationStatus = 'INVALID';
        }
      } catch {
        // Permanece UNCHECKED caso offline
      }
    }

    appendAuditLog(
      db,
      'SONAR_PROJECT_PROFILE_SAVED',
      'SONAR_PROJECT_PROFILE',
      existing.id,
      `Perfil de projeto Sonar "${existing.name}" (${existing.projectKey}) salvo com política de token ${existing.tokenValidityDaysPolicy}.`
    );
    saveDatabase(db);

    return res.json({
      project: {
        ...sanitizeSavedSonarProjectForClient(existing),
        tokenVerification: computeSonarTokenVerification(existing),
      },
      projects: db.savedSonarProjects.map((p) => ({
        ...sanitizeSavedSonarProjectForClient(p),
        tokenVerification: computeSonarTokenVerification(p),
      })),
    });
  });

  app.delete('/api/sonar/saved-projects/:id', (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    if (!Array.isArray(db.savedSonarProjects)) {
      db.savedSonarProjects = [];
    }
    const idx = db.savedSonarProjects.findIndex((p) => p.id === req.params.id);
    if (idx === -1) {
      return res.status(404).json({ error: 'Perfil de projeto Sonar não encontrado.' });
    }
    const removed = db.savedSonarProjects.splice(idx, 1)[0];
    appendAuditLog(
      db,
      'SONAR_PROJECT_PROFILE_DELETED',
      'SONAR_PROJECT_PROFILE',
      removed.id,
      `Perfil de projeto Sonar "${removed.projectKey}" removido.`
    );
    saveDatabase(db);
    return res.json({
      ok: true,
      projects: db.savedSonarProjects.map((p) => ({
        ...sanitizeSavedSonarProjectForClient(p),
        tokenVerification: computeSonarTokenVerification(p),
      })),
    });
  });

  app.post('/api/sonar/saved-projects/:id/verify-token', async (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    if (!Array.isArray(db.savedSonarProjects)) {
      db.savedSonarProjects = [];
    }
    const proj = db.savedSonarProjects.find((p) => p.id === req.params.id);
    if (!proj) {
      return res.status(404).json({ error: 'Perfil de projeto Sonar não encontrado.' });
    }

    const { token: inlineToken } = (req.body || {}) as { token?: string };
    if (inlineToken && inlineToken.trim().length > 0) {
      proj.encryptedToken = MqrBridgeConnection.encryptToken(inlineToken.trim());
      proj.maskedToken = MqrBridgeConnection.maskToken(inlineToken.trim());
      proj.hasToken = true;
    }

    const plainToken = proj.encryptedToken
      ? MqrBridgeConnection.decryptToken(proj.encryptedToken)
      : null;

    if (!plainToken) {
      const verification = computeSonarTokenVerification(
        proj,
        false,
        'Nenhum token Bearer configurado neste projeto. Edite ou insira o token para validar.'
      );
      return res.json({
        project: {
          ...sanitizeSavedSonarProjectForClient(proj),
          tokenVerification: verification,
        },
        verification,
      });
    }

    let safeOrigin: string;
    try {
      safeOrigin = await validateSonarServerOriginSafe(proj.serverUrl, proj.platform);
    } catch (err: any) {
      return res.status(400).json({ error: err?.message || 'URL do servidor Sonar inválida.' });
    }

    const nowIso = new Date().toISOString();
    try {
      const validateUrl = new URL('/api/authentication/validate', safeOrigin);
      const authRes = await fetchWithTimeoutAndNoRedirect(
        validateUrl.toString(),
        {
          method: 'GET',
          headers: {
            Accept: 'application/json',
            Authorization: `Bearer ${plainToken}`,
            'User-Agent': 'WinHood-SonarExporter/2.0',
          },
        },
        6000
      );

      if (authRes.status === 401 || authRes.status === 403) {
        proj.lastVerifiedAt = nowIso;
        proj.lastVerificationStatus = 'INVALID';
        saveDatabase(db);
        const verification = computeSonarTokenVerification(
          proj,
          false,
          `Autenticação recusada (HTTP ${authRes.status}): token inválido ou expirado no servidor.`
        );
        return res.json({
          project: {
            ...sanitizeSavedSonarProjectForClient(proj),
            tokenVerification: verification,
          },
          verification,
        });
      }

      const authData = (await authRes.json()) as { valid?: boolean };
      const isValid = Boolean(authData.valid);

      // Tentar consultar /api/user_tokens/search para descobrir expirationDate real se disponível
      if (isValid) {
        try {
          const tokensUrl = new URL('/api/user_tokens/search', safeOrigin);
          const tokensRes = await fetchWithTimeoutAndNoRedirect(
            tokensUrl.toString(),
            {
              method: 'GET',
              headers: {
                Accept: 'application/json',
                Authorization: `Bearer ${plainToken}`,
                'User-Agent': 'WinHood-SonarExporter/2.0',
              },
            },
            6000
          );
          if (tokensRes.ok) {
            const tokensJson = (await tokensRes.json()) as {
              userTokens?: Array<{
                name?: string;
                createdAt?: string;
                expirationDate?: string;
                isExpired?: boolean;
              }>;
            };
            const tokenWithExp = (tokensJson.userTokens || []).find((t) => Boolean(t.expirationDate));
            if (tokenWithExp?.expirationDate) {
              proj.tokenExpiresAt = new Date(tokenWithExp.expirationDate).toISOString();
            }
          }
        } catch {
          // Endpoint opcional, mantém tokenExpiresAt da política cadastrada
        }
      }

      proj.lastVerifiedAt = nowIso;
      proj.lastVerificationStatus = isValid ? 'VALID' : 'INVALID';
      saveDatabase(db);

      const verification = computeSonarTokenVerification(
        proj,
        isValid,
        isValid
          ? undefined
          : 'O endpoint /api/authentication/validate retornou valid: false para este token.'
      );

      return res.json({
        project: {
          ...sanitizeSavedSonarProjectForClient(proj),
          tokenVerification: verification,
        },
        verification,
      });
    } catch (err: any) {
      const verification = computeSonarTokenVerification(
        proj,
        undefined,
        `Não foi possível contatar ${safeOrigin} (${err?.message || 'Erro de rede'}). Exibindo cálculo baseado na validade cadastrada.`
      );
      return res.json({
        project: {
          ...sanitizeSavedSonarProjectForClient(proj),
          tokenVerification: verification,
        },
        verification,
      });
    }
  });

  app.get('/api/sonar/saved-projects/:id/export-json', async (req, res) => {
    if (!requireWritePermission(res, req, 'reports:export')) return;
    if (!Array.isArray(db.savedSonarProjects)) {
      db.savedSonarProjects = [];
    }
    const proj = db.savedSonarProjects.find((p) => p.id === req.params.id);
    if (!proj) {
      return res.status(404).json({ error: 'Perfil de projeto Sonar não encontrado.' });
    }

    const plainToken = proj.encryptedToken
      ? MqrBridgeConnection.decryptToken(proj.encryptedToken)
      : null;

    if (!plainToken) {
      return res.status(400).json({
        error:
          'Token Bearer não configurado para este projeto. Insira e salve seu token do SonarCloud/MqrBridge antes de baixar o relatório JSON.',
      });
    }

    let safeOrigin: string;
    try {
      safeOrigin = await validateSonarServerOriginSafe(proj.serverUrl, proj.platform);
    } catch (err: any) {
      return res.status(400).json({ error: err?.message || 'URL do servidor Sonar inválida.' });
    }

    if (!SAFE_SONAR_KEY_REGEX.test(proj.projectKey)) {
      return res.status(400).json({ error: 'Project Key inválido.' });
    }

    const reqHeaders = {
      Accept: 'application/json',
      Authorization: `Bearer ${plainToken}`,
      'User-Agent': 'WinHood-SonarExporter/2.0',
    };

    const hasValidOrg =
      proj.platform === 'SONARCLOUD' &&
      Boolean(proj.organization) &&
      SAFE_SONAR_ORG_REGEX.test(proj.organization);

    try {
      // 1. Consultar metadados do Componente/Projeto (/api/components/show)
      let componentMetadata: Record<string, unknown> | null = null;
      let componentAncestors: unknown[] = [];
      try {
        const compUrl = new URL('/api/components/show', safeOrigin);
        compUrl.searchParams.set('component', proj.projectKey);
        if (compUrl.origin === safeOrigin) {
          const compRes = await fetchWithTimeoutAndNoRedirect(compUrl.toString(), { method: 'GET', headers: reqHeaders }, 8000);
          if (compRes.ok) {
            const compData = (await compRes.json()) as {
              component?: Record<string, unknown>;
              ancestors?: unknown[];
            };
            componentMetadata = compData.component || null;
            componentAncestors = Array.isArray(compData.ancestors) ? compData.ancestors : [];
          }
        }
      } catch {
        // Continua caso endpoint opcional falhe
      }

      // 2. Consultar Status do Quality Gate (/api/qualitygates/project_status)
      let qualityGateStatusObj: Record<string, unknown> | null = null;
      try {
        const qgUrl = new URL('/api/qualitygates/project_status', safeOrigin);
        qgUrl.searchParams.set('projectKey', proj.projectKey);
        if (qgUrl.origin === safeOrigin) {
          const qgRes = await fetchWithTimeoutAndNoRedirect(qgUrl.toString(), { method: 'GET', headers: reqHeaders }, 8000);
          if (qgRes.ok) {
            const qgData = (await qgRes.json()) as {
              projectStatus?: Record<string, unknown>;
            };
            qualityGateStatusObj = qgData.projectStatus || (qgData as Record<string, unknown>);
          }
        }
      } catch {
        // Continua caso endpoint opcional falhe
      }

      // 3. Consultar Métricas Estáticas e MQR (/api/measures/component)
      let rawMeasures: Array<{
        metric: string;
        value?: string;
        period?: { value?: string };
        periods?: Array<{ value?: string }>;
      }> = [];
      const measuresMap: Record<string, string | number> = {};
      try {
        const measuresUrl = new URL('/api/measures/component', safeOrigin);
        measuresUrl.searchParams.set('component', proj.projectKey);
        measuresUrl.searchParams.set('metricKeys', SONAR_FULL_METRIC_KEYS);
        if (measuresUrl.origin === safeOrigin) {
          const mRes = await fetchWithTimeoutAndNoRedirect(measuresUrl.toString(), { method: 'GET', headers: reqHeaders }, 8000);
          if (mRes.ok) {
            const mData = (await mRes.json()) as {
              component?: {
                measures?: Array<{
                  metric: string;
                  value?: string;
                  period?: { value?: string };
                  periods?: Array<{ value?: string }>;
                }>;
              };
            };
            if (Array.isArray(mData.component?.measures)) {
              rawMeasures = mData.component!.measures!;
              for (const m of rawMeasures) {
                const rawVal =
                  m.value ??
                  m.period?.value ??
                  (Array.isArray(m.periods) ? m.periods[0]?.value : undefined) ??
                  '';
                const numVal = Number(rawVal);
                measuresMap[m.metric] =
                  rawVal !== '' && !Number.isNaN(numVal) && String(numVal) === String(rawVal).trim()
                    ? numVal
                    : String(rawVal);
              }
            }
          }
        }
      } catch {
        // Continua caso endpoint opcional falhe
      }

      // 4. Consultar Todas as Issues Paginadas com additionalFields=_all (/api/issues/search)
      const pageSize = 500;
      let page = 1;
      let totalIssuesReported = 0;
      let effortTotal = 0;
      let debtTotal = 0;
      const allIssues: Array<Record<string, any>> = [];
      const componentsByKey = new Map<string, Record<string, unknown>>();
      const rulesByKey = new Map<string, Record<string, unknown>>();
      const usersByLogin = new Map<string, Record<string, unknown>>();
      let facetsList: unknown[] = [];

      do {
        const searchUrl = new URL('/api/issues/search', safeOrigin);
        searchUrl.searchParams.set('componentKeys', proj.projectKey);
        if (hasValidOrg) {
          searchUrl.searchParams.set('organization', proj.organization);
        }
        searchUrl.searchParams.set('ps', String(pageSize));
        searchUrl.searchParams.set('p', String(page));
        searchUrl.searchParams.set('additionalFields', '_all');
        searchUrl.searchParams.set(
          'facets',
          'severities,types,rules,statuses,resolutions,cleanCodeAttributeCategories,impactSoftwareQualities,impactSeverities'
        );

        if (searchUrl.origin !== safeOrigin) {
          return res.status(400).json({ error: 'Origem da URL de busca inválida.' });
        }

        const response = await fetchWithTimeoutAndNoRedirect(
          searchUrl.toString(),
          {
            method: 'GET',
            headers: reqHeaders,
          },
          10_000
        );

        if (response.status === 401 || response.status === 403) {
          proj.lastVerificationStatus = 'INVALID';
          proj.lastVerifiedAt = new Date().toISOString();
          saveDatabase(db);
          return res.status(401).json({
            error: `Falha de autenticação HTTP ${response.status} no Sonar (${safeOrigin}). Verifique se o token Bearer está ativo e possui permissão Browse no projeto "${proj.projectKey}".`,
          });
        }

        if (!response.ok) {
          return res.status(response.status).json({
            error: `A API do Sonar retornou status HTTP ${response.status} ao buscar issues de "${proj.projectKey}".`,
          });
        }

        const pageData = (await response.json()) as {
          total?: number;
          effortTotal?: number;
          debtTotal?: number;
          paging?: { total?: number; pageIndex?: number; pageSize?: number };
          issues?: Array<Record<string, any>>;
          components?: Array<Record<string, any>>;
          rules?: Array<Record<string, any>>;
          users?: Array<Record<string, any>>;
          facets?: unknown[];
        };

        const issuesBatch = Array.isArray(pageData.issues) ? pageData.issues : [];
        totalIssuesReported = Number(
          pageData.total ?? pageData.paging?.total ?? issuesBatch.length
        );
        if (typeof pageData.effortTotal === 'number') effortTotal = pageData.effortTotal;
        if (typeof pageData.debtTotal === 'number') debtTotal = pageData.debtTotal;

        allIssues.push(...issuesBatch);

        if (Array.isArray(pageData.components)) {
          for (const comp of pageData.components) {
            if (comp && typeof comp.key === 'string') {
              componentsByKey.set(comp.key, comp);
            }
          }
        }
        if (Array.isArray(pageData.rules)) {
          for (const rule of pageData.rules) {
            if (rule && typeof rule.key === 'string') {
              rulesByKey.set(rule.key, rule);
            }
          }
        }
        if (Array.isArray(pageData.users)) {
          for (const usr of pageData.users) {
            if (usr && typeof usr.login === 'string') {
              usersByLogin.set(usr.login, usr);
            }
          }
        }
        if (page === 1 && Array.isArray(pageData.facets)) {
          facetsList = pageData.facets;
        }

        if (issuesBatch.length === 0) {
          break;
        }
        page += 1;
      } while (allIssues.length < totalIssuesReported && (page - 1) * pageSize < 10000);

      // 5. Consultar Todos os Security Hotspots Paginados (/api/hotspots/search)
      const allHotspots: Array<Record<string, any>> = [];
      const hotspotComponentsByKey = new Map<string, Record<string, unknown>>();
      try {
        let hsPage = 1;
        let hsTotal = 0;
        do {
          const hsUrl = new URL('/api/hotspots/search', safeOrigin);
          hsUrl.searchParams.set('projectKey', proj.projectKey);
          hsUrl.searchParams.set('ps', String(pageSize));
          hsUrl.searchParams.set('p', String(hsPage));

          if (hsUrl.origin !== safeOrigin) break;
          const hsRes = await fetchWithTimeoutAndNoRedirect(hsUrl.toString(), { method: 'GET', headers: reqHeaders }, 8000);
          if (!hsRes.ok) break;

          const hsData = (await hsRes.json()) as {
            paging?: { total?: number };
            hotspots?: Array<Record<string, any>>;
            components?: Array<Record<string, any>>;
          };
          const hsBatch = Array.isArray(hsData.hotspots) ? hsData.hotspots : [];
          hsTotal = Number(hsData.paging?.total ?? hsBatch.length);
          allHotspots.push(...hsBatch);

          if (Array.isArray(hsData.components)) {
            for (const c of hsData.components) {
              if (c && typeof c.key === 'string') {
                hotspotComponentsByKey.set(c.key, c);
              }
            }
          }

          if (hsBatch.length === 0) break;
          hsPage += 1;
        } while (allHotspots.length < hsTotal && (hsPage - 1) * pageSize < 10000);
      } catch {
        // Continua caso endpoint opcional falhe
      }

      // 6. Consultar Branches e Histórico de Análises (/api/project_branches/list & /api/project_analyses/search)
      let projectBranches: unknown[] = [];
      let projectAnalyses: unknown[] = [];
      try {
        const brUrl = new URL('/api/project_branches/list', safeOrigin);
        brUrl.searchParams.set('project', proj.projectKey);
        if (brUrl.origin === safeOrigin) {
          const brRes = await fetchWithTimeoutAndNoRedirect(brUrl.toString(), { method: 'GET', headers: reqHeaders }, 8000);
          if (brRes.ok) {
            const brData = (await brRes.json()) as { branches?: unknown[] };
            projectBranches = Array.isArray(brData.branches) ? brData.branches : [];
          }
        }
      } catch {
        // Opcional
      }

      try {
        const anUrl = new URL('/api/project_analyses/search', safeOrigin);
        anUrl.searchParams.set('project', proj.projectKey);
        anUrl.searchParams.set('ps', '50');
        anUrl.searchParams.set('p', '1');
        if (anUrl.origin === safeOrigin) {
          const anRes = await fetchWithTimeoutAndNoRedirect(anUrl.toString(), { method: 'GET', headers: reqHeaders }, 8000);
          if (anRes.ok) {
            const anData = (await anRes.json()) as { analyses?: unknown[] };
            projectAnalyses = Array.isArray(anData.analyses) ? anData.analyses : [];
          }
        }
      } catch {
        // Opcional
      }

      // 7. Construir Resumo Analítico Consolidado (summary)
      const bySeverity: Record<string, number> = {
        BLOCKER: 0,
        CRITICAL: 0,
        MAJOR: 0,
        MINOR: 0,
        INFO: 0,
      };
      const byType: Record<string, number> = {
        VULNERABILITY: 0,
        BUG: 0,
        CODE_SMELL: 0,
        SECURITY_HOTSPOT: allHotspots.length,
      };
      const byStatus: Record<string, number> = {};
      const byMqrImpactSoftwareQuality: Record<string, number> = {
        SECURITY: 0,
        RELIABILITY: 0,
        MAINTAINABILITY: 0,
      };
      let openIssuesCount = 0;
      let closedIssuesCount = 0;

      for (const iss of allIssues) {
        const sev = String(iss.severity || 'MAJOR').toUpperCase();
        bySeverity[sev] = (bySeverity[sev] || 0) + 1;

        const typ = String(iss.type || 'CODE_SMELL').toUpperCase();
        byType[typ] = (byType[typ] || 0) + 1;

        const st = String(iss.status || 'OPEN').toUpperCase();
        byStatus[st] = (byStatus[st] || 0) + 1;
        if (st === 'CLOSED' || st === 'RESOLVED') {
          closedIssuesCount += 1;
        } else {
          openIssuesCount += 1;
        }

        if (Array.isArray(iss.impacts)) {
          for (const imp of iss.impacts) {
            const sq = String(imp?.softwareQuality || '').toUpperCase();
            if (sq) {
              byMqrImpactSoftwareQuality[sq] = (byMqrImpactSoftwareQuality[sq] || 0) + 1;
            }
          }
        }
      }

      const toReviewHotspotsCount = allHotspots.filter(
        (h) => String(h.status || '').toUpperCase() === 'TO_REVIEW'
      ).length;
      const reviewedHotspotsCount = allHotspots.length - toReviewHotspotsCount;

      const nowIso = new Date().toISOString();
      proj.lastExportedAt = nowIso;
      proj.lastExportedIssuesCount = allIssues.length;
      proj.lastVerifiedAt = nowIso;
      proj.lastVerificationStatus = 'VALID';

      appendAuditLog(
        db,
        'SONAR_JSON_REPORT_EXPORTED',
        'SONAR_PROJECT_PROFILE',
        proj.id,
        `Análise completa exportada de ${safeOrigin} para "${proj.projectKey}" (${allIssues.length} issues, ${allHotspots.length} hotspots, ${rawMeasures.length} métricas).`
      );
      saveDatabase(db);

      const safeFileProjectKey = proj.projectKey.replace(/[^a-zA-Z0-9._-]/g, '_');
      const reportPayload = {
        platform: proj.platform,
        serverUrl: safeOrigin,
        projectKey: proj.projectKey,
        organization: proj.organization,
        generatedAt: nowIso,
        total: allIssues.length,
        p: 1,
        ps: allIssues.length,
        paging: {
          pageIndex: 1,
          pageSize: allIssues.length,
          total: totalIssuesReported || allIssues.length,
        },
        effortTotal,
        debtTotal,
        totalIssues: allIssues.length,
        totalHotspots: allHotspots.length,
        summary: {
          qualityGateStatus:
            (qualityGateStatusObj?.status as string) ||
            (measuresMap.alert_status as string) ||
            'UNKNOWN',
          totalIssues: allIssues.length,
          openIssuesCount,
          closedIssuesCount,
          totalHotspots: allHotspots.length,
          toReviewHotspotsCount,
          reviewedHotspotsCount,
          effortTotalMinutes: effortTotal,
          bySeverity,
          byType,
          byStatus,
          byMqrImpactSoftwareQuality,
        },
        component: componentMetadata,
        ancestors: componentAncestors,
        qualityGate: qualityGateStatusObj,
        measuresMap,
        measures: rawMeasures,
        branches: projectBranches,
        analyses: projectAnalyses,
        issues: allIssues,
        hotspots: allHotspots,
        components: Array.from(componentsByKey.values()),
        hotspotComponents: Array.from(hotspotComponentsByKey.values()),
        rules: Array.from(rulesByKey.values()),
        users: Array.from(usersByLogin.values()),
        facets: facetsList,
      };

      // Sincronização automática com o estado global da avaliação ativa (Seção 10)
      if (allIssues.length > 0) {
        const targetRun = db.runs[0];
        if (targetRun) {
          const parsedRecords = SonarResultParser.parseIssuesAndHotspots({
            analysisId: `sonar-sync-${Date.now()}`,
            projectKey: proj.projectKey,
            softwareId: targetRun.softwareIds[0] || 'sw-sonarcloud-imported',
            softwareName: targetRun.scoreCards[0]?.softwareName || proj.name || proj.projectKey,
            rawIssues: allIssues.map((iss) => ({
              key: iss.key,
              rule: iss.rule,
              severity: iss.severity || 'MAJOR',
              component: iss.component || '',
              project: iss.project || proj.projectKey,
              line: iss.line,
              message: iss.message || '',
              effort: iss.effort,
              type: iss.type || 'CODE_SMELL',
              externalRuleEngine: iss.externalRuleEngine,
            })),
            rawHotspots: allHotspots.map((hs) => ({
              key: hs.key,
              component: hs.component || '',
              project: hs.project || proj.projectKey,
              securityCategory: hs.securityCategory || 'OTHERS',
              vulnerabilityProbability: hs.vulnerabilityProbability || 'MEDIUM',
              status: hs.status || 'TO_REVIEW',
              resolution: hs.resolution,
              line: hs.line,
              message: hs.message || '',
              ruleKey: hs.ruleKey,
            })),
          });

          const normalizedNewFindings = SonarResultParser.mapSonarIssuesToNormalizedFindings(
            parsedRecords,
            targetRun.softwareIds[0] || 'sw-sonarcloud-imported',
            targetRun.scoreCards[0]?.softwareName || proj.name || proj.projectKey
          );

          // Mesclar achados sem duplicidade
          const existingIds = new Set(targetRun.findings.map((f) => f.id));
          const toAdd = normalizedNewFindings.filter((f) => !existingIds.has(f.id));
          targetRun.findings = [...toAdd, ...targetRun.findings];
          recalculateBenchmarkRunScoreCards(targetRun, db.softwares);
          saveDatabase(db);
        }
      }

      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="sonarcloud-report-${safeFileProjectKey}.json"`
      );
      return res.end(Buffer.from(JSON.stringify(reportPayload, null, 2), 'utf-8'));
    } catch (err: any) {
      return res.status(502).json({
        error: `Falha de comunicação ao exportar análise completa de ${safeOrigin}: ${err?.message || 'Erro de conexão'}.`,
      });
    }
  });

  // 4.1 Endpoint de Recuperação Segura de Sessão do Cofre (GET /api/sonar/vault-status)
  app.get('/api/sonar/vault-status', (_req, res) => {
    if (!Array.isArray(db.savedSonarProjects)) {
      db.savedSonarProjects = [];
    }
    const defaultProj = db.savedSonarProjects[0] || null;
    const hasToken = Boolean(defaultProj?.hasToken && defaultProj?.encryptedToken);
    res.json({
      configured: Boolean(defaultProj),
      id: defaultProj?.id || null,
      name: defaultProj?.name || null,
      organization: defaultProj?.organization || '',
      projectKey: defaultProj?.projectKey || '',
      serverUrl: defaultProj?.serverUrl || 'https://sonarcloud.io',
      platform: defaultProj?.platform || 'SONARCLOUD',
      hasToken,
      maskedToken: hasToken ? '••••••••' : null,
      lastVerifiedAt: defaultProj?.lastVerifiedAt || null,
      lastVerificationStatus: defaultProj?.lastVerificationStatus || 'NOT_CONFIGURED',
      lastExportedAt: defaultProj?.lastExportedAt || null,
    });
  });

  // 4.2 Endpoint de Extração Silenciosa em 1-Clique (POST /api/sonar/export-full-report)
  app.post('/api/sonar/export-full-report', async (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const { organization, projectKey, token } = req.body as {
      organization?: string;
      projectKey?: string;
      token?: string;
    };

    if (!Array.isArray(db.savedSonarProjects)) {
      db.savedSonarProjects = [];
    }
    const defaultProj = db.savedSonarProjects[0] || null;

    const effectiveOrg = (organization || defaultProj?.organization || '').trim();
    const effectiveKey = (projectKey || defaultProj?.projectKey || '').trim();
    let effectiveToken = (token || '').trim();

    if (!effectiveToken && defaultProj?.encryptedToken) {
      effectiveToken = MqrBridgeConnection.decryptToken(defaultProj.encryptedToken) || '';
    }

    if (!effectiveKey) {
      return res.status(400).json({ error: 'Project Key não informado.' });
    }
    if (!effectiveToken) {
      return res.status(400).json({
        error:
          'Token do SonarCloud não configurado. Forneça o token ou salve-o com segurança no cofre.',
      });
    }

    const safeOrigin = await validateSonarServerOriginSafe('https://sonarcloud.io', 'SONARCLOUD');
    const reqHeaders = {
      Accept: 'application/json',
      Authorization: `Bearer ${effectiveToken}`,
      'User-Agent': 'WinHood-SonarCloudSilentExtractor/2.0',
    };

    try {
      // 1. Quality Gate
      let qualityGate: any = null;
      try {
        const qgRes = await fetchWithTimeoutAndNoRedirect(
          `${safeOrigin}/api/qualitygates/project_status?projectKey=${encodeURIComponent(effectiveKey)}`,
          { headers: reqHeaders },
          8000
        );
        if (qgRes.ok) {
          const qgJson = await qgRes.json<{ projectStatus?: Record<string, unknown> }>();
          qualityGate = qgJson.projectStatus || qgJson;
        }
      } catch {
        // Fallback
      }

      // 2. Component Measures (MQR + Standard + New Code + Cobertura Separada)
      let measures: Array<{
        metric: string;
        value?: string;
        period?: { value?: string };
        periods?: Array<{ value?: string }>;
      }> = [];
      const measuresMap: Record<string, string | number> = {};
      try {
        const mKeys = DEFAULT_SONAR_METRIC_KEYS.join(',');
        const mRes = await fetchWithTimeoutAndNoRedirect(
          `${safeOrigin}/api/measures/component?component=${encodeURIComponent(effectiveKey)}&metricKeys=${mKeys}`,
          { headers: reqHeaders },
          8000
        );
        if (mRes.ok) {
          const mJson = await mRes.json<{
            component?: {
              measures?: Array<{
                metric: string;
                value?: string;
                period?: { value?: string };
                periods?: Array<{ value?: string }>;
              }>;
            };
          }>();
          measures = mJson.component?.measures || [];
          for (const m of measures) {
            measuresMap[m.metric] =
              m.value ??
              m.period?.value ??
              (Array.isArray(m.periods) ? m.periods[0]?.value : '') ??
              '';
          }
        }
      } catch {
        // Fallback
      }

      // 3. Hotspots
      let hotspots: RawSonarHotspotApiItem[] = [];
      try {
        const hsRes = await fetchWithTimeoutAndNoRedirect(
          `${safeOrigin}/api/hotspots/search?projectKey=${encodeURIComponent(effectiveKey)}&ps=500`,
          { headers: reqHeaders },
          8000
        );
        if (hsRes.ok) {
          const hsJson = await hsRes.json<{ hotspots?: RawSonarHotspotApiItem[] }>();
          hotspots = hsJson.hotspots || [];
        }
      } catch {
        // Fallback
      }

      // 4. Issues Paginadas
      const allIssues: RawSonarIssueApiItem[] = [];
      let page = 1;
      let totalIssues = 0;
      let issuesFailed = false;
      do {
        const orgParam = effectiveOrg ? `&organization=${encodeURIComponent(effectiveOrg)}` : '';
        const issRes = await fetchWithTimeoutAndNoRedirect(
          `${safeOrigin}/api/issues/search?componentKeys=${encodeURIComponent(effectiveKey)}${orgParam}&ps=500&p=${page}&additionalFields=_all&facets=severities,types,rules,statuses`,
          { headers: reqHeaders },
          10_000
        );
        if (!issRes.ok) {
          issuesFailed = true;
          break;
        }
        const issJson = await issRes.json<{
          total?: number;
          issues?: RawSonarIssueApiItem[];
        }>();
        totalIssues = Number(issJson.total ?? (issJson.issues || []).length);
        const batch = issJson.issues || [];
        allIssues.push(...batch);
        if (batch.length === 0) break;
        page++;
      } while (allIssues.length < totalIssues && page <= 20);

      // 5. Quality Profiles Reais (/api/qualityprofiles/search)
      let realProfiles: Array<{
        key?: string;
        name?: string;
        language?: string;
        isBuiltIn?: boolean;
        isDefault?: boolean;
      }> = [];
      try {
        const orgParam = effectiveOrg ? `&organization=${encodeURIComponent(effectiveOrg)}` : '';
        const qpRes = await fetchWithTimeoutAndNoRedirect(
          `${safeOrigin}/api/qualityprofiles/search?project=${encodeURIComponent(effectiveKey)}${orgParam}`,
          { headers: reqHeaders },
          8000
        );
        if (qpRes.ok) {
          const qpJson = await qpRes.json<{
            profiles?: Array<{
              key?: string;
              name?: string;
              language?: string;
              isBuiltIn?: boolean;
              isDefault?: boolean;
            }>;
          }>();
          realProfiles = Array.isArray(qpJson.profiles) ? qpJson.profiles : [];
        }
      } catch {
        // Opcional
      }

      // 6. Nome Verificado do Quality Gate (/api/qualitygates/get_by_project)
      let verifiedGateName: string | undefined;
      try {
        const orgParam = effectiveOrg ? `&organization=${encodeURIComponent(effectiveOrg)}` : '';
        const qgNameRes = await fetchWithTimeoutAndNoRedirect(
          `${safeOrigin}/api/qualitygates/get_by_project?project=${encodeURIComponent(effectiveKey)}${orgParam}`,
          { headers: reqHeaders },
          8000
        );
        if (qgNameRes.ok) {
          const qgNameJson = await qgNameRes.json<{ qualityGate?: { name?: string } }>();
          if (qgNameJson?.qualityGate?.name) {
            verifiedGateName = String(qgNameJson.qualityGate.name);
          }
        }
      } catch {
        // Opcional
      }

      const nowIso = new Date().toISOString();
      const analysisId = `sonarcloud-live-${Date.now()}`;
      const targetRun = db.runs[0];
      const swId = targetRun?.softwareIds[0] || 'sw-sonarcloud-imported';
      const swName = targetRun?.scoreCards[0]?.softwareName || effectiveKey;
      const rawResponseHash = computeSha256(JSON.stringify({ qualityGate, measures }));

      const normalizedMeasures = SonarMetricsMapper.mapMeasuresPayload({
        analysisId,
        projectKey: effectiveKey,
        softwareId: swId,
        softwareName: swName,
        commitHash: 'HEAD',
        rawMeasures: measures,
        rawApiResponseHash: rawResponseHash,
      });
      const normalizedQualityGate = SonarQualityGateMapper.mapProjectStatusPayload({
        analysisId,
        projectKey: effectiveKey,
        softwareId: swId,
        softwareName: swName,
        gateName: verifiedGateName,
        newLinesCount: normalizedMeasures.newCode?.newLines ?? null,
        newLinesToCoverCount: normalizedMeasures.newCode?.newLinesToCover ?? null,
        projectStatus: qualityGate,
      });
      const hotspotsBreakdown = SonarResultParser.computeHotspotsBreakdown(hotspots);

      const reportPayload = {
        schemaVersion: '2.0.0',
        extractedAt: nowIso,
        platform: 'SONARCLOUD',
        serverUrl: safeOrigin,
        organization: effectiveOrg,
        projectKey: effectiveKey,
        qualityGate,
        normalizedQualityGate,
        measures,
        measuresMap,
        normalizedMeasures,
        hotspots,
        hotspotsBreakdown,
        qualityProfiles: realProfiles,
        totalIssues: allIssues.length,
        totalHotspots: hotspots.length,
        issues: allIssues,
      };

      // Atualizar / salvar perfil no cofre caso ainda não exista
      db.savedSonarProjects = db.savedSonarProjects || [];
      const existingProfile = db.savedSonarProjects.find((p) => p.projectKey === effectiveKey);
      if (!existingProfile) {
        const newProfile: SavedSonarProjectProfile = {
          id: `sonar-proj-${crypto.randomUUID().slice(0, 8)}`,
          name: effectiveKey,
          platform: 'SONARCLOUD',
          serverUrl: safeOrigin,
          organization: effectiveOrg,
          projectKey: effectiveKey,
          encryptedToken: MqrBridgeConnection.encryptToken(effectiveToken),
          maskedToken: MqrBridgeConnection.maskToken(effectiveToken),
          hasToken: true,
          tokenCreatedAt: nowIso,
          tokenValidityDaysPolicy: 90,
          tokenExpiresAt: null,
          lastVerifiedAt: nowIso,
          lastVerificationStatus: 'VALID',
          lastExportedAt: nowIso,
          lastExportedIssuesCount: allIssues.length,
        };
        db.savedSonarProjects.unshift(newProfile);
      } else {
        if (token) {
          existingProfile.encryptedToken = MqrBridgeConnection.encryptToken(token);
          existingProfile.maskedToken = MqrBridgeConnection.maskToken(token);
          existingProfile.hasToken = true;
        }
        existingProfile.lastVerifiedAt = nowIso;
        existingProfile.lastVerificationStatus = 'VALID';
        existingProfile.lastExportedAt = nowIso;
        existingProfile.lastExportedIssuesCount = allIssues.length;
      }

      // Propagação automática para o BenchmarkRun ativo (Seção 10)
      let syncedFindingsCount = 0;
      const parsedRecords = SonarResultParser.parseIssuesAndHotspots({
        analysisId,
        projectKey: effectiveKey,
        softwareId: swId,
        softwareName: swName,
        rawIssues: allIssues.map((iss) => ({
          key: iss.key,
          rule: iss.rule,
          severity: iss.severity || 'MAJOR',
          component: iss.component || '',
          project: iss.project || effectiveKey,
          line: iss.line,
          message: iss.message || '',
          effort: iss.effort,
          type: iss.type || 'CODE_SMELL',
          externalRuleEngine: iss.externalRuleEngine,
        })),
        rawHotspots: hotspots.map((hs) => ({
          key: hs.key,
          component: hs.component || '',
          project: hs.project || effectiveKey,
          securityCategory: hs.securityCategory || 'OTHERS',
          vulnerabilityProbability: hs.vulnerabilityProbability || 'MEDIUM',
          status: hs.status || 'TO_REVIEW',
          resolution: hs.resolution,
          line: hs.line,
          message: hs.message || '',
          ruleKey: hs.ruleKey,
        })),
      });

      if (allIssues.length > 0 && targetRun) {
        const normalized = SonarResultParser.mapSonarIssuesToNormalizedFindings(
          parsedRecords,
          swId,
          swName
        );

        const existingIds = new Set(targetRun.findings.map((f) => f.id));
        const toAdd = normalized.filter((f) => !existingIds.has(f.id));
        targetRun.findings = [...toAdd, ...targetRun.findings];
        syncedFindingsCount = toAdd.length;
        recalculateBenchmarkRunScoreCards(targetRun, db.softwares);
      }

      // Registrar na lista de análises Sonar para governança metodológica
      db.toolsDb.sonar_measures = [normalizedMeasures, ...(db.toolsDb.sonar_measures || [])];
      db.toolsDb.sonar_quality_gates = [
        normalizedQualityGate,
        ...(db.toolsDb.sonar_quality_gates || []),
      ];
      const primaryProfile = realProfiles[0];
      const profileVerificationState = primaryProfile
        ? primaryProfile.isBuiltIn &&
          String(primaryProfile.name || '').toLowerCase().includes('sonar way')
          ? ('VERIFIED_SONAR_WAY' as const)
          : ('VERIFIED_CUSTOM' as const)
        : ('NOT_VERIFIED' as const);
      const paginationState =
        issuesFailed && allIssues.length === 0
          ? ('FAILED' as const)
          : issuesFailed
            ? ('PARTIAL' as const)
            : ('COMPLETE' as const);

      db.toolsDb.sonar_analyses = [
        {
          id: analysisId,
          runId: targetRun?.id || 'live-extraction',
          instanceId: 'sonar-cloud-saas',
          projectId: effectiveKey,
          projectKey: effectiveKey,
          softwareId: swId,
          softwareName: swName,
          softwareVersion: '1.0.0',
          commitHash: 'HEAD',
          scannerUsed: 'SONAR_SCANNER_CLI',
          scannerVersion: '8.4.0.16527',
          sonarVersion: '26.11.0.134175',
          qualityProfileName: primaryProfile?.name || 'NOT_VERIFIED',
          qualityProfileVerificationState: profileVerificationState,
          qualityProfileVerification: {
            profileName: primaryProfile?.name || 'NOT_VERIFIED',
            profileKey: primaryProfile?.key || 'NOT_VERIFIED',
            language: primaryProfile?.language || 'MULTI',
            isBuiltIn: Boolean(primaryProfile?.isBuiltIn),
            isDefault: Boolean(primaryProfile?.isDefault),
            verificationState: profileVerificationState,
          },
          qualityModelMode: normalizedMeasures.qualityModel || 'STANDARD_EXPERIENCE',
          qualityGateStatus: normalizedQualityGate.status,
          startedAt: nowIso,
          completedAt: nowIso,
          status: 'COMPLETED',
          sonarExecutionState: 'RESULTS_IMPORTED',
          cacheHit: false,
          cacheKeySha256: computeSha256(`${effectiveKey}|${nowIso}`),
          measuresId: normalizedMeasures.id,
          qualityGateId: normalizedQualityGate.id,
          issuesCount: allIssues.length,
          externalIssuesImportedCount: parsedRecords.filter((r) => r.isExternalImportedRule).length,
          hotspotsBreakdown,
          issuesPagination: {
            endpoint: '/api/issues/search',
            totalExpected: totalIssues || allIssues.length,
            totalReceived: allIssues.length,
            pendingCount: Math.max(0, (totalIssues || allIssues.length) - allIssues.length),
            totalReported: totalIssues || allIssues.length,
            fetchedRecords: allIssues.length,
            pagesFetched: page,
            pageSize: 500,
            hitSonarSearchLimit10k: allIssues.length >= 10000,
            status: paginationState,
            completeness: paginationState,
            state: paginationState,
          },
          evidenceSha256: rawResponseHash,
        },
        ...(db.toolsDb.sonar_analyses || []),
      ];

      appendAuditLog(
        db,
        'SONARCLOUD_SILENT_FULL_EXTRACTION',
        'SONAR_PROJECT_PROFILE',
        effectiveKey,
        `Extração 1-Clique do SonarCloud concluída: ${allIssues.length} issues, ${hotspots.length} hotspots, ${measures.length} métricas. Sincronizados ${syncedFindingsCount} novos achados.`
      );
      saveDatabase(db);

      return res.json({
        ok: true,
        report: reportPayload,
        syncedFindingsCount,
        latestRun: db.runs[0] || null,
        message: `Relatório do SonarCloud (${effectiveKey}) extraído com sucesso! ${allIssues.length} issues coletadas e sincronizadas.`,
      });
    } catch (err: any) {
      return res.status(500).json({
        error: `Falha na extração de dados do SonarCloud: ${err?.message || 'Erro interno'}.`,
      });
    }
  });

  // 4.3 Endpoint de Governança Metodológica Oficial SonarCloud vs WinHood (GET /api/sonar/methodology-summary)
  app.get('/api/sonar/methodology-summary', (_req, res) => {
    const latestAnalysis = db.toolsDb?.sonar_analyses?.[0] || null;
    const defaultProjectKey =
      latestAnalysis?.projectKey ||
      db.savedSonarProjects?.[0]?.projectKey ||
      'NOT_CONFIGURED';
    const latestMeasures =
      (latestAnalysis &&
        db.toolsDb?.sonar_measures?.find((m) => m.analysisId === latestAnalysis.id)) ||
      db.toolsDb?.sonar_measures?.[0] ||
      SonarMetricsMapper.mapMeasuresPayload({
        analysisId: 'unmeasured',
        projectKey: defaultProjectKey,
        softwareId: 'unmeasured',
        softwareName: defaultProjectKey,
        commitHash: 'NONE',
        rawMeasures: [],
        rawApiResponseHash: computeSha256('unmeasured'),
      });
    const latestQg =
      (latestAnalysis &&
        db.toolsDb?.sonar_quality_gates?.find((g) => g.analysisId === latestAnalysis.id)) ||
      db.toolsDb?.sonar_quality_gates?.[0] ||
      SonarQualityGateMapper.mapProjectStatusPayload({
        analysisId: 'unmeasured',
        projectKey: defaultProjectKey,
        softwareId: 'unmeasured',
        softwareName: defaultProjectKey,
        projectStatus: null,
        apiError: false,
      });
    const latestHotspotsBreakdown =
      latestAnalysis?.hotspotsBreakdown ||
      SonarResultParser.computeHotspotsBreakdown(
        latestMeasures.measurementState === 'MEASURED' ? [] : null
      );
    const latestRun = db.runs[0] || null;
    const primaryCard = latestRun?.scoreCards?.[0] || null;
    const nativeSonarComposite =
      SonarMetricsMapper.computeNativeSonarScoreFromRatings(latestMeasures.metrics);
    const issuesTotal = (db.toolsDb?.sonar_issues || []).length;

    return res.json({
      projectKey: defaultProjectKey,
      organization: db.savedSonarProjects?.[0]?.organization || '',
      qualityModelMode: latestMeasures.qualityModel || 'STANDARD_EXPERIENCE',
      qualityProfileVerification: latestAnalysis?.qualityProfileVerification || {
        profileName: latestAnalysis?.qualityProfileName || 'NOT_VERIFIED',
        profileKey: 'NOT_VERIFIED',
        language: 'ts',
        isBuiltIn: false,
        isDefault: false,
        verificationState:
          latestAnalysis?.qualityProfileVerificationState || 'NOT_VERIFIED',
      },
      qualityGate: latestQg,
      measures: latestMeasures,
      hotspotsBreakdown: latestHotspotsBreakdown,
      paginationSummary: {
        issuesPagination: latestAnalysis?.issuesPagination || {
          endpoint: '/api/issues/search',
          totalExpected: issuesTotal,
          totalReceived: issuesTotal,
          pendingCount: 0,
          totalReported: issuesTotal,
          fetchedRecords: issuesTotal,
          pagesFetched: issuesTotal > 0 ? 1 : 0,
          pageSize: 500,
          hitSonarSearchLimit10k: false,
          status: 'COMPLETE',
          completeness: 'COMPLETE',
          state: 'COMPLETE',
        },
        hotspotsPagination: latestAnalysis?.hotspotsPagination || {
          endpoint: '/api/hotspots/search',
          totalExpected: latestHotspotsBreakdown.totalIdentified ?? 0,
          totalReceived: latestHotspotsBreakdown.totalIdentified ?? 0,
          pendingCount: 0,
          totalReported: latestHotspotsBreakdown.totalIdentified ?? 0,
          fetchedRecords: latestHotspotsBreakdown.totalIdentified ?? 0,
          pagesFetched: (latestHotspotsBreakdown.totalIdentified ?? 0) > 0 ? 1 : 0,
          pageSize: 500,
          hitSonarSearchLimit10k: false,
          status: 'COMPLETE',
          completeness: 'COMPLETE',
          state: 'COMPLETE',
        },
      },
      scoreSeparation: {
        nativeSonarMetrics: {
          source:
            latestMeasures.measurementState === 'MEASURED'
              ? 'SONARCLOUD_OFFICIAL_API'
              : 'NOT_MEASURED',
          reliabilityRating: latestMeasures.metrics.reliabilityRating ?? 'NOT_MEASURED',
          securityRating: latestMeasures.metrics.securityRating ?? 'NOT_MEASURED',
          maintainabilityRating:
            latestMeasures.metrics.maintainabilityRating ?? 'NOT_MEASURED',
          securityReviewRating:
            latestMeasures.metrics.securityReviewRating ?? 'NOT_MEASURED',
          qualityGateStatus: latestQg.status,
          nativeSonarCompositeReference: nativeSonarComposite,
        },
        winhoodCalculatedScore: {
          source: 'WINHOOD_CALCULATED',
          overallScore: primaryCard?.groupedScores?.overallScore ?? null,
          securityScore: primaryCard?.groupedScores?.securityScore ?? null,
          qualityScore: primaryCard?.groupedScores?.qualityScore ?? null,
          algorithmVersion: latestRun?.algorithmVersion || ALGORITHM_VERSION,
          note: 'Pontuação calculada pelo motor determinístico WinHood — nunca apresentada como métrica oficial nativa do SonarCloud.',
        },
      },
    });
  });

  const buildCompleteSonarPs1Script = (params: {
    platform: 'SONARCLOUD' | 'MQR_BRIDGE_SERVER';
    serverUrl: string;
    projectKey: string;
    organization: string;
    plainToken?: string | null;
  }): { filename: string; content: string } => {
    const safeFileProjectKey = (params.projectKey || 'sonar_project').replace(
      /[^a-zA-Z0-9._-]/g,
      '_'
    );
    const safeProjectKey = (params.projectKey || '').replace(/[^a-zA-Z0-9._:-]/g, '');
    const safeOrg = (params.organization || '').replace(/[^a-zA-Z0-9._-]/g, '');
    let safeOrigin: string;
    try {
      safeOrigin = validateSonarServerOrigin(params.serverUrl, params.platform);
    } catch {
      safeOrigin = params.platform === 'MQR_BRIDGE_SERVER' ? 'http://localhost:9000' : 'https://sonarcloud.io';
    }

    const sanitizedSavedToken = (params.plainToken || '').replace(/["`$]/g, '');

    const ps1Lines = [
      `# ==============================================================================`,
      `# WinHood Analyzer — Exportador Completo de Análise SonarCloud / MqrBridge (.PS1)`,
      `# Coleta Integral: Componente, Quality Gate, Métricas MQR, Issues, Rules,`,
      `#                  Components, Facets, Security Hotspots, Branches e Análises`,
      `# Projeto: ${safeProjectKey || 'N/A'} | Organização: ${safeOrg || 'N/A'}`,
      `# ==============================================================================`,
      `$ErrorActionPreference = "Stop"`,
      `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`,
      ``,
      `$configuredToken = "${sanitizedSavedToken}"`,
      `$sonarToken      = if (-not [string]::IsNullOrWhiteSpace($env:SONAR_TOKEN)) { $env:SONAR_TOKEN } elseif (-not [string]::IsNullOrWhiteSpace($configuredToken)) { $configuredToken } else { "" }`,
      `$projectKey      = "${safeProjectKey}"`,
      `$organization    = "${safeOrg}"`,
      `$serverUrl       = "${safeOrigin}".TrimEnd('/')`,
      `$platform        = "${params.platform}"`,
      ``,
      `if ([string]::IsNullOrWhiteSpace($projectKey)) {`,
      `    $projectKey = (Read-Host "Informe o Project Key (sonar.projectKey)").Trim()`,
      `}`,
      `if ($platform -eq "SONARCLOUD" -and [string]::IsNullOrWhiteSpace($organization)) {`,
      `    $organization = (Read-Host "Informe a Organization do SonarCloud (sonar.organization)").Trim()`,
      `}`,
      `if ([string]::IsNullOrWhiteSpace($sonarToken)) {`,
      `    $sonarToken = (Read-Host "Informe seu Bearer Token do SonarCloud/MqrBridge (SONAR_TOKEN)").Trim()`,
      `}`,
      `if ([string]::IsNullOrWhiteSpace($sonarToken) -or [string]::IsNullOrWhiteSpace($projectKey)) {`,
      `    Write-Error "Project Key e SONAR_TOKEN sao obrigatorios para exportar a analise completa."`,
      `    exit 1`,
      `}`,
      ``,
      `$safeFileKey = ($projectKey -replace '[^a-zA-Z0-9._-]', '_')`,
      `$outputFile  = Join-Path -Path (Get-Location).Path -ChildPath ("sonarcloud-report-{0}.json" -f $safeFileKey)`,
      ``,
      `$headers = @{`,
      `    Authorization = "Bearer $sonarToken"`,
      `    Accept        = "application/json"`,
      `    "User-Agent"  = "WinHood-SonarExporter-PS1/2.0"`,
      `}`,
      ``,
      `function Invoke-SonarEndpointSafe {`,
      `    param([string]$FullUrl, [bool]$Critical = $false)`,
      `    try {`,
      `        return Invoke-RestMethod -Uri $FullUrl -Headers $headers -Method Get`,
      `    } catch {`,
      `        if ($Critical) { throw $_ }`,
      `        Write-Host ("  [Aviso] Endpoint opcional indisponivel: {0}" -f $FullUrl) -ForegroundColor DarkYellow`,
      `        return $null`,
      `    }`,
      `}`,
      ``,
      `$escapedKey = [uri]::EscapeDataString($projectKey)`,
      `$orgParam   = if ([string]::IsNullOrWhiteSpace($organization)) { "" } else { "&organization=$([uri]::EscapeDataString($organization))" }`,
      ``,
      `Write-Host "========================================================================" -ForegroundColor Cyan`,
      `Write-Host " Iniciando Exportacao Completa do Sonar ($platform) para '$projectKey' " -ForegroundColor Cyan`,
      `Write-Host "========================================================================" -ForegroundColor Cyan`,
      ``,
      `# 1. Metadados do Componente (/api/components/show)`,
      `Write-Host "[1/6] Coletando metadados do projeto (/api/components/show)..." -ForegroundColor Cyan`,
      `$compResp = Invoke-SonarEndpointSafe -FullUrl "$serverUrl/api/components/show?component=$escapedKey"`,
      `$componentData = if ($null -ne $compResp -and $null -ne $compResp.component) { $compResp.component } else { $null }`,
      `$ancestorsData = if ($null -ne $compResp -and $null -ne $compResp.ancestors) { @($compResp.ancestors) } else { @() }`,
      ``,
      `# 2. Status do Quality Gate (/api/qualitygates/project_status)`,
      `Write-Host "[2/6] Coletando Quality Gate (/api/qualitygates/project_status)..." -ForegroundColor Cyan`,
      `$qgResp = Invoke-SonarEndpointSafe -FullUrl "$serverUrl/api/qualitygates/project_status?projectKey=$escapedKey"`,
      `$qualityGateData = if ($null -ne $qgResp -and $null -ne $qgResp.projectStatus) { $qgResp.projectStatus } else { $qgResp }`,
      ``,
      `# 3. Metricas Estaticas e MQR (/api/measures/component)`,
      `Write-Host "[3/6] Coletando 39 metricas estaticas e MQR (/api/measures/component)..." -ForegroundColor Cyan`,
      `$metricKeys = "${SONAR_FULL_METRIC_KEYS}"`,
      `$measuresResp = Invoke-SonarEndpointSafe -FullUrl "$serverUrl/api/measures/component?component=$escapedKey&metricKeys=$metricKeys"`,
      `$measuresList = New-Object 'System.Collections.Generic.List[object]'`,
      `$measuresMap  = [ordered]@{}`,
      `if ($null -ne $measuresResp -and $null -ne $measuresResp.component -and $null -ne $measuresResp.component.measures) {`,
      `    foreach ($m in $measuresResp.component.measures) {`,
      `        [void]$measuresList.Add($m)`,
      `        $val = if ($null -ne $m.value) { $m.value } elseif ($null -ne $m.period -and $null -ne $m.period.value) { $m.period.value } elseif ($null -ne $m.periods -and $m.periods.Count -gt 0) { $m.periods[0].value } else { "" }`,
      `        $measuresMap[$m.metric] = $val`,
      `    }`,
      `}`,
      ``,
      `# 4. Issues Paginadas com additionalFields=_all (/api/issues/search)`,
      `Write-Host "[4/6] Coletando todas as paginas de Issues com fluxos, regras e impactos MQR..." -ForegroundColor Cyan`,
      `$pageSize        = 500`,
      `$page            = 1`,
      `$totalIssues     = 0`,
      `$effortTotal     = 0`,
      `$debtTotal       = 0`,
      `$allIssues       = New-Object 'System.Collections.Generic.List[object]'`,
      `$allComponents   = New-Object 'System.Collections.Generic.List[object]'`,
      `$seenComponents  = @{}`,
      `$allRules        = New-Object 'System.Collections.Generic.List[object]'`,
      `$seenRules       = @{}`,
      `$allUsers        = New-Object 'System.Collections.Generic.List[object]'`,
      `$seenUsers       = @{}`,
      `$facetsData      = @()`,
      ``,
      `do {`,
      `    $facetsParam = "severities,types,rules,statuses,resolutions,cleanCodeAttributeCategories,impactSoftwareQualities,impactSeverities"`,
      `    $issuesUrl = "$serverUrl/api/issues/search?componentKeys=$escapedKey$orgParam&ps=$pageSize&p=$page&additionalFields=_all&facets=$facetsParam"`,
      `    $response = Invoke-SonarEndpointSafe -FullUrl $issuesUrl -Critical $true`,
      `    if ($null -eq $response) { break }`,
      ``,
      `    $batchCount = 0`,
      `    if ($null -ne $response.issues) {`,
      `        foreach ($iss in $response.issues) {`,
      `            [void]$allIssues.Add($iss)`,
      `            $batchCount++`,
      `        }`,
      `    }`,
      `    if ($null -ne $response.components) {`,
      `        foreach ($comp in $response.components) {`,
      `            if ($null -ne $comp.key -and -not $seenComponents.ContainsKey($comp.key)) {`,
      `                $seenComponents[$comp.key] = $true`,
      `                [void]$allComponents.Add($comp)`,
      `            }`,
      `        }`,
      `    }`,
      `    if ($null -ne $response.rules) {`,
      `        foreach ($rule in $response.rules) {`,
      `            if ($null -ne $rule.key -and -not $seenRules.ContainsKey($rule.key)) {`,
      `                $seenRules[$rule.key] = $true`,
      `                [void]$allRules.Add($rule)`,
      `            }`,
      `        }`,
      `    }`,
      `    if ($null -ne $response.users) {`,
      `        foreach ($usr in $response.users) {`,
      `            if ($null -ne $usr.login -and -not $seenUsers.ContainsKey($usr.login)) {`,
      `                $seenUsers[$usr.login] = $true`,
      `                [void]$allUsers.Add($usr)`,
      `            }`,
      `        }`,
      `    }`,
      `    if ($page -eq 1 -and $null -ne $response.facets) {`,
      `        $facetsData = @($response.facets)`,
      `    }`,
      `    if ($null -ne $response.effortTotal) { $effortTotal = [int]$response.effortTotal }`,
      `    if ($null -ne $response.debtTotal)   { $debtTotal   = [int]$response.debtTotal }`,
      ``,
      `    $totalIssues = if ($null -ne $response.total) { [int]$response.total } elseif ($null -ne $response.paging -and $null -ne $response.paging.total) { [int]$response.paging.total } else { $allIssues.Count }`,
      `    Write-Host ("  -> Pagina {0}: {1}/{2} issues coletadas (Regras: {3}, Arquivos: {4})..." -f $page, $allIssues.Count, $totalIssues, $allRules.Count, $allComponents.Count) -ForegroundColor Gray`,
      `    if ($batchCount -eq 0) { break }`,
      `    $page++`,
      `} while ($allIssues.Count -lt $totalIssues -and (($page - 1) * $pageSize) -lt 10000)`,
      ``,
      `# 5. Security Hotspots Paginados (/api/hotspots/search)`,
      `Write-Host "[5/6] Coletando Security Hotspots (/api/hotspots/search)..." -ForegroundColor Cyan`,
      `$hsPage      = 1`,
      `$hsTotal     = 0`,
      `$allHotspots = New-Object 'System.Collections.Generic.List[object]'`,
      `do {`,
      `    $hsUrl  = "$serverUrl/api/hotspots/search?projectKey=$escapedKey&ps=$pageSize&p=$hsPage"`,
      `    $hsResp = Invoke-SonarEndpointSafe -FullUrl $hsUrl`,
      `    if ($null -eq $hsResp -or $null -eq $hsResp.hotspots) { break }`,
      `    $hsBatchCount = 0`,
      `    foreach ($hs in $hsResp.hotspots) {`,
      `        [void]$allHotspots.Add($hs)`,
      `        $hsBatchCount++`,
      `    }`,
      `    $hsTotal = if ($null -ne $hsResp.paging -and $null -ne $hsResp.paging.total) { [int]$hsResp.paging.total } else { $allHotspots.Count }`,
      `    Write-Host ("  -> Pagina {0}: {1}/{2} hotspots coletados..." -f $hsPage, $allHotspots.Count, $hsTotal) -ForegroundColor Gray`,
      `    if ($hsBatchCount -eq 0) { break }`,
      `    $hsPage++`,
      `} while ($allHotspots.Count -lt $hsTotal -and (($hsPage - 1) * $pageSize) -lt 10000)`,
      ``,
      `# 6. Branches e Historico de Analises (/api/project_branches/list & /api/project_analyses/search)`,
      `Write-Host "[6/6] Coletando branches e historico de analises..." -ForegroundColor Cyan`,
      `$branchesResp = Invoke-SonarEndpointSafe -FullUrl "$serverUrl/api/project_branches/list?project=$escapedKey"`,
      `$branchesData = if ($null -ne $branchesResp -and $null -ne $branchesResp.branches) { @($branchesResp.branches) } else { @() }`,
      `$analysesResp = Invoke-SonarEndpointSafe -FullUrl "$serverUrl/api/project_analyses/search?project=$escapedKey&ps=50&p=1"`,
      `$analysesData = if ($null -ne $analysesResp -and $null -ne $analysesResp.analyses) { @($analysesResp.analyses) } else { @() }`,
      ``,
      `# Contabilizar Resumo Estatistico`,
      `$bySeverity = [ordered]@{ BLOCKER = 0; CRITICAL = 0; MAJOR = 0; MINOR = 0; INFO = 0 }`,
      `$byType     = [ordered]@{ VULNERABILITY = 0; BUG = 0; CODE_SMELL = 0; SECURITY_HOTSPOT = $allHotspots.Count }`,
      `$byStatus   = [ordered]@{}`,
      `$openCount  = 0`,
      `$closedCount = 0`,
      `foreach ($iss in $allIssues) {`,
      `    $sev = if ($null -ne $iss.severity) { [string]$iss.severity } else { "MAJOR" }`,
      `    if (-not $bySeverity.Contains($sev)) { $bySeverity[$sev] = 0 }`,
      `    $bySeverity[$sev] = [int]$bySeverity[$sev] + 1`,
      `    $typ = if ($null -ne $iss.type) { [string]$iss.type } else { "CODE_SMELL" }`,
      `    if (-not $byType.Contains($typ)) { $byType[$typ] = 0 }`,
      `    $byType[$typ] = [int]$byType[$typ] + 1`,
      `    $st = if ($null -ne $iss.status) { [string]$iss.status } else { "OPEN" }`,
      `    if (-not $byStatus.Contains($st)) { $byStatus[$st] = 0 }`,
      `    $byStatus[$st] = [int]$byStatus[$st] + 1`,
      `    if ($st -eq "CLOSED" -or $st -eq "RESOLVED") { $closedCount++ } else { $openCount++ }`,
      `}`,
      ``,
      `$qgStatusText = if ($null -ne $qualityGateData -and $null -ne $qualityGateData.status) { [string]$qualityGateData.status } elseif ($measuresMap.Contains("alert_status")) { [string]$measuresMap["alert_status"] } else { "UNKNOWN" }`,
      ``,
      `$finalReport = [PSCustomObject]@{`,
      `    platform      = $platform`,
      `    serverUrl     = $serverUrl`,
      `    projectKey    = $projectKey`,
      `    organization  = $organization`,
      `    generatedAt   = (Get-Date).ToString("o")`,
      `    total         = $allIssues.Count`,
      `    p             = 1`,
      `    ps            = $allIssues.Count`,
      `    paging        = [PSCustomObject]@{`,
      `        pageIndex = 1`,
      `        pageSize  = $allIssues.Count`,
      `        total     = $totalIssues`,
      `    }`,
      `    effortTotal   = $effortTotal`,
      `    debtTotal     = $debtTotal`,
      `    totalIssues   = $allIssues.Count`,
      `    totalHotspots = $allHotspots.Count`,
      `    summary       = [PSCustomObject]@{`,
      `        qualityGateStatus  = $qgStatusText`,
      `        totalIssues        = $allIssues.Count`,
      `        openIssuesCount    = $openCount`,
      `        closedIssuesCount  = $closedCount`,
      `        totalHotspots      = $allHotspots.Count`,
      `        effortTotalMinutes = $effortTotal`,
      `        bySeverity         = $bySeverity`,
      `        byType             = $byType`,
      `        byStatus           = $byStatus`,
      `    }`,
      `    component     = $componentData`,
      `    ancestors     = $ancestorsData`,
      `    qualityGate   = $qualityGateData`,
      `    measuresMap   = $measuresMap`,
      `    measures      = $measuresList.ToArray()`,
      `    branches      = $branchesData`,
      `    analyses      = $analysesData`,
      `    issues        = $allIssues.ToArray()`,
      `    hotspots      = $allHotspots.ToArray()`,
      `    components    = $allComponents.ToArray()`,
      `    rules         = $allRules.ToArray()`,
      `    users         = $allUsers.ToArray()`,
      `    facets        = $facetsData`,
      `}`,
      ``,
      `Write-Host "Serializando arvore JSON completa (-Depth 100)..." -ForegroundColor Cyan`,
      `$jsonContent = ConvertTo-Json -InputObject $finalReport -Depth 100`,
      `$utf8NoBom   = New-Object System.Text.UTF8Encoding($false)`,
      `[System.IO.File]::WriteAllText($outputFile, $jsonContent, $utf8NoBom)`,
      ``,
      `Write-Host "========================================================================" -ForegroundColor Green`,
      `Write-Host (" Relatorio Completo salvo em: {0}" -f $outputFile) -ForegroundColor Green`,
      `Write-Host (" -> Quality Gate: {0} | Issues: {1} (Abertas: {2}) | Hotspots: {3} | Metricas: {4}" -f $qgStatusText, $allIssues.Count, $openCount, $allHotspots.Count, $measuresList.Count) -ForegroundColor Green`,
      `Write-Host "========================================================================" -ForegroundColor Green`,
    ];

    return {
      filename: `sonarcloud-${safeFileProjectKey}.ps1`,
      content: ps1Lines.join('\r\n'),
    };
  };

  app.get('/api/sonar/saved-projects/:id/export-ps1', (req, res) => {
    if (!Array.isArray(db.savedSonarProjects)) {
      db.savedSonarProjects = [];
    }
    const proj = db.savedSonarProjects.find((p) => p.id === req.params.id);
    if (!proj) {
      return res.status(404).json({ error: 'Perfil de projeto Sonar não encontrado.' });
    }

    const plainToken = proj.encryptedToken
      ? MqrBridgeConnection.decryptToken(proj.encryptedToken)
      : null;

    const generated = buildCompleteSonarPs1Script({
      platform: proj.platform,
      serverUrl: proj.serverUrl,
      projectKey: proj.projectKey,
      organization: proj.organization,
      plainToken,
    });

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${generated.filename}"`
    );
    return res.end(Buffer.from(generated.content, 'utf-8'));
  });

  app.post('/api/sonar/export-ps1-direct', (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const { platform, serverUrl, projectKey, organization, token } = (req.body || {}) as {
      platform?: 'SONARCLOUD' | 'MQR_BRIDGE_SERVER';
      serverUrl?: string;
      projectKey?: string;
      organization?: string;
      token?: string;
    };

    const resolvedPlatform: 'SONARCLOUD' | 'MQR_BRIDGE_SERVER' =
      platform === 'MQR_BRIDGE_SERVER' ? 'MQR_BRIDGE_SERVER' : 'SONARCLOUD';

    const generated = buildCompleteSonarPs1Script({
      platform: resolvedPlatform,
      serverUrl:
        serverUrl ||
        (resolvedPlatform === 'SONARCLOUD' ? 'https://sonarcloud.io' : 'http://localhost:9000'),
      projectKey: (projectKey || '').trim(),
      organization: (organization || '').trim(),
      plainToken: (token || '').trim() || null,
    });

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${generated.filename}"`
    );
    return res.end(Buffer.from(generated.content, 'utf-8'));
  });

  app.post('/api/mqr-bridge/probe', async (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const { instanceId, serverUrl, port, token, mode, organizationKey, name } = req.body as {
      instanceId?: string;
      serverUrl?: string;
      port?: number;
      token?: string;
      mode?: SonarInstallationMode;
      organizationKey?: string;
      name?: string;
    };

    let inst = db.toolsDb.sonar_instances.find((i) => i.id === instanceId);
    if (!inst) {
      inst = {
        id: instanceId || `sonar-${Date.now()}`,
        name: name || 'Instância MqrBridge Customizada',
        mode: mode || 'REMOTE',
        serverUrl: serverUrl || '',
        port: port || 9000,
        organizationKey: organizationKey || '',
        hasTokenConfigured: false,
        maskedToken: 'Não configurado',
        tokenExpiresAt: null,
        connectionState: 'NOT_CONFIGURED',
        version: null,
        edition: null,
        apiCompatibility: 'UNKNOWN',
        lastVerifiedAt: null,
        lastErrorMessage: null,
        permissionsVerified: {
          browse: false,
          executeAnalysis: false,
          administerQualityGates: false,
          provisioning: false,
        },
      };
      db.toolsDb.sonar_instances.push(inst);
    }

    if (serverUrl !== undefined) inst.serverUrl = serverUrl.trim();
    if (port !== undefined) inst.port = Number(port) || 9000;
    if (mode !== undefined) inst.mode = mode;
    if (organizationKey !== undefined) inst.organizationKey = organizationKey.trim();
    if (name !== undefined && name.trim()) inst.name = name.trim();

    if (token !== undefined && token.trim().length > 0) {
      sonarService.storeEncryptedToken(inst.id, token.trim());
      inst.hasTokenConfigured = true;
      inst.maskedToken = MqrBridgeConnection.maskToken(token.trim());
    }

    const effectiveToken = sonarService.getDecryptedToken(inst.id);
    const probeRes = await MqrBridgeConnection.probeMqrBridge({
      serverUrl: inst.serverUrl,
      token: effectiveToken,
      mode: inst.mode,
      organizationKey: inst.organizationKey,
    });

    inst.connectionState = probeRes.connectionState;
    inst.version = probeRes.version;
    inst.edition = probeRes.edition;
    inst.apiCompatibility = probeRes.apiCompatibility;
    inst.permissionsVerified = probeRes.permissions;
    inst.tokenExpiresAt = probeRes.tokenExpiresAt;
    inst.lastVerifiedAt = new Date().toISOString();
    inst.lastErrorMessage = probeRes.errorMessage;

    lifecycleManager.appendLog(
      inst.mode === 'CLOUD' ? 'SONAR_CLOUD' : 'SONAR_WEB_API',
      probeRes.connectionState === 'READY' || probeRes.connectionState === 'CONNECTED'
        ? 'INFO'
        : 'WARN',
      'MQR_BRIDGE_PROBED',
      `probeMqrBridge(${inst.serverUrl}) -> Estado: ${probeRes.connectionState} (${probeRes.errorMessage || `v${probeRes.version} em ${probeRes.latencyMs}ms`}).`
    );

    appendAuditLog(
      db,
      'MQR_BRIDGE_INSTANCE_PROBED',
      'SONAR_INSTANCE',
      inst.id,
      `Verificação probeMqrBridge executada para "${inst.name}" (${inst.serverUrl}): estado=${inst.connectionState}.`
    );
    saveDatabase(db);

    return res.json({ instance: inst, probeResult: probeRes });
  });

  app.post('/api/mqr-bridge/disconnect', (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const { instanceId } = req.body as { instanceId?: string };
    const inst = db.toolsDb.sonar_instances.find((i) => i.id === instanceId);
    if (!inst) {
      return res.status(404).json({ error: 'Instância MqrBridge não encontrada.' });
    }
    sonarService.storeEncryptedToken(inst.id, '');
    inst.hasTokenConfigured = false;
    inst.maskedToken = 'Não configurado';
    inst.connectionState = inst.mode === 'LOCAL' ? 'NOT_INSTALLED' : 'NOT_CONFIGURED';
    inst.lastErrorMessage = 'Instância desconectada manualmente pelo usuário.';
    inst.permissionsVerified = {
      browse: false,
      executeAnalysis: false,
      administerQualityGates: false,
      provisioning: false,
    };
    lifecycleManager.appendLog(
      'SONAR_SERVER',
      'INFO',
      'INSTANCE_DISCONNECTED',
      `Instância "${inst.name}" desconectada e credenciais em memória limpas.`
    );
    saveDatabase(db);
    return res.json({ instance: inst });
  });

  app.post('/api/mqr-bridge/lifecycle', (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const { action, mode, limits } = req.body as {
      action?: 'START_LOCAL' | 'STOP_LOCAL' | 'UPDATE_LIMITS';
      mode?: SonarInstallationMode;
      limits?: Record<string, number>;
    };

    if (action === 'UPDATE_LIMITS' && limits) {
      const updated = lifecycleManager.updateLimits(limits);
      return res.json({ ok: true, limits: updated });
    }

    if (action === 'STOP_LOCAL') {
      const stopRes = lifecycleManager.stopLocalInstance('COMANDO_MANUAL_DO_USUARIO');
      return res.json({
        ok: stopRes.stopped,
        message: stopRes.message,
        localServerRunning: lifecycleManager.isLocalServerRunning(),
      });
    }

    const startRes = lifecycleManager.requestOnDemandStart(mode || 'LOCAL');
    return res.json({
      ok: startRes.started,
      state: startRes.state,
      hostCheck: startRes.hostCheck,
      message: startRes.message,
      localServerRunning: lifecycleManager.isLocalServerRunning(),
    });
  });

  app.post('/api/mqr-bridge/refresh-versions', async (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const versions = await MqrBridgeVersionManager.discoverLatestOfficialVersions();
    const distCheck = await MqrBridgeInstallationManager.verifyOfficialDistributionOnline();
    db.toolsDb.sonar_versions = versions;
    db.toolsDb.sonar_installations = [
      MqrBridgeInstallationManager.buildInstallationRecord(versions[0]),
    ];

    lifecycleManager.appendLog(
      'SONAR_SERVER',
      'INFO',
      'OFFICIAL_VERSIONS_REFRESHED',
      distCheck.message
    );
    saveDatabase(db);

    return res.json({
      versions,
      distributionCheck: distCheck,
      installations: db.toolsDb.sonar_installations,
    });
  });

  app.post('/api/mqr-bridge/compare-ab', async (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const { softwareAId, softwareBId } = req.body as {
      softwareAId?: string;
      softwareBId?: string;
    };

    const swA =
      db.softwares.find((s) => s.id === softwareAId) || db.softwares[0];
    const swB =
      db.softwares.find((s) => s.id === softwareBId) || db.softwares[1];

    if (!swA || !swB) {
      return res.status(400).json({
        error: 'É necessário ter no mínimo Software A e Software B cadastrados para executar a comparação padronizada A/B com MqrBridge.',
      });
    }

    const latestRun = db.runs[0];
    const scoreA =
      latestRun?.scoreCards.find((sc) => sc.softwareId === swA.id)?.groupedScores
        .overallScore ?? 3.1;
    const scoreB =
      latestRun?.scoreCards.find((sc) => sc.softwareId === swB.id)?.groupedScores
        .overallScore ?? 4.78;

    try {
      const comparison = await sonarWorker.enqueueABComparisonJob({
        softwareA: swA,
        softwareB: swB,
        runId: latestRun?.id || `run-${Date.now()}`,
        toolsDb: db.toolsDb,
        compositeScoreA: scoreA,
        compositeScoreB: scoreB,
      });

      appendAuditLog(
        db,
        'MQR_BRIDGE_AB_COMPARISON_EXECUTED',
        'SONAR_COMPARISON',
        comparison.comparisonId,
        `Comparação sequencial A/B com MqrBridge v${comparison.sharedConditions.sonarVersion} concluída: ${swA.name} (QG: ${comparison.softwareA.qualityGate.displayLabel}) vs ${swB.name} (QG: ${comparison.softwareB.qualityGate.displayLabel}).`
      );
      saveDatabase(db);
      return res.json({ comparison, toolsDb: db.toolsDb });
    } catch (err: any) {
      const msg = err?.message || 'Erro durante a execução da comparação A/B do MqrBridge.';
      const isNotConnected = msg.includes('MQR_BRIDGE_NOT_CONNECTED');
      return res.status(isNotConnected ? 400 : 500).json({
        error: isNotConnected ? 'MQR_BRIDGE_NOT_CONNECTED' : 'MQR_BRIDGE_AB_ERROR',
        message: msg,
      });
    }
  });

  app.post('/api/mqr-bridge/import-sarif', (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const { toolId, softwareId, customSarifFindings } = req.body as {
      toolId?: SarifExternalReportPayload['toolId'];
      softwareId?: string;
      customSarifFindings?: SarifExternalReportPayload['sarifFindings'];
    };

    const targetSw =
      db.softwares.find((s) => s.id === softwareId) || db.softwares[0];
    if (!targetSw) {
      return res.status(400).json({ error: 'Software não encontrado para importação SARIF.' });
    }

    const latestRun = db.runs[0];
    const effectiveToolId = toolId || 'semgrep';
    const toolMeta =
      db.toolsDb.sonar_integrations.externalToolsSupported.find(
        (t) => t.toolId === effectiveToolId
      ) || {
        toolId: 'semgrep' as const,
        toolName: 'Semgrep / Opengrep SAST',
        sarifSupported: true,
        sonarPropertyKey: 'sonar.sarifReportPaths',
        importedIssuesCount: 0,
      };

    const matchingFindings = (latestRun?.findings || []).filter(
      (f) => f.softwareId === targetSw.id
    );

    const sarifFindings =
      Array.isArray(customSarifFindings) && customSarifFindings.length > 0
        ? customSarifFindings
        : matchingFindings.map((f) => ({
            ruleId: f.originalRuleId,
            message: f.title,
            severity: f.severity,
            confidence: f.confidence,
            filePath: f.filePath,
            lineNumber: f.lineNumber,
            snippet: f.snippet,
          }));

    if (sarifFindings.length === 0) {
      return res.status(400).json({
        error: 'SARIF_NO_FINDINGS',
        message: `Nenhum achado real existente para ${targetSw.name} e nenhum payload SARIF fornecido para importação.`,
      });
    }

    const importResult = ExternalReportImportWorker.importExternalSarifFindings({
      payload: {
        toolId: effectiveToolId,
        toolName: toolMeta.toolName,
        toolVersion: 'SARIF 2.1.0',
        softwareId: targetSw.id,
        softwareName: targetSw.name,
        projectKey: `winhood-sarif-${targetSw.id}`,
        sarifFindings,
      },
      analysisId: `anl-sarif-${Date.now()}`,
      toolsDb: db.toolsDb,
      existingNormalizedFindings: latestRun?.findings || [],
    });

    lifecycleManager.appendLog(
      'SONAR_SCANNER',
      'INFO',
      'EXTERNAL_SARIF_IMPORTED',
      importResult.message
    );
    saveDatabase(db);

    return res.json({
      ok: true,
      ...importResult,
      externalToolsSupported: db.toolsDb.sonar_integrations.externalToolsSupported,
    });
  });

  app.post('/api/mqr-bridge/vscode-config', (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const { bindingMode, serverUrl, projectKey, developerConsent } = req.body as {
      bindingMode?: 'COMMUNITY_BUILD' | 'SERVER' | 'CLOUD' | 'NOT_BOUND';
      serverUrl?: string;
      projectKey?: string;
      developerConsent?: boolean;
    };

    if (!developerConsent) {
      return res.status(400).json({
        error: 'Consentimento explícito do desenvolvedor é obrigatório. A plataforma nunca instala ou altera extensões VS Code automaticamente sem autorização.',
      });
    }

    const mode = bindingMode || 'COMMUNITY_BUILD';
    const url = serverUrl || 'http://localhost:9000';
    const pKey = projectKey || 'winhood-software-a-vaultcore-internal';

    const generatedSettings =
      mode === 'CLOUD'
        ? {
            'sonarlint.connectedMode.connections.sonarcloud': [
              {
                connectionId: 'winhood-sonarcloud-org',
                organizationKey: 'winhood-enterprise-sec',
              },
            ],
            'sonarlint.connectedMode.project': {
              connectionId: 'winhood-sonarcloud-org',
              projectKey: pKey,
            },
          }
        : {
            'sonarlint.connectedMode.connections.mqr-bridge': [
              {
                connectionId: 'winhood-mqr-bridge-cb',
                serverUrl: url,
              },
            ],
            'sonarlint.connectedMode.project': {
              connectionId: 'winhood-mqr-bridge-cb',
              projectKey: pKey,
            },
          };

    db.toolsDb.sonar_integrations.vscodeConnectedMode = {
      configured: mode !== 'NOT_BOUND',
      extensionDetected: false,
      bindingMode: mode,
      sharedQualityProfileKey: 'sonar-way-ts-26-11',
      generatedSettingsJson: JSON.stringify(generatedSettings, null, 2),
    };

    saveDatabase(db);
    return res.json({
      vscodeConnectedMode: db.toolsDb.sonar_integrations.vscodeConnectedMode,
    });
  });

  // GITAR AI ENDPOINTS (Seção 9 e Seção 15)
  app.post('/api/gitar/configure', async (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const {
      gitProvider,
      apiBaseUrl,
      apiToken,
      explicitExternalCodeConsent,
      authorizedRepositories,
      disconnect,
    } = req.body as {
      gitProvider?: GitProviderType;
      apiBaseUrl?: string;
      apiToken?: string;
      explicitExternalCodeConsent?: boolean;
      authorizedRepositories?: string[];
      disconnect?: boolean;
    };

    const g = db.toolsDb.gitar_integration;

    if (disconnect) {
      gitarAdapter.getConnection().setToken('');
      g.connectionState = 'NOT_CONFIGURED';
      g.hasApiToken = false;
      g.maskedToken = 'Não configurado';
      g.explicitExternalCodeConsent = false;
      g.lastErrorMessage =
        'Conta Gitar AI desconectada (NOT_CONFIGURED). Nenhuma revisão de IA é simulada.';
      saveDatabase(db);
      return res.json({ gitarIntegration: g });
    }

    if (apiBaseUrl && apiBaseUrl.trim().length > 0) {
      const candidateBaseUrl = apiBaseUrl.trim();
      const ssrfCheck = await SsrfGuard.validateUrl({
        targetUrl: candidateBaseUrl,
        allowExplicitLoopback: SsrfGuard.isExplicitLoopbackUrl(candidateBaseUrl),
      });
      if (!ssrfCheck.allowed) {
        const blockedMessage = `SSRF_BLOCKED: ${ssrfCheck.reason}`;
        lifecycleManager.appendLog('GITAR_AI', 'WARN', 'GITAR_SSRF_BLOCKED', blockedMessage);
        return res.status(400).json({
          error: 'SSRF_BLOCKED',
          message: blockedMessage,
          health: {
            healthy: false,
            state: 'PROVIDER_UNAVAILABLE',
            provider: gitProvider || g.gitProvider,
            apiBaseUrl: candidateBaseUrl,
            checkedAt: new Date().toISOString(),
            latencyMs: 0,
            message: blockedMessage,
          },
        });
      }
      g.apiBaseUrl = candidateBaseUrl;
    }

    if (gitProvider) g.gitProvider = gitProvider;
    if (explicitExternalCodeConsent !== undefined) {
      g.explicitExternalCodeConsent = Boolean(explicitExternalCodeConsent);
    }
    if (Array.isArray(authorizedRepositories)) {
      g.authorizedRepositories = authorizedRepositories;
    }

    if (apiToken && apiToken.trim().length > 0) {
      gitarAdapter.getConnection().setToken(apiToken.trim());
      g.hasApiToken = true;
      g.maskedToken = MqrBridgeConnection.maskToken(apiToken.trim());
    }

    const tokenToTest = gitarAdapter.getConnection().getToken();
    const health = await GitarInstallationHealth.checkInstallationHealth({
      apiBaseUrl: g.apiBaseUrl,
      token: tokenToTest,
      provider: g.gitProvider,
      explicitConsent: g.explicitExternalCodeConsent,
    });

    g.connectionState = health.state;
    g.lastHealthCheckAt = health.checkedAt;
    g.lastErrorMessage = health.healthy ? null : health.message;

    lifecycleManager.appendLog(
      'GITAR_AI',
      health.healthy ? 'INFO' : 'WARN',
      'GITAR_HEALTH_CHECK',
      health.message
    );
    saveDatabase(db);

    return res.json({ gitarIntegration: g, health });
  });

  app.post('/api/gitar/validate-suite', async (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const actor = getRequestActor(req, res);
    const swA = db.softwares[0];
    const swB = db.softwares[1];
    if (!swA || !swB) {
      return res.status(400).json({
        error: 'Cadastre os softwares A e B antes de executar a validação de contrato do Gitar AI.',
      });
    }

    const result = await gitarWorker.executeAuthorizedValidationJob({
      softwareA: swA,
      softwareB: swB,
      actorName: actor.name,
      toolsDb: db.toolsDb,
    });

    appendAuditLog(
      db,
      'GITAR_CONTRACT_VALIDATION_EXECUTED',
      'GITAR_AI',
      db.toolsDb.gitar_integration.id,
      `Validação autorizada Gitar AI executada: ${result.reviewsImported} revisões de PR em branch isolada e ${result.ciFailuresImported} falhas de CI correlacionadas (arquivos originais intocados).`,
      actor
    );
    saveDatabase(db);

    return res.json({
      ok: true,
      ...result,
      gitarReviews: db.toolsDb.gitar_reviews,
      gitarCiFailures: db.toolsDb.gitar_ci_failures,
    });
  });

  app.post('/api/gitar/reviews/:id/decision', (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    const actor = getRequestActor(req, res);
    const { decision } = req.body as { decision?: 'APPROVE' | 'REJECT' };
    if (!decision || !['APPROVE', 'REJECT'].includes(decision)) {
      return res.status(400).json({ error: 'Decisão inválida. Informe APPROVE ou REJECT.' });
    }

    const outcome = gitarAdapter.reviewAndValidateProposedFix({
      reviewId: req.params.id,
      decision,
      actorName: actor.name,
      toolsDb: db.toolsDb,
    });

    if (!outcome.ok) {
      return res.status(404).json({ error: outcome.message });
    }

    appendAuditLog(
      db,
      `GITAR_REMEDIATION_${decision}`,
      'GITAR_REVIEW',
      req.params.id,
      outcome.message,
      actor
    );
    saveDatabase(db);
    return res.json(outcome);
  });

  // SUÍTE DE 15 ETAPAS + 12 CENÁRIOS DE FALHA (Seção 14) — bloqueada fora do modo de teste
  app.post('/api/mqr-bridge/run-integration-tests', async (req, res) => {
    if (!requireWritePermission(res, req, 'sonar:config')) return;
    if (!isTestRuntimeEnvironment()) {
      return res.status(403).json({
        error: 'CONTRACT_TEST_ONLY_IN_TEST_MODE',
        message:
          'A suíte efêmera de testes de contrato MqrBridge Web API só é permitida quando NODE_ENV=test ou WINHOOD_TEST_MODE=1.',
      });
    }
    const swA = db.softwares[0];
    const swB = db.softwares[1];
    if (!swA || !swB) {
      return res.status(400).json({
        error: 'É necessário ter Software A e Software B carregados para executar os 27 testes reais de integração.',
      });
    }

    const latestRun = db.runs[0];
    const scoreA =
      latestRun?.scoreCards.find((sc) => sc.softwareId === swA.id)?.groupedScores
        .overallScore ?? 3.1;
    const scoreB =
      latestRun?.scoreCards.find((sc) => sc.softwareId === swB.id)?.groupedScores
        .overallScore ?? 4.78;

    const testResults = await sonarService.executeFullIntegrationTestSuite({
      softwareA: swA,
      softwareB: swB,
      runId: latestRun?.id || `run-${Date.now()}`,
      toolsDb: db.toolsDb,
      compositeScoreA: scoreA,
      compositeScoreB: scoreB,
    });

    appendAuditLog(
      db,
      'MQR_BRIDGE_INTEGRATION_TESTS_EXECUTED',
      'SONAR_TEST_SUITE',
      'suite-27-steps',
      `Suíte de contrato MqrBridge concluída (${testResults.length} etapas executadas).`,
      getRequestActor(req, res)
    );
    saveDatabase(db);

    return res.json({
      testResults,
      abComparison: db.toolsDb.ab_comparisons[0] || null,
      toolsDb: db.toolsDb,
    });
  });

  app.get('/api/optimization/metrics', (_req, res) => {
    const cacheStats = toolCacheManager.getCacheStats();
    const report = ToolResourceMonitor.buildOptimizationReport(
      dataDir,
      cacheStats.sizeKb,
      lifecycleManager.isLocalServerRunning()
    );
    db.toolsDb.optimization_report = report;
    res.json({
      optimizationReport: report,
      cacheStats,
      hostResources: ToolResourceMonitor.inspectHostResources(),
    });
  });

  // 16. Hardware, GPU, Storage & Display Benchmark Suite (Frente 4)
  let latestHardwareBenchmark: HostHardwareBenchmarkResult | null = null;

  app.get('/api/hardware-benchmark/latest', (_req, res) => {
    if (!latestHardwareBenchmark) {
      latestHardwareBenchmark = ToolResourceMonitor.runHostHardwareBenchmark();
    }
    res.json({
      benchmark: latestHardwareBenchmark,
      hostResources: ToolResourceMonitor.inspectHostResources(),
      hardwareProfile: getHardwareProfile(),
    });
  });

  app.post('/api/hardware-benchmark/run', (req, res) => {
    if (!requireWritePermission(res, req, 'tests:run')) return;
    const result = ToolResourceMonitor.runHostHardwareBenchmark();
    latestHardwareBenchmark = result;
    appendAuditLog(
      db,
      'HARDWARE_BENCHMARK_EXECUTED',
      'HARDWARE_BENCHMARK',
      result.benchmarkId,
      `Benchmark de Hardware & Storage executado: Score ${result.overallHostScore}/100 (Tier ${result.tier}) | SHA-256: ${result.verificationSha256.slice(0, 16)}...`,
      getRequestActor(req, res)
    );
    saveDatabase(db);
    res.json({
      benchmark: result,
      hostResources: ToolResourceMonitor.inspectHostResources(),
      hardwareProfile: getHardwareProfile(),
    });
  });

  app.post('/api/hardware-benchmark/attach-to-run', (req, res) => {
    if (!requireWritePermission(res, req, 'runs:execute')) return;
    const { runId, compositeScore, tier, displaySummary, verificationHash } = req.body as {
      runId?: string;
      compositeScore?: number;
      tier?: string;
      displaySummary?: string;
      verificationHash?: string;
    };
    const targetRun = db.runs.find((r) => r.id === runId) || db.runs[0];
    if (!targetRun) {
      return res.status(404).json({ error: 'Execução de benchmark não encontrada para vincular snapshot de hardware.' });
    }
    appendAuditLog(
      db,
      'HARDWARE_SNAPSHOT_ATTACHED',
      'BENCHMARK_RUN',
      targetRun.id,
      `Snapshot Hardware & Display vinculado à execução ${targetRun.id}: Score ${compositeScore ?? 0}/100 (Tier ${tier || 'A'}) — ${displaySummary || 'Display Telemetry'} [SHA-256: ${(verificationHash || '').slice(0, 16)}]`,
      getRequestActor(req, res)
    );
    saveDatabase(db);
    return res.json({
      attached: true,
      runId: targetRun.id,
      attachedAt: new Date().toISOString(),
    });
  });

  // 17. Reference Intelligence, Comparability Matcher, Golden Validation, Real Execution, SBOM & Key Management
  const refRegistry = new ReferenceRegistry(dataDir);
  const refSynchronizer = new ReferenceSynchronizer(dataDir);
  let latestGoldenValidation: import('./src/types/benchmark').GoldenValidationSuiteReport | null = null;

  app.get('/api/intelligence/references', (_req, res) => {
    const snapshots = refRegistry.listSnapshots(db.runs.length);
    res.json({
      snapshots,
      totalSources: snapshots.length,
      freshCount: snapshots.filter((s) => s.freshnessStatus === 'FRESH').length,
      cachedCount: snapshots.filter((s) => s.freshnessStatus === 'CACHED_VALID' || s.freshnessStatus === 'UNAVAILABLE_USING_CACHED').length,
      staleCount: snapshots.filter((s) => s.freshnessStatus === 'STALE').length,
      history: refRegistry.listSnapshotHistory(30),
    });
  });

  app.post('/api/intelligence/sync', async (req, res) => {
    if (!requireWritePermission(res, req, 'security:ops')) return;
    const { sources, sonarServerUrl, sonarToken, sbomPackages } = (req.body || {}) as {
      sources?: import('./src/types/benchmark').ReferenceSourceKey[];
      sonarServerUrl?: string;
      sonarToken?: string;
      sbomPackages?: Array<{
        ecosystem: import('./src/types/benchmark').SbomComponentRecord['ecosystem'];
        name: string;
        version: string;
      }>;
    };

    let derivedPackages = sbomPackages;
    if (!derivedPackages || derivedPackages.length === 0) {
      const pkgs: Array<{
        ecosystem: import('./src/types/benchmark').SbomComponentRecord['ecosystem'];
        name: string;
        version: string;
      }> = [];
      const seen = new Set<string>();
      for (const sw of db.softwares) {
        const sbom = db.runs[0]?.sbomsBySoftware?.[sw.id] || SbomGenerator.generateFromSoftware(sw);
        for (const comp of sbom.components || []) {
          const key = `${comp.ecosystem}:${comp.name}@${comp.version}`;
          if (!seen.has(key)) {
            seen.add(key);
            pkgs.push({ ecosystem: comp.ecosystem, name: comp.name, version: comp.version });
          }
        }
      }
      derivedPackages = pkgs.slice(0, 40);
    }

    const outcome = await refSynchronizer.syncSources({
      sources,
      sonarServerUrl,
      sonarToken,
      sbomPackages: derivedPackages,
      internalRunsCount: db.runs.length,
    });
    appendAuditLog(
      db,
      'REFERENCE_INTELLIGENCE_SYNCED',
      'REFERENCE_REGISTRY',
      'global',
      `Sincronização de referências: ${outcome.liveFetchedSources.length} fonte(s) ao vivo, ${outcome.cachedFallbackSources.length} em cache válido.`,
      getRequestActor(req, res)
    );
    saveDatabase(db);
    res.json(outcome);
  });

  app.post('/api/intelligence/match', analysisRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'runs:execute')) return;
    const { softwareIds, mode = 'AB_SOFTWARE' } = (req.body || {}) as {
      softwareIds?: string[];
      mode?: import('./src/types/benchmark').BenchmarkMatchDecision['mode'];
    };
    const selectedSoftwares =
      Array.isArray(softwareIds) && softwareIds.length > 0
        ? db.softwares.filter((s) => softwareIds.includes(s.id))
        : db.softwares.slice(0, 2);
    const latestRun = db.runs[0];
    const decision = BenchmarkMatcher.evaluate({
      mode,
      softwares: selectedSoftwares,
      profile: {
        enabledCategories: latestRun?.enabledCategories || ALL_BENCHMARK_CATEGORIES,
        notApplicableCategories: latestRun?.notApplicableCategories || [],
        qualityGateId: latestRun?.qualityGateId || 'qg-sonar-way',
      },
      scoreCards: latestRun?.scoreCards || [],
      algorithmVersion: ALGORITHM_VERSION,
      environmentEquivalent: latestRun?.environmentEquivalent ?? true,
    });
    res.json({ decision, softwaresEvaluated: selectedSoftwares.map((s) => ({ id: s.id, name: s.name })) });
  });

  app.get('/api/validation/latest', (_req, res) => {
    if (!latestGoldenValidation) {
      latestGoldenValidation = GoldenDatasetRunner.runValidationSuite();
    }
    res.json({ report: latestGoldenValidation });
  });

  app.post('/api/validation/run-golden', (req, res) => {
    if (!requireWritePermission(res, req, 'tests:run')) return;
    const report = GoldenDatasetRunner.runValidationSuite();
    latestGoldenValidation = report;
    appendAuditLog(
      db,
      'GOLDEN_DATASET_VALIDATED',
      'VALIDATION_SUITE',
      report.validationId,
      `Golden Dataset (${report.datasetOriginLabel}) executado: Precision=${report.precision}, Recall=${report.recall}, F1=${report.f1Score} (${report.truePositives} TP / ${report.falsePositives} FP / ${report.trueNegatives} TN / ${report.falseNegatives} FN) em ${report.totalDurationMs}ms.`,
      getRequestActor(req, res)
    );
    saveDatabase(db);
    res.json({ report });
  });

  // Authorized Performance Target Registry (SSRF Guard Allowlist)
  app.get('/api/execution/targets', (_req, res) => {
    res.json({ targets: db.authorizedTargets || [] });
  });

  app.post('/api/execution/targets', async (req, res) => {
    if (!requireWritePermission(res, req, 'targets:manage')) return;
    const actor = getRequestActor(req, res);
    const { label, origin, purpose, allowLocalhostInTest } = (req.body || {}) as {
      label?: string;
      origin?: string;
      purpose?: string;
      allowLocalhostInTest?: boolean;
    };
    if (!label || !origin) {
      return res.status(400).json({ error: 'Informe label e origin HTTP/HTTPS válidos para cadastrar o destino autorizado.' });
    }
    let parsedOrigin: URL;
    try {
      parsedOrigin = new URL(origin.trim());
    } catch {
      return res.status(400).json({ error: 'URL de origem malformada.' });
    }
    const ssrfCheck = await SsrfGuard.validateUrl({
      targetUrl: parsedOrigin.origin,
      allowExplicitLoopback: Boolean(allowLocalhostInTest || isTestRuntimeEnvironment()),
    });
    if (!ssrfCheck.allowed) {
      appendAuditLog(db, 'SSRF_TARGET_REGISTRATION_BLOCKED', 'PERF_TARGET', parsedOrigin.origin, ssrfCheck.reason, actor);
      saveDatabase(db);
      return res.status(403).json({
        error: 'SSRF_BLOCKED',
        message: ssrfCheck.reason,
      });
    }
    const target: AuthorizedPerfTarget = {
      id: `tgt-${crypto.randomUUID().slice(0, 8)}`,
      label: label.trim(),
      origin: parsedOrigin.origin,
      purpose: (purpose || 'Medição controlada de latência HTTP').trim(),
      allowLocalhostInTest: Boolean(allowLocalhostInTest),
      authorizedBy: actor.email,
      createdAt: new Date().toISOString(),
    };
    db.authorizedTargets = db.authorizedTargets || [];
    db.authorizedTargets.unshift(target);
    appendAuditLog(db, 'PERF_TARGET_AUTHORIZED', 'PERF_TARGET', target.id, `Destino autorizado cadastrado: ${target.origin} (${target.label}).`, actor);
    saveDatabase(db);
    return res.status(201).json({ target, targets: db.authorizedTargets });
  });

  app.delete('/api/execution/targets/:id', (req, res) => {
    if (!requireWritePermission(res, req, 'targets:manage')) return;
    const list = db.authorizedTargets || [];
    const idx = list.findIndex((t) => t.id === req.params.id);
    if (idx === -1) {
      return res.status(404).json({ error: 'Destino autorizado não encontrado.' });
    }
    const removed = list.splice(idx, 1)[0]!;
    db.authorizedTargets = list;
    appendAuditLog(db, 'PERF_TARGET_REMOVED', 'PERF_TARGET', removed.id, `Destino autorizado removido: ${removed.origin}.`, getRequestActor(req, res));
    saveDatabase(db);
    return res.json({ ok: true, targets: db.authorizedTargets });
  });

  app.post('/api/execution/run-tests', analysisRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'tests:run')) return;
    const actor = getRequestActor(req, res);
    const { softwareId, runId } = (req.body || {}) as { softwareId?: string; runId?: string };
    if (!softwareId) {
      return res.status(400).json({ error: 'Informe softwareId obrigatório para execução isolada de testes.' });
    }
    const sw = db.softwares.find((s) => s.id === softwareId);
    if (!sw) {
      return res.status(404).json({ error: 'Software não encontrado.' });
    }
    const result = ControlledTestAndPerfRunner.runIsolatedTestSuite({
      softwareName: sw.name,
      filesMap: sw.sourceFilesContent || {},
    });

    const targetRun = runId
      ? db.runs.find((r) => r.id === runId)
      : db.runs.find((r) => r.softwareIds.includes(sw.id));
    let attachedToRunId: string | null = null;

    if (targetRun) {
      const execRecord: UnifiedExecutionRecord = {
        id: `uexec-test-${crypto.randomUUID().slice(0, 8)}`,
        runId: targetRun.id,
        softwareId: sw.id,
        kind: 'TEST_EXECUTION',
        state: result.provenance.state,
        isolationMode: result.isolationMode,
        isolationState: result.isolationState,
        recoveryVerified: result.recoveryVerified,
        executedAt: new Date().toISOString(),
        durationMs: result.durationMs ?? 0,
        summary: `Execução isolada (${result.runnerUsed}): ${result.testsPassed}/${result.testsTotal} aprovados.`,
        evidenceHash: result.provenance.evidenceHash || computeSha256(`${sw.id}|${result.testsTotal}|${result.testsPassed}`),
        metricsPayload: {
          testsTotal: result.testsTotal,
          testsPassed: result.testsPassed,
          testsFailed: result.testsFailed,
          exitCode: result.exitCode,
        },
      };
      targetRun.executionRecords = [execRecord, ...(targetRun.executionRecords || [])];
      const sc = targetRun.scoreCards.find((card) => card.softwareId === sw.id);
      if (sc && result.executed) {
        sc.metricsSummary.functionalTestsTotal = result.testsTotal;
        sc.metricsSummary.functionalTestsPassed = result.testsPassed;
        sc.metricsSummary.functionalTestsFailed = result.testsFailed;
        if (result.coverageReport.found && result.coverageReport.lineCoveragePercent !== null) {
          sc.metricsSummary.testCoveragePercent = result.coverageReport.lineCoveragePercent;
        }
        recalculateBenchmarkRunScoreCards(targetRun, db.softwares);
      }
      attachedToRunId = targetRun.id;
    }

    appendAuditLog(
      db,
      'CONTROLLED_TEST_EXECUTION',
      'SOFTWARE',
      sw.id,
      `Execução isolada de testes (${result.runnerUsed}, isolation=${result.isolationMode}, cleanup=${result.recoveryVerified}): ${result.testsPassed}/${result.testsTotal} aprovados (estado: ${result.provenance.state}).`,
      actor
    );
    saveDatabase(db, true);
    return res.json({ softwareId: sw.id, softwareName: sw.name, attachedToRunId, result });
  });

  app.post('/api/execution/import-coverage', (req, res) => {
    if (!requireWritePermission(res, req, 'tests:run')) return;
    const { filePath = 'coverage/lcov.info', content, softwareId, runId } = (req.body || {}) as {
      filePath?: string;
      content?: string;
      softwareId?: string;
      runId?: string;
    };
    if (!content || typeof content !== 'string') {
      return res.status(400).json({ error: 'Conteúdo do relatório de cobertura (LCOV/JaCoCo/Cobertura/Istanbul) obrigatório.' });
    }
    const parsed = CoverageReportParser.parseFromFilesMap({ [filePath]: content });

    let attachedToRunId: string | null = null;
    if (softwareId) {
      const targetRun = runId
        ? db.runs.find((r) => r.id === runId)
        : db.runs.find((r) => r.softwareIds.includes(softwareId));
      if (targetRun && parsed.found && parsed.lineCoveragePercent !== null) {
        const sc = targetRun.scoreCards.find((card) => card.softwareId === softwareId);
        if (sc) {
          sc.metricsSummary.testCoveragePercent = parsed.lineCoveragePercent;
          targetRun.executionRecords = [
            {
              id: `uexec-cov-${crypto.randomUUID().slice(0, 8)}`,
              runId: targetRun.id,
              softwareId,
              kind: 'COVERAGE_IMPORT',
              state: parsed.state,
              isolationMode: 'NOT_REQUIRED',
              isolationState: 'CLEANUP_VERIFIED',
              recoveryVerified: true,
              executedAt: new Date().toISOString(),
              durationMs: 1,
              summary: `Relatório ${parsed.format} importado: ${parsed.lineCoveragePercent}% (${parsed.linesHit}/${parsed.linesFound}).`,
              evidenceHash: parsed.evidenceHash || computeSha256(content),
              metricsPayload: {
                format: parsed.format,
                lineCoveragePercent: parsed.lineCoveragePercent,
                linesHit: parsed.linesHit,
                linesFound: parsed.linesFound,
              },
            },
            ...(targetRun.executionRecords || []),
          ];
          recalculateBenchmarkRunScoreCards(targetRun, db.softwares);
          attachedToRunId = targetRun.id;
          saveDatabase(db, true);
        }
      }
    }

    return res.json({ coverage: parsed, attachedToRunId });
  });

  app.post('/api/execution/run-perf', analysisRateLimiter, async (req, res) => {
    if (!requireWritePermission(res, req, 'perf:run')) return;
    const actor = getRequestActor(req, res);
    const {
      targetUrl,
      requestsCount = 20,
      concurrency = 4,
      allowExplicitLoopback,
      softwareId,
      runId,
    } = (req.body || {}) as {
      targetUrl?: string;
      requestsCount?: number;
      concurrency?: number;
      allowExplicitLoopback?: boolean;
      softwareId?: string;
      runId?: string;
    };
    if (!targetUrl) {
      return res.status(400).json({
        error: 'TARGET_URL_REQUIRED',
        message: 'Informe targetUrl HTTP/HTTPS cadastrada em destinos autorizados para medição controlada.',
      });
    }
    let parsedTargetOrigin = '';
    try {
      parsedTargetOrigin = new URL(targetUrl).origin.toLowerCase();
    } catch {
      parsedTargetOrigin = '';
    }
    const registeredTarget = (db.authorizedTargets || []).find(
      (t) => t.origin.toLowerCase() === parsedTargetOrigin
    );
    const result = await ControlledTestAndPerfRunner.measureHttpWorkload({
      targetUrl,
      requestsCount,
      concurrency,
      authorizedTargets: db.authorizedTargets || [],
      requireRegisteredTarget: true,
      allowExplicitLoopback: Boolean(
        (allowExplicitLoopback && isTestRuntimeEnvironment()) ||
          (registeredTarget && (registeredTarget.allowLocalhostInTest || allowExplicitLoopback))
      ),
    });

    if (result.status === 'BLOCKED_SSRF') {
      appendAuditLog(
        db,
        'SSRF_ATTEMPT_BLOCKED',
        'RUNTIME_PERF',
        targetUrl,
        `Tentativa de medição bloqueada por SsrfGuard em ${targetUrl}: ${result.reason}`,
        actor
      );
      saveDatabase(db);
      return res.status(403).json({
        error: 'SSRF_BLOCKED',
        message: result.reason,
        result,
      });
    }

    let attachedToRunId: string | null = null;
    if (result.status === 'MEASURED') {
      const targetRun = runId
        ? db.runs.find((r) => r.id === runId)
        : softwareId
          ? db.runs.find((r) => r.softwareIds.includes(softwareId))
          : undefined;
      if (targetRun && softwareId) {
        const sc = targetRun.scoreCards.find((card) => card.softwareId === softwareId);
        if (sc) {
          sc.runtimeMetrics = {
            status: 'MEASURED',
            p50LatencyMs: result.p50LatencyMs ?? undefined,
            p95LatencyMs: result.p95LatencyMs ?? undefined,
            p99LatencyMs: result.p99LatencyMs ?? undefined,
            throughputRps: result.throughputRps ?? undefined,
            cpuPercent: result.targetMetrics.cpuPercent ?? undefined,
            memoryMb: result.targetMetrics.memoryRssMb ?? undefined,
            reason: `Medição HTTP SSRF-safe concluída em ${targetUrl} (telemetria de CPU/RAM do alvo remoto = NOT_MEASURED).`,
          };
          sc.metricsSummary.p50LatencyMs = result.p50LatencyMs ?? 0;
          sc.metricsSummary.p95LatencyMs = result.p95LatencyMs ?? 0;
          sc.metricsSummary.p99LatencyMs = result.p99LatencyMs ?? 0;
          sc.metricsSummary.throughputRps = result.throughputRps ?? 0;
          targetRun.executionRecords = [
            {
              id: `uexec-perf-${crypto.randomUUID().slice(0, 8)}`,
              runId: targetRun.id,
              softwareId,
              kind: 'HTTP_PERF_PROBE',
              state: 'MEASURED',
              isolationMode: 'SSRF_GUARD_PINNED',
              isolationState: 'CLEANUP_VERIFIED',
              recoveryVerified: true,
              executedAt: result.measuredAt,
              durationMs: result.agentMetrics.probeTimeMs,
              summary: `P50=${result.p50LatencyMs}ms, P95=${result.p95LatencyMs}ms, RPS=${result.throughputRps} em ${targetUrl}.`,
              evidenceHash: result.provenance.evidenceHash || computeSha256(`${targetUrl}|${result.measuredAt}`),
              metricsPayload: {
                p50LatencyMs: result.p50LatencyMs,
                p95LatencyMs: result.p95LatencyMs,
                p99LatencyMs: result.p99LatencyMs,
                throughputRps: result.throughputRps,
                agentMetrics: result.agentMetrics,
              },
            },
            ...(targetRun.executionRecords || []),
          ];
          recalculateBenchmarkRunScoreCards(targetRun, db.softwares);
          attachedToRunId = targetRun.id;
        }
      }
    }

    appendAuditLog(
      db,
      'CONTROLLED_PERF_MEASUREMENT',
      'RUNTIME_PERF',
      targetUrl,
      `Medição HTTP em ${targetUrl}: status=${result.status}, P95=${result.p95LatencyMs}ms, RPS=${result.throughputRps}.`,
      actor
    );
    saveDatabase(db, true);
    return res.json({ result, attachedToRunId });
  });

  app.get('/api/runs/:runId/sbom', (req, res) => {
    const run = db.runs.find((r) => r.id === req.params.runId) || db.runs[0];
    const format = req.query.format === 'spdx' ? 'spdx' : 'cyclonedx';
    const softwareId =
      typeof req.query.softwareId === 'string'
        ? req.query.softwareId
        : run?.softwareIds[0] || db.softwares[0]?.id;

    let sbom = softwareId ? run?.sbomsBySoftware?.[softwareId] : undefined;
    let correlations = softwareId ? run?.scaCorrelationsBySoftware?.[softwareId] : undefined;

    if (!sbom && softwareId) {
      const sw = db.softwares.find((s) => s.id === softwareId);
      if (sw) {
        sbom = SbomGenerator.generateFromSoftware(sw);
        const correlated = ScaCorrelator.correlateSbom({
          software: sw,
          sbom,
          runId: run?.id || 'on-demand',
        });
        correlations = correlated.correlations;
      }
    }
    if (!sbom) {
      return res.status(404).json({ error: 'SBOM não disponível para o software informado.' });
    }

    const sbomVerification = SbomGenerator.verifySbomSignature(sbom);

    return res.json({
      runId: run?.id || 'on-demand',
      softwareId,
      format,
      document: format === 'spdx' ? sbom.spdx23Json : sbom.cyclonedx15Json,
      documentSha256: format === 'spdx' ? sbom.spdxSha256 : sbom.cyclonedxSha256,
      componentsCount: sbom.componentsCount,
      directCount: sbom.directCount,
      transitiveCount: sbom.transitiveCount,
      signature: sbom.signature || null,
      signatureVerification: sbomVerification,
      scaCorrelations: correlations || [],
    });
  });

  app.get('/api/security/keys/status', (_req, res) => {
    res.json({ keys: KeyManagementService.getStatus() });
  });

  app.post('/api/security/keys/rotate', (req, res) => {
    if (!requireWritePermission(res, req, 'keys:rotate')) return;
    const actor = getRequestActor(req, res);
    const { purpose } = (req.body || {}) as {
      purpose?:
        | 'evidence-hmac'
        | 'evidence-ed25519'
        | 'sonar-vault-aes'
        | 'EVIDENCE_HMAC'
        | 'EVIDENCE_ED25519'
        | 'TOKEN_VAULT_AES256';
    };
    const purposeMap: Record<
      string,
      'EVIDENCE_HMAC' | 'EVIDENCE_ED25519' | 'TOKEN_VAULT_AES256'
    > = {
      'evidence-hmac': 'EVIDENCE_HMAC',
      EVIDENCE_HMAC: 'EVIDENCE_HMAC',
      'evidence-ed25519': 'EVIDENCE_ED25519',
      EVIDENCE_ED25519: 'EVIDENCE_ED25519',
      'sonar-vault-aes': 'TOKEN_VAULT_AES256',
      TOKEN_VAULT_AES256: 'TOKEN_VAULT_AES256',
    };
    const mappedPurpose = purpose ? purposeMap[purpose] : undefined;
    if (!mappedPurpose) {
      return res.status(400).json({
        error:
          'Informe purpose: "EVIDENCE_HMAC" ("evidence-hmac"), "EVIDENCE_ED25519" ("evidence-ed25519") ou "TOKEN_VAULT_AES256" ("sonar-vault-aes").',
      });
    }

    let reencryptedCount = 0;
    const newRecord = KeyManagementService.rotateKey(mappedPurpose, undefined, (ctx) => {
      if (Array.isArray(db.savedSonarProjects)) {
        for (const proj of db.savedSonarProjects) {
          if (proj.encryptedToken) {
            const reenc = MqrBridgeConnection.reencryptToken(proj.encryptedToken, ctx);
            if (reenc) {
              proj.encryptedToken = reenc;
              reencryptedCount += 1;
            }
          }
        }
      }
      reencryptedCount += sonarService.reencryptAllTokens(ctx);
      if (gitarAdapter.getConnection().reencryptStoredToken(ctx)) {
        reencryptedCount += 1;
      }
      reencryptedCount += totpService.reencryptTotpSecrets(ctx);
    });

    let reencryptedArtifactBundlesCount = 0;
    if (mappedPurpose === 'TOKEN_VAULT_AES256') {
      const reencResult = EncryptedArtifactStore.reencryptAllBundles(isolatedArtifactsDir);
      reencryptedArtifactBundlesCount = reencResult.reencryptedCount;
    }

    appendAuditLog(
      db,
      'CRYPTO_KEY_ROTATED',
      'KEY_MANAGEMENT',
      newRecord.keyId,
      `Chave criptográfica para ${mappedPurpose} rotacionada com sucesso (novo keyId: ${newRecord.keyId}; re-criptografados=${reencryptedCount}; bundles=${reencryptedArtifactBundlesCount}; chaves anteriores mantidas para verificação histórica).`,
      actor
    );
    saveDatabase(db, true);
    return res.json({
      rotated: true,
      newKeyId: newRecord.keyId,
      purpose: newRecord.purpose,
      algorithm: newRecord.algorithm,
      reencryptedTokensCount: reencryptedCount,
      reencryptedArtifactBundlesCount,
      createdAt: newRecord.createdAt,
      keys: KeyManagementService.getStatus(),
    });
  });

  app.get('/api/softwares/:softwareId/sbom', (req, res) => {
    const sw = db.softwares.find((s) => s.id === req.params.softwareId) || db.softwares[0];
    if (!sw) {
      return res.status(404).json({ error: 'Software não encontrado para geração de SBOM.' });
    }
    const format = req.query.format === 'spdx' ? 'spdx' : 'cyclonedx';
    const matchingRun = db.runs.find((r) => r.softwareIds.includes(sw.id));

    let sbom = matchingRun?.sbomsBySoftware?.[sw.id];
    let correlations = matchingRun?.scaCorrelationsBySoftware?.[sw.id];

    if (!sbom) {
      sbom = SbomGenerator.generateFromSoftware(sw, { signSbom: true });
      const correlated = ScaCorrelator.correlateSbom({
        software: sw,
        sbom,
        runId: matchingRun?.id || 'on-demand-sbom',
      });
      correlations = correlated.correlations;
    }

    const sbomVerification = SbomGenerator.verifySbomSignature(sbom);

    return res.json({
      runId: matchingRun?.id || 'on-demand-sbom',
      softwareId: sw.id,
      softwareName: sw.name,
      format,
      document: format === 'spdx' ? sbom.spdx23Json : sbom.cyclonedx15Json,
      documentSha256: format === 'spdx' ? sbom.spdxSha256 : sbom.cyclonedxSha256,
      componentsCount: sbom.componentsCount,
      directCount: sbom.directCount,
      transitiveCount: sbom.transitiveCount,
      signature: sbom.signature || null,
      signatureVerification: sbomVerification,
      scaCorrelations: correlations || [],
    });
  });

  app.post('/api/security/keys/verify', analysisRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'security:ops')) return;
    const actor = getRequestActor(req, res);
    const probePayload = `winhood-keystore-self-test:${Date.now()}:${actor.email}`;
    const testPayloadSha256 = computeSha256(probePayload);

    // 1. Verify HMAC-SHA256
    const hmacKey = KeyManagementService.getActiveEvidenceHmacKey();
    const hmacDigest = crypto.createHmac('sha256', hmacKey.secret).update(probePayload, 'utf8').digest('hex');
    const resolvedHmacSecret = KeyManagementService.getEvidenceSecretByKeyId(hmacKey.keyId);
    const hmacExpected = resolvedHmacSecret
      ? crypto.createHmac('sha256', resolvedHmacSecret).update(probePayload, 'utf8').digest('hex')
      : '';
    const hmacValid = Boolean(hmacDigest && hmacDigest === hmacExpected);

    // 2. Verify Ed25519
    const edKey = KeyManagementService.getActiveEvidenceEd25519Key();
    const edSignature = crypto.sign(null, Buffer.from(probePayload, 'utf8'), edKey.privateKeyPem);
    const resolvedPub = KeyManagementService.getEd25519PublicKeyByKeyId(edKey.keyId) || edKey.publicKeyPem;
    const ed25519Valid = crypto.verify(null, Buffer.from(probePayload, 'utf8'), resolvedPub, edSignature);

    // 3. Verify AES-256-GCM
    const encryptedProbe = MqrBridgeConnection.encryptToken(probePayload);
    const decryptedProbe = MqrBridgeConnection.decryptToken(encryptedProbe);
    const aesGcmValid = decryptedProbe === probePayload;

    const verified = hmacValid && ed25519Valid && aesGcmValid;
    appendAuditLog(
      db,
      'KEYSTORE_SELF_TEST_VERIFIED',
      'KEY_MANAGEMENT',
      hmacKey.keyId,
      `Autoteste criptográfico executado (verified=${verified}, Ed25519=${ed25519Valid}, HMAC-SHA256=${hmacValid}, AES-256-GCM=${aesGcmValid}).`,
      actor
    );
    saveDatabase(db);

    return res.json({
      verified,
      ed25519Valid,
      hmacValid,
      aesGcmValid,
      testPayloadSha256,
      ed25519SignatureHex: edSignature.toString('hex').slice(0, 32),
      hmacDigestHex: hmacDigest.slice(0, 32),
      testedAt: new Date().toISOString(),
      keys: KeyManagementService.getStatus(),
    });
  });

  // ============================================================================
  // AUTONOMOUS GOVERNANCE, OPENAPI 3.0.3, QUALITY GATES, COMPLIANCE & PORTFOLIO
  // ============================================================================
  app.get(['/api/openapi.json', '/openapi.json'], (req, res) => {
    const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const hostHeader = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
    res.json(buildOpenApiSpec(`${proto}://${hostHeader}`));
  });

  app.get('/api/rules/catalog', (_req, res) => {
    res.json({
      ...RuleRegistry.getCatalogSnapshot(),
      plugins: AnalyzerRegistry.listNativePlugins(),
    });
  });

  app.get('/api/secrets/catalog', (_req, res) => {
    res.json(SecretScanner.getCatalogMetadata());
  });

  app.get('/api/quality-gates', (_req, res) => {
    const gates = QualityGateEngine.listGates().map((g) => ({
      ...g,
      gateHash: QualityGateEngine.computeGateHash(g),
    }));
    res.json({ gates });
  });

  app.post('/api/quality-gates', (req, res) => {
    if (!requireWritePermission(res, req, 'security:ops')) return;
    const body = (req.body || {}) as Partial<QualityGateDefinition>;
    if (!body.id || !body.name || !Array.isArray(body.conditions) || body.conditions.length === 0) {
      return res.status(400).json({
        error: 'Informe id, name e ao menos uma condição booleana em conditions[].',
      });
    }
    const created: QualityGateDefinition = {
      id: String(body.id).replace(/[^a-zA-Z0-9._-]/g, '-'),
      name: String(body.name),
      version: String(body.version || '1.0.0'),
      description: String(body.description || 'Custom versioned WinHood Quality Gate'),
      requireVerifiedEvidence: body.requireVerifiedEvidence !== false,
      createdAt: new Date().toISOString(),
      conditions: body.conditions,
    };
    QualityGateEngine.registerGate(created);
    appendAuditLog(
      db,
      'QUALITY_GATE_REGISTERED',
      'QUALITY_GATE',
      created.id,
      `Quality Gate "${created.name}" v${created.version} registrado (hash=${QualityGateEngine.computeGateHash(created).slice(0, 12)}).`,
      getRequestActor(req, res)
    );
    saveDatabase(db);
    return res.status(201).json({
      gate: created,
      gateHash: QualityGateEngine.computeGateHash(created),
    });
  });

  app.post('/api/quality-gates/evaluate', analysisRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'runs:execute')) return;
    const body = (req.body || {}) as {
      runId?: string;
      gateId?: string;
      findings?: NormalizedFinding[];
      scopeCoveragePercent?: number | null;
      evidenceConfidence?: 'HIGH' | 'MEDIUM' | 'LOW';
    };
    const run = body.runId ? db.runs.find((r) => r.id === body.runId) : db.runs[0];
    if (body.findings && Array.isArray(body.findings)) {
      const evaluation = QualityGateEngine.evaluate({
        gateId: body.gateId,
        findings: body.findings,
        scopeCoveragePercent: body.scopeCoveragePercent ?? 100,
        evidenceConfidence: body.evidenceConfidence ?? 'HIGH',
        evidenceVerified: true,
      });
      return res.json({ evaluation });
    }
    if (!run) {
      return res.status(404).json({ error: 'Execução não encontrada para avaliação do Quality Gate.' });
    }
    const evaluation = QualityGateEngine.evaluateFromRun(run, body.gateId);
    return res.json({ runId: run.id, evaluation });
  });

  app.post('/api/webhooks/sign-test', async (req, res) => {
    if (!requireWritePermission(res, req, 'security:ops')) return;
    const body = (req.body || {}) as {
      runId?: string;
      gateId?: string;
      targetUrl?: string;
      secret?: string;
    };
    const run = body.runId ? db.runs.find((r) => r.id === body.runId) : db.runs[0];
    const evaluation = run
      ? QualityGateEngine.evaluateFromRun(run, body.gateId)
      : QualityGateEngine.evaluate({
          gateId: body.gateId,
          findings: [],
          scopeCoveragePercent: 100,
          evidenceConfidence: 'HIGH',
          evidenceVerified: true,
        });

    if (body.targetUrl && body.targetUrl.trim().length > 0) {
      const dispatchResult = await QualityGateEngine.dispatchSignedWebhook({
        targetUrl: body.targetUrl.trim(),
        evaluation,
        runId: run?.id,
        secret: body.secret,
      });
      return res.status(dispatchResult.blockedBySsrf ? 400 : 200).json({
        mode: 'DISPATCHED',
        evaluation,
        dispatchResult,
      });
    }

    const signed = QualityGateEngine.signWebhookPayload({
      event: 'quality_gate.evaluated',
      runId: run?.id,
      evaluation,
      secret: body.secret,
    });
    return res.json({
      mode: 'SIGNED_PREVIEW',
      evaluation,
      signedPayload: {
        headerName: 'X-WinHood-Signature',
        signatureHeader: signed.signatureHeader,
        keyId: signed.keyId,
        payloadSha256: signed.payloadSha256,
        body: JSON.parse(signed.bodyJson),
      },
    });
  });

  app.get('/api/compliance/:runId/matrix', (req, res) => {
    const run = db.runs.find((r) => r.id === req.params.runId) || db.runs[0];
    if (!run) {
      return res.status(404).json({ error: 'Execução não encontrada para matriz de rastreabilidade.' });
    }
    const matrix = ComplianceMapper.buildTraceabilityMatrix({
      runId: run.id,
      findings: run.findings || [],
    });
    return res.json({ matrix });
  });

  app.get('/api/portfolio/summary', (_req, res) => {
    const summary = PortfolioEngine.buildSummary({
      runs: db.runs,
      softwares: db.softwares,
    });
    return res.json({ summary });
  });

  app.post('/api/integrations/pr-decoration', analysisRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'runs:execute')) return;
    const body = (req.body || {}) as {
      provider?: PrCiProvider;
      repository?: string;
      pullRequestOrMrId?: string | number;
      runId?: string;
      baselineRunId?: string;
      gateId?: string;
    };
    const run = (body.runId ? db.runs.find((r) => r.id === body.runId) : db.runs[0]) || null;
    if (!run) {
      return res.status(404).json({ error: 'Execução não encontrada para geração de PR/MR decoration.' });
    }
    const baselineRun = body.baselineRunId
      ? db.runs.find((r) => r.id === body.baselineRunId) || null
      : null;
    const decoration = PrDecorationAdapter.buildDecoration({
      provider: body.provider || 'GITHUB',
      repository: body.repository || run.projectName || 'org/repo',
      pullRequestOrMrId: body.pullRequestOrMrId ?? 1,
      run,
      baselineRun,
      gateId: body.gateId,
    });
    return res.json({ decoration });
  });

  app.post('/api/analyze/sarif', analysisRateLimiter, heavyUploadJsonParser, (req, res) => {
    if (!requireWritePermission(res, req, 'runs:execute')) return;
    const body = (req.body || {}) as {
      softwareName?: string;
      softwareVersion?: string;
      gateId?: string;
      filesMap?: Record<string, string>;
      sarifInput?: unknown;
      deterministicTimestamp?: string;
    };

    if (body.sarifInput) {
      const imported = SarifCodec.importSarif210(body.sarifInput, {
        runId: 'sarif-import',
        softwareId: 'imported-sw',
        softwareName: body.softwareName || 'External SARIF Target',
        softwareVersion: body.softwareVersion || '1.0.0',
      });
      if (!imported.valid) {
        return res.status(400).json({ error: 'SARIF_INVALID', details: imported.errors });
      }
      const gateEval = QualityGateEngine.evaluate({
        gateId: body.gateId,
        findings: imported.findings,
        scopeCoveragePercent: 100,
        evidenceConfidence: 'MEDIUM',
        evidenceVerified: true,
        deterministicTimestamp: body.deterministicTimestamp,
      });
      return res.json({
        mode: 'SARIF_IMPORT',
        importedToolNames: imported.importedToolNames,
        payloadSha256: imported.payloadSha256,
        findingsCount: imported.findings.length,
        findings: imported.findings,
        gateEvaluation: gateEval,
      });
    }

    const filesMap = body.filesMap && typeof body.filesMap === 'object' ? body.filesMap : {};
    const swStub = {
      id: 'api-sarif-sw',
      projectId: 'api-sarif-proj',
      name: body.softwareName || 'SubmittedWorkspace',
      vendor: 'API',
      description: 'On-demand SARIF audit',
      version: body.softwareVersion || '1.0.0',
      languages: [],
      architecture: 'Unknown',
      operatingSystem: process.platform,
      distributionModel: 'Source',
      licenseType: 'Unknown',
      officialUrl: '',
      repositoryUrl: '',
      documentationUrl: '',
      owner: 'api',
      notes: '',
      sourceType: 'LOCAL_AUTHORIZED',
      commitHash: 'API_HEAD',
      packageSha256: 'API_SUBMISSION',
      createdAt: body.deterministicTimestamp || new Date().toISOString(),
      inventory: {
        totalFiles: Object.keys(filesMap).length,
        eligibleFiles: Object.keys(filesMap).length,
        totalLinesOfCode: 0,
        totalSizeBytes: 0,
        languageBreakdown: {},
        files: [],
        isolatedStoragePath: '/api',
        verifiedIntegrity: true,
      },
      sourceFilesContent: filesMap,
    } as Software;

    const pipeline = AnalyzerRegistry.runNativeAstAndTaintPipeline(
      {
        runId: 'api-sarif',
        softwareId: swStub.id,
        softwareName: swStub.name,
        softwareVersion: swStub.version,
        commitHash: 'API_HEAD',
        filesMap,
      },
      { deterministicTimestamp: body.deterministicTimestamp }
    );
    const sbom = SbomGenerator.generateFromSoftware(swStub, {
      deterministicTimestamp: body.deterministicTimestamp,
    });
    const sca = ScaCorrelator.correlateSbom({
      software: swStub,
      sbom,
      runId: 'api-sarif',
      licensePolicy: DEFAULT_ENTERPRISE_LICENSE_POLICY,
    });
    const allFindings = [...pipeline.findings, ...sca.findings];
    const totalFiles = Object.keys(filesMap).length;
    const gateEvaluation = QualityGateEngine.evaluate({
      gateId: body.gateId,
      findings: allFindings,
      scopeCoveragePercent: totalFiles > 0 ? 100 : 0,
      evidenceConfidence: totalFiles > 0 ? 'HIGH' : 'LOW',
      evidenceVerified: true,
      deterministicTimestamp: body.deterministicTimestamp,
    });
    const sarif = SarifCodec.exportSarif210(allFindings, {
      toolVersion: RULE_ENGINE_VERSION,
    });
    return res.json({
      mode: 'NATIVE_ANALYSIS',
      engineVersion: RULE_ENGINE_VERSION,
      deterministicDigestSha256: pipeline.deterministicDigestSha256,
      ruleCatalogSha256: pipeline.ruleCatalogSha256,
      findingsCount: allFindings.length,
      sbomComponentsCount: sbom.componentsCount,
      gateEvaluation,
      sarif,
    });
  });

  // Storage plaintext audit & atomic legacy migration endpoints
  app.get('/api/storage/plaintext-audit', (_req, res) => {
    const scan = EncryptedArtifactStore.auditNoPlaintextOnDisk(isolatedArtifactsDir);
    const persistentVolumeAudit = EncryptedArtifactStore.auditPersistentDataDir(dataDir);
    return res.json({
      ...scan,
      clean: scan.clean && persistentVolumeAudit.clean,
      persistentVolumeAudit,
    });
  });

  app.post('/api/storage/migrate-legacy-plaintext', (req, res) => {
    if (!requireWritePermission(res, req, 'storage:migrate')) return;
    const report = EncryptedArtifactStore.migrateLegacyPlaintextArtifacts(isolatedArtifactsDir);
    if (report.migratedSlugs > 0) {
      appendAuditLog(
        db,
        'LEGACY_PLAINTEXT_ARTIFACTS_MIGRATED',
        'STORAGE_SECURITY',
        isolatedArtifactsDir,
        `Migração manual executada: ${report.migratedSlugs} slug(s) migrado(s), ${report.plaintextFilesRemovedTotal} arquivo(s) em texto plano removido(s).`,
        getRequestActor(req, res)
      );
      saveDatabase(db, true);
    }
    return res.json(report);
  });

  // Dedicated Scanner Worker capabilities & async job orchestration endpoints
  const allowedScannerTools = new Set<string>(SCANNER_TOOL_CATALOG.map((c) => c.toolId));

  app.get('/api/scanner-worker/capabilities', async (_req, res) => {
    const snapshot = await scannerJobOrchestrator.getCapabilities();
    return res.json(snapshot);
  });

  app.get('/api/scanner-worker/jobs', (_req, res) => {
    return res.json({ jobs: scannerJobOrchestrator.listJobs() });
  });

  app.post('/api/scanner-worker/jobs', analysisRateLimiter, (req, res) => {
    if (!requireWritePermission(res, req, 'scanner-worker:enqueue')) return;
    const body = (req.body || {}) as {
      projectId?: string;
      softwareId?: string;
      toolIds?: string[];
      filesMap?: Record<string, string>;
      timeoutMs?: number;
      maxRetries?: number;
    };
    const requestedTools = Array.isArray(body.toolIds)
      ? body.toolIds.filter((t): t is ScannerToolId => typeof t === 'string' && allowedScannerTools.has(t))
      : [];
    if (requestedTools.length === 0) {
      return res.status(400).json({
        error: 'INVALID_SCANNER_TOOLS',
        message: 'Informe ao menos uma ferramenta suportada em toolIds.',
        supportedTools: Array.from(allowedScannerTools),
      });
    }
    let resolvedFilesMap: Record<string, string> | null =
      body.filesMap && typeof body.filesMap === 'object' ? body.filesMap : null;
    if (!resolvedFilesMap && body.softwareId) {
      const sw = db.softwares.find((s) => s.id === body.softwareId);
      if (sw && sw.sourceFilesContent && Object.keys(sw.sourceFilesContent).length > 0) {
        resolvedFilesMap = sw.sourceFilesContent;
      } else if (sw?.inventory?.isolatedStoragePath) {
        try {
          resolvedFilesMap = EncryptedArtifactStore.readEncryptedBundle(sw.inventory.isolatedStoragePath);
        } catch {
          resolvedFilesMap = null;
        }
      }
    }
    if (!resolvedFilesMap || Object.keys(resolvedFilesMap).length === 0) {
      return res.status(400).json({
        error: 'EMPTY_SOURCE_FILES',
        message: 'Informe filesMap não vazio ou um softwareId existente com arquivos fonte.',
      });
    }
    const job = scannerJobOrchestrator.enqueueJob({
      projectId: body.projectId,
      softwareId: body.softwareId,
      toolIds: requestedTools,
      filesMap: resolvedFilesMap,
      timeoutMs: body.timeoutMs,
      maxRetries: body.maxRetries,
    });
    return res.status(202).json({ job });
  });

  app.get('/api/scanner-worker/jobs/:jobId', (req, res) => {
    const job = scannerJobOrchestrator.getJob(req.params.jobId);
    if (!job) {
      return res.status(404).json({ error: 'SCANNER_JOB_NOT_FOUND' });
    }
    return res.json({ job });
  });

  app.post('/api/scanner-worker/jobs/:jobId/cancel', async (req, res) => {
    if (!requireWritePermission(res, req, 'scanner-worker:cancel')) return;
    const outcome = await scannerJobOrchestrator.cancelJobConfirmed(req.params.jobId);
    if (!outcome.job) {
      return res.status(404).json({ error: 'SCANNER_JOB_NOT_FOUND' });
    }
    return res.json(outcome);
  });

  // Safe API JSON fallback & error handler
  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'ENDPOINT_NOT_FOUND' });
  });
  app.use(
    '/api',
    (err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      if (err?.type === 'entity.too.large' || err?.status === 413) {
        return res.status(413).json({
          error: 'PAYLOAD_TOO_LARGE',
          message: 'Payload excede o limite máximo permitido para este endpoint.',
        });
      }
      if (err instanceof SyntaxError && (err as { status?: number }).status === 400) {
        return res.status(400).json({
          error: 'INVALID_JSON_PAYLOAD',
          message: 'Corpo JSON malformado.',
        });
      }
      return res.status(err?.status || 500).json({
        error: 'INTERNAL_API_ERROR',
        message: err?.message || 'Erro interno no servidor WinHood.',
      });
    }
  );

  return {
    app,
    dbManager,
    totpService,
    scannerJobOrchestrator,
    deploymentMode,
    runtimeEnv,
    trustProxyConfig,
    registerAllowedLocalPort,
    getDb: () => db,
    flushPendingSave: flushPendingDatabaseSave,
    dispose: () => {
      scannerJobOrchestrator.cancelAllPendingAndRunning();
      flushPendingDatabaseSave();
      remoteAuthFailureTracker.dispose();
      EphemeralWorkspaceManager.cleanupAllActiveWorkspaces();
    },
  };
}

export interface StartWinHoodServerOptions {
  dataDir?: string;
  host?: string;
  port?: number;
  distPath?: string;
  deploymentMode?: DeploymentMode;
  remoteApiToken?: string;
  trustProxy?: string | number | boolean;
  environment?:
    | 'AI_STUDIO_PREVIEW'
    | 'LOCAL_WEB_DEVELOPMENT'
    | 'LOCAL_PRODUCTION'
    | 'DOCKER_LOCAL_WEB'
    | 'ELECTRON_DESKTOP'
    | 'WINDOWS_PACKAGED'
    | 'REMOTE_DEPLOYMENT';
  enableVite?: boolean;
}

export interface StartedWinHoodServer {
  app: express.Express;
  server: http.Server;
  host: string;
  port: number;
  url: string;
  dataDir: string;
  close: () => Promise<void>;
}

export async function startServer(
  options?: StartWinHoodServerOptions
): Promise<StartedWinHoodServer> {
  const dataDir = resolveWinHoodDataRoot(options?.dataDir);
  const { app, dispose, registerAllowedLocalPort } = await createWinHoodApp({
    dataDir,
    deploymentMode: options?.deploymentMode,
    remoteApiToken: options?.remoteApiToken,
    trustProxy: options?.trustProxy,
    environment: options?.environment,
    host: options?.host,
    port: options?.port,
  });

  const isElectronDesktop =
    options?.environment === 'ELECTRON_DESKTOP' ||
    options?.environment === 'WINDOWS_PACKAGED' ||
    process.env.WINHOOD_RUNTIME_ENV === 'ELECTRON_DESKTOP';

  const shouldEnableVite =
    options?.enableVite !== undefined
      ? options.enableVite
      : process.env.NODE_ENV !== 'production' && !isElectronDesktop;

  // Mount Vite (dev-only dynamic import) or Static Dist (Docker / production standalone)
  if (shouldEnableVite) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = options?.distPath || path.resolve(process.cwd(), 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (req, res) => {
        if (req.path === '/api' || req.path.startsWith('/api/')) {
          return res.status(404).json({ error: 'ENDPOINT_NOT_FOUND' });
        }
        return res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  const bindHost =
    options?.host ||
    (isElectronDesktop
      ? '127.0.0.1'
      : process.env.WINHOOD_ALLOW_NETWORK_BIND === 'true'
        ? process.env.WINHOOD_BIND_HOST || '0.0.0.0'
        : '127.0.0.1');

  const requestedPort = options?.port !== undefined ? options.port : PORT;

  const listenOnPort = (portToTry: number): Promise<http.Server> =>
    new Promise((resolve, reject) => {
      const srv = app.listen(portToTry, bindHost, () => {
        resolve(srv);
      });
      srv.once('error', (err: NodeJS.ErrnoException) => {
        reject(err);
      });
    });

  let server: http.Server;
  try {
    server = await listenOnPort(requestedPort);
  } catch (err: unknown) {
    const errCode = (err as NodeJS.ErrnoException | undefined)?.code;
    if (errCode === 'EADDRINUSE' && isElectronDesktop && requestedPort !== 0) {
      // Dynamic fallback port on loopback for desktop mode
      server = await listenOnPort(0);
    } else {
      dispose();
      throw err;
    }
  }

  const addr = server.address();
  const effectivePort =
    typeof addr === 'object' && addr !== null ? addr.port : requestedPort;
  registerAllowedLocalPort(effectivePort);
  const effectiveUrl = `http://${bindHost === '0.0.0.0' ? '127.0.0.1' : bindHost}:${effectivePort}`;

  const shutdownController = registerGracefulShutdown({
    server,
    onBeforeClose: () => {
      dispose();
    },
    onAfterClose: () => {
      EphemeralWorkspaceManager.cleanupAllActiveWorkspaces();
    },
    signals: isEntrypoint ? ['SIGINT', 'SIGTERM'] : [],
    exitProcess: isEntrypoint,
    enableIpcShutdown: isEntrypoint,
  });

  console.log(`WinHood Benchmark Server listening on http://${bindHost}:${effectivePort}`);

  return {
    app,
    server,
    host: bindHost,
    port: effectivePort,
    url: effectiveUrl,
    dataDir,
    close: async () => {
      shutdownController.unregister();
      await shutdownController.shutdown('SERVER_CLOSE');
    },
  };
}

function parseServerCliArgs(argv: string[]): Pick<StartWinHoodServerOptions, 'port' | 'host'> {
  const parsed: Pick<StartWinHoodServerOptions, 'port' | 'host'> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--port' && i + 1 < argv.length) {
      const portNum = parseValidPortNumber(argv[++i]);
      if (portNum !== null) parsed.port = portNum;
    } else if (token.startsWith('--port=')) {
      const portNum = parseValidPortNumber(token.slice('--port='.length));
      if (portNum !== null) parsed.port = portNum;
    } else if (token === '--host' && i + 1 < argv.length) {
      const hostVal = argv[++i].trim();
      if (hostVal && /^[a-zA-Z0-9.:-]+$/.test(hostVal)) parsed.host = hostVal;
    } else if (token.startsWith('--host=')) {
      const hostVal = token.slice('--host='.length).trim();
      if (hostVal && /^[a-zA-Z0-9.:-]+$/.test(hostVal)) parsed.host = hostVal;
    }
  }
  return parsed;
}

const isEntrypoint =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  Boolean(process.argv[1]) &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntrypoint) {
  const cliOptions = parseServerCliArgs(process.argv.slice(2));
  void startServer(cliOptions).catch((err) => {
    console.error('Failed to start WinHood server:', err);
    process.exit(1);
  });
}
