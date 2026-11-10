export type VeracityClassification =
  | 'SUCCESS_VALIDATED'
  | 'SUCCESS_WITH_WARNINGS'
  | 'INCOMPLETE_COVERAGE'
  | 'EMPTY_ERROR'
  | 'EXECUTION_FAILED'
  | 'INVALID_OUTPUT'
  | 'AUTHENTICATION_FAILED'
  | 'TIMEOUT'
  | 'NOT_SUPPORTED'
  | 'NOT_APPLICABLE'
  | 'VISUAL_ONLY';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type BenchmarkCategoryKey =
  | 'functionality'
  | 'code_quality'
  | 'security'
  | 'performance'
  | 'architecture'
  | 'database'
  | 'reliability'
  | 'compatibility'
  | 'usability'
  | 'installation'
  | 'privacy'
  | 'documentation';

export interface Project {
  id: string;
  name: string;
  category: string;
  objective: string;
  description: string;
  owner: string;
  createdAt: string;
  updatedAt: string;
  history: Array<{
    timestamp: string;
    action: string;
    actor: string;
    details: string;
  }>;
}

export interface FileInventoryItem {
  relativePath: string;
  extension: string;
  language: string;
  sizeBytes: number;
  linesOfCode: number;
  sha256: string;
  eligibleForAnalysis: boolean;
}

export interface Software {
  id: string;
  projectId: string;
  name: string;
  vendor: string;
  description: string;
  category: string;
  version: string;
  languages: string[];
  architecture: string;
  operatingSystem: string;
  distributionModel: string;
  licenseType: string;
  officialUrl: string;
  repositoryUrl: string;
  documentationUrl: string;
  owner: string;
  notes: string;
  sourceType: 'GIT_REPO' | 'ARCHIVE' | 'LOCAL_AUTHORIZED' | 'COMPILED_BINARY' | 'CONTAINER' | 'EXECUTION_ENV';
  commitHash: string;
  packageSha256: string;
  createdAt: string;
  inventory: {
    totalFiles: number;
    eligibleFiles: number;
    totalLinesOfCode: number;
    totalSizeBytes: number;
    languageBreakdown: Record<string, number>;
    files: FileInventoryItem[];
    isolatedStoragePath: string;
    verifiedIntegrity: boolean;
  };
  sourceFilesContent?: Record<string, string>;
}

export interface ToolAdapterInfo {
  id: string;
  name: string;
  vendor: string;
  version: string;
  category: 'CODE_QUALITY' | 'SECURITY_DEVSECOPS' | 'ARCHITECTURE' | 'QA_FUNCTIONAL' | 'PERFORMANCE' | 'DATABASE' | 'OS_INSTALL';
  analysisType: string;
  executionMethod: 'NATIVE_AST_ENGINE' | 'CLI_BINARY' | 'EXTERNAL_API' | 'SANDBOX_WORKER';
  canonicalFormat: 'SARIF_2_1_0' | 'CYCLONEDX_1_5' | 'JUNIT_XML' | 'OTLP_METRICS' | 'ARCH_GRAPH_JSON' | 'SNAPSHOT_DIFF';
  status:
    | 'OPERATIONAL'
    | 'FERRAMENTA NÃO INSTALADA'
    | 'INTEGRAÇÃO CONFIGURADA'
    | 'INTEGRAÇÃO NÃO CONFIGURADA'
    | 'ACESSO NÃO AUTORIZADO';
  binaryDetected: boolean;
  configured: boolean;
  signatureHash: string;
  description: string;
  supportedLanguages: string[];
  lastExecutionAt: string | null;
  lastExitCode: number | null;
}

export interface NormalizedFinding {
  id: string;
  runId: string;
  softwareId: string;
  softwareName: string;
  softwareVersion: string;
  toolId: string;
  toolName: string;
  toolVersion: string;
  category: 'CODE_QUALITY' | 'SAST' | 'SCA' | 'SECRETS' | 'SBOM' | 'ARCHITECTURE' | 'DATABASE' | 'DAST' | 'IAC' | 'OS_SANDBOX';
  originalRuleId: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  filePath: string;
  lineNumber: number;
  component: string;
  snippet: string;
  cwe?: string;
  cve?: string;
  cvss?: number;
  epss?: number;
  cisaKev?: boolean;
  remediation: string;
  evidenceSha256: string;
  validationStatus: 'VALIDATED' | 'FALSE_POSITIVE_REVIEWED' | 'CORRELATED_DEDUPLICATED' | 'UNVERIFIED';
  collectedAt: string;
}

export interface ToolExecutionRecord {
  id: string;
  runId: string;
  softwareId: string;
  toolId: string;
  toolName: string;
  toolVersion: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  exitCode: number;
  veracityStatus: VeracityClassification;
  eligibleFilesCount: number;
  analyzedFilesCount: number;
  coveragePercent: number;
  parsingErrorsCount: number;
  schemaValidated: boolean;
  canonicalFormat: string;
  rawOutputSha256: string;
  logs: string[];
}

export interface VeracityCheckResult {
  runId: string;
  softwareId: string;
  softwareName: string;
  overallClassification: VeracityClassification;
  checks: {
    toolExecuted: boolean;
    versionIdentified: boolean;
    artifactsReceived: boolean;
    eligibleFilesIdentified: boolean;
    filesEffectivelyAnalyzed: boolean;
    coverageCalculated: boolean;
    parsingErrorsChecked: boolean;
    reportGenerated: boolean;
    schemaValidated: boolean;
    evidenceStored: boolean;
    persistenceConfirmed: boolean;
    integrityVerified: boolean;
  };
  overallCoveragePercent: number;
  warnings: string[];
  blockingReasons: string[];
  auditedAt: string;
}

export interface PenaltyCapTriggered {
  ruleId: string;
  category: BenchmarkCategoryKey | 'overall';
  reason: string;
  maxAllowedScore: number;
  originalScore: number;
  cappedScore: number;
}

export interface SoftwareScoreCard {
  softwareId: string;
  softwareName: string;
  softwareVersion: string;
  categoryScores: Record<BenchmarkCategoryKey, number | null>;
  groupedScores: {
    functionalScore: number;
    securityScore: number;
    technicalScore: number;
    performanceScore: number;
    architectureScore: number;
    qualityScore: number;
    overallScore: number;
  };
  classificationLabel: 'Inexistente' | 'Crítico' | 'Insuficiente' | 'Adequado' | 'Muito bom' | 'Excelente';
  penaltyCapsTriggered: PenaltyCapTriggered[];
  advantages: string[];
  deficiencies: string[];
  risks: string[];
  metricsSummary: {
    bugs: number;
    codeSmells: number;
    vulnerabilities: number;
    criticalVulns: number;
    highVulns: number;
    mediumVulns: number;
    lowVulns: number;
    secretsExposed: number;
    duplicatedLinesPercent: number;
    deadCodeSymbols: number;
    avgCyclomaticComplexity: number;
    avgCognitiveComplexity: number;
    technicalDebtMinutes: number;
    testCoveragePercent: number;
    circularDependencies: number;
    couplingIndex: number;
    cohesionIndex: number;
    dbSchemaIssues: number;
    functionalTestsTotal: number;
    functionalTestsPassed: number;
    functionalTestsFailed: number;
    p50LatencyMs: number;
    p95LatencyMs: number;
    p99LatencyMs: number;
    throughputRps: number;
    memoryMb: number;
    cpuPercent: number;
    startupTimeMs: number;
  };
  qualityGate?: {
    status: 'PASSED' | 'FAILED' | 'WARN';
    conditionsMet: number;
    conditionsFailed: number;
    failedMetrics: string[];
  };
  ratings?: {
    reliability: 'A' | 'B' | 'C' | 'D' | 'E';
    security: 'A' | 'B' | 'C' | 'D' | 'E';
    maintainability: 'A' | 'B' | 'C' | 'D' | 'E';
  };
}

export interface BenchmarkRunProgress {
  percent: number;
  stageLabel: string;
  estimatedRemainingSeconds: number;
  currentTool?: string;
  processedFiles: number;
  totalFiles: number;
}

export interface BenchmarkProfileConfig {
  id: string;
  name: string;
  description: string;
  weights: Record<BenchmarkCategoryKey, number>;
  selectedAdapters: string[];
  enablePenaltyCaps: boolean;
  equivalenceEnvironment: {
    cpuCoresLimit: number;
    memoryMbLimit: number;
    osTarget: string;
    workloadConcurrency: number;
    dastFormalAuthorization: boolean;
    authorizedByOwner: string;
  };
}

export interface ArchitectureGraphData {
  softwareId: string;
  softwareName: string;
  modules: Array<{
    id: string;
    name: string;
    layer: 'PRESENTATION' | 'APPLICATION' | 'DOMAIN' | 'INFRASTRUCTURE' | 'DATABASE' | 'UTILITY';
    loc: number;
    afferentCoupling: number;
    efferentCoupling: number;
    instability: number;
    unusedExports: number;
  }>;
  edges: Array<{
    from: string;
    to: string;
    isCircular: boolean;
    isLayerViolation: boolean;
  }>;
  circularChains: string[][];
  layerViolations: string[];
}

export interface FunctionalEquivalenceRow {
  featureId: string;
  featureName: string;
  domainCategory: string;
  essential: boolean;
  resultsBySoftware: Record<
    string,
    {
      status: 'PASSED_VALIDATED' | 'FAILED' | 'NOT_IMPLEMENTED' | 'VISUAL_ONLY';
      executionTimeMs: number;
      assertionCount: number;
      evidenceLog: string;
    }
  >;
}

export interface WindowsSandboxSnapshotDiff {
  softwareId: string;
  softwareName: string;
  sandboxEnvironment: string;
  t0BaselineHash: string;
  t1PostInstallHash: string;
  t2PostUninstallHash: string;
  filesCreatedT1: string[];
  registryKeysModifiedT1: string[];
  servicesRegisteredT1: string[];
  processesSpawnedT1: string[];
  networkEndpointsContacted: string[];
  residualFilesT2: string[];
  residualRegistryKeysT2: string[];
  unexpectedMutations: string[];
  cleanUninstall: boolean;
}

export interface EvidenceRecord {
  id: string;
  runId: string;
  softwareId: string;
  softwareName: string;
  version: string;
  category: string;
  toolName: string;
  toolVersion: string;
  timestamp: string;
  resultSummary: string;
  severity: SeverityLevel;
  fileOrComponent: string;
  validationStatus: VeracityClassification;
  sha256: string;
  rawPayloadPreview: string;
  immutableIndex: number;
  previousRecordSha256: string;
}

export interface BenchmarkRun {
  id: string;
  projectId: string;
  projectName: string;
  profileName: string;
  softwareIds: string[];
  status: 'RUNNING' | 'COMPLETED' | 'COMPLETED_WITH_WARNINGS' | 'INCOMPLETE' | 'FAILED';
  startedAt: string;
  completedAt: string;
  algorithmVersion: string;
  weightsUsed: Record<BenchmarkCategoryKey, number>;
  equivalenceEnvironment: BenchmarkProfileConfig['equivalenceEnvironment'];
  environmentEquivalent: boolean;
  progress?: BenchmarkRunProgress;
  scoreCards: SoftwareScoreCard[];
  toolExecutions: ToolExecutionRecord[];
  veracityResults: VeracityCheckResult[];
  findings: NormalizedFinding[];
  architectureGraphs: ArchitectureGraphData[];
  functionalMatrix: FunctionalEquivalenceRow[];
  sandboxDiffs: WindowsSandboxSnapshotDiff[];
  evidenceChain: EvidenceRecord[];
  winnerSoftwareId: string | null;
  qualityGate?: {
    status: 'PASSED' | 'FAILED' | 'WARN';
    conditionsMet: number;
    conditionsFailed: number;
    failedMetrics: string[];
  };
  ratings?: {
    reliability: 'A' | 'B' | 'C' | 'D' | 'E';
    security: 'A' | 'B' | 'C' | 'D' | 'E';
    maintainability: 'A' | 'B' | 'C' | 'D' | 'E';
  };
  executiveSummary: string;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  actor: string;
  role: 'ADMIN' | 'SECURITY_LEAD' | 'AUDITOR' | 'QA_ENGINEER';
  action: string;
  entityType: string;
  entityId: string;
  details: string;
  integrityHash: string;
}

export type VulnerabilityValidationState =
  | 'CONFIRMADA'
  | 'PROVAVEL'
  | 'FALSO_POSITIVO'
  | 'NAO_REPRODUZIVEL'
  | 'INCONCLUSIVA'
  | 'NAO_TESTADA';

export type SecurityAssessmentModuleKey =
  | 'SECURITY_ASSESSMENT'
  | 'AUTOMATED_PENTEST'
  | 'RED_TEAM_SIMULATION'
  | 'ATTACK_SURFACE_ANALYSIS'
  | 'VULNERABILITY_VALIDATION'
  | 'ATTACK_PATH_ANALYSIS'
  | 'API_SECURITY_TESTING'
  | 'AUTH_AUTHZ_TESTING'
  | 'DATABASE_SECURITY_ASSESSMENT'
  | 'CRYPTOGRAPHY_ASSESSMENT'
  | 'DEPENDENCY_SUPPLY_CHAIN'
  | 'STRESS_RESILIENCE_TESTING'
  | 'WINDOWS_SECURITY_ASSESSMENT'
  | 'EVIDENCE_COLLECTION'
  | 'SECURITY_BENCHMARK_COMPARISON';

export interface StandardizedExecutionRecord {
  id: string;
  sha256: string;
  softwareId: string;
  softwareName: string;
  softwareVersion: string;
  environmentDescriptor: string;
  configurationHash: string;
  toolId: string;
  toolName: string;
  toolVersion: string;
  moduleKey: SecurityAssessmentModuleKey;
  scenarioExecuted: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  resultStatus: 'EXECUTED_VALIDATED' | 'TOOL_NOT_INSTALLED' | 'OUT_OF_SCOPE_BLOCKED' | 'ABORTED_EMERGENCY' | 'INCONCLUSIVE';
  technicalEvidence: string;
  logs: string[];
  severity: SeverityLevel;
  impactDescription: string;
  reproducibility: 'ALTA_DETERMINISTICA' | 'MEDIA_CONDICIONAL' | 'BAIXA' | 'NAO_REPRODUZIVEL';
  validationState: VulnerabilityValidationState;
  reexecutionHistory: Array<{
    timestamp: string;
    actor: string;
    previousState: VulnerabilityValidationState;
    newState: VulnerabilityValidationState;
    verificationNote: string;
    evidenceHash: string;
  }>;
}

export interface AttackSurfaceProfile {
  softwareId: string;
  softwareName: string;
  exposedEntryPoints: string[];
  publicApisAndControllers: string[];
  databaseConnectors: string[];
  externalProcessInvocations: string[];
  networkEndpoints: string[];
  privilegedOperations: string[];
  surfaceRiskIndex: number; // 0.00 (Mínima exposição) a 10.00 (Exposição crítica)
}

export interface AttackPathNode {
  stepOrder: number;
  layer: 'ENTRY_POINT' | 'CONTROLLER_UI' | 'SERVICE_DOMAIN' | 'PERSISTENCE_OS_SINK';
  component: string;
  filePath: string;
  lineNumber: number;
  weaknessCwe: string;
  evidenceSnippet: string;
}

export interface AttackPathChain {
  id: string;
  softwareId: string;
  softwareName: string;
  title: string;
  severity: SeverityLevel;
  validationState: VulnerabilityValidationState;
  reproducibilityEase: 'ALTA' | 'MEDIA' | 'BAIXA';
  potentialImpact: string;
  nodes: AttackPathNode[];
  mitigationControl: string;
  evidenceSha256: string;
}

export interface ExecutionSandboxControl {
  isolationMode: 'DISPOSABLE_MICROVM' | 'RESTRICTED_CONTAINER' | 'WINDOWS_SANDBOX';
  scopeAllowlist: string[];
  networkPolicy: 'AIRGAPPED_NONE' | 'ALLOWLIST_ONLY';
  cpuLimitCores: number;
  memoryLimitMb: number;
  timeoutSeconds: number;
  snapshotBaselineId: string;
  recoveryVerified: boolean;
  emergencyStopTriggered: boolean;
  emergencyStopAt?: string | null;
  emergencyStopActor?: string | null;
}

export interface SoftwareSecurityComparisonMetrics {
  softwareId: string;
  softwareName: string;
  softwareVersion: string;
  vulnerabilitiesFound: number;
  vulnerabilitiesConfirmed: number;
  vulnerabilitiesProbable: number;
  falsePositivesCount: number;
  inconclusiveCount: number;
  notTestedCount: number;
  reproducibilityScore: number;
  potentialImpactIndex: number;
  testCoveragePercent: number;
  comparisonConfidencePercent: number;
  totalExecutionTimeMs: number;
  securityFailuresCount: number;
  recoveryCapabilityScore: number; // 0.00 a 5.00
  performanceUnderStressScore: number; // 0.00 a 5.00
  overallSecurityMaturityScore: number; // 0.00 a 5.00
}

export interface SecurityAssessmentSuiteBundle {
  runId: string;
  evaluatedAt: string;
  sandboxControl: ExecutionSandboxControl;
  modulesCatalog: Array<{
    key: SecurityAssessmentModuleKey;
    title: string;
    status: 'OPERATIONAL' | 'PARTIAL_COVERAGE' | 'EXTERNAL_TOOL_REQUIRED';
    coveragePercent: number;
  }>;
  attackSurfaces: AttackSurfaceProfile[];
  attackPaths: AttackPathChain[];
  executionRecords: StandardizedExecutionRecord[];
  comparisonMetrics: SoftwareSecurityComparisonMetrics[];
}

// ============================================================================
// SONARQUBE COMMUNITY BUILD, CLOUD, IDE & GITAR AI INTEGRATION TYPES
// ============================================================================

export type SonarConnectionState =
  | 'NOT_INSTALLED'
  | 'NOT_CONFIGURED'
  | 'CONNECTING'
  | 'CONNECTED'
  | 'AUTH_FAILED'
  | 'SERVER_UNAVAILABLE'
  | 'VERSION_UNSUPPORTED'
  | 'READY'
  | 'RUNNING'
  | 'ERROR';

export type SonarInstallationMode = 'LOCAL' | 'REMOTE' | 'CLOUD';

export type SonarScannerType =
  | 'SONAR_SCANNER_MAVEN'
  | 'SONAR_SCANNER_GRADLE'
  | 'SONAR_SCANNER_DOTNET'
  | 'SONAR_SCANNER_NPM'
  | 'SONAR_SCANNER_PYTHON'
  | 'SONAR_SCANNER_CLI';

export interface SonarVersionMetadata {
  id: string;
  productName: 'SonarQube Community Build' | 'SonarScanner CLI';
  version: string;
  buildNumber: string;
  releaseDate: string;
  architecture: string;
  operatingSystem: string;
  downloadUrl: string;
  officialPortalUrl: string;
  releaseNotesUrl: string;
  sizeBytes: number;
  officialSha256: string | null;
  calculatedSha256: string | null;
  checksumSource: 'OFFICIAL_SONARSOURCE_SHA256' | 'LOCAL_COMPUTED_ONLY';
  validationResult: 'VALIDATED_MATCH' | 'HASH_MISMATCH' | 'METADATA_VERIFIED_PENDING_BINARY' | 'NOT_DOWNLOADED';
  minimumRequirements: {
    javaVersion: string;
    minRamMb: number;
    minCpuCores: number;
    minDiskGb: number;
    maxMapCount: number;
    fileMax: number;
  };
  checkedAt: string;
}

export interface SonarInstallationRecord {
  id: string;
  productName: string;
  version: string;
  installDirectory: string;
  operatingSystem: string;
  architecture: string;
  downloadOriginUrl: string;
  installedAt: string | null;
  archiveSizeBytes: number;
  calculatedSha256: string | null;
  officialSha256: string | null;
  validationStatus: 'VALIDATED' | 'NOT_INSTALLED_IN_CONTAINER' | 'CHECKSUM_FAILED' | 'READY_ON_HOST';
  hostCompatibility: {
    internetAccess: boolean;
    officialDownloadReachable: boolean;
    processExecutionAllowed: boolean;
    serviceInstallationAllowed: boolean;
    filePersistenceAllowed: boolean;
    javaRuntimeAvailable: boolean;
    javaVersionDetected: string | null;
    ramAvailableMb: number;
    cpuCoresDetected: number;
    diskFreeGb: number;
    vmMaxMapCountSufficient: boolean;
    canRunLocalServerInCurrentEnv: boolean;
    blockingReasons: string[];
    hostExecutionInstructions: string[];
  };
  scriptsGenerated: {
    windowsPowerShell: string;
    linuxBash: string;
    verificationScript: string;
  };
}

export interface SonarInstanceRecord {
  id: string;
  name: string;
  mode: SonarInstallationMode;
  serverUrl: string;
  port: number;
  organizationKey?: string;
  hasTokenConfigured: boolean;
  maskedToken: string;
  tokenExpiresAt: string | null;
  connectionState: SonarConnectionState;
  version: string | null;
  edition: 'Community Build' | 'SonarQube Cloud' | 'Developer/Enterprise (Não utilizado)' | null;
  apiCompatibility: 'WEB_API_V2_AND_V1' | 'WEB_API_V1_LEGACY' | 'UNSUPPORTED' | 'UNKNOWN';
  lastVerifiedAt: string | null;
  lastErrorMessage: string | null;
  permissionsVerified: {
    browse: boolean;
    executeAnalysis: boolean;
    administerQualityGates: boolean;
    provisioning: boolean;
  };
}

export interface SonarScannerRecord {
  id: string;
  scannerType: SonarScannerType;
  displayName: string;
  version: string;
  targetEcosystem: string;
  binaryDetected: boolean;
  executablePath: string;
  downloadUrl: string;
  officialSha256: string;
  cachedInToolsDir: boolean;
  lastUsedAt: string | null;
}

export interface SonarProjectRecord {
  id: string;
  instanceId: string;
  softwareId: string;
  softwareName: string;
  softwareRole: 'SOFTWARE_A' | 'SOFTWARE_B';
  projectKey: string;
  projectName: string;
  branch: string;
  commitHash: string;
  softwareVersion: string;
  scmFullCloneAvailable: boolean;
  scmLimitationWarning: string | null;
  qualityProfileKey: string;
  qualityProfileName: string;
  qualityGateName: string;
  scannerSelected: SonarScannerType;
  scannerPropertiesUsed: Record<string, string>;
  exclusionReasonsRecorded: string[];
  createdAt: string;
  lastAnalysisAt: string | null;
}

export interface SonarTaskRecord {
  id: string;
  executionId: string;
  ceTaskId: string;
  instanceId: string;
  projectKey: string;
  softwareId: string;
  status: 'PENDING' | 'IN_PROGRESS' | 'SUCCESS' | 'FAILED' | 'CANCELED';
  submittedAt: string;
  startedAt: string | null;
  completedAt: string | null;
  executionTimeMs: number;
  pollAttempts: number;
  backoffStrategy: string;
  errorCode: string | null;
  errorMessage: string | null;
  analysisId: string | null;
  evidenceSha256: string;
}

export interface SonarMeasuresRecord {
  id: string;
  analysisId: string;
  projectKey: string;
  softwareId: string;
  softwareName: string;
  commitHash: string;
  measuredAt: string;
  metrics: {
    bugs: number;
    vulnerabilities: number;
    securityHotspots: number;
    securityHotspotsReviewedPercent: number;
    codeSmells: number;
    cyclomaticComplexity: number;
    cognitiveComplexity: number;
    duplicatedLinesDensityPercent: number;
    duplicatedBlocks: number;
    duplicatedLines: number;
    ncloc: number;
    technicalDebtMinutes: number;
    maintainabilityRating: 'A' | 'B' | 'C' | 'D' | 'E';
    reliabilityRating: 'A' | 'B' | 'C' | 'D' | 'E';
    securityRating: 'A' | 'B' | 'C' | 'D' | 'E';
    coveragePercent: number | null;
    linesToCover: number;
    uncoveredLines: number;
    conditionsToCover: number;
    newCodeCoveragePercent: number | null;
    coverageReportSource: string;
  };
  rawApiResponseHash: string;
}

export interface SonarIssueRecord {
  id: string;
  issueKey: string;
  analysisId: string;
  projectKey: string;
  softwareId: string;
  softwareName: string;
  type: 'BUG' | 'VULNERABILITY' | 'CODE_SMELL' | 'SECURITY_HOTSPOT';
  severity: 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';
  ruleKey: string;
  ruleName: string;
  isExternalImportedRule: boolean;
  externalOriginTool: string | null;
  externalOriginVersion: string | null;
  originalRuleId: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  filePath: string;
  lineNumber: number;
  message: string;
  effortMinutes: number;
  remediationGuidance: string;
  hotspotReviewStatus?: 'TO_REVIEW' | 'REVIEWED_SAFE' | 'REVIEWED_FIXED' | 'REVIEWED_ACKNOWLEDGED';
  evidenceSnippet: string;
  evidenceSha256: string;
}

export interface SonarQualityGateCondition {
  metricKey: string;
  metricLabel: string;
  comparator: 'GT' | 'LT' | 'EQ' | 'NE';
  errorThreshold: string;
  actualValue: string;
  status: 'OK' | 'ERROR' | 'WARN';
}

export interface SonarQualityGateRecord {
  id: string;
  analysisId: string;
  projectKey: string;
  softwareId: string;
  softwareName: string;
  gateName: string;
  status: 'OK' | 'ERROR' | 'WARN' | 'NONE';
  displayLabel: 'APROVADO' | 'REPROVADO' | 'ALERTA' | 'NÃO AVALIADO';
  conditionsMetCount: number;
  conditionsFailedCount: number;
  failedMetrics: string[];
  conditions: SonarQualityGateCondition[];
  evaluatedAt: string;
}

export interface SonarQualityProfileRecord {
  id: string;
  key: string;
  name: string;
  language: string;
  activeRulesCount: number;
  isDefault: boolean;
  updatedAt: string;
}

export interface SonarAnalysisRecord {
  id: string;
  runId: string;
  instanceId: string;
  projectKey: string;
  softwareId: string;
  softwareName: string;
  softwareVersion: string;
  commitHash: string;
  scannerUsed: SonarScannerType;
  scannerVersion: string;
  sonarVersion: string;
  qualityProfileName: string;
  qualityGateStatus: 'OK' | 'ERROR' | 'WARN' | 'NONE';
  startedAt: string;
  completedAt: string;
  status: 'COMPLETED' | 'FAILED' | 'CACHED_REUSED';
  cacheHit: boolean;
  cacheKeySha256: string;
  measuresId: string;
  qualityGateId: string;
  issuesCount: number;
  externalIssuesImportedCount: number;
  evidenceSha256: string;
}

export interface SonarExecutionLogRecord {
  id: string;
  timestamp: string;
  component: 'SONAR_SERVER' | 'SONAR_SCANNER' | 'SONAR_WEB_API' | 'SONAR_CLOUD' | 'LIFECYCLE_MANAGER' | 'GITAR_AI';
  level: 'INFO' | 'WARN' | 'ERROR';
  action: string;
  message: string;
  redactedTokenSafe: boolean;
}

// Gitar AI Integration Types (Section 9)
export type GitarConnectionState =
  | 'NOT_CONFIGURED'
  | 'CONNECTING'
  | 'CONNECTED'
  | 'AUTH_FAILED'
  | 'PROVIDER_UNAVAILABLE'
  | 'ERROR';

export type GitProviderType = 'GITHUB' | 'GITLAB' | 'BITBUCKET' | 'AZURE_DEVOPS';

export interface GitarIntegrationRecord {
  id: string;
  connectionState: GitarConnectionState;
  gitProvider: GitProviderType;
  apiBaseUrl: string;
  hasApiToken: boolean;
  maskedToken: string;
  explicitExternalCodeConsent: boolean;
  authorizedRepositories: string[];
  ciIntegrationsEnabled: Array<'GitHub Actions' | 'GitLab CI' | 'Bitbucket Pipelines' | 'Azure Pipelines'>;
  safetyPolicies: {
    allowDirectModificationOfOriginalFiles: false;
    autoApplyFixes: boolean;
    autoApprovePr: boolean;
    autoMergePr: boolean;
    isolatedWorkingBranchPrefix: string;
    requireHumanApprovalBeforeApply: true;
    reRunTestsAfterApprovedFix: true;
  };
  lastHealthCheckAt: string | null;
  lastErrorMessage: string | null;
}

export interface GitarReviewFinding {
  id: string;
  softwareId: string;
  softwareName: string;
  repository: string;
  pullRequestNumber: number;
  branchName: string;
  originalCommitHash: string;
  category: 'BUG' | 'SECURITY' | 'PERFORMANCE' | 'QUALITY' | 'CI_FAILURE' | 'CROSS_REPO_IMPACT';
  severity: SeverityLevel;
  title: string;
  description: string;
  filePath: string;
  lineNumber: number;
  originMethodology: 'GITAR_AST_PR_AGENT' | 'GITAR_CI_LOG_CORRELATOR';
  deduplicatedWithSonarIssueKey: string | null;
  proposedFix: {
    patchId: string;
    isolatedBranch: string;
    explanation: string;
    beforeSnippet: string;
    afterSnippet: string;
    humanApprovalStatus:
      | 'PENDING_HUMAN_APPROVAL'
      | 'APPROVED_BY_HUMAN'
      | 'REJECTED_BY_HUMAN'
      | 'VERIFIED_RESOLVED'
      | 'PERSISTENT_FAILURE';
    approvedBy: string | null;
    approvedAt: string | null;
    retestExecuted: boolean;
    retestResultSummary: string | null;
  } | null;
  createdAt: string;
  evidenceSha256: string;
}

export interface GitarCiFailureRecord {
  id: string;
  softwareId: string;
  softwareName: string;
  repository: string;
  pipelineId: string;
  ciPlatform: 'GitHub Actions' | 'GitLab CI' | 'Bitbucket Pipelines' | 'Azure Pipelines';
  branch: string;
  commitHash: string;
  failedStage: string;
  rootCauseSummary: string;
  correlatedFilePath: string;
  remediationSuggested: string;
  status: 'DIAGNOSED' | 'FIX_PROPOSED_IN_ISOLATED_BRANCH' | 'VERIFIED_PASSING' | 'PERSISTENT_FAILURE';
  detectedAt: string;
}

export interface SonarABComparisonResult {
  comparisonId: string;
  comparedAt: string;
  equivalenceVerified: boolean;
  equivalenceNotes: string[];
  sharedConditions: {
    sonarVersion: string;
    scannerVersion: string;
    qualityProfile: string;
    qualityGate: string;
    coverageCriteria: string;
    newCodeDefinition: string;
    executionOrder: 'SEQUENTIAL_SHARED_INSTANCE';
  };
  softwareA: {
    project: SonarProjectRecord;
    measures: SonarMeasuresRecord['metrics'];
    qualityGate: SonarQualityGateRecord;
    nativeSonarScore: number; // 0.00 - 5.00 derived strictly from Sonar ratings
    benchmarkCompositeScore: number; // 0.00 - 5.00 calculated by Benchmark Analyzer
    externalIssuesCount: number;
    nativeIssuesCount: number;
  };
  softwareB: {
    project: SonarProjectRecord;
    measures: SonarMeasuresRecord['metrics'];
    qualityGate: SonarQualityGateRecord;
    nativeSonarScore: number;
    benchmarkCompositeScore: number;
    externalIssuesCount: number;
    nativeIssuesCount: number;
  };
  indicatorClassification: Array<{
    metricKey: string;
    label: string;
    sourceType: 'SONARQUBE_NATIVE' | 'BENCHMARK_CALCULATED' | 'EXTERNAL_TEST_REPORT_IMPORTED';
    softwareAValue: string | number;
    softwareBValue: string | number;
    betterSoftware: 'SOFTWARE_A' | 'SOFTWARE_B' | 'TIE' | 'NOT_COLLECTED';
  }>;
}

export interface IntegrationTestStepResult {
  stepNumber: number;
  name: string;
  category: 'CORE_PIPELINE' | 'FAULT_INJECTION' | 'GITAR_VALIDATION';
  status: 'PASSED' | 'SKIPPED_HOST_DEPENDENT' | 'EXPECTED_ERROR_HANDLED' | 'FAILED';
  stateProduced: string;
  durationMs: number;
  evidenceSummary: string;
  sha256: string;
}

export interface ResourceOptimizationReport {
  measuredAt: string;
  beforeOptimization: {
    startupTimeMs: number;
    frontendBundleSizeKb: number;
    frontendInitialChunkKb: number;
    frontendChunksCount: number;
    buildTimeMs: number;
    initialPageApiRequestsCount: number;
    initialPayloadSizeKb: number;
    backendMemoryRssMb: number;
    backendHeapUsedMb: number;
    cpuIdlePercent: number;
    cpuDuringAnalysisPercent: number;
    activeProcessesCount: number;
    diskUsageKb: number;
    cacheSizeKb: number;
    benchmarkExecutionTimeMs: number;
  };
  afterOptimization: {
    startupTimeMs: number;
    frontendBundleSizeKb: number;
    frontendInitialChunkKb: number;
    frontendChunksCount: number;
    buildTimeMs: number;
    initialPageApiRequestsCount: number;
    initialPayloadSizeKb: number;
    backendMemoryRssMb: number;
    backendHeapUsedMb: number;
    cpuIdlePercent: number;
    cpuDuringAnalysisPercent: number;
    activeProcessesCount: number;
    diskUsageKb: number;
    cacheSizeKb: number;
    benchmarkExecutionTimeMs: number;
    cacheHitTimeMs: number;
  };
  externalToolsSeparation: {
    mainAppMemoryRssMb: number;
    sonarServerLocalProcessRunning: boolean;
    sonarServerMemoryMb: number;
    activeScannersMemoryMb: number;
    idleAutoShutdownMinutes: number;
    maxConcurrentSonarAnalyses: number;
  };
  uncollectedMetricsNotes: string[];
}

export interface SonarAndToolsDatabaseBundle {
  sonar_instances: SonarInstanceRecord[];
  sonar_installations: SonarInstallationRecord[];
  sonar_versions: SonarVersionMetadata[];
  sonar_scanners: SonarScannerRecord[];
  sonar_projects: SonarProjectRecord[];
  sonar_analyses: SonarAnalysisRecord[];
  sonar_tasks: SonarTaskRecord[];
  sonar_issues: SonarIssueRecord[];
  sonar_measures: SonarMeasuresRecord[];
  sonar_quality_gates: SonarQualityGateRecord[];
  sonar_quality_profiles: SonarQualityProfileRecord[];
  sonar_integrations: {
    vscodeConnectedMode: {
      configured: boolean;
      extensionDetected: boolean;
      bindingMode: 'COMMUNITY_BUILD' | 'SERVER' | 'CLOUD' | 'NOT_BOUND';
      sharedQualityProfileKey: string;
      generatedSettingsJson: string;
    };
    externalToolsSupported: Array<{
      toolId: string;
      toolName: string;
      sarifSupported: boolean;
      sonarPropertyKey: string;
      importedIssuesCount: number;
    }>;
  };
  sonar_execution_logs: SonarExecutionLogRecord[];
  gitar_integration: GitarIntegrationRecord;
  gitar_reviews: GitarReviewFinding[];
  gitar_ci_failures: GitarCiFailureRecord[];
  ab_comparisons: SonarABComparisonResult[];
  integration_test_results: IntegrationTestStepResult[];
  optimization_report: ResourceOptimizationReport;
}


