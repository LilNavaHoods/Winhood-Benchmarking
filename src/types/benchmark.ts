export type AppEnvironment = 'PRODUCTION' | 'DEMO' | 'TEST' | 'DEVELOPMENT';

export type SourceIngestionState =
  | 'METADATA_ONLY'
  | 'SOURCE_IMPORTED'
  | 'SOURCE_PARTIAL'
  | 'SOURCE_VALIDATED'
  | 'SOURCE_FAILED'
  | 'DEMO_FIXTURE'
  | 'TEST_FIXTURE'
  | 'PUBLIC_DOCUMENTATION_ONLY';

export type SourceAvailabilityKind =
  | 'FULL_SOURCE'
  | 'PARTIAL_SOURCE'
  | 'PUBLIC_DOCUMENTATION_ONLY'
  | 'CLOSED_SOURCE'
  | 'RUNTIME_ACCESS'
  | 'MANUAL_ASSESSMENT';

export type DataOrigin =
  | 'USER_SOURCE'
  | 'GITHUB_SOURCE'
  | 'GITLAB_SOURCE'
  | 'EXTERNAL_TOOL'
  | 'OFFICIAL_MARKET_SOURCE'
  | 'DEMO_FIXTURE'
  | 'TEST_FIXTURE'
  | 'INTERNAL_MEASUREMENT'
  | 'STATIC_ANALYSIS'
  | 'METADATA_ONLY'
  | 'PUBLIC_DOCUMENTATION_ONLY';

export type ExecutionMode =
  | 'REAL_STATIC_ANALYSIS'
  | 'REAL_RUNTIME_TEST'
  | 'REAL_EXTERNAL_TOOL'
  | 'REAL_MARKET_RESEARCH'
  | 'CONTRACT_SIMULATION'
  | 'DEMONSTRATION'
  | 'MANUAL_ASSESSMENT';

export type AssessmentMode = 'INDIVIDUAL' | 'AB_COMPARE' | 'MARKET_COMPETITOR';

export type CategoryAssessmentStatus =
  | 'ASSESSED'
  | 'PARTIAL'
  | 'NOT_ASSESSED'
  | 'NOT_APPLICABLE'
  | 'NOT_COMPARABLE'
  | 'INCONCLUSIVE'
  | 'INSUFFICIENT_COVERAGE'
  | 'FAILED_VALIDATION';

export interface SourceManifest {
  softwareId: string;
  sourceType: string;
  sourceUrl: string;
  branch: string;
  commitSha: string;
  treeSha: string;
  artifactSha256: string;
  importedAt: string;
  ingestionState?: SourceIngestionState;
  sourceAvailability?: SourceAvailabilityKind;
  importStatus:
    | 'DISCOVERING'
    | 'FETCHING'
    | 'VALIDATING'
    | 'COMPLETE'
    | 'PARTIAL'
    | 'FAILED'
    | 'AUTHENTICATION_FAILED'
    | 'RATE_LIMITED'
    | 'UNSUPPORTED_CONTENT'
    | 'SOURCE_MISSING';
  filesDiscovered?: number;
  filesReceived?: number;
  filesEligible?: number;
  filesAnalyzed?: number;
  filesIgnored?: number;
  filesExcluded?: number;
  filesFailed?: number;
  filesPartiallyProcessed?: number;
  unsupportedFiles?: number;
  discoveredFilesCount?: number;
  ingestedFilesCount?: number;
  analyzedFilesCount?: number;
  excludedFilesCount?: number;
  failedFilesCount?: number;
  totalBytes?: number;
  sourceProvider?: string;
  authenticationMode?: string;
  provenanceEvidence: string;
  failureReasons?: string[];
}

export type VeracityClassification =
  | 'NOT_AVAILABLE'
  | 'NOT_INSTALLED'
  | 'NOT_CONFIGURED'
  | 'NOT_AUTHORIZED'
  | 'NOT_EXECUTED'
  | 'QUEUED'
  | 'RUNNING'
  | 'SUCCESS_VALIDATED'
  | 'SUCCESS_WITH_WARNINGS'
  | 'PARTIAL'
  | 'INCOMPLETE_COVERAGE'
  | 'EMPTY_ERROR'
  | 'EXECUTION_FAILED'
  | 'TOOL_NOT_INSTALLED'
  | 'TOOL_NOT_CONFIGURED'
  | 'AUTHENTICATION_FAILED'
  | 'INVALID_OUTPUT'
  | 'PARSING_ERROR'
  | 'TIMEOUT'
  | 'CANCELLED'
  | 'NOT_SUPPORTED'
  | 'CONTRACT_SIMULATION'
  | 'SOURCE_MISSING';

export type SeverityLevel = 'BLOCKER' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type SoftwareQualityAttribute = 'SECURITY' | 'RELIABILITY' | 'MAINTAINABILITY';

export type CleanCodeAttribute = 'CONSISTENT' | 'INTENTIONAL' | 'ADAPTABLE' | 'RESPONSIBLE';

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

export interface CodeExecutionFlowStep {
  stepOrder: number;
  stepIndex?: number;
  nodeType: 'SOURCE' | 'PROPAGATOR' | 'SANITIZER_MISSING' | 'SINK';
  nodeKind?: 'SOURCE' | 'PROPAGATOR' | 'SANITIZER_MISSING' | 'SINK';
  filePath: string;
  lineNumber: number;
  endLineNumber?: number;
  columnStart?: number;
  columnEnd?: number;
  symbolName: string;
  codeSnippet: string;
  contextBefore?: string[];
  contextAfter?: string[];
  explanation: string;
}

export interface MqrCategoryImpact {
  softwareQuality: SoftwareQualityAttribute;
  qualityAttribute?: SoftwareQualityAttribute;
  benchmarkCategory: BenchmarkCategoryKey;
  category?: BenchmarkCategoryKey;
  severity: SeverityLevel;
  scoreDeduction: number;
  rationale: string;
}

export interface CategoryEvaluationReason {
  id: string;
  category: BenchmarkCategoryKey;
  impactType: 'PENALTY' | 'BONUS' | 'CAP_APPLIED' | 'METRIC_THRESHOLD';
  originType?: 'PENALTY' | 'BONUS' | 'CAP_APPLIED' | 'METRIC_THRESHOLD' | 'FINDING_PENALTY';
  toolName?: string;
  scoreDelta: number;
  severity: SeverityLevel;
  ruleId: string;
  cwe?: string;
  cve?: string;
  title: string;
  whyExplanation: string;
  filePath?: string;
  lineNumber?: number;
  endLineNumber?: number;
  columnStart?: number;
  columnEnd?: number;
  codeSnippet?: string;
  contextBefore?: string[];
  contextAfter?: string[];
  executionFlow?: CodeExecutionFlowStep[];
  remediationSummary?: string;
  compliantCodeExample?: string;
  remediationEffortMinutes?: number;
  findingId?: string;
}

export interface Project {
  id: string;
  name: string;
  category?: string;
  domainTags?: string[];
  defaultQualityProfileIds?: string[];
  defaultQualityGateId?: string;
  enabledCategories?: BenchmarkCategoryKey[];
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

export type FindingValidationLifecycleState =
  | 'VALIDATED'
  | 'ACCEPTED'
  | 'FALSE_POSITIVE_REVIEWED'
  | 'CORRELATED_DEDUPLICATED'
  | 'UNVERIFIED'
  | 'CONFIRMED'
  | 'PROBABLE'
  | 'FALSE_POSITIVE'
  | 'INCONCLUSIVE'
  | 'NOT_REPRODUCIBLE'
  | 'NOT_TESTED'
  | 'ACCEPTED_RISK'
  | 'FIXED_PENDING_RETEST'
  | 'VERIFIED_RESOLVED';

export type CriterionVerificationMethod =
  | 'STATIC_ANALYSIS'
  | 'AST_ANALYSIS'
  | 'FUNCTIONAL_TEST'
  | 'RUNTIME_TEST'
  | 'PERFORMANCE_TEST'
  | 'EXTERNAL_TOOL'
  | 'MANUAL_ASSESSMENT'
  | 'DOCUMENTATION_REVIEW'
  | 'CONTRACT_VALIDATION';

export interface EvaluationCriterionDefinition {
  id: string;
  name: string;
  description: string;
  domain: string;
  dimension: BenchmarkCategoryKey;
  objective: string;
  verificationMethod: CriterionVerificationMethod;
  requiredTools: string[];
  prerequisites: string[];
  applicabilityConditions: string[];
  mandatoryEvidence: string[];
  interpretationRule: string;
  severity: SeverityLevel;
  weight: number;
  scoringRule: string;
  version: string;
  maintenanceState: 'ACTIVE' | 'DEPRECATED' | 'EXPERIMENTAL';
  knownLimitations: string[];
}

export interface CriterionEvaluationOutcome {
  criterionId: string;
  criterionName: string;
  dimension: BenchmarkCategoryKey;
  domain: string;
  verificationMethod: CriterionVerificationMethod;
  status:
    | 'PASSED_VALIDATED'
    | 'FAILED_VALIDATED'
    | 'INCONCLUSIVE'
    | 'NOT_VERIFIED'
    | 'NOT_APPLICABLE'
    | 'NOT_EXECUTED';
  verificationLevel:
    | 'VALIDATED_BY_TEST'
    | 'IMPLEMENTATION_FOUND'
    | 'POTENTIAL_IMPLEMENTATION'
    | 'NOT_FOUND'
    | 'NOT_APPLICABLE'
    | 'INCONCLUSIVE';
  scoreImpact: number;
  evidenceSummary: string;
  evidenceReferences: string[];
  limitations: string[];
  evaluatedAt: string;
}

export interface DomainSpecializedProfile {
  id: string;
  name: string;
  domainKey: string;
  profileKind: 'GENERAL_DIMENSION' | 'DOMAIN_SPECIALIZED';
  profileType?: 'GENERAL_DIMENSION' | 'DOMAIN_SPECIALIZED';
  description: string;
  recommendedCategories: BenchmarkCategoryKey[];
  enabledCategories: BenchmarkCategoryKey[];
  notApplicableCategories: BenchmarkCategoryKey[];
  weights: Record<BenchmarkCategoryKey, number>;
  requiredCriteriaIds: string[];
  specializedChecks: string[];
  targetApplications: string[];
}

export interface DimensionComparabilityEntry {
  category: BenchmarkCategoryKey;
  comparable: boolean;
  status: 'COMPARABLE' | 'PARTIALLY_COMPARABLE' | 'NOT_COMPARABLE' | 'NOT_APPLICABLE';
  coverageBySoftware: Record<string, number>;
  sourceAvailabilityBySoftware: Record<string, SourceAvailabilityKind>;
  commonCriteriaCount: number;
  notes: string;
}

export interface ComparabilityReport {
  overallComparable: boolean;
  overallStatus?: 'COMPARABLE' | 'PARTIALLY_COMPARABLE' | 'INCONCLUSIVE_COMPARISON' | 'NOT_COMPARABLE';
  canDeclareOfficialWinner: boolean;
  domainCompatible: boolean;
  objectiveCompatible: boolean;
  scopeCompatible: boolean;
  methodologyCompatible: boolean;
  environmentCompatible: boolean;
  sourceAvailabilityCompatible: boolean;
  algorithmVersionMatches: boolean;
  blockingReasons: string[];
  warnings: string[];
  sourceAvailabilityBySoftware: Record<string, SourceAvailabilityKind>;
  dimensionMatrix: DimensionComparabilityEntry[];
}

export interface SignedEvidenceManifest {
  manifestId: string;
  runId: string;
  algorithmVersion: string;
  generatedAt: string;
  recordsCount: number;
  genesisHash: string;
  merkleOrChainRootSha256: string;
  rootChainSha256?: string;
  manifestPayloadSha256: string;
  digitalSignatureHmacSha256: string;
  hmacSignature?: string;
  signatureAlgorithm?: 'HMAC-SHA256';
  signingKeyId: string;
  keyId?: string;
  authenticityProofType: 'HMAC_SHA256_PROTECTED_SERVER_KEY';
  integrityNote: string;
  verified: boolean;
}

export interface PreAnalysisSummary {
  softwareId: string;
  softwareName: string;
  softwareVersion: string;
  ingestionState: SourceIngestionState;
  sourceAvailability: SourceAvailabilityKind;
  integrityVerified: boolean;
  calculatedPackageSha256: string;
  filesDiscovered: number;
  filesReceived: number;
  filesEligible: number;
  eligibleFiles: number;
  totalFiles: number;
  totalLinesOfCode: number;
  filesIgnored: number;
  filesUnsupported: number;
  availableTools: string[];
  missingTools: string[];
  applicableCriteriaCount: number;
  verifiableCriteriaCount: number;
  notApplicableCriteriaCount: number;
  nonExecutableCriteriaCount: number;
  notApplicableCategories: BenchmarkCategoryKey[];
  inferredDomain: string;
  recommendedProfileName: string;
  requiresFormalAuthorization: boolean;
  limitations: string[];
  warnings: string[];
  estimatedPotentialCoveragePercent: number;
}

export interface Software {
  id: string;
  projectId: string;
  name: string;
  vendor: string;
  description: string;
  category?: string;
  domainTags?: string[];
  functionalDomain?: string;
  defaultQualityProfileIds?: string[];
  defaultQualityGateId?: string;
  enabledCategories?: BenchmarkCategoryKey[];
  version: string;
  languages: string[];
  architecture: string;
  operatingSystem: string;
  distributionModel: string;
  licenseType: string;
  officialUrl: string;
  repositoryUrl: string;
  repoUrl?: string;
  documentationUrl: string;
  owner: string;
  notes: string;
  sourceType:
    | 'GIT_REPO'
    | 'GIT_REPOSITORY'
    | 'ARCHIVE'
    | 'LOCAL_AUTHORIZED'
    | 'LOCAL_UPLOAD'
    | 'COMPILED_BINARY'
    | 'CONTAINER'
    | 'EXECUTION_ENV'
    | 'PUBLIC_DOCUMENTATION_ONLY'
    | 'METADATA_ONLY';
  ingestionState?: SourceIngestionState;
  sourceIngestionState?: SourceIngestionState;
  sourceAvailability?: SourceAvailabilityKind;
  gitProvider?: string;
  commitHash: string;
  packageSha256: string;
  sourceHash?: string;
  verifiedSha256?: string;
  createdAt: string;
  updatedAt?: string;
  dataOrigin?: DataOrigin;
  executionMode?: ExecutionMode;
  sourceManifest?: Partial<SourceManifest> & {
    discoveredFilesCount?: number;
    ingestedFilesCount?: number;
    analyzedFilesCount?: number;
    excludedFilesCount?: number;
    failedFilesCount?: number;
    totalBytes?: number;
    provenanceEvidence: string;
  };
  isMarketCompetitor?: boolean;
  competitorCandidate?: MarketCompetitorCandidate;
  competitorMetadata?: {
    isOpenSource: boolean;
    approvedByUser: boolean;
    similarityScore?: number;
  };
  inventory: {
    totalFiles: number;
    discoveredFilesCount?: number;
    receivedFilesCount?: number;
    eligibleFiles: number;
    analyzedFilesCount?: number;
    ignoredFilesCount?: number;
    excludedFilesCount?: number;
    unsupportedFilesCount?: number;
    errorFilesCount?: number;
    partiallyProcessedFilesCount?: number;
    totalLinesOfCode: number;
    totalSizeBytes: number;
    languageBreakdown: Record<string, number>;
    primaryLanguage?: string;
    languages?: string[];
    frameworks?: string[];
    dependenciesIdentified?: string[];
    fileExtensions?: string[];
    cyclomaticComplexityTotal?: number;
    category?: string;
    domainTags?: string[];
    entropyViolationsCount?: number;
    estimatedHoursTechDebt?: number;
    files: FileInventoryItem[];
    isolatedStoragePath: string;
    verifiedIntegrity: boolean;
  };
  sourceFilesContent?: Record<string, string>;
  sourceCodeFiles?: any[];
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
    | 'ACESSO NÃO AUTORIZADO'
    | 'DISABLED';
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
  detectionMethod?: CriterionVerificationMethod;
  originType?: 'WINHOOD_NATIVE_STATIC' | 'EXTERNAL_TOOL_EXECUTION' | 'IMPORTED_REPORT' | 'MANUAL_AUDIT';
  category: 'CODE_QUALITY' | 'SAST' | 'SCA' | 'SECRETS' | 'SBOM' | 'ARCHITECTURE' | 'DATABASE' | 'DAST' | 'IAC' | 'OS_SANDBOX';
  originalRuleId: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  cleanCodeAttribute: CleanCodeAttribute;
  mqrImpacts: MqrCategoryImpact[];
  isNewCode: boolean;
  filePath: string;
  lineNumber: number;
  endLineNumber?: number;
  columnStart?: number;
  columnEnd?: number;
  component: string;
  snippet: string;
  contextBefore?: string[];
  contextAfter?: string[];
  whyItIsAnIssue: string;
  evaluationImpactSummary: string;
  executionFlows?: CodeExecutionFlowStep[];
  compliantCodeExample?: string;
  remediationEffortMinutes: number;
  cwe?: string;
  cve?: string;
  cvss?: number;
  epss?: number;
  cisaKev?: boolean;
  remediation: string;
  evidenceSha256: string;
  validationStatus: FindingValidationLifecycleState;
  lifecycleState?: FindingValidationLifecycleState;
  retestHistory?: Array<{
    timestamp: string;
    actor: string;
    previousStatus: FindingValidationLifecycleState;
    newStatus: FindingValidationLifecycleState;
    notes: string;
    evidenceHash: string;
  }>;
  collectedAt: string;
}

export interface ToolExecutionRecord {
  id: string;
  runId: string;
  softwareId: string;
  toolId: string;
  toolName: string;
  toolVersion: string;
  executionMethod?: 'NATIVE_AST_ENGINE' | 'CLI_BINARY' | 'EXTERNAL_API' | 'SANDBOX_WORKER' | 'NOT_EXECUTED';
  configurationUsed?: Record<string, any>;
  configHash?: string;
  sourceHash?: string;
  commitHash?: string;
  workingDirectory?: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  exitCode: number | null;
  stdout?: string;
  stderr?: string;
  veracityStatus: VeracityClassification;
  eligibleFilesCount: number;
  analyzedFilesCount: number;
  errorFilesCount?: number;
  coveragePercent: number;
  parsingErrorsCount: number;
  schemaValidated: boolean;
  canonicalFormat: string;
  rawOutputSha256: string;
  failureReasons?: string[];
  persistedEvidenceIds?: string[];
  logs: string[];
}

export interface Veracity19Checks {
  sourceReceived: boolean;
  integrityVerified: boolean;
  commitIdentified: boolean;
  toolExists: boolean;
  versionIdentified: boolean;
  configValidated: boolean;
  toolStarted: boolean;
  executionCompleted: boolean;
  exitCodeRecorded: boolean;
  outputReceived: boolean;
  outputParsed: boolean;
  formatValidated: boolean;
  coverageCalculated: boolean;
  failuresRecorded: boolean;
  evidencePersisted: boolean;
  evidenceHashVerified: boolean;
  matchesSoftware: boolean;
  matchesCommit: boolean;
  eligibleForScoring: boolean;
  // Legacy aliases
  toolExecuted?: boolean;
  artifactsReceived?: boolean;
  eligibleFilesIdentified?: boolean;
  filesEffectivelyAnalyzed?: boolean;
  parsingErrorsChecked?: boolean;
  reportGenerated?: boolean;
  schemaValidated?: boolean;
  evidenceStored?: boolean;
  persistenceConfirmed?: boolean;
}

export interface VeracityAuditMatrixRow {
  checkKey: keyof Veracity19Checks;
  checkId?: string;
  label?: string;
  passed: boolean;
  claimedStatus?: string;
  observedFact?: string;
  reconciledStatus?: 'VERIFIED' | 'FAILED' | 'NOT_APPLICABLE';
  justification: string;
  evidenceReference: string;
}

export interface VeracityCheckResult {
  runId: string;
  softwareId: string;
  softwareName: string;
  overallClassification: VeracityClassification;
  checks: Veracity19Checks;
  auditMatrix?: VeracityAuditMatrixRow[];
  overallCoveragePercent: number;
  warnings: string[];
  blockingReasons: string[];
  auditedAt: string;
}

export interface CategoryScoreDetail {
  category: BenchmarkCategoryKey;
  status: CategoryAssessmentStatus;
  rawScore: number | null;
  finalScore: number | null;
  score: number | null;
  rating?: 'A' | 'B' | 'C' | 'D' | 'E' | null;
  weight: number;
  weightPercent?: number;
  effectiveWeight?: number;
  originalWeight?: number;
  remediationEffortMinutes?: number;
  coveragePercent: number;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  toolsUsed: string[];
  limitations: string[];
  evidenceCount: number;
  evaluationReasons: CategoryEvaluationReason[];
  criteriaOutcomes?: CriterionEvaluationOutcome[];
  testsTotal?: number;
  testsPassed?: number;
  testsFailed?: number;
  testsNotExecuted?: number;
  rawMetricSummary?: Record<string, any>;
}

export interface MarketCompetitorCandidate {
  id: string;
  name: string;
  vendor: string;
  version?: string;
  description: string;
  officialUrl: string;
  documentationUrl: string;
  repositoryUrl?: string;
  publicRepoUrl?: string;
  marketSourceUrl?: string;
  category: string;
  estimatedSimilarityPercent: number;
  similarityScore: number;
  similarityBreakdown: {
    purpose: number;
    features: number;
    audience: number;
    platform: number;
    distribution: number;
    integrations: number;
    purposeMatch: number;
    featuresMatch: number;
    audienceMatch: number;
    platformMatch: number;
    distributionMatch: number;
    integrationsMatch: number;
  };
  matchReasons: string[];
  equivalentFeatures: string[];
  distinctFeatures: string[];
  featuresIdentified?: string[];
  sources: Array<{ title: string; url: string; date: string; confidence: 'HIGH' | 'MEDIUM' | 'LOW' }>;
  researchDate: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  isOpenSource: boolean;
  openSource?: boolean;
  sourceAvailability: 'FULL_SOURCE' | 'PARTIAL_SOURCE' | 'CLOSED_SOURCE' | 'PUBLIC_DOCUMENTATION_ONLY';
  analysisScope?: 'FULL_SOURCE' | 'PARTIAL_SOURCE' | 'CLOSED_SOURCE' | 'PUBLIC_DOCUMENTATION_ONLY';
  approvedByUser: boolean;
  approvedAt?: string;
}

export interface PenaltyCapTriggered {
  ruleId: string;
  category: BenchmarkCategoryKey | 'overall';
  reason: string;
  maxAllowedScore: number;
  originalScore: number;
  cappedScore: number;
}

export interface QualityGateConditionDetail {
  metricKey: string;
  label: string;
  threshold: string;
  actualValue: string;
  status: 'PASSED' | 'FAILED' | 'WARN_FUDGE_FACTOR' | 'INCONCLUSIVE' | 'NOT_EVALUATED';
  failureReason?: string;
}

export type ExecutiveQualityGateDecision =
  | 'APROVADO'
  | 'APROVADO COM RESSALVAS'
  | 'REPROVADO'
  | 'INCONCLUSIVO'
  | 'NÃO AVALIADO'
  | 'APPROVED'
  | 'APPROVED_WITH_RESERVATIONS'
  | 'BLOCKED'
  | 'INCONCLUSIVE'
  | 'REJECTED';

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
  separatedIndicators?: {
    technicalScore: number | null;
    scopeCoveragePercent: number;
    evidenceConfidence: 'HIGH' | 'MEDIUM' | 'LOW';
    qualityGateDecision: ExecutiveQualityGateDecision;
    veracityState: VeracityClassification;
  };
  originalWeights?: Record<BenchmarkCategoryKey, number>;
  effectiveWeights?: Record<BenchmarkCategoryKey, number>;
  classificationLabel:
    | 'Inexistente'
    | 'Crítico'
    | 'Insuficiente'
    | 'Adequado'
    | 'Muito bom'
    | 'Excelente'
    | 'Inconclusivo / Cobertura Insuficiente';
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
  categoryDetails?: Record<BenchmarkCategoryKey, CategoryScoreDetail>;
  runtimeMetrics?: {
    status: 'MEASURED' | 'NOT_MEASURED';
    reason?: string;
    p50LatencyMs?: number;
    p90LatencyMs?: number;
    p95LatencyMs?: number;
    p99LatencyMs?: number;
    throughputRps?: number;
    cpuPercent?: number;
    memoryRssMb?: number;
    memoryPeakMb?: number;
    startupTimeMs?: number;
    shutdownTimeMs?: number;
    diskUsageMb?: number;
    errorRatePercent?: number;
    measuredAt?: string;
    hardwareInfo?: string;
    loadProfile?: string;
  };
  staticMetrics?: {
    loc: number;
    cyclomaticComplexity: number;
    cognitiveComplexity: number;
    duplicatedLinesPercent: number;
    testCoveragePercent?: number;
    couplingIndex: number;
    cohesionIndex: number;
    circularDependenciesCount: number;
    layerViolationsCount: number;
    riskIndicators: string[];
  };
  qualityGate?: {
    gateName?: string;
    status: 'PASSED' | 'FAILED' | 'WARN' | 'INCONCLUSIVE' | 'NOT_EVALUATED';
    executiveDecision?: ExecutiveQualityGateDecision;
    fudgeFactorApplied?: boolean;
    conditionsMet: number;
    conditionsFailed: number;
    failedMetrics: string[];
    conditions?: QualityGateConditionDetail[];
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
  estimatedRemainingSeconds: number | null;
  estimationBasis?: 'HISTORICAL_COMPARABLE_RUNS' | 'UNAVAILABLE_FIRST_RUN';
  currentTool?: string;
  currentSoftwareName?: string;
  processedFiles: number;
  totalFiles: number;
  elapsedTimeMs?: number;
  recentEvents?: string[];
  errorsCount?: number;
  cancellable?: boolean;
}

export interface BenchmarkProfileConfig {
  id: string;
  name: string;
  description: string;
  domainKey?: string;
  profileKind?: 'GENERAL_DIMENSION' | 'DOMAIN_SPECIALIZED';
  enabledCategories?: BenchmarkCategoryKey[];
  notApplicableCategories?: BenchmarkCategoryKey[];
  weights: Record<BenchmarkCategoryKey, number>;
  selectedAdapters: string[];
  qualityProfileIds?: string[];
  qualityGateId?: string;
  analyzeNewCodeOnly?: boolean;
  referenceBranch?: string;
  enablePenaltyCaps: boolean;
  equivalenceEnvironment: {
    cpuCoresLimit: number;
    memoryMbLimit: number;
    osTarget: string;
    workloadConcurrency: number;
    dastFormalAuthorization?: boolean;
    authorizedByOwner?: string;
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
  requirement?: string;
  objective?: string;
  preconditions?: string[];
  inputs?: string[];
  procedure?: string;
  expectedResult?: string;
  version?: string;
  resultsBySoftware: Record<
    string,
    {
      status:
        | 'PASSED_VALIDATED'
        | 'FAILED_VALIDATED'
        | 'FAILED'
        | 'NOT_IMPLEMENTED'
        | 'NOT_APPLICABLE'
        | 'NOT_EXECUTED'
        | 'INCONCLUSIVE'
        | 'BLOCKED'
        | 'SIMULATED'
        | 'VISUAL_ONLY';
      verificationLevel?:
        | 'VALIDATED_BY_TEST'
        | 'IMPLEMENTATION_FOUND'
        | 'POTENTIAL_IMPLEMENTATION'
        | 'NOT_FOUND'
        | 'NOT_APPLICABLE'
        | 'INCONCLUSIVE';
      obtainedResult?: string;
      executionTimeMs: number | null;
      assertionCount: number;
      evidenceLog: string;
      limitations?: string[];
    }
  >;
}

export interface WindowsSandboxSnapshotDiff {
  softwareId: string;
  softwareName: string;
  sandboxEnvironment: string;
  executionStatus?: 'EXECUTED_REAL_SANDBOX' | 'NOT_EXECUTED_HOST_UNAVAILABLE' | 'STATIC_MANIFEST_INSPECTION';
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
  cleanUninstall: boolean | null;
}

export interface EvidenceRecord {
  id: string;
  runId: string;
  softwareId: string;
  softwareName: string;
  version: string;
  commitHash?: string;
  sourceHash?: string;
  criterionId?: string;
  evidenceType?: 'STATIC_AST_FINDING' | 'TOOL_RAW_OUTPUT' | 'VERACITY_ATTESTATION' | 'MANIFEST_SIGNATURE';
  origin?: string;
  responsibleActor?: string;
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
  profileId?: string;
  functionalDomain?: string;
  evaluationObjective?: string;
  wizardMode?: 'QUICK' | 'CUSTOM' | 'ADVANCED';
  softwareIds: string[];
  status: 'RUNNING' | 'COMPLETED' | 'COMPLETED_WITH_WARNINGS' | 'INCOMPLETE' | 'FAILED' | 'CANCELLED';
  startedAt: string;
  completedAt: string;
  algorithmVersion: string;
  methodologyVersion?: string;
  enabledCategories?: BenchmarkCategoryKey[];
  notApplicableCategories?: BenchmarkCategoryKey[];
  qualityGateId?: string;
  originalWeights?: Record<BenchmarkCategoryKey, number>;
  weightsUsed: Record<BenchmarkCategoryKey, number>;
  equivalenceEnvironment: BenchmarkProfileConfig['equivalenceEnvironment'];
  environmentEquivalent: boolean;
  comparabilityReport?: ComparabilityReport;
  signedManifest?: SignedEvidenceManifest;
  criteriaOutcomesBySoftware?: Record<string, CriterionEvaluationOutcome[]>;
  progress?: BenchmarkRunProgress;
  scoreCards: SoftwareScoreCard[];
  categoryDetails?: Record<BenchmarkCategoryKey, CategoryScoreDetail>;
  toolExecutions: ToolExecutionRecord[];
  veracityResults: VeracityCheckResult[];
  findings: NormalizedFinding[];
  architectureGraphs: ArchitectureGraphData[];
  functionalMatrix: FunctionalEquivalenceRow[];
  sandboxDiffs: WindowsSandboxSnapshotDiff[];
  evidenceChain: EvidenceRecord[];
  winnerSoftwareId: string | null;
  assessmentMode?: AssessmentMode;
  environmentMode?: AppEnvironment;
  dataOrigin?: DataOrigin;
  qualityGate?: {
    gateName?: string;
    status: 'PASSED' | 'FAILED' | 'WARN' | 'INCONCLUSIVE' | 'NOT_EVALUATED';
    executiveDecision?: ExecutiveQualityGateDecision;
    fudgeFactorApplied?: boolean;
    conditionsMet: number;
    conditionsFailed: number;
    failedMetrics: string[];
    conditions?: QualityGateConditionDetail[];
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

export type SonarInstallationMode = 'LOCAL' | 'REMOTE' | 'CLOUD' | 'DOCKER';

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

export type SonarTokenStatusLabel =
  | 'VALID_ACTIVE'
  | 'EXPIRING_SOON'
  | 'EXPIRED'
  | 'NO_EXPIRATION'
  | 'INVALID_TOKEN'
  | 'NOT_CONFIGURED';

export interface SavedSonarProjectProfile {
  id: string;
  name: string;
  platform: 'SONARCLOUD' | 'SONARQUBE_SERVER';
  serverUrl: string;
  organization: string;
  projectKey: string;
  encryptedToken?: string;
  maskedToken: string;
  hasToken: boolean;
  tokenCreatedAt: string;
  tokenExpiresAt: string | null;
  tokenValidityDaysPolicy: 30 | 60 | 90 | 'NO_EXPIRATION' | 'CUSTOM';
  lastVerifiedAt: string | null;
  lastVerificationStatus: 'VALID' | 'EXPIRED' | 'INVALID' | 'UNCHECKED';
  lastExportedAt: string | null;
  lastExportedIssuesCount: number | null;
}

export interface SonarTokenVerificationResult {
  valid: boolean;
  tokenExpiresAt: string | null;
  remainingDays: number | null;
  remainingHours: number | null;
  statusLabel: SonarTokenStatusLabel;
  message: string;
}



