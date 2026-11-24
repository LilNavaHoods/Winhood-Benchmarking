import type {
  CodeExecutionFlowStep,
  MetricMeasurementState,
  NormalizedFinding,
  SeverityLevel,
} from '../types/benchmark';

export type SupportedAstLanguage =
  | 'TypeScript'
  | 'JavaScript'
  | 'Python'
  | 'Java'
  | 'C#'
  | 'Go'
  | 'Rust'
  | 'SQL'
  | 'Other';

export interface AstFunctionNode {
  name: string;
  filePath: string;
  startLine: number;
  endLine: number;
  params: string[];
  cyclomaticComplexity: number;
  cognitiveComplexity: number;
  isExported: boolean;
  callsMade: AstCallSite[];
  returnValues: string[];
  variableBindings: Array<{
    varName: string;
    lineNumber: number;
    expressionText: string;
    dependencies: string[];
    isSanitized: boolean;
    sanitizerName?: string;
    sanitizerContext?:
      | 'NUMERIC'
      | 'URL_ENCODE'
      | 'HTML_ESCAPE'
      | 'PATH_BASENAME'
      | 'CRYPTO_KDF'
      | 'SQL_PREPARED'
      | 'GENERIC_SCHEMA';
  }>;
}

export interface AstCallSite {
  callee: string;
  calleeBase?: string;
  filePath: string;
  lineNumber: number;
  argsText: string[];
  argIdentifiers: string[];
  snippet: string;
  enclosingFunction: string;
  inTryBlock: boolean;
}

export interface AstImportNode {
  sourcePath: string;
  importedSymbols: Array<{ name: string; lineNumber: number; usedInBody: boolean }>;
  lineNumber: number;
}

export interface AstIssueCandidate {
  ruleId: string;
  title: string;
  description: string;
  category: NormalizedFinding['category'];
  severity: SeverityLevel;
  cwe?: string;
  filePath: string;
  lineNumber: number;
  endLineNumber: number;
  columnStart?: number;
  columnEnd?: number;
  snippet: string;
  remediation: string;
  detectionMethod: 'AST_ANALYSIS' | 'TAINT_ANALYSIS' | 'STATIC_PATTERN';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  effortMinutes: number;
  executionFlows?: CodeExecutionFlowStep[];
}

export type AstAnalyticalDepth =
  | 'FULL_AST'
  | 'STRUCTURAL_AST'
  | 'PARTIAL_RECOVERY'
  | 'UNSUPPORTED';

export interface AstParseResult {
  filePath: string;
  language: SupportedAstLanguage;
  astParsed: boolean;
  parserKind: 'BABEL_AST' | 'STRUCTURAL_PARSER' | 'UNSUPPORTED';
  analyticalDepth?: AstAnalyticalDepth;
  errorCount?: number;
  parserEngine: string;
  loc: number;
  cyclomaticComplexity: number;
  cognitiveComplexity: number;
  imports: AstImportNode[];
  functions: AstFunctionNode[];
  callSites: AstCallSite[];
  issues: AstIssueCandidate[];
  hasAuditSignals: boolean;
  hasCryptoSignals: boolean;
  hasWeakCryptoSignals: boolean;
  hasPreparedStatementSignals: boolean;
  todoCommentLines?: number[];
}

export interface AnalysisScope {
  runId: string;
  softwareId: string;
  softwareName: string;
  softwareVersion: string;
  commitHash?: string;
  filesMap: Record<string, string>;
  includedExtensions?: string[];
  exclusions?: string[];
}

export interface RuleDefinition {
  ruleId: string;
  title: string;
  category: NormalizedFinding['category'];
  severity: SeverityLevel;
  cwe: string;
  owaspTop10?: string;
  cweTop25Rank?: number | null;
  cvssBase?: number;
  version: string;
  sinceEngineVersion: string;
  deprecated?: boolean;
  languages: SupportedAstLanguage[];
  requiresAst: boolean;
  effortMinutes: number;
  remediation: string;
  packId: string;
  positiveExamples?: string[];
  negativeExamples?: string[];
}

export interface RulePackMetadata {
  packId: string;
  name: string;
  version: string;
  releasedAt: string;
  rulesCount: number;
  checksumSha256: string;
  languages: SupportedAstLanguage[];
}

export interface AnalyzerExecution {
  analyzerId: string;
  analyzerName: string;
  analyzerVersion: string;
  executionMethod: 'NATIVE_AST_ENGINE' | 'CLI_BINARY' | 'NOT_EXECUTED';
  binaryDetected: boolean;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  exitCode: number | null;
  filesProcessed: number;
  filesFailed: number;
  measurementState: MetricMeasurementState | 'BLOCKED';
  stdout?: string;
  stderr?: string;
  rawOutputSha256: string;
  timedOut?: boolean;
  slaBudgetMs?: number;
}

export interface AnalyzerResult {
  execution: AnalyzerExecution;
  findings: NormalizedFinding[];
  limitations: string[];
  ruleCatalogSha256?: string;
  deterministicDigestSha256?: string;
}

export type PluginSupportedLanguage =
  | SupportedAstLanguage
  | 'Terraform'
  | 'Kubernetes'
  | 'Dockerfile'
  | 'GitHubActions';

export interface AnalyzerPluginContext {
  scope: AnalysisScope;
  files: Array<{ filePath: string; content: string }>;
  parseResults: AstParseResult[];
  slaBudgetMs: number;
  deterministicTimestamp?: string;
}

export interface AnalyzerPluginOutput {
  pluginId: string;
  pluginVersion: string;
  filesScanned: number;
  filesFailed: number;
  candidates: AstIssueCandidate[];
  limitations: string[];
  timedOut?: boolean;
  durationMs: number;
}

export interface AnalyzerPlugin {
  id: string;
  name: string;
  version: string;
  supportedLanguages: PluginSupportedLanguage[];
  supportedExtensions: string[];
  capabilities: Array<'AST' | 'TAINT' | 'SECRETS' | 'IAC' | 'QUALITY'>;
  matchesFile: (filePath: string, content: string) => boolean;
  analyze: (ctx: AnalyzerPluginContext) => AnalyzerPluginOutput;
}

export interface DeterministicAnalysisOptions {
  deterministicTimestamp?: string;
  slaBudgetMsPerPlugin?: number;
  enablePluginIds?: string[];
}
