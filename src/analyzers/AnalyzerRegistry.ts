import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SandboxExecutor } from '../execution/SandboxExecutor';
import { ToolAvailabilityService } from '../services/tools/ToolAvailabilityService';
import type { NormalizedFinding, SeverityLevel } from '../types/benchmark';
import { FindingNormalizer } from './FindingNormalizer';
import { ParserRegistry } from './ParserRegistry';
import { AnalyzerPluginManager } from './plugins/AnalyzerPluginSystem';
import { RULE_ENGINE_VERSION, RuleRegistry } from './RuleRegistry';
import { SarifCodec } from './SarifCodec';
import { TaintAnalyzer } from './TaintAnalyzer';
import type {
  AnalysisScope,
  AnalyzerExecution,
  AnalyzerPlugin,
  AnalyzerResult,
  AstIssueCandidate,
  DeterministicAnalysisOptions,
} from './types';

export interface ExternalEngineDescriptor {
  id: string;
  name: string;
  binaryNames: string[];
  category: 'SAST' | 'SECRETS' | 'CODE_QUALITY' | 'ARCHITECTURE';
  argsBuilder: (workspaceDir: string) => string[];
  outputFormat: 'SEMGREP_JSON' | 'GITLEAKS_JSON' | 'ESLINT_JSON' | 'RUFF_JSON' | 'BANDIT_JSON' | 'SARIF';
}

export type CodeQlSupportedLanguage =
  | 'javascript-typescript'
  | 'python'
  | 'java-kotlin'
  | 'csharp'
  | 'go'
  | 'cpp'
  | 'ruby';

export interface CodeQlLifecycleCommandPlan {
  language: CodeQlSupportedLanguage;
  databaseCreateArgs: string[];
  databaseAnalyzeArgs: string[];
  sarifOutputPath: string;
  databaseDir: string;
}

export function detectCodeQlLanguage(filesMap: Record<string, string>): CodeQlSupportedLanguage | null {
  const counts: Record<CodeQlSupportedLanguage, number> = {
    'javascript-typescript': 0,
    python: 0,
    'java-kotlin': 0,
    csharp: 0,
    go: 0,
    cpp: 0,
    ruby: 0,
  };
  for (const filePath of Object.keys(filesMap || {})) {
    const ext = path.extname(filePath).toLowerCase();
    if (['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].includes(ext)) counts['javascript-typescript'] += 1;
    else if (ext === '.py') counts.python += 1;
    else if (ext === '.java' || ext === '.kt') counts['java-kotlin'] += 1;
    else if (ext === '.cs') counts.csharp += 1;
    else if (ext === '.go') counts.go += 1;
    else if (['.c', '.cc', '.cpp', '.cxx', '.h', '.hpp'].includes(ext)) counts.cpp += 1;
    else if (ext === '.rb') counts.ruby += 1;
  }
  const ranked = Object.entries(counts)
    .filter(([, count]) => count > 0)
    .sort((a, b) => b[1] - a[1]);
  return ranked.length > 0 ? (ranked[0]![0] as CodeQlSupportedLanguage) : null;
}

export function buildCodeQlLifecycleCommands(
  workspaceDir: string,
  language: CodeQlSupportedLanguage,
  databaseDir: string,
  sarifOutputPath: string
): CodeQlLifecycleCommandPlan {
  const isInterpreted =
    language === 'javascript-typescript' || language === 'python' || language === 'ruby';
  const databaseCreateArgs = [
    'database',
    'create',
    databaseDir,
    `--language=${language}`,
    `--source-root=${workspaceDir}`,
    '--overwrite',
    ...(isInterpreted ? [] : ['--build-mode=autobuild']),
  ];
  const databaseAnalyzeArgs = [
    'database',
    'analyze',
    databaseDir,
    '--format=sarifv2.1.0',
    `--output=${sarifOutputPath}`,
    '--no-download',
  ];
  return {
    language,
    databaseCreateArgs,
    databaseAnalyzeArgs,
    sarifOutputPath,
    databaseDir,
  };
}

export const EXTERNAL_STATIC_ENGINES: ExternalEngineDescriptor[] = [
  {
    id: 'semgrep-opengrep',
    name: 'Semgrep / Opengrep SAST',
    binaryNames: ['semgrep', 'opengrep'],
    category: 'SAST',
    argsBuilder: (dir) => ['--config', 'auto', '--json', '--quiet', dir],
    outputFormat: 'SEMGREP_JSON',
  },
  {
    id: 'codeql-cli',
    name: 'GitHub CodeQL CLI',
    binaryNames: ['codeql'],
    category: 'SAST',
    argsBuilder: (dir) => ['database', 'analyze', '--format=sarifv2.1.0', dir],
    outputFormat: 'SARIF',
  },
  {
    id: 'gitleaks-secrets',
    name: 'Gitleaks Secrets Scanner',
    binaryNames: ['gitleaks'],
    category: 'SECRETS',
    argsBuilder: (dir) => ['detect', '--no-git', '--source', dir, '--report-format', 'json', '--report-path', '-'],
    outputFormat: 'GITLEAKS_JSON',
  },
  {
    id: 'eslint-analyzer',
    name: 'ESLint Static Analyzer',
    binaryNames: ['eslint'],
    category: 'CODE_QUALITY',
    argsBuilder: (dir) => ['--format', 'json', '--no-error-on-unmatched-pattern', dir],
    outputFormat: 'ESLINT_JSON',
  },
  {
    id: 'ruff-python',
    name: 'Ruff Python Linter',
    binaryNames: ['ruff'],
    category: 'CODE_QUALITY',
    argsBuilder: (dir) => ['check', '--output-format', 'json', dir],
    outputFormat: 'RUFF_JSON',
  },
  {
    id: 'bandit-python',
    name: 'Bandit Python Security',
    binaryNames: ['bandit'],
    category: 'SAST',
    argsBuilder: (dir) => ['-r', dir, '-f', 'json', '-q'],
    outputFormat: 'BANDIT_JSON',
  },
  {
    id: 'roslyn-analyzers',
    name: 'Roslyn .NET Analyzers',
    binaryNames: ['dotnet'],
    category: 'CODE_QUALITY',
    argsBuilder: (dir) => [
      'build',
      dir,
      '--no-restore',
      '/p:TreatWarningsAsErrors=false',
      `/p:ErrorLog=${path.join(dir, 'roslyn-analysis.sarif')},version=2.1`,
    ],
    outputFormat: 'SARIF',
  },
  {
    id: 'spotbugs-java',
    name: 'SpotBugs Java Bytecode Analyzer',
    binaryNames: ['spotbugs'],
    category: 'SAST',
    argsBuilder: (dir) => ['-textui', '-sarif', dir],
    outputFormat: 'SARIF',
  },
  {
    id: 'checkstyle-java',
    name: 'Checkstyle Java Style & Complexity',
    binaryNames: ['checkstyle'],
    category: 'CODE_QUALITY',
    argsBuilder: (dir) => ['-c', '/google_checks.xml', '-f', 'sarif', dir],
    outputFormat: 'SARIF',
  },
];

function markExternalFindingUnverified(finding: NormalizedFinding): NormalizedFinding {
  return {
    ...finding,
    originType: 'EXTERNAL_TOOL_EXECUTION',
    validationStatus: 'UNVERIFIED',
    lifecycleState: 'UNVERIFIED',
  };
}

function normalizeRelativePath(rawPath: unknown): string {
  const s = String(rawPath || 'unknown').trim().replace(/\\/g, '/');
  return s || 'unknown';
}

export class AnalyzerRegistry {
  public static listNativePlugins(): Array<{
    id: string;
    name: string;
    version: string;
    supportedLanguages: string[];
    capabilities: string[];
  }> {
    return AnalyzerPluginManager.listPlugins().map((p: AnalyzerPlugin) => ({
      id: p.id,
      name: p.name,
      version: p.version,
      supportedLanguages: p.supportedLanguages,
      capabilities: p.capabilities,
    }));
  }

  public static runNativeAstAndTaintPipeline(
    scope: AnalysisScope,
    options?: DeterministicAnalysisOptions
  ): AnalyzerResult {
    const startMs = performance.now();
    const fixedTs = options?.deterministicTimestamp;
    const startedAt = fixedTs || new Date().toISOString();

    const filesEntries = Object.entries(scope.filesMap || {}).sort(([a], [b]) => a.localeCompare(b));
    const sortedFilesMap: Record<string, string> = {};
    for (const [k, v] of filesEntries) {
      sortedFilesMap[k] = v;
    }

    const parseResults = filesEntries.map(([filePath, content]) =>
      ParserRegistry.parseFile(filePath, content)
    );
    const taintCandidates = TaintAnalyzer.analyzeFlows(parseResults, sortedFilesMap);

    const pluginExecution = AnalyzerPluginManager.executePlugins(
      {
        files: filesEntries.map(([filePath, content]) => ({ filePath, content })),
        parseResults,
        scope,
        slaBudgetMs: options?.slaBudgetMsPerPlugin ?? 5000,
        deterministicTimestamp: fixedTs,
      },
      options?.enablePluginIds
    );

    const rawCandidates: AstIssueCandidate[] = [
      ...parseResults.flatMap((p) => p.issues),
      ...taintCandidates,
      ...pluginExecution.candidates,
    ];

    // Deterministic deduplication preferring TAINT_ANALYSIS when identical location + rule/CWE
    const dedupMap = new Map<string, AstIssueCandidate>();
    for (const cand of rawCandidates) {
      const key = `${cand.ruleId}|${cand.filePath}|${cand.lineNumber}`;
      const existing = dedupMap.get(key);
      if (!existing || (cand.detectionMethod === 'TAINT_ANALYSIS' && existing.detectionMethod !== 'TAINT_ANALYSIS')) {
        dedupMap.set(key, cand);
      }
    }

    const allCandidates = Array.from(dedupMap.values()).sort(
      (a, b) =>
        a.filePath.localeCompare(b.filePath) ||
        a.lineNumber - b.lineNumber ||
        a.ruleId.localeCompare(b.ruleId)
    );

    const findings: NormalizedFinding[] = allCandidates.map((cand, idx) =>
      FindingNormalizer.fromAstCandidate({
        candidate: cand,
        scope,
        toolName:
          cand.detectionMethod === 'TAINT_ANALYSIS'
            ? 'WinHood Cross-File Taint AST Analyzer'
            : cand.category === 'IAC'
              ? 'WinHood Native IaC Plugin'
              : cand.category === 'SECRETS'
                ? 'WinHood Native Secrets & Entropy Plugin'
                : 'WinHood Compiler AST Analyzer',
        toolVersion: RULE_ENGINE_VERSION,
        filesMap: sortedFilesMap,
        index: idx,
        collectedAt: fixedTs,
      })
    );

    const completedAt = fixedTs || new Date().toISOString();
    const durationMs = fixedTs ? 1 : Math.max(1, Math.round(performance.now() - startMs));
    const astFilesCount = parseResults.filter((p) => p.astParsed).length;
    const iacPluginTimedOut = pluginExecution.outputs.some((o) => o.timedOut);
    const catalogSnapshot = RuleRegistry.getCatalogSnapshot();

    const canonicalFingerprintPayload = {
      engineVersion: RULE_ENGINE_VERSION,
      ruleCatalogSha256: catalogSnapshot.catalogSha256,
      files: filesEntries.map(([filePath, content]) => ({
        filePath,
        sha256: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
      })),
      findings: findings.map((f) => ({
        ruleId: f.originalRuleId,
        category: f.category,
        severity: f.severity,
        cwe: f.cwe || null,
        filePath: f.filePath,
        lineNumber: f.lineNumber,
        flowSteps: (f.executionFlows || []).length,
      })),
    };
    const deterministicDigestSha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(canonicalFingerprintPayload), 'utf8')
      .digest('hex');

    const execution: AnalyzerExecution = {
      analyzerId: 'winhood-native-ast-taint',
      analyzerName: 'WinHood Native Compiler AST, Taint, Secrets & IaC Engine',
      analyzerVersion: RULE_ENGINE_VERSION,
      executionMethod: 'NATIVE_AST_ENGINE',
      binaryDetected: true,
      startedAt,
      completedAt,
      durationMs,
      exitCode: 0,
      filesProcessed: filesEntries.length,
      filesFailed: parseResults.filter((p) => (p.errorCount || 0) > 0).length,
      measurementState: filesEntries.length > 0 ? 'STATIC_DERIVED' : 'NOT_MEASURED',
      timedOut: iacPluginTimedOut,
      slaBudgetMs: options?.slaBudgetMsPerPlugin ?? 5000,
      rawOutputSha256: deterministicDigestSha256,
    };

    const limitations: string[] = [...pluginExecution.limitations];
    if (astFilesCount < filesEntries.length) {
      limitations.push(
        `${filesEntries.length - astFilesCount} arquivo(s) não pertencem às linguagens AST imperativas (analisados por plugins IaC/Secrets/Manifestos quando aplicável).`
      );
    }

    return {
      execution,
      findings,
      limitations,
      ruleCatalogSha256: catalogSnapshot.catalogSha256,
      deterministicDigestSha256,
    };
  }

  public static discoverExternalEngineAvailability(): Array<{
    id: string;
    name: string;
    binaryDetected: boolean;
    executablePath: string;
    versionOutput: string | null;
  }> {
    return EXTERNAL_STATIC_ENGINES.map((desc) => {
      for (const bin of desc.binaryNames) {
        const probe = ToolAvailabilityService.checkBinaryInPath(bin);
        if (probe.detected) {
          return {
            id: desc.id,
            name: desc.name,
            binaryDetected: true,
            executablePath: probe.executablePath,
            versionOutput: probe.versionOutput,
          };
        }
      }
      return {
        id: desc.id,
        name: desc.name,
        binaryDetected: false,
        executablePath: '',
        versionOutput: null,
      };
    });
  }

  /**
   * Executes installed external analyzers strictly inside SandboxExecutor (bwrap/Docker OS sandbox).
   * Blocks host fallback cleanly if OS isolation is absent, validates exitCode + output schema,
   * and preserves standardized states: MEASURED, NOT_MEASURED, INCONCLUSIVE, FAILED, BLOCKED.
   */
  public static runInstalledExternalAnalyzers(
    scope: AnalysisScope,
    timeoutMs = 12000
  ): AnalyzerResult[] {
    const results: AnalyzerResult[] = [];
    const availability = AnalyzerRegistry.discoverExternalEngineAvailability();

    if (Object.keys(scope.filesMap || {}).length === 0) {
      return availability.map((item) => ({
        execution: {
          analyzerId: item.id,
          analyzerName: item.name,
          analyzerVersion: item.versionOutput || 'NOT_INSTALLED',
          executionMethod: 'NOT_EXECUTED',
          binaryDetected: item.binaryDetected,
          startedAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
          durationMs: 0,
          exitCode: null,
          filesProcessed: 0,
          filesFailed: 0,
          measurementState: 'NOT_MEASURED',
          rawOutputSha256: crypto.createHash('sha256').update(`${item.id}:EMPTY_SCOPE`).digest('hex'),
        },
        findings: [],
        limitations: ['Escopo vazio para análise externa.'],
      }));
    }

    for (const item of availability) {
      const desc = EXTERNAL_STATIC_ENGINES.find((e) => e.id === item.id)!;
      if (!item.binaryDetected) {
        results.push({
          execution: {
            analyzerId: item.id,
            analyzerName: item.name,
            analyzerVersion: 'NOT_INSTALLED',
            executionMethod: 'NOT_EXECUTED',
            binaryDetected: false,
            startedAt: new Date().toISOString(),
            completedAt: new Date().toISOString(),
            durationMs: 0,
            exitCode: null,
            filesProcessed: 0,
            filesFailed: 0,
            measurementState: 'NOT_MEASURED',
            rawOutputSha256: crypto.createHash('sha256').update(`${item.id}:NOT_INSTALLED`).digest('hex'),
          },
          findings: [],
          limitations: [`Binário ${item.name} não instalado no host.`],
        });
        continue;
      }

      // Dedicated CodeQL multi-step lifecycle: validate language -> database create -> database analyze -> SARIF 2.1.0
      if (desc.id === 'codeql-cli') {
        results.push(
          AnalyzerRegistry.runCodeQlLifecycle(desc, item.executablePath, item.versionOutput || 'CLI', scope, timeoutMs)
        );
        continue;
      }

      // Guard language applicability for Roslyn/SpotBugs/Checkstyle so we never report MEASURED on inapplicable repos
      const filesKeys = Object.keys(scope.filesMap);
      if (desc.id === 'roslyn-analyzers' && !filesKeys.some((f) => /\.(csproj|sln|cs)$/i.test(f))) {
        results.push({
          execution: {
            analyzerId: item.id,
            analyzerName: item.name,
            analyzerVersion: item.versionOutput || 'CLI',
            executionMethod: 'NOT_EXECUTED',
            binaryDetected: true,
            startedAt: new Date().toISOString(),
            completedAt: new Date().toISOString(),
            durationMs: 0,
            exitCode: null,
            filesProcessed: 0,
            filesFailed: 0,
            measurementState: 'NOT_MEASURED',
            rawOutputSha256: crypto.createHash('sha256').update(`${item.id}:NO_DOTNET_PROJECT`).digest('hex'),
          },
          findings: [],
          limitations: ['Nenhum projeto .NET (.csproj/.sln/.cs) encontrado no escopo para Roslyn.'],
        });
        continue;
      }

      const sbxRes = SandboxExecutor.runSandboxedCliBinary({
        executablePath: item.executablePath,
        argsBuilder: desc.argsBuilder,
        filesMap: scope.filesMap,
        timeoutMs,
      });

      if (sbxRes.blocked || !sbxRes.executed) {
        results.push({
          execution: {
            analyzerId: item.id,
            analyzerName: item.name,
            analyzerVersion: item.versionOutput || 'CLI',
            executionMethod: 'NOT_EXECUTED',
            binaryDetected: true,
            startedAt: sbxRes.startedAt,
            completedAt: sbxRes.completedAt,
            durationMs: sbxRes.durationMs,
            exitCode: sbxRes.exitCode,
            filesProcessed: 0,
            filesFailed: Object.keys(scope.filesMap).length,
            measurementState: sbxRes.blocked ? 'BLOCKED' : 'NOT_MEASURED',
            stdout: sbxRes.stdout.slice(0, 4000),
            stderr: sbxRes.stderr.slice(0, 2000),
            rawOutputSha256: sbxRes.stderrSha256,
          },
          findings: [],
          limitations: sbxRes.limitations.length > 0 ? sbxRes.limitations : [sbxRes.stderr],
        });
        continue;
      }

      const parsedOut = AnalyzerRegistry.parseExternalJsonOutputWithValidation(
        desc,
        sbxRes.stdout,
        scope,
        item.versionOutput || 'CLI'
      );

      const nonZeroUnexpected = sbxRes.exitCode !== null && sbxRes.exitCode > 1 && !parsedOut.validSchema;
      const executionFailed = nonZeroUnexpected || (!parsedOut.validSchema && sbxRes.stdout.trim().length > 0);
      const measurementState: AnalyzerExecution['measurementState'] = executionFailed
        ? 'FAILED'
        : !parsedOut.validSchema
          ? 'INCONCLUSIVE'
          : 'MEASURED';

      results.push({
        execution: {
          analyzerId: item.id,
          analyzerName: item.name,
          analyzerVersion: item.versionOutput || 'CLI',
          executionMethod: 'CLI_BINARY',
          binaryDetected: true,
          startedAt: sbxRes.startedAt,
          completedAt: sbxRes.completedAt,
          durationMs: sbxRes.durationMs,
          exitCode: sbxRes.exitCode,
          filesProcessed: parsedOut.validSchema ? Object.keys(scope.filesMap).length : 0,
          filesFailed: executionFailed ? Object.keys(scope.filesMap).length : 0,
          measurementState,
          stdout: sbxRes.stdout.slice(0, 4000),
          stderr: sbxRes.stderr.slice(0, 2000),
          rawOutputSha256: sbxRes.stdoutSha256,
        },
        findings: parsedOut.findings,
        limitations: parsedOut.validSchema
          ? [...sbxRes.limitations, ...parsedOut.warnings]
          : [
              ...parsedOut.errors,
              `Saída do analisador ${item.name} inválida ou vazia (exitCode=${sbxRes.exitCode}).`,
            ],
      });
    }

    return results;
  }

  private static runCodeQlLifecycle(
    desc: ExternalEngineDescriptor,
    executablePath: string,
    toolVersion: string,
    scope: AnalysisScope,
    timeoutMs: number
  ): AnalyzerResult {
    const startedAt = new Date().toISOString();
    const detectedLang = detectCodeQlLanguage(scope.filesMap);
    if (!detectedLang) {
      return {
        execution: {
          analyzerId: desc.id,
          analyzerName: desc.name,
          analyzerVersion: toolVersion,
          executionMethod: 'NOT_EXECUTED',
          binaryDetected: true,
          startedAt,
          completedAt: new Date().toISOString(),
          durationMs: 0,
          exitCode: null,
          filesProcessed: 0,
          filesFailed: 0,
          measurementState: 'NOT_MEASURED',
          rawOutputSha256: crypto.createHash('sha256').update(`${desc.id}:UNSUPPORTED_LANGUAGE`).digest('hex'),
        },
        findings: [],
        limitations: ['Nenhuma linguagem suportada pelo CodeQL CLI detectada no escopo.'],
      };
    }

    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-codeql-'));
    const dbDir = path.join(workDir, 'codeql-db');
    const sarifPath = path.join(workDir, 'codeql-results.sarif');

    try {
      const createRes = SandboxExecutor.runSandboxedCliBinary({
        executablePath,
        argsBuilder: (srcDir) =>
          buildCodeQlLifecycleCommands(srcDir, detectedLang, dbDir, sarifPath).databaseCreateArgs,
        filesMap: scope.filesMap,
        timeoutMs,
      });

      if (createRes.blocked || !createRes.executed) {
        return {
          execution: {
            analyzerId: desc.id,
            analyzerName: desc.name,
            analyzerVersion: toolVersion,
            executionMethod: 'NOT_EXECUTED',
            binaryDetected: true,
            startedAt: createRes.startedAt,
            completedAt: createRes.completedAt,
            durationMs: createRes.durationMs,
            exitCode: createRes.exitCode,
            filesProcessed: 0,
            filesFailed: Object.keys(scope.filesMap).length,
            measurementState: createRes.blocked ? 'BLOCKED' : 'NOT_MEASURED',
            stdout: createRes.stdout.slice(0, 4000),
            stderr: createRes.stderr.slice(0, 2000),
            rawOutputSha256: createRes.stderrSha256,
          },
          findings: [],
          limitations: createRes.limitations.length > 0 ? createRes.limitations : [createRes.stderr],
        };
      }

      if (createRes.exitCode !== 0 || !fs.existsSync(dbDir)) {
        return {
          execution: {
            analyzerId: desc.id,
            analyzerName: desc.name,
            analyzerVersion: toolVersion,
            executionMethod: 'CLI_BINARY',
            binaryDetected: true,
            startedAt: createRes.startedAt,
            completedAt: createRes.completedAt,
            durationMs: createRes.durationMs,
            exitCode: createRes.exitCode,
            filesProcessed: 0,
            filesFailed: Object.keys(scope.filesMap).length,
            measurementState: 'FAILED',
            stdout: createRes.stdout.slice(0, 4000),
            stderr: createRes.stderr.slice(0, 2000),
            rawOutputSha256: createRes.stderrSha256,
          },
          findings: [],
          limitations: [`CodeQL database create falhou para linguagem ${detectedLang} (exitCode=${createRes.exitCode}).`],
        };
      }

      const analyzeRes = SandboxExecutor.runSandboxedCliBinary({
        executablePath,
        argsBuilder: (srcDir) =>
          buildCodeQlLifecycleCommands(srcDir, detectedLang, dbDir, sarifPath).databaseAnalyzeArgs,
        filesMap: scope.filesMap,
        timeoutMs,
      });

      const sarifContent = fs.existsSync(sarifPath) ? fs.readFileSync(sarifPath, 'utf8') : analyzeRes.stdout;
      const parsedOut = AnalyzerRegistry.parseExternalJsonOutputWithValidation(
        desc,
        sarifContent,
        scope,
        toolVersion
      );

      const measurementState: AnalyzerExecution['measurementState'] =
        analyzeRes.blocked
          ? 'BLOCKED'
          : !parsedOut.validSchema
            ? analyzeRes.exitCode !== 0
              ? 'FAILED'
              : 'INCONCLUSIVE'
            : 'MEASURED';

      return {
        execution: {
          analyzerId: desc.id,
          analyzerName: desc.name,
          analyzerVersion: toolVersion,
          executionMethod: 'CLI_BINARY',
          binaryDetected: true,
          startedAt: createRes.startedAt,
          completedAt: analyzeRes.completedAt,
          durationMs: createRes.durationMs + analyzeRes.durationMs,
          exitCode: analyzeRes.exitCode,
          filesProcessed: parsedOut.validSchema ? Object.keys(scope.filesMap).length : 0,
          filesFailed: parsedOut.validSchema ? 0 : Object.keys(scope.filesMap).length,
          measurementState,
          stdout: sarifContent.slice(0, 4000),
          stderr: analyzeRes.stderr.slice(0, 2000),
          rawOutputSha256: crypto.createHash('sha256').update(sarifContent || '').digest('hex'),
        },
        findings: parsedOut.findings,
        limitations: parsedOut.validSchema
          ? [...analyzeRes.limitations, ...parsedOut.warnings]
          : [...parsedOut.errors, `CodeQL analyze não produziu SARIF 2.1.0 válido (exitCode=${analyzeRes.exitCode}).`],
      };
    } finally {
      try {
        fs.rmSync(workDir, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup
      }
    }
  }

  /**
   * Public, schema-validated parser and converter for all supported external tool outputs.
   * Every converted finding preserves external provenance and starts as UNVERIFIED (never auto-confirmed).
   */
  public static parseExternalJsonOutputWithValidation(
    desc: ExternalEngineDescriptor,
    stdout: string,
    scope: AnalysisScope,
    toolVersion: string
  ): {
    validSchema: boolean;
    findings: NormalizedFinding[];
    errors: string[];
    warnings: string[];
  } {
    if (!stdout || !stdout.trim()) {
      return {
        validSchema: false,
        findings: [],
        errors: [`Saída vazia recebida para ${desc.name} (${desc.outputFormat}).`],
        warnings: [],
      };
    }

    const findings: NormalizedFinding[] = [];
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      const json = JSON.parse(stdout);

      if (desc.outputFormat === 'SARIF') {
        const imported = SarifCodec.importSarif210(json, scope, {
          originType: 'EXTERNAL_TOOL_EXECUTION',
          fallbackToolName: desc.name,
        });
        return {
          validSchema: imported.valid,
          findings: imported.findings,
          errors: imported.errors,
          warnings: imported.warnings,
        };
      }

      if (desc.outputFormat === 'SEMGREP_JSON') {
        if (!json || typeof json !== 'object' || Array.isArray(json) || !Array.isArray(json.results)) {
          return {
            validSchema: false,
            findings: [],
            errors: ['Schema SEMGREP_JSON inválido: esperado objeto com array "results".'],
            warnings: [],
          };
        }
        const sevMap: Record<string, SeverityLevel> = {
          ERROR: 'CRITICAL',
          WARNING: 'HIGH',
          INFO: 'MEDIUM',
        };
        for (let idx = 0; idx < json.results.length; idx++) {
          const r = json.results[idx];
          if (!r || typeof r !== 'object' || typeof r.check_id !== 'string' || typeof r.path !== 'string') {
            return {
              validSchema: false,
              findings: [],
              errors: [`Entrada Semgrep results[${idx}] inválida: campos check_id e path são obrigatórios.`],
              warnings: [],
            };
          }
          const normalized = FindingNormalizer.fromAstCandidate({
            candidate: {
              ruleId: r.check_id,
              title: String(r.extra?.message || r.check_id),
              description: String(r.extra?.message || ''),
              category: 'SAST',
              severity: sevMap[String(r.extra?.severity || '').toUpperCase()] || 'MEDIUM',
              cwe: Array.isArray(r.extra?.metadata?.cwe)
                ? String(r.extra.metadata.cwe[0])
                : typeof r.extra?.metadata?.cwe === 'string'
                  ? r.extra.metadata.cwe
                  : 'CWE-710',
              filePath: normalizeRelativePath(r.path),
              lineNumber: Math.max(1, Number(r.start?.line || 1)),
              endLineNumber: Math.max(1, Number(r.end?.line || r.start?.line || 1)),
              columnStart: Number.isFinite(Number(r.start?.col)) ? Number(r.start.col) : undefined,
              columnEnd: Number.isFinite(Number(r.end?.col)) ? Number(r.end.col) : undefined,
              snippet: String(r.extra?.lines || ''),
              remediation: String(r.extra?.fix || 'Aplicar remediação conforme regra Semgrep.'),
              detectionMethod: 'STATIC_PATTERN',
              confidence: String(r.extra?.metadata?.confidence || '').toUpperCase() === 'HIGH' ? 'HIGH' : 'MEDIUM',
              effortMinutes: 15,
            },
            scope,
            toolName: desc.name,
            toolVersion,
            filesMap: scope.filesMap,
            index: idx,
          });
          findings.push(markExternalFindingUnverified(normalized));
        }
        return { validSchema: true, findings, errors, warnings };
      }

      if (desc.outputFormat === 'GITLEAKS_JSON') {
        if (!Array.isArray(json)) {
          return {
            validSchema: false,
            findings: [],
            errors: ['Schema GITLEAKS_JSON inválido: esperado array JSON de detecções.'],
            warnings: [],
          };
        }
        for (let idx = 0; idx < json.length; idx++) {
          const g = json[idx];
          if (!g || typeof g !== 'object' || typeof g.RuleID !== 'string' || typeof g.File !== 'string') {
            return {
              validSchema: false,
              findings: [],
              errors: [`Entrada Gitleaks[${idx}] inválida: campos RuleID e File são obrigatórios.`],
              warnings: [],
            };
          }
          const normalized = FindingNormalizer.fromAstCandidate({
            candidate: {
              ruleId: g.RuleID,
              title: `Segredo detectado pelo Gitleaks: ${g.Description || g.RuleID}`,
              description: `Regra Gitleaks ${g.RuleID} identificou potencial segredo exposto em ${g.File}.`,
              category: 'SECRETS',
              severity: 'BLOCKER',
              cwe: 'CWE-798',
              filePath: normalizeRelativePath(g.File),
              lineNumber: Math.max(1, Number(g.StartLine || 1)),
              endLineNumber: Math.max(1, Number(g.EndLine || g.StartLine || 1)),
              columnStart: Number.isFinite(Number(g.StartColumn)) ? Number(g.StartColumn) : undefined,
              columnEnd: Number.isFinite(Number(g.EndColumn)) ? Number(g.EndColumn) : undefined,
              snippet: String(g.Match || ''),
              remediation: 'Revogar credencial imediatamente, rotacionar segredo e remover do repositório.',
              detectionMethod: 'STATIC_PATTERN',
              confidence: 'MEDIUM',
              effortMinutes: 30,
            },
            scope,
            toolName: desc.name,
            toolVersion,
            filesMap: scope.filesMap,
            index: idx,
          });
          findings.push(markExternalFindingUnverified(normalized));
        }
        return { validSchema: true, findings, errors, warnings };
      }

      if (desc.outputFormat === 'ESLINT_JSON') {
        if (!Array.isArray(json)) {
          return {
            validSchema: false,
            findings: [],
            errors: ['Schema ESLINT_JSON inválido: esperado array de relatórios por arquivo.'],
            warnings: [],
          };
        }
        let findingIdx = 0;
        for (let fIdx = 0; fIdx < json.length; fIdx++) {
          const fileReport = json[fIdx];
          if (
            !fileReport ||
            typeof fileReport !== 'object' ||
            typeof fileReport.filePath !== 'string' ||
            !Array.isArray(fileReport.messages)
          ) {
            return {
              validSchema: false,
              findings: [],
              errors: [`Relatório ESLint[${fIdx}] inválido: campos filePath e messages[] são obrigatórios.`],
              warnings: [],
            };
          }
          const filePath = normalizeRelativePath(fileReport.filePath);
          for (const msg of fileReport.messages) {
            if (!msg || typeof msg !== 'object') continue;
            const rawSev = Number(msg.severity);
            // ESLint convention: 0 = off (ignored), 1 = warning, 2 = error
            if (rawSev === 0) continue;
            if (rawSev !== 1 && rawSev !== 2) {
              warnings.push(`Severidade ESLint não reconhecida (${String(msg.severity)}) em ${filePath}; ignorada.`);
              continue;
            }
            const severity: SeverityLevel = rawSev === 2 ? 'HIGH' : 'MEDIUM';
            const ruleId = String(msg.ruleId || (msg.fatal ? 'eslint-parse-error' : 'eslint-rule'));
            const isSecurityRule = /security|no-eval|no-implied-eval|no-new-func|xss|inject/i.test(ruleId);
            const fixHint = msg.fix
              ? 'Correção automática disponível via eslint --fix.'
              : 'Corrigir violação conforme regra ESLint.';
            const nodeNote = msg.nodeType ? ` (AST node: ${String(msg.nodeType)})` : '';

            const normalized = FindingNormalizer.fromAstCandidate({
              candidate: {
                ruleId,
                title: `${ruleId}: ${String(msg.message || 'ESLint issue')}`.slice(0, 180),
                description: `${String(msg.message || '')}${nodeNote}`,
                category: isSecurityRule ? 'SAST' : 'CODE_QUALITY',
                severity,
                cwe: isSecurityRule ? 'CWE-95' : undefined,
                filePath,
                lineNumber: Math.max(1, Number(msg.line || 1)),
                endLineNumber: Math.max(1, Number(msg.endLine || msg.line || 1)),
                columnStart: Number.isFinite(Number(msg.column)) ? Number(msg.column) : undefined,
                columnEnd: Number.isFinite(Number(msg.endColumn)) ? Number(msg.endColumn) : undefined,
                snippet: String(msg.source || ''),
                remediation: fixHint,
                detectionMethod: 'STATIC_PATTERN',
                confidence: rawSev === 2 ? 'MEDIUM' : 'LOW',
                effortMinutes: msg.fix ? 5 : 15,
              },
              scope,
              toolName: desc.name,
              toolVersion,
              filesMap: scope.filesMap,
              index: findingIdx++,
            });
            findings.push(markExternalFindingUnverified(normalized));
          }
        }
        return { validSchema: true, findings, errors, warnings };
      }

      if (desc.outputFormat === 'RUFF_JSON') {
        if (!Array.isArray(json)) {
          return {
            validSchema: false,
            findings: [],
            errors: ['Schema RUFF_JSON inválido: esperado array JSON de diagnósticos Ruff.'],
            warnings: [],
          };
        }
        for (let idx = 0; idx < json.length; idx++) {
          const item = json[idx];
          if (
            !item ||
            typeof item !== 'object' ||
            typeof item.filename !== 'string' ||
            typeof item.message !== 'string'
          ) {
            return {
              validSchema: false,
              findings: [],
              errors: [`Diagnóstico Ruff[${idx}] inválido: campos filename e message são obrigatórios.`],
              warnings: [],
            };
          }
          const code = String(item.code || 'RUFF-UNKNOWN');
          const isSecurity = /^S\d+/i.test(code);
          const isBugbearOrPyflakes = /^(B|F|ASYNC|BLE)\d+/i.test(code);
          const severity: SeverityLevel = isSecurity ? 'HIGH' : isBugbearOrPyflakes ? 'MEDIUM' : 'LOW';
          const startLine = Math.max(1, Number(item.location?.row || 1));
          const endLine = Math.max(startLine, Number(item.end_location?.row || startLine));

          const normalized = FindingNormalizer.fromAstCandidate({
            candidate: {
              ruleId: code,
              title: `${code}: ${item.message}`.slice(0, 180),
              description: item.message,
              category: isSecurity ? 'SAST' : 'CODE_QUALITY',
              severity,
              cwe: isSecurity ? 'CWE-703' : undefined,
              filePath: normalizeRelativePath(item.filename),
              lineNumber: startLine,
              endLineNumber: endLine,
              columnStart: Number.isFinite(Number(item.location?.column))
                ? Number(item.location.column)
                : undefined,
              columnEnd: Number.isFinite(Number(item.end_location?.column))
                ? Number(item.end_location.column)
                : undefined,
              snippet: '',
              remediation: item.fix?.message
                ? `Correção sugerida pelo Ruff: ${String(item.fix.message)}`
                : 'Revisar diagnóstico Python reportado pelo Ruff.',
              detectionMethod: 'STATIC_PATTERN',
              confidence: isSecurity ? 'MEDIUM' : 'LOW',
              effortMinutes: item.fix ? 5 : 15,
            },
            scope,
            toolName: desc.name,
            toolVersion,
            filesMap: scope.filesMap,
            index: idx,
          });
          findings.push(markExternalFindingUnverified(normalized));
        }
        return { validSchema: true, findings, errors, warnings };
      }

      if (desc.outputFormat === 'BANDIT_JSON') {
        if (!json || typeof json !== 'object' || Array.isArray(json) || !Array.isArray(json.results)) {
          return {
            validSchema: false,
            findings: [],
            errors: ['Schema BANDIT_JSON inválido: esperado objeto com array "results".'],
            warnings: [],
          };
        }
        const banditSevMap: Record<string, SeverityLevel> = {
          HIGH: 'HIGH',
          MEDIUM: 'MEDIUM',
          LOW: 'LOW',
        };
        const banditConfMap: Record<string, 'HIGH' | 'MEDIUM' | 'LOW'> = {
          HIGH: 'HIGH',
          MEDIUM: 'MEDIUM',
          LOW: 'LOW',
        };
        for (let idx = 0; idx < json.results.length; idx++) {
          const b = json.results[idx];
          if (!b || typeof b !== 'object' || typeof b.test_id !== 'string' || typeof b.filename !== 'string') {
            return {
              validSchema: false,
              findings: [],
              errors: [`Resultado Bandit results[${idx}] inválido: campos test_id e filename são obrigatórios.`],
              warnings: [],
            };
          }
          const lineRange = Array.isArray(b.line_range)
            ? b.line_range.map(Number).filter((n: number) => Number.isFinite(n) && n > 0)
            : [];
          const startLine = Math.max(1, Number(b.line_number || lineRange[0] || 1));
          const endLine = lineRange.length > 0 ? Math.max(startLine, ...lineRange) : startLine;
          const cweId = b.issue_cwe?.id ? `CWE-${String(b.issue_cwe.id).replace(/^CWE-/i, '')}` : undefined;
          const rawSev = String(b.issue_severity || 'MEDIUM').toUpperCase();
          const rawConf = String(b.issue_confidence || 'MEDIUM').toUpperCase();

          const normalized = FindingNormalizer.fromAstCandidate({
            candidate: {
              ruleId: b.test_id,
              title: `${b.test_id} (${String(b.test_name || 'bandit')}): ${String(b.issue_text || '')}`.slice(0, 180),
              description: String(b.issue_text || b.test_name || b.test_id),
              category: 'SAST',
              severity: banditSevMap[rawSev] || 'MEDIUM',
              cwe: cweId,
              filePath: normalizeRelativePath(b.filename),
              lineNumber: startLine,
              endLineNumber: endLine,
              snippet: String(b.code || ''),
              remediation: String(
                b.more_info
                  ? `Revisar vulnerabilidade Python (${b.test_id}) — referência: ${b.more_info}`
                  : `Revisar vulnerabilidade Python (${b.test_id}) reportada pelo Bandit.`
              ),
              detectionMethod: 'STATIC_PATTERN',
              confidence: banditConfMap[rawConf] || 'MEDIUM',
              effortMinutes: rawSev === 'HIGH' ? 30 : 15,
            },
            scope,
            toolName: desc.name,
            toolVersion,
            filesMap: scope.filesMap,
            index: idx,
          });
          findings.push(markExternalFindingUnverified(normalized));
        }
        return { validSchema: true, findings, errors, warnings };
      }

      return {
        validSchema: false,
        findings: [],
        errors: [`Formato de saída externo não suportado: ${String(desc.outputFormat)}.`],
        warnings: [],
      };
    } catch (err) {
      return {
        validSchema: false,
        findings: [],
        errors: [`Falha ao interpretar JSON de ${desc.name}: ${(err as Error).message}`],
        warnings: [],
      };
    }
  }
}
