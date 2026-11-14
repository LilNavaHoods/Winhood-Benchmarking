import crypto from 'node:crypto';
import { SandboxExecutor } from '../execution/SandboxExecutor';
import { ToolAvailabilityService } from '../services/tools/ToolAvailabilityService';
import type { NormalizedFinding, SeverityLevel } from '../types/benchmark';
import { FindingNormalizer } from './FindingNormalizer';
import { ParserRegistry } from './ParserRegistry';
import { AnalyzerPluginManager } from './plugins/AnalyzerPluginSystem';
import { RULE_ENGINE_VERSION, RuleRegistry } from './RuleRegistry';
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
    argsBuilder: (dir) => ['build', dir, '--no-restore', '/p:TreatWarningsAsErrors=false'],
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
    argsBuilder: (dir) => ['-f', 'sarif', dir],
    outputFormat: 'SARIF',
  },
];

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
    const pluginFilesSet = new Set<string>();
    for (const f of filesEntries) {
      if (parseResults.find((p) => p.filePath === f[0])?.astParsed) {
        pluginFilesSet.add(f[0]);
      }
    }
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
   * Blocks host fallback cleanly if OS isolation is absent, and validates exitCode + stdout JSON schema.
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
            measurementState: 'NOT_MEASURED',
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
      const measurementState = executionFailed
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
          ? sbxRes.limitations
          : [`Saída do analisador ${item.name} inválida ou vazia (exitCode=${sbxRes.exitCode}).`],
      });
    }

    return results;
  }

  private static parseExternalJsonOutputWithValidation(
    desc: ExternalEngineDescriptor,
    stdout: string,
    scope: AnalysisScope,
    toolVersion: string
  ): { validSchema: boolean; findings: NormalizedFinding[] } {
    if (!stdout || !stdout.trim()) return { validSchema: false, findings: [] };
    const findings: NormalizedFinding[] = [];
    try {
      const json = JSON.parse(stdout);
      if (desc.outputFormat === 'SEMGREP_JSON' && Array.isArray(json.results)) {
        json.results.forEach((r: any, idx: number) => {
          const sevMap: Record<string, SeverityLevel> = {
            ERROR: 'CRITICAL',
            WARNING: 'HIGH',
            INFO: 'MEDIUM',
          };
          findings.push(
            FindingNormalizer.fromAstCandidate({
              candidate: {
                ruleId: String(r.check_id || 'semgrep-rule'),
                title: String(r.extra?.message || r.check_id || 'Semgrep Finding'),
                description: String(r.extra?.message || ''),
                category: 'SAST',
                severity: sevMap[String(r.extra?.severity || '').toUpperCase()] || 'MEDIUM',
                cwe: Array.isArray(r.extra?.metadata?.cwe) ? String(r.extra.metadata.cwe[0]) : 'CWE-710',
                filePath: String(r.path || 'unknown'),
                lineNumber: Number(r.start?.line || 1),
                endLineNumber: Number(r.end?.line || 1),
                snippet: String(r.extra?.lines || ''),
                remediation: String(r.extra?.fix || 'Aplicar remediação conforme regra Semgrep.'),
                detectionMethod: 'STATIC_PATTERN',
                confidence: 'HIGH',
                effortMinutes: 15,
              },
              scope,
              toolName: desc.name,
              toolVersion,
              filesMap: scope.filesMap,
              index: idx,
            })
          );
        });
      } else if (desc.outputFormat === 'GITLEAKS_JSON' && Array.isArray(json)) {
        json.forEach((g: any, idx: number) => {
          findings.push(
            FindingNormalizer.fromAstCandidate({
              candidate: {
                ruleId: String(g.RuleID || 'gitleaks-secret'),
                title: `Segredo detectado pelo Gitleaks: ${g.Description || g.RuleID}`,
                description: `Regra Gitleaks ${g.RuleID} identificou potencial segredo exposto.`,
                category: 'SECRETS',
                severity: 'BLOCKER',
                cwe: 'CWE-798',
                filePath: String(g.File || 'unknown'),
                lineNumber: Number(g.StartLine || 1),
                endLineNumber: Number(g.EndLine || 1),
                snippet: String(g.Match || ''),
                remediation: 'Revogar credencial imediatamente e remover do repositório.',
                detectionMethod: 'STATIC_PATTERN',
                confidence: 'HIGH',
                effortMinutes: 30,
              },
              scope,
              toolName: desc.name,
              toolVersion,
              filesMap: scope.filesMap,
              index: idx,
            })
          );
        });
      } else {
        const schemaValid =
          (desc.outputFormat === 'ESLINT_JSON' && Array.isArray(json)) ||
          (desc.outputFormat === 'RUFF_JSON' && Array.isArray(json)) ||
          (desc.outputFormat === 'BANDIT_JSON' && Array.isArray(json?.results)) ||
          (desc.outputFormat === 'SARIF' && Array.isArray(json?.runs));
        return { validSchema: schemaValid, findings };
      }
      return { validSchema: true, findings };
    } catch {
      return { validSchema: false, findings: [] };
    }
  }
}
