import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ToolAvailabilityService } from '../services/tools/ToolAvailabilityService';
import type { NormalizedFinding, SeverityLevel } from '../types/benchmark';
import { FindingNormalizer } from './FindingNormalizer';
import { ParserRegistry } from './ParserRegistry';
import { TaintAnalyzer } from './TaintAnalyzer';
import type { AnalysisScope, AnalyzerExecution, AnalyzerResult } from './types';

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
  public static runNativeAstAndTaintPipeline(scope: AnalysisScope): AnalyzerResult {
    const startMs = performance.now();
    const startedAt = new Date().toISOString();
    const filesEntries = Object.entries(scope.filesMap || {});

    const parseResults = filesEntries.map(([filePath, content]) =>
      ParserRegistry.parseFile(filePath, content)
    );
    const taintCandidates = TaintAnalyzer.analyzeFlows(parseResults, scope.filesMap);

    const allCandidates = [
      ...parseResults.flatMap((p) => p.issues),
      ...taintCandidates,
    ];

    const findings: NormalizedFinding[] = allCandidates.map((cand, idx) =>
      FindingNormalizer.fromAstCandidate({
        candidate: cand,
        scope,
        toolName:
          cand.detectionMethod === 'TAINT_ANALYSIS'
            ? 'WinHood Cross-File Taint AST Analyzer'
            : 'WinHood Compiler AST Analyzer',
        toolVersion: '4.1.0',
        filesMap: scope.filesMap,
        index: idx,
      })
    );

    const completedAt = new Date().toISOString();
    const durationMs = Math.max(1, Math.round(performance.now() - startMs));
    const astFilesCount = parseResults.filter((p) => p.astParsed).length;

    const execution: AnalyzerExecution = {
      analyzerId: 'winhood-native-ast-taint',
      analyzerName: 'WinHood Native Compiler AST & Taint Engine',
      analyzerVersion: '4.1.0',
      executionMethod: 'NATIVE_AST_ENGINE',
      binaryDetected: true,
      startedAt,
      completedAt,
      durationMs,
      exitCode: 0,
      filesProcessed: astFilesCount,
      filesFailed: 0,
      measurementState: astFilesCount > 0 ? 'STATIC_DERIVED' : 'NOT_MEASURED',
      rawOutputSha256: crypto
        .createHash('sha256')
        .update(JSON.stringify({ findingsCount: findings.length, astFilesCount }))
        .digest('hex'),
    };

    return {
      execution,
      findings,
      limitations:
        astFilesCount < filesEntries.length
          ? [
              `${filesEntries.length - astFilesCount} arquivo(s) não pertencem às linguagens AST suportadas e não foram marcados como AST_ANALYSIS.`,
            ]
          : [],
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
   * Executes installed external analyzers safely in an isolated temporary directory
   * using spawnSync(..., { shell: false, timeout }). Never fakes results if not installed.
   */
  public static runInstalledExternalAnalyzers(
    scope: AnalysisScope,
    timeoutMs = 12000
  ): AnalyzerResult[] {
    const results: AnalyzerResult[] = [];
    const availability = AnalyzerRegistry.discoverExternalEngineAvailability();
    const installed = availability.filter((a) => a.binaryDetected);

    if (installed.length === 0 || Object.keys(scope.filesMap).length === 0) {
      return availability.map((item) => ({
        execution: {
          analyzerId: item.id,
          analyzerName: item.name,
          analyzerVersion: item.versionOutput || 'NOT_INSTALLED',
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
        limitations: [`Binário ${item.name} não encontrado no PATH do host.`],
      }));
    }

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-ext-'));
    try {
      for (const [relPath, content] of Object.entries(scope.filesMap)) {
        const safeRel = relPath.replace(/^\/+/, '');
        const dest = path.resolve(tmpRoot, safeRel);
        if (!dest.startsWith(tmpRoot + path.sep)) continue;
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, content, 'utf8');
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

        const startedAt = new Date().toISOString();
        const startPerf = performance.now();
        const args = desc.argsBuilder(tmpRoot);
        const proc = spawnSync(item.executablePath, args, {
          shell: false,
          encoding: 'utf8',
          timeout: timeoutMs,
          maxBuffer: 8 * 1024 * 1024,
        });
        const durationMs = Math.max(1, Math.round(performance.now() - startPerf));
        const stdout = proc.stdout || '';
        const stderr = proc.stderr || '';
        const parsedFindings = AnalyzerRegistry.parseExternalJsonOutput(
          desc,
          stdout,
          scope,
          item.versionOutput || 'CLI'
        );

        results.push({
          execution: {
            analyzerId: item.id,
            analyzerName: item.name,
            analyzerVersion: item.versionOutput || 'CLI',
            executionMethod: 'CLI_BINARY',
            binaryDetected: true,
            startedAt,
            completedAt: new Date().toISOString(),
            durationMs,
            exitCode: proc.status,
            filesProcessed: Object.keys(scope.filesMap).length,
            filesFailed: proc.error ? 1 : 0,
            measurementState: proc.error ? 'FAILED' : 'MEASURED',
            stdout: stdout.slice(0, 4000),
            stderr: stderr.slice(0, 2000),
            rawOutputSha256: crypto.createHash('sha256').update(stdout || stderr || 'empty').digest('hex'),
          },
          findings: parsedFindings,
          limitations: proc.error ? [proc.error.message] : [],
        });
      }
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }

    return results;
  }

  private static parseExternalJsonOutput(
    desc: ExternalEngineDescriptor,
    stdout: string,
    scope: AnalysisScope,
    toolVersion: string
  ): NormalizedFinding[] {
    if (!stdout || !stdout.trim()) return [];
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
      }
    } catch {
      return [];
    }
    return findings;
  }
}
