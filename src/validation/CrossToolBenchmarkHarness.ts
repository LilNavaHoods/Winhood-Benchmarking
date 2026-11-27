/* winhood-benchmark-corpus: synthetic-sast-fixtures */
import crypto from 'node:crypto';
import { AnalyzerRegistry } from '../analyzers/AnalyzerRegistry';
import { RULE_ENGINE_VERSION } from '../analyzers/RuleRegistry';
import {
  computeConfusionMetrics,
  computeWilson95ConfidenceInterval,
} from './GoldenDatasetRunner';
import type {
  StatisticalAggregateMetrics,
  WilsonConfidenceInterval95,
} from '../types/benchmark';

export type BenchmarkVulnerabilityClass =
  | 'SQL_INJECTION'
  | 'XSS'
  | 'COMMAND_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'SSRF'
  | 'INSECURE_DESERIALIZATION'
  | 'HARDCODED_SECRETS'
  | 'WEAK_CRYPTO'
  | 'VULNERABLE_DEPENDENCIES'
  | 'INSECURE_CONFIG_IAC'
  | 'CODE_QUALITY_COMPLEXITY';

export interface ControlledBenchmarkCase {
  caseId: string;
  title: string;
  language: string;
  vulnerabilityClass: BenchmarkVulnerabilityClass;
  cwe: string;
  expectedVulnerable: boolean;
  filesMap: Record<string, string>;
}

export interface ExternalToolBenchmarkFinding {
  caseId: string;
  ruleId: string;
  cwe?: string | null;
  severity: 'BLOCKER' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  filePath: string;
  lineNumber: number;
  message?: string;
}

export interface ExternalToolRunInput {
  toolName: 'SonarQube Cloud' | 'Semgrep' | 'CodeQL' | string;
  toolVersion: string;
  executionState: 'EXECUTED' | 'NOT_EXECUTED';
  analyticalDepthDeclared: string;
  runtimeMs: number | null;
  /** Either pre-parsed findings or a raw SARIF 2.1.0 document mapped by file path. */
  findings?: ExternalToolBenchmarkFinding[];
  sarif210?: {
    version?: string;
    runs?: Array<{
      tool?: { driver?: { name?: string; version?: string } };
      results?: Array<{
        ruleId?: string;
        level?: string;
        message?: { text?: string };
        properties?: { cwe?: string; tags?: string[] };
        locations?: Array<{
          physicalLocation?: {
            artifactLocation?: { uri?: string };
            region?: { startLine?: number };
          };
        }>;
      }>;
    }>;
  };
  limitations: string[];
}

export interface ToolBenchmarkEvaluation {
  toolName: string;
  toolVersion: string;
  executionState: 'EXECUTED' | 'NOT_EXECUTED';
  analyticalDepthDeclared: string;
  runtimeMs: number | null;
  counts: { tp: number; fp: number; tn: number; fn: number; totalEvaluated: number };
  metrics: StatisticalAggregateMetrics;
  confidenceIntervals95: {
    precision: WilsonConfidenceInterval95;
    recall: WilsonConfidenceInterval95;
  };
  byClass: Record<
    string,
    { tp: number; fp: number; tn: number; fn: number; precision: number | null; recall: number | null }
  >;
  detectedRuleIds: string[];
  limitations: string[];
}

export interface CrossToolComparisonReport {
  schemaVersion: '1.0.0';
  generatedAt: string;
  corpusSha256: string;
  totalCases: number;
  positiveCases: number;
  negativeCases: number;
  coveredClasses: BenchmarkVulnerabilityClass[];
  winhoodEvaluation: ToolBenchmarkEvaluation;
  externalEvaluations: ToolBenchmarkEvaluation[];
  pairwiseOverlap: Array<{
    externalTool: string;
    bothDetectedTp: number;
    onlyWinhoodTp: number;
    onlyExternalTp: number;
    neitherDetectedFn: number;
  }>;
  objectivityDisclaimer: string;
}

function mapSarifLevelToSeverity(
  level?: string
): ExternalToolBenchmarkFinding['severity'] {
  switch ((level || '').toLowerCase()) {
    case 'error':
      return 'HIGH';
    case 'warning':
      return 'MEDIUM';
    case 'note':
      return 'LOW';
    default:
      return 'INFO';
  }
}

export function extractFindingsFromSarifForCorpus(
  sarif: NonNullable<ExternalToolRunInput['sarif210']>,
  corpus: ControlledBenchmarkCase[]
): ExternalToolBenchmarkFinding[] {
  const fileToCaseId = new Map<string, string>();
  for (const item of corpus) {
    for (const relPath of Object.keys(item.filesMap)) {
      fileToCaseId.set(relPath.replace(/\\/g, '/').replace(/^\/+/, ''), item.caseId);
    }
  }

  const findings: ExternalToolBenchmarkFinding[] = [];
  for (const run of sarif.runs || []) {
    for (const res of run.results || []) {
      const uri = (res.locations?.[0]?.physicalLocation?.artifactLocation?.uri || '')
        .replace(/\\/g, '/')
        .replace(/^\.\//, '')
        .replace(/^\/+/, '');
      const caseId = fileToCaseId.get(uri);
      if (!caseId) continue;
      const cweTag = (res.properties?.tags || []).find((t) => /CWE-\d+/i.test(t));
      const cweMatch = (res.properties?.cwe || cweTag || '').match(/CWE-\d+/i);
      findings.push({
        caseId,
        ruleId: String(res.ruleId || 'EXTERNAL_RULE'),
        cwe: cweMatch ? cweMatch[0].toUpperCase() : null,
        severity: mapSarifLevelToSeverity(res.level),
        filePath: uri,
        lineNumber: res.locations?.[0]?.physicalLocation?.region?.startLine ?? 1,
        message: res.message?.text,
      });
    }
  }
  return findings;
}

export const CONTROLLED_11_CLASS_VALIDATION_CORPUS: ControlledBenchmarkCase[] = [
  // 1. SQL Injection (TP + TN)
  {
    caseId: 'CTRL-SQLI-TP',
    title: 'SQL Injection via string concatenation',
    language: 'TypeScript',
    vulnerabilityClass: 'SQL_INJECTION',
    cwe: 'CWE-89',
    expectedVulnerable: true,
    filesMap: {
      'corpus/sqli_tp.ts':
        'export function findUser(db: any, userId: string) {\n  return db.query("SELECT id, email FROM users WHERE id = " + userId);\n}\n',
    },
  },
  {
    caseId: 'CTRL-SQLI-TN',
    title: 'Parameterized SQL Prepared Statement',
    language: 'TypeScript',
    vulnerabilityClass: 'SQL_INJECTION',
    cwe: 'CWE-89',
    expectedVulnerable: false,
    filesMap: {
      'corpus/sqli_tn.ts':
        'export function findUserSafe(db: { query: (sql: string, args: unknown[]) => unknown }, userId: string) {\n  return db.query("SELECT id, email FROM users WHERE id = $1", [userId]);\n}\n',
    },
  },
  // 2. XSS (TP + TN)
  {
    caseId: 'CTRL-XSS-TP',
    title: 'Unescaped HTML rendering of user input',
    language: 'TypeScript',
    vulnerabilityClass: 'XSS',
    cwe: 'CWE-79',
    expectedVulnerable: true,
    filesMap: {
      'corpus/xss_tp.ts':
        'export function renderBanner(res: { sendHtml: (h: string) => void }, userTitle: string) {\n  res.sendHtml("<h1>" + userTitle + "</h1>");\n}\n',
    },
  },
  {
    caseId: 'CTRL-XSS-TN',
    title: 'HTML-escaped rendering of user input',
    language: 'TypeScript',
    vulnerabilityClass: 'XSS',
    cwe: 'CWE-79',
    expectedVulnerable: false,
    filesMap: {
      'corpus/xss_tn.ts':
        'declare function escapeHtml(s: string): string;\nexport function renderBannerSafe(res: { sendHtml: (h: string) => void }, userTitle: string) {\n  const safeTitle = escapeHtml(userTitle);\n  res.sendHtml("<h1>" + safeTitle + "</h1>");\n}\n',
    },
  },
  // 3. Command Injection (TP + TN)
  {
    caseId: 'CTRL-CMDI-TP',
    title: 'OS Command Injection via execSync interpolation',
    language: 'TypeScript',
    vulnerabilityClass: 'COMMAND_INJECTION',
    cwe: 'CWE-78',
    expectedVulnerable: true,
    filesMap: {
      'corpus/cmdi_tp.ts':
        'import { execSync } from "node:child_process";\nexport function archiveDir(targetPath: string) {\n  return execSync(`tar -czf /tmp/out.tgz ${targetPath}`);\n}\n',
    },
  },
  {
    caseId: 'CTRL-CMDI-TN',
    title: 'Safe static execFile with shell: false',
    language: 'TypeScript',
    vulnerabilityClass: 'COMMAND_INJECTION',
    cwe: 'CWE-78',
    expectedVulnerable: false,
    filesMap: {
      'corpus/cmdi_tn.ts':
        'import { execFileSync } from "node:child_process";\nexport function listVersion() {\n  const bin = "node";\n  return execFileSync(bin, ["--version"], { shell: false });\n}\n',
    },
  },
  // 4. Path Traversal (TP + TN)
  {
    caseId: 'CTRL-PATH-TP',
    title: 'Unsanitized path read via readFileSync',
    language: 'TypeScript',
    vulnerabilityClass: 'PATH_TRAVERSAL',
    cwe: 'CWE-22',
    expectedVulnerable: true,
    filesMap: {
      'corpus/path_tp.ts':
        'import fs from "node:fs";\nexport function loadReport(filePath: string) {\n  return fs.readFileSync(filePath, "utf8");\n}\n',
    },
  },
  {
    caseId: 'CTRL-PATH-TN',
    title: 'Path confined via path.basename',
    language: 'TypeScript',
    vulnerabilityClass: 'PATH_TRAVERSAL',
    cwe: 'CWE-22',
    expectedVulnerable: false,
    filesMap: {
      'corpus/path_tn.ts':
        'import fs from "node:fs";\nimport path from "node:path";\nexport function loadReportSafe(filePath: string) {\n  const safeName = path.basename(filePath);\n  return fs.readFileSync(safeName, "utf8");\n}\n',
    },
  },
  // 5. SSRF (TP + TN)
  {
    caseId: 'CTRL-SSRF-TP',
    title: 'Unvalidated outbound fetch with user URL',
    language: 'TypeScript',
    vulnerabilityClass: 'SSRF',
    cwe: 'CWE-918',
    expectedVulnerable: true,
    filesMap: {
      'corpus/ssrf_tp.ts':
        'export async function callWebhook(webhookUrl: string) {\n  return fetch(webhookUrl);\n}\n',
    },
  },
  {
    caseId: 'CTRL-SSRF-TN',
    title: 'Outbound fetch guarded by SsrfGuard',
    language: 'TypeScript',
    vulnerabilityClass: 'SSRF',
    cwe: 'CWE-918',
    expectedVulnerable: false,
    filesMap: {
      'corpus/ssrf_tn.ts':
        'declare const SsrfGuard: { validateUrl: (u: string) => Promise<void> };\nexport async function callWebhookSafe(webhookUrl: string) {\n  await SsrfGuard.validateUrl(webhookUrl);\n  return fetch(webhookUrl);\n}\n',
    },
  },
  // 6. Unsafe Deserialization (TP + TN)
  {
    caseId: 'CTRL-DESER-TP',
    title: 'Unsafe pickle.loads deserialization in Python',
    language: 'Python',
    vulnerabilityClass: 'INSECURE_DESERIALIZATION',
    cwe: 'CWE-502',
    expectedVulnerable: true,
    filesMap: {
      'corpus/deser_tp.py':
        'import pickle\ndef load_session(payload):\n    return pickle.loads(payload)\n',
    },
  },
  {
    caseId: 'CTRL-DESER-TN',
    title: 'Safe JSON parsing in Python',
    language: 'Python',
    vulnerabilityClass: 'INSECURE_DESERIALIZATION',
    cwe: 'CWE-502',
    expectedVulnerable: false,
    filesMap: {
      'corpus/deser_tn.py':
        'import json\ndef load_session_safe(payload):\n    return json.loads(payload)\n',
    },
  },
  // 7. Hardcoded Secrets (TP + TN)
  {
    caseId: 'CTRL-SECRET-TP',
    title: 'Hardcoded high-entropy API secret',
    language: 'TypeScript',
    vulnerabilityClass: 'HARDCODED_SECRETS',
    cwe: 'CWE-798',
    expectedVulnerable: true,
    filesMap: {
      'corpus/secret_tp.ts':
        'export function initClient() {\n  const apiSecret = "wh_live_9xK8mP2qR7vL4nT6wZ1bC5fH3jD0sA";\n  return apiSecret.length;\n}\n',
    },
  },
  {
    caseId: 'CTRL-SECRET-TN',
    title: 'Secret loaded from environment variable',
    language: 'TypeScript',
    vulnerabilityClass: 'HARDCODED_SECRETS',
    cwe: 'CWE-798',
    expectedVulnerable: false,
    filesMap: {
      'corpus/secret_tn.ts':
        'export function initClientSafe() {\n  const apiSecret = process.env.SERVICE_API_SECRET || "";\n  return apiSecret.length;\n}\n',
    },
  },
  // 8. Weak Crypto (TP + TN)
  {
    caseId: 'CTRL-CRYPTO-TP',
    title: 'MD5 hash used for cryptographic digest',
    language: 'TypeScript',
    vulnerabilityClass: 'WEAK_CRYPTO',
    cwe: 'CWE-328',
    expectedVulnerable: true,
    filesMap: {
      'corpus/crypto_tp.ts':
        'import crypto from "node:crypto";\nexport function hashPassword(pw: string) {\n  return crypto.createHash("md5").update(pw).digest("hex");\n}\n',
    },
  },
  {
    caseId: 'CTRL-CRYPTO-TN',
    title: 'SHA-256 digest used cleanly',
    language: 'TypeScript',
    vulnerabilityClass: 'WEAK_CRYPTO',
    cwe: 'CWE-328',
    expectedVulnerable: false,
    filesMap: {
      'corpus/crypto_tn.ts':
        'import crypto from "node:crypto";\nexport function hashContent(data: string) {\n  return crypto.createHash("sha256").update(data).digest("hex");\n}\n',
    },
  },
  // 9. Insecure Config / IaC (TP + TN)
  {
    caseId: 'CTRL-IAC-TP',
    title: 'Dockerfile running as root with :latest tag',
    language: 'Dockerfile',
    vulnerabilityClass: 'INSECURE_CONFIG_IAC',
    cwe: 'CWE-250',
    expectedVulnerable: true,
    filesMap: {
      'corpus/Dockerfile.vuln': 'FROM node:latest\nUSER root\nCMD ["node", "app.js"]\n',
    },
  },
  {
    caseId: 'CTRL-IAC-TN',
    title: 'Hardened non-root Dockerfile with pinned image',
    language: 'Dockerfile',
    vulnerabilityClass: 'INSECURE_CONFIG_IAC',
    cwe: 'CWE-250',
    expectedVulnerable: false,
    filesMap: {
      'corpus/Dockerfile.safe': 'FROM node:22.14.0-bookworm-slim\nUSER winhood\nHEALTHCHECK CMD node -e "process.exit(0)"\nCMD ["node", "app.js"]\n',
    },
  },
  // 10. Code Quality / Error Handling (TP + TN)
  {
    caseId: 'CTRL-QUALITY-TP',
    title: 'Empty catch clause silencing exceptions',
    language: 'TypeScript',
    vulnerabilityClass: 'CODE_QUALITY_COMPLEXITY',
    cwe: 'CWE-390',
    expectedVulnerable: true,
    filesMap: {
      'corpus/quality_tp.ts':
        'export function parseQuietly(raw: string) {\n  try {\n    return JSON.parse(raw);\n  } catch {}\n  return null;\n}\n',
    },
  },
  {
    caseId: 'CTRL-QUALITY-TN',
    title: 'Handled catch block returning explicit error',
    language: 'TypeScript',
    vulnerabilityClass: 'CODE_QUALITY_COMPLEXITY',
    cwe: 'CWE-390',
    expectedVulnerable: false,
    filesMap: {
      'corpus/quality_tn.ts':
        'export function parseSafely(raw: string): { ok: boolean; value?: unknown } {\n  try {\n    return { ok: true, value: JSON.parse(raw) };\n  } catch (err) {\n    return { ok: false, value: String(err) };\n  }\n}\n',
    },
  },
];

export class CrossToolBenchmarkHarness {
  public static runComparison(params: {
    corpus?: ControlledBenchmarkCase[];
    externalToolRuns?: ExternalToolRunInput[];
    deterministicTimestamp?: string;
  }): CrossToolComparisonReport {
    const corpus = params.corpus || CONTROLLED_11_CLASS_VALIDATION_CORPUS;
    const generatedAt = params.deterministicTimestamp || new Date().toISOString();
    const corpusSha256 = crypto
      .createHash('sha256')
      .update(
        JSON.stringify(
          corpus.map((c) => ({
            caseId: c.caseId,
            cwe: c.cwe,
            expectedVulnerable: c.expectedVulnerable,
            filesMap: c.filesMap,
          }))
        ),
        'utf8'
      )
      .digest('hex');

    const winhoodStart = performance.now();
    const winhoodDetectedByCase = new Map<string, string[]>();
    for (const item of corpus) {
      const pipeline = AnalyzerRegistry.runNativeAstAndTaintPipeline(
        {
          runId: `bench-${item.caseId}`,
          softwareId: item.caseId,
          softwareName: item.title,
          softwareVersion: '1.0.0',
          filesMap: item.filesMap,
        },
        { deterministicTimestamp: generatedAt }
      );
      const relevant = pipeline.findings.filter((f) => {
        if (item.vulnerabilityClass === 'HARDCODED_SECRETS') {
          return f.category === 'SECRETS' || f.cwe === 'CWE-798';
        }
        if (item.vulnerabilityClass === 'INSECURE_CONFIG_IAC') {
          return f.category === 'IAC';
        }
        if (item.vulnerabilityClass === 'CODE_QUALITY_COMPLEXITY') {
          return f.category === 'CODE_QUALITY' || f.cwe === item.cwe;
        }
        if (item.vulnerabilityClass === 'WEAK_CRYPTO') {
          return f.cwe === 'CWE-328' || f.cwe === 'CWE-327' || f.originalRuleId.includes('S4790');
        }
        return f.cwe === item.cwe || f.category === 'SAST';
      });
      winhoodDetectedByCase.set(
        item.caseId,
        Array.from(new Set(relevant.map((f) => f.originalRuleId)))
      );
    }
    const winhoodRuntimeMs = Math.max(1, Math.round(performance.now() - winhoodStart));

    const evaluateDetector = (
      meta: {
        toolName: string;
        toolVersion: string;
        executionState: 'EXECUTED' | 'NOT_EXECUTED';
        analyticalDepthDeclared: string;
        runtimeMs: number | null;
        limitations: string[];
      },
      detectedMap: Map<string, string[]>
    ): ToolBenchmarkEvaluation => {
      if (meta.executionState === 'NOT_EXECUTED') {
        return {
          ...meta,
          counts: { tp: 0, fp: 0, tn: 0, fn: 0, totalEvaluated: 0 },
          metrics: computeConfusionMetrics({ tp: 0, fp: 0, tn: 0, fn: 0 }),
          confidenceIntervals95: {
            precision: computeWilson95ConfidenceInterval(0, 0),
            recall: computeWilson95ConfidenceInterval(0, 0),
          },
          byClass: {},
          detectedRuleIds: [],
        };
      }

      let tp = 0;
      let fp = 0;
      let tn = 0;
      let fn = 0;
      const allRules = new Set<string>();
      const byClassAcc: Record<string, { tp: number; fp: number; tn: number; fn: number }> = {};

      for (const item of corpus) {
        if (!byClassAcc[item.vulnerabilityClass]) {
          byClassAcc[item.vulnerabilityClass] = { tp: 0, fp: 0, tn: 0, fn: 0 };
        }
        const rules = detectedMap.get(item.caseId) || [];
        rules.forEach((r) => allRules.add(r));
        const detected = rules.length > 0;
        if (item.expectedVulnerable && detected) {
          tp += 1;
          byClassAcc[item.vulnerabilityClass]!.tp += 1;
        } else if (!item.expectedVulnerable && detected) {
          fp += 1;
          byClassAcc[item.vulnerabilityClass]!.fp += 1;
        } else if (!item.expectedVulnerable && !detected) {
          tn += 1;
          byClassAcc[item.vulnerabilityClass]!.tn += 1;
        } else {
          fn += 1;
          byClassAcc[item.vulnerabilityClass]!.fn += 1;
        }
      }

      const byClass: ToolBenchmarkEvaluation['byClass'] = {};
      for (const [cls, acc] of Object.entries(byClassAcc)) {
        const m = computeConfusionMetrics(acc);
        byClass[cls] = { ...acc, precision: m.precision, recall: m.recall };
      }

      return {
        ...meta,
        counts: { tp, fp, tn, fn, totalEvaluated: corpus.length },
        metrics: computeConfusionMetrics({ tp, fp, tn, fn }),
        confidenceIntervals95: {
          precision: computeWilson95ConfidenceInterval(tp, tp + fp),
          recall: computeWilson95ConfidenceInterval(tp, tp + fn),
        },
        byClass,
        detectedRuleIds: Array.from(allRules).sort((a, b) => a.localeCompare(b)),
      };
    };

    const winhoodEvaluation = evaluateDetector(
      {
        toolName: 'WinHood Native SAST/Taint/IaC Engine',
        toolVersion: RULE_ENGINE_VERSION,
        executionState: 'EXECUTED',
        analyticalDepthDeclared: 'FULL_AST (TS/JS) + STRUCTURAL_AST (Python/Java/C#/Go/Rust) + Multi-Hop Call-Graph Taint',
        runtimeMs: winhoodRuntimeMs,
        limitations: [
          'Resultados sobre corpus controlado interno NÃO substituem validação independente externa com repositórios de terceiros.',
          'Sem compilação cross-package TypeScript/Roslyn/javac; vulnerabilidades que dependem de resolução completa de tipos externos podem produzir FN.',
        ],
      },
      winhoodDetectedByCase
    );

    const externalEvaluations: ToolBenchmarkEvaluation[] = [];
    const pairwiseOverlap: CrossToolComparisonReport['pairwiseOverlap'] = [];

    for (const ext of params.externalToolRuns || []) {
      const extMap = new Map<string, string[]>();
      if (ext.executionState === 'EXECUTED') {
        const parsedFindings =
          ext.findings ?? (ext.sarif210 ? extractFindingsFromSarifForCorpus(ext.sarif210, corpus) : []);
        for (const f of parsedFindings) {
          const list = extMap.get(f.caseId) || [];
          if (!list.includes(f.ruleId)) list.push(f.ruleId);
          extMap.set(f.caseId, list);
        }
      }

      const evalRes = evaluateDetector(
        {
          toolName: ext.toolName,
          toolVersion: ext.toolVersion,
          executionState: ext.executionState,
          analyticalDepthDeclared: ext.analyticalDepthDeclared,
          runtimeMs: ext.runtimeMs,
          limitations: ext.limitations,
        },
        extMap
      );
      externalEvaluations.push(evalRes);

      if (ext.executionState === 'EXECUTED') {
        let bothDetectedTp = 0;
        let onlyWinhoodTp = 0;
        let onlyExternalTp = 0;
        let neitherDetectedFn = 0;
        for (const item of corpus) {
          if (!item.expectedVulnerable) continue;
          const whHit = (winhoodDetectedByCase.get(item.caseId) || []).length > 0;
          const exHit = (extMap.get(item.caseId) || []).length > 0;
          if (whHit && exHit) bothDetectedTp += 1;
          else if (whHit && !exHit) onlyWinhoodTp += 1;
          else if (!whHit && exHit) onlyExternalTp += 1;
          else neitherDetectedFn += 1;
        }
        pairwiseOverlap.push({
          externalTool: ext.toolName,
          bothDetectedTp,
          onlyWinhoodTp,
          onlyExternalTp,
          neitherDetectedFn,
        });
      }
    }

    return {
      schemaVersion: '1.0.0',
      generatedAt,
      corpusSha256,
      totalCases: corpus.length,
      positiveCases: corpus.filter((c) => c.expectedVulnerable).length,
      negativeCases: corpus.filter((c) => !c.expectedVulnerable).length,
      coveredClasses: Array.from(new Set(corpus.map((c) => c.vulnerabilityClass))),
      winhoodEvaluation,
      externalEvaluations,
      pairwiseOverlap,
      objectivityDisclaimer:
        'Benchmark comparativo objetivo sobre o mesmo corpus controlado (SHA-256 verificável). Ferramentas externas não executadas no ambiente permanecem explicitamente marcadas como NOT_EXECUTED; nenhum resultado externo é simulado.',
    };
  }
}
