import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import express from 'express';
import { EphemeralWorkspaceManager } from '../execution/EphemeralWorkspaceManager';
import { registerGracefulShutdown } from '../server/gracefulShutdown';
import {
  ALLOWED_SCANNER_TOOL_IDS,
  SCANNER_TOOL_CATALOG,
  type ScannerToolId,
  type ScannerToolJobOutput,
  type ToolCapabilityRecord,
} from './ScannerJobOrchestrator';

interface PinnedScannerRunnerSpec {
  toolId: ScannerToolId;
  binaryNames: string[];
  versionArgs: string[];
  buildArgs: (workspaceDir: string, outFilePath: string, prereqPath?: string) => string[];
  outputFormat: 'JSON' | 'SARIF';
  readsFromFile?: boolean;
  validateParsedOutput: (parsed: unknown) => { valid: boolean; findingsCount: number };
  selfTestFiles: Record<string, string>;
  positiveTestFiles?: Record<string, string>;
  minPositiveFindings?: number;
}

interface OfflineDbManifestArtifact {
  relativePath: string;
  sizeBytes?: number;
  sha256: string;
}

interface OfflineDbManifest {
  schemaVersion?: string;
  tool?: string;
  updatedAt?: string;
  expiresAt?: string;
  artifacts?: OfflineDbManifestArtifact[];
}

export interface OfflinePrerequisiteResult {
  ready: boolean;
  state?: 'DATABASE_UNAVAILABLE' | 'RULES_UNAVAILABLE' | 'NOT_CONFIGURED';
  resolvedPath?: string;
  reason?: string;
}

export interface ActiveWorkerProcessEntry {
  jobId: string;
  toolId: ScannerToolId;
  child: ChildProcess;
  pid: number | undefined;
  cancelled: boolean;
  startedAt: number;
}

const ACTIVE_JOB_PROCESSES = new Map<string, Set<ActiveWorkerProcessEntry>>();
const CANCELLED_JOB_IDS = new Set<string>();
const MAX_CANCELLED_JOB_HISTORY = 500;
const MAX_STDIO_CAPTURE_BYTES = 12 * 1024 * 1024;

export const SAFE_WORKER_PATH =
  process.platform === 'win32'
    ? `${process.env.SystemRoot || 'C:\\Windows'}\\System32;${process.env.SystemRoot || 'C:\\Windows'}`
    : '/opt/winhood-pytools/bin:/opt/winhood-scanners/bin:/usr/local/bin:/usr/bin:/bin';

export function resolveWorkerBindHost(explicitHost?: string, defaultHost = '127.0.0.1'): string {
  return (
    explicitHost ||
    process.env.WINHOOD_SCANNER_WORKER_HOST ||
    process.env.WINHOOD_WORKER_BIND_HOST ||
    defaultHost
  ).trim();
}

export function resolveWorkerPort(explicitPort?: number): number {
  if (typeof explicitPort === 'number' && Number.isFinite(explicitPort)) {
    return explicitPort;
  }
  const raw = process.env.WINHOOD_SCANNER_WORKER_PORT || process.env.WINHOOD_WORKER_PORT || '4100';
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 4100;
}

export function getAllowedBinarySearchDirs(): string[] {
  return process.platform === 'win32'
    ? SAFE_WORKER_PATH.split(';')
    : [
        '/opt/winhood-pytools/bin',
        '/opt/winhood-scanners/bin',
        '/usr/local/bin',
        '/usr/bin',
        '/bin',
        path.join(process.cwd(), 'node_modules', '.bin'),
      ];
}

export function resolveAllowedBinary(binaryNames: string[]): string | null {
  const searchDirs = getAllowedBinarySearchDirs();

  for (const binName of binaryNames) {
    if (!/^[a-zA-Z0-9._-]+$/.test(binName)) continue;
    for (const dir of searchDirs) {
      const candidate = path.join(dir, process.platform === 'win32' ? `${binName}.exe` : binName);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
      if (process.platform === 'win32') {
        const cmdCandidate = path.join(dir, `${binName}.cmd`);
        if (fs.existsSync(cmdCandidate)) return cmdCandidate;
      }
    }
  }
  return null;
}

function directoryHasMatchingFile(
  rootDir: string,
  predicate: (fileName: string, fullPath: string) => boolean,
  maxDepth = 4,
  depth = 0
): boolean {
  if (depth > maxDepth || !rootDir || !fs.existsSync(rootDir)) return false;
  try {
    const stat = fs.statSync(rootDir);
    if (stat.isFile()) {
      return predicate(path.basename(rootDir), rootDir);
    }
    if (!stat.isDirectory()) return false;
    const entries = fs.readdirSync(rootDir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(rootDir, entry.name);
      if (entry.isFile() && predicate(entry.name, full)) {
        return true;
      }
      if (entry.isDirectory() && directoryHasMatchingFile(full, predicate, maxDepth, depth + 1)) {
        return true;
      }
    }
  } catch {
    return false;
  }
  return false;
}

export function validateOfflineDbManifest(
  dbDir: string,
  expectedTool: 'grype' | 'osv-scanner'
): { valid: boolean; reason?: string } {
  const manifestPath = path.join(dbDir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    return { valid: true };
  }
  try {
    const raw = fs.readFileSync(manifestPath, 'utf8');
    const parsed = JSON.parse(raw) as OfflineDbManifest;
    if (parsed.tool && parsed.tool !== expectedTool) {
      return {
        valid: false,
        reason: `Manifesto offline inválido para ${expectedTool}: ferramenta declarada "${parsed.tool}".`,
      };
    }
    if (parsed.expiresAt) {
      const expiresMs = Date.parse(parsed.expiresAt);
      if (Number.isNaN(expiresMs) || Date.now() > expiresMs) {
        return {
          valid: false,
          reason: `Base offline do ${expectedTool} vencida (${parsed.expiresAt}). Execute scripts/docker-update-scanner-dbs.sh para atualizar.`,
        };
      }
    }
    if (Array.isArray(parsed.artifacts)) {
      if (parsed.artifacts.length === 0) {
        return {
          valid: false,
          reason: `Manifesto offline do ${expectedTool} não lista artefatos válidos.`,
        };
      }
      for (const art of parsed.artifacts) {
        if (!art?.relativePath || !art?.sha256 || art.relativePath.includes('..')) {
          return {
            valid: false,
            reason: `Entrada inválida no manifesto offline do ${expectedTool}.`,
          };
        }
        const targetPath = path.resolve(dbDir, art.relativePath);
        if (!targetPath.startsWith(path.resolve(dbDir) + path.sep) || !fs.existsSync(targetPath)) {
          return {
            valid: false,
            reason: `Artefato ausente na base offline do ${expectedTool}: ${art.relativePath}.`,
          };
        }
        const actualSha = crypto.createHash('sha256').update(fs.readFileSync(targetPath)).digest('hex');
        if (actualSha !== art.sha256.toLowerCase()) {
          return {
            valid: false,
            reason: `Corrupção detectada (SHA-256 divergente) na base offline do ${expectedTool}: ${art.relativePath}.`,
          };
        }
      }
    }
    return { valid: true };
  } catch {
    return {
      valid: false,
      reason: `Manifesto offline corrompido (JSON inválido) em ${dbDir}.`,
    };
  }
}

/**
 * Verifies offline rule packs or vulnerability databases required for air-gapped execution.
 * Tools requiring offline rules/databases NEVER report `OPERATIONAL` or "0 vulnerabilities"
 * when their local ruleset or vulnerability DB cache is missing, corrupted, or expired.
 */
export function checkToolOfflinePrerequisites(toolId: ScannerToolId): OfflinePrerequisiteResult {
  if (toolId === 'semgrep') {
    const candidates = [
      process.env.WINHOOD_SEMGREP_RULES_DIR,
      '/opt/winhood-scanner-rules',
      path.join(process.cwd(), 'security', 'semgrep-offline-rules'),
    ].filter((p): p is string => Boolean(p && p.trim()));

    for (const dir of candidates) {
      const resolved = path.resolve(dir);
      if (
        directoryHasMatchingFile(resolved, (name, full) => {
          if (!/\.ya?ml$/i.test(name)) return false;
          try {
            return fs.statSync(full).size > 20;
          } catch {
            return false;
          }
        })
      ) {
        return { ready: true, resolvedPath: resolved };
      }
    }
    return {
      ready: false,
      state: 'RULES_UNAVAILABLE',
      reason:
        'Regras offline do Semgrep ausentes em WINHOOD_SEMGREP_RULES_DIR (/opt/winhood-scanner-rules). O worker opera sem acesso à internet; resultado não pode ser tratado como zero achados.',
    };
  }

  if (toolId === 'eslint') {
    const configCandidates = [
      process.env.WINHOOD_ESLINT_CONFIG_PATH,
      '/opt/winhood-scanner-rules/eslint.config.mjs',
      path.join(process.cwd(), 'security', 'semgrep-offline-rules', 'eslint.config.mjs'),
    ].filter((p): p is string => Boolean(p && p.trim()));

    for (const cfg of configCandidates) {
      const resolved = path.resolve(cfg);
      if (fs.existsSync(resolved)) {
        return { ready: true, resolvedPath: resolved };
      }
    }
    return {
      ready: false,
      state: 'RULES_UNAVAILABLE',
      reason: 'Configuração offline do ESLint ausente em WINHOOD_ESLINT_CONFIG_PATH.',
    };
  }

  if (toolId === 'grype') {
    const grypeDir = path.resolve(process.env.GRYPE_DB_CACHE_DIR || '/data/scanner-cache/grype');
    const hasDb = directoryHasMatchingFile(grypeDir, (name, full) => {
      if (!/^(vulnerability\.db|metadata\.json)$/i.test(name)) return false;
      try {
        return fs.statSync(full).size > 32;
      } catch {
        return false;
      }
    });
    if (!hasDb) {
      return {
        ready: false,
        state: 'DATABASE_UNAVAILABLE',
        reason:
          'Base offline de vulnerabilidades do Grype ausente em GRYPE_DB_CACHE_DIR (/data/scanner-cache/grype). Execute ./scripts/docker-update-scanner-dbs.sh (ou .\\scripts\\docker-update-scanner-dbs.ps1) para popular o cache offline.',
      };
    }
    const manifestCheck = validateOfflineDbManifest(grypeDir, 'grype');
    if (!manifestCheck.valid) {
      return {
        ready: false,
        state: 'DATABASE_UNAVAILABLE',
        reason: manifestCheck.reason,
      };
    }
    return { ready: true, resolvedPath: grypeDir };
  }

  if (toolId === 'osv-scanner') {
    const osvDir = path.resolve(process.env.WINHOOD_OSV_DB_DIR || '/data/scanner-cache/osv');
    const hasDb = directoryHasMatchingFile(osvDir, (name, full) => {
      if (!/\.(zip|json|db|sqlite)$/i.test(name) || name.toLowerCase() === 'manifest.json') return false;
      try {
        return fs.statSync(full).size > 32;
      } catch {
        return false;
      }
    });
    if (!hasDb) {
      return {
        ready: false,
        state: 'DATABASE_UNAVAILABLE',
        reason:
          'Base offline do OSV-Scanner ausente em WINHOOD_OSV_DB_DIR (/data/scanner-cache/osv). Execute ./scripts/docker-update-scanner-dbs.sh para popular o cache local.',
      };
    }
    const manifestCheck = validateOfflineDbManifest(osvDir, 'osv-scanner');
    if (!manifestCheck.valid) {
      return {
        ready: false,
        state: 'DATABASE_UNAVAILABLE',
        reason: manifestCheck.reason,
      };
    }
    return { ready: true, resolvedPath: osvDir };
  }

  if (toolId === 'trivy') {
    const trivyDir = path.resolve(process.env.TRIVY_CACHE_DIR || '/data/scanner-cache/trivy');
    const hasDb = directoryHasMatchingFile(trivyDir, (name, full) => {
      if (!/^(trivy\.db|metadata\.json)$/i.test(name)) return false;
      try {
        return fs.statSync(full).size > 32;
      } catch {
        return false;
      }
    });
    if (!hasDb) {
      return {
        ready: false,
        state: 'DATABASE_UNAVAILABLE',
        reason:
          'Base offline do Trivy ausente em TRIVY_CACHE_DIR (/data/scanner-cache/trivy).',
      };
    }
    return { ready: true, resolvedPath: trivyDir };
  }

  return { ready: true };
}

export function buildSanitizedScannerEnv(workspaceDir: string): NodeJS.ProcessEnv {
  const grypeCacheDir = process.env.GRYPE_DB_CACHE_DIR || '/data/scanner-cache/grype';
  const osvDbDir = process.env.WINHOOD_OSV_DB_DIR || '/data/scanner-cache/osv';
  return {
    PATH: `${SAFE_WORKER_PATH}:${path.join(process.cwd(), 'node_modules', '.bin')}`,
    HOME: workspaceDir,
    TMPDIR: workspaceDir,
    TMP: workspaceDir,
    TEMP: workspaceDir,
    XDG_CACHE_HOME: path.join(workspaceDir, '.cache'),
    XDG_CONFIG_HOME: path.join(workspaceDir, '.config'),
    SEMGREP_SETTINGS_FILE: path.join(workspaceDir, '.semgrep-settings.yml'),
    SEMGREP_VERSION_CACHE_PATH: path.join(workspaceDir, '.semgrep-version-cache'),
    PYTHONDONTWRITEBYTECODE: '1',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    NO_COLOR: '1',
    SEMGREP_SEND_METRICS: 'off',
    SEMGREP_ENABLE_VERSION_CHECK: '0',
    GRYPE_DB_CACHE_DIR: grypeCacheDir,
    GRYPE_DB_AUTO_UPDATE: 'false',
    GRYPE_CHECK_FOR_APP_UPDATE: 'false',
    SYFT_CHECK_FOR_APP_UPDATE: 'false',
    WINHOOD_OSV_DB_DIR: osvDbDir,
    OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: osvDbDir,
    DO_NOT_TRACK: '1',
  };
}

export function redactScannerPayloadSecrets(toolId: ScannerToolId, payload: unknown): unknown {
  const redactPemBlocks = (input: string): string => {
    let out = input;
    let cursor = 0;
    while (cursor < out.length) {
      const start = out.indexOf('-----BEGIN ', cursor);
      if (start < 0) break;
      const headerEnd = out.indexOf('PRIVATE KEY-----', start);
      if (headerEnd < 0 || headerEnd - start > 64) {
        cursor = start + 11;
        continue;
      }
      const endMarker = out.indexOf('-----END ', headerEnd);
      if (endMarker < 0) {
        return `${out.slice(0, start)}[REDACTED_PRIVATE_KEY]`;
      }
      const tailEnd = out.indexOf('-----', endMarker + 9);
      const cutEnd = tailEnd >= 0 ? tailEnd + 5 : out.length;
      out = `${out.slice(0, start)}[REDACTED_PRIVATE_KEY]${out.slice(cutEnd)}`;
      cursor = start + '[REDACTED_PRIVATE_KEY]'.length;
    }
    return out;
  };
  const redactString = (value: string): string =>
    redactPemBlocks(value)
      .replace(/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, '[REDACTED_AWS_KEY]')
      .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g, '[REDACTED_GITHUB_TOKEN]')
      .replace(/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, '[REDACTED_GITHUB_TOKEN]')
      .replace(/\b(?:sk_live|wh_live|wh_canary)_[A-Za-z0-9_-]{12,}\b/g, '[REDACTED_SECRET_TOKEN]');

  if (toolId === 'gitleaks' && Array.isArray(payload)) {
    return payload.map((item) => {
      if (!item || typeof item !== 'object') return item;
      const rec = { ...(item as Record<string, unknown>) };
      if (typeof rec.Secret === 'string' && rec.Secret.length > 0) {
        rec.Secret = '[REDACTED]';
      }
      if (typeof rec.Match === 'string' && rec.Match.length > 0) {
        rec.Match = redactString(rec.Match);
      }
      if (typeof rec.Line === 'string' && rec.Line.length > 0) {
        rec.Line = redactString(rec.Line);
      }
      return rec;
    });
  }

  const walk = (node: unknown, depth = 0): unknown => {
    if (depth > 10 || node === null || node === undefined) return node;
    if (typeof node === 'string') return redactString(node);
    if (Array.isArray(node)) return node.map((v) => walk(v, depth + 1));
    if (typeof node === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        if (/^(?:secret|rawSecret|token|password|privateKey)$/i.test(k) && typeof v === 'string' && v.length > 0) {
          out[k] = '[REDACTED]';
        } else {
          out[k] = walk(v, depth + 1);
        }
      }
      return out;
    }
    return node;
  };
  return walk(payload);
}

const PINNED_SCANNER_SPECS: Record<ScannerToolId, PinnedScannerRunnerSpec> = {
  semgrep: {
    toolId: 'semgrep',
    binaryNames: ['semgrep', 'opengrep'],
    versionArgs: ['--version'],
    buildArgs: (ws, _outFile, rulesDir) => [
      'scan',
      '--config',
      rulesDir || '/opt/winhood-scanner-rules',
      '--offline',
      '--disable-version-check',
      '--json',
      '--quiet',
      '--metrics=off',
      '--no-git-ignore',
      ws,
    ],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      const obj = p as { results?: unknown[] };
      return { valid: Boolean(obj && Array.isArray(obj.results)), findingsCount: obj?.results?.length ?? 0 };
    },
    selfTestFiles: { 'sample.js': 'const x = 1;\nexport default x;\n' },
    positiveTestFiles: { 'vuln.js': 'export function run(input) { return eval(input); }\n' },
    minPositiveFindings: 1,
  },
  codeql: {
    toolId: 'codeql',
    binaryNames: ['codeql'],
    versionArgs: ['version', '--format=terse'],
    buildArgs: (ws, outFile) => ['database', 'analyze', '--format=sarifv2.1.0', `--output=${outFile}`, '--no-download', ws],
    outputFormat: 'SARIF',
    readsFromFile: true,
    validateParsedOutput: (p) => {
      const obj = p as { version?: string; runs?: Array<{ results?: unknown[] }> };
      const valid = Boolean(obj && obj.version === '2.1.0' && Array.isArray(obj.runs));
      const findingsCount = valid
        ? (obj.runs || []).reduce((acc, r) => acc + (Array.isArray(r.results) ? r.results.length : 0), 0)
        : 0;
      return { valid, findingsCount };
    },
    selfTestFiles: { 'sample.js': 'export const ok = 1;\n' },
  },
  gitleaks: {
    toolId: 'gitleaks',
    binaryNames: ['gitleaks'],
    versionArgs: ['version'],
    buildArgs: (ws, outFile) => [
      'detect',
      '--no-git',
      '--redact',
      '--source',
      ws,
      '--report-format',
      'json',
      '--report-path',
      outFile,
      '--exit-code',
      '0',
    ],
    outputFormat: 'JSON',
    readsFromFile: true,
    validateParsedOutput: (p) => ({
      valid: Array.isArray(p),
      findingsCount: Array.isArray(p) ? p.length : 0,
    }),
    selfTestFiles: { 'sample.txt': 'clean_config=true\n' },
    positiveTestFiles: {
      'leak.env': `AWS_ACCESS_KEY_ID=${['AKIA', 'IOSFODNN7EXAMPLE'].join('')}\n`,
    },
    minPositiveFindings: 1,
  },
  eslint: {
    toolId: 'eslint',
    binaryNames: ['eslint'],
    versionArgs: ['--version'],
    buildArgs: (ws, _outFile, configPath) => [
      '--no-config-lookup',
      ...(configPath ? ['--config', configPath] : []),
      '--format',
      'json',
      '--no-error-on-unmatched-pattern',
      ws,
    ],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      if (!Array.isArray(p)) return { valid: false, findingsCount: 0 };
      const count = p.reduce(
        (acc, item) => acc + (Array.isArray((item as { messages?: unknown[] })?.messages) ? (item as { messages: unknown[] }).messages.length : 0),
        0
      );
      return { valid: true, findingsCount: count };
    },
    selfTestFiles: { 'sample.js': 'export const ok = 1;\n' },
    positiveTestFiles: { 'vuln.js': 'export function bad(x) { return eval(x); }\n' },
    minPositiveFindings: 1,
  },
  ruff: {
    toolId: 'ruff',
    binaryNames: ['ruff'],
    versionArgs: ['--version'],
    buildArgs: (ws) => ['check', '--output-format', 'json', '--exit-zero', ws],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => ({
      valid: Array.isArray(p),
      findingsCount: Array.isArray(p) ? p.length : 0,
    }),
    selfTestFiles: { 'sample.py': 'def ok() -> int:\n    return 1\n' },
    positiveTestFiles: { 'vuln.py': 'import os\n\ndef unused() -> int:\n    return 1\n' },
    minPositiveFindings: 1,
  },
  bandit: {
    toolId: 'bandit',
    binaryNames: ['bandit'],
    versionArgs: ['--version'],
    buildArgs: (ws) => ['-r', ws, '-f', 'json', '-q', '--exit-zero'],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      const obj = p as { results?: unknown[] };
      return { valid: Boolean(obj && Array.isArray(obj.results)), findingsCount: obj?.results?.length ?? 0 };
    },
    selfTestFiles: { 'sample.py': 'def ok():\n    return 1\n' },
    positiveTestFiles: {
      'vuln.py': 'import subprocess\n\ndef run(cmd):\n    return subprocess.Popen(cmd, shell=True)\n',
    },
    minPositiveFindings: 1,
  },
  roslyn: {
    toolId: 'roslyn',
    binaryNames: ['dotnet'],
    versionArgs: ['--version'],
    buildArgs: (ws, outFile) => [
      'build',
      ws,
      '--no-restore',
      '/p:TreatWarningsAsErrors=false',
      `/p:ErrorLog=${outFile},version=2.1`,
    ],
    outputFormat: 'SARIF',
    readsFromFile: true,
    validateParsedOutput: (p) => {
      const obj = p as { version?: string; runs?: Array<{ results?: unknown[] }> };
      return {
        valid: Boolean(obj && Array.isArray(obj.runs)),
        findingsCount: Array.isArray(obj?.runs)
          ? obj.runs.reduce((acc, r) => acc + (Array.isArray(r.results) ? r.results.length : 0), 0)
          : 0,
      };
    },
    selfTestFiles: { 'Sample.cs': 'public class Sample { public int Ok() => 1; }\n' },
  },
  spotbugs: {
    toolId: 'spotbugs',
    binaryNames: ['spotbugs'],
    versionArgs: ['-version'],
    buildArgs: (ws) => ['-textui', '-sarif', ws],
    outputFormat: 'SARIF',
    validateParsedOutput: (p) => {
      const obj = p as { runs?: unknown[] };
      return { valid: Boolean(obj && Array.isArray(obj.runs)), findingsCount: 0 };
    },
    selfTestFiles: { 'Sample.java': 'public class Sample { public int ok() { return 1; } }\n' },
  },
  checkstyle: {
    toolId: 'checkstyle',
    binaryNames: ['checkstyle'],
    versionArgs: ['--version'],
    buildArgs: (ws) => ['-c', '/google_checks.xml', '-f', 'sarif', ws],
    outputFormat: 'SARIF',
    validateParsedOutput: (p) => {
      const obj = p as { runs?: unknown[] };
      return { valid: Boolean(obj && Array.isArray(obj.runs)), findingsCount: 0 };
    },
    selfTestFiles: { 'Sample.java': 'public class Sample { public int ok() { return 1; } }\n' },
  },
  'osv-scanner': {
    toolId: 'osv-scanner',
    binaryNames: ['osv-scanner'],
    versionArgs: ['--version'],
    buildArgs: (ws, _outFile, dbDir) => [
      'scan',
      '--format=json',
      '--offline',
      '--download-offline-databases=false',
      ...(dbDir ? ['--local-db-path', dbDir] : []),
      '-r',
      ws,
    ],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      const obj = p as { results?: unknown[] };
      return { valid: Boolean(obj && Array.isArray(obj.results)), findingsCount: obj?.results?.length ?? 0 };
    },
    selfTestFiles: { 'package-lock.json': JSON.stringify({ name: 'selftest', lockfileVersion: 3, packages: {} }) },
  },
  syft: {
    toolId: 'syft',
    binaryNames: ['syft'],
    versionArgs: ['version'],
    buildArgs: (ws) => ['scan', `dir:${ws}`, '-o', 'cyclonedx-json'],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      const obj = p as { bomFormat?: string; components?: unknown[] };
      return {
        valid: obj?.bomFormat === 'CycloneDX',
        findingsCount: Array.isArray(obj?.components) ? obj.components.length : 0,
      };
    },
    selfTestFiles: { 'package.json': JSON.stringify({ name: 'selftest', version: '1.0.0' }) },
  },
  grype: {
    toolId: 'grype',
    binaryNames: ['grype'],
    versionArgs: ['version'],
    buildArgs: (ws) => [`dir:${ws}`, '-o', 'json'],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      const obj = p as { matches?: unknown[] };
      return { valid: Boolean(obj && Array.isArray(obj.matches)), findingsCount: obj?.matches?.length ?? 0 };
    },
    selfTestFiles: { 'package.json': JSON.stringify({ name: 'selftest', version: '1.0.0' }) },
  },
  trivy: {
    toolId: 'trivy',
    binaryNames: ['trivy'],
    versionArgs: ['--version'],
    buildArgs: (ws) => ['fs', '--format', 'json', '--offline-scan', '--quiet', ws],
    outputFormat: 'JSON',
    validateParsedOutput: (p) => {
      const obj = p as { Results?: unknown[] };
      return { valid: Boolean(obj && typeof obj === 'object'), findingsCount: obj?.Results?.length ?? 0 };
    },
    selfTestFiles: { 'package.json': JSON.stringify({ name: 'selftest', version: '1.0.0' }) },
  },
};

function detectBinaryVersion(binaryPath: string, versionArgs: string[]): string | null {
  try {
    const res = spawnSync(binaryPath, versionArgs, {
      shell: false,
      encoding: 'utf8',
      timeout: 4_000,
      env: { PATH: SAFE_WORKER_PATH, LANG: 'C.UTF-8' },
    });
    const combined = `${res.stdout || ''}\n${res.stderr || ''}`.trim();
    return combined ? combined.split(/\r?\n/)[0]?.trim() || null : null;
  } catch {
    return null;
  }
}

function sendSignalToProcessGroup(child: ChildProcess, signal: NodeJS.Signals): void {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform !== 'win32' && typeof child.pid === 'number' && child.pid > 0) {
      process.kill(-child.pid, signal);
    } else {
      child.kill(signal);
    }
  } catch {
    try {
      child.kill(signal);
    } catch {
      // Process already exited
    }
  }
}

export async function terminateProcessGroup(child: ChildProcess, graceMs = 1_500): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return true;
  }

  return await new Promise<boolean>((resolve) => {
    let settled = false;
    const finish = (terminated: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(escalateTimer);
      clearTimeout(finalTimer);
      child.off('exit', onExit);
      child.off('close', onExit);
      resolve(terminated);
    };
    const onExit = (): void => finish(true);

    child.once('exit', onExit);
    child.once('close', onExit);

    sendSignalToProcessGroup(child, 'SIGTERM');

    const escalateTimer = setTimeout(() => {
      sendSignalToProcessGroup(child, 'SIGKILL');
    }, Math.max(100, graceMs));
    escalateTimer.unref();

    const finalTimer = setTimeout(() => {
      finish(child.exitCode !== null || child.signalCode !== null);
    }, Math.max(400, graceMs + 1_500));
    finalTimer.unref();
  });
}

function registerActiveProcess(entry: ActiveWorkerProcessEntry): void {
  let set = ACTIVE_JOB_PROCESSES.get(entry.jobId);
  if (!set) {
    set = new Set<ActiveWorkerProcessEntry>();
    ACTIVE_JOB_PROCESSES.set(entry.jobId, set);
  }
  set.add(entry);
}

function unregisterActiveProcess(entry: ActiveWorkerProcessEntry): void {
  const set = ACTIVE_JOB_PROCESSES.get(entry.jobId);
  if (!set) return;
  set.delete(entry);
  if (set.size === 0) {
    ACTIVE_JOB_PROCESSES.delete(entry.jobId);
  }
}

export function getActiveScannerProcessCount(): number {
  let count = 0;
  for (const set of ACTIVE_JOB_PROCESSES.values()) {
    count += set.size;
  }
  return count;
}

function markJobCancelled(jobId: string): void {
  CANCELLED_JOB_IDS.add(jobId);
  if (CANCELLED_JOB_IDS.size > MAX_CANCELLED_JOB_HISTORY) {
    const oldest = CANCELLED_JOB_IDS.values().next().value;
    if (oldest) CANCELLED_JOB_IDS.delete(oldest);
  }
}

export async function cancelActiveWorkerJob(jobId: string): Promise<{
  jobId: string;
  terminated: boolean;
  activeProcessesKilled: number;
}> {
  markJobCancelled(jobId);
  const set = ACTIVE_JOB_PROCESSES.get(jobId);
  if (!set || set.size === 0) {
    return { jobId, terminated: true, activeProcessesKilled: 0 };
  }

  const entries = Array.from(set);
  let killed = 0;
  let allTerminated = true;
  await Promise.all(
    entries.map(async (entry) => {
      entry.cancelled = true;
      const ok = await terminateProcessGroup(entry.child, 1_200);
      if (ok) {
        killed += 1;
      } else {
        allTerminated = false;
      }
      unregisterActiveProcess(entry);
    })
  );

  return {
    jobId,
    terminated: allTerminated,
    activeProcessesKilled: killed,
  };
}

export async function terminateAllActiveScannerProcesses(): Promise<number> {
  const jobIds = Array.from(ACTIVE_JOB_PROCESSES.keys());
  let total = 0;
  for (const jobId of jobIds) {
    const res = await cancelActiveWorkerJob(jobId);
    total += res.activeProcessesKilled;
  }
  return total;
}

export interface SpawnManagedProcessResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  cancelled: boolean;
  spawnError?: string;
}

export async function spawnManagedScannerProcess(params: {
  jobId: string;
  toolId: ScannerToolId;
  command: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
}): Promise<SpawnManagedProcessResult> {
  if (CANCELLED_JOB_IDS.has(params.jobId)) {
    return {
      stdout: '',
      stderr: '',
      exitCode: null,
      signal: 'SIGTERM',
      timedOut: false,
      cancelled: true,
    };
  }

  return await new Promise<SpawnManagedProcessResult>((resolve) => {
    const child = spawn(params.command, params.args, {
      cwd: params.cwd,
      shell: false,
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: params.env,
    });

    const entry: ActiveWorkerProcessEntry = {
      jobId: params.jobId,
      toolId: params.toolId,
      child,
      pid: child.pid,
      cancelled: false,
      startedAt: Date.now(),
    };
    registerActiveProcess(entry);

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let settled = false;

    const finalize = (result: SpawnManagedProcessResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutHandle);
      unregisterActiveProcess(entry);
      resolve(result);
    };

    const effectiveTimeout = Math.max(500, Math.min(180_000, params.timeoutMs));
    const timeoutHandle = setTimeout(() => {
      timedOut = true;
      void terminateProcessGroup(child, 1_000);
    }, effectiveTimeout);
    timeoutHandle.unref();

    child.stdout?.on('data', (chunk: Buffer) => {
      if (stdoutBytes >= MAX_STDIO_CAPTURE_BYTES) return;
      const remaining = MAX_STDIO_CAPTURE_BYTES - stdoutBytes;
      const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
      stdoutChunks.push(slice);
      stdoutBytes += slice.length;
    });

    child.stderr?.on('data', (chunk: Buffer) => {
      if (stderrBytes >= MAX_STDIO_CAPTURE_BYTES) return;
      const remaining = MAX_STDIO_CAPTURE_BYTES - stderrBytes;
      const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
      stderrChunks.push(slice);
      stderrBytes += slice.length;
    });

    child.once('error', (err) => {
      finalize({
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        exitCode: null,
        signal: null,
        timedOut,
        cancelled: entry.cancelled || CANCELLED_JOB_IDS.has(params.jobId),
        spawnError: err.message,
      });
    });

    child.once('close', (code, signal) => {
      finalize({
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        exitCode: code,
        signal,
        timedOut,
        cancelled: entry.cancelled || CANCELLED_JOB_IDS.has(params.jobId),
      });
    });

    // Guard against race where cancel arrived right as spawn completed
    if (CANCELLED_JOB_IDS.has(params.jobId)) {
      entry.cancelled = true;
      void terminateProcessGroup(child, 500);
    }
  });
}

export async function runIsolatedScannerTool(params: {
  jobId: string;
  toolId: ScannerToolId;
  filesMap: Record<string, string>;
  timeoutMs: number;
  baseWorkspaceDir?: string;
}): Promise<ScannerToolJobOutput> {
  const spec = PINNED_SCANNER_SPECS[params.toolId];
  if (CANCELLED_JOB_IDS.has(params.jobId)) {
    return {
      toolId: params.toolId,
      state: 'CANCELLED',
      version: null,
      exitCode: null,
      durationMs: 0,
      outputFormat: spec.outputFormat,
      outputValidated: false,
      findingsCount: 0,
      rawOutputSha256: crypto.createHash('sha256').update(`CANCELLED:${params.toolId}`).digest('hex'),
      limitations: ['Execução cancelada antes do disparo da ferramenta.'],
    };
  }

  const binPath = resolveAllowedBinary(spec.binaryNames);
  if (!binPath) {
    return {
      toolId: params.toolId,
      state: 'NOT_INSTALLED',
      version: null,
      exitCode: null,
      durationMs: 0,
      outputFormat: spec.outputFormat,
      outputValidated: false,
      findingsCount: 0,
      rawOutputSha256: crypto.createHash('sha256').update(`NOT_INSTALLED:${params.toolId}`).digest('hex'),
      limitations: [`Binário (${spec.binaryNames.join(' / ')}) não instalado no container worker.`],
    };
  }

  const version = detectBinaryVersion(binPath, spec.versionArgs);
  const prereq = checkToolOfflinePrerequisites(params.toolId);
  if (!prereq.ready) {
    const state = prereq.state || 'NOT_CONFIGURED';
    return {
      toolId: params.toolId,
      state,
      version,
      exitCode: null,
      durationMs: 0,
      outputFormat: spec.outputFormat,
      outputValidated: false,
      findingsCount: 0,
      rawOutputSha256: crypto.createHash('sha256').update(`${state}:${params.toolId}`).digest('hex'),
      limitations: [prereq.reason || `Pré-requisito offline ausente para ${params.toolId}.`],
      errorMessage: state,
    };
  }

  const startMs = performance.now();

  const { result } = await EphemeralWorkspaceManager.withWorkspace(
    {
      jobId: `${params.jobId}-${params.toolId}`,
      filesMap: params.filesMap,
      baseDir: params.baseWorkspaceDir,
    },
    async (ws) => {
      const outFilePath = path.join(ws.rootPath, `.winhood_${params.toolId}_out.json`);
      const args = spec.buildArgs(ws.rootPath, outFilePath, prereq.resolvedPath);
      const env = buildSanitizedScannerEnv(ws.rootPath);

      const proc = await spawnManagedScannerProcess({
        jobId: params.jobId,
        toolId: params.toolId,
        command: binPath,
        args,
        cwd: ws.rootPath,
        env,
        timeoutMs: Math.max(2_000, Math.min(180_000, params.timeoutMs)),
      });

      const durationMs = Math.max(1, Math.round(performance.now() - startMs));

      if (proc.cancelled) {
        return {
          toolId: params.toolId,
          state: 'CANCELLED' as const,
          version,
          exitCode: proc.exitCode,
          durationMs,
          outputFormat: spec.outputFormat,
          outputValidated: false,
          findingsCount: 0,
          rawOutputSha256: crypto.createHash('sha256').update('CANCELLED').digest('hex'),
          limitations: ['Processo do analisador encerrado por solicitação de cancelamento.'],
          errorMessage: 'SCANNER_EXECUTION_CANCELLED',
        };
      }

      if (proc.timedOut) {
        return {
          toolId: params.toolId,
          state: 'TIMED_OUT' as const,
          version,
          exitCode: proc.exitCode,
          durationMs,
          outputFormat: spec.outputFormat,
          outputValidated: false,
          findingsCount: 0,
          rawOutputSha256: crypto.createHash('sha256').update('TIMED_OUT').digest('hex'),
          limitations: [`Execução excedeu timeout de ${params.timeoutMs}ms e o grupo de processos foi encerrado.`],
          errorMessage: 'SCANNER_EXECUTION_TIMED_OUT',
        };
      }

      const rawOutput =
        spec.readsFromFile && fs.existsSync(outFilePath)
          ? fs.readFileSync(outFilePath, 'utf8')
          : proc.stdout || '';
      const rawOutputSha256 = crypto.createHash('sha256').update(rawOutput, 'utf8').digest('hex');

      if (!rawOutput.trim()) {
        return {
          toolId: params.toolId,
          state: 'INCONCLUSIVE' as const,
          version,
          exitCode: proc.exitCode,
          durationMs,
          outputFormat: spec.outputFormat,
          outputValidated: false,
          findingsCount: 0,
          rawOutputSha256,
          limitations: ['Saída vazia do analisador; resultado não pôde ser validado estruturalmente.'],
          errorMessage: (proc.stderr || proc.spawnError || '').slice(0, 400) || undefined,
        };
      }

      try {
        const parsed = JSON.parse(rawOutput);
        const validation = spec.validateParsedOutput(parsed);
        const redactedPayload = validation.valid
          ? redactScannerPayloadSecrets(params.toolId, parsed)
          : undefined;
        return {
          toolId: params.toolId,
          state: validation.valid ? ('COMPLETED' as const) : ('FAILED' as const),
          version,
          exitCode: proc.exitCode,
          durationMs,
          outputFormat: spec.outputFormat,
          outputValidated: validation.valid,
          findingsCount: validation.findingsCount,
          rawOutputSha256,
          normalizedPayload: redactedPayload,
          limitations: validation.valid
            ? []
            : ['Saída JSON/SARIF produzida pelo analisador não atendeu ao esquema esperado.'],
        };
      } catch {
        return {
          toolId: params.toolId,
          state: 'FAILED' as const,
          version,
          exitCode: proc.exitCode,
          durationMs,
          outputFormat: spec.outputFormat,
          outputValidated: false,
          findingsCount: 0,
          rawOutputSha256,
          limitations: ['Falha ao interpretar saída JSON/SARIF do analisador.'],
          errorMessage: (proc.stderr || rawOutput).slice(0, 400),
        };
      }
    }
  );

  return result;
}

/**
 * Probes every cataloged tool by actually executing it on a minimal ephemeral self-test file.
 * A tool is NEVER marked `OPERATIONAL` solely because its binary exists on PATH or when its
 * offline vulnerability database / ruleset is missing.
 */
export async function probeVerifiedWorkerCapabilities(
  baseWorkspaceDir?: string
): Promise<ToolCapabilityRecord[]> {
  const isContainerizedWorker =
    process.env.WINHOOD_SCANNER_WORKER_CONTAINER === 'true' || fs.existsSync('/.dockerenv');
  const results: ToolCapabilityRecord[] = [];

  for (const catalogEntry of SCANNER_TOOL_CATALOG) {
    const spec = PINNED_SCANNER_SPECS[catalogEntry.toolId];
    const binPath = resolveAllowedBinary(spec.binaryNames);
    const checkedAt = new Date().toISOString();

    if (!binPath) {
      results.push({
        toolId: catalogEntry.toolId,
        displayName: catalogEntry.displayName,
        purpose: catalogEntry.purpose,
        binaryNames: [...catalogEntry.binaryNames],
        installed: false,
        version: null,
        executionEnvironment: isContainerizedWorker ? 'DOCKER_SCANNER_WORKER' : 'UNAVAILABLE',
        isolationAvailable: isContainerizedWorker,
        executionPerformed: false,
        outputValidated: false,
        limitations: ['Ferramenta não instalada nesta imagem de worker.'],
        finalState: 'NOT_INSTALLED',
        checkedAt,
      });
      continue;
    }

    const version = detectBinaryVersion(binPath, spec.versionArgs);
    const prereq = checkToolOfflinePrerequisites(catalogEntry.toolId);
    if (!prereq.ready) {
      results.push({
        toolId: catalogEntry.toolId,
        displayName: catalogEntry.displayName,
        purpose: catalogEntry.purpose,
        binaryNames: [...catalogEntry.binaryNames],
        installed: true,
        version,
        executionEnvironment: isContainerizedWorker ? 'DOCKER_SCANNER_WORKER' : 'UNAVAILABLE',
        isolationAvailable: isContainerizedWorker,
        executionPerformed: false,
        outputValidated: false,
        limitations: [prereq.reason || 'Pré-requisito offline ausente.'],
        finalState: prereq.state || 'NOT_CONFIGURED',
        checkedAt,
      });
      continue;
    }

    if (!isContainerizedWorker && process.env.WINHOOD_ALLOW_WORKER_SELFTEST_HOST !== 'true') {
      results.push({
        toolId: catalogEntry.toolId,
        displayName: catalogEntry.displayName,
        purpose: catalogEntry.purpose,
        binaryNames: [...catalogEntry.binaryNames],
        installed: true,
        version,
        executionEnvironment: 'UNAVAILABLE',
        isolationAvailable: false,
        executionPerformed: false,
        outputValidated: false,
        limitations: [
          'Binário detectado, porém isolamento de container worker não está ativo; execução bloqueada.',
        ],
        finalState: 'BLOCKED',
        checkedAt,
      });
      continue;
    }

    const probeRun = await runIsolatedScannerTool({
      jobId: `selftest-neg-${catalogEntry.toolId}`,
      toolId: catalogEntry.toolId,
      filesMap: spec.selfTestFiles,
      timeoutMs: 12_000,
      baseWorkspaceDir,
    });

    let operational = probeRun.state === 'COMPLETED' && probeRun.outputValidated;
    const probeLimitations = [...probeRun.limitations];

    // Positive detection & secret-redaction check for offline-verifiable tools
    if (operational && spec.positiveTestFiles && (spec.minPositiveFindings ?? 0) > 0) {
      const posRun = await runIsolatedScannerTool({
        jobId: `selftest-pos-${catalogEntry.toolId}`,
        toolId: catalogEntry.toolId,
        filesMap: spec.positiveTestFiles,
        timeoutMs: 12_000,
        baseWorkspaceDir,
      });
      if (
        posRun.state !== 'COMPLETED' ||
        !posRun.outputValidated ||
        posRun.findingsCount < (spec.minPositiveFindings ?? 1)
      ) {
        operational = false;
        probeLimitations.push(
          `Autoteste positivo falhou para ${catalogEntry.toolId} (esperado >= ${spec.minPositiveFindings ?? 1} achado(s), obtido ${posRun.findingsCount}).`
        );
      } else if (catalogEntry.toolId === 'gitleaks' && posRun.normalizedPayload) {
        const serializedPos = JSON.stringify(posRun.normalizedPayload);
        if (serializedPos.includes(['AKIA', 'IOSFODNN7EXAMPLE'].join(''))) {
          operational = false;
          probeLimitations.push('Falha de redação de segredo no autoteste positivo do Gitleaks.');
        }
      }
    }

    const mappedState = operational
      ? 'OPERATIONAL'
      : probeRun.state === 'DATABASE_UNAVAILABLE' ||
          probeRun.state === 'RULES_UNAVAILABLE' ||
          probeRun.state === 'NOT_CONFIGURED' ||
          probeRun.state === 'INCONCLUSIVE' ||
          probeRun.state === 'BLOCKED'
        ? probeRun.state
        : 'EXECUTION_FAILED';

    results.push({
      toolId: catalogEntry.toolId,
      displayName: catalogEntry.displayName,
      purpose: catalogEntry.purpose,
      binaryNames: [...catalogEntry.binaryNames],
      installed: true,
      version: probeRun.version || version,
      executionEnvironment: isContainerizedWorker ? 'DOCKER_SCANNER_WORKER' : 'OS_SANDBOX_SUBPROCESS',
      isolationAvailable: isContainerizedWorker,
      executionPerformed: true,
      outputValidated: operational,
      limitations: probeLimitations,
      finalState: mappedState,
      checkedAt,
    });
  }

  return results;
}

export type WorkerToolExecutionOverride = (params: {
  jobId: string;
  toolId: ScannerToolId;
  filesMap: Record<string, string>;
  timeoutMs: number;
  baseWorkspaceDir?: string;
}) => Promise<ScannerToolJobOutput>;

export function createScannerWorkerApp(options?: {
  workerToken?: string;
  baseWorkspaceDir?: string;
  toolRunnerOverride?: WorkerToolExecutionOverride;
}): express.Express {
  const app = express();
  const expectedToken = (
    options?.workerToken ??
    process.env.WINHOOD_SCANNER_WORKER_TOKEN ??
    ''
  ).trim();

  if (process.env.NODE_ENV === 'production' && expectedToken.length < 24) {
    throw new Error(
      'SCANNER_WORKER_TOKEN_REQUIRED: WINHOOD_SCANNER_WORKER_TOKEN (>= 24 caracteres) é obrigatório em produção.'
    );
  }

  app.disable('x-powered-by');
  app.use(express.json({ limit: '50mb' }));

  // Healthcheck (no secrets exposed)
  app.get('/worker/health', (_req, res) => {
    res.json({
      status: 'ONLINE',
      service: 'winhood-scanner-worker',
      nonRootUid: typeof process.getuid === 'function' ? process.getuid() : null,
      activeWorkspaces: EphemeralWorkspaceManager.getActiveWorkspaceCount(),
      activeScannerProcesses: getActiveScannerProcessCount(),
      containerIsolated:
        process.env.WINHOOD_SCANNER_WORKER_CONTAINER === 'true' || fs.existsSync('/.dockerenv'),
      timestamp: new Date().toISOString(),
    });
  });

  // Authenticate all operational worker routes via constant-time Bearer check
  app.use((req, res, next) => {
    if (!expectedToken) return next();
    const authHeader = String(req.headers.authorization || '');
    const provided = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const a = Buffer.from(provided, 'utf8');
    const b = Buffer.from(expectedToken, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(401).json({ error: 'WORKER_UNAUTHORIZED' });
    }
    return next();
  });

  app.get('/worker/capabilities', async (_req, res) => {
    const capabilities = await probeVerifiedWorkerCapabilities(options?.baseWorkspaceDir);
    res.json({
      service: 'winhood-scanner-worker',
      checkedAt: new Date().toISOString(),
      capabilities,
    });
  });

  app.post('/worker/jobs/:jobId/cancel', async (req, res) => {
    const safeJobId = String(req.params.jobId || '').replace(/[^a-zA-Z0-9_-]/g, '_');
    if (!safeJobId) {
      return res.status(400).json({ error: 'INVALID_JOB_ID' });
    }
    const outcome = await cancelActiveWorkerJob(safeJobId);
    return res.json({
      ...outcome,
      activeWorkspaces: EphemeralWorkspaceManager.getActiveWorkspaceCount(),
      activeScannerProcesses: getActiveScannerProcessCount(),
    });
  });

  app.post('/worker/execute', async (req, res) => {
    const body = req.body as {
      jobId?: string;
      toolIds?: string[];
      filesMap?: Record<string, string>;
      timeoutMs?: number;
    };
    const jobId = String(body?.jobId || `job-${crypto.randomUUID()}`).replace(/[^a-zA-Z0-9_-]/g, '_');
    const rawToolIds = Array.isArray(body?.toolIds) ? body.toolIds : [];
    const validToolIds = rawToolIds.filter((t): t is ScannerToolId =>
      ALLOWED_SCANNER_TOOL_IDS.has(t as ScannerToolId)
    );
    if (validToolIds.length === 0) {
      return res.status(400).json({ error: 'INVALID_TOOL_IDS' });
    }
    if (!body?.filesMap || typeof body.filesMap !== 'object' || Array.isArray(body.filesMap)) {
      return res.status(400).json({ error: 'INVALID_FILES_MAP' });
    }
    const timeoutMs = Math.max(2_000, Math.min(180_000, Number(body.timeoutMs) || 30_000));
    const runner = options?.toolRunnerOverride || runIsolatedScannerTool;

    const results: ScannerToolJobOutput[] = [];
    for (const toolId of validToolIds) {
      const out = await runner({
        jobId,
        toolId,
        filesMap: body.filesMap,
        timeoutMs,
        baseWorkspaceDir: options?.baseWorkspaceDir,
      });
      results.push(out);
      if (CANCELLED_JOB_IDS.has(jobId)) {
        break;
      }
    }

    return res.json({
      jobId,
      completedAt: new Date().toISOString(),
      results,
    });
  });

  return app;
}

export async function startScannerWorkerServer(options?: {
  host?: string;
  port?: number;
  workerToken?: string;
  baseWorkspaceDir?: string;
  toolRunnerOverride?: WorkerToolExecutionOverride;
}): Promise<{ server: http.Server; port: number; url: string; close: () => Promise<void> }> {
  const app = createScannerWorkerApp({
    workerToken: options?.workerToken,
    baseWorkspaceDir: options?.baseWorkspaceDir,
    toolRunnerOverride: options?.toolRunnerOverride,
  });
  const host = resolveWorkerBindHost(options?.host, '127.0.0.1');
  const port = resolveWorkerPort(options?.port);

  const server = await new Promise<http.Server>((resolve, reject) => {
    const srv = app.listen(port, host, () => resolve(srv));
    srv.once('error', reject);
  });

  const addr = server.address();
  const effectivePort = typeof addr === 'object' && addr ? addr.port : port;
  const isMain =
    typeof process !== 'undefined' &&
    Array.isArray(process.argv) &&
    Boolean(process.argv[1]) &&
    /scanner[-_]worker/i.test(process.argv[1]!);

  const shutdownController = registerGracefulShutdown({
    server,
    onBeforeClose: async () => {
      await terminateAllActiveScannerProcesses();
    },
    onAfterClose: () => {
      EphemeralWorkspaceManager.cleanupAllActiveWorkspaces();
    },
    signals: isMain ? ['SIGINT', 'SIGTERM'] : [],
    exitProcess: isMain,
    enableIpcShutdown: isMain,
  });

  return {
    server,
    port: effectivePort,
    url: `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${effectivePort}`,
    close: async () => {
      shutdownController.unregister();
      await shutdownController.shutdown('WORKER_CLOSE');
    },
  };
}

const isWorkerEntrypoint =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  Boolean(process.argv[1]) &&
  /scanner[-_]worker/i.test(process.argv[1]!);

if (isWorkerEntrypoint) {
  startScannerWorkerServer({
    host: resolveWorkerBindHost(undefined, '0.0.0.0'),
    port: resolveWorkerPort(),
  })
    .then(({ port }) => {
      console.log(`[WinHood Scanner Worker] Listening on internal port ${port}`);
    })
    .catch((err) => {
      console.error('[WinHood Scanner Worker] Fatal startup error:', err);
      process.exit(1);
    });
}
