import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createWinHoodApp } from '../../server';
import { KeyManagementService } from './KeyManagementService';
import {
  EncryptedArtifactStore,
  VAULT_BUNDLE_FILENAME,
  VAULT_MANIFEST_FILENAME,
} from '../storage/EncryptedArtifactStore';
import {
  EphemeralWorkspaceManager,
  resolveEphemeralWorkspaceRoot,
} from '../execution/EphemeralWorkspaceManager';
import {
  registerGracefulShutdown,
  WINHOOD_IPC_SHUTDOWN_MESSAGE,
} from '../server/gracefulShutdown';
import { ScannerJobOrchestrator } from '../worker/ScannerJobOrchestrator';
import {
  startScannerWorkerServer,
  probeVerifiedWorkerCapabilities,
  checkToolOfflinePrerequisites,
  getAllowedBinarySearchDirs,
  resolveWorkerBindHost,
  resolveWorkerPort,
  spawnManagedScannerProcess,
  getActiveScannerProcessCount,
} from '../worker/scannerWorkerServer';
import { ParserRegistry } from '../analyzers/ParserRegistry';
import { TaintAnalyzer } from '../analyzers/TaintAnalyzer';
import { RuleRegistry, RULE_CATALOG_VERSION } from '../analyzers/RuleRegistry';
import {
  compareSemver,
  comparePep440,
  compareMavenVersion,
  compareNugetVersion,
  satisfiesVersionRange,
  ScaCorrelator,
} from '../analyzers/sca/ScaCorrelator';
import { SbomGenerator } from '../analyzers/sca/SbomGenerator';
import {
  buildVerifiableEvidenceChain,
  signEvidenceManifestHmacSha256,
  verifyEvidenceChainAndManifest,
  DEFAULT_CRYPTOGRAPHIC_SCOPE_DISCLAIMER,
} from '../engine/evidenceProvenanceEngine';
import { QualityGateEngine, BUILTIN_QUALITY_GATES } from '../gate/QualityGateEngine';
import {
  CrossToolBenchmarkHarness,
  CONTROLLED_11_CLASS_VALIDATION_CORPUS,
} from '../validation/CrossToolBenchmarkHarness';
import { resolveViteAllowedHosts } from '../../vite.config';
import { evaluateAuditReport } from '../../scripts/verify-npm-audit.mjs';
import type { Software, VeracityCheckResult } from '../types/benchmark';

function createTempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function walkAllFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  const acc: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      acc.push(...walkAllFiles(full));
    } else if (entry.isFile()) {
      acc.push(full);
    }
  }
  return acc;
}

// ============================================================================
// 1. P0 — Encrypted-Only Storage, Canary Plaintext Regression, Key Rotation & Migration
// ============================================================================
test('P0-Storage: EncryptedArtifactStore persists ZERO plaintext canary on disk, survives key rotation, and migrates legacy plaintext atomically & idempotently', async () => {
  const prevDataDir = process.env.WINHOOD_DATA_DIR;
  const tmpDataDir = createTempDir('wh-p0-enc-store-');
  const artifactsRoot = path.join(tmpDataDir, 'isolated_artifacts');
  process.env.WINHOOD_DATA_DIR = tmpDataDir;

  try {
    const canarySecret = `WINHOOD_CANARY_PLAINTEXT_NEVER_DISK_${crypto.randomBytes(8).toString('hex')}`;
    const filesMap = {
      'src/app.ts': `export const secretToken = "${canarySecret}";\n`,
      'src/nested/helper.ts': 'export const helper = (x: number) => x + 1;\n',
    };

    const { targetDir, manifest } = EncryptedArtifactStore.writeEncryptedBundle({
      softwareSlug: 'canary-service',
      filesMap,
      artifactsRoot,
    });

    assert.equal(manifest.storagePolicy, 'ENCRYPTED_ONLY_NO_PLAINTEXT_AT_REST');
    assert.equal(manifest.fileCount, 2);
    assert.ok(fs.existsSync(path.join(targetDir, VAULT_BUNDLE_FILENAME)));
    assert.ok(fs.existsSync(path.join(targetDir, VAULT_MANIFEST_FILENAME)));

    // Canary scan across EVERY byte of EVERY file in artifactsRoot
    const diskFiles = walkAllFiles(artifactsRoot);
    assert.equal(diskFiles.length, 2, 'Only encrypted envelope and non-secret manifest may exist');
    for (const filePath of diskFiles) {
      const rawBytes = fs.readFileSync(filePath, 'utf8');
      assert.ok(
        !rawBytes.includes(canarySecret),
        `Canary secret leaked in plaintext at ${filePath}`
      );
    }

    const auditClean = EncryptedArtifactStore.auditNoPlaintextOnDisk(artifactsRoot);
    assert.equal(auditClean.clean, true);
    assert.equal(auditClean.plaintextFilePaths.length, 0);
    assert.equal(auditClean.encryptedBundleCount, 1);

    // Authorized decryption recovers exact content
    const recovered = EncryptedArtifactStore.readEncryptedBundle(targetDir);
    assert.equal(recovered['src/app.ts'], filesMap['src/app.ts']);
    assert.equal(recovered['src/nested/helper.ts'], filesMap['src/nested/helper.ts']);

    // Unauthorized wrong key fails closed
    const wrongKey = crypto.randomBytes(32);
    assert.throws(
      () => EncryptedArtifactStore.readEncryptedBundle(targetDir, wrongKey),
      /Decifração|Failed|Unsupported state|unable to authenticate|auth/i
    );

    // Tampered ciphertext fails integrity check
    const bundlePath = path.join(targetDir, VAULT_BUNDLE_FILENAME);
    const originalBundle = fs.readFileSync(bundlePath, 'utf8');
    fs.writeFileSync(bundlePath, originalBundle.slice(0, -4) + 'AAAA', 'utf8');
    assert.throws(
      () => EncryptedArtifactStore.readEncryptedBundle(targetDir),
      /ENCRYPTED_BUNDLE_INTEGRITY_VIOLATION/i
    );
    fs.writeFileSync(bundlePath, originalBundle, 'utf8');

    // Path traversal blocked
    assert.throws(
      () =>
        EncryptedArtifactStore.writeEncryptedBundle({
          softwareSlug: 'canary-service',
          filesMap: { '../../escape.txt': 'evil' },
          artifactsRoot,
        }),
      /Path Traversal/i
    );

    // Key rotation + re-encryption
    const beforeKeyId = KeyManagementService.getActiveVaultAesKey().keyId;
    KeyManagementService.rotateKey('TOKEN_VAULT_AES256');
    const reenc = EncryptedArtifactStore.reencryptAllBundles(artifactsRoot);
    assert.equal(reenc.reencryptedCount, 1);
    assert.equal(reenc.errors.length, 0);
    assert.notEqual(reenc.newKeyId, beforeKeyId);
    const postRotationRecovered = EncryptedArtifactStore.readEncryptedBundle(targetDir);
    assert.equal(postRotationRecovered['src/app.ts'], filesMap['src/app.ts']);

    // Legacy plaintext migration: atomic, round-trip verified, and idempotent
    const legacySlugDir = path.join(artifactsRoot, 'legacy-plaintext-app', 'src');
    fs.mkdirSync(legacySlugDir, { recursive: true });
    const legacyCanary = 'LEGACY_MIGRATION_CANARY_4242';
    fs.writeFileSync(
      path.join(legacySlugDir, 'index.ts'),
      `export const legacy = "${legacyCanary}";\n`,
      'utf8'
    );
    assert.equal(EncryptedArtifactStore.auditNoPlaintextOnDisk(artifactsRoot).clean, false);

    const mig1 = EncryptedArtifactStore.migrateLegacyPlaintextArtifacts(artifactsRoot);
    assert.equal(mig1.migratedSlugs, 1);
    assert.equal(mig1.failedSlugs, 0);
    assert.equal(EncryptedArtifactStore.auditNoPlaintextOnDisk(artifactsRoot).clean, true);

    const recoveredLegacy = EncryptedArtifactStore.readEncryptedBundle(
      path.join(artifactsRoot, 'legacy-plaintext-app')
    );
    assert.ok(recoveredLegacy['src/index.ts']?.includes(legacyCanary));

    // Idempotent second run
    const mig2 = EncryptedArtifactStore.migrateLegacyPlaintextArtifacts(artifactsRoot);
    assert.equal(mig2.migratedSlugs, 0);
    assert.equal(mig2.alreadyEncryptedSlugs, 2);
    assert.equal(mig2.failedSlugs, 0);
  } finally {
    if (prevDataDir === undefined) delete process.env.WINHOOD_DATA_DIR;
    else process.env.WINHOOD_DATA_DIR = prevDataDir;
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
  }
});

test('P0-Server-Canary: POST /api/softwares stores encrypted bundle only and /api/storage/plaintext-audit verifies clean disk', async () => {
  const prevDataDir = process.env.WINHOOD_DATA_DIR;
  const tmpDataDir = createTempDir('wh-p0-srv-canary-');
  process.env.WINHOOD_DATA_DIR = tmpDataDir;

  const { app, dispose } = await createWinHoodApp({ dataDir: tmpDataDir });
  const server = await new Promise<http.Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const canary = `HTTP_UPLOAD_CANARY_${crypto.randomBytes(6).toString('hex')}`;
    const res = await fetch(`${baseUrl}/api/softwares`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Canary Web App',
        vendor: 'WinHood QA',
        version: '1.0.0',
        customFilesMap: {
          'src/main.ts': `export const secret = "${canary}";\n`,
        },
      }),
    });
    assert.equal(res.status, 201);
    const created = (await res.json()) as { software?: { id: string } };
    assert.ok(created.software?.id);

    // Audit endpoint confirms zero plaintext files in isolated_artifacts
    const auditRes = await fetch(`${baseUrl}/api/storage/plaintext-audit`);
    assert.equal(auditRes.status, 200);
    const auditBody = (await auditRes.json()) as {
      clean: boolean;
      plaintextFilePaths: string[];
      encryptedBundleCount: number;
    };
    assert.equal(auditBody.clean, true);
    assert.equal(auditBody.plaintextFilePaths.length, 0);
    assert.ok(auditBody.encryptedBundleCount >= 1);

    // Physical scan of isolated_artifacts confirms canary is nowhere in plaintext
    const artifactsDir = path.join(tmpDataDir, 'isolated_artifacts');
    for (const f of walkAllFiles(artifactsDir)) {
      const content = fs.readFileSync(f, 'utf8');
      assert.ok(!content.includes(canary), `Canary leaked at ${f}`);
    }
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    dispose();
    if (prevDataDir === undefined) delete process.env.WINHOOD_DATA_DIR;
    else process.env.WINHOOD_DATA_DIR = prevDataDir;
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
  }
});

// ============================================================================
// 2. P0 — EphemeralWorkspaceManager Isolation & Cleanup
// ============================================================================
test('P0-EphemeralWorkspace: refuses WINHOOD_DATA_DIR, enforces quotas & path safety, cleans up on success and error', async () => {
  const prevDataDir = process.env.WINHOOD_DATA_DIR;
  const tmpPersistent = createTempDir('wh-p0-persist-');
  const tmpEphemeral = createTempDir('wh-p0-ephem-');
  process.env.WINHOOD_DATA_DIR = tmpPersistent;

  try {
    // Must refuse to place ephemeral workspace inside WINHOOD_DATA_DIR
    assert.throws(
      () => resolveEphemeralWorkspaceRoot(path.join(tmpPersistent, 'sub-ws')),
      /EPHEMERAL_WORKSPACE_POLICY_VIOLATION/i
    );

    // Clean execution cleans up directory
    let createdPath = '';
    const { result, cleanupVerified } = await EphemeralWorkspaceManager.withWorkspace(
      {
        jobId: 'job-ok',
        filesMap: { 'src/index.ts': 'export const ok = 1;\n' },
        baseDir: tmpEphemeral,
      },
      (ws) => {
        createdPath = ws.rootPath;
        assert.ok(fs.existsSync(path.join(ws.rootPath, 'src/index.ts')));
        return ws.filesWritten;
      }
    );
    assert.equal(result, 1);
    assert.equal(cleanupVerified, true);
    assert.equal(fs.existsSync(createdPath), false);

    // Failure path ALSO cleans up directory
    let failedPath = '';
    await assert.rejects(
      () =>
        EphemeralWorkspaceManager.withWorkspace(
          {
            jobId: 'job-fail',
            filesMap: { 'src/fail.ts': 'throw new Error("boom");\n' },
            baseDir: tmpEphemeral,
          },
          (ws) => {
            failedPath = ws.rootPath;
            throw new Error('INTENTIONAL_TEST_FAILURE');
          }
        ),
      /INTENTIONAL_TEST_FAILURE/
    );
    assert.equal(fs.existsSync(failedPath), false);

    // Path traversal & file quota blocked
    assert.throws(
      () =>
        EphemeralWorkspaceManager.createWorkspace({
          jobId: 'job-trav',
          filesMap: { '../escape.js': 'evil' },
          baseDir: tmpEphemeral,
        }),
      /PATH_TRAVERSAL/i
    );
    assert.throws(
      () =>
        EphemeralWorkspaceManager.createWorkspace({
          jobId: 'job-quota',
          filesMap: { 'a.txt': '12345678901' },
          baseDir: tmpEphemeral,
          limits: { maxSingleFileBytes: 5 },
        }),
      /FILE_TOO_LARGE/i
    );
  } finally {
    if (prevDataDir === undefined) delete process.env.WINHOOD_DATA_DIR;
    else process.env.WINHOOD_DATA_DIR = prevDataDir;
    fs.rmSync(tmpPersistent, { recursive: true, force: true });
    fs.rmSync(tmpEphemeral, { recursive: true, force: true });
  }
});

// ============================================================================
// 3. P0 — Multiplatform Graceful Shutdown (IPC + Keep-Alive Draining)
// ============================================================================
test('P0-Shutdown: registerGracefulShutdown closes keep-alive connections cleanly with exitCode 0 and flushes state', async () => {
  const srv = http.createServer((_req, res) => {
    res.writeHead(200, { Connection: 'keep-alive' });
    res.end('ok');
  });
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', () => resolve()));
  const addr = srv.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;

  let flushedBefore = false;
  let cleanedAfter = false;
  const controller = registerGracefulShutdown({
    server: srv,
    signals: [],
    exitProcess: false,
    enableIpcShutdown: true,
    onBeforeClose: () => {
      flushedBefore = true;
    },
    onAfterClose: () => {
      cleanedAfter = true;
    },
  });

  try {
    const resp = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(resp.status, 200);
    await resp.text();

    const outcome = await controller.shutdown(WINHOOD_IPC_SHUTDOWN_MESSAGE, null);
    assert.equal(outcome.closed, true);
    assert.equal(outcome.timedOut, false);
    assert.equal(outcome.exitCode, 0);
    assert.equal(outcome.flushed, true);
    assert.equal(flushedBefore, true);
    assert.equal(cleanedAfter, true);
  } finally {
    controller.unregister();
  }
});

// ============================================================================
// 4. P0 — Dedicated Scanner Worker + Job Orchestrator E2E
// ============================================================================
test('P0-ScannerWorker: authenticates via constant-time Bearer token, fails closed when unconfigured, handles async job queue/cancel/recovery', async () => {
  const tmpData = createTempDir('wh-p0-orch-');
  const tmpWs = createTempDir('wh-p0-worker-ws-');
  const workerToken = crypto.randomBytes(24).toString('hex');

  const worker = await startScannerWorkerServer({
    host: '127.0.0.1',
    port: 0,
    workerToken,
    baseWorkspaceDir: tmpWs,
  });

  try {
    // 1. Health endpoint works without exposing secret
    const healthRes = await fetch(`${worker.url}/worker/health`);
    assert.equal(healthRes.status, 200);
    const healthBody = (await healthRes.json()) as { status: string; service: string };
    assert.equal(healthBody.status, 'ONLINE');
    assert.equal(healthBody.service, 'winhood-scanner-worker');

    // 2. Unauthorized request without Bearer token MUST be rejected with 401
    const unauthRes = await fetch(`${worker.url}/worker/capabilities`);
    assert.equal(unauthRes.status, 401);
    const wrongTokRes = await fetch(`${worker.url}/worker/capabilities`, {
      headers: { Authorization: 'Bearer wrong-token-value' },
    });
    assert.equal(wrongTokRes.status, 401);

    // 3. Authorized capability probe NEVER claims OPERATIONAL for unexecuted/unisolated binaries
    const capRes = await fetch(`${worker.url}/worker/capabilities`, {
      headers: { Authorization: `Bearer ${workerToken}` },
    });
    assert.equal(capRes.status, 200);
    const capBody = (await capRes.json()) as {
      capabilities: Array<{ toolId: string; executionPerformed: boolean; finalState: string }>;
    };
    assert.ok(capBody.capabilities.length >= 10);
    for (const c of capBody.capabilities) {
      if (!c.executionPerformed) {
        assert.notEqual(
          c.finalState,
          'OPERATIONAL',
          `Tool ${c.toolId} marked OPERATIONAL without execution`
        );
      }
    }

    // 4. Fail-closed BLOCKED when worker URL is NOT configured (no insecure host fallback)
    const blockedOrch = new ScannerJobOrchestrator({
      dataDir: tmpData,
      workerUrl: '',
    });
    const blockedJob = blockedOrch.enqueueJob({
      toolIds: ['semgrep'],
      filesMap: { 'index.ts': 'export const a = 1;\n' },
    });
    const finalBlocked = await blockedOrch.waitForJob(blockedJob.jobId, 5_000);
    assert.equal(finalBlocked?.state, 'BLOCKED');
    assert.equal(finalBlocked?.executionBackend, 'BLOCKED_NO_ISOLATION');
    assert.ok(finalBlocked?.inputSha256 && finalBlocked.inputSha256.length === 64);

    // 5. Connected orchestrator dispatches over real HTTP to worker & records SHA-256 digests
    const liveOrch = new ScannerJobOrchestrator({
      dataDir: tmpData,
      workerUrl: worker.url,
      workerToken,
      maxConcurrency: 2,
    });
    const capsFromOrch = await liveOrch.getCapabilities();
    assert.equal(capsFromOrch.workerConfigured, true);
    assert.equal(capsFromOrch.workerReachable, true);

    const job = liveOrch.enqueueJob({
      projectId: 'proj-1',
      softwareId: 'sw-1',
      toolIds: ['semgrep', 'gitleaks'],
      filesMap: { 'src/app.ts': 'export const x = 42;\n' },
      timeoutMs: 10_000,
    });
    const completed = await liveOrch.waitForJob(job.jobId, 15_000);
    assert.ok(completed);
    assert.equal(completed.state, 'COMPLETED');
    assert.equal(completed.results.length, 2);
    assert.ok(completed.outputSha256 && completed.outputSha256.length === 64);
    assert.equal(EphemeralWorkspaceManager.getActiveWorkspaceCount(), 0);

    // 6. Restart recovery: simulated RUNNING job persisted on disk is recovered cleanly as FAILED
    const jobsFile = path.join(tmpData, 'database', 'scanner_jobs.json');
    const persisted = JSON.parse(fs.readFileSync(jobsFile, 'utf8')) as {
      jobs: Array<Record<string, unknown>>;
    };
    persisted.jobs.push({
      jobId: 'wh-scan-interrupted-test',
      projectId: null,
      softwareId: null,
      toolIds: ['semgrep'],
      state: 'RUNNING',
      executionBackend: 'DOCKER_SCANNER_WORKER',
      inputSha256: '0'.repeat(64),
      outputSha256: null,
      fileCount: 1,
      attemptCount: 1,
      maxRetries: 1,
      timeoutMs: 10000,
      createdAt: new Date().toISOString(),
      startedAt: new Date().toISOString(),
      completedAt: null,
      durationMs: null,
      cancelRequested: false,
      recoveredFromInterruption: false,
      results: [],
      errorMessage: null,
    });
    fs.writeFileSync(jobsFile, JSON.stringify(persisted, null, 2), 'utf8');

    const recoveredOrch = new ScannerJobOrchestrator({ dataDir: tmpData });
    const recoveredJob = recoveredOrch.getJob('wh-scan-interrupted-test');
    assert.equal(recoveredJob?.state, 'FAILED');
    assert.equal(recoveredJob?.recoveredFromInterruption, true);
    assert.match(recoveredJob?.errorMessage || '', /JOB_INTERRUPTED_ON_RESTART/);
  } finally {
    await worker.close();
    fs.rmSync(tmpData, { recursive: true, force: true });
    fs.rmSync(tmpWs, { recursive: true, force: true });
  }
});

// ============================================================================
// 5. P1 — NPM Audit Governance Strict Negative Tests
// ============================================================================
test('P1-NpmAuditGovernance: rejects mismatched advisory, severity escalation, version drift, expired & duplicate exceptions; never claims ZERO_VULNERABILITIES when exception is active', () => {
  const now = new Date('2026-11-26T12:00:00Z');
  const validException = {
    package: 'pkg-demo',
    advisoryId: 'GHSA-1111-2222-3333',
    severity: 'high',
    version: '1.2.3',
    affectedRange: '<1.3.0',
    dependencyPath: 'dev-tool>pkg-demo',
    fixAvailable: false,
    winhoodImpact: 'BUILD_TIME_ONLY_NO_RUNTIME_EXPOSURE',
    owner: 'AppSec-Lead',
    approvedAt: '2026-11-01T00:00:00Z',
    expiresAt: '2027-01-01T00:00:00Z',
    justification: 'Build-time only transitive tool',
    compensatingControl: 'Never bundled in runtime dist or Docker runtime image',
    removalCondition: 'Upgrade upstream dev-tool once patched release ships',
  };

  const makeAudit = (
    overrides: Partial<{
      advisoryUrl: string;
      severity: string;
      version: string;
      range: string;
      nodes: string[];
    }> = {}
  ) => ({
    vulnerabilities: {
      'pkg-demo': {
        name: 'pkg-demo',
        severity: overrides.severity ?? 'high',
        version: overrides.version ?? '1.2.3',
        range: overrides.range ?? '<1.3.0',
        nodes: overrides.nodes ?? ['node_modules/dev-tool/node_modules/pkg-demo'],
        via: [
          {
            source: 999,
            name: 'pkg-demo',
            severity: overrides.severity ?? 'high',
            range: overrides.range ?? '<1.3.0',
            url: overrides.advisoryUrl ?? 'https://github.com/advisories/GHSA-1111-2222-3333',
          },
        ],
      },
    },
  });

  // (a) Valid exact-match exception passes but NEVER reports ZERO_VULNERABILITIES
  const okRes = evaluateAuditReport(makeAudit(), { exceptions: [validException] }, now);
  assert.equal(okRes.passed, true);
  assert.equal(okRes.honestStatus, 'GOVERNED_BUILD_TIME_EXCEPTIONS_ACTIVE');
  assert.notEqual(okRes.honestStatus, 'ZERO_VULNERABILITIES');

  // (b) Different advisory on SAME package MUST fail
  const wrongAdv = evaluateAuditReport(
    makeAudit({ advisoryUrl: 'https://github.com/advisories/GHSA-9999-8888-7777' }),
    { exceptions: [validException] },
    now
  );
  assert.equal(wrongAdv.passed, false);
  assert.equal(wrongAdv.unapprovedVulnerabilities.length, 1);

  // (c) Severity escalation (high -> critical) MUST fail
  const sevEscalation = evaluateAuditReport(
    makeAudit({ severity: 'critical' }),
    { exceptions: [validException] },
    now
  );
  assert.equal(sevEscalation.passed, false);

  // (d) Version drift MUST fail
  const verDrift = evaluateAuditReport(
    makeAudit({ version: '1.2.4' }),
    { exceptions: [validException] },
    now
  );
  assert.equal(verDrift.passed, false);

  // (e) Expired exception MUST fail
  const expiredRes = evaluateAuditReport(
    makeAudit(),
    { exceptions: [{ ...validException, expiresAt: '2026-11-20T00:00:00Z' }] },
    now
  );
  assert.equal(expiredRes.passed, false);
  assert.ok(expiredRes.expiredOrInvalidExceptions.length >= 1);

  // (f) Duplicate exception MUST fail
  const dupRes = evaluateAuditReport(
    makeAudit(),
    { exceptions: [validException, { ...validException }] },
    now
  );
  assert.equal(dupRes.passed, false);
  assert.ok(dupRes.duplicateOrAmbiguousExceptions.length >= 1);
});

// ============================================================================
// 6. P1 — Deep Multi-Hop Call-Graph Taint Analysis, ParserRegistry & RuleRegistry
// ============================================================================
test('P1-TaintEngine: detects 5-hop cross-file taint flow, respects context sanitizers, flags incomplete sanitizers, detects cycles & dynamic dispatch', () => {
  // 5-hop cross-file SQLi chain (> old 2-hop limit!)
  const files5Hop: Record<string, string> = {
    'src/controller.ts': `import { step2 } from './step2';\nexport function handleRequest(userId: string) {\n  return step2(userId);\n}\n`,
    'src/step2.ts': `import { step3 } from './step3';\nexport function step2(rawId: string) {\n  return step3(rawId);\n}\n`,
    'src/step3.ts': `import { step4 } from './step4';\nexport function step3(val: string) {\n  return step4(val);\n}\n`,
    'src/step4.ts': `import { runQuery } from './repo';\nexport function step4(arg: string) {\n  return runQuery(arg);\n}\n`,
    'src/repo.ts': `export function runQuery(id: string) {\n  const sql = "SELECT * FROM accounts WHERE id = " + id;\n  return db.query(sql);\n}\n`,
  };

  const parsed5Hop = Object.entries(files5Hop).map(([fp, content]) =>
    ParserRegistry.parseFile(fp, content)
  );
  const diag5Hop = TaintAnalyzer.analyzeFlowsWithDiagnostics(parsed5Hop, files5Hop, {
    maxCallDepth: 6,
  });
  const sqliIssues = diag5Hop.issues.filter((i) => i.cwe === 'CWE-89');
  assert.ok(sqliIssues.length >= 1, 'Expected 5-hop cross-file SQLi to be detected');
  assert.ok(
    diag5Hop.stats.maxDepthObserved >= 4,
    `Expected call depth >= 4, got ${diag5Hop.stats.maxDepthObserved}`
  );
  assert.ok(
    sqliIssues.some((i) => (i.executionFlows?.length ?? 0) >= 4),
    'Expected multi-step interprocedural executionFlows'
  );

  // Depth truncation honestly recorded when maxCallDepth is small
  const truncatedDiag = TaintAnalyzer.analyzeFlowsWithDiagnostics(parsed5Hop, files5Hop, {
    maxCallDepth: 2,
  });
  assert.ok(
    truncatedDiag.incompletePaths.some((p) => p.reason === 'MAX_DEPTH_REACHED'),
    'Expected MAX_DEPTH_REACHED incomplete path when depth budget is exceeded'
  );

  // Valid contextual sanitizer suppresses XSS, while wrong sanitizer (encodeURIComponent for SQLi) still flags
  const sanitizerFiles: Record<string, string> = {
    'src/safe_xss.ts': `export function safeRender(res: any, userTitle: string) {\n  const clean = escapeHtml(userTitle);\n  res.sendHtml("<div>" + clean + "</div>");\n}\n`,
    'src/bad_san_sqli.ts': `export function badSql(db: any, userQuery: string) {\n  const encoded = encodeURIComponent(userQuery);\n  return db.query("SELECT * FROM items WHERE name = " + encoded);\n}\n`,
  };
  const parsedSan = Object.entries(sanitizerFiles).map(([fp, content]) =>
    ParserRegistry.parseFile(fp, content)
  );
  const sanDiag = TaintAnalyzer.analyzeFlowsWithDiagnostics(parsedSan, sanitizerFiles);
  assert.equal(
    sanDiag.issues.filter((i) => i.filePath === 'src/safe_xss.ts' && i.cwe === 'CWE-79').length,
    0,
    'Proper escapeHtml sanitizer should suppress XSS'
  );
  assert.ok(
    sanDiag.issues.filter((i) => i.filePath === 'src/bad_san_sqli.ts' && i.cwe === 'CWE-89').length >=
      1,
    'Incompatible sanitizer (encodeURIComponent) must NOT suppress SQLi'
  );

  // Cycle / recursion termination + Dynamic dispatch incomplete path tracking
  const cycleAndDynamic: Record<string, string> = {
    'src/cycle.ts': `export function ping(input: string) {\n  return pong(input);\n}\nexport function pong(val: string) {\n  return ping(val);\n}\n`,
    'src/dynamic.ts': `export function dispatch(handlers: any, action: string, userInput: string) {\n  return handlers[action](userInput);\n}\n`,
  };
  const parsedCD = Object.entries(cycleAndDynamic).map(([fp, content]) =>
    ParserRegistry.parseFile(fp, content)
  );
  const cdDiag = TaintAnalyzer.analyzeFlowsWithDiagnostics(parsedCD, cycleAndDynamic);
  assert.ok(cdDiag.stats.cyclesDetected >= 1, 'Expected recursion cycle to be detected safely');
  assert.ok(
    cdDiag.incompletePaths.some((p) => p.reason === 'DYNAMIC_CALL_DISPATCH'),
    'Expected dynamic call dispatch to be tracked as incomplete path'
  );

  // ParserRegistry & RuleRegistry honest capability & version governance checks
  const langCaps = ParserRegistry.getLanguageAnalyticalCapabilities();
  const tsCap = langCaps.find((c) => c.language === 'TypeScript');
  const pyCap = langCaps.find((c) => c.language === 'Python');
  assert.equal(tsCap?.analyticalDepth, 'FULL_AST');
  assert.ok(Array.isArray(pyCap?.limitations) && pyCap.limitations.length > 0);

  const catalog = RuleRegistry.getCatalogSnapshot();
  assert.equal(catalog.catalogVersion, RULE_CATALOG_VERSION);
  const firstRule = catalog.rules[0]!;
  const gov = RuleRegistry.getRuleGovernanceMetadata(firstRule.ruleId);
  assert.ok(gov);
  assert.equal(gov.catalogVersion, RULE_CATALOG_VERSION);
  assert.ok(gov.defaultConfidence);
});

// ============================================================================
// 7. P1 — Ecosystem Version Comparators, SCA Freshness & Multi-Lockfile SBOM
// ============================================================================
test('P1-SCA-SBOM: ecosystem-aware comparators (SemVer, PEP 440, Maven, NuGet), honest offline freshness, and Gradle/NuGet/Poetry/Pipfile/go.sum lockfiles', () => {
  // SemVer 2.0.0
  assert.equal(compareSemver('1.0.0-alpha.1', '1.0.0'), -1);
  assert.equal(compareSemver('1.0.0-alpha.2', '1.0.0-alpha.10'), -1);
  assert.equal(compareSemver('1.0.0+build.1', '1.0.0+build.99'), 0);

  // PEP 440
  assert.equal(comparePep440('1.0.0a1', '1.0.0rc1'), -1);
  assert.equal(comparePep440('1.0.0rc1', '1.0.0'), -1);
  assert.equal(comparePep440('1.0.0', '1.0.0.post1'), -1);

  // Maven
  assert.equal(compareMavenVersion('2.0-beta9', '2.17.1-SNAPSHOT'), -1);
  assert.equal(compareMavenVersion('2.17.1-SNAPSHOT', '2.17.1'), -1);

  // NuGet 4-part
  assert.equal(compareNugetVersion('1.2.3.4', '1.2.3.5'), -1);
  assert.equal(compareNugetVersion('1.2.3-beta.1', '1.2.3'), -1);

  assert.equal(satisfiesVersionRange('pypi', '2.0.0rc1', '<2.0.0'), true);
  assert.equal(satisfiesVersionRange('npm', '4.17.20', '<4.17.21'), true);
  assert.equal(satisfiesVersionRange('npm', '4.17.21', '<4.17.21'), false);

  // Multi-lockfile SBOM extraction (Gradle, NuGet, Poetry, Pipfile, go.sum)
  const multiLockFiles: Record<string, string> = {
    'build.gradle': `dependencies {\n  implementation 'org.apache.logging.log4j:log4j-core:2.14.1'\n}\n`,
    'gradle.lockfile': `org.springframework:spring-core:5.3.20=compileClasspath\nempty=\n`,
    'packages.lock.json': JSON.stringify({
      version: 1,
      dependencies: {
        net8: {
          'Newtonsoft.Json': { type: 'Direct', resolved: '13.0.1' },
          'System.Text.Encodings.Web': { type: 'Transitive', resolved: '4.5.0' },
        },
      },
    }),
    'poetry.lock': `[[package]]\nname = "django"\nversion = "3.2.10"\n`,
    'Pipfile.lock': JSON.stringify({
      default: { requests: { version: '==2.28.1' } },
    }),
    'go.sum': `golang.org/x/net v0.17.0 h1:abc=\ngolang.org/x/net v0.17.0/go.mod h1:def=\n`,
  };

  const mockSw = {
    id: 'sw-multi-lock',
    projectId: 'proj-multi-lock',
    name: 'Polyglot Monorepo',
    vendor: 'WinHood Test',
    version: '1.0.0',
    category: 'Backend',
    description: 'Multi-lockfile SCA/SBOM fixture',
    architecture: 'Monorepo',
    languages: ['TypeScript', 'Java', 'Python', 'C#', 'Go'],
    sourceType: 'LOCAL_UPLOAD',
    dataOrigin: 'USER_SOURCE',
    sourceFilesContent: multiLockFiles,
    createdAt: '2026-11-26T00:00:00Z',
  } as unknown as Software;

  const sbom = SbomGenerator.generateFromSoftware(mockSw);
  const pkgNames = sbom.components.map((c) => c.name);
  assert.ok(pkgNames.includes('org.apache.logging.log4j:log4j-core'));
  assert.ok(pkgNames.includes('org.springframework:spring-core'));
  assert.ok(pkgNames.includes('Newtonsoft.Json'));
  assert.ok(pkgNames.includes('django'));
  assert.ok(pkgNames.includes('requests'));
  assert.ok(pkgNames.includes('golang.org/x/net'));
  assert.ok(
    sbom.components.every((c) => typeof c.dependencyPath === 'string' && c.dependencyPath.length > 0)
  );
  assert.equal(typeof sbom.unresolvedDependenciesCount, 'number');
  assert.equal(typeof sbom.unknownLicenseCount, 'number');
  assert.equal(sbom.cyclonedx17Json?.bomFormat, 'CycloneDX');
  assert.equal(sbom.spdx23Json?.spdxVersion, 'SPDX-2.3');
  assert.equal(sbom.structuralValidation?.cyclonedx17Valid, true);
  assert.equal(sbom.structuralValidation?.spdx30Valid, true);

  // Offline SCA honesty: freshnessStatus = OFFLINE_LIMITED_BASELINE & isComprehensiveDatabase = false
  const sca = ScaCorrelator.correlateSbom({
    software: mockSw,
    sbom,
    deterministicTimestamp: '2026-11-26T00:00:00Z',
  });
  assert.equal(sca.advisoryFeedMetadata.freshnessStatus, 'OFFLINE_LIMITED_BASELINE');
  assert.equal(sca.advisoryFeedMetadata.isComprehensiveDatabase, false);
  assert.ok(sca.advisoryFeedMetadata.snapshotSha256.length === 64);
  assert.ok(sca.advisoryFeedMetadata.limitations.length > 0);
  assert.ok(
    sca.correlations.some((v) => v.cveId === 'CVE-2021-44228'),
    'Expected Log4Shell to be correlated from Gradle build file'
  );
});

// ============================================================================
// 8. P1 — Signed Evidence Provenance, QualityGate, CrossToolBenchmarkHarness & Vite allowedHosts
// ============================================================================
test('P1-Governance: signed provenanceMetadata tamper detection, strict QualityGate decisions, CrossToolBenchmarkHarness & Vite allowedHosts hardening', () => {
  const prevDataDir = process.env.WINHOOD_DATA_DIR;
  const tmpData = createTempDir('wh-p1-gov-');
  process.env.WINHOOD_DATA_DIR = tmpData;

  try {
    // 1. Evidence Provenance Signing & Tamper Detection
    const sw = {
      id: 'sw-prov',
      projectId: 'proj-prov',
      name: 'Provenance App',
      vendor: 'WinHood Test',
      version: '2.0.0',
      category: 'API',
      description: 'Provenance test fixture',
      architecture: 'Service',
      languages: ['TypeScript'],
      sourceType: 'LOCAL_UPLOAD',
      dataOrigin: 'USER_SOURCE',
      packageSha256: 'a'.repeat(64),
      createdAt: '2026-11-26T00:00:00Z',
    } as unknown as Software;
    const vr: VeracityCheckResult = {
      runId: 'run-prov-1',
      softwareId: sw.id,
      softwareName: sw.name,
      auditedAt: '2026-11-26T00:00:00Z',
      overallClassification: 'SUCCESS_VALIDATED',
      overallCoveragePercent: 100,
      warnings: [],
      blockingReasons: [],
      checks: {
        sourceReceived: true,
        integrityVerified: true,
        commitIdentified: true,
        toolExists: true,
        versionIdentified: true,
        configValidated: true,
        toolStarted: true,
        executionCompleted: true,
        exitCodeRecorded: true,
        outputReceived: true,
        outputParsed: true,
        formatValidated: true,
        coverageCalculated: true,
        failuresRecorded: true,
        evidencePersisted: true,
        evidenceHashVerified: true,
        matchesSoftware: true,
        matchesCommit: true,
        eligibleForScoring: true,
      },
    };
    const chain = buildVerifiableEvidenceChain({
      runId: 'run-prov-1',
      softwares: [sw],
      findings: [],
      toolExecutions: [],
      veracityResults: [vr],
      deterministicTimestamp: '2026-11-26T00:00:00Z',
    });

    const manifest = signEvidenceManifestHmacSha256({
      runId: 'run-prov-1',
      algorithmVersion: '4.4.0',
      evidenceChain: chain,
      generatedAt: '2026-11-26T00:00:00Z',
      provenanceMetadata: {
        winhoodVersion: '4.4.0',
        inputProjectSha256: 'b'.repeat(64),
        analyzedFileHashesCount: 2,
        externalAnalyzers: [{ toolId: 'winhood_native', version: '4.4.0', status: 'MEASURED' }],
        executionStatus: 'LOCAL_NATIVE_AST',
        limitations: ['No external worker executed in unit test'],
      },
    });

    assert.equal(
      manifest.provenanceMetadata?.cryptographicScopeDisclaimer,
      DEFAULT_CRYPTOGRAPHIC_SCOPE_DISCLAIMER
    );

    const verified = verifyEvidenceChainAndManifest(chain, manifest);
    assert.equal(verified.valid, true);
    assert.equal(verified.verificationState, 'VERIFIED');

    // Tampering with provenanceMetadata MUST break signature verification
    const tamperedManifest = {
      ...manifest,
      provenanceMetadata: {
        ...manifest.provenanceMetadata!,
        executionStatus: 'FORGED_CLOUD_RUNNER',
      },
    };
    const tamperedRes = verifyEvidenceChainAndManifest(chain, tamperedManifest);
    assert.equal(tamperedRes.valid, false);
    assert.equal(tamperedRes.verificationState, 'TAMPERED');

    // 2. Quality Gate strict distinction (INCONCLUSIVE when mandatory metric is NOT_MEASURED)
    const standardGate = BUILTIN_QUALITY_GATES[0]!;
    const inconclusiveGate = QualityGateEngine.evaluate({
      gate: standardGate,
      findings: [],
      evidenceVerified: true,
      scopeCoveragePercent: null, // NOT_MEASURED
      evidenceConfidence: 'HIGH',
    });
    assert.equal(inconclusiveGate.decision, 'INCONCLUSIVE');
    assert.equal(inconclusiveGate.cliExitCode, 2);

    const approvedGate = QualityGateEngine.evaluate({
      gate: standardGate,
      findings: [],
      evidenceVerified: true,
      scopeCoveragePercent: 95,
      evidenceConfidence: 'HIGH',
    });
    assert.equal(approvedGate.decision, 'APPROVED');
    assert.equal(approvedGate.cliExitCode, 0);

    // 3. CrossToolBenchmarkHarness on controlled 10-class / 20-case corpus + SARIF ingestion
    const benchmarkReport = CrossToolBenchmarkHarness.runComparison({
      corpus: CONTROLLED_11_CLASS_VALIDATION_CORPUS,
      deterministicTimestamp: '2026-11-26T00:00:00Z',
      externalToolRuns: [
        {
          toolName: 'Semgrep',
          toolVersion: '1.109.0-sample',
          executionState: 'EXECUTED',
          analyticalDepthDeclared: 'AST pattern matching',
          runtimeMs: 420,
          sarif210: {
            version: '2.1.0',
            runs: [
              {
                results: [
                  {
                    ruleId: 'javascript.lang.security.audit.sqli',
                    level: 'error',
                    properties: { cwe: 'CWE-89' },
                    locations: [
                      {
                        physicalLocation: {
                          artifactLocation: { uri: 'corpus/sqli_tp.ts' },
                          region: { startLine: 2 },
                        },
                      },
                    ],
                  },
                ],
              },
            ],
          },
          limitations: ['Sample SARIF fixture for harness verification'],
        },
        {
          toolName: 'SonarQube Cloud',
          toolVersion: 'unexecuted',
          executionState: 'NOT_EXECUTED',
          analyticalDepthDeclared: 'Remote SaaS',
          runtimeMs: null,
          limitations: ['SONAR_TOKEN not executed in local unit test'],
        },
      ],
    });

    assert.equal(benchmarkReport.totalCases, 20);
    assert.equal(benchmarkReport.positiveCases, 10);
    assert.equal(benchmarkReport.negativeCases, 10);
    assert.equal(benchmarkReport.winhoodEvaluation.executionState, 'EXECUTED');
    assert.ok(benchmarkReport.winhoodEvaluation.counts.tp >= 6);
    assert.equal(benchmarkReport.externalEvaluations[0]?.counts.tp, 1);
    assert.equal(benchmarkReport.externalEvaluations[1]?.executionState, 'NOT_EXECUTED');
    assert.equal(benchmarkReport.externalEvaluations[1]?.counts.totalEvaluated, 0);

    // 4. Vite allowedHosts hardening: rejects .run.app / * wildcards, preserves explicit hostnames
    const allowed = resolveViteAllowedHosts({
      NG_ALLOWED_HOSTS: '.run.app, *, app.winhood.internal, https://audit.company.local:8443/path',
      APP_URL: 'https://preview-123.example.org',
    });
    assert.ok(allowed.includes('localhost'));
    assert.ok(allowed.includes('127.0.0.1'));
    assert.ok(allowed.includes('app.winhood.internal'));
    assert.ok(allowed.includes('audit.company.local'));
    assert.ok(allowed.includes('preview-123.example.org'));
    assert.ok(!allowed.includes('.run.app'));
    assert.ok(!allowed.includes('*'));
  } finally {
    if (prevDataDir === undefined) delete process.env.WINHOOD_DATA_DIR;
    else process.env.WINHOOD_DATA_DIR = prevDataDir;
    fs.rmSync(tmpData, { recursive: true, force: true });
  }
});

// ============================================================================
// 9. P0 — Probe Verified Worker Capabilities Direct Unit Verification
// ============================================================================
test('P0-WorkerCapabilities: probeVerifiedWorkerCapabilities never fabricates OPERATIONAL state outside container isolation', async () => {
  const prevContainer = process.env.WINHOOD_SCANNER_WORKER_CONTAINER;
  const prevAllowHost = process.env.WINHOOD_ALLOW_WORKER_SELFTEST_HOST;
  delete process.env.WINHOOD_SCANNER_WORKER_CONTAINER;
  delete process.env.WINHOOD_ALLOW_WORKER_SELFTEST_HOST;

  try {
    const caps = await probeVerifiedWorkerCapabilities();
    assert.ok(caps.length >= 10);
    for (const cap of caps) {
      if (!fs.existsSync('/.dockerenv')) {
        assert.notEqual(
          cap.finalState,
          'OPERATIONAL',
          `Tool ${cap.toolId} must not be marked OPERATIONAL without container isolation`
        );
      }
    }
  } finally {
    if (prevContainer !== undefined) process.env.WINHOOD_SCANNER_WORKER_CONTAINER = prevContainer;
    if (prevAllowHost !== undefined) process.env.WINHOOD_ALLOW_WORKER_SELFTEST_HOST = prevAllowHost;
  }
});

// ============================================================================
// 10. Docker-First Hardening — Worker PATH, Env Alignment & Offline Prerequisites
// ============================================================================
test('DockerFirst-WorkerPrereqs: includes /opt/winhood-pytools/bin, aligns env vars, and returns DATABASE_UNAVAILABLE / RULES_UNAVAILABLE honestly', () => {
  if (process.platform !== 'win32') {
    const dirs = getAllowedBinarySearchDirs();
    assert.ok(
      dirs.includes('/opt/winhood-pytools/bin'),
      'Worker binary search path MUST include /opt/winhood-pytools/bin for ruff/bandit/semgrep'
    );
  }

  const prevHost = process.env.WINHOOD_SCANNER_WORKER_HOST;
  const prevPort = process.env.WINHOOD_SCANNER_WORKER_PORT;
  const prevGrype = process.env.GRYPE_DB_CACHE_DIR;
  const prevOsv = process.env.WINHOOD_OSV_DB_DIR;
  const prevSemgrep = process.env.WINHOOD_SEMGREP_RULES_DIR;
  const emptyDir = createTempDir('wh-empty-prereq-');
  const populatedDir = createTempDir('wh-pop-prereq-');

  try {
    process.env.WINHOOD_SCANNER_WORKER_HOST = '0.0.0.0';
    process.env.WINHOOD_SCANNER_WORKER_PORT = '4199';
    assert.equal(resolveWorkerBindHost(), '0.0.0.0');
    assert.equal(resolveWorkerPort(), 4199);

    // Missing Grype / OSV DB -> DATABASE_UNAVAILABLE (NEVER ready / 0 vulnerabilities)
    process.env.GRYPE_DB_CACHE_DIR = emptyDir;
    process.env.WINHOOD_OSV_DB_DIR = emptyDir;
    assert.equal(checkToolOfflinePrerequisites('grype').ready, false);
    assert.equal(checkToolOfflinePrerequisites('grype').state, 'DATABASE_UNAVAILABLE');
    assert.equal(checkToolOfflinePrerequisites('osv-scanner').ready, false);
    assert.equal(checkToolOfflinePrerequisites('osv-scanner').state, 'DATABASE_UNAVAILABLE');

    // Missing Semgrep rules -> RULES_UNAVAILABLE
    const prevCwd = process.cwd();
    process.env.WINHOOD_SEMGREP_RULES_DIR = emptyDir;
    // Note: bundled fallback under repo security/semgrep-offline-rules exists; verify bundled rules pass
    const bundledSemgrep = checkToolOfflinePrerequisites('semgrep');
    assert.equal(bundledSemgrep.ready, true, 'Bundled offline Semgrep rules must be detected');
    assert.ok(bundledSemgrep.resolvedPath?.includes('semgrep-offline-rules'));

    // Populated Grype & OSV DB caches -> ready: true
    fs.writeFileSync(
      path.join(populatedDir, 'vulnerability.db'),
      'SQLite format 3 synthetic test cache content over 32 bytes!',
      'utf8'
    );
    fs.writeFileSync(
      path.join(populatedDir, 'osv-cache.json'),
      JSON.stringify({ schema_version: '1.6.0', vulns: [] }),
      'utf8'
    );
    process.env.GRYPE_DB_CACHE_DIR = populatedDir;
    process.env.WINHOOD_OSV_DB_DIR = populatedDir;
    assert.equal(checkToolOfflinePrerequisites('grype').ready, true);
    assert.equal(checkToolOfflinePrerequisites('osv-scanner').ready, true);
    assert.equal(prevCwd, process.cwd());
  } finally {
    if (prevHost === undefined) delete process.env.WINHOOD_SCANNER_WORKER_HOST;
    else process.env.WINHOOD_SCANNER_WORKER_HOST = prevHost;
    if (prevPort === undefined) delete process.env.WINHOOD_SCANNER_WORKER_PORT;
    else process.env.WINHOOD_SCANNER_WORKER_PORT = prevPort;
    if (prevGrype === undefined) delete process.env.GRYPE_DB_CACHE_DIR;
    else process.env.GRYPE_DB_CACHE_DIR = prevGrype;
    if (prevOsv === undefined) delete process.env.WINHOOD_OSV_DB_DIR;
    else process.env.WINHOOD_OSV_DB_DIR = prevOsv;
    if (prevSemgrep === undefined) delete process.env.WINHOOD_SEMGREP_RULES_DIR;
    else process.env.WINHOOD_SEMGREP_RULES_DIR = prevSemgrep;
    fs.rmSync(emptyDir, { recursive: true, force: true });
    fs.rmSync(populatedDir, { recursive: true, force: true });
  }
});

// ============================================================================
// 11. Docker-First Hardening — scanner_jobs.json Confidentiality & Full Volume Audit
// ============================================================================
test('DockerFirst-JobConfidentiality: strips normalizedPayload from scanner_jobs.json, encrypts payloads at rest, and detects leaks via auditPersistentDataDir', async () => {
  const prevDataDir = process.env.WINHOOD_DATA_DIR;
  const tmpData = createTempDir('wh-job-confid-');
  process.env.WINHOOD_DATA_DIR = tmpData;

  try {
    const secretCanary = `CANARY_RAW_SNIPPET_${crypto.randomBytes(6).toString('hex')}`;
    const syntheticBearer = `Bearer tok_${crypto.randomBytes(12).toString('hex')}`;

    const orch = new ScannerJobOrchestrator({
      dataDir: tmpData,
      remoteExecutor: {
        fetchCapabilities: async () => [],
        executeJob: async () => [
          {
            toolId: 'gitleaks',
            state: 'COMPLETED',
            version: '8.24.0',
            exitCode: 0,
            durationMs: 12,
            outputFormat: 'JSON',
            outputValidated: true,
            findingsCount: 1,
            rawOutputSha256: 'a'.repeat(64),
            normalizedPayload: [{ secret: secretCanary, file: 'src/config.ts', line: 3 }],
            limitations: [`Header leak test ${syntheticBearer}`],
          },
        ],
      },
    });

    const job = orch.enqueueJob({
      toolIds: ['gitleaks'],
      filesMap: { 'src/config.ts': `export const k = "${secretCanary}";\n` },
    });
    const done = await orch.waitForJob(job.jobId, 5_000);
    assert.equal(done?.state, 'COMPLETED');
    assert.equal(done?.analysisVerdict, 'VERIFIED');
    assert.equal(done?.encryptedPayloadRef, 'scanner_jobs_payloads.whenc');

    // 1. Plaintext scanner_jobs.json MUST NOT contain normalizedPayload, canary snippet, or Bearer token
    const jobsJsonPath = path.join(tmpData, 'database', 'scanner_jobs.json');
    const rawJobsJson = fs.readFileSync(jobsJsonPath, 'utf8');
    assert.equal(rawJobsJson.includes('normalizedPayload'), false, 'scanner_jobs.json must NEVER store normalizedPayload');
    assert.equal(rawJobsJson.includes(secretCanary), false, 'Canary snippet must NEVER appear in scanner_jobs.json');
    assert.equal(rawJobsJson.includes(syntheticBearer), false, 'Bearer token must be redacted from scanner_jobs.json');

    // 2. Encrypted payload vault exists, does NOT contain plaintext canary, and decrypts cleanly
    const encPayloadsPath = path.join(tmpData, 'database', 'scanner_jobs_payloads.whenc');
    assert.ok(fs.existsSync(encPayloadsPath), 'scanner_jobs_payloads.whenc must exist');
    const rawEnc = fs.readFileSync(encPayloadsPath, 'utf8');
    assert.equal(rawEnc.includes(secretCanary), false, 'Encrypted payload file must not contain plaintext canary');

    const freshOrch = new ScannerJobOrchestrator({ dataDir: tmpData });
    const decrypted = freshOrch.getDecryptedJobPayloads(job.jobId);
    assert.ok(decrypted);
    assert.ok(JSON.stringify(decrypted['gitleaks']).includes(secretCanary));

    // 3. Full persistent volume audit reports clean=true
    const cleanAudit = EncryptedArtifactStore.auditPersistentDataDir(tmpData);
    assert.equal(cleanAudit.clean, true, `Expected clean volume audit, got: ${JSON.stringify(cleanAudit.findings)}`);

    // 4. Injecting a rogue plaintext secret into logs/ is caught immediately
    const logsDir = path.join(tmpData, 'logs');
    fs.mkdirSync(logsDir, { recursive: true });
    fs.writeFileSync(path.join(logsDir, 'leak.log'), 'aws_key=AKIAIOSFODNN7EXAMPLE\n', 'utf8');
    const dirtyAudit = EncryptedArtifactStore.auditPersistentDataDir(tmpData);
    assert.equal(dirtyAudit.clean, false);
    assert.ok(dirtyAudit.findings.some((f) => f.category === 'SENSITIVE_SECRET_PATTERN'));
  } finally {
    if (prevDataDir === undefined) delete process.env.WINHOOD_DATA_DIR;
    else process.env.WINHOOD_DATA_DIR = prevDataDir;
    fs.rmSync(tmpData, { recursive: true, force: true });
  }
});

// ============================================================================
// 12. Docker-First Hardening — Real Async Subprocess Cancellation (Zero Orphans)
// ============================================================================
test('DockerFirst-RealCancellation: POST /worker/jobs/:jobId/cancel terminates real running child process and cleans up ephemeral workspace', async () => {
  const tmpData = createTempDir('wh-cancel-orch-');
  const tmpWs = createTempDir('wh-cancel-ws-');
  const workerToken = crypto.randomBytes(24).toString('hex');

  const worker = await startScannerWorkerServer({
    host: '127.0.0.1',
    port: 0,
    workerToken,
    baseWorkspaceDir: tmpWs,
    toolRunnerOverride: async ({ jobId, toolId, filesMap, timeoutMs, baseWorkspaceDir }) => {
      const { result } = await EphemeralWorkspaceManager.withWorkspace(
        { jobId: `${jobId}-${toolId}`, filesMap, baseDir: baseWorkspaceDir },
        async (ws) => {
          const proc = await spawnManagedScannerProcess({
            jobId,
            toolId,
            command: process.execPath,
            args: ['-e', 'setInterval(() => {}, 1000);'],
            cwd: ws.rootPath,
            env: { PATH: process.env.PATH || '' },
            timeoutMs,
          });
          return {
            toolId,
            state: proc.cancelled ? ('CANCELLED' as const) : ('COMPLETED' as const),
            version: 'node-test',
            exitCode: proc.exitCode,
            durationMs: 10,
            outputFormat: 'JSON' as const,
            outputValidated: false,
            findingsCount: 0,
            rawOutputSha256: 'b'.repeat(64),
            limitations: [],
          };
        }
      );
      return result;
    },
  });

  try {
    const orch = new ScannerJobOrchestrator({
      dataDir: tmpData,
      workerUrl: worker.url,
      workerToken,
      maxConcurrency: 1,
    });

    const job = orch.enqueueJob({
      toolIds: ['semgrep'],
      filesMap: { 'src/slow.ts': 'export const slow = true;\n' },
      timeoutMs: 30_000,
      maxRetries: 0,
    });

    // Wait until the real child process is spawned and registered inside the worker
    const waitDeadline = Date.now() + 5_000;
    while (getActiveScannerProcessCount() === 0 && Date.now() < waitDeadline) {
      await new Promise((r) => setTimeout(r, 30));
    }
    assert.ok(
      getActiveScannerProcessCount() >= 1,
      'Expected an active child process to be running inside the worker'
    );

    const cancelOutcome = await orch.cancelJobConfirmed(job.jobId);
    assert.equal(cancelOutcome.workerCancellationConfirmed, true);
    assert.ok(cancelOutcome.activeProcessesKilled >= 1, 'Expected real worker child process to be killed');
    assert.equal(cancelOutcome.job?.state, 'CANCELLED');
    assert.equal(cancelOutcome.job?.analysisVerdict, 'CANCELLED');

    // Allow workspace finally block to settle and confirm zero orphans
    const settleDeadline = Date.now() + 3_000;
    while (
      (getActiveScannerProcessCount() > 0 || EphemeralWorkspaceManager.getActiveWorkspaceCount() > 0) &&
      Date.now() < settleDeadline
    ) {
      await new Promise((r) => setTimeout(r, 30));
    }
    assert.equal(getActiveScannerProcessCount(), 0, 'Zero active scanner processes may remain');
    assert.equal(EphemeralWorkspaceManager.getActiveWorkspaceCount(), 0, 'Zero ephemeral workspaces may remain');
  } finally {
    await worker.close();
    fs.rmSync(tmpData, { recursive: true, force: true });
    fs.rmSync(tmpWs, { recursive: true, force: true });
  }
});
