#!/usr/bin/env node
/**
 * WinHood Benchmarking — End-to-End Verification Script (Docker Local-Web & Standalone Production)
 *
 * Usage:
 *   node scripts/verify-docker-local-web.mjs                         # Validates running Docker container at http://localhost:3000 + docker compose restart persistence
 *   node scripts/verify-docker-local-web.mjs --base-url http://localhost:3080 --no-restart
 *   node scripts/verify-docker-local-web.mjs --self-hosted           # Spawns real dist-server/server.mjs in DOCKER_LOCAL_WEB production mode + SIGTERM restart persistence
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync, spawn } from 'node:child_process';

const SHA256_HEX_RE = /^[a-f0-9]{64}$/i;

function computeSha256(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function buildZipBuffer(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  const crc32Table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    crc32Table[i] = c >>> 0;
  }
  const crc32 = (buf) => {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
      c = crc32Table[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    }
    return (c ^ 0xffffffff) >>> 0;
  };

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const rawBuf = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content, 'utf8');
    const method = entry.deflate ? 8 : 0;
    const compBuf = entry.deflate ? zlib.deflateRawSync(rawBuf, { level: 9 }) : rawBuf;
    const crc = crc32(rawBuf);

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(method, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compBuf.length, 18);
    localHeader.writeUInt32LE(rawBuf.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);

    localParts.push(localHeader, nameBuf, compBuf);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(method, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(compBuf.length, 20);
    centralHeader.writeUInt32LE(rawBuf.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);

    centralParts.push(centralHeader, nameBuf);
    offset += localHeader.length + nameBuf.length + compBuf.length;
  }

  const centralDirBuf = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralDirBuf, eocd]);
}

async function getFreeLoopbackPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 3000;
      srv.close(() => resolve(port));
    });
  });
}

async function waitForHealth(baseUrl, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  let lastErr = null;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${baseUrl}/api/health`);
      if (res.ok) {
        const body = await res.json();
        if (body.status === 'ONLINE' && body.ready === true) {
          return body;
        }
      }
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(
    `Healthcheck timed out after ${timeoutMs}ms at ${baseUrl}/api/health${lastErr ? `: ${lastErr.message}` : ''}`
  );
}

function parseCliArgs(argv) {
  const opts = {
    baseUrl: process.env.WINHOOD_VERIFY_URL || 'http://localhost:3000',
    selfHosted: false,
    checkRestart: true,
    keepProject: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--self-hosted') {
      opts.selfHosted = true;
    } else if (arg === '--no-restart') {
      opts.checkRestart = false;
    } else if (arg === '--keep-project') {
      opts.keepProject = true;
    } else if (arg === '--base-url' && argv[i + 1]) {
      let rawBase = argv[++i];
      while (rawBase.endsWith('/')) {
        rawBase = rawBase.slice(0, -1);
      }
      opts.baseUrl = rawBase;
    }
  }
  return opts;
}

function resolveFixedDockerExecutable() {
  const candidates =
    process.platform === 'win32'
      ? [
          'C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe',
          'C:\\ProgramData\\DockerDesktop\\version-bin\\docker.exe',
        ]
      : ['/usr/bin/docker', '/usr/local/bin/docker', '/opt/homebrew/bin/docker'];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error(`Docker executable not found in fixed system directories: ${candidates.join(', ')}`);
}

function spawnProductionWorker({ workerBundlePath, port, workerToken, tempWorkspaceDir }) {
  return spawn(process.execPath, [workerBundlePath], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      NODE_ENV: 'production',
      WINHOOD_SCANNER_WORKER_HOST: '127.0.0.1',
      WINHOOD_SCANNER_WORKER_PORT: String(port),
      WINHOOD_SCANNER_WORKER_TOKEN: workerToken,
      WINHOOD_TEMP_WORKSPACE_DIR: tempWorkspaceDir,
    },
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
}

function spawnProductionServer({ bundlePath, port, dataDir, masterSecret, workerUrl, workerToken }) {
  return spawn(process.execPath, [bundlePath], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      NODE_ENV: 'production',
      PORT: String(port),
      WINHOOD_PORT: String(port),
      WINHOOD_DEPLOYMENT_MODE: 'LOCAL_WEB',
      WINHOOD_RUNTIME_ENV: 'DOCKER_LOCAL_WEB',
      WINHOOD_ALLOW_NETWORK_BIND: 'false',
      WINHOOD_BIND_HOST: '127.0.0.1',
      WINHOOD_DATA_DIR: dataDir,
      WINHOOD_KEYSTORE_MASTER_SECRET: masterSecret,
      ...(workerUrl ? { WINHOOD_SCANNER_WORKER_URL: workerUrl } : {}),
      ...(workerToken ? { WINHOOD_SCANNER_WORKER_TOKEN: workerToken } : {}),
    },
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
}

async function waitForWorkerHealth(workerUrl, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${workerUrl}/worker/health`);
      if (res.ok) {
        const body = await res.json();
        if (body.status === 'ONLINE') return body;
      }
    } catch {
      // Retry
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`Worker healthcheck timed out at ${workerUrl}/worker/health`);
}

async function stopProcessGracefully(child) {
  if (!child || child.exitCode !== null) {
    return { exitCode: child?.exitCode ?? 0, signal: child?.signalCode ?? null, timedOut: false };
  }
  const exitPromise = new Promise((resolve) => {
    child.once('exit', (code, signal) => resolve({ exitCode: code, signal: signal ?? null, timedOut: false }));
  });

  // On Windows, SIGTERM maps to TerminateProcess (exitCode === null). Use IPC graceful shutdown
  // channel when available on Windows so the server runs onBeforeClose/onAfterClose and exits 0.
  if (process.platform === 'win32' && typeof child.send === 'function' && child.connected) {
    child.send({ type: 'WINHOOD_GRACEFUL_SHUTDOWN', reason: 'VERIFY_SCRIPT_RESTART' });
  } else {
    child.kill('SIGTERM');
  }

  const outcome = await Promise.race([
    exitPromise,
    new Promise((resolve) =>
      setTimeout(() => resolve({ exitCode: null, signal: null, timedOut: true }), 8000)
    ),
  ]);
  if (child.exitCode === null) {
    child.kill('SIGKILL');
  }
  return outcome;
}

async function runVerification() {
  const opts = parseCliArgs(process.argv.slice(2));
  const results = [];
  const record = (name, detail) => {
    results.push({ name, status: 'PASSED', detail });
    console.log(`[PASS] ${name} — ${detail}`);
  };

  let baseUrl = opts.baseUrl;
  let selfHostedChild = null;
  let selfHostedWorkerChild = null;
  let selfHostedDir = null;
  let selfHostedWorkerWsDir = null;
  let selfHostedPort = null;
  let selfHostedSecret = null;
  let selfHostedWorkerUrl = null;
  let selfHostedWorkerToken = null;
  const bundlePath = path.join(process.cwd(), 'dist-server', 'server.mjs');
  const workerBundlePath = path.join(process.cwd(), 'dist-server', 'scanner-worker.mjs');

  try {
    if (opts.selfHosted) {
      if (!fs.existsSync(path.join(process.cwd(), 'dist', 'index.html'))) {
        throw new Error('dist/index.html missing. Run `npm run build` first.');
      }
      if (!fs.existsSync(bundlePath)) {
        throw new Error('dist-server/server.mjs missing. Run `npm run build:server` first.');
      }
      if (!fs.existsSync(workerBundlePath)) {
        throw new Error('dist-server/scanner-worker.mjs missing. Run `npm run build:server` first.');
      }
      selfHostedPort = await getFreeLoopbackPort();
      const selfHostedWorkerPort = await getFreeLoopbackPort();
      selfHostedDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-verify-docker-web-'));
      selfHostedWorkerWsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-verify-worker-ws-'));
      selfHostedSecret = crypto.randomBytes(32).toString('hex');
      selfHostedWorkerToken = crypto.randomBytes(32).toString('hex');
      selfHostedWorkerUrl = `http://127.0.0.1:${selfHostedWorkerPort}`;
      baseUrl = `http://127.0.0.1:${selfHostedPort}`;

      selfHostedWorkerChild = spawnProductionWorker({
        workerBundlePath,
        port: selfHostedWorkerPort,
        workerToken: selfHostedWorkerToken,
        tempWorkspaceDir: selfHostedWorkerWsDir,
      });
      await waitForWorkerHealth(selfHostedWorkerUrl, 20_000);

      selfHostedChild = spawnProductionServer({
        bundlePath,
        port: selfHostedPort,
        dataDir: selfHostedDir,
        masterSecret: selfHostedSecret,
        workerUrl: selfHostedWorkerUrl,
        workerToken: selfHostedWorkerToken,
      });
      await waitForHealth(baseUrl, 20_000);
    }

    console.log(`[WinHood Verify] Running E2E Docker Local-Web verification against ${baseUrl} ...`);

    // 1. GET / returns HTTP 200 with React SPA HTML and referenced JS/CSS assets return HTTP 200
    const rootRes = await fetch(`${baseUrl}/`);
    assert.equal(rootRes.status, 200, 'GET / must return HTTP 200');
    const html = await rootRes.text();
    assert.match(html, /<div\s+id=["']root["']>/i, 'GET / must serve React SPA HTML with #root');

    const assetPaths = new Set();
    for (const m of html.matchAll(/(?:src|href)=["'](\/assets\/[^"']+\.(?:js|css))["']/gi)) {
      assetPaths.add(m[1]);
    }
    assert.ok(assetPaths.size >= 1, 'SPA HTML must reference at least one JS/CSS asset under /assets/');
    for (const assetPath of assetPaths) {
      const assetRes = await fetch(`${baseUrl}${assetPath}`);
      assert.equal(assetRes.status, 200, `Asset ${assetPath} must return HTTP 200`);
      const assetText = await assetRes.text();
      assert.ok(assetText.length > 0, `Asset ${assetPath} must be non-empty`);
    }
    record('SPA & Static Assets', `GET / HTTP 200 + ${assetPaths.size} JS/CSS assets HTTP 200`);

    // 2. GET /api/health returns ONLINE, ready: true, runtimeEnv: DOCKER_LOCAL_WEB
    const healthRes = await fetch(`${baseUrl}/api/health`);
    assert.equal(healthRes.status, 200);
    const health = await healthRes.json();
    assert.equal(health.status, 'ONLINE');
    assert.equal(health.ready, true);
    assert.equal(health.runtimeEnv, 'DOCKER_LOCAL_WEB');
    assert.equal(health.deploymentMode, 'LOCAL_WEB');
    record(
      'Health Contract',
      `status=${health.status}, ready=${health.ready}, runtimeEnv=${health.runtimeEnv}, deploymentMode=${health.deploymentMode}`
    );

    // 3. GET /api/bootstrap and GET /api/dashboard return HTTP 200 without login or OAuth
    const bootstrapRes = await fetch(`${baseUrl}/api/bootstrap`);
    assert.equal(bootstrapRes.status, 200);
    const bootstrap = await bootstrapRes.json();
    assert.equal(bootstrap.accessMode, 'UNRESTRICTED_LOCAL');
    assert.equal(bootstrap.runtimeEnv, 'DOCKER_LOCAL_WEB');

    const dashboardRes = await fetch(`${baseUrl}/api/dashboard`);
    assert.equal(dashboardRes.status, 200);
    const dashboard = await dashboardRes.json();
    assert.ok(dashboard && typeof dashboard === 'object');
    record(
      'Local-First Unrestricted Access',
      'GET /api/bootstrap & GET /api/dashboard HTTP 200 (no login/OAuth required)'
    );

    // 4. POST /api/projects/extract-zip extracts valid ZIP and blocks synthetic ZIP Bomb (HTTP 400 ZIP_BOMB_BLOCKED)
    const validZip = buildZipBuffer([
      {
        name: 'demo-repo/src/index.ts',
        content: 'export function greet(name: string): string { return `Hello ${name}`; }\n',
        deflate: true,
      },
    ]);
    const validZipRes = await fetch(`${baseUrl}/api/projects/extract-zip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ zipBase64: validZip.toString('base64') }),
    });
    assert.equal(validZipRes.status, 200, 'Valid ZIP must extract with HTTP 200');
    const validZipJson = await validZipRes.json();
    assert.equal(validZipJson.extractedCount, 1);
    assert.match(validZipJson.filesMap['demo-repo/src/index.ts'] || '', /Hello/);

    // Synthetic DEFLATE ZIP bomb: 1.5 MB of zeros compresses to ~1.5 KB (ratio ~1000:1 > 100:1 limit)
    const bombZip = buildZipBuffer([
      {
        name: 'bomb/payload.txt',
        content: Buffer.alloc(1_500_000, 0x41),
        deflate: true,
      },
    ]);
    const bombZipRes = await fetch(`${baseUrl}/api/projects/extract-zip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ zipBase64: bombZip.toString('base64') }),
    });
    assert.equal(bombZipRes.status, 400, 'Synthetic ZIP Bomb must be rejected with HTTP 400');
    const bombZipJson = await bombZipRes.json();
    assert.equal(bombZipJson.error, 'ZIP_BOMB_BLOCKED');
    record(
      'ZIP Extraction & ZIP Bomb Guard',
      `valid ZIP extracted (${validZipJson.extractedCount} file) & synthetic ZIP bomb blocked (HTTP 400 ${bombZipJson.error})`
    );

    // 5. POST /api/gitar/configure with http://169.254.169.254 is blocked by SSRF_BLOCKED
    const ssrfRes = await fetch(`${baseUrl}/api/gitar/configure`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        gitProvider: 'GITHUB',
        apiBaseUrl: 'http://169.254.169.254',
        apiToken: 'verify-dummy-token-never-transmitted',
        explicitExternalCodeConsent: true,
      }),
    });
    assert.equal(ssrfRes.status, 400, 'Metadata URL must be rejected with HTTP 400');
    const ssrfJson = await ssrfRes.json();
    assert.equal(ssrfJson.error, 'SSRF_BLOCKED');
    assert.match(String(ssrfJson.message || ''), /SSRF_BLOCKED/);
    record('SSRF Metadata Protection', `POST /api/gitar/configure -> HTTP 400 (${ssrfJson.error})`);

    // 6. Full Project + Benchmark + Export (JSON / SARIF / SBOM) with SHA-256 verification
    const projName = `DockerVerify-${Date.now()}`;
    const createProjRes = await fetch(`${baseUrl}/api/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: projName,
        category: 'Backend APIs & Seguranca',
        objective: 'Validacao E2E Docker Local-Web com persistencia e evidencias SHA-256.',
        description: 'Projeto criado por scripts/verify-docker-local-web.mjs',
      }),
    });
    assert.equal(createProjRes.status, 201);
    const { project } = await createProjRes.json();
    assert.ok(project?.id);

    const createSwA = await fetch(`${baseUrl}/api/softwares`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        projectId: project.id,
        name: 'CleanCandidate',
        version: '1.0.0',
        vendor: 'VerifyLab',
        templatePreset: 'CUSTOM_FILES',
        customFilesMap: {
          'src/service.ts':
            'export function getUser(db: { query: (sql: string, p: string[]) => unknown }, id: string) {\n  return db.query("SELECT id, name FROM users WHERE id = $1", [id]);\n}\n',
          'package.json': JSON.stringify({ name: 'clean-candidate', version: '1.0.0', dependencies: {} }),
        },
      }),
    });
    assert.equal(createSwA.status, 201);
    const swA = (await createSwA.json()).software;

    const createSwB = await fetch(`${baseUrl}/api/softwares`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        projectId: project.id,
        name: 'RiskCandidate',
        version: '1.0.0',
        vendor: 'VerifyLab',
        templatePreset: 'CUSTOM_FILES',
        customFilesMap: {
          'src/vuln.ts':
            'export function rawQuery(req: { query: { id: string } }, db: { query: (s: string) => unknown }) {\n  return db.query("SELECT * FROM users WHERE id = " + req.query.id);\n}\n',
          'package.json': JSON.stringify({
            name: 'risk-candidate',
            version: '1.0.0',
            dependencies: { lodash: '4.17.15' },
          }),
        },
      }),
    });
    assert.equal(createSwB.status, 201);
    const swB = (await createSwB.json()).software;

    const runCreateRes = await fetch(`${baseUrl}/api/benchmark-runs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        projectId: project.id,
        softwareIds: [swA.id, swB.id],
        wizardMode: 'QUICK',
        assessmentMode: 'AB_COMPARE',
      }),
    });
    assert.equal(runCreateRes.status, 201);
    let run = (await runCreateRes.json()).run;
    assert.ok(run?.id);

    const pollDeadline = Date.now() + 25_000;
    while (run.status === 'RUNNING' && Date.now() < pollDeadline) {
      await new Promise((r) => setTimeout(r, 150));
      const pollRes = await fetch(`${baseUrl}/api/benchmark-runs/${encodeURIComponent(run.id)}`);
      if (pollRes.ok) {
        const polled = await pollRes.json();
        if (polled?.run) run = polled.run;
      }
    }
    assert.ok(
      run.status === 'COMPLETED' || run.status === 'COMPLETED_WITH_WARNINGS',
      `Benchmark run did not finish cleanly: ${run.status}`
    );

    const verifyEvidenceRes = await fetch(`${baseUrl}/api/evidence/${encodeURIComponent(run.id)}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(verifyEvidenceRes.status, 200);
    const evidenceVerify = await verifyEvidenceRes.json();
    assert.equal(evidenceVerify.valid, true, 'Evidence chain & manifest must be cryptographically valid');
    assert.equal(evidenceVerify.chainIntegrityValid, true, 'Evidence chain integrity must be valid');
    assert.equal(evidenceVerify.manifestSignatureValid, true, 'Signed manifest signature must be valid');
    assert.match(String(evidenceVerify.actualRootHash || ''), SHA256_HEX_RE);

    const jsonExportRes = await fetch(
      `${baseUrl}/api/reports/${encodeURIComponent(run.id)}/export?format=json`
    );
    assert.equal(jsonExportRes.status, 200);
    const jsonExportText = await jsonExportRes.text();
    const jsonExportSha256 = computeSha256(jsonExportText);
    assert.match(jsonExportSha256, SHA256_HEX_RE);
    const jsonExportObj = JSON.parse(jsonExportText);
    assert.ok(jsonExportObj && typeof jsonExportObj === 'object');

    const sarifExportRes = await fetch(
      `${baseUrl}/api/reports/${encodeURIComponent(run.id)}/export?format=sarif`
    );
    assert.equal(sarifExportRes.status, 200);
    const sarifText = await sarifExportRes.text();
    const sarifSha256 = computeSha256(sarifText);
    assert.match(sarifSha256, SHA256_HEX_RE);
    const sarifObj = JSON.parse(sarifText);
    assert.equal(sarifObj.version, '2.1.0');

    const sbomRes = await fetch(
      `${baseUrl}/api/runs/${encodeURIComponent(run.id)}/sbom?format=cyclonedx`
    );
    assert.equal(sbomRes.status, 200);
    const sbomJson = await sbomRes.json();
    assert.match(String(sbomJson.documentSha256 || ''), SHA256_HEX_RE);
    assert.equal(sbomJson.signatureVerification?.valid, true);

    record(
      'Benchmark & Signed Exports (JSON/SARIF/SBOM)',
      `run=${run.id} (${run.status}), jsonSha256=${jsonExportSha256.slice(0, 12)}, sarifSha256=${sarifSha256.slice(0, 12)}, sbomSha256=${String(sbomJson.documentSha256).slice(0, 12)}`
    );

    // 6b. Verify encrypted-only storage at rest (zero plaintext source files or secret leaks across WINHOOD_DATA_DIR)
    const plaintextAuditRes = await fetch(`${baseUrl}/api/storage/plaintext-audit`);
    assert.equal(plaintextAuditRes.status, 200);
    const plaintextAudit = await plaintextAuditRes.json();
    assert.equal(
      plaintextAudit.clean,
      true,
      `Plaintext source files or secret leaks detected: ${JSON.stringify(plaintextAudit)}`
    );
    assert.ok(
      plaintextAudit.encryptedBundleCount >= 2,
      'Encrypted vault_bundle.whenc bundles must exist for ingested softwares'
    );
    assert.equal(
      plaintextAudit.persistentVolumeAudit?.clean,
      true,
      `Persistent volume audit reported findings: ${JSON.stringify(plaintextAudit.persistentVolumeAudit?.findings)}`
    );
    record(
      'Encrypted-Only Persistent Storage & Volume Audit',
      `clean=${plaintextAudit.clean}, encryptedBundles=${plaintextAudit.encryptedBundleCount}, scannedDirs=${(plaintextAudit.persistentVolumeAudit?.scannedDirectories || []).length}`
    );

    // 6c. Verify authenticated API <-> Scanner Worker communication & async job orchestration
    const capsRes = await fetch(`${baseUrl}/api/scanner-worker/capabilities`);
    assert.equal(capsRes.status, 200);
    const capsBody = await capsRes.json();
    assert.equal(capsBody.workerConfigured, true, 'Scanner worker must be configured');
    assert.equal(capsBody.workerReachable, true, 'Scanner worker must be reachable via Bearer token auth');
    assert.ok(Array.isArray(capsBody.capabilities) && capsBody.capabilities.length >= 10);

    const jobCreateRes = await fetch(`${baseUrl}/api/scanner-worker/jobs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        projectId: project.id,
        softwareId: swA.id,
        toolIds: ['semgrep', 'gitleaks', 'grype'],
        timeoutMs: 15_000,
      }),
    });
    assert.equal(jobCreateRes.status, 202);
    let workerJob = (await jobCreateRes.json()).job;
    assert.ok(workerJob?.jobId);
    const jobDeadline = Date.now() + 20_000;
    while (
      (workerJob.state === 'QUEUED' || workerJob.state === 'RUNNING' || workerJob.state === 'CANCELLING') &&
      Date.now() < jobDeadline
    ) {
      await new Promise((r) => setTimeout(r, 100));
      const jRes = await fetch(`${baseUrl}/api/scanner-worker/jobs/${encodeURIComponent(workerJob.jobId)}`);
      if (jRes.ok) {
        workerJob = (await jRes.json()).job;
      }
    }
    assert.ok(
      workerJob.state !== 'QUEUED' && workerJob.state !== 'RUNNING',
      `Scanner worker job did not settle: ${workerJob.state}`
    );
    const operationalCount = capsBody.capabilities.filter((c) => c.finalState === 'OPERATIONAL').length;
    record(
      'Isolated Scanner Worker Auth & Job Orchestration',
      `workerReachable=true, operationalTools=${operationalCount}/${capsBody.capabilities.length}, job=${workerJob.jobId} (${workerJob.state}, verdict=${workerJob.analysisVerdict})`
    );

    // 7. Persistence across restart
    if (opts.checkRestart) {
      if (opts.selfHosted) {
        const shutdownOutcome = await stopProcessGracefully(selfHostedChild);
        assert.equal(shutdownOutcome.timedOut, false, 'Self-hosted production server shutdown must not time out');
        assert.equal(
          shutdownOutcome.exitCode,
          0,
          `Self-hosted production server must exit 0 gracefully (got code=${shutdownOutcome.exitCode}, signal=${shutdownOutcome.signal})`
        );
        selfHostedChild = spawnProductionServer({
          bundlePath,
          port: selfHostedPort,
          dataDir: selfHostedDir,
          masterSecret: selfHostedSecret,
          workerUrl: selfHostedWorkerUrl,
          workerToken: selfHostedWorkerToken,
        });
        await waitForHealth(baseUrl, 20_000);
      } else {
        const dockerBin = resolveFixedDockerExecutable();
        const fixedPath =
          process.platform === 'win32'
            ? 'C:\\Program Files\\Docker\\Docker\\resources\\bin;C:\\Windows\\System32;C:\\Windows'
            : '/usr/local/bin:/usr/bin:/bin';
        execFileSync(dockerBin, ['compose', 'restart', 'winhood'], {
          cwd: process.cwd(),
          stdio: 'inherit',
          env: {
            ...process.env,
            PATH: fixedPath,
          },
        });
        await waitForHealth(baseUrl, 45_000);
      }

      const persistedProjRes = await fetch(`${baseUrl}/api/projects`);
      assert.equal(persistedProjRes.status, 200);
      const { projects } = await persistedProjRes.json();
      const found = Array.isArray(projects) && projects.some((p) => p.id === project.id);
      assert.equal(found, true, `Project ${project.id} must persist across container/server restart`);
      record(
        'Persistence Across Restart',
        `Project ${project.id} (${projName}) verified in GET /api/projects after restart`
      );
    }

    if (!opts.keepProject) {
      await fetch(`${baseUrl}/api/projects/${encodeURIComponent(project.id)}`, {
        method: 'DELETE',
      }).catch(() => {});
    }

    console.log(`\n[WinHood Verify] ALL ${results.length} CHECKS PASSED.`);
  } finally {
    if (selfHostedChild) {
      await stopProcessGracefully(selfHostedChild);
    }
    if (selfHostedWorkerChild) {
      await stopProcessGracefully(selfHostedWorkerChild);
    }
    if (selfHostedDir) {
      fs.rmSync(selfHostedDir, { recursive: true, force: true });
    }
    if (selfHostedWorkerWsDir) {
      fs.rmSync(selfHostedWorkerWsDir, { recursive: true, force: true });
    }
  }
}

runVerification().catch((err) => {
  console.error('[WinHood Verify FAILED]:', err);
  process.exit(1);
});
