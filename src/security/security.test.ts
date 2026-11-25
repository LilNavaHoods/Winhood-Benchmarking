import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { AddressInfo } from 'node:net';
import {
  computeGitNewCodeDiffMap,
  evaluateCleanAsYouCodeGate,
} from '../gate/NewCodeDiffEngine';
import {
  parseSarifToNormalizedFindings,
  runLocalRulesPack,
} from '../analyzers/ExternalRulesBridge';
import { WINHOOD_SQLITE_SCHEMA_SQL } from '../storage/SqliteMigrationPlan';
import {
  OptionalTotpService,
  base32Decode,
  base32Encode,
  generateTotpCode,
  verifyTotpCode,
} from './OptionalTotpService';
import { KeyManagementService } from './KeyManagementService';
import { SsrfGuard } from '../execution/SsrfGuard';
import { buildMinimalSandboxEnv, SandboxExecutor } from '../execution/SandboxExecutor';
import { PersistentDatabaseManager } from '../storage/PersistentDatabaseManager';
import {
  GENESIS_EVIDENCE_HASH,
  signEvidenceManifestHmacSha256,
  verifyEvidenceChainAndManifest,
} from '../engine/evidenceProvenanceEngine';
import { MqrBridgeConnection } from '../integrations/mqr-bridge/SonarConnection';
import { GitarInstallationHealth } from '../integrations/gitar/GitarInstallationHealth';
import { MqrBridgeApiClient } from '../integrations/mqr-bridge/SonarApiClient';
import { SonarScannerExecutor } from '../integrations/mqr-bridge/SonarScannerExecutor';
import { GitarApiClient } from '../integrations/gitar/GitarApiClient';
import {
  enforceVerifiedQualityGateOnRun,
  executeBenchmarkRunOrchestration,
} from '../engine/benchmarkOrchestrator';
import {
  ALL_BENCHMARK_CATEGORIES,
  DEFAULT_CATEGORY_WEIGHTS,
} from '../engine/scoringEngine';
import { buildTechnicalInventory } from '../engine/staticAnalyzer';
import { ProjectBackupService } from '../services/backup/ProjectBackupService';
import { createWinHoodApp } from '../../server';

function extractSetCookieValues(res: Response): Record<string, string> {
  const anyHeaders = res.headers as unknown as {
    getSetCookie?: () => string[];
    raw?: () => Record<string, string[]>;
  };
  const rawList: string[] =
    typeof anyHeaders.getSetCookie === 'function'
      ? anyHeaders.getSetCookie()
      : res.headers.get('set-cookie')
        ? [res.headers.get('set-cookie') as string]
        : [];
  const jar: Record<string, string> = {};
  for (const headerLine of rawList) {
    const firstPair = headerLine.split(';')[0] || '';
    const eq = firstPair.indexOf('=');
    if (eq > 0) {
      jar[firstPair.slice(0, eq).trim()] = firstPair.slice(eq + 1).trim();
    }
  }
  return jar;
}

async function withIsolatedKeystoreEnv(fn: (tmpDir: string) => Promise<void>): Promise<void> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-sec-test-'));
  const prevKeystore = process.env.WINHOOD_KEYSTORE_PATH;
  const prevHmac = process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
  const prevVault = process.env.WINHOOD_VAULT_SECRET;
  const prevSalt = process.env.SONAR_SECRET_SALT;
  const prevNodeEnv = process.env.NODE_ENV;
  const prevTestMode = process.env.WINHOOD_TEST_MODE;

  process.env.WINHOOD_KEYSTORE_PATH = path.join(tmpDir, 'keys', 'keystore.json');
  delete process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
  delete process.env.WINHOOD_VAULT_SECRET;
  delete process.env.SONAR_SECRET_SALT;

  try {
    await fn(tmpDir);
  } finally {
    if (prevKeystore === undefined) delete process.env.WINHOOD_KEYSTORE_PATH;
    else process.env.WINHOOD_KEYSTORE_PATH = prevKeystore;
    if (prevHmac === undefined) delete process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
    else process.env.WINHOOD_EVIDENCE_HMAC_SECRET = prevHmac;
    if (prevVault === undefined) delete process.env.WINHOOD_VAULT_SECRET;
    else process.env.WINHOOD_VAULT_SECRET = prevVault;
    if (prevSalt === undefined) delete process.env.SONAR_SECRET_SALT;
    else process.env.SONAR_SECRET_SALT = prevSalt;
    if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevNodeEnv;
    if (prevTestMode === undefined) delete process.env.WINHOOD_TEST_MODE;
    else process.env.WINHOOD_TEST_MODE = prevTestMode;

    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

test('OptionalTotpService enforces AES-256-GCM at-rest encryption, RFC-6238 replay protection, salted SHA-256 single-use recovery codes, rate limiting, and key rotation', async () => {
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    // 1. Base32 round-trip & pure RFC-6238 verification
    const rawBytes = crypto.randomBytes(20);
    const encoded = base32Encode(rawBytes);
    assert.deepEqual(base32Decode(encoded), rawBytes);

    const fixedNow = Date.now();
    const codeNow = generateTotpCode(encoded, fixedNow);
    assert.match(codeNow, /^\d{6}$/);
    assert.equal(verifyTotpCode(encoded, codeNow, fixedNow), true);
    assert.equal(verifyTotpCode(encoded, '000000', fixedNow), codeNow === '000000');

    // 2. Disabled by default -> unrestricted local access
    const svc = new OptionalTotpService(tmpDir);
    assert.equal(svc.isEnabled(), false);
    assert.equal(svc.isRequestUnlocked(null), true);
    const status0 = svc.getStatus();
    assert.equal(status0.enabled, false);
    assert.equal(status0.unlocked, true);
    assert.equal(status0.remainingRecoveryCodes, 0);

    // 3. Begin setup & reject invalid code before confirming
    const setup = svc.beginSetup();
    assert.ok(setup.secret.length >= 24);
    assert.ok(setup.otpauthUrl.startsWith('otpauth://totp/WinHood:LocalWorkspace?secret='));
    assert.equal(setup.recoveryCodes.length, 8);
    assert.throws(() => svc.confirmSetup('000000', '10.0.0.1', fixedNow), /TOTP_CODE_INVALID/);
    assert.equal(svc.isEnabled(), false);

    // 4. Confirm setup with valid RFC-6238 code
    const confirmed = svc.confirmSetup(generateTotpCode(setup.secret, fixedNow), '10.0.0.1', fixedNow);
    assert.equal(confirmed.ok, true);
    assert.equal(confirmed.enabled, true);
    assert.equal(confirmed.unlocked, true);
    assert.equal(confirmed.remainingRecoveryCodes, 8);
    assert.equal(svc.isRequestUnlocked(confirmed.unlockToken, fixedNow), true);
    assert.equal(svc.isRequestUnlocked(null, fixedNow), false);

    // 5. Verify disk file stores AES-256-GCM ciphertext (zero plaintext secret or recovery codes)
    const configPath = path.join(tmpDir, 'totp_config.json');
    assert.equal(fs.existsSync(configPath), true);
    const rawDisk = fs.readFileSync(configPath, 'utf8');
    assert.equal(rawDisk.includes(setup.secret), false, 'Plaintext TOTP secret must never appear on disk');
    for (const rc of setup.recoveryCodes) {
      assert.equal(rawDisk.includes(rc), false, 'Plaintext recovery code must never appear on disk');
      assert.equal(rawDisk.includes(rc.replace('-', '')), false, 'Raw hex recovery code must never appear on disk');
    }
    assert.ok(rawDisk.includes('whvault:v1:'), 'TOTP secret must be encrypted with AES-256-GCM vault envelope');

    // 6. Lock revokes active unlock session
    const lockRes = svc.lock(confirmed.unlockToken);
    assert.equal(lockRes.enabled, true);
    assert.equal(lockRes.unlocked, false);
    assert.equal(svc.isRequestUnlocked(confirmed.unlockToken, fixedNow), false);

    // 7. Replay protection rejects re-using the exact same 30s TOTP step
    assert.throws(
      () => svc.verifyUnlock({ code: generateTotpCode(setup.secret, fixedNow), ipKey: '10.0.0.2', atMs: fixedNow }),
      /TOTP_REPLAY_REJECTED/
    );

    // 8. Next 30s step unlocks cleanly
    const nextStepMs = fixedNow + 30_000;
    const unlocked = svc.verifyUnlock({
      code: generateTotpCode(setup.secret, nextStepMs),
      ipKey: '10.0.0.2',
      atMs: nextStepMs,
    });
    assert.equal(unlocked.unlocked, true);
    assert.equal(unlocked.usedRecoveryCode, false);
    assert.equal(svc.validateCsrfToken(unlocked.unlockToken, unlocked.csrfToken), true);
    assert.equal(svc.validateCsrfToken(unlocked.unlockToken, 'wrong-csrf-token'), false);

    // 9. Single-use recovery code works once and is rejected on reuse
    const recUnlock = svc.verifyUnlock({
      recoveryCode: setup.recoveryCodes[0],
      ipKey: '10.0.0.3',
      atMs: nextStepMs,
    });
    assert.equal(recUnlock.usedRecoveryCode, true);
    assert.equal(recUnlock.remainingRecoveryCodes, 7);
    assert.throws(
      () => svc.verifyUnlock({ recoveryCode: setup.recoveryCodes[0], ipKey: '10.0.0.3', atMs: nextStepMs }),
      /TOTP_CODE_INVALID/
    );

    // 10. Rate limit triggers after 5 failed attempts from same IP
    for (let i = 0; i < 5; i++) {
      assert.throws(
        () => svc.verifyUnlock({ code: '999999', ipKey: '10.0.0.99', atMs: nextStepMs }),
        /TOTP_CODE_INVALID/
      );
    }
    assert.throws(
      () => svc.verifyUnlock({ recoveryCode: setup.recoveryCodes[1], ipKey: '10.0.0.99', atMs: nextStepMs }),
      /TOTP_RATE_LIMITED/
    );

    // 11. KMS rotation re-encrypts TOTP secret & persists across service reload
    const beforeEncrypted = JSON.parse(fs.readFileSync(configPath, 'utf8')).encryptedSecret as string;
    const rotated = KeyManagementService.rotateKey('TOKEN_VAULT_AES256', undefined, (ctx) => {
      const count = svc.reencryptTotpSecrets(ctx);
      assert.equal(count, 1);
    });
    const afterEncrypted = JSON.parse(fs.readFileSync(configPath, 'utf8')).encryptedSecret as string;
    assert.notEqual(afterEncrypted, beforeEncrypted);
    assert.ok(afterEncrypted.startsWith(`whvault:v1:${rotated.keyId}:`));

    // Fresh OptionalTotpService instance reloads from disk and verifies the next TOTP step
    const reloaded = new OptionalTotpService(tmpDir);
    assert.equal(reloaded.isEnabled(), true);
    const step3Ms = nextStepMs + 30_000;
    const unlockedAfterReload = reloaded.verifyUnlock({
      code: generateTotpCode(setup.secret, step3Ms),
      ipKey: '10.0.0.5',
      atMs: step3Ms,
    });
    assert.equal(unlockedAfterReload.unlocked, true);

    // 12. Disable requires valid code and restores unrestricted access
    assert.throws(
      () => reloaded.disable({ code: '123456', ipKey: '10.0.0.6', atMs: step3Ms }),
      /TOTP_CODE_INVALID/
    );
    const disabled = reloaded.disable({
      recoveryCode: setup.recoveryCodes[1],
      ipKey: '10.0.0.6',
      atMs: step3Ms,
    });
    assert.equal(disabled.enabled, false);
    assert.equal(disabled.unlocked, true);
    assert.equal(reloaded.isEnabled(), false);
    assert.equal(reloaded.isRequestUnlocked(null), true);
  });
});

test('HTTP integration: Unrestricted Local Access by default, Optional TOTP 2FA gate + CSRF, legacy auth routes 404, SSRF guard, run-tests attachment, contract test guard, CSP & KMS rotation', async () => {
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const { app, getDb } = await createWinHoodApp({
      dataDir: tmpDir,
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // 1. Strict CSP, single Referrer-Policy, and Unrestricted Local Access on /api/health
      const healthRes = await fetch(`${baseUrl}/api/health`);
      assert.equal(healthRes.status, 200);
      const healthJson = (await healthRes.json()) as {
        status: string;
        accessMode: string;
        totpEnabled: boolean;
      };
      assert.equal(healthJson.status, 'ONLINE');
      assert.equal(healthJson.accessMode, 'UNRESTRICTED_LOCAL');
      assert.equal(healthJson.totpEnabled, false);

      const csp = healthRes.headers.get('content-security-policy') || '';
      assert.ok(csp.includes("default-src 'self'"), 'CSP must include default-src self');
      assert.ok(csp.includes("script-src 'self'"), 'CSP must include script-src self');
      assert.ok(csp.includes("object-src 'none'"), 'CSP must include object-src none');
      assert.ok(csp.includes("frame-ancestors 'self'"), 'Localhost CSP must restrict frame-ancestors to self');
      assert.equal(healthRes.headers.get('referrer-policy'), 'no-referrer');
      assert.equal(healthRes.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(healthRes.headers.get('x-frame-options'), 'SAMEORIGIN');

      // 1b. Hosted preview iframe (*.run.app) allows https://*.google.com framing without X-Frame-Options conflict
      const previewHealthRes = await fetch(`${baseUrl}/api/health`, {
        headers: { 'x-forwarded-host': 'ais-dev-example.us-east1.run.app' },
      });
      assert.equal(previewHealthRes.status, 200);
      assert.ok(
        (previewHealthRes.headers.get('content-security-policy') || '').includes(
          "frame-ancestors 'self' https://*.google.com"
        ),
        'Hosted preview CSP must allow https://*.google.com frame-ancestors'
      );
      assert.equal(
        previewHealthRes.headers.get('x-frame-options'),
        null,
        'Hosted preview must omit X-Frame-Options so CSP frame-ancestors governs framing'
      );

      // 2. All legacy login / signup / OAuth / PIN / WebAuthn / RBAC routes must be completely removed (404)
      const removedRoutes: Array<[string, string]> = [
        ['GET', '/api/auth/bootstrap-status'],
        ['POST', '/api/auth/bootstrap-admin'],
        ['POST', '/api/auth/solo-local'],
        ['POST', '/api/auth/register'],
        ['POST', '/api/auth/login'],
        ['GET', '/api/auth/me'],
        ['POST', '/api/auth/logout'],
        ['GET', '/api/auth/users'],
        ['POST', '/api/auth/switch-role'],
        ['GET', '/api/auth/github/oauth/start'],
        ['GET', '/api/auth/github/oauth/callback'],
        ['POST', '/api/auth/github/device/start'],
        ['POST', '/api/auth/github/token'],
        ['POST', '/api/auth/webauthn/login/options'],
        ['GET', '/api/admin/integrations/github-oauth'],
      ];
      for (const [method, route] of removedRoutes) {
        const res = await fetch(`${baseUrl}${route}`, {
          method,
          headers: method === 'POST' ? { 'Content-Type': 'application/json' } : undefined,
          body: method === 'POST' ? '{}' : undefined,
        });
        assert.equal(res.status, 404, `Legacy auth route ${method} ${route} must be removed (404)`);
      }

      // 3. Immediate unrestricted read & write access when Optional TOTP is disabled
      const directBootstrap = await fetch(`${baseUrl}/api/bootstrap`);
      assert.equal(directBootstrap.status, 200);
      const directCreateProj = await fetch(`${baseUrl}/api/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Unrestricted Local Project',
          category: 'Backend APIs',
          objective: 'Confirm unrestricted local workspace access.',
        }),
      });
      assert.equal(directCreateProj.status, 201);

      // 4. SSRF Guard enforcement on /api/execution/run-perf + Audit log recording
      const ssrfLoopback = await fetch(`${baseUrl}/api/execution/run-perf`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl: 'http://127.0.0.1:9999/health' }),
      });
      assert.equal(ssrfLoopback.status, 403);
      assert.equal(((await ssrfLoopback.json()) as { error: string }).error, 'SSRF_BLOCKED');

      const ssrfMeta = await fetch(`${baseUrl}/api/execution/run-perf`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl: 'http://169.254.169.254/latest/meta-data' }),
      });
      assert.equal(ssrfMeta.status, 403);
      assert.equal(((await ssrfMeta.json()) as { error: string }).error, 'SSRF_BLOCKED');

      const auditRes = await fetch(`${baseUrl}/api/audit`);
      assert.equal(auditRes.status, 200);
      const auditJson = (await auditRes.json()) as { auditLogs: Array<{ action: string }> };
      assert.ok(auditJson.auditLogs.some((l) => l.action === 'SSRF_ATTEMPT_BLOCKED'));

      // 5. /api/execution/run-tests returns 404 on nonexistent softwareId & attaches UnifiedExecutionRecord on valid softwareId
      const missingSwRes = await fetch(`${baseUrl}/api/execution/run-tests`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ softwareId: 'sw-does-not-exist-404' }),
      });
      assert.equal(missingSwRes.status, 404);

      const envSwitchRes = await fetch(`${baseUrl}/api/environment/switch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'DEMO' }),
      });
      assert.equal(envSwitchRes.status, 200);

      const seedRes = await fetch(`${baseUrl}/api/demo/seed`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      assert.equal(seedRes.status, 200);
      const seededSw = getDb().softwares[0];
      assert.ok(seededSw);

      const execRunRes = await fetch(`${baseUrl}/api/benchmark-runs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: seededSw.projectId,
          softwareIds: [seededSw.id],
          profileName: 'Sonar way (Modo MQR)',
        }),
      });
      assert.equal(execRunRes.status, 201);

      const runTestsRes = await fetch(`${baseUrl}/api/execution/run-tests`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ softwareId: seededSw.id }),
      });
      assert.equal(runTestsRes.status, 200);
      const runTestsJson = (await runTestsRes.json()) as { attachedToRunId: string | null };
      assert.ok(runTestsJson.attachedToRunId);
      const attachedRun = getDb().runs.find((r) => r.id === runTestsJson.attachedToRunId);
      assert.ok(attachedRun && (attachedRun.executionRecords?.length ?? 0) >= 1);

      // 6. /api/mqr-bridge/run-integration-tests returns 403 CONTRACT_TEST_ONLY_IN_TEST_MODE outside test mode
      const savedNodeEnv = process.env.NODE_ENV;
      const savedTestMode = process.env.WINHOOD_TEST_MODE;
      process.env.NODE_ENV = 'production';
      delete process.env.WINHOOD_TEST_MODE;
      try {
        const contractGuardRes = await fetch(`${baseUrl}/api/mqr-bridge/run-integration-tests`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        });
        assert.equal(contractGuardRes.status, 403);
        const contractJson = (await contractGuardRes.json()) as { error: string };
        assert.equal(contractJson.error, 'CONTRACT_TEST_ONLY_IN_TEST_MODE');
      } finally {
        if (savedNodeEnv === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = savedNodeEnv;
        if (savedTestMode === undefined) delete process.env.WINHOOD_TEST_MODE;
        else process.env.WINHOOD_TEST_MODE = savedTestMode;
      }

      // 7. Optional TOTP 2FA full HTTP lifecycle: setup -> confirm -> lock -> 401 gate -> verify -> CSRF -> KMS rotation -> disable
      const setupRes = await fetch(`${baseUrl}/api/totp/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      assert.equal(setupRes.status, 200);
      const setupJson = (await setupRes.json()) as {
        secret: string;
        otpauthUrl: string;
        qrDataUrl: string;
        recoveryCodes: string[];
      };
      assert.ok(setupJson.secret.length >= 24);
      assert.ok(setupJson.qrDataUrl.startsWith('data:image/png;base64,'));
      assert.equal(setupJson.recoveryCodes.length, 8);

      // Loopback confirm sets HttpOnly SameSite=Strict cookie and omits X-WinHood-Session-Token header
      const confirmRes = await fetch(`${baseUrl}/api/totp/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: generateTotpCode(setupJson.secret) }),
      });
      assert.equal(confirmRes.status, 200);
      assert.equal(confirmRes.headers.get('x-winhood-session-token'), null);
      const confirmSetCookies = confirmRes.headers.getSetCookie?.() || [];
      assert.ok(
        confirmSetCookies.some(
          (c) => c.includes('winhood_totp_unlock=') && c.includes('HttpOnly') && c.includes('SameSite=Strict')
        ),
        'TOTP unlock cookie must be HttpOnly and SameSite=Strict on loopback'
      );
      const jar1 = extractSetCookieValues(confirmRes);
      const cookie1 = `winhood_totp_unlock=${jar1.winhood_totp_unlock}; winhood_csrf=${jar1.winhood_csrf}`;

      // Cookie-based mutation without CSRF token must be rejected with 403 while TOTP is active
      const noCsrfRes = await fetch(`${baseUrl}/api/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: cookie1 },
        body: JSON.stringify({ name: 'Missing CSRF' }),
      });
      assert.equal(noCsrfRes.status, 403);

      // Lock session -> protected routes return 401 TOTP_REQUIRED; /api/health & /api/totp/status stay open
      const lockRes = await fetch(`${baseUrl}/api/totp/lock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: cookie1, 'x-csrf-token': jar1.winhood_csrf! },
      });
      assert.equal(lockRes.status, 200);

      const lockedProjectsRes = await fetch(`${baseUrl}/api/projects`);
      assert.equal(lockedProjectsRes.status, 401);
      const lockedBody = (await lockedProjectsRes.json()) as { code: string };
      assert.equal(lockedBody.code, 'TOTP_LOCKED');

      const aliasStatusRes = await fetch(`${baseUrl}/api/security/totp/status`);
      assert.equal(aliasStatusRes.status, 200);
      const aliasStatus = (await aliasStatusRes.json()) as { enabled: boolean; unlocked: boolean };
      assert.equal(aliasStatus.enabled, true);
      assert.equal(aliasStatus.unlocked, false);

      // Unlock via hosted preview iframe headers emits SameSite=None; Secure; Partitioned & X-WinHood-Session-Token
      const iframeUnlockRes = await fetch(`${baseUrl}/api/security/totp/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-forwarded-host': 'ais-dev-preview.us-east1.run.app',
          'x-forwarded-proto': 'https',
          'sec-fetch-site': 'same-origin',
          'sec-fetch-dest': 'empty',
        },
        body: JSON.stringify({ recoveryCode: setupJson.recoveryCodes[0] }),
      });
      assert.equal(iframeUnlockRes.status, 200);
      const iframeCookies = iframeUnlockRes.headers.getSetCookie?.() || [];
      assert.ok(
        iframeCookies.some(
          (c) =>
            c.includes('winhood_totp_unlock=') &&
            c.includes('HttpOnly') &&
            c.includes('SameSite=None; Secure; Partitioned')
        ),
        'Hosted preview TOTP unlock must emit SameSite=None; Secure; Partitioned cookie'
      );
      const headerUnlockToken = iframeUnlockRes.headers.get('x-winhood-session-token') || '';
      assert.ok(headerUnlockToken.length >= 32);

      // Bearer unlock token works on protected routes without cookies
      const jar2 = extractSetCookieValues(iframeUnlockRes);
      const authHeaders = {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${headerUnlockToken}`,
        'x-csrf-token': jar2.winhood_csrf || '',
      };

      // 8. Key rotation re-encrypts BOTH saved Sonar tokens AND TOTP encrypted secret
      const rawSonarToken = 'squ_winhood_rotation_test_token_2026';
      const saveSonarProjRes = await fetch(`${baseUrl}/api/sonar/saved-projects`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({
          name: 'Rotate Test Sonar',
          platform: 'SONARCLOUD',
          serverUrl: 'https://sonarcloud.io',
          organization: 'winhood-sec',
          projectKey: 'winhood-rotate-test',
          token: rawSonarToken,
        }),
      });
      assert.equal(saveSonarProjRes.status, 200);
      const beforeCipher = getDb().savedSonarProjects?.find(
        (p) => p.projectKey === 'winhood-rotate-test'
      )?.encryptedToken;
      assert.ok(beforeCipher);

      const totpConfigPath = path.join(tmpDir, 'totp_config.json');
      const totpCipherBefore = JSON.parse(fs.readFileSync(totpConfigPath, 'utf8')).encryptedSecret as string;

      const rotateAesRes = await fetch(`${baseUrl}/api/security/keys/rotate`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ purpose: 'TOKEN_VAULT_AES256' }),
      });
      assert.equal(rotateAesRes.status, 200);
      const rotateAesJson = (await rotateAesRes.json()) as {
        rotated: boolean;
        newKeyId: string;
        reencryptedTokensCount: number;
      };
      assert.equal(rotateAesJson.rotated, true);
      assert.ok(rotateAesJson.reencryptedTokensCount >= 2);

      const afterCipher = getDb().savedSonarProjects?.find(
        (p) => p.projectKey === 'winhood-rotate-test'
      )?.encryptedToken;
      assert.ok(afterCipher);
      assert.notEqual(afterCipher, beforeCipher);
      assert.ok(afterCipher.startsWith(`${rotateAesJson.newKeyId}:`));
      assert.equal(MqrBridgeConnection.decryptToken(afterCipher), rawSonarToken);

      const totpCipherAfter = JSON.parse(fs.readFileSync(totpConfigPath, 'utf8')).encryptedSecret as string;
      assert.notEqual(totpCipherAfter, totpCipherBefore);
      assert.ok(totpCipherAfter.startsWith(`whvault:v1:${rotateAesJson.newKeyId}:`));

      const rotateEdRes = await fetch(`${baseUrl}/api/security/keys/rotate`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ purpose: 'EVIDENCE_ED25519' }),
      });
      assert.equal(rotateEdRes.status, 200);
      const rotateEdJson = (await rotateEdRes.json()) as {
        rotated: boolean;
        purpose: string;
        keys: { activeEd25519KeyId: string };
      };
      assert.equal(rotateEdJson.purpose, 'EVIDENCE_ED25519');
      assert.ok(rotateEdJson.keys.activeEd25519KeyId);

      // 9. Disable Optional TOTP with valid recovery code -> restores immediate unrestricted access
      const disableRes = await fetch(`${baseUrl}/api/totp/disable`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ recoveryCode: setupJson.recoveryCodes[1] }),
      });
      assert.equal(disableRes.status, 200);
      const afterDisableProjects = await fetch(`${baseUrl}/api/projects`);
      assert.equal(afterDisableProjects.status, 200);

      // 10. Global 2MB JSON limit blocks oversized payload (413)
      const hugePayload = JSON.stringify({ code: 'x'.repeat(2_300_000) });
      const oversizedRes = await fetch(`${baseUrl}/api/totp/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: hugePayload,
      });
      assert.equal(oversizedRes.status, 413, 'Routes must reject >2MB JSON payloads');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test('SsrfGuard blocks IPv4 private/metadata, IPv6 loopback/mapped/link-local, DNS rebinding and HTTP redirects to internal targets', async () => {
  const blockedUrls = [
    'http://127.0.0.1:8080/health',
    'http://10.0.0.1/internal',
    'http://172.16.0.1/internal',
    'http://192.168.1.1/admin',
    'http://169.254.169.254/latest/meta-data',
    'http://[::1]:3000/',
    'http://[::ffff:127.0.0.1]:3000/',
    'http://[fe80::1]/',
  ];

  for (const url of blockedUrls) {
    const check = await SsrfGuard.validateUrl({ targetUrl: url });
    assert.equal(check.allowed, false, `Expected SSRF block for ${url}`);
  }

  // DNS rebinding to RFC1918 blocked
  const rebindCheck = await SsrfGuard.validateUrl({
    targetUrl: 'https://evil-rebind.example.com/api',
    dnsResolver: async () => [{ address: '10.0.0.5', family: 4 }],
  });
  assert.equal(rebindCheck.allowed, false);

  // Explicit loopback allowed only when flag is set
  const allowedLoopback = await SsrfGuard.validateUrl({
    targetUrl: 'http://127.0.0.1:3000/api/health',
    allowExplicitLoopback: true,
  });
  assert.equal(allowedLoopback.allowed, true);

  // Redirect hop to metadata URL blocked by pinnedSafeRequest
  const redirectServer = http.createServer((_req, res) => {
    res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
    res.end();
  });
  await new Promise<void>((resolve) => redirectServer.listen(0, '127.0.0.1', resolve));
  const rPort = (redirectServer.address() as AddressInfo).port;
  try {
    await assert.rejects(
      async () => {
        await SsrfGuard.pinnedSafeRequest({
          targetUrl: `http://127.0.0.1:${rPort}/start`,
          allowExplicitLoopback: true,
        });
      },
      /SSRF_BLOCKED/
    );
  } finally {
    await new Promise<void>((resolve) => redirectServer.close(() => resolve()));
  }
});

test('SandboxExecutor blocks host /etc/passwd reads under --permission, verifies cleanup recovery, and enforces timeout', () => {
  // 1. Confined read outside temp dir blocked by Node Permission Model
  const escapeAttempt = SandboxExecutor.runSandboxedNodeTestWithRecovery({
    filesMap: {
      'escape.test.mjs': [
        'import test from "node:test";',
        'import fs from "node:fs";',
        'test("cannot read host passwd", () => {',
        '  fs.readFileSync("/etc/passwd", "utf8");',
        '});',
      ].join('\n'),
    },
    testFiles: ['escape.test.mjs'],
    timeoutMs: 8000,
  });
  assert.equal(escapeAttempt.recoveryVerified, true);
  assert.equal(escapeAttempt.isolationState, 'RECOVERY_VERIFIED');
  if (escapeAttempt.isolationMode === 'NODE_PERMISSION_SUBPROCESS') {
    assert.notEqual(escapeAttempt.exitCode, 0);
    assert.match(`${escapeAttempt.stdout}\n${escapeAttempt.stderr}`, /ERR_ACCESS_DENIED|AccessDenied/i);
  }

  // 2. Valid isolated TAP suite runs cleanly with verified temp dir removal
  const validRun = SandboxExecutor.runSandboxedNodeTestWithRecovery({
    filesMap: {
      'sum.mjs': 'export const sum = (a, b) => a + b;\n',
      'sum.test.mjs':
        'import test from "node:test"; import assert from "node:assert/strict"; import { sum } from "./sum.mjs"; test("sum", () => assert.equal(sum(4, 6), 10));\n',
    },
    testFiles: ['sum.test.mjs'],
    timeoutMs: 10000,
  });
  assert.equal(validRun.executed, true);
  assert.equal(validRun.exitCode, 0);
  assert.equal(validRun.recoveryVerified, true);
  assert.equal(validRun.isolationState, 'RECOVERY_VERIFIED');

  // 3. Infinite loop test terminated cleanly on timeout
  const timeoutRun = SandboxExecutor.runSandboxedNodeTestWithRecovery({
    filesMap: {
      'hang.test.mjs': 'while (true) {}\n',
    },
    testFiles: ['hang.test.mjs'],
    timeoutMs: 1000,
  });
  assert.equal(timeoutRun.executed, false);
  assert.equal(timeoutRun.recoveryVerified, true);
  assert.match(timeoutRun.stderr, /Timeout/i);
});

test('PersistentDatabaseManager writes checksum sidecars, detects corruption, and auto-recovers from .bak', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-db-test-'));
  try {
    const dbPath = path.join(tmpDir, 'winhood_persistent_db.json');
    const mgr = new PersistentDatabaseManager();

    mgr.writeAtomicChecksummed(dbPath, { step: 1, projects: ['alpha'] });
    mgr.writeAtomicChecksummed(dbPath, { step: 2, projects: ['alpha', 'beta'] });
    assert.ok(fs.existsSync(`${dbPath}.sha256`));
    assert.ok(fs.existsSync(`${dbPath}.bak`));

    // Corrupt primary JSON
    fs.writeFileSync(dbPath, '{ corrupted json !!!', 'utf8');
    const recovered = mgr.readWithChecksumRecovery<{ step: number; projects: string[] }>(dbPath);
    assert.equal(recovered.recoveredFromBackup, true);
    assert.equal(recovered.integrityStatus, 'RECOVERED_FROM_BACKUP');
    assert.equal(recovered.data?.step, 1);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('KeyManagementService detects keystore checksum tampering and evidenceProvenanceEngine tracks SIGNED -> VERIFIED -> TAMPERED states with Ed25519', async () => {
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const keystorePath = path.join(tmpDir, 'keys', 'keystore.json');
    const status = KeyManagementService.getStatus(keystorePath);
    assert.equal(status.integrityVerified, true);
    assert.ok(status.activeEd25519KeyId);

    const manifest = signEvidenceManifestHmacSha256({
      runId: 'run-ed-01',
      algorithmVersion: 'WINHOOD-SONAR-MQR-v3.0.0',
      evidenceChain: [
        {
          id: 'ev-0',
          runId: 'run-ed-01',
          softwareId: 'sw-1',
          softwareName: 'AppOne',
          version: '1.0.0',
          commitHash: 'abc',
          sourceHash: 'def',
          criterionId: 'TEST',
          evidenceType: 'VERACITY_ATTESTATION',
          origin: 'USER_SOURCE',
          responsibleActor: 'test',
          category: 'VERACITY',
          toolName: 'TestTool',
          toolVersion: '1.0.0',
          timestamp: new Date().toISOString(),
          resultSummary: 'OK',
          severity: 'INFO',
          fileOrComponent: 'src/a.ts',
          validationStatus: 'SUCCESS_VALIDATED',
          sha256: crypto.createHash('sha256').update('ev-0').digest('hex'),
          rawPayloadPreview: 'ok',
          immutableIndex: 0,
          previousRecordSha256: GENESIS_EVIDENCE_HASH,
        },
      ],
    });
    assert.equal(manifest.verified, false);
    assert.equal(manifest.verificationState, 'SIGNED');
    assert.ok(manifest.ed25519Signature);

    const tamperRes = verifyEvidenceChainAndManifest([], manifest);
    assert.equal(tamperRes.valid, false);
    assert.equal(tamperRes.verificationState, 'TAMPERED');

    if (fs.existsSync(`${keystorePath}.bak`)) {
      fs.unlinkSync(`${keystorePath}.bak`);
    }
    const rawKs = fs.readFileSync(keystorePath, 'utf8');
    fs.writeFileSync(keystorePath, `${rawKs}\n/* tampered */`, 'utf8');
    assert.throws(() => {
      KeyManagementService.getStatus(keystorePath);
    }, /KEYSTORE_INTEGRITY_VIOLATION/);
  });
});

test('ProjectBackupService blocks Path Traversal & Filesystem Oracle attacks on verifyBackup, restoreBackup, deleteBackup, and createBackup', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-bkp-sec-'));
  try {
    const svc = new ProjectBackupService(tmpDir);
    const now = new Date().toISOString();
    const manifest = svc.createBackup(
      {
        id: 'proj-sec-1',
        name: 'Safe Backup Project',
        description: 'Backup test',
        category: 'SECURITY',
        createdAt: now,
        updatedAt: now,
      } as any,
      [],
      { 'src/index.ts': 'export const ok = true;\n' }
    );

    assert.match(manifest.backupId, /^bkp-\d+-[a-f0-9]{8}$/i);
    assert.equal(svc.listBackups().length, 1);
    assert.equal(svc.verifyBackup(manifest.backupId).valid, true);

    const restored = svc.restoreBackup(manifest.backupId);
    assert.equal(restored.sourceFilesMap['src/index.ts'], 'export const ok = true;\n');

    const maliciousIds = [
      '../etc/passwd',
      '..\\..\\windows\\system32',
      '/etc/passwd',
      `${manifest.backupId}/../other`,
      `${manifest.backupId}\0`,
      '',
      'bkp-123-zzzzzzzz',
      `bkp-${'9'.repeat(130)}-abcd1234`,
    ];

    for (const badId of maliciousIds) {
      assert.throws(() => svc.verifyBackup(badId), /INVALID_BACKUP_ID|PATH_TRAVERSAL_BLOCKED/);
      assert.throws(() => svc.restoreBackup(badId), /INVALID_BACKUP_ID|PATH_TRAVERSAL_BLOCKED/);
      assert.throws(() => svc.deleteBackup(badId), /INVALID_BACKUP_ID|PATH_TRAVERSAL_BLOCKED/);
    }

    assert.throws(
      () =>
        svc.createBackup(
          {
            id: 'proj-sec-2',
            name: 'Traversal Source',
            description: 'Evil paths',
            category: 'SECURITY',
            createdAt: now,
            updatedAt: now,
          } as any,
          [],
          { '../outside.txt': 'pwned' }
        ),
      /PATH_TRAVERSAL_BLOCKED/
    );

    assert.equal(svc.deleteBackup(manifest.backupId), true);
    assert.equal(svc.listBackups().length, 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('CORS canonical allowlist (tssecurity:S8348) and ELECTRON_DESKTOP localhost restriction reject unauthorized origins', async () => {
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const prevRuntimeEnv = process.env.WINHOOD_RUNTIME_ENV;
    const prevAllowedOrigins = process.env.WINHOOD_ALLOWED_ORIGINS;
    process.env.WINHOOD_ALLOWED_ORIGINS = 'https://app.winhood.example';
    delete process.env.WINHOOD_RUNTIME_ENV;

    const { app } = await createWinHoodApp({ dataDir: tmpDir });
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      const allowedRes = await fetch(`${baseUrl}/api/health`, {
        headers: { Origin: 'http://localhost:3000' },
      });
      assert.equal(allowedRes.status, 200);
      assert.equal(allowedRes.headers.get('access-control-allow-origin'), 'http://localhost:3000');

      const blockedOptRes = await fetch(`${baseUrl}/api/health`, {
        method: 'OPTIONS',
        headers: { Origin: 'https://evil-attacker.example' },
      });
      assert.equal(blockedOptRes.status, 403);
      assert.equal(blockedOptRes.headers.get('access-control-allow-origin'), null);

      process.env.WINHOOD_RUNTIME_ENV = 'ELECTRON_DESKTOP';
      const electronAllowed = await fetch(`${baseUrl}/api/health`, {
        headers: { Origin: 'http://127.0.0.1:41234' },
      });
      assert.equal(electronAllowed.status, 200);
      assert.equal(electronAllowed.headers.get('access-control-allow-origin'), 'http://127.0.0.1:41234');

      const electronEvilOpt = await fetch(`${baseUrl}/api/health`, {
        method: 'OPTIONS',
        headers: { Origin: 'https://app.winhood.example' },
      });
      assert.equal(electronEvilOpt.status, 403);
      assert.equal(electronEvilOpt.headers.get('access-control-allow-origin'), null);
    } finally {
      if (prevRuntimeEnv === undefined) delete process.env.WINHOOD_RUNTIME_ENV;
      else process.env.WINHOOD_RUNTIME_ENV = prevRuntimeEnv;
      if (prevAllowedOrigins === undefined) delete process.env.WINHOOD_ALLOWED_ORIGINS;
      else process.env.WINHOOD_ALLOWED_ORIGINS = prevAllowedOrigins;
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test('SandboxExecutor (typescript:S4036) enforces controlled PATH without host writable directory inheritance', () => {
  const prevPath = process.env.PATH;
  const injectedDir = path.join(os.tmpdir(), 'attacker-writable-bin');
  process.env.PATH = `${injectedDir}${path.delimiter}${prevPath || ''}`;

  try {
    const controlledPath = SandboxExecutor.getControlledSafePath();
    assert.equal(controlledPath.includes(injectedDir), false);

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-env-test-'));
    try {
      const env = buildMinimalSandboxEnv(tmpRoot, {
        PATH: injectedDir,
        CUSTOM_SAFE_FLAG: '1',
      });
      assert.equal(env.PATH, controlledPath);
      assert.equal(env.PATH?.includes(injectedDir), false);
      assert.equal(env.CUSTOM_SAFE_FLAG, '1');
      assert.equal(env.HOME, tmpRoot);
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  } finally {
    if (prevPath === undefined) delete process.env.PATH;
    else process.env.PATH = prevPath;
  }
});

test('SonarScannerExecutor (typescript:S2245) generates CSPRNG UUID temp properties file', async () => {
  if (process.platform === 'win32') return;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-scanner-uuid-'));
  try {
    const fakeScanner = path.join(tmpDir, 'fake-scanner.sh');
    fs.writeFileSync(fakeScanner, '#!/bin/sh\necho "ARG=$1"\n', { mode: 0o755 });

    const res = await SonarScannerExecutor.executeIsolatedScanner({
      scannerType: 'SONAR_SCANNER_CLI',
      executablePath: fakeScanner,
      projectBaseDir: tmpDir,
      propertiesContent: 'sonar.projectKey=test-uuid\n',
      timeoutMs: 5000,
    });

    assert.equal(res.executed, true);
    assert.match(
      res.stdout,
      /\.winhood-sonar-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.properties/i
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Outbound HTTP clients (MqrBridgeConnection, MqrBridgeApiClient, GitarApiClient) block SSRF metadata & private IPs', async () => {
  const probeMetadata = await MqrBridgeConnection.probeMqrBridge({
    serverUrl: 'http://169.254.169.254/latest/meta-data',
    mode: 'DOCKER',
    timeoutMs: 1500,
  });
  assert.equal(probeMetadata.httpReachable, false);
  assert.match(probeMetadata.errorMessage || '', /SSRF/i);

  const sonarClient = new MqrBridgeApiClient({
    serverUrl: 'http://10.0.0.5:9000',
    timeoutMs: 1500,
  });
  const sonarProjectRes = await sonarClient.createProject('demo', 'Demo');
  assert.equal(sonarProjectRes.ok, false);
  assert.equal(sonarProjectRes.status, 403);
  assert.match(sonarProjectRes.error || '', /SSRF_BLOCKED/i);

  const gitarClient = new GitarApiClient('http://169.254.169.254', 'dummy-token');
  const gitarRes = await gitarClient.listOnboardedRepositories();
  assert.equal(gitarRes.ok, false);
  assert.equal(gitarRes.status, 403);
  assert.match(gitarRes.error || '', /SSRF_BLOCKED/i);
});

test('Upload, GitHub import orphan prevention, and ingestion/analysis rate limiting (429 RATE_LIMITED)', async () => {
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const { app, getDb } = await createWinHoodApp({
      dataDir: tmpDir,
      rateLimits: {
        ingestionMax: 2,
        analysisMax: 2,
        backupMax: 2,
        windowMs: 60_000,
      },
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      const jsonHeaders = { 'Content-Type': 'application/json' };
      const initialProjectsCount = getDb().projects.length;

      // 1. Invalid upload (traversal) must fail without leaving orphan project
      const badUploadRes = await fetch(`${baseUrl}/api/projects/upload`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify({
          name: 'Orphan Check Upload',
          objective: 'Should not create orphan project',
          filesMap: { '../evil.ts': 'export const bad = 1;' },
        }),
      });
      assert.equal(badUploadRes.status, 400);
      assert.equal(getDb().projects.length, initialProjectsCount);

      // 2. Invalid GitHub import repoFullName/branch must fail without leaving orphan project
      const badGhRes = await fetch(`${baseUrl}/api/github/import`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify({
          repoFullName: 'owner/../evil',
          repoName: 'evil',
          defaultBranch: 'main;rm -rf /',
        }),
      });
      assert.equal(badGhRes.status, 400);
      assert.equal(getDb().projects.length, initialProjectsCount);

      // 3. Third ingestion request in the same bucket hits rate limit (429 RATE_LIMITED)
      const limitedRes = await fetch(`${baseUrl}/api/projects/upload`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify({
          name: 'Third Request',
          objective: 'Hits rate limiter',
          filesMap: { 'src/index.ts': 'export const ok = true;' },
        }),
      });
      assert.equal(limitedRes.status, 429);
      assert.ok(limitedRes.headers.get('retry-after'));
      const limitedJson = (await limitedRes.json()) as { error: string };
      assert.equal(limitedJson.error, 'RATE_LIMITED');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test('enforceVerifiedQualityGateOnRun downgrades tampered evidence chain to INCONCLUSIVE and clears winner', () => {
  const now = new Date().toISOString();
  const filesMap = {
    'src/safe.ts': 'export function add(a: number, b: number): number { return a + b; }\n',
    'coverage/lcov.info': 'TN:\nSF:src/safe.ts\nDA:1,1\nLF:1\nLH:1\nend_of_record\n',
  };
  const inv = buildTechnicalInventory(filesMap, '/isolated/sw-verify-a');
  const swA = {
    id: 'sw-verify-a',
    projectId: 'proj-verify',
    name: 'Verified Alpha',
    vendor: 'WinHood QA',
    description: 'Clean TS module',
    category: 'SECURITY',
    version: '1.0.0',
    languages: ['TypeScript'],
    architecture: 'Modular',
    operatingSystem: 'Linux',
    distributionModel: 'Source',
    licenseType: 'MIT',
    officialUrl: '',
    repositoryUrl: '',
    documentationUrl: '',
    owner: 'QA',
    notes: '',
    sourceType: 'LOCAL_AUTHORIZED' as const,
    commitHash: 'abc1234',
    packageSha256: inv.packageSha256,
    createdAt: now,
    inventory: {
      totalFiles: inv.totalFiles,
      eligibleFiles: inv.eligibleFiles,
      totalLinesOfCode: inv.totalLinesOfCode,
      totalSizeBytes: inv.totalSizeBytes,
      languageBreakdown: inv.languageBreakdown,
      files: inv.files,
      isolatedStoragePath: '/isolated/sw-verify-a',
      verifiedIntegrity: inv.verifiedIntegrity,
    },
    sourceFilesContent: filesMap,
  };

  const run = executeBenchmarkRunOrchestration({
    runId: 'run-qg-verify-1',
    projectId: 'proj-verify',
    projectName: 'QG Verification Test',
    profileName: 'Sonar way',
    softwares: [swA],
    weights: { ...DEFAULT_CATEGORY_WEIGHTS },
    enabledCategories: [...ALL_BENCHMARK_CATEGORIES],
    qualityGateId: 'qg-sonar-way-mqr',
    enablePenaltyCaps: true,
    equivalenceEnvironment: {
      cpuCoresLimit: 4,
      memoryMbLimit: 4096,
      osTarget: 'Linux',
      workloadConcurrency: 50,
      dastFormalAuthorization: false,
      authorizedByOwner: 'QA',
    },
  });

  assert.equal(run.evidenceVerification?.valid, true);
  assert.notEqual(run.qualityGate?.status, 'INCONCLUSIVE');

  if (run.evidenceChain.length > 0) {
    run.evidenceChain[0].resultSummary = 'TAMPERED_RESULT_SUMMARY';
  }
  const guarded = enforceVerifiedQualityGateOnRun(run);
  assert.equal(guarded.evidenceVerification?.valid, false);
  assert.equal(guarded.qualityGate?.status, 'INCONCLUSIVE');
  assert.equal(guarded.winnerSoftwareId, null);
  assert.equal(guarded.qualityGate?.executiveDecision, 'INCONCLUSIVE');
  assert.equal(guarded.scoreCards[0]?.separatedIndicators?.qualityGateDecision, 'INCONCLUSIVE');
});

test('PersistentDatabaseManager.decryptSourceFilesMap throws typed cryptographic errors instead of returning empty object silently', async () => {
  await withIsolatedKeystoreEnv(async () => {
    const original = {
      'src/main.ts': 'export const answer = 42;\n',
      'src/crypto.ts': 'export const alg = "AES-256-GCM";\n',
    };
    const envelope = PersistentDatabaseManager.encryptSourceFilesMap(original);
    assert.ok(envelope.startsWith(PersistentDatabaseManager.ENVELOPE_PREFIX));

    const roundTrip = PersistentDatabaseManager.decryptSourceFilesMap(envelope);
    assert.deepEqual(roundTrip, original);

    const parts = envelope.split(':');
    const lastChar = parts[5].slice(-1) === 'a' ? 'b' : 'a';
    const tamperedAuthTagEnvelope = [...parts.slice(0, 5), parts[5].slice(0, -1) + lastChar, parts[6]].join(':');
    assert.throws(
      () => PersistentDatabaseManager.decryptSourceFilesMap(tamperedAuthTagEnvelope),
      /DECRYPTION_AUTH_FAILED/
    );

    const wrongKey = crypto.randomBytes(32);
    assert.throws(
      () => PersistentDatabaseManager.decryptSourceFilesMap(envelope, wrongKey),
      /DECRYPTION_AUTH_FAILED/
    );

    assert.throws(
      () => PersistentDatabaseManager.decryptSourceFilesMap('whdb:enc:v2:only-two:parts'),
      /DECRYPTION_FORMAT_INVALID/
    );

    assert.throws(
      () => PersistentDatabaseManager.decryptSourceFilesMap('whdb:enc:v99:kid:iv:tag:payload'),
      /DECRYPTION_VERSION_UNSUPPORTED/
    );

    assert.throws(
      () => PersistentDatabaseManager.decryptSourceFilesMap('{corrupted-json'),
      /DECRYPTION_FORMAT_INVALID/
    );
  });
});

test('SandboxExecutor.runSandboxedNodeTest updates recoveryVerified to true and isolationState to RECOVERY_VERIFIED after temp cleanup', async () => {
  const result = await SandboxExecutor.runSandboxedNodeTest({
    filesMap: {
      'index.test.mjs':
        'import test from "node:test"; import assert from "node:assert"; test("math", () => { assert.strictEqual(2 + 2, 4); });\n',
    },
    testFiles: ['index.test.mjs'],
    timeoutMs: 10000,
  });

  assert.equal(result.executed, true);
  assert.equal(result.exitCode, 0);
  assert.equal(result.recoveryVerified, true);
  assert.equal(result.isolationState, 'RECOVERY_VERIFIED');
});

test('Phase 3 P0 Keystore fail-closed in PRODUCTION_SECURE, strict secret domain separation, separated Trust Store, and legacy migration', async () => {
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const storePath = path.join(tmpDir, 'keys', 'keystore.json');
    const prevMode = process.env.WINHOOD_KEYSTORE_MODE;
    const prevMaster = process.env.WINHOOD_KEYSTORE_MASTER_SECRET;
    const prevLegacyMaster = process.env.WINHOOD_MASTER_KEY_SECRET;
    const prevHmac = process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
    const prevVault = process.env.WINHOOD_VAULT_SECRET;
    const prevSonarSalt = process.env.SONAR_SECRET_SALT;
    const prevSimDpapi = process.env.WINHOOD_SIMULATE_DPAPI_UNAVAILABLE;
    const prevSimKeyring = process.env.WINHOOD_SIMULATE_KEYRING_UNAVAILABLE;
    const prevRequireEnv = process.env.WINHOOD_REQUIRE_ENV_SECRETS;

    try {
      process.env.WINHOOD_KEYSTORE_MODE = 'PRODUCTION_SECURE';
      process.env.WINHOOD_SIMULATE_DPAPI_UNAVAILABLE = 'true';
      process.env.WINHOOD_SIMULATE_KEYRING_UNAVAILABLE = 'true';
      delete process.env.WINHOOD_KEYSTORE_MASTER_SECRET;
      delete process.env.WINHOOD_MASTER_KEY_SECRET;

      assert.throws(
        () => KeyManagementService.getStatus(storePath),
        /KEYSTORE_PRODUCTION_PROVIDER_REQUIRED|KEYSTORE_DPAPI_REQUIRED_IN_PRODUCTION/
      );
      assert.equal(fs.existsSync(`${storePath}.kek`), false, '.kek file must never be created in PRODUCTION_SECURE');

      process.env.SONAR_SECRET_SALT = 'shared-secret-value-at-least-16-chars';
      process.env.WINHOOD_KEYSTORE_MASTER_SECRET = 'shared-secret-value-at-least-16-chars';
      assert.throws(
        () => KeyManagementService.assertSecretDomainSeparation(),
        /KEYSTORE_SECRET_DOMAIN_VIOLATION/
      );

      delete process.env.WINHOOD_KEYSTORE_MASTER_SECRET;
      process.env.WINHOOD_REQUIRE_ENV_SECRETS = 'true';
      delete process.env.WINHOOD_VAULT_SECRET;
      assert.throws(
        () => KeyManagementService.getActiveVaultAesKey(storePath),
        /KEY_MANAGEMENT_ENV_SECRET_REQUIRED/
      );
      delete process.env.WINHOOD_REQUIRE_ENV_SECRETS;

      const legacyBuf = KeyManagementService.getVaultKeyBufferByKeyId('ENV-VAULT-KEY', storePath);
      assert.ok(legacyBuf && legacyBuf.length === 32, 'Must derive legacy decrypt-only key from SONAR_SECRET_SALT');
      delete process.env.SONAR_SECRET_SALT;

      process.env.WINHOOD_KEYSTORE_MASTER_SECRET = 'prod-canonical-master-secret-2026-secure!';
      const status = KeyManagementService.getStatus(storePath);
      assert.equal(status.operatingMode, 'PRODUCTION_SECURE');
      assert.equal(status.kekProtectionMechanism, 'HKDF_EXTERNAL_ENV');
      assert.equal(status.trustStoreSeparated, true);
      assert.equal(fs.existsSync(status.trustStorePath), true);

      const { encryptWithAes256GcmEnvelope, decryptWithAes256GcmEnvelope } = await import('./KeyManagementService');
      const testKey = Buffer.alloc(32, 7);
      const env = encryptWithAes256GcmEnvelope('secret-payload', testKey, 'winhood:ctx:a');
      assert.throws(
        () => decryptWithAes256GcmEnvelope(env, testKey, 'winhood:ctx:b'),
        /KEYSTORE_ENVELOPE_AAD_MISMATCH/
      );
      assert.throws(
        () =>
          decryptWithAes256GcmEnvelope(
            { ...env, authTagHex: '00'.repeat(16) },
            testKey,
            'winhood:ctx:a'
          ),
        /KEYSTORE_GCM_AUTH_FAILED/
      );

      const rawTrust = fs.readFileSync(status.trustStorePath, 'utf8');
      const tamperedTrust = JSON.parse(rawTrust);
      tamperedTrust.monotonicSequence = 9999;
      fs.writeFileSync(status.trustStorePath, JSON.stringify(tamperedTrust, null, 2), 'utf8');
      const trustVerifyTampered = KeyManagementService.verifyTrustedEd25519PublicKey(
        status.activeEd25519KeyId,
        undefined,
        undefined,
        storePath
      );
      assert.equal(trustVerifyTampered.trusted, false);
      assert.match(trustVerifyTampered.reason, /TRUST_STORE_INTEGRITY_VIOLATION/);
      fs.writeFileSync(status.trustStorePath, rawTrust, 'utf8');

      const oldEdId = status.activeEd25519KeyId;
      const rotatedEd = KeyManagementService.rotateKey('EVIDENCE_ED25519', storePath);
      assert.notEqual(rotatedEd.keyId, oldEdId);
      const retiredCheck = KeyManagementService.verifyTrustedEd25519PublicKey(oldEdId, undefined, undefined, storePath);
      assert.equal(retiredCheck.trusted, true);
      assert.equal(retiredCheck.status, 'ROTATED_VERIFY_ONLY');

      KeyManagementService.revokeKey(oldEdId, 'Compromised test key', storePath);
      const revokedCheck = KeyManagementService.verifyTrustedEd25519PublicKey(oldEdId, undefined, undefined, storePath);
      assert.equal(revokedCheck.trusted, false);
      assert.equal(revokedCheck.status, 'REVOKED');

      fs.writeFileSync(`${storePath}.seq`, '99999', 'utf8');
      assert.throws(
        () => KeyManagementService.getStatus(storePath),
        /KEYSTORE_ROLLBACK_DETECTED/
      );
    } finally {
      if (prevMode === undefined) delete process.env.WINHOOD_KEYSTORE_MODE;
      else process.env.WINHOOD_KEYSTORE_MODE = prevMode;
      if (prevMaster === undefined) delete process.env.WINHOOD_KEYSTORE_MASTER_SECRET;
      else process.env.WINHOOD_KEYSTORE_MASTER_SECRET = prevMaster;
      if (prevLegacyMaster === undefined) delete process.env.WINHOOD_MASTER_KEY_SECRET;
      else process.env.WINHOOD_MASTER_KEY_SECRET = prevLegacyMaster;
      if (prevHmac === undefined) delete process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
      else process.env.WINHOOD_EVIDENCE_HMAC_SECRET = prevHmac;
      if (prevVault === undefined) delete process.env.WINHOOD_VAULT_SECRET;
      else process.env.WINHOOD_VAULT_SECRET = prevVault;
      if (prevSonarSalt === undefined) delete process.env.SONAR_SECRET_SALT;
      else process.env.SONAR_SECRET_SALT = prevSonarSalt;
      if (prevSimDpapi === undefined) delete process.env.WINHOOD_SIMULATE_DPAPI_UNAVAILABLE;
      else process.env.WINHOOD_SIMULATE_DPAPI_UNAVAILABLE = prevSimDpapi;
      if (prevSimKeyring === undefined) delete process.env.WINHOOD_SIMULATE_KEYRING_UNAVAILABLE;
      else process.env.WINHOOD_SIMULATE_KEYRING_UNAVAILABLE = prevSimKeyring;
      if (prevRequireEnv === undefined) delete process.env.WINHOOD_REQUIRE_ENV_SECRETS;
      else process.env.WINHOOD_REQUIRE_ENV_SECRETS = prevRequireEnv;
    }
  });
});

test('Clean as You Code (NewCodeDiffEngine), ExternalRulesBridge, and SqliteMigrationPlan', async () => {
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const repoDir = path.join(tmpDir, 'git-repo');
    fs.mkdirSync(repoDir, { recursive: true });
    execFileSync('git', ['init', '-b', 'main'], { cwd: repoDir, shell: false });
    execFileSync('git', ['config', 'user.email', 'ci@winhood.local'], { cwd: repoDir, shell: false });
    execFileSync('git', ['config', 'user.name', 'WinHood CI'], { cwd: repoDir, shell: false });
    fs.writeFileSync(path.join(repoDir, 'app.ts'), 'const a = 1;\nconst b = 2;\n', 'utf8');
    execFileSync('git', ['add', 'app.ts'], { cwd: repoDir, shell: false });
    execFileSync('git', ['commit', '-m', 'base commit'], { cwd: repoDir, shell: false });

    execFileSync('git', ['checkout', '-b', 'feature/test'], { cwd: repoDir, shell: false });
    fs.writeFileSync(path.join(repoDir, 'app.ts'), 'const a = 1;\nconst b = 2;\nconst unsafe = eval("1+1");\n', 'utf8');
    execFileSync('git', ['add', 'app.ts'], { cwd: repoDir, shell: false });
    execFileSync('git', ['commit', '-m', 'introduce eval on line 3'], { cwd: repoDir, shell: false });

    const diffMap = computeGitNewCodeDiffMap({ cwd: repoDir, baseRef: 'main', headRef: 'HEAD' });
    assert.ok(diffMap.mergeBaseSha.length >= 7);
    assert.equal(diffMap.totalAddedOrModifiedLines, 1);
    assert.ok(diffMap.changedFiles['app.ts']?.has(3));

    const gateFail = evaluateCleanAsYouCodeGate(
      [
        { filePath: 'app.ts', lineNumber: 1, severity: 'HIGH', ruleId: 'legacy-rule' },
        { filePath: 'app.ts', lineNumber: 3, severity: 'CRITICAL', ruleId: 'new-eval-rule' },
      ],
      diffMap
    );
    assert.equal(gateFail.passed, false);
    assert.equal(gateFail.newCodeFindings.length, 1);
    assert.equal(gateFail.overallOnlyFindings.length, 1);
    assert.equal(gateFail.blockingNewFindings.length, 1);

    const gatePass = evaluateCleanAsYouCodeGate(
      [{ filePath: 'app.ts', lineNumber: 1, severity: 'CRITICAL', ruleId: 'legacy-only' }],
      diffMap
    );
    assert.equal(gatePass.passed, true);

    const sampleSarif = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              rules: [
                {
                  id: 'semgrep.sql-injection',
                  properties: { tags: ['security', 'CWE-89'] },
                },
              ],
            },
          },
          results: [
            {
              ruleId: 'semgrep.sql-injection',
              level: 'error',
              message: { text: 'Unsanitized SQL query' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'src/db.ts' },
                    region: { startLine: 42 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });
    const parsed = parseSarifToNormalizedFindings(sampleSarif, 'semgrep');
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0]?.severity, 'HIGH');
    assert.deepEqual(parsed[0]?.cweIds, ['CWE-89']);
    assert.equal(parsed[0]?.lineNumber, 42);

    assert.throws(
      () =>
        runLocalRulesPack({
          engine: 'bash' as any,
          targetDir: repoDir,
          localRulesConfigPath: path.join(repoDir, 'rules.yml'),
        }),
      /EXTERNAL_ENGINE_FORBIDDEN/
    );
    assert.throws(
      () =>
        runLocalRulesPack({
          engine: 'semgrep',
          targetDir: repoDir,
          localRulesConfigPath: path.join(repoDir, 'missing-rules.yml'),
        }),
      /RULES_CONFIG_NOT_FOUND/
    );

    assert.ok(WINHOOD_SQLITE_SCHEMA_SQL.includes('PRAGMA journal_mode = WAL;'));
    assert.ok(WINHOOD_SQLITE_SCHEMA_SQL.includes('PRAGMA foreign_keys = ON;'));
    assert.ok(WINHOOD_SQLITE_SCHEMA_SQL.includes('CREATE INDEX IF NOT EXISTS idx_runs_project_branch'));
    assert.ok(WINHOOD_SQLITE_SCHEMA_SQL.includes('CREATE INDEX IF NOT EXISTS idx_findings_project_fp'));
    assert.ok(WINHOOD_SQLITE_SCHEMA_SQL.includes('CREATE INDEX IF NOT EXISTS idx_findings_run_sev'));
  });
});

test('Static Bundle & Production Config Audit: zero VITE_ secret exposure, zero legacy OAuth/login artifacts, and TOTP-enabled fail-closed protection', async () => {
  const repoRoot = process.cwd();

  // 1. Ensure .env.example never defines VITE_* secrets or removed GitHub OAuth credentials
  const envExamplePath = path.join(repoRoot, '.env.example');
  const envExampleContent = fs.readFileSync(envExamplePath, 'utf8');
  assert.equal(
    /^\s*VITE_.*(SECRET|TOKEN|CLIENT_SECRET|OAUTH_CLIENT_SECRET)/im.test(envExampleContent),
    false,
    '.env.example must never define VITE_* secret/token variables'
  );
  assert.equal(
    /WINHOOD_GITHUB_OAUTH_/i.test(envExampleContent),
    false,
    '.env.example must not define removed GitHub OAuth login variables'
  );

  // 2. Verify legacy auth/OAuth modules are physically removed
  const removedFiles = [
    'src/security/AuthService.ts',
    'src/security/GitHubOAuthTransactionStore.ts',
    'src/security/ZeroFrictionAuthConfig.ts',
    'src/components/AuthGateModal.tsx',
    'src/components/GitHubOAuthAdminPanel.tsx',
  ];
  for (const rel of removedFiles) {
    assert.equal(fs.existsSync(path.join(repoRoot, rel)), false, `Legacy module ${rel} must not exist`);
  }

  // 3. Scan frontend source directories for forbidden secret patterns
  const clientDirs = [path.join(repoRoot, 'src', 'components'), path.join(repoRoot, 'src', 'shared')];
  const clientFiles: string[] = [
    path.join(repoRoot, 'src', 'App.tsx'),
    path.join(repoRoot, 'src', 'main.tsx'),
    path.join(repoRoot, 'index.html'),
  ];
  const collectTsFiles = (dir: string) => {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) collectTsFiles(full);
      else if (/\.(ts|tsx|js|jsx|mjs)$/.test(entry.name) && !entry.name.endsWith('.test.ts')) {
        clientFiles.push(full);
      }
    }
  };
  for (const d of clientDirs) collectTsFiles(d);

  const forbiddenClientPatterns = [
    /VITE_.*CLIENT_SECRET/,
    /import\.meta\.env\.VITE_.*SECRET/,
    /github\.com\/login\/oauth\/access_token/,
  ];
  for (const file of clientFiles) {
    if (!fs.existsSync(file)) continue;
    const content = fs.readFileSync(file, 'utf8');
    for (const pattern of forbiddenClientPatterns) {
      assert.equal(
        pattern.test(content),
        false,
        `Client file ${path.relative(repoRoot, file)} matched forbidden secret pattern ${pattern}`
      );
    }
  }

  // 4. Inspect compiled frontend bundle (dist/assets/*.js) when present for leaked secrets
  const distAssetsDir = path.join(repoRoot, 'dist', 'assets');
  if (fs.existsSync(distAssetsDir)) {
    const jsBundles = fs.readdirSync(distAssetsDir).filter((f) => f.endsWith('.js'));
    assert.ok(jsBundles.length > 0, 'dist/assets must contain compiled JS bundles when dist exists');
    for (const bundle of jsBundles) {
      const bundleContent = fs.readFileSync(path.join(distAssetsDir, bundle), 'utf8');
      assert.equal(
        bundleContent.includes('github.com/login/oauth/access_token'),
        false,
        `Compiled bundle ${bundle} must never contain GitHub token exchange endpoint`
      );
      assert.equal(
        bundleContent.includes('WINHOOD_KEYSTORE_MASTER_SECRET'),
        false,
        `Compiled bundle ${bundle} must never reference server keystore master secret`
      );
    }
  }

  // 5. Fail-closed verification: when Optional TOTP is enabled, locked requests to /api/projects receive 401 TOTP_REQUIRED
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const { app, totpService } = await createWinHoodApp({ dataDir: tmpDir });
    const setup = totpService.beginSetup();
    totpService.confirmSetup(generateTotpCode(setup.secret));
    totpService.lock();

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;
    try {
      const lockedProjects = await fetch(`${baseUrl}/api/projects`);
      assert.equal(lockedProjects.status, 401);
      const body = (await lockedProjects.json()) as { code: string };
      assert.equal(body.code, 'TOTP_LOCKED');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test('WH-AUD-002: GitarInstallationHealth blocks SSRF targets (169.254.169.254, 10.0.0.1) and HTTP 302 redirects without leaking Bearer tokens', async () => {
  // 1. Cloud metadata IP must be blocked before any network request
  const metaRes = await GitarInstallationHealth.checkInstallationHealth({
    apiBaseUrl: 'http://169.254.169.254',
    token: 'gitar_secret_bearer_token_must_not_leak',
    provider: 'GITHUB',
    explicitConsent: true,
  });
  assert.equal(metaRes.healthy, false);
  assert.equal(metaRes.state, 'PROVIDER_UNAVAILABLE');
  assert.ok(
    metaRes.message.startsWith('SSRF_BLOCKED:'),
    `Expected SSRF_BLOCKED message for 169.254.169.254, got: ${metaRes.message}`
  );

  // 2. Private RFC1918 IP (10.0.0.1) must be blocked before any network request
  const rfc1918Res = await GitarInstallationHealth.checkInstallationHealth({
    apiBaseUrl: 'http://10.0.0.1',
    token: 'gitar_secret_bearer_token_must_not_leak',
    provider: 'GITHUB',
    explicitConsent: true,
  });
  assert.equal(rfc1918Res.healthy, false);
  assert.equal(rfc1918Res.state, 'PROVIDER_UNAVAILABLE');
  assert.ok(
    rfc1918Res.message.startsWith('SSRF_BLOCKED:'),
    `Expected SSRF_BLOCKED message for 10.0.0.1, got: ${rfc1918Res.message}`
  );

  // 3. HTTP 302 redirect on loopback endpoint must be rejected with SSRF_REDIRECT_BLOCKED
  let receivedAuthHeader: string | undefined;
  let redirectTargetHit = false;
  const targetSrv = http.createServer((_req, res) => {
    redirectTargetHit = true;
    res.statusCode = 200;
    res.end('should never be reached');
  });
  await new Promise<void>((resolve) => targetSrv.listen(0, '127.0.0.1', () => resolve()));
  const targetPort = (targetSrv.address() as AddressInfo).port;

  let respondMode: 'REDIRECT' | 'OK' = 'REDIRECT';
  const proxySrv = http.createServer((req, res) => {
    receivedAuthHeader = req.headers.authorization;
    if (respondMode === 'REDIRECT') {
      res.statusCode = 302;
      res.setHeader('Location', `http://127.0.0.1:${targetPort}/steal`);
      res.end();
      return;
    }
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ status: 'ok' }));
  });
  await new Promise<void>((resolve) => proxySrv.listen(0, '127.0.0.1', () => resolve()));
  const proxyPort = (proxySrv.address() as AddressInfo).port;

  try {
    const redirectRes = await GitarInstallationHealth.checkInstallationHealth({
      apiBaseUrl: `http://127.0.0.1:${proxyPort}`,
      token: 'gitar_test_loopback_token',
      provider: 'GITHUB',
      explicitConsent: true,
    });
    assert.equal(redirectRes.healthy, false);
    assert.equal(redirectRes.state, 'PROVIDER_UNAVAILABLE');
    assert.ok(
      redirectRes.message.startsWith('SSRF_REDIRECT_BLOCKED:'),
      `Expected SSRF_REDIRECT_BLOCKED on HTTP 302, got: ${redirectRes.message}`
    );
    assert.equal(redirectTargetHit, false, 'Redirect target must never be contacted');

    // 4. Legitimate loopback 200 OK still connects cleanly
    respondMode = 'OK';
    const okRes = await GitarInstallationHealth.checkInstallationHealth({
      apiBaseUrl: `http://127.0.0.1:${proxyPort}`,
      token: 'gitar_test_loopback_token',
      provider: 'GITHUB',
      explicitConsent: true,
    });
    assert.equal(okRes.healthy, true);
    assert.equal(okRes.state, 'CONNECTED');
    assert.equal(receivedAuthHeader, 'Bearer gitar_test_loopback_token');
  } finally {
    await new Promise<void>((resolve) => proxySrv.close(() => resolve()));
    await new Promise<void>((resolve) => targetSrv.close(() => resolve()));
  }
});

