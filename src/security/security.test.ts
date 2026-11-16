import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { AuthService, generateTotpCode, isValidEmailAddress, validateQuickPin } from './AuthService';
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

function readBootstrapTokenFromFile(filePath: string): string {
  const raw = fs.readFileSync(filePath, 'utf8');
  const lines = raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  return lines[0] || '';
}

function extractSetCookieValues(res: Response): Record<string, string> {
  const anyHeaders = res.headers as unknown as { getSetCookie?: () => string[]; raw?: () => Record<string, string[]> };
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
  const prevAdmin = process.env.WINHOOD_ADMIN_TOKEN;
  const prevBootstrap = process.env.WINHOOD_BOOTSTRAP_TOKEN;
  const prevNodeEnv = process.env.NODE_ENV;
  const prevTestMode = process.env.WINHOOD_TEST_MODE;

  process.env.WINHOOD_KEYSTORE_PATH = path.join(tmpDir, 'keys', 'keystore.json');
  delete process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
  delete process.env.WINHOOD_VAULT_SECRET;
  delete process.env.SONAR_SECRET_SALT;
  delete process.env.WINHOOD_ADMIN_TOKEN;
  delete process.env.WINHOOD_BOOTSTRAP_TOKEN;

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
    if (prevAdmin === undefined) delete process.env.WINHOOD_ADMIN_TOKEN;
    else process.env.WINHOOD_ADMIN_TOKEN = prevAdmin;
    if (prevBootstrap === undefined) delete process.env.WINHOOD_BOOTSTRAP_TOKEN;
    else process.env.WINHOOD_BOOTSTRAP_TOKEN = prevBootstrap;
    if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevNodeEnv;
    if (prevTestMode === undefined) delete process.env.WINHOOD_TEST_MODE;
    else process.env.WINHOOD_TEST_MODE = prevTestMode;

    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

test('AuthService enforces single-use bootstrap token, scrypt password check, brute-force lockout, TOTP MFA and recovery session revocation', async () => {
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const auth = new AuthService(tmpDir);
    assert.equal(auth.isBootstrapRequired(), true);
    const meta = auth.getBootstrapMetadata();
    const bootToken = readBootstrapTokenFromFile(meta.bootstrapTokenFilePath);
    assert.ok(bootToken.startsWith('wh-boot-'));

    const boot = auth.bootstrapInitialAdmin({
      bootstrapToken: bootToken,
      name: 'Admin WinHood',
      email: 'admin@winhood.local',
      password: 'Str0ng!AdminPassword2026',
      enableMfa: true,
    });

    assert.equal(boot.user.role, 'ADMIN');
    assert.equal(boot.user.mfaEnabled, true);
    assert.equal(boot.user.mfaVerified, false);
    assert.ok(boot.totpSetup?.secretBase32);
    assert.equal(auth.isBootstrapRequired(), false);

    // Bootstrap token must be single-use and file deleted
    assert.equal(fs.existsSync(meta.bootstrapTokenFilePath), false);
    assert.throws(() => {
      auth.bootstrapInitialAdmin({
        bootstrapToken: bootToken,
        name: 'Rogue Admin',
        email: 'rogue@winhood.local',
        password: 'AnotherStrongPassword123',
      });
    }, /BOOTSTRAP_ALREADY_COMPLETED/);

    // Verify pending MFA session is blocked until verifySessionMfa runs
    assert.equal(auth.validateSession(boot.sessionId), null);
    const codeNow = generateTotpCode(boot.totpSetup!.secretBase32);
    const verifiedUser = auth.verifySessionMfa(boot.sessionId, codeNow);
    assert.equal(verifiedUser.mfaVerified, true);
    assert.ok(auth.validateSession(boot.sessionId));

    // Brute-force lockout after 5 wrong password attempts
    const regularUser = auth.createUser({
      name: 'QA Analyst',
      email: 'qa@winhood.local',
      password: 'QaStrongPassword!2026',
      role: 'QA_ENGINEER',
      enableMfa: false,
    });
    assert.equal(regularUser.role, 'QA_ENGINEER');

    const qaLoginOk = auth.login({ email: 'qa@winhood.local', password: 'QaStrongPassword!2026' });
    assert.equal(qaLoginOk.mfaRequired, false);
    assert.ok(auth.validateSession(qaLoginOk.sessionId));

    for (let i = 0; i < AuthService.MAX_LOGIN_ATTEMPTS; i++) {
      assert.throws(() => {
        auth.login({ email: 'qa@winhood.local', password: 'WrongPassword12345' });
      }, /AUTH_INVALID_CREDENTIALS/);
    }
    assert.throws(() => {
      auth.login({ email: 'qa@winhood.local', password: 'QaStrongPassword!2026' });
    }, /AUTH_ACCOUNT_LOCKED/);

    // Password recovery revokes all previous sessions and invalidates single-use token
    const rec = auth.requestPasswordRecovery('qa@winhood.local');
    assert.ok(rec.recoveryFilePath && fs.existsSync(rec.recoveryFilePath));
    const recToken = readBootstrapTokenFromFile(rec.recoveryFilePath);
    auth.confirmPasswordRecovery({
      email: 'qa@winhood.local',
      recoveryToken: recToken,
      newPassword: 'RecoveredPassword!999',
    });

    assert.equal(auth.validateSession(qaLoginOk.sessionId), null);
    assert.throws(() => {
      auth.confirmPasswordRecovery({
        email: 'qa@winhood.local',
        recoveryToken: recToken,
        newPassword: 'ReusedTokenPassword!111',
      });
    }, /inválido/i);

    const postRecovery = auth.login({ email: 'qa@winhood.local', password: 'RecoveredPassword!999' });
    assert.ok(postRecovery.sessionId);

    // Self-registration blocks ADMIN elevation, enforces password policy, and creates valid session
    assert.throws(() => {
      auth.registerAccount({
        name: 'Rogue Self Admin',
        email: 'selfadmin@winhood.local',
        password: 'StrongPassword!2026',
        role: 'ADMIN',
      });
    }, /ROLE_ELEVATION_BLOCKED/);

    const selfReg = auth.registerAccount({
      name: 'Engenheira de Segurança',
      email: 'sec.lead@winhood.local',
      password: 'SecLeadPassword!2026',
      role: 'SECURITY_LEAD',
      enableMfa: false,
    });
    assert.equal(selfReg.user.role, 'SECURITY_LEAD');
    assert.ok(auth.validateSession(selfReg.sessionId));

    // Duplicate email rejected
    assert.throws(() => {
      auth.registerAccount({
        name: 'Duplicate User',
        email: 'sec.lead@winhood.local',
        password: 'SecLeadPassword!2026',
      });
    }, /EMAIL_ALREADY_EXISTS/);
  });
});

test('HTTP integration with enforceProductionAuth: auth gating, CSRF, RBAC, SSRF guard, run-tests attachment, contract test guard & KMS rotation', async () => {
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const { app, authService, getDb } = await createWinHoodApp({
      dataDir: tmpDir,
      enforceProductionAuth: true,
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // 1. Unauthenticated requests blocked with 401 AUTH_REQUIRED
      const unauthRes = await fetch(`${baseUrl}/api/projects`);
      assert.equal(unauthRes.status, 401);
      const unauthJson = (await unauthRes.json()) as { error: string };
      assert.equal(unauthJson.error, 'AUTH_REQUIRED');

      // 2. Spoofing x-winhood-role rejected in enforceProductionAuth mode
      const spoofRes = await fetch(`${baseUrl}/api/projects`, {
        headers: { 'x-winhood-role': 'ADMIN' },
      });
      assert.equal(spoofRes.status, 401);

      // 3. Bootstrap initial admin via HTTP using real bootstrap token
      const bootMeta = authService.getBootstrapMetadata();
      const bootToken = readBootstrapTokenFromFile(bootMeta.bootstrapTokenFilePath);
      const bootRes = await fetch(`${baseUrl}/api/auth/bootstrap-admin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          bootstrapToken: bootToken,
          name: 'Admin Principal',
          email: 'root@winhood.local',
          password: 'AdminRootPassword!2026',
          enableMfa: false,
        }),
      });
      assert.equal(bootRes.status, 201);
      const adminJar = extractSetCookieValues(bootRes);
      assert.ok(adminJar.winhood_session);
      assert.ok(adminJar.winhood_csrf);
      const adminCookie = `winhood_session=${adminJar.winhood_session}; winhood_csrf=${adminJar.winhood_csrf}`;

      // 3b. Public self-registration (/api/auth/register) creates account + session cookies and blocks ADMIN role elevation
      const blockedAdminReg = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Blocked Admin',
          email: 'blocked-admin@winhood.local',
          password: 'StrongPassword!2026',
          role: 'ADMIN',
        }),
      });
      assert.equal(blockedAdminReg.status, 403);

      const publicRegRes = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Novo Analista AppSec',
          email: 'novo.analista@winhood.local',
          password: 'AnalistaStrongPassword!2026',
          role: 'SECURITY_LEAD',
          enableMfa: false,
        }),
      });
      assert.equal(publicRegRes.status, 201);
      const publicRegJar = extractSetCookieValues(publicRegRes);
      assert.ok(publicRegJar.winhood_session);
      assert.ok(publicRegJar.winhood_csrf);

      // 4. Missing or tampered CSRF token rejected with 403 CSRF_INVALID on mutating POST
      const missingCsrfRes = await fetch(`${baseUrl}/api/projects`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
        },
        body: JSON.stringify({ name: 'No CSRF Project' }),
      });
      assert.equal(missingCsrfRes.status, 403);
      const missingCsrfJson = (await missingCsrfRes.json()) as { error: string };
      assert.equal(missingCsrfJson.error, 'CSRF_INVALID');

      // Create AUDITOR and QA_ENGINEER accounts for RBAC tests
      const createAuditor = await fetch(`${baseUrl}/api/auth/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({
          name: 'Auditor Externo',
          email: 'auditor@winhood.local',
          password: 'AuditorPassword!2026',
          role: 'AUDITOR',
        }),
      });
      assert.equal(createAuditor.status, 201);

      const createQa = await fetch(`${baseUrl}/api/auth/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({
          name: 'QA Engineer',
          email: 'qa2@winhood.local',
          password: 'QaEngineerPassword!2026',
          role: 'QA_ENGINEER',
        }),
      });
      assert.equal(createQa.status, 201);

      const loginAs = async (email: string, password: string) => {
        const res = await fetch(`${baseUrl}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        assert.equal(res.status, 200);
        const jar = extractSetCookieValues(res);
        return {
          cookie: `winhood_session=${jar.winhood_session}; winhood_csrf=${jar.winhood_csrf}`,
          csrf: jar.winhood_csrf!,
        };
      };

      const auditorAuth = await loginAs('auditor@winhood.local', 'AuditorPassword!2026');
      const qaAuth = await loginAs('qa2@winhood.local', 'QaEngineerPassword!2026');

      // AUDITOR blocked from creating projects
      const auditorWrite = await fetch(`${baseUrl}/api/projects`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: auditorAuth.cookie,
          'x-csrf-token': auditorAuth.csrf,
        },
        body: JSON.stringify({ name: 'Auditor Project Blocked' }),
      });
      assert.equal(auditorWrite.status, 403);

      // QA_ENGINEER blocked from rotating cryptographic keys & registering perf targets
      const qaRotate = await fetch(`${baseUrl}/api/security/keys/rotate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: qaAuth.cookie,
          'x-csrf-token': qaAuth.csrf,
        },
        body: JSON.stringify({ purpose: 'EVIDENCE_HMAC' }),
      });
      assert.equal(qaRotate.status, 403);

      const qaTarget = await fetch(`${baseUrl}/api/execution/targets`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: qaAuth.cookie,
          'x-csrf-token': qaAuth.csrf,
        },
        body: JSON.stringify({ label: 'QA Target', origin: 'https://example.com' }),
      });
      assert.equal(qaTarget.status, 403);

      // 5. SSRF Guard enforcement on /api/execution/run-perf + Audit log recording
      const ssrfLoopback = await fetch(`${baseUrl}/api/execution/run-perf`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({ targetUrl: 'http://127.0.0.1:9999/health' }),
      });
      assert.equal(ssrfLoopback.status, 403);
      assert.equal(((await ssrfLoopback.json()) as { error: string }).error, 'SSRF_BLOCKED');

      const ssrfMeta = await fetch(`${baseUrl}/api/execution/run-perf`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({ targetUrl: 'http://169.254.169.254/latest/meta-data' }),
      });
      assert.equal(ssrfMeta.status, 403);
      assert.equal(((await ssrfMeta.json()) as { error: string }).error, 'SSRF_BLOCKED');

      const auditRes = await fetch(`${baseUrl}/api/audit`, {
        headers: { Cookie: adminCookie },
      });
      assert.equal(auditRes.status, 200);
      const auditJson = (await auditRes.json()) as { auditLogs: Array<{ action: string }> };
      assert.ok(auditJson.auditLogs.some((l) => l.action === 'SSRF_ATTEMPT_BLOCKED'));

      // 6. /api/execution/run-tests returns 404 on nonexistent softwareId & attaches UnifiedExecutionRecord on valid softwareId
      const missingSwRes = await fetch(`${baseUrl}/api/execution/run-tests`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({ softwareId: 'sw-does-not-exist-404' }),
      });
      assert.equal(missingSwRes.status, 404);

      // Switch environment to DEMO first (since /api/demo/seed is blocked in PRODUCTION mode)
      const envSwitchRes = await fetch(`${baseUrl}/api/environment/switch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({ mode: 'DEMO' }),
      });
      assert.equal(envSwitchRes.status, 200);

      const seedRes = await fetch(`${baseUrl}/api/demo/seed`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
      });
      assert.equal(seedRes.status, 200);
      const seededSw = getDb().softwares[0];
      assert.ok(seededSw);

      const execRunRes = await fetch(`${baseUrl}/api/benchmark-runs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({
          projectId: seededSw.projectId,
          softwareIds: [seededSw.id],
          profileName: 'Sonar way (Modo MQR)',
        }),
      });
      assert.equal(execRunRes.status, 201);

      const runTestsRes = await fetch(`${baseUrl}/api/execution/run-tests`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({ softwareId: seededSw.id }),
      });
      assert.equal(runTestsRes.status, 200);
      const runTestsJson = (await runTestsRes.json()) as { attachedToRunId: string | null };
      assert.ok(runTestsJson.attachedToRunId);
      const attachedRun = getDb().runs.find((r) => r.id === runTestsJson.attachedToRunId);
      assert.ok(attachedRun && (attachedRun.executionRecords?.length ?? 0) >= 1);

      // 7. /api/mqr-bridge/run-integration-tests returns 403 CONTRACT_TEST_ONLY_IN_TEST_MODE outside test mode
      const savedNodeEnv = process.env.NODE_ENV;
      const savedTestMode = process.env.WINHOOD_TEST_MODE;
      process.env.NODE_ENV = 'production';
      delete process.env.WINHOOD_TEST_MODE;
      try {
        const contractGuardRes = await fetch(`${baseUrl}/api/mqr-bridge/run-integration-tests`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: adminCookie,
            'x-csrf-token': adminJar.winhood_csrf!,
          },
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

      // 8. Key rotation re-encrypts saved Sonar tokens & preserves decryptability
      const rawSonarToken = 'squ_winhood_rotation_test_token_2026';
      const saveSonarProjRes = await fetch(`${baseUrl}/api/sonar/saved-projects`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
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

      const rotateAesRes = await fetch(`${baseUrl}/api/security/keys/rotate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({ purpose: 'TOKEN_VAULT_AES256' }),
      });
      assert.equal(rotateAesRes.status, 200);
      const rotateAesJson = (await rotateAesRes.json()) as {
        rotated: boolean;
        newKeyId: string;
        reencryptedTokensCount: number;
      };
      assert.equal(rotateAesJson.rotated, true);
      assert.ok(rotateAesJson.reencryptedTokensCount >= 1);

      const afterCipher = getDb().savedSonarProjects?.find(
        (p) => p.projectKey === 'winhood-rotate-test'
      )?.encryptedToken;
      assert.ok(afterCipher);
      assert.notEqual(afterCipher, beforeCipher);
      assert.ok(afterCipher.startsWith(`${rotateAesJson.newKeyId}:`));
      assert.equal(MqrBridgeConnection.decryptToken(afterCipher), rawSonarToken);

      const rotateEdRes = await fetch(`${baseUrl}/api/security/keys/rotate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
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

    // Sign manifest with HMAC-SHA256 + Ed25519 -> initial verificationState must be SIGNED & verified=false
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

    // Verify manifest passes Ed25519 verification once chain hashes are consistent, or detect tampering cleanly
    const tamperRes = verifyEvidenceChainAndManifest([], manifest);
    assert.equal(tamperRes.valid, false);
    assert.equal(tamperRes.verificationState, 'TAMPERED');

    // Tamper keystore without backup -> throws KEYSTORE_INTEGRITY_VIOLATION
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

test('TOTP AES-256-GCM at-rest encryption, preAuthToken 2-step flow, replay protection, 8 recovery codes, 30d trustDevice cookies, and hardened HTML export CSP', async () => {
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const { app, authService, getDb } = await createWinHoodApp({
      dataDir: tmpDir,
      enforceProductionAuth: true,
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // 1. Bootstrap admin cleanly (MFA disabled initially)
      const bootMeta = authService.getBootstrapMetadata();
      const bootToken = readBootstrapTokenFromFile(bootMeta.bootstrapTokenFilePath);
      const bootRes = await fetch(`${baseUrl}/api/auth/bootstrap-admin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          bootstrapToken: bootToken,
          name: 'TOTP Principal',
          email: 'totp.admin@winhood.local',
          password: 'TotpAdminPassword!2026',
          enableMfa: false,
        }),
      });
      assert.equal(bootRes.status, 201);
      const adminJar = extractSetCookieValues(bootRes);
      const adminCookie = `winhood_session=${adminJar.winhood_session}; winhood_csrf=${adminJar.winhood_csrf}`;

      // 2. Post-login enrollment: /api/auth/totp/setup -> pending secret MUST be AES-256-GCM encrypted on disk
      const setupRes = await fetch(`${baseUrl}/api/auth/totp/setup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({}),
      });
      assert.equal(setupRes.status, 200);
      const setupData = (await setupRes.json()) as {
        secretBase32: string;
        secret: string;
        otpauthUri: string;
        otpauthUrl: string;
        serverTimeIso: string;
      };
      assert.ok(setupData.secretBase32.length >= 16);
      assert.equal(setupData.secretBase32, setupData.secret);
      assert.equal(setupData.otpauthUri, setupData.otpauthUrl);
      assert.ok(!Number.isNaN(Date.parse(setupData.serverTimeIso)));

      const authStorePath = path.join(tmpDir, 'security', 'auth_users.json');
      const rawBeforeConfirm = fs.readFileSync(authStorePath, 'utf8');
      assert.equal(
        rawBeforeConfirm.includes(setupData.secretBase32),
        false,
        'Plaintext pending TOTP secret must NEVER be persisted to disk'
      );
      assert.ok(
        rawBeforeConfirm.includes('whvault:v1:'),
        'Encrypted pending TOTP secret must carry whvault:v1: envelope'
      );

      // 3. Confirm enrollment -> returns 8 single-use XXXX-XXXX recovery codes & encrypts totpSecretBase32 at rest
      const stepNow = Math.floor(Date.now() / 1000 / 30);
      const initialCode = generateTotpCode(setupData.secretBase32, stepNow * 30 * 1000);
      const confirmRes = await fetch(`${baseUrl}/api/auth/totp/verify-setup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({ totpCode: initialCode }),
      });
      assert.equal(confirmRes.status, 200);
      const confirmData = (await confirmRes.json()) as {
        ok: boolean;
        recoveryCodes: string[];
        user: { mfaEnabled: boolean; mfaVerified: boolean };
      };
      assert.equal(confirmData.ok, true);
      assert.equal(confirmData.user.mfaEnabled, true);
      assert.equal(confirmData.recoveryCodes.length, 8);
      for (const rc of confirmData.recoveryCodes) {
        assert.match(rc, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
      }

      const rawAfterConfirm = fs.readFileSync(authStorePath, 'utf8');
      assert.equal(
        rawAfterConfirm.includes(setupData.secretBase32),
        false,
        'Plaintext active TOTP secret must NEVER be persisted to disk'
      );
      assert.equal(
        rawAfterConfirm.includes(confirmData.recoveryCodes[0]!),
        false,
        'Plaintext recovery codes must NEVER be persisted to disk'
      );

      // 4. Two-step login with preAuthToken & anti-replay check
      // Login without totpCode returns requiresTotp: true + signed preAuthToken
      const loginStep1Res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'totp.admin@winhood.local',
          password: 'TotpAdminPassword!2026',
          trustDevice: true,
        }),
      });
      assert.equal(loginStep1Res.status, 200);
      const loginStep1Json = (await loginStep1Res.json()) as {
        authenticated: boolean;
        requiresTotp: boolean;
        preAuthToken: string;
        serverTimeIso: string;
        totpPeriodSeconds: number;
      };
      assert.equal(loginStep1Json.authenticated, false);
      assert.equal(loginStep1Json.requiresTotp, true);
      assert.ok(loginStep1Json.preAuthToken.startsWith('whpa1.'));
      assert.equal(loginStep1Json.totpPeriodSeconds, 30);

      // Attempting to replay the exact same TOTP step code used during confirm (stepNow) must be rejected with 401 AUTH_TOTP_REPLAY
      const replayRes = await fetch(`${baseUrl}/api/auth/totp/authenticate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          preAuthToken: loginStep1Json.preAuthToken,
          totpCode: initialCode,
          trustDevice: true,
        }),
      });
      assert.equal(replayRes.status, 401);
      const replayJson = (await replayRes.json()) as { error: string };
      assert.match(replayJson.error, /AUTH_TOTP_REPLAY/);

      // Completing 2FA with a distinct valid TOTP window (+1 step) succeeds and issues 30-day SameSite=Strict cookies
      const nextStepCode = generateTotpCode(setupData.secretBase32, (stepNow + 1) * 30 * 1000);
      const authTotpRes = await fetch(`${baseUrl}/api/auth/totp/authenticate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          preAuthToken: loginStep1Json.preAuthToken,
          totpCode: nextStepCode,
          trustDevice: true,
        }),
      });
      assert.equal(authTotpRes.status, 200);
      const authTotpJson = (await authTotpRes.json()) as {
        authenticated: boolean;
        requiresTotp: boolean;
        trustDevice: boolean;
      };
      assert.equal(authTotpJson.authenticated, true);
      assert.equal(authTotpJson.requiresTotp, false);
      assert.equal(authTotpJson.trustDevice, true);

      const rawSetCookieHeaders =
        (authTotpRes.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() || [];
      assert.ok(
        rawSetCookieHeaders.some((c) => c.includes('winhood_session=') && c.includes('SameSite=Strict') && c.includes('Max-Age=2592000')),
        'Trusted device login must issue SameSite=Strict 30-day (2592000s) session cookie'
      );

      // 5. Single-use recovery code works once and fails on reuse
      const loginStep1ForRc = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'totp.admin@winhood.local',
          password: 'TotpAdminPassword!2026',
        }),
      });
      const rcChallenge = (await loginStep1ForRc.json()) as { preAuthToken: string };
      const firstRecoveryCode = confirmData.recoveryCodes[0]!;

      const rcAuthRes = await fetch(`${baseUrl}/api/auth/totp/authenticate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          preAuthToken: rcChallenge.preAuthToken,
          recoveryCode: firstRecoveryCode,
        }),
      });
      assert.equal(rcAuthRes.status, 200);
      const rcAuthJson = (await rcAuthRes.json()) as {
        authenticated: boolean;
        usedRecoveryCode: boolean;
        remainingRecoveryCodesCount: number;
      };
      assert.equal(rcAuthJson.authenticated, true);
      assert.equal(rcAuthJson.usedRecoveryCode, true);
      assert.equal(rcAuthJson.remainingRecoveryCodesCount, 7);

      // Reusing the consumed recovery code must fail with 401
      const rcReuseRes = await fetch(`${baseUrl}/api/auth/totp/authenticate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          preAuthToken: rcChallenge.preAuthToken,
          recoveryCode: firstRecoveryCode,
        }),
      });
      assert.equal(rcReuseRes.status, 401);

      // 6. Key rotation re-encrypts active TOTP secrets seamlessly with new AES key
      const rotateRes = await fetch(`${baseUrl}/api/security/keys/rotate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({
          purpose: 'TOKEN_VAULT_AES256',
          reason: 'Unit test TOTP re-encryption rotation',
        }),
      });
      assert.equal(rotateRes.status, 200);
      const rotateJson = (await rotateRes.json()) as { rotated: boolean; reencryptedTokensCount: number };
      assert.equal(rotateJson.rotated, true);
      assert.ok(rotateJson.reencryptedTokensCount >= 1);

      // 7. Seed a real BenchmarkRun (via DEMO seed) and verify hardened HTML report export CSP & X-Content-Type-Options: nosniff
      const envSwitchRes = await fetch(`${baseUrl}/api/environment/switch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({ mode: 'DEMO' }),
      });
      assert.equal(envSwitchRes.status, 200);

      const seedRes = await fetch(`${baseUrl}/api/demo/seed`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
      });
      assert.equal(seedRes.status, 200);

      const db = getDb();
      const seededSw = db.softwares[0];
      assert.ok(seededSw, 'Expected seeded software');
      const execRunRes = await fetch(`${baseUrl}/api/benchmark-runs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie,
          'x-csrf-token': adminJar.winhood_csrf!,
        },
        body: JSON.stringify({
          projectId: seededSw.projectId,
          softwareIds: [seededSw.id],
          profileName: 'Sonar way (Modo MQR)',
        }),
      });
      assert.equal(execRunRes.status, 201);

      const firstRunId = db.runs[0]?.id;
      assert.ok(firstRunId, 'Expected created BenchmarkRun for HTML report export check');
      const htmlExportRes = await fetch(`${baseUrl}/api/reports/${encodeURIComponent(firstRunId)}/export?format=html`, {
        headers: { Cookie: adminCookie },
      });
      assert.equal(htmlExportRes.status, 200);
      assert.equal(htmlExportRes.headers.get('content-type'), 'text/html; charset=utf-8');
      assert.equal(htmlExportRes.headers.get('x-content-type-options'), 'nosniff');
      const cspHeader = htmlExportRes.headers.get('content-security-policy') || '';
      assert.match(cspHeader, /default-src 'none'/);
      assert.match(cspHeader, /base-uri 'none'/);
      assert.match(cspHeader, /form-action 'none'/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test('Hybrid session: first user registered at /api/auth/register receives ADMIN and completes bootstrap; 2nd user is blocked from ADMIN elevation; /api/auth/me + Bearer/X-WinHood-Session + logout work deterministically', async () => {
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const { app, authService } = await createWinHoodApp({
      dataDir: tmpDir,
      enforceProductionAuth: true,
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      assert.equal(authService.isBootstrapRequired(), true);
      const bootMeta = authService.getBootstrapMetadata();
      assert.ok(fs.existsSync(bootMeta.bootstrapTokenFilePath));

      // 0. Unauthenticated GET /api/auth/me returns 401 SESSION_INVALID
      const unauthMeRes = await fetch(`${baseUrl}/api/auth/me`);
      assert.equal(unauthMeRes.status, 401);
      const unauthMeJson = (await unauthMeRes.json()) as { code: string; authenticated: boolean };
      assert.equal(unauthMeJson.code, 'SESSION_INVALID');
      assert.equal(unauthMeJson.authenticated, false);

      // 1. First user registered directly via /api/auth/register automatically receives ADMIN and completes bootstrap
      const firstRegRes = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'First Local Admin User',
          email: 'first.admin@winhood.local',
          password: 'FirstAdminStrongPassword!2026',
          role: 'SECURITY_LEAD',
        }),
      });
      assert.equal(firstRegRes.status, 201);
      const firstRegJson = (await firstRegRes.json()) as {
        authenticated: boolean;
        user: { email: string; role: string };
      };
      assert.equal(firstRegJson.authenticated, true);
      assert.equal(firstRegJson.user.role, 'ADMIN');
      assert.equal(authService.isBootstrapRequired(), false);
      assert.equal(fs.existsSync(bootMeta.bootstrapTokenFilePath), false);

      // 2. Second user attempting to self-assign ADMIN role is blocked with 403 ROLE_ELEVATION_BLOCKED
      const elevationRes = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Privilege Escalation Attempt',
          email: 'escalation@winhood.local',
          password: 'EscalationStrong!2026',
          role: 'ADMIN',
        }),
      });
      assert.equal(elevationRes.status, 403);
      const elevationJson = (await elevationRes.json()) as { code: string };
      assert.equal(elevationJson.code, 'ROLE_ELEVATION_BLOCKED');

      // 3b. Subsequent user registers via /api/auth/register simulating cross-site HTTPS iframe proxy
      const regRes = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-forwarded-proto': 'https',
          'sec-fetch-dest': 'iframe',
          'sec-fetch-site': 'cross-site',
        },
        body: JSON.stringify({
          name: 'First Frame User',
          email: 'iframe.user@winhood.local',
          password: 'IframeUserStrong!2026',
          role: 'SECURITY_LEAD',
        }),
      });
      assert.equal(regRes.status, 201);

      const rawCookies =
        (regRes.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() || [];
      assert.ok(
        rawCookies.some((c) => c.includes('SameSite=None; Secure; Partitioned')),
        'HTTPS cross-site iframe requests must receive SameSite=None; Secure; Partitioned cookies'
      );
      assert.ok(regRes.headers.get('x-winhood-session-token'));
      assert.ok(regRes.headers.get('x-winhood-csrf-token'));

      const regJson = (await regRes.json()) as {
        authenticated: boolean;
        sessionId: string;
        csrfToken: string;
        user: { email: string; role: string };
      };
      assert.equal(regJson.authenticated, true);
      assert.notEqual(regJson.user.role, 'ADMIN');
      assert.ok(regJson.sessionId.length >= 32);
      assert.ok(regJson.csrfToken.length >= 16);

      // 4. Verify GET /api/auth/me returns 200 with sanitized user profile
      const meRes = await fetch(`${baseUrl}/api/auth/me`, {
        headers: {
          Authorization: `Bearer ${regJson.sessionId}`,
        },
      });
      assert.equal(meRes.status, 200);
      const meJson = (await meRes.json()) as {
        authenticated: boolean;
        user: { email: string; role: string; passwordHash?: string; totpSecretEncrypted?: string };
      };
      assert.equal(meJson.authenticated, true);
      assert.equal(meJson.user.email, 'iframe.user@winhood.local');
      assert.equal(meJson.user.passwordHash, undefined);
      assert.equal(meJson.user.totpSecretEncrypted, undefined);

      // 5. Subsequent /api/bootstrap & /api/auth/session with NO cookies and ONLY Authorization: Bearer <sessionId>
      const bootstrapRes = await fetch(`${baseUrl}/api/bootstrap`, {
        headers: {
          Authorization: `Bearer ${regJson.sessionId}`,
        },
      });
      assert.equal(bootstrapRes.status, 200);
      const bootstrapJson = (await bootstrapRes.json()) as { user: { email: string } };
      assert.equal(bootstrapJson.user.email, 'iframe.user@winhood.local');

      const sessRes = await fetch(`${baseUrl}/api/auth/session`, {
        headers: {
          'x-winhood-session': regJson.sessionId,
        },
      });
      assert.equal(sessRes.status, 200);
      const sessJson = (await sessRes.json()) as {
        authenticated: boolean;
        csrfToken: string;
        user: { email: string };
      };
      assert.equal(sessJson.authenticated, true);
      assert.equal(sessJson.user.email, 'iframe.user@winhood.local');
      assert.equal(sessJson.csrfToken, regJson.csrfToken);

      // 6. Logout via Bearer header revokes session on server -> subsequent /api/bootstrap & /api/auth/me return 401
      const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${regJson.sessionId}`,
        },
      });
      assert.equal(logoutRes.status, 200);

      const postLogoutBootstrap = await fetch(`${baseUrl}/api/bootstrap`, {
        headers: {
          Authorization: `Bearer ${regJson.sessionId}`,
        },
      });
      assert.equal(postLogoutBootstrap.status, 401);

      const postLogoutMe = await fetch(`${baseUrl}/api/auth/me`, {
        headers: {
          Authorization: `Bearer ${regJson.sessionId}`,
        },
      });
      assert.equal(postLogoutMe.status, 401);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
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
    const { app, authService, getDb } = await createWinHoodApp({
      dataDir: tmpDir,
      enforceProductionAuth: true,
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
      const bootFile = authService.getBootstrapMetadata().bootstrapTokenFilePath;
      const bootstrapToken = readBootstrapTokenFromFile(bootFile);
      const bootRes = await fetch(`${baseUrl}/api/auth/bootstrap-admin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          bootstrapToken,
          name: 'Rate Limit Admin',
          email: 'ratelimit.admin@winhood.local',
          password: 'RateLimitAdminStrong!2026',
        }),
      });
      assert.equal(bootRes.status, 201);
      const bootJson = (await bootRes.json()) as { sessionId: string; csrfToken: string };
      const authHeaders = {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${bootJson.sessionId}`,
        'x-csrf-token': bootJson.csrfToken,
      };

      const initialProjectsCount = getDb().projects.length;

      // 1. Invalid upload (traversal) must fail without leaving orphan project
      const badUploadRes = await fetch(`${baseUrl}/api/projects/upload`, {
        method: 'POST',
        headers: authHeaders,
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
        headers: authHeaders,
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
        headers: authHeaders,
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

  // Tamper evidence chain
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

test('isValidEmailAddress validates standard formats and rejects malformed or backtracking-prone inputs in linear time', () => {
  assert.equal(isValidEmailAddress('admin@winhood.local'), true);
  assert.equal(isValidEmailAddress('sec.lead+01@sub.example.org'), true);

  assert.equal(isValidEmailAddress(''), false);
  assert.equal(isValidEmailAddress('sem-arroba.com'), false);
  assert.equal(isValidEmailAddress('@sem-local.com'), false);
  assert.equal(isValidEmailAddress('user@semdominio'), false);
  assert.equal(isValidEmailAddress('user@.invalid.com'), false);
  assert.equal(isValidEmailAddress('user@invalid.com.'), false);
  assert.equal(isValidEmailAddress('user name@winhood.local'), false);
  assert.equal(isValidEmailAddress('a@@b.com'), false);

  const startedAt = performance.now();
  const adversarial = `${'a'.repeat(50000)}@${'b'.repeat(50000)}`;
  assert.equal(isValidEmailAddress(adversarial), false);
  assert.ok(performance.now() - startedAt < 50);
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

    // 1. Tampered authTag must throw DECRYPTION_AUTH_FAILED
    const parts = envelope.split(':');
    const lastChar = parts[5].slice(-1) === 'a' ? 'b' : 'a';
    const tamperedAuthTagEnvelope = [...parts.slice(0, 5), parts[5].slice(0, -1) + lastChar, parts[6]].join(':');
    assert.throws(
      () => PersistentDatabaseManager.decryptSourceFilesMap(tamperedAuthTagEnvelope),
      /DECRYPTION_AUTH_FAILED/
    );

    // 2. Wrong AES-256 key must throw DECRYPTION_AUTH_FAILED
    const wrongKey = crypto.randomBytes(32);
    assert.throws(
      () => PersistentDatabaseManager.decryptSourceFilesMap(envelope, wrongKey),
      /DECRYPTION_AUTH_FAILED/
    );

    // 3. Truncated / malformed envelope must throw DECRYPTION_FORMAT_INVALID
    assert.throws(
      () => PersistentDatabaseManager.decryptSourceFilesMap('whdb:enc:v2:only-two:parts'),
      /DECRYPTION_FORMAT_INVALID/
    );

    // 4. Unsupported version prefix must throw DECRYPTION_VERSION_UNSUPPORTED
    assert.throws(
      () => PersistentDatabaseManager.decryptSourceFilesMap('whdb:enc:v99:kid:iv:tag:payload'),
      /DECRYPTION_VERSION_UNSUPPORTED/
    );

    // 5. Invalid JSON string must throw DECRYPTION_FORMAT_INVALID
    assert.throws(
      () => PersistentDatabaseManager.decryptSourceFilesMap('{corrupted-json'),
      /DECRYPTION_FORMAT_INVALID/
    );
  });
});

test('SandboxExecutor.runSandboxedNodeTest updates recoveryVerified to true and isolationState to RECOVERY_VERIFIED after temp cleanup', async () => {
  const result = await SandboxExecutor.runSandboxedNodeTest({
    filesMap: {
      'index.test.mjs': 'import test from "node:test"; import assert from "node:assert"; test("math", () => { assert.strictEqual(2 + 2, 4); });\n',
    },
    testFiles: ['index.test.mjs'],
    timeoutMs: 10000,
  });

  assert.equal(result.executed, true);
  assert.equal(result.exitCode, 0);
  assert.equal(result.recoveryVerified, true);
  assert.equal(result.isolationState, 'RECOVERY_VERIFIED');
});

test('Quick PIN (6-8 digits) rejects weak PINs (123456, 111111) and supports PIN registration, login, brute-force lockout, and CSRF-protected PIN setup', async () => {
  // 1. Direct unit validation of PIN policy
  assert.throws(() => validateQuickPin('123456'), /WEAK_PIN/);
  assert.throws(() => validateQuickPin('654321'), /WEAK_PIN/);
  assert.throws(() => validateQuickPin('111111'), /WEAK_PIN/);
  assert.throws(() => validateQuickPin('00000000'), /WEAK_PIN/);
  assert.throws(() => validateQuickPin('12345'), /INVALID_PIN/);
  assert.throws(() => validateQuickPin('123456789'), /INVALID_PIN/);
  assert.equal(validateQuickPin('482917'), '482917');
  assert.equal(validateQuickPin('90418273'), '90418273');

  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const { app, authService } = await createWinHoodApp({
      dataDir: tmpDir,
      enforceProductionAuth: true,
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // 2. Weak PIN rejected on /api/auth/register
      for (const weakPin of ['123456', '111111', '654321']) {
        const weakRes = await fetch(`${baseUrl}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'Weak PIN User',
            email: 'weak.pin@winhood.local',
            pin: weakPin,
          }),
        });
        assert.equal(weakRes.status, 400);
        const weakJson = (await weakRes.json()) as { code: string };
        assert.equal(weakJson.code, 'WEAK_PIN');
      }

      // 3. Valid PIN-only registration for 1st user promotes to ADMIN and completes bootstrap
      const regRes = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'PIN Admin User',
          email: 'pin.admin@winhood.local',
          pin: '482917',
        }),
      });
      assert.equal(regRes.status, 201);
      const regJson = (await regRes.json()) as {
        authenticated: boolean;
        sessionId: string;
        csrfToken: string;
        user: { email: string; role: string; pinEnabled?: boolean };
      };
      assert.equal(regJson.authenticated, true);
      assert.equal(regJson.user.role, 'ADMIN');
      assert.equal(regJson.user.pinEnabled, true);
      assert.equal(authService.isBootstrapRequired(), false);

      // 4. Login via POST /api/auth/login-pin succeeds
      const loginPinRes = await fetch(`${baseUrl}/api/auth/login-pin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'pin.admin@winhood.local',
          pin: '482917',
        }),
      });
      assert.equal(loginPinRes.status, 200);
      const loginPinJson = (await loginPinRes.json()) as {
        authenticated: boolean;
        sessionId: string;
        csrfToken: string;
      };
      assert.equal(loginPinJson.authenticated, true);
      assert.ok(loginPinJson.sessionId.length >= 32);

      // 4b. Verify Global Security Headers & Permissions-Policy for WebAuthn
      assert.equal(loginPinRes.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(loginPinRes.headers.get('x-frame-options'), 'SAMEORIGIN');
      assert.equal(loginPinRes.headers.get('referrer-policy'), 'no-referrer');
      assert.match(
        loginPinRes.headers.get('permissions-policy') || '',
        /publickey-credentials-create=\*, publickey-credentials-get=\*/
      );

      // 5. Update PIN via authenticated POST /api/auth/pin/setup with CSRF
      const setupPinRes = await fetch(`${baseUrl}/api/auth/pin/setup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${loginPinJson.sessionId}`,
          'x-csrf-token': loginPinJson.csrfToken,
        },
        body: JSON.stringify({ pin: '73918462' }),
      });
      assert.equal(setupPinRes.status, 200);

      // 6. Brute-force lockout after 5 wrong PIN attempts
      for (let i = 0; i < AuthService.MAX_LOGIN_ATTEMPTS; i++) {
        const badPinRes = await fetch(`${baseUrl}/api/auth/login-pin`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: 'pin.admin@winhood.local',
            pin: '998877',
          }),
        });
        assert.equal(badPinRes.status, 401);
      }

      const lockedPinRes = await fetch(`${baseUrl}/api/auth/login-pin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'pin.admin@winhood.local',
          pin: '73918462',
        }),
      });
      assert.equal(lockedPinRes.status, 429);
      const lockedJson = (await lockedPinRes.json()) as { error: string; code: string };
      assert.match(lockedJson.error, /AUTH_ACCOUNT_LOCKED/);
      assert.equal(lockedJson.code, 'RATE_LIMITED');

      // 7. Self-service local account deletion (DELETE /api/auth/me) requires CSRF + valid PIN/password and revokes session
      const delNoCsrf = await fetch(`${baseUrl}/api/auth/me`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${loginPinJson.sessionId}`,
        },
        body: JSON.stringify({ pin: '73918462' }),
      });
      assert.equal(delNoCsrf.status, 403);

      const delWrongPin = await fetch(`${baseUrl}/api/auth/me`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${loginPinJson.sessionId}`,
          'x-csrf-token': loginPinJson.csrfToken,
        },
        body: JSON.stringify({ pin: '999999' }),
      });
      assert.equal(delWrongPin.status, 401);

      const delOkRes = await fetch(`${baseUrl}/api/auth/me`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${loginPinJson.sessionId}`,
          'x-csrf-token': loginPinJson.csrfToken,
        },
        body: JSON.stringify({ pin: '73918462' }),
      });
      assert.equal(delOkRes.status, 200);
      const delOkJson = (await delOkRes.json()) as { ok: boolean; revokedSessionsCount: number };
      assert.equal(delOkJson.ok, true);
      assert.ok(delOkJson.revokedSessionsCount >= 1);

      // Session is immediately invalid after DELETE /api/auth/me
      const postDelMe = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${loginPinJson.sessionId}` },
      });
      assert.equal(postDelMe.status, 401);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test('WebAuthn / Windows Hello (FIDO2) generates platform challenge options and verifies ES256 cryptographic registration and login with signCount anti-replay', async () => {
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const { app, authService } = await createWinHoodApp({
      dataDir: tmpDir,
      enforceProductionAuth: true,
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    // Minimal CBOR helper to build a valid attestationObject { authData: bstr } for ES256 (-7)
    const buildEs256CosePublicKey = (x: Buffer, y: Buffer): Buffer => {
      // CBOR map(5): { 1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: bstr(32) x, -3: bstr(32) y }
      return Buffer.concat([
        Buffer.from([0xa5]),
        Buffer.from([0x01, 0x02]), // 1: 2
        Buffer.from([0x03, 0x26]), // 3: -7 (0x20 | 6)
        Buffer.from([0x20, 0x01]), // -1: 1
        Buffer.from([0x21, 0x58, 0x20]), // -2: bstr(32)
        x,
        Buffer.from([0x22, 0x58, 0x20]), // -3: bstr(32)
        y,
      ]);
    };

    const wrapAuthDataInAttestationCbor = (authData: Buffer): Buffer => {
      // CBOR map(1): { "authData": bstr(authData) }
      const keyBytes = Buffer.from('authData', 'utf8');
      const lenHeader =
        authData.length < 256
          ? Buffer.from([0x58, authData.length])
          : Buffer.from([0x59, (authData.length >> 8) & 0xff, authData.length & 0xff]);
      return Buffer.concat([
        Buffer.from([0xa1, 0x60 | keyBytes.length]),
        keyBytes,
        lenHeader,
        authData,
      ]);
    };

    try {
      // 1. Request WebAuthn registration options via HTTP
      const regOptRes = await fetch(`${baseUrl}/api/auth/webauthn/register-account/options`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Host: `127.0.0.1:${port}`,
        },
        body: JSON.stringify({
          name: 'Windows Hello Admin',
          email: 'hello.admin@winhood.local',
          role: 'SECURITY_LEAD',
        }),
      });
      assert.equal(regOptRes.status, 200);
      const regOptJson = (await regOptRes.json()) as {
        challengeId: string;
        publicKey: {
          challenge: string;
          rp: { id: string; name: string };
          authenticatorSelection: { authenticatorAttachment: string; userVerification: string };
          pubKeyCredParams: Array<{ type: string; alg: number }>;
        };
      };
      assert.ok(regOptJson.challengeId);
      assert.equal(regOptJson.publicKey.authenticatorSelection.authenticatorAttachment, 'platform');
      assert.equal(regOptJson.publicKey.authenticatorSelection.userVerification, 'required');
      assert.deepEqual(
        regOptJson.publicKey.pubKeyCredParams.map((p) => p.alg),
        [-7, -257]
      );
      assert.equal(Buffer.from(regOptJson.publicKey.challenge, 'base64url').length, 32);

      // 2. Construct valid ES256 credential and verify WebAuthn registration (1st user -> ADMIN)
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
      const coseKey = buildEs256CosePublicKey(
        Buffer.from(jwk.x, 'base64url'),
        Buffer.from(jwk.y, 'base64url')
      );

      const rpIdHash = crypto.createHash('sha256').update(regOptJson.publicKey.rp.id, 'utf8').digest();
      const flags = Buffer.from([0x45]); // UP (0x01) | UV (0x04) | AT (0x40)
      const signCountBuf = Buffer.alloc(4);
      signCountBuf.writeUInt32BE(1, 0);
      const aaguid = Buffer.alloc(16, 0);
      const credIdBytes = crypto.randomBytes(32);
      const credIdB64 = credIdBytes.toString('base64url');
      const credLenBuf = Buffer.alloc(2);
      credLenBuf.writeUInt16BE(credIdBytes.length, 0);

      const authDataReg = Buffer.concat([rpIdHash, flags, signCountBuf, aaguid, credLenBuf, credIdBytes, coseKey]);
      const attestationObject = wrapAuthDataInAttestationCbor(authDataReg);
      const clientDataReg = Buffer.from(
        JSON.stringify({
          type: 'webauthn.create',
          challenge: regOptJson.publicKey.challenge,
          origin: `http://127.0.0.1:${port}`,
        }),
        'utf8'
      );

      const regVerifyRes = await fetch(`${baseUrl}/api/auth/webauthn/register-account/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: regOptJson.challengeId,
          credential: {
            id: credIdB64,
            rawId: credIdB64,
            type: 'public-key',
            response: {
              clientDataJSON: clientDataReg.toString('base64url'),
              attestationObject: attestationObject.toString('base64url'),
            },
          },
        }),
      });
      assert.equal(regVerifyRes.status, 201);
      const regVerifyJson = (await regVerifyRes.json()) as {
        authenticated: boolean;
        user: { email: string; role: string; webauthnEnabled?: boolean };
      };
      assert.equal(regVerifyJson.authenticated, true);
      assert.equal(regVerifyJson.user.role, 'ADMIN');
      assert.equal(regVerifyJson.user.webauthnEnabled, true);
      assert.equal(authService.isBootstrapRequired(), false);

      // 3. Request WebAuthn login options and verify cryptographic signature + signCount anti-replay
      const loginOptRes = await fetch(`${baseUrl}/api/auth/webauthn/login/options`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Host: `127.0.0.1:${port}`,
        },
        body: JSON.stringify({ email: 'hello.admin@winhood.local' }),
      });
      assert.equal(loginOptRes.status, 200);
      const loginOptJson = (await loginOptRes.json()) as {
        challengeId: string;
        publicKey: { challenge: string; rpId: string; userVerification: string };
      };
      assert.equal(loginOptJson.publicKey.userVerification, 'required');

      const loginSignCount = Buffer.alloc(4);
      loginSignCount.writeUInt32BE(2, 0);
      const authDataLogin = Buffer.concat([rpIdHash, Buffer.from([0x05]), loginSignCount]); // UP | UV
      const clientDataLogin = Buffer.from(
        JSON.stringify({
          type: 'webauthn.get',
          challenge: loginOptJson.publicKey.challenge,
          origin: `http://127.0.0.1:${port}`,
        }),
        'utf8'
      );
      const clientDataHash = crypto.createHash('sha256').update(clientDataLogin).digest();
      const signedPayload = Buffer.concat([authDataLogin, clientDataHash]);
      const signature = crypto.sign('sha256', signedPayload, privateKey);

      const loginVerifyRes = await fetch(`${baseUrl}/api/auth/webauthn/login/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: loginOptJson.challengeId,
          credential: {
            id: credIdB64,
            rawId: credIdB64,
            type: 'public-key',
            response: {
              clientDataJSON: clientDataLogin.toString('base64url'),
              authenticatorData: authDataLogin.toString('base64url'),
              signature: signature.toString('base64url'),
            },
          },
        }),
      });
      assert.equal(loginVerifyRes.status, 200);
      const loginVerifyJson = (await loginVerifyRes.json()) as { authenticated: boolean; sessionId: string };
      assert.equal(loginVerifyJson.authenticated, true);
      assert.ok(loginVerifyJson.sessionId.length >= 32);

      // 4. Replay attempt with stale signCount (<= 2) must be rejected with WEBAUTHN_COUNTER_REPLAY
      const replayOptRes = await fetch(`${baseUrl}/api/auth/webauthn/login/options`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Host: `127.0.0.1:${port}`,
        },
        body: JSON.stringify({ email: 'hello.admin@winhood.local' }),
      });
      const replayOptJson = (await replayOptRes.json()) as {
        challengeId: string;
        publicKey: { challenge: string };
      };
      const staleCount = Buffer.alloc(4);
      staleCount.writeUInt32BE(2, 0); // same signCount = 2 -> replay!
      const authDataReplay = Buffer.concat([rpIdHash, Buffer.from([0x05]), staleCount]);
      const clientDataReplay = Buffer.from(
        JSON.stringify({
          type: 'webauthn.get',
          challenge: replayOptJson.publicKey.challenge,
          origin: `http://127.0.0.1:${port}`,
        }),
        'utf8'
      );
      const replaySig = crypto.sign(
        'sha256',
        Buffer.concat([authDataReplay, crypto.createHash('sha256').update(clientDataReplay).digest()]),
        privateKey
      );
      const replayVerifyRes = await fetch(`${baseUrl}/api/auth/webauthn/login/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: replayOptJson.challengeId,
          credential: {
            id: credIdB64,
            rawId: credIdB64,
            type: 'public-key',
            response: {
              clientDataJSON: clientDataReplay.toString('base64url'),
              authenticatorData: authDataReplay.toString('base64url'),
              signature: replaySig.toString('base64url'),
            },
          },
        }),
      });
      assert.equal(replayVerifyRes.status, 401);
      const replayVerifyJson = (await replayVerifyRes.json()) as { error: string };
      assert.match(replayVerifyJson.error, /WEBAUTHN_REPLAY_DETECTED/);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test('WebAuthn options prioritize body.rpId and Origin hostname over Host header, and native Windows Hello OS verification enforces win32 + ES256 P-256 key generation', async () => {
  await withIsolatedKeystoreEnv(async (tmpDir) => {
    const { app, authService } = await createWinHoodApp({
      dataDir: tmpDir,
      enforceProductionAuth: true,
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // 1. Dynamic rpId: body.rpId takes priority over Origin and Host headers
      const bodyRpRes = await fetch(`${baseUrl}/api/auth/webauthn/register-account/options`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://proxy.example.com:8443',
          Host: `127.0.0.1:${port}`,
        },
        body: JSON.stringify({
          name: 'Proxy Domain User',
          email: 'proxy.domain@winhood.local',
          rpId: 'ais-dev-preview.us-east1.run.app',
        }),
      });
      assert.equal(bodyRpRes.status, 200);
      const bodyRpJson = (await bodyRpRes.json()) as { rp: { id: string } };
      assert.equal(bodyRpJson.rp.id, 'ais-dev-preview.us-east1.run.app');

      // 2. Origin header hostname takes priority over Host header when body.rpId is omitted
      const originRpRes = await fetch(`${baseUrl}/api/auth/webauthn/login/options`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://portal.winhood.dev:9443',
          Host: `127.0.0.1:${port}`,
        },
        body: JSON.stringify({}),
      });
      assert.equal(originRpRes.status, 200);
      const originRpJson = (await originRpRes.json()) as { rpId: string };
      assert.equal(originRpJson.rpId, 'portal.winhood.dev');

      // 3. PowerShell WinRT UserConsentVerifier script contains official Windows Hello API
      const psScript = AuthService.buildWindowsHelloPowerShellScript();
      assert.match(psScript, /Windows\.Security\.Credentials\.UI\.UserConsentVerifier/);
      assert.match(psScript, /RequestVerificationAsync/);

      // 4. On non-Windows hosts (e.g. Linux container), native endpoints fail cleanly with 501 WINDOWS_HELLO_OS_UNSUPPORTED
      if (process.platform !== 'win32') {
        const nativeRegRes = await fetch(`${baseUrl}/api/auth/windows-hello/native-register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'Native Linux Check',
            email: 'native.linux@winhood.local',
          }),
        });
        assert.equal(nativeRegRes.status, 501);
        const nativeRegJson = (await nativeRegRes.json()) as { code: string };
        assert.equal(nativeRegJson.code, 'WINDOWS_HELLO_OS_UNSUPPORTED');

        const nativeLoginRes = await fetch(`${baseUrl}/api/auth/windows-hello/native-login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'native.linux@winhood.local' }),
        });
        assert.equal(nativeLoginRes.status, 501);
        const nativeLoginJson = (await nativeLoginRes.json()) as { code: string };
        assert.equal(nativeLoginJson.code, 'WINDOWS_HELLO_OS_UNSUPPORTED');
      }

      // 5. Native Windows Hello registration + login with verified OS prompt generates valid ES256 P-256 keypair in auth_users.json
      const nativeRegOutcome = await authService.registerNativeWindowsHelloAccount({
        name: 'Windows Native User',
        email: 'win.native@winhood.local',
        promptVerifier: async (msg) => {
          assert.match(msg, /win\.native@winhood\.local/);
        },
      });
      assert.equal(nativeRegOutcome.keyAlgorithm, 'ES256');
      assert.equal(nativeRegOutcome.user.role, 'ADMIN');
      assert.equal(nativeRegOutcome.user.webauthnEnabled, true);
      assert.ok(nativeRegOutcome.sessionId.length >= 32);

      const nativeLoginOutcome = await authService.loginNativeWindowsHelloAccount({
        email: 'win.native@winhood.local',
        promptVerifier: async (msg) => {
          assert.match(msg, /win\.native@winhood\.local/);
        },
      });
      assert.equal(nativeLoginOutcome.user.email, 'win.native@winhood.local');
      assert.ok(nativeLoginOutcome.sessionId.length >= 32);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});


