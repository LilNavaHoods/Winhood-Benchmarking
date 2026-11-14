import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { AuthService, generateTotpCode } from './AuthService';
import { KeyManagementService } from './KeyManagementService';
import { SsrfGuard } from '../execution/SsrfGuard';
import { SandboxExecutor } from '../execution/SandboxExecutor';
import { PersistentDatabaseManager } from '../storage/PersistentDatabaseManager';
import {
  GENESIS_EVIDENCE_HASH,
  signEvidenceManifestHmacSha256,
  verifyEvidenceChainAndManifest,
} from '../engine/evidenceProvenanceEngine';
import { SonarQubeConnection } from '../integrations/sonarqube/SonarQubeConnection';
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

      // 7. /api/sonarqube/run-integration-tests returns 403 CONTRACT_TEST_ONLY_IN_TEST_MODE outside test mode
      const savedNodeEnv = process.env.NODE_ENV;
      const savedTestMode = process.env.WINHOOD_TEST_MODE;
      process.env.NODE_ENV = 'production';
      delete process.env.WINHOOD_TEST_MODE;
      try {
        const contractGuardRes = await fetch(`${baseUrl}/api/sonarqube/run-integration-tests`, {
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
      assert.equal(SonarQubeConnection.decryptToken(afterCipher), rawSonarToken);

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
