import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import zlib from 'node:zlib';
import {
  createWinHoodApp,
  resolveDeploymentMode,
  resolveRuntimeEnv,
  resolveTrustProxyConfig,
  startServer,
} from '../../server';
import { KeyManagementService } from './KeyManagementService';
import {
  MAX_ZIP_ENTRIES,
  extractZipBufferToFilesMap,
} from '../server/zipExtractor';
import {
  RemoteAuthFailureTracker,
  buildAllowedOriginMap,
  parseValidPortNumber,
} from '../server/securityMiddleware';
import { registerGracefulShutdown } from '../server/gracefulShutdown';

/**
 * Builds a minimal valid uncompressed (STORE, method 0) ZIP archive buffer in pure Node.js
 * so tests can validate real ZIP extraction, large ZIP payloads (>2MB), and path-traversal ZIPs.
 */
function buildStoredZipBuffer(entries: Array<{ name: string; content: Buffer }>): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;

  const crc32Table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    crc32Table[i] = c >>> 0;
  }
  const crc32 = (buf: Buffer): number => {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
      c = crc32Table[(c ^ buf[i]!) & 0xff]! ^ (c >>> 8);
    }
    return (c ^ 0xffffffff) >>> 0;
  };

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const dataBuf = entry.content;
    const crc = crc32(dataBuf);

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(0, 8); // STORE
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(dataBuf.length, 18);
    localHeader.writeUInt32LE(dataBuf.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);

    localParts.push(localHeader, nameBuf, dataBuf);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(dataBuf.length, 20);
    centralHeader.writeUInt32LE(dataBuf.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);

    centralParts.push(centralHeader, nameBuf);
    offset += localHeader.length + nameBuf.length + dataBuf.length;
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

test('CODE-001: Upload endpoints accept >2MB payloads up to 50MB while standard endpoints enforce 2MB limit, and reject invalid JSON/Base64/ZIP/Path Traversal cleanly', async () => {
  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-code001-'));
  let server: http.Server | null = null;
  try {
    const { app } = await createWinHoodApp({ dataDir: tmpDataDir });
    server = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    // 1. Small upload (<2MB) succeeds
    const smallRes = await fetch(`${baseUrl}/api/projects/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'SmallUpload',
        objective: 'Test small upload <2MB',
        filesMap: { 'src/index.ts': 'export const ok = 1;\n' },
      }),
    });
    assert.equal(smallRes.status, 201);

    // 2. Large upload (>2MB, ~3.1MB) succeeds on /api/projects/upload (global 2MB parser bypassed!)
    const largeFilesMap: Record<string, string> = {};
    const chunkText = 'export const line = "winhood-benchmark-payload-verification";\n'.repeat(1800); // ~108 KB
    for (let i = 0; i < 30; i++) {
      largeFilesMap[`src/mod_${i}.ts`] = chunkText;
    }
    const largeUploadBody = JSON.stringify({
      name: 'LargeUpload3MB',
      objective: 'Test >2MB upload bypassing global 2MB parser',
      filesMap: largeFilesMap,
    });
    assert.ok(Buffer.byteLength(largeUploadBody, 'utf8') > 2.5 * 1024 * 1024);

    const largeRes = await fetch(`${baseUrl}/api/projects/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: largeUploadBody,
    });
    assert.equal(largeRes.status, 201, `Expected >2MB upload to succeed, got ${largeRes.status}`);

    // 3. Large ZIP (>2MB Base64 across multiple realistic source files) succeeds on /api/projects/extract-zip
    const zipEntries = Array.from({ length: 12 }, (_, idx) => ({
      name: `src/module_${idx}.ts`,
      content: Buffer.from(`// ${'A'.repeat(200_000)}\nexport const mod${idx} = ${idx};\n`, 'utf8'),
    }));
    const zipBuf = buildStoredZipBuffer(zipEntries);
    const zipB64 = zipBuf.toString('base64');
    assert.ok(zipB64.length > 2.5 * 1024 * 1024);
    const zipRes = await fetch(`${baseUrl}/api/projects/extract-zip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ zipBase64: zipB64 }),
    });
    assert.equal(zipRes.status, 200);
    const zipJson = (await zipRes.json()) as { extractedCount: number };
    assert.equal(zipJson.extractedCount, 12);

    // 4. Standard non-upload endpoint still enforces 2MB global limit (HTTP 413 PAYLOAD_TOO_LARGE)
    const oversizedStandard = await fetch(`${baseUrl}/api/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'OversizedStandard',
        objective: 'X'.repeat(2_500_000),
      }),
    });
    assert.equal(oversizedStandard.status, 413);
    const oversizedJson = (await oversizedStandard.json()) as { error: string };
    assert.equal(oversizedJson.error, 'PAYLOAD_TOO_LARGE');

    // 5. Invalid JSON returns 400 INVALID_JSON_PAYLOAD
    const badJsonRes = await fetch(`${baseUrl}/api/projects/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{ invalid json',
    });
    assert.equal(badJsonRes.status, 400);
    const badJsonBody = (await badJsonRes.json()) as { error: string };
    assert.equal(badJsonBody.error, 'INVALID_JSON_PAYLOAD');

    // 6. Invalid Base64 returns 400 INVALID_BASE64_PAYLOAD
    const badB64Res = await fetch(`${baseUrl}/api/projects/extract-zip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ zipBase64: '!!!not-valid-base64!!!' }),
    });
    assert.equal(badB64Res.status, 400);
    const badB64Body = (await badB64Res.json()) as { error: string };
    assert.equal(badB64Body.error, 'INVALID_BASE64_PAYLOAD');

    // 7. Malformed ZIP (valid Base64, non-ZIP bytes) returns 400 ZIP_EXTRACTION_FAILED
    const fakeZipRes = await fetch(`${baseUrl}/api/projects/extract-zip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ zipBase64: Buffer.from('NOT_A_ZIP_ARCHIVE_HEADER_1234567890').toString('base64') }),
    });
    assert.equal(fakeZipRes.status, 400);
    const fakeZipBody = (await fakeZipRes.json()) as { error: string };
    assert.equal(fakeZipBody.error, 'ZIP_EXTRACTION_FAILED');

    // 8. ZIP with Path Traversal attempt is sanitized/blocked
    const traversalZip = buildStoredZipBuffer([
      { name: '../../etc/passwd', content: Buffer.from('root:x:0:0:', 'utf8') },
      { name: 'src/safe.ts', content: Buffer.from('export const safe = 1;\n', 'utf8') },
    ]);
    const travRes = await fetch(`${baseUrl}/api/projects/extract-zip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ zipBase64: traversalZip.toString('base64') }),
    });
    const travBody = (await travRes.json()) as { filesMap?: Record<string, string>; error?: string };
    if (travRes.status === 200) {
      assert.equal(Object.keys(travBody.filesMap || {}).some((k) => k.includes('..')), false);
    } else {
      assert.equal(travRes.status, 400);
    }

    // 9. Explicit path traversal in /api/projects/upload returns 400 UPLOAD_SECURITY_VIOLATION
    const travUpload = await fetch(`${baseUrl}/api/projects/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'TraversalUpload',
        objective: 'Should be blocked',
        filesMap: { '../../../etc/shadow': 'malicious' },
      }),
    });
    assert.equal(travUpload.status, 400);
    const travUploadJson = (await travUpload.json()) as { error: string };
    assert.equal(travUploadJson.error, 'UPLOAD_SECURITY_VIOLATION');
  } finally {
    if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
  }
});

test('SEC-001 & SEC-004: Deployment mode classification, fail-closed REMOTE_DEPLOYMENT auth, brute-force lockout, structured audit log with zero secrets, and preserved local unrestricted mode', async () => {
  // 1. Deployment mode resolver checks
  assert.equal(resolveDeploymentMode({ deploymentMode: 'LOCAL_DESKTOP' }), 'LOCAL_DESKTOP');
  assert.equal(resolveDeploymentMode({ deploymentMode: 'LOCAL_WEB' }), 'LOCAL_WEB');
  assert.equal(resolveDeploymentMode({ deploymentMode: 'REMOTE_DEPLOYMENT' }), 'REMOTE_DEPLOYMENT');
  assert.equal(resolveDeploymentMode({ environment: 'ELECTRON_DESKTOP' }), 'LOCAL_DESKTOP');
  assert.equal(resolveDeploymentMode({ environment: 'REMOTE_DEPLOYMENT' }), 'REMOTE_DEPLOYMENT');

  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-sec001-'));
  let server: http.Server | null = null;
  try {
    // 2. REMOTE_DEPLOYMENT refuses insecure startup without >=32 char token
    await assert.rejects(
      () =>
        createWinHoodApp({
          dataDir: tmpDataDir,
          deploymentMode: 'REMOTE_DEPLOYMENT',
          remoteApiToken: 'too-short',
        }),
      /REMOTE_DEPLOYMENT_TOKEN_REQUIRED/
    );

    // 3. REMOTE_DEPLOYMENT with strong token enforces auth, lockout, and audit trail
    const strongRemoteToken = `wh_remote_${crypto.randomBytes(24).toString('hex')}`;
    const { app, getDb } = await createWinHoodApp({
      dataDir: tmpDataDir,
      deploymentMode: 'REMOTE_DEPLOYMENT',
      remoteApiToken: strongRemoteToken,
    });
    server = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    // Health exposes deploymentMode and masks host filesystem dataDir in remote mode
    const healthRes = await fetch(`${baseUrl}/api/health`);
    assert.equal(healthRes.status, 200);
    const healthJson = (await healthRes.json()) as {
      deploymentMode: string;
      accessMode: string;
      dataDir: string;
    };
    assert.equal(healthJson.deploymentMode, 'REMOTE_DEPLOYMENT');
    assert.equal(healthJson.accessMode, 'REMOTE_TOKEN_PROTECTED');
    assert.equal(healthJson.dataDir, '[RESTRICTED_IN_REMOTE_MODE]');

    // Unauthenticated mutation is blocked with 401
    const unauthRes = await fetch(`${baseUrl}/api/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Unauthorized', objective: 'Must fail' }),
    });
    assert.equal(unauthRes.status, 401);

    // Valid Bearer token succeeds and logs remote operator identity in audit trail
    const authCreate = await fetch(`${baseUrl}/api/projects`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${strongRemoteToken}`,
      },
      body: JSON.stringify({ name: 'AuthorizedRemoteProj', objective: 'Remote audit check' }),
    });
    assert.equal(authCreate.status, 201);

    // 5 consecutive invalid tokens trigger brute-force lockout (429)
    for (let i = 0; i < 5; i++) {
      const badTry = await fetch(`${baseUrl}/api/projects`, {
        headers: { Authorization: 'Bearer invalid-wrong-secret-token-value' },
      });
      assert.equal(badTry.status, 401);
    }
    const lockedRes = await fetch(`${baseUrl}/api/projects`, {
      headers: { Authorization: `Bearer ${strongRemoteToken}` },
    });
    assert.equal(lockedRes.status, 429);

    // Audit log contains structured remote entries, zero raw secret exposure, and valid integrity hashes
    const logs = getDb().auditLogs;
    assert.ok(logs.some((l) => l.action === 'REMOTE_AUTH_DENIED' && l.details.includes('mode=REMOTE_DEPLOYMENT')));
    assert.ok(logs.some((l) => l.action === 'REMOTE_AUTH_LOCKED' && l.details.includes('BRUTE_FORCE_LOCKOUT')));
    assert.ok(logs.some((l) => l.action === 'REMOTE_WRITE_AUTHORIZED' && l.role === 'REMOTE_OPERATOR'));
    const serializedLogs = JSON.stringify(logs);
    assert.equal(serializedLogs.includes(strongRemoteToken), false, 'Remote token must never appear in audit logs');
    assert.equal(serializedLogs.includes('invalid-wrong-secret-token-value'), false, 'Invalid token must never appear in audit logs');
  } finally {
    if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
  }
});

test('SEC-002: Trust proxy is disabled by default (ignores spoofed X-Forwarded-For) and honors explicit validated hop configuration', async () => {
  assert.equal(resolveTrustProxyConfig(undefined), false);
  assert.equal(resolveTrustProxyConfig('false'), false);
  assert.equal(resolveTrustProxyConfig('0'), false);
  assert.equal(resolveTrustProxyConfig('invalid-hop-value'), false);
  assert.equal(resolveTrustProxyConfig('99'), false);
  assert.equal(resolveTrustProxyConfig('true'), 1);
  assert.equal(resolveTrustProxyConfig('2'), 2);
  assert.equal(resolveTrustProxyConfig('loopback'), 'loopback');
  assert.deepEqual(resolveTrustProxyConfig('127.0.0.1, 10.0.0.0/8'), ['127.0.0.1', '10.0.0.0/8']);

  // 1. Trust proxy DISABLED (default): spoofing X-Forwarded-For cannot bypass rate limiter
  const tmpDirA = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-tp-off-'));
  let srvA: http.Server | null = null;
  try {
    const { app, trustProxyConfig } = await createWinHoodApp({
      dataDir: tmpDirA,
      trustProxy: false,
      rateLimits: { ingestionMax: 2, windowMs: 60_000 },
    });
    assert.equal(trustProxyConfig, false);
    srvA = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const baseUrl = `http://127.0.0.1:${(srvA.address() as AddressInfo).port}`;

    for (let i = 0; i < 2; i++) {
      const r = await fetch(`${baseUrl}/api/projects/upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Forwarded-For': `203.0.113.${10 + i}`,
        },
        body: JSON.stringify({
          name: `Proj-${i}`,
          objective: 'Test rate limit without trust proxy',
          filesMap: { 'a.ts': 'export const a = 1;' },
        }),
      });
      assert.equal(r.status, 201);
    }
    // Third request with a DIFFERENT spoofed X-Forwarded-For MUST still be rate-limited (429) because trust proxy is false
    const spoofedThird = await fetch(`${baseUrl}/api/projects/upload`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '198.51.100.77',
      },
      body: JSON.stringify({
        name: 'Proj-Spoof',
        objective: 'Should be rate limited despite spoofed XFF',
        filesMap: { 'a.ts': 'export const a = 1;' },
      }),
    });
    assert.equal(spoofedThird.status, 429);
  } finally {
    if (srvA) await new Promise<void>((resolve) => srvA!.close(() => resolve()));
    fs.rmSync(tmpDirA, { recursive: true, force: true });
  }

  // 2. Trust proxy ENABLED (1 hop): distinct upstream client IPs via trusted proxy get distinct buckets
  const tmpDirB = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-tp-on-'));
  let srvB: http.Server | null = null;
  try {
    const { app, trustProxyConfig } = await createWinHoodApp({
      dataDir: tmpDirB,
      trustProxy: 1,
      rateLimits: { ingestionMax: 1, windowMs: 60_000 },
    });
    assert.equal(trustProxyConfig, 1);
    srvB = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const baseUrl = `http://127.0.0.1:${(srvB.address() as AddressInfo).port}`;

    const firstClient = await fetch(`${baseUrl}/api/projects/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': '203.0.113.1' },
      body: JSON.stringify({
        name: 'Client1',
        objective: 'Trusted proxy client 1',
        filesMap: { 'a.ts': 'export const a = 1;' },
      }),
    });
    assert.equal(firstClient.status, 201);

    const secondClient = await fetch(`${baseUrl}/api/projects/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': '203.0.113.2' },
      body: JSON.stringify({
        name: 'Client2',
        objective: 'Trusted proxy client 2',
        filesMap: { 'b.ts': 'export const b = 2;' },
      }),
    });
    assert.equal(secondClient.status, 201);
  } finally {
    if (srvB) await new Promise<void>((resolve) => srvB!.close(() => resolve()));
    fs.rmSync(tmpDirB, { recursive: true, force: true });
  }
});

test('KeyManagementService enforces secret domain separation, production fail-closed checks, rotation, revocation, and Ed25519 trust store verification', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-kms-extra-'));
  const storePath = path.join(tmpDir, 'keystore.json');
  const prevMaster = process.env.WINHOOD_KEYSTORE_MASTER_SECRET;
  const prevHmac = process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
  const prevVault = process.env.WINHOOD_VAULT_SECRET;
  const prevSalt = process.env.SONAR_SECRET_SALT;
  const prevMode = process.env.WINHOOD_KEYSTORE_MODE;

  try {
    // 1. Domain separation violation detections
    process.env.WINHOOD_KEYSTORE_MASTER_SECRET = 'shared-secret-value-for-domain-test-1234';
    process.env.SONAR_SECRET_SALT = 'shared-secret-value-for-domain-test-1234';
    assert.throws(() => KeyManagementService.assertSecretDomainSeparation(), /KEYSTORE_SECRET_DOMAIN_VIOLATION/);
    delete process.env.SONAR_SECRET_SALT;

    process.env.WINHOOD_EVIDENCE_HMAC_SECRET = 'shared-secret-value-for-domain-test-1234';
    assert.throws(() => KeyManagementService.assertSecretDomainSeparation(), /KEYSTORE_SECRET_DOMAIN_VIOLATION/);
    delete process.env.WINHOOD_EVIDENCE_HMAC_SECRET;

    process.env.WINHOOD_VAULT_SECRET = 'shared-secret-value-for-domain-test-1234';
    assert.throws(() => KeyManagementService.assertSecretDomainSeparation(), /KEYSTORE_SECRET_DOMAIN_VIOLATION/);
    delete process.env.WINHOOD_VAULT_SECRET;

    // 2. Operating mode resolution & full key lifecycle with external master secret
    process.env.WINHOOD_KEYSTORE_MODE = 'PRODUCTION_SECURE';
    assert.equal(KeyManagementService.resolveOperatingMode(), 'PRODUCTION_SECURE');

    const status1 = KeyManagementService.getStatus(storePath);
    assert.equal(status1.integrityVerified, true);
    assert.equal(status1.kekProtectionMechanism, 'HKDF_EXTERNAL_ENV');
    assert.ok(status1.activeEd25519KeyId);

    // Rotate HMAC & Ed25519 keys and verify status + trust store
    const rotatedHmac = KeyManagementService.rotateKey('EVIDENCE_HMAC', storePath);
    assert.notEqual(rotatedHmac.keyId, status1.activeEvidenceKeyId);

    const rotatedEd = KeyManagementService.rotateKey('EVIDENCE_ED25519', storePath);
    assert.notEqual(rotatedEd.keyId, status1.activeEd25519KeyId);
    const activeEdPair = KeyManagementService.getActiveEvidenceEd25519Key(storePath);

    const pubVerify = KeyManagementService.verifyTrustedEd25519PublicKey(
      rotatedEd.keyId,
      activeEdPair.publicKeyPem,
      undefined,
      storePath
    );
    assert.equal(pubVerify.trusted, true);

    // Verify missing keyId and tampered PEM are rejected by Trust Store
    assert.equal(
      KeyManagementService.verifyTrustedEd25519PublicKey(undefined, undefined, undefined, storePath).trusted,
      false
    );
    assert.equal(
      KeyManagementService.verifyTrustedEd25519PublicKey('nonexistent-key', undefined, undefined, storePath).trusted,
      false
    );
    assert.equal(
      KeyManagementService.verifyTrustedEd25519PublicKey(
        rotatedEd.keyId,
        '-----BEGIN PUBLIC KEY-----\nTAMPERED\n-----END PUBLIC KEY-----',
        undefined,
        storePath
      ).trusted,
      false
    );

    // Rotate VAULT_AES and resolve active & retired keys by ID
    const initialVault = KeyManagementService.getActiveVaultAesKey(storePath);
    assert.equal(initialVault.keyBuffer.length, 32);
    const rotatedVault = KeyManagementService.rotateKey('TOKEN_VAULT_AES256', storePath);
    assert.notEqual(rotatedVault.keyId, initialVault.keyId);
    const resolvedRetiredVault = KeyManagementService.getVaultKeyBufferByKeyId(initialVault.keyId, storePath);
    assert.ok(resolvedRetiredVault && resolvedRetiredVault.length === 32);
    assert.ok(KeyManagementService.getEvidenceSecretByKeyId(rotatedHmac.keyId, storePath));
    assert.ok(KeyManagementService.getEd25519PublicKeyByKeyId(rotatedEd.keyId, storePath));

    // Revoke previous keys and confirm fail-closed rejection
    KeyManagementService.revokeKey(status1.activeEd25519KeyId, 'Auditoria de revogação Ed25519', storePath);
    KeyManagementService.revokeKey(initialVault.keyId, 'Auditoria de revogação Vault', storePath);
    assert.equal(
      KeyManagementService.verifyTrustedEd25519PublicKey(status1.activeEd25519KeyId, undefined, undefined, storePath)
        .trusted,
      false
    );
    assert.equal(KeyManagementService.getVaultKeyBufferByKeyId(initialVault.keyId, storePath), null);

    // External env vault key + legacy decrypt-only key resolution + strict admin token check
    const prevAdmin = process.env.WINHOOD_ADMIN_TOKEN;
    try {
      process.env.WINHOOD_VAULT_SECRET = 'distinct-vault-secret-for-test-99999';
      assert.equal(KeyManagementService.getActiveVaultAesKey(storePath).origin, 'ENV_EXTERNAL');
      assert.ok(KeyManagementService.getVaultKeyBufferByKeyId('ENV-VAULT-KEY', storePath));
      delete process.env.WINHOOD_VAULT_SECRET;

      process.env.SONAR_SECRET_SALT = 'distinct-legacy-sonar-salt-for-test-88888';
      assert.ok(KeyManagementService.getVaultKeyBufferByKeyId('ENV-VAULT-KEY', storePath));
      assert.ok(KeyManagementService.getVaultKeyBufferByKeyId('LEGACY-SONAR-SALT-KEY', storePath));
      delete process.env.SONAR_SECRET_SALT;

      assert.equal(KeyManagementService.getVaultKeyBufferByKeyId('ENV-VAULT-KEY', storePath), null);
      assert.equal(KeyManagementService.getVaultKeyBufferByKeyId('LEGACY-SONAR-SALT-KEY', storePath), null);

      process.env.WINHOOD_ADMIN_TOKEN = 'strict-admin-token-check-xyz-12345';
      assert.equal(KeyManagementService.verifyStrictAdminToken('strict-admin-token-check-xyz-12345', storePath), true);
      assert.equal(KeyManagementService.verifyStrictAdminToken('wrong-token', storePath), false);
      assert.equal(KeyManagementService.verifyStrictAdminToken('', storePath), false);
    } finally {
      if (prevAdmin === undefined) delete process.env.WINHOOD_ADMIN_TOKEN;
      else process.env.WINHOOD_ADMIN_TOKEN = prevAdmin;
    }

    const statusAfter = KeyManagementService.getStatus(storePath);
    assert.ok(statusAfter.rotationHistory.length >= 3);
    assert.ok(statusAfter.trustedPublicKeysCount >= 2);

    // Confirm zlib import used for compressed test helper check (noop sanity)
    assert.ok(typeof zlib.inflateRawSync === 'function');
  } finally {
    if (prevMaster === undefined) delete process.env.WINHOOD_KEYSTORE_MASTER_SECRET;
    else process.env.WINHOOD_KEYSTORE_MASTER_SECRET = prevMaster;
    if (prevHmac === undefined) delete process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
    else process.env.WINHOOD_EVIDENCE_HMAC_SECRET = prevHmac;
    if (prevVault === undefined) delete process.env.WINHOOD_VAULT_SECRET;
    else process.env.WINHOOD_VAULT_SECRET = prevVault;
    if (prevSalt === undefined) delete process.env.SONAR_SECRET_SALT;
    else process.env.SONAR_SECRET_SALT = prevSalt;
    if (prevMode === undefined) delete process.env.WINHOOD_KEYSTORE_MODE;
    else process.env.WINHOOD_KEYSTORE_MODE = prevMode;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

/**
 * Helper to build a real DEFLATE (method 8) ZIP archive buffer with EOCD (or LFH-only).
 */
function buildDeflatedZipBuffer(
  entries: Array<{ name: string; rawData: Buffer }>,
  includeEocd = true
): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const compressed = zlib.deflateRawSync(entry.rawData, { level: 9 });
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(8, 8); // DEFLATE
    lfh.writeUInt32LE(compressed.length, 18);
    lfh.writeUInt32LE(entry.rawData.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);

    localParts.push(lfh, nameBuf, compressed);

    if (includeEocd) {
      const cdh = Buffer.alloc(46);
      cdh.writeUInt32LE(0x02014b50, 0);
      cdh.writeUInt16LE(20, 4);
      cdh.writeUInt16LE(20, 6);
      cdh.writeUInt16LE(8, 10); // DEFLATE
      cdh.writeUInt32LE(compressed.length, 20);
      cdh.writeUInt32LE(entry.rawData.length, 24);
      cdh.writeUInt16LE(nameBuf.length, 28);
      cdh.writeUInt32LE(offset, 42);
      centralParts.push(cdh, nameBuf);
    }

    offset += 30 + nameBuf.length + compressed.length;
  }

  if (!includeEocd) {
    return Buffer.concat(localParts);
  }

  const centralDir = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDir.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...localParts, centralDir, eocd]);
}

test('WH-AUD-003: extractZipBufferToFilesMap and /api/projects/extract-zip block ZIP bombs (high compression ratio, >2000 entries, cumulative >64MB)', async () => {
  // 1. High compression ratio >= 100x (compressed >= 1KB, uncompressed ~1.8MB of repeated ASCII)
  const bombPayload = Buffer.alloc(1_800_000, 0x41); // 'A' repeated -> compresses to ~1.7KB (> 1000x ratio)
  const ratioBombZip = buildDeflatedZipBuffer([{ name: 'src/bomb.ts', rawData: bombPayload }], true);
  assert.throws(
    () => extractZipBufferToFilesMap(ratioBombZip),
    /ZIP_BOMB_BLOCKED/
  );

  // Also test LFH-only fallback path without EOCD
  const lfhOnlyBombZip = buildDeflatedZipBuffer([{ name: 'src/bomb.ts', rawData: bombPayload }], false);
  assert.throws(
    () => extractZipBufferToFilesMap(lfhOnlyBombZip),
    /ZIP_BOMB_BLOCKED/
  );

  // 2. Excess entry count (> MAX_ZIP_ENTRIES = 2000)
  const tooManyEntries = Array.from({ length: MAX_ZIP_ENTRIES + 1 }, (_, i) => ({
    name: `src/file_${i}.ts`,
    content: Buffer.from(`export const x${i} = ${i};`, 'utf8'),
  }));
  const floodZip = buildStoredZipBuffer(tooManyEntries);
  assert.throws(
    () => extractZipBufferToFilesMap(floodZip),
    /ZIP_BOMB_BLOCKED/
  );

  // 3. Cumulative uncompressed volume > 64MB across multiple <= 2MB entries (34 x 2MB = 68MB)
  const pseudoRandom2Mb = crypto.randomBytes(2 * 1024 * 1024).toString('base64').slice(0, 1_950_000);
  const entryBuf = Buffer.from(pseudoRandom2Mb, 'utf8');
  const cumulativeEntries = Array.from({ length: 35 }, (_, i) => ({
    name: `src/chunk_${i}.txt`,
    content: entryBuf,
  }));
  const cumulativeZip = buildStoredZipBuffer(cumulativeEntries);
  assert.throws(
    () => extractZipBufferToFilesMap(cumulativeZip),
    /ZIP_BOMB_BLOCKED/
  );

  // 4. End-to-end HTTP check on /api/projects/extract-zip -> HTTP 400 with error: ZIP_BOMB_BLOCKED
  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-zipbomb-http-'));
  let srv: http.Server | null = null;
  try {
    const { app, dispose } = await createWinHoodApp({ dataDir: tmpDataDir });
    srv = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const baseUrl = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;

    const bombRes = await fetch(`${baseUrl}/api/projects/extract-zip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ zipBase64: ratioBombZip.toString('base64') }),
    });
    assert.equal(bombRes.status, 400);
    const bombJson = (await bombRes.json()) as { error: string; message: string };
    assert.equal(bombJson.error, 'ZIP_BOMB_BLOCKED');
    assert.ok(bombJson.message.includes('ZIP_BOMB_BLOCKED'));

    const floodRes = await fetch(`${baseUrl}/api/projects/extract-zip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ zipBase64: floodZip.toString('base64') }),
    });
    assert.equal(floodRes.status, 400);
    const floodJson = (await floodRes.json()) as { error: string };
    assert.equal(floodJson.error, 'ZIP_BOMB_BLOCKED');

    dispose();
  } finally {
    if (srv) await new Promise<void>((resolve) => srv!.close(() => resolve()));
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
  }
});

test('WH-AUD-005 & WH-AUD-006 & WH-AUD-009: Docker confinement/container guidance, bounded RemoteAuthFailureTracker + JSONL audit, and graceful shutdown', async () => {
  // 1. Bounded RemoteAuthFailureTracker enforces maxTrackedIps ceiling and pruning
  const tracker = new RemoteAuthFailureTracker({
    maxTrackedIps: 100,
    lockoutThreshold: 5,
    lockoutDurationMs: 60_000,
    entryTtlMs: 5000,
    cleanupIntervalMs: 60_000,
  });
  try {
    const t0 = 1_000_000;
    for (let i = 0; i < 150; i++) {
      tracker.recordFailure(`198.51.100.${i}`, t0);
    }
    assert.equal(tracker.size(), 100, 'Tracker must remain strictly bounded at maxTrackedIps');

    for (let i = 0; i < 5; i++) {
      tracker.recordFailure('203.0.113.55', t0 + 10);
    }
    assert.equal(tracker.isLocked('203.0.113.55', t0 + 20).locked, true);
    assert.ok(tracker.pruneExpired(t0 + 100_000) > 0, 'Expired entries must be pruned');
    assert.equal(tracker.size(), 0);
  } finally {
    tracker.dispose();
  }

  // 2. REMOTE_DEPLOYMENT writes failed auth events to append-only logs/security-auth-audit.jsonl without secret leakage
  const tmpRemoteDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-remote-jsonl-'));
  let remoteSrv: http.Server | null = null;
  try {
    const token = `wh_remote_${crypto.randomBytes(24).toString('hex')}`;
    const { app, dispose } = await createWinHoodApp({
      dataDir: tmpRemoteDir,
      deploymentMode: 'REMOTE_DEPLOYMENT',
      remoteApiToken: token,
    });
    remoteSrv = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const baseUrl = `http://127.0.0.1:${(remoteSrv.address() as AddressInfo).port}`;

    for (let i = 0; i < 6; i++) {
      await fetch(`${baseUrl}/api/projects`, {
        headers: { Authorization: 'Bearer wrong-token-must-never-leak' },
      });
    }

    const auditJsonlPath = path.join(tmpRemoteDir, 'logs', 'security-auth-audit.jsonl');
    assert.equal(fs.existsSync(auditJsonlPath), true, 'security-auth-audit.jsonl must be created');
    const lines = fs.readFileSync(auditJsonlPath, 'utf8').trim().split('\n');
    assert.equal(lines.length, 6, 'All 5 denied + 1 locked events must be logged to JSONL');
    const parsedEvents = lines.map((l) => JSON.parse(l) as { action: string; failureReason: string });
    assert.equal(parsedEvents[0]?.action, 'REMOTE_AUTH_DENIED');
    assert.equal(parsedEvents[5]?.action, 'REMOTE_AUTH_LOCKED');
    assert.equal(
      fs.readFileSync(auditJsonlPath, 'utf8').includes('wrong-token-must-never-leak'),
      false,
      'JSONL audit log must never leak raw bearer tokens'
    );
    dispose();
  } finally {
    if (remoteSrv) await new Promise<void>((resolve) => remoteSrv!.close(() => resolve()));
    fs.rmSync(tmpRemoteDir, { recursive: true, force: true });
  }

  // 3. WH-AUD-005: Docker status confines bind to 127.0.0.1:9000:9000 with pinned image, and DOCKER_LOCAL_WEB returns compose profile guidance
  const tmpDockerDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-docker-confine-'));
  const prevRuntimeEnv = process.env.WINHOOD_RUNTIME_ENV;
  let dockerSrv: http.Server | null = null;
  try {
    process.env.WINHOOD_RUNTIME_ENV = 'DOCKER_LOCAL_WEB';
    const { app, dispose } = await createWinHoodApp({ dataDir: tmpDockerDir });
    dockerSrv = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const baseUrl = `http://127.0.0.1:${(dockerSrv.address() as AddressInfo).port}`;

    const autoStartRes = await fetch(`${baseUrl}/api/sonar/docker-auto-start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    assert.equal(autoStartRes.status, 200);
    const autoStartJson = (await autoStartRes.json()) as {
      ok: boolean;
      runningInContainer: boolean;
      fallbackToNative: boolean;
      suggestedCommand: string;
    };
    assert.equal(autoStartJson.ok, false);
    assert.equal(autoStartJson.runningInContainer, true);
    assert.equal(autoStartJson.fallbackToNative, true);
    assert.equal(autoStartJson.suggestedCommand, 'docker compose --profile sonar up -d');

    const statusRes = await fetch(`${baseUrl}/api/sonar/docker-status`);
    assert.equal(statusRes.status, 200);
    const statusJson = (await statusRes.json()) as {
      runningInContainer: boolean;
      dockerContainerSuggestedCommand: string;
    };
    assert.equal(statusJson.runningInContainer, true);
    assert.equal(statusJson.dockerContainerSuggestedCommand, 'docker compose --profile sonar up -d');
    assert.equal(statusJson.dockerContainerSuggestedCommand.includes(':latest'), false);
    dispose();
  } finally {
    if (prevRuntimeEnv === undefined) delete process.env.WINHOOD_RUNTIME_ENV;
    else process.env.WINHOOD_RUNTIME_ENV = prevRuntimeEnv;
    if (dockerSrv) await new Promise<void>((resolve) => dockerSrv!.close(() => resolve()));
    fs.rmSync(tmpDockerDir, { recursive: true, force: true });
  }

  // 4. WH-AUD-009: registerGracefulShutdown flushes state and closes server idempotently
  let flushedCount = 0;
  const dummySrv = http.createServer((_req, res) => res.end('ok'));
  await new Promise<void>((resolve) => dummySrv.listen(0, '127.0.0.1', () => resolve()));
  const ctrl = registerGracefulShutdown({
    server: dummySrv,
    onBeforeClose: () => {
      flushedCount += 1;
    },
    signals: [],
  });
  const firstResult = await ctrl.shutdown('TEST_SHUTDOWN');
  const secondResult = await ctrl.shutdown('SECOND_CALL');
  assert.equal(firstResult.closed, true);
  assert.equal(firstResult.flushed, true);
  assert.equal(secondResult.reason, 'TEST_SHUTDOWN');
  assert.equal(flushedCount, 1, 'Graceful shutdown must be idempotent');
  ctrl.unregister();
});

async function getFreeLoopbackPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address() as AddressInfo;
      const freePort = address.port;
      probe.close(() => resolve(freePort));
    });
  });
}

test('Módulo 03: Docker Local-Web runtime detection, dynamic CORS, SPA fallback, standalone dist-server bundle & container contracts', async () => {
  // 1. Unit checks for resolveRuntimeEnv, parseValidPortNumber & buildAllowedOriginMap
  assert.equal(resolveRuntimeEnv({ runtimeEnv: 'DOCKER_LOCAL_WEB' }), 'DOCKER_LOCAL_WEB');
  assert.equal(resolveRuntimeEnv({ environment: 'DOCKER_LOCAL_WEB' }), 'DOCKER_LOCAL_WEB');
  assert.equal(
    resolveRuntimeEnv({ runtimeEnv: '', environment: undefined, dockerEnvFileExists: true }),
    'DOCKER_LOCAL_WEB'
  );
  assert.equal(
    resolveRuntimeEnv({ runtimeEnv: '', environment: 'ELECTRON_DESKTOP', dockerEnvFileExists: false }),
    'ELECTRON_DESKTOP'
  );
  assert.equal(
    resolveRuntimeEnv({ runtimeEnv: '', environment: undefined, dockerEnvFileExists: false }),
    'LOCAL_NODE'
  );

  assert.equal(parseValidPortNumber('3080'), 3080);
  assert.equal(parseValidPortNumber(0), null);
  assert.equal(parseValidPortNumber(70000), null);
  assert.equal(parseValidPortNumber('not-a-port'), null);

  const localOrigins = buildAllowedOriginMap({
    deploymentMode: 'LOCAL_WEB',
    effectivePort: 3040,
    winhoodPort: '3088',
    allowedOriginsEnv: 'http://localhost:4100',
  });
  assert.equal(localOrigins.get('http://localhost:3000'), 'http://localhost:3000');
  assert.equal(localOrigins.get('http://localhost:3040'), 'http://localhost:3040');
  assert.equal(localOrigins.get('http://127.0.0.1:3088'), 'http://127.0.0.1:3088');
  assert.equal(localOrigins.get('http://localhost:4100'), 'http://localhost:4100');

  const remoteOrigins = buildAllowedOriginMap({
    deploymentMode: 'REMOTE_DEPLOYMENT',
    effectivePort: 3040,
    winhoodPort: '3088',
  });
  assert.equal(remoteOrigins.has('http://localhost:3088'), false);

  // 2. startServer in production static mode (enableVite: false) with SPA fallback, /api/* 404 JSON, dynamic CORS, and loopback TOTP cookie
  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-docker-web-data-'));
  const tmpDistDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-docker-web-dist-'));
  const prevWinhoodPort = process.env.WINHOOD_PORT;
  const prevNodeEnv = process.env.NODE_ENV;
  const prevDataDir = process.env.WINHOOD_DATA_DIR;
  const prevMasterSecret = process.env.WINHOOD_KEYSTORE_MASTER_SECRET;
  let started: Awaited<ReturnType<typeof startServer>> | null = null;
  try {
    fs.mkdirSync(path.join(tmpDistDir, 'assets'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDistDir, 'index.html'),
      '<!doctype html><html><body><div id="root">WinHood SPA</div></body></html>',
      'utf8'
    );
    fs.writeFileSync(
      path.join(tmpDistDir, 'assets', 'bundle.js'),
      'console.log("winhood-static-asset");',
      'utf8'
    );

    process.env.WINHOOD_PORT = '3088';
    process.env.NODE_ENV = 'production';
    process.env.WINHOOD_DATA_DIR = tmpDataDir;
    process.env.WINHOOD_KEYSTORE_MASTER_SECRET = crypto.randomBytes(32).toString('hex');
    started = await startServer({
      dataDir: tmpDataDir,
      distPath: tmpDistDir,
      host: '127.0.0.1',
      port: 0,
      deploymentMode: 'LOCAL_WEB',
      environment: 'DOCKER_LOCAL_WEB',
      enableVite: false,
    });

    const healthRes = await fetch(`${started.url}/api/health`);
    assert.equal(healthRes.status, 200);
    const healthJson = (await healthRes.json()) as {
      deploymentMode: string;
      runtimeEnv: string;
      accessMode: string;
    };
    assert.equal(healthJson.deploymentMode, 'LOCAL_WEB');
    assert.equal(healthJson.runtimeEnv, 'DOCKER_LOCAL_WEB');
    assert.equal(healthJson.accessMode, 'UNRESTRICTED_LOCAL');

    const bootRes = await fetch(`${started.url}/api/bootstrap`);
    assert.equal(bootRes.status, 200);
    const bootJson = (await bootRes.json()) as {
      deploymentMode: string;
      runtimeEnv: string;
      accessMode: string;
    };
    assert.equal(bootJson.deploymentMode, 'LOCAL_WEB');
    assert.equal(bootJson.runtimeEnv, 'DOCKER_LOCAL_WEB');
    assert.equal(bootJson.accessMode, 'UNRESTRICTED_LOCAL');

    // Dynamic CORS allows configured WINHOOD_PORT (3088) and bound ephemeral port, blocks foreign origins
    const corsCustomRes = await fetch(`${started.url}/api/health`, {
      method: 'OPTIONS',
      headers: { Origin: 'http://localhost:3088' },
    });
    assert.equal(corsCustomRes.status, 204);
    assert.equal(corsCustomRes.headers.get('access-control-allow-origin'), 'http://localhost:3088');

    const corsBoundRes = await fetch(`${started.url}/api/health`, {
      method: 'OPTIONS',
      headers: { Origin: `http://localhost:${started.port}` },
    });
    assert.equal(corsBoundRes.status, 204);
    assert.equal(
      corsBoundRes.headers.get('access-control-allow-origin'),
      `http://localhost:${started.port}`
    );

    const corsBlockedRes = await fetch(`${started.url}/api/health`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://untrusted.example' },
    });
    assert.equal(corsBlockedRes.status, 403);

    // Static assets, SPA fallback, and strict /api/* 404 JSON
    const indexRes = await fetch(`${started.url}/`);
    assert.equal(indexRes.status, 200);
    assert.match(await indexRes.text(), /WinHood SPA/);

    const assetRes = await fetch(`${started.url}/assets/bundle.js`);
    assert.equal(assetRes.status, 200);
    assert.match(await assetRes.text(), /winhood-static-asset/);

    const spaRouteRes = await fetch(`${started.url}/projects/demo/reports`);
    assert.equal(spaRouteRes.status, 200);
    assert.match(await spaRouteRes.text(), /WinHood SPA/);

    const missingApiRes = await fetch(`${started.url}/api/does-not-exist-docker-check`);
    assert.equal(missingApiRes.status, 404);
    const missingApiJson = (await missingApiRes.json()) as { error: string };
    assert.equal(missingApiJson.error, 'ENDPOINT_NOT_FOUND');

    // POST /api/gitar/configure blocks cloud metadata SSRF upfront with HTTP 400 SSRF_BLOCKED
    const gitarSsrfRes = await fetch(`${started.url}/api/gitar/configure`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        gitProvider: 'GITHUB',
        apiBaseUrl: 'http://169.254.169.254',
      }),
    });
    assert.equal(gitarSsrfRes.status, 400);
    const gitarSsrfJson = (await gitarSsrfRes.json()) as { error: string; message: string };
    assert.equal(gitarSsrfJson.error, 'SSRF_BLOCKED');
    assert.match(gitarSsrfJson.message, /SSRF_BLOCKED/);

    // Optional TOTP cookies on http://127.0.0.1:<port> in NODE_ENV=production use SameSite=Strict without Secure
    const setupRes = await fetch(`${started.url}/api/totp/setup`, {
      method: 'POST',
    });
    assert.equal(setupRes.status, 200);
    const setupJson = (await setupRes.json()) as { secret: string };
    assert.ok(setupJson.secret.length >= 16);

    const { generateTotpCode } = await import('./OptionalTotpService');
    const validCode = generateTotpCode(setupJson.secret);
    const confirmRes = await fetch(`${started.url}/api/totp/confirm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: validCode }),
    });
    assert.equal(confirmRes.status, 200);
    const setCookies =
      typeof confirmRes.headers.getSetCookie === 'function'
        ? confirmRes.headers.getSetCookie()
        : [confirmRes.headers.get('set-cookie') || ''];
    const joinedCookies = setCookies.join('; ');
    assert.match(joinedCookies, /winhood_totp_unlock=/);
    assert.match(joinedCookies, /winhood_csrf=/);
    assert.match(joinedCookies, /SameSite=Strict/);
    assert.equal(/;\s*Secure\b/i.test(joinedCookies), false);
    assert.equal(
      fs.existsSync(path.join(tmpDataDir, 'keys', 'keystore.json')),
      true,
      'Keystore must persist inside WINHOOD_DATA_DIR/keys/ for Docker volume durability'
    );
    assert.equal(
      fs.existsSync(path.join(tmpDataDir, 'keys', 'trust-store.json')),
      true,
      'Trust store must persist inside WINHOOD_DATA_DIR/keys/ for Docker volume durability'
    );
  } finally {
    if (started) await started.close();
    if (prevWinhoodPort === undefined) delete process.env.WINHOOD_PORT;
    else process.env.WINHOOD_PORT = prevWinhoodPort;
    if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevNodeEnv;
    if (prevDataDir === undefined) delete process.env.WINHOOD_DATA_DIR;
    else process.env.WINHOOD_DATA_DIR = prevDataDir;
    if (prevMasterSecret === undefined) delete process.env.WINHOOD_KEYSTORE_MASTER_SECRET;
    else process.env.WINHOOD_KEYSTORE_MASTER_SECRET = prevMasterSecret;
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
    fs.rmSync(tmpDistDir, { recursive: true, force: true });
  }

  // 3. Standalone dist-server/server.mjs build & real process execution with SIGTERM graceful shutdown
  const rootDir = process.cwd();
  const bundlePath = path.join(rootDir, 'dist-server', 'server.mjs');
  execFileSync(process.execPath, [path.join(rootDir, 'scripts', 'build-server.mjs')], {
    cwd: rootDir,
    stdio: 'pipe',
  });
  assert.equal(fs.existsSync(bundlePath), true, 'dist-server/server.mjs must be built');
  const bundleCode = fs.readFileSync(bundlePath, 'utf8');
  assert.equal(
    /^\s*import\s+[\s\S]*?\s+from\s+["']vite["']/m.test(bundleCode),
    false,
    'Production server bundle must not statically import vite'
  );

  const freePort = await getFreeLoopbackPort();
  const tmpStandaloneDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-standalone-bundle-'));
  const child = spawn(process.execPath, [bundlePath], {
    cwd: rootDir,
    env: {
      ...process.env,
      NODE_ENV: 'production',
      PORT: String(freePort),
      WINHOOD_PORT: '3099',
      WINHOOD_DEPLOYMENT_MODE: 'LOCAL_WEB',
      WINHOOD_RUNTIME_ENV: 'DOCKER_LOCAL_WEB',
      WINHOOD_ALLOW_NETWORK_BIND: 'false',
      WINHOOD_DATA_DIR: tmpStandaloneDir,
      WINHOOD_KEYSTORE_MASTER_SECRET: crypto.randomBytes(32).toString('hex'),
    },
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });

  try {
    let healthy = false;
    for (let attempt = 0; attempt < 40; attempt++) {
      try {
        const res = await fetch(`http://127.0.0.1:${freePort}/api/health`);
        if (res.ok) {
          const body = (await res.json()) as {
            status: string;
            runtimeEnv: string;
            deploymentMode: string;
          };
          assert.equal(body.status, 'ONLINE');
          assert.equal(body.runtimeEnv, 'DOCKER_LOCAL_WEB');
          assert.equal(body.deploymentMode, 'LOCAL_WEB');
          healthy = true;
          break;
        }
      } catch {
        await new Promise((r) => setTimeout(r, 150));
      }
    }
    assert.equal(healthy, true, 'Standalone dist-server/server.mjs must become healthy');

    const preflightRes = await fetch(`http://127.0.0.1:${freePort}/api/health`, {
      method: 'OPTIONS',
      headers: { Origin: 'http://localhost:3099' },
    });
    assert.equal(preflightRes.status, 204);
    assert.equal(preflightRes.headers.get('access-control-allow-origin'), 'http://localhost:3099');

    const exitResultPromise = new Promise<{
      exitCode: number | null;
      signal: NodeJS.Signals | null;
      timedOut: boolean;
    }>((resolve) => {
      child.once('exit', (code, signal) =>
        resolve({ exitCode: code, signal: signal ?? null, timedOut: false })
      );
    });
    if (process.platform === 'win32' && typeof child.send === 'function' && child.connected) {
      child.send({ type: 'WINHOOD_GRACEFUL_SHUTDOWN', reason: 'TEST_WINDOWS_SHUTDOWN' });
    } else {
      child.kill('SIGTERM');
    }
    const exitResult = await Promise.race([
      exitResultPromise,
      new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null; timedOut: boolean }>(
        (resolve) =>
          setTimeout(() => resolve({ exitCode: null, signal: null, timedOut: true }), 8000)
      ),
    ]);
    assert.equal(exitResult.timedOut, false, 'Standalone server graceful shutdown must not time out');
    assert.equal(
      exitResult.exitCode,
      0,
      `Standalone server must exit cleanly with code 0 (got code=${exitResult.exitCode}, signal=${exitResult.signal})`
    );
  } finally {
    if (child.exitCode === null) {
      child.kill('SIGKILL');
    }
    fs.rmSync(tmpStandaloneDir, { recursive: true, force: true });
  }

  // 4. Hardened Docker, Scanner Worker & 1-click distribution file contracts
  const dockerfile = fs.readFileSync(path.join(rootDir, 'Dockerfile'), 'utf8');
  assert.match(dockerfile, /FROM node:22\.\d+\.\d+-bookworm-slim AS builder/);
  assert.match(dockerfile, /FROM node:22\.\d+\.\d+-bookworm-slim AS deps/);
  assert.match(dockerfile, /FROM node:22\.\d+\.\d+-bookworm-slim AS runtime/);
  assert.equal(dockerfile.includes(':latest'), false, 'Dockerfile must never use :latest');
  assert.match(dockerfile, /USER winhood/);
  assert.match(dockerfile, /HEALTHCHECK/);
  assert.match(dockerfile, /WINHOOD_TEMP_WORKSPACE_DIR=\/tmp\/winhood-workspaces/);
  assert.match(dockerfile, /CMD \["node", "dist-server\/server\.mjs"\]/);
  assert.match(dockerfile, /npm ci --omit=dev --ignore-scripts/);

  const workerDockerfile = fs.readFileSync(path.join(rootDir, 'Dockerfile.scanner-worker'), 'utf8');
  assert.match(workerDockerfile, /FROM node:22\.\d+\.\d+-bookworm-slim AS worker-builder/);
  assert.match(workerDockerfile, /FROM node:22\.\d+\.\d+-bookworm-slim AS worker-deps/);
  assert.match(workerDockerfile, /FROM node:22\.\d+\.\d+-bookworm-slim AS worker-runtime/);
  assert.equal(workerDockerfile.includes(':latest'), false, 'Dockerfile.scanner-worker must never use :latest');
  assert.match(workerDockerfile, /COPY --from=worker-deps --chown=winhood:winhood \/app\/node_modules \.\/node_modules/);
  assert.match(workerDockerfile, /COPY --chown=winhood:winhood security\/semgrep-offline-rules \/opt\/winhood-scanner-rules/);
  assert.match(workerDockerfile, /WINHOOD_SCANNER_WORKER_CONTAINER=true/);
  assert.match(workerDockerfile, /GRYPE_DB_AUTO_UPDATE=false/);
  assert.match(workerDockerfile, /import\('express'\)/);
  assert.match(workerDockerfile, /USER winhood/);
  assert.match(workerDockerfile, /HEALTHCHECK/);
  assert.match(workerDockerfile, /CMD \["node", "dist-server\/scanner-worker\.mjs"\]/);

  const dockerignore = fs.readFileSync(path.join(rootDir, '.dockerignore'), 'utf8');
  assert.match(dockerignore, /^\.env\.docker$/m);
  assert.match(dockerignore, /^dist-server$/m);
  assert.match(dockerignore, /^!LICENSE$/m);
  assert.match(dockerignore, /^!SECURITY\.md$/m);

  const compose = fs.readFileSync(path.join(rootDir, 'docker-compose.yml'), 'utf8');
  assert.match(compose, /127\.0\.0\.1:\$\{WINHOOD_PORT:-3000\}:3000/);
  assert.match(compose, /127\.0\.0\.1:9000:9000/);
  assert.match(compose, /cap_drop:\s*\n\s*-\s*ALL/);
  assert.match(compose, /no-new-privileges:true/);
  assert.match(compose, /winhood_data:\/data\/winhood/);
  assert.match(compose, /winhood_scanner_cache:\/data\/scanner-cache/);
  assert.match(compose, /winhood-scanner-worker:/);
  assert.match(compose, /WINHOOD_SCANNER_WORKER_CONTAINER:\s*"true"/);
  assert.match(compose, /stop_grace_period:\s*20s/);
  assert.match(compose, /read_only: true/);
  assert.match(compose, /internal: true/);
  assert.match(compose, /WINHOOD_KEYSTORE_MASTER_SECRET/);
  assert.match(compose, /WINHOOD_SCANNER_WORKER_TOKEN/);
  assert.equal(
    compose.includes('${WINHOOD_KEYSTORE_MASTER_SECRET:?'),
    false,
    'docker-compose.yml must not block bare docker compose ps/logs/down with :? error interpolation'
  );
  assert.equal(
    compose.includes('${WINHOOD_SCANNER_WORKER_TOKEN:?'),
    false,
    'docker-compose.yml must not block bare docker compose ps/logs/down with :? error interpolation'
  );
  assert.equal(compose.includes('docker.sock'), false, 'docker-compose.yml must never mount docker.sock');
  assert.equal(compose.includes(':latest'), false, 'docker-compose.yml must never pin :latest');

  const envExample = fs.readFileSync(path.join(rootDir, '.env.docker.example'), 'utf8');
  assert.match(envExample, /^NODE_ENV=production$/m);
  assert.match(envExample, /^PORT=3000$/m);
  assert.match(envExample, /^WINHOOD_PORT=3000$/m);
  assert.match(envExample, /^WINHOOD_DEPLOYMENT_MODE=LOCAL_WEB$/m);
  assert.match(envExample, /^WINHOOD_RUNTIME_ENV=DOCKER_LOCAL_WEB$/m);
  assert.match(
    envExample,
    /^WINHOOD_KEYSTORE_MASTER_SECRET=(?:|replace-with-[a-z0-9-]+)$/m,
    '.env.docker.example must never ship a real master secret'
  );
  assert.match(
    envExample,
    /^WINHOOD_SCANNER_WORKER_TOKEN=(?:|replace-with-[a-z0-9-]+)$/m,
    '.env.docker.example must never ship a real worker token'
  );

  const dockerUpSh = fs.readFileSync(path.join(rootDir, 'scripts', 'docker-up.sh'), 'utf8');
  assert.match(dockerUpSh, /replace-with-\*/);
  const dockerUpPs1 = fs.readFileSync(path.join(rootDir, 'scripts', 'docker-up.ps1'), 'utf8');
  assert.match(dockerUpPs1, /StartsWith\('replace-with-'\)/);

  const gitignore = fs.readFileSync(path.join(rootDir, '.gitignore'), 'utf8');
  assert.match(gitignore, /^!\.env\.docker\.example$/m);
  assert.match(gitignore, /^\.env\.docker$/m);

  const pkgJson = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8')) as {
    dependencies: Record<string, string>;
    devDependencies: Record<string, string>;
  };
  assert.equal(pkgJson.dependencies['vite'], undefined);
  assert.equal(pkgJson.dependencies['@vitejs/plugin-react'], undefined);
  assert.equal(pkgJson.dependencies['@tailwindcss/vite'], undefined);
  assert.ok(pkgJson.devDependencies['vite']);
  assert.ok(pkgJson.devDependencies['@vitejs/plugin-react']);
  assert.ok(pkgJson.devDependencies['@tailwindcss/vite']);

  assert.equal(fs.existsSync(path.join(rootDir, 'scripts', 'docker-up.sh')), true);
  assert.equal(fs.existsSync(path.join(rootDir, 'scripts', 'docker-up.ps1')), true);
  assert.equal(fs.existsSync(path.join(rootDir, 'scripts', 'docker-down.sh')), true);
  assert.equal(fs.existsSync(path.join(rootDir, 'scripts', 'docker-down.ps1')), true);
  assert.equal(fs.existsSync(path.join(rootDir, 'scripts', 'docker-update-scanner-dbs.sh')), true);
  assert.equal(fs.existsSync(path.join(rootDir, 'scripts', 'docker-update-scanner-dbs.ps1')), true);
  assert.equal(fs.existsSync(path.join(rootDir, 'security', 'semgrep-offline-rules', 'winhood-core.yaml')), true);
  assert.equal(fs.existsSync(path.join(rootDir, 'scripts', 'verify-docker-local-web.mjs')), true);
  assert.equal(fs.existsSync(path.join(rootDir, 'DOCKER_LOCAL_WEB.md')), true);
});

test('Security & Quality Gate Regression: SSRF guard ranges, path confinement, safe target=_blank links, and zero NOSONAR/TS suppressions', async () => {
  const { isDisallowedIpAddress } = await import('../execution/SsrfGuard');
  const { ReferenceRegistry } = await import('../intelligence/reference/ReferenceRegistry');
  const { PersistentDatabaseManager } = await import('../storage/PersistentDatabaseManager');

  // 1. SSRF Guard blocks private, loopback, link-local, metadata, CGNAT, multicast, and IPv4-mapped IPv6
  const disallowedIps = [
    '10.0.0.1',
    '172.16.0.1',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '127.0.0.1',
    '224.0.0.1',
    '::1',
    '::ffff:169.254.169.254',
    'fc00::1',
    'fe80::1',
  ];
  for (const ip of disallowedIps) {
    assert.equal(isDisallowedIpAddress(ip).blocked, true, `Expected ${ip} to be blocked by SsrfGuard`);
  }
  assert.equal(isDisallowedIpAddress('8.8.8.8').blocked, false);
  assert.equal(isDisallowedIpAddress('1.1.1.1').blocked, false);

  // 2. ReferenceRegistry blocks path traversal source keys
  const tmpRefDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wh-ref-guard-'));
  try {
    const registry = new ReferenceRegistry(tmpRefDir);
    assert.throws(
      () => registry.getSnapshot('../../etc/passwd' as any),
      /traversal|inv[aá]lid/i,
      'ReferenceRegistry must reject path traversal source keys'
    );
  } finally {
    fs.rmSync(tmpRefDir, { recursive: true, force: true });
  }

  // 3. PersistentDatabaseManager rejects NUL-byte file paths
  const dbManager = new PersistentDatabaseManager();
  assert.throws(
    () => dbManager.writeAtomicChecksummed('/tmp/bad\0path.json', {}),
    /inv[aá]lid|nulo|nul/i,
    'PersistentDatabaseManager must reject paths containing NUL bytes'
  );

  // 4. Reverse Tabnabbing guard: every target="_blank" in SonarDockerCloudHubModule includes noopener
  const rootDir = process.cwd();
  const hubSrc = fs.readFileSync(path.join(rootDir, 'src', 'components', 'SonarDockerCloudHubModule.tsx'), 'utf8');
  const blankAnchorMatches = hubSrc.match(/<a\b[^>]*target="_blank"[^>]*>/g) || [];
  assert.ok(blankAnchorMatches.length >= 5, 'Expected external links in SonarDockerCloudHubModule.tsx');
  for (const anchorTag of blankAnchorMatches) {
    assert.match(anchorTag, /rel="[^"]*\bnoopener\b[^"]*"/, `External link missing rel="noopener": ${anchorTag}`);
  }

  // 5. Zero quality-fraud suppressions across production src/ files (excluding tests)
  const walkSrc = (dir: string, out: string[] = []): string[] => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walkSrc(full, out);
      } else if (/\.(?:ts|tsx)$/.test(entry.name) && !/\.(?:test|spec)\.(?:ts|tsx)$/.test(entry.name)) {
        out.push(full);
      }
    }
    return out;
  };
  const prodFiles = walkSrc(path.join(rootDir, 'src'));
  for (const file of prodFiles) {
    const content = fs.readFileSync(file, 'utf8');
    const rel = path.relative(rootDir, file).replace(/\\/g, '/');
    const hasActualNoSonarComment = content.split(/\r?\n/).some((line) => {
      const strippedStrings = line.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, '');
      return /\/\/\s*NOSONAR\b|\/\*\s*NOSONAR\b/.test(strippedStrings);
    });
    assert.equal(hasActualNoSonarComment, false, `Found forbidden // NOSONAR comment in ${rel}`);
    assert.equal(/@ts-(?:ignore|expect-error)\b/.test(content), false, `Found forbidden @ts-ignore/@ts-expect-error in ${rel}`);
    assert.equal(/eslint-disable/.test(content), false, `Found forbidden eslint-disable in ${rel}`);
  }
});

test('AUD-001..AUD-007 Regression: CI bash invocation & LF shell scripts, scoped SonarCloud properties, clean SsrfGuard metadata constant, audited CrossToolBenchmarkHarness, and clean health check', async () => {
  const rootDir = process.cwd();

  // 1. AUD-002 & AUD-003: .env.docker.example exists with non-secret placeholders, CI uses bash ./scripts/... and all scripts/*.sh use LF
  const envExample = fs.readFileSync(path.join(rootDir, '.env.docker.example'), 'utf8');
  assert.match(envExample, /^WINHOOD_DEPLOYMENT_MODE=LOCAL_WEB$/m);
  assert.match(envExample, /^WINHOOD_RUNTIME_ENV=DOCKER_LOCAL_WEB$/m);
  assert.match(envExample, /^WINHOOD_KEYSTORE_MASTER_SECRET=replace-with-/m);
  assert.match(envExample, /^WINHOOD_SCANNER_WORKER_TOKEN=replace-with-/m);

  const ciWorkflow = fs.readFileSync(
    path.join(rootDir, '.github', 'workflows', 'ci-multiplatform.yml'),
    'utf8'
  );
  assert.match(ciWorkflow, /bash \.\/scripts\/docker-up\.sh/);
  assert.match(ciWorkflow, /bash \.\/scripts\/docker-down\.sh/);
  assert.equal(/(^|\s)\.\/scripts\/docker-(?:up|down)\.sh/.test(ciWorkflow.replace(/bash \.\/scripts\/docker-(?:up|down)\.sh/g, '')), false);

  const scriptsDir = path.join(rootDir, 'scripts');
  for (const name of fs.readdirSync(scriptsDir).filter((f) => f.endsWith('.sh'))) {
    const raw = fs.readFileSync(path.join(scriptsDir, name), 'utf8');
    assert.equal(raw.includes('\r\n'), false, `Shell script scripts/${name} must use LF line endings`);
  }

  // 2. AUD-004 & AUD-005: sonar-project.properties does NOT exempt executable CrossToolBenchmarkHarness.ts; build.yml verifies relative SF:src/ LCOV paths
  const sonarProps = fs.readFileSync(path.join(rootDir, 'sonar-project.properties'), 'utf8');
  const activeSonarConfig = sonarProps
    .split(/\r?\n/)
    .filter((line) => !line.trim().startsWith('#'))
    .join('\n');
  assert.equal(activeSonarConfig.includes('CrossToolBenchmarkHarness.ts'), false, 'CrossToolBenchmarkHarness.ts must be audited by SonarCloud without exclusions');
  assert.equal(activeSonarConfig.includes('corpus3'), false, 'corpus3 wildcard exclusion must be removed');
  assert.match(activeSonarConfig, /^sonar\.issue\.ignore\.multicriteria=corpus1,corpus2$/m);
  assert.match(activeSonarConfig, /^sonar\.javascript\.lcov\.reportPaths=coverage\/lcov\.info$/m);

  const buildWorkflow = fs.readFileSync(path.join(rootDir, '.github', 'workflows', 'build.yml'), 'utf8');
  assert.match(buildWorkflow, /grep -q "\^SF:src\/" coverage\/lcov\.info/);

  // 3. AUD-007: SsrfGuard uses clear CLOUD_METADATA_IPV4 constant without array.join obfuscation
  const ssrfSrc = fs.readFileSync(path.join(rootDir, 'src', 'execution', 'SsrfGuard.ts'), 'utf8');
  assert.match(ssrfSrc, /const CLOUD_METADATA_IPV4 = '169\.254\.169\.254';/);
  assert.equal(ssrfSrc.includes('[169, 254, 169, 254]'), false);

  // 4. CrossToolBenchmarkHarness stays executable and preserves the 20-case synthetic validation corpus re-export
  const { CrossToolBenchmarkHarness, CONTROLLED_11_CLASS_VALIDATION_CORPUS } = await import(
    '../validation/CrossToolBenchmarkHarness'
  );
  assert.equal(CONTROLLED_11_CLASS_VALIDATION_CORPUS.length, 20);
  const harnessReport = CrossToolBenchmarkHarness.runComparison({});
  assert.equal(harnessReport.totalCases, 20);
  assert.ok((harnessReport.winhoodEvaluation.metrics.recall ?? 0) >= 0.8);

  // 5. AUD-006: waitForBackendHealth exits cleanly on unreachable loopback port without leaking timers
  const { waitForBackendHealth } = await import('../../electron-main');
  const unreachablePort = await new Promise<number>((resolve, reject) => {
    const tmpSrv = http.createServer();
    tmpSrv.listen(0, '127.0.0.1', () => {
      const addr = tmpSrv.address() as AddressInfo;
      tmpSrv.close((err) => (err ? reject(err) : resolve(addr.port)));
    });
  });
  const healthResult = await waitForBackendHealth({
    baseUrl: `http://127.0.0.1:${unreachablePort}`,
    port: unreachablePort,
    maxAttempts: 1,
    intervalMs: 10,
  });
  assert.equal(healthResult.healthy, false);
  assert.equal(healthResult.attempts, 1);
});



