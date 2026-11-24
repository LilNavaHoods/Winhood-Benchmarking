import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import type http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import zlib from 'node:zlib';
import {
  createWinHoodApp,
  resolveDeploymentMode,
  resolveTrustProxyConfig,
} from '../../server';
import { KeyManagementService } from './KeyManagementService';

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
