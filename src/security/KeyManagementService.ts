import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export type ManagedKeyPurpose =
  | 'EVIDENCE_HMAC'
  | 'EVIDENCE_ED25519'
  | 'TOKEN_VAULT_AES256'
  | 'ADMIN_RBAC';

export interface ManagedKeyRecord {
  keyId: string;
  purpose: ManagedKeyPurpose;
  createdAt: string;
  rotatedAt: string | null;
  status: 'ACTIVE' | 'RETIRED_VERIFY_ONLY';
  fingerprintSha256: string;
  algorithm: 'HMAC-SHA256' | 'ED25519' | 'AES-256-GCM';
}

interface StoredHmacOrAesKey {
  purpose: 'EVIDENCE_HMAC' | 'TOKEN_VAULT_AES256';
  secretHex: string;
  dpapiProtected?: boolean;
  createdAt: string;
  status: 'ACTIVE' | 'RETIRED_VERIFY_ONLY';
  rotatedAt: string | null;
}

interface StoredEd25519Key {
  purpose: 'EVIDENCE_ED25519';
  privateKeyPem: string;
  publicKeyPem: string;
  dpapiProtected?: boolean;
  createdAt: string;
  status: 'ACTIVE' | 'RETIRED_VERIFY_ONLY';
  rotatedAt: string | null;
}

interface PersistedKeyStore {
  version: number;
  activeEvidenceKeyId: string;
  activeEd25519KeyId: string;
  activeVaultKeyId: string;
  keysHex: Record<string, StoredHmacOrAesKey>;
  ed25519Keys: Record<string, StoredEd25519Key>;
  adminTokenSha256: string | null;
}

export interface KeyManagementStatus {
  keystorePath: string;
  integrityVerified: boolean;
  dpapiSupported: boolean;
  keyOrigin: 'ENV_EXTERNAL' | 'HOST_CSPRNG_KEYSTORE';
  activeEvidenceKeyId: string;
  activeEd25519KeyId: string;
  activeVaultKeyId: string;
  adminTokenConfigured: boolean;
  totalKeysTracked: number;
  keys: ManagedKeyRecord[];
}

export interface VaultReencryptContext {
  oldKeyId: string;
  oldKeyBuffer: Buffer;
  newKeyId: string;
  newKeyBuffer: Buffer;
}

function generateEd25519Pair(): { privateKeyPem: string; publicKeyPem: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

function tryDpapiProtectUtf8(plainText: string): { protectedText: string; usedDpapi: boolean } {
  if (os.platform() !== 'win32') {
    return { protectedText: plainText, usedDpapi: false };
  }
  try {
    const b64 = Buffer.from(plainText, 'utf8').toString('base64');
    const ps = [
      'Add-Type -AssemblyName System.Security;',
      `$bytes = [Convert]::FromBase64String('${b64}');`,
      '$prot = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser);',
      '[Convert]::ToBase64String($prot)',
    ].join(' ');
    const res = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], {
      shell: false,
      encoding: 'utf8',
      timeout: 5000,
    });
    if (res.status === 0 && res.stdout && res.stdout.trim().length > 0) {
      return { protectedText: res.stdout.trim(), usedDpapi: true };
    }
  } catch {
    // Fall back explicitly without claiming DPAPI protection
  }
  return { protectedText: plainText, usedDpapi: false };
}

function tryDpapiUnprotectUtf8(cipherB64OrPlain: string, wasProtected?: boolean): string {
  if (!wasProtected || os.platform() !== 'win32') {
    return cipherB64OrPlain;
  }
  const ps = [
    'Add-Type -AssemblyName System.Security;',
    `$bytes = [Convert]::FromBase64String('${cipherB64OrPlain}');`,
    '$unprot = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser);',
    '[System.Text.Encoding]::UTF8.GetString($unprot)',
  ].join(' ');
  const res = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], {
    shell: false,
    encoding: 'utf8',
    timeout: 5000,
  });
  if (res.status !== 0 || !res.stdout) {
    throw new Error('KEYSTORE_DPAPI_UNPROTECT_FAILED: Falha ao descriptografar chave via Windows DPAPI.');
  }
  return res.stdout.trim();
}

export class KeyManagementService {
  private static readonly DEFAULT_STORE_PATH = path.resolve(
    process.cwd(),
    '.winhood_data',
    'keys',
    'keystore.json'
  );

  private static getStorePath(customPath?: string): string {
    return customPath || process.env.WINHOOD_KEYSTORE_PATH || KeyManagementService.DEFAULT_STORE_PATH;
  }

  private static computeSha256(content: string): string {
    return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  }

  private static writeAtomicWithChecksum(storePath: string, payloadJson: string): void {
    const dir = path.dirname(storePath);
    fs.mkdirSync(dir, { recursive: true });
    const checksumPath = `${storePath}.sha256`;
    const backupPath = `${storePath}.bak`;

    if (fs.existsSync(storePath)) {
      try {
        fs.copyFileSync(storePath, backupPath);
        fs.chmodSync(backupPath, 0o600);
      } catch {
        // Non-fatal if backup copy failed before first write, main atomic write proceeds
      }
    }

    const tmpMain = `${storePath}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
    const fd = fs.openSync(tmpMain, 'w', 0o600);
    try {
      fs.writeFileSync(fd, payloadJson, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmpMain, storePath);
    fs.chmodSync(storePath, 0o600);

    const hash = KeyManagementService.computeSha256(payloadJson);
    const tmpHash = `${checksumPath}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
    const hfd = fs.openSync(tmpHash, 'w', 0o600);
    try {
      fs.writeFileSync(hfd, hash, 'utf8');
      fs.fsyncSync(hfd);
    } finally {
      fs.closeSync(hfd);
    }
    fs.renameSync(tmpHash, checksumPath);
    fs.chmodSync(checksumPath, 0o600);
  }

  private static readVerifiedStoreFile(storePath: string): { store: PersistedKeyStore; integrityVerified: boolean } | null {
    if (!fs.existsSync(storePath)) return null;

    const checksumPath = `${storePath}.sha256`;
    const raw = fs.readFileSync(storePath, 'utf8');

    if (fs.existsSync(checksumPath)) {
      const expectedSha = fs.readFileSync(checksumPath, 'utf8').trim();
      const actualSha = KeyManagementService.computeSha256(raw);
      if (expectedSha !== actualSha) {
        // Try backup if main corrupted
        const backupPath = `${storePath}.bak`;
        if (fs.existsSync(backupPath)) {
          const bakRaw = fs.readFileSync(backupPath, 'utf8');
          const bakParsed = JSON.parse(bakRaw) as PersistedKeyStore;
          if (bakParsed && bakParsed.keysHex && bakParsed.activeEvidenceKeyId && bakParsed.activeVaultKeyId) {
            return { store: bakParsed, integrityVerified: false };
          }
        }
        throw new Error(`KEYSTORE_INTEGRITY_VIOLATION: Checksum SHA-256 de ${storePath} não confere.`);
      }
    }

    const parsed = JSON.parse(raw) as PersistedKeyStore;
    if (!parsed || !parsed.keysHex || !parsed.activeEvidenceKeyId || !parsed.activeVaultKeyId) {
      throw new Error(`KEYSTORE_CORRUPTED: Estrutura inválida em ${storePath}.`);
    }

    let upgraded = false;
    if (!parsed.ed25519Keys || !parsed.activeEd25519KeyId) {
      const now = new Date().toISOString();
      const edId = `wh-ed25519-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
      const pair = generateEd25519Pair();
      const prot = tryDpapiProtectUtf8(pair.privateKeyPem);
      parsed.ed25519Keys = {
        [edId]: {
          purpose: 'EVIDENCE_ED25519',
          privateKeyPem: prot.protectedText,
          publicKeyPem: pair.publicKeyPem,
          dpapiProtected: prot.usedDpapi,
          createdAt: now,
          status: 'ACTIVE',
          rotatedAt: null,
        },
      };
      parsed.activeEd25519KeyId = edId;
      parsed.version = Math.max(2, parsed.version || 1);
      upgraded = true;
    }

    if (upgraded || !fs.existsSync(checksumPath)) {
      KeyManagementService.persistStore(parsed, storePath);
    }

    return { store: parsed, integrityVerified: true };
  }

  private static loadOrInitializeStore(customPath?: string): { store: PersistedKeyStore; integrityVerified: boolean } {
    const storePath = KeyManagementService.getStorePath(customPath);
    const existing = KeyManagementService.readVerifiedStoreFile(storePath);
    if (existing) {
      return existing;
    }

    const now = new Date().toISOString();
    const evidenceKeyId = `wh-hmac-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
    const ed25519KeyId = `wh-ed25519-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
    const vaultKeyId = `wh-vault-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;

    const hmacSecretHex = crypto.randomBytes(32).toString('hex');
    const vaultSecretHex = crypto.randomBytes(32).toString('hex');
    const hmacProt = tryDpapiProtectUtf8(hmacSecretHex);
    const vaultProt = tryDpapiProtectUtf8(vaultSecretHex);
    const edPair = generateEd25519Pair();
    const edProt = tryDpapiProtectUtf8(edPair.privateKeyPem);

    const initialStore: PersistedKeyStore = {
      version: 2,
      activeEvidenceKeyId: evidenceKeyId,
      activeEd25519KeyId: ed25519KeyId,
      activeVaultKeyId: vaultKeyId,
      keysHex: {
        [evidenceKeyId]: {
          purpose: 'EVIDENCE_HMAC',
          secretHex: hmacProt.protectedText,
          dpapiProtected: hmacProt.usedDpapi,
          createdAt: now,
          status: 'ACTIVE',
          rotatedAt: null,
        },
        [vaultKeyId]: {
          purpose: 'TOKEN_VAULT_AES256',
          secretHex: vaultProt.protectedText,
          dpapiProtected: vaultProt.usedDpapi,
          createdAt: now,
          status: 'ACTIVE',
          rotatedAt: null,
        },
      },
      ed25519Keys: {
        [ed25519KeyId]: {
          purpose: 'EVIDENCE_ED25519',
          privateKeyPem: edProt.protectedText,
          publicKeyPem: edPair.publicKeyPem,
          dpapiProtected: edProt.usedDpapi,
          createdAt: now,
          status: 'ACTIVE',
          rotatedAt: null,
        },
      },
      adminTokenSha256: process.env.WINHOOD_ADMIN_TOKEN
        ? crypto.createHash('sha256').update(process.env.WINHOOD_ADMIN_TOKEN, 'utf8').digest('hex')
        : null,
    };

    KeyManagementService.persistStore(initialStore, storePath);
    return { store: initialStore, integrityVerified: true };
  }

  private static persistStore(store: PersistedKeyStore, customPath?: string): void {
    const storePath = KeyManagementService.getStorePath(customPath);
    try {
      KeyManagementService.writeAtomicWithChecksum(storePath, JSON.stringify(store, null, 2));
    } catch (err: any) {
      throw new Error(
        `KEYSTORE_PERSISTENCE_FAILED: Não foi possível persistir o keystore de forma segura em ${storePath}: ${err?.message || String(err)}`
      );
    }
  }

  public static getActiveEvidenceHmacKey(customPath?: string): {
    keyId: string;
    secret: string;
    origin: 'ENV_EXTERNAL' | 'HOST_CSPRNG_KEYSTORE';
  } {
    const envSecret = process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
    if (envSecret && envSecret.trim().length >= 16) {
      return {
        keyId: process.env.WINHOOD_EVIDENCE_KEY_ID || 'ENV-HMAC-KEY',
        secret: envSecret.trim(),
        origin: 'ENV_EXTERNAL',
      };
    }

    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    const active = store.keysHex[store.activeEvidenceKeyId];
    return {
      keyId: store.activeEvidenceKeyId,
      secret: tryDpapiUnprotectUtf8(active.secretHex, active.dpapiProtected),
      origin: 'HOST_CSPRNG_KEYSTORE',
    };
  }

  public static getEvidenceSecretByKeyId(keyId: string, customPath?: string): string | null {
    const envSecret = process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
    const envKeyId = process.env.WINHOOD_EVIDENCE_KEY_ID || 'ENV-HMAC-KEY';
    if (envSecret && envSecret.trim().length >= 16 && keyId === envKeyId) {
      return envSecret.trim();
    }

    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    const entry = store.keysHex[keyId];
    return entry ? tryDpapiUnprotectUtf8(entry.secretHex, entry.dpapiProtected) : null;
  }

  public static getActiveEvidenceEd25519Key(customPath?: string): {
    keyId: string;
    privateKeyPem: string;
    publicKeyPem: string;
  } {
    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    const active = store.ed25519Keys[store.activeEd25519KeyId];
    return {
      keyId: store.activeEd25519KeyId,
      privateKeyPem: tryDpapiUnprotectUtf8(active.privateKeyPem, active.dpapiProtected),
      publicKeyPem: active.publicKeyPem,
    };
  }

  public static getEd25519PublicKeyByKeyId(keyId: string, customPath?: string): string | null {
    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    return store.ed25519Keys?.[keyId]?.publicKeyPem ?? null;
  }

  public static getActiveVaultAesKey(customPath?: string): {
    keyId: string;
    keyBuffer: Buffer;
    origin: 'ENV_EXTERNAL' | 'HOST_CSPRNG_KEYSTORE';
  } {
    const envVaultSecret = process.env.SONAR_SECRET_SALT || process.env.WINHOOD_VAULT_SECRET;
    if (envVaultSecret && envVaultSecret.trim().length >= 16) {
      return {
        keyId: 'ENV-VAULT-KEY',
        keyBuffer: crypto.createHash('sha256').update(envVaultSecret.trim(), 'utf8').digest(),
        origin: 'ENV_EXTERNAL',
      };
    }

    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    const active = store.keysHex[store.activeVaultKeyId];
    const hex = tryDpapiUnprotectUtf8(active.secretHex, active.dpapiProtected);
    return {
      keyId: store.activeVaultKeyId,
      keyBuffer: Buffer.from(hex, 'hex'),
      origin: 'HOST_CSPRNG_KEYSTORE',
    };
  }

  public static getVaultKeyBufferByKeyId(keyId: string, customPath?: string): Buffer | null {
    if (keyId === 'ENV-VAULT-KEY') {
      const envVaultSecret = process.env.SONAR_SECRET_SALT || process.env.WINHOOD_VAULT_SECRET;
      if (envVaultSecret && envVaultSecret.trim().length >= 16) {
        return crypto.createHash('sha256').update(envVaultSecret.trim(), 'utf8').digest();
      }
      return null;
    }

    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    const entry = store.keysHex[keyId];
    if (!entry) return null;
    const hex = tryDpapiUnprotectUtf8(entry.secretHex, entry.dpapiProtected);
    return Buffer.from(hex, 'hex');
  }

  public static rotateKey(
    purpose: 'EVIDENCE_HMAC' | 'EVIDENCE_ED25519' | 'TOKEN_VAULT_AES256',
    customPath?: string,
    onVaultReencrypt?: (ctx: VaultReencryptContext) => void
  ): ManagedKeyRecord {
    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    const now = new Date().toISOString();

    if (purpose === 'EVIDENCE_ED25519') {
      const prevKeyId = store.activeEd25519KeyId;
      if (store.ed25519Keys[prevKeyId]) {
        store.ed25519Keys[prevKeyId].status = 'RETIRED_VERIFY_ONLY';
        store.ed25519Keys[prevKeyId].rotatedAt = now;
      }

      const newKeyId = `wh-ed25519-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
      const pair = generateEd25519Pair();
      const prot = tryDpapiProtectUtf8(pair.privateKeyPem);

      store.ed25519Keys[newKeyId] = {
        purpose: 'EVIDENCE_ED25519',
        privateKeyPem: prot.protectedText,
        publicKeyPem: pair.publicKeyPem,
        dpapiProtected: prot.usedDpapi,
        createdAt: now,
        status: 'ACTIVE',
        rotatedAt: null,
      };
      store.activeEd25519KeyId = newKeyId;
      KeyManagementService.persistStore(store, customPath);

      return {
        keyId: newKeyId,
        purpose: 'EVIDENCE_ED25519',
        createdAt: now,
        rotatedAt: null,
        status: 'ACTIVE',
        fingerprintSha256: KeyManagementService.computeSha256(pair.publicKeyPem).slice(0, 16),
        algorithm: 'ED25519',
      };
    }

    const prevKeyId =
      purpose === 'EVIDENCE_HMAC' ? store.activeEvidenceKeyId : store.activeVaultKeyId;
    const prevEntry = store.keysHex[prevKeyId];
    const prevKeyBuffer =
      purpose === 'TOKEN_VAULT_AES256' && prevEntry
        ? Buffer.from(tryDpapiUnprotectUtf8(prevEntry.secretHex, prevEntry.dpapiProtected), 'hex')
        : null;

    const prefix = purpose === 'EVIDENCE_HMAC' ? 'wh-hmac' : 'wh-vault';
    const newKeyId = `${prefix}-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
    const rawSecretHex = crypto.randomBytes(32).toString('hex');
    const newKeyBuffer = Buffer.from(rawSecretHex, 'hex');

    // If rotating vault AES-256 key, invoke re-encryption BEFORE retiring old key.
    if (purpose === 'TOKEN_VAULT_AES256' && onVaultReencrypt && prevKeyBuffer) {
      onVaultReencrypt({
        oldKeyId: prevKeyId,
        oldKeyBuffer: prevKeyBuffer,
        newKeyId,
        newKeyBuffer,
      });
    }

    if (prevEntry) {
      prevEntry.status = 'RETIRED_VERIFY_ONLY';
      prevEntry.rotatedAt = now;
    }

    const prot = tryDpapiProtectUtf8(rawSecretHex);
    store.keysHex[newKeyId] = {
      purpose,
      secretHex: prot.protectedText,
      dpapiProtected: prot.usedDpapi,
      createdAt: now,
      status: 'ACTIVE',
      rotatedAt: null,
    };

    if (purpose === 'EVIDENCE_HMAC') {
      store.activeEvidenceKeyId = newKeyId;
    } else {
      store.activeVaultKeyId = newKeyId;
    }

    KeyManagementService.persistStore(store, customPath);

    return {
      keyId: newKeyId,
      purpose,
      createdAt: now,
      rotatedAt: null,
      status: 'ACTIVE',
      fingerprintSha256: KeyManagementService.computeSha256(rawSecretHex).slice(0, 16),
      algorithm: purpose === 'EVIDENCE_HMAC' ? 'HMAC-SHA256' : 'AES-256-GCM',
    };
  }

  public static verifyStrictAdminToken(providedToken: string | undefined, customPath?: string): boolean {
    if (!providedToken || providedToken.trim().length === 0) return false;
    const envAdminToken = process.env.WINHOOD_ADMIN_TOKEN;
    if (envAdminToken && envAdminToken.trim().length > 0) {
      const a = Buffer.from(providedToken.trim(), 'utf8');
      const b = Buffer.from(envAdminToken.trim(), 'utf8');
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    }
    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    if (!store.adminTokenSha256) {
      return false;
    }
    const providedSha = KeyManagementService.computeSha256(providedToken.trim());
    const a = Buffer.from(providedSha, 'hex');
    const b = Buffer.from(store.adminTokenSha256, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  public static getStatus(customPath?: string): KeyManagementStatus {
    const { store, integrityVerified } = KeyManagementService.loadOrInitializeStore(customPath);
    const hasEnvEvidence = Boolean(
      process.env.WINHOOD_EVIDENCE_HMAC_SECRET && process.env.WINHOOD_EVIDENCE_HMAC_SECRET.trim().length >= 16
    );
    const hasEnvVault = Boolean(
      (process.env.SONAR_SECRET_SALT || process.env.WINHOOD_VAULT_SECRET || '').trim().length >= 16
    );

    const symKeys: ManagedKeyRecord[] = Object.entries(store.keysHex).map(([keyId, info]) => ({
      keyId,
      purpose: info.purpose,
      createdAt: info.createdAt,
      rotatedAt: info.rotatedAt,
      status: info.status,
      fingerprintSha256: KeyManagementService.computeSha256(info.secretHex).slice(0, 16),
      algorithm: info.purpose === 'EVIDENCE_HMAC' ? 'HMAC-SHA256' : 'AES-256-GCM',
    }));

    const asymKeys: ManagedKeyRecord[] = Object.entries(store.ed25519Keys || {}).map(([keyId, info]) => ({
      keyId,
      purpose: info.purpose,
      createdAt: info.createdAt,
      rotatedAt: info.rotatedAt,
      status: info.status,
      fingerprintSha256: KeyManagementService.computeSha256(info.publicKeyPem).slice(0, 16),
      algorithm: 'ED25519',
    }));

    const keys = [...symKeys, ...asymKeys];

    return {
      keystorePath: KeyManagementService.getStorePath(customPath),
      integrityVerified,
      dpapiSupported: os.platform() === 'win32',
      keyOrigin: hasEnvEvidence || hasEnvVault ? 'ENV_EXTERNAL' : 'HOST_CSPRNG_KEYSTORE',
      activeEvidenceKeyId: store.activeEvidenceKeyId,
      activeEd25519KeyId: store.activeEd25519KeyId,
      activeVaultKeyId: store.activeVaultKeyId,
      adminTokenConfigured: Boolean(process.env.WINHOOD_ADMIN_TOKEN || store.adminTokenSha256),
      totalKeysTracked: keys.length,
      keys,
    };
  }
}
