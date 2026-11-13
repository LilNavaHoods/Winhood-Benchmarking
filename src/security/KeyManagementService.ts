import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export interface ManagedKeyRecord {
  keyId: string;
  purpose: 'EVIDENCE_HMAC' | 'TOKEN_VAULT_AES256' | 'ADMIN_RBAC';
  createdAt: string;
  rotatedAt: string | null;
  status: 'ACTIVE' | 'RETIRED_VERIFY_ONLY';
  fingerprintSha256: string;
}

interface PersistedKeyStore {
  version: number;
  activeEvidenceKeyId: string;
  activeVaultKeyId: string;
  keysHex: Record<string, { purpose: ManagedKeyRecord['purpose']; secretHex: string; createdAt: string; status: ManagedKeyRecord['status']; rotatedAt: string | null }>;
  adminTokenSha256: string | null;
}

export interface KeyManagementStatus {
  keystorePath: string;
  keyOrigin: 'ENV_EXTERNAL' | 'HOST_CSPRNG_KEYSTORE';
  activeEvidenceKeyId: string;
  activeVaultKeyId: string;
  adminTokenConfigured: boolean;
  totalKeysTracked: number;
  keys: ManagedKeyRecord[];
}

export class KeyManagementService {
  private static readonly DEFAULT_STORE_PATH = path.resolve(
    process.cwd(),
    '.winhood_data',
    'keys',
    'keystore.json'
  );

  private static memoryFallbackStore: PersistedKeyStore | null = null;

  private static getStorePath(customPath?: string): string {
    return customPath || process.env.WINHOOD_KEYSTORE_PATH || KeyManagementService.DEFAULT_STORE_PATH;
  }

  private static loadOrInitializeStore(customPath?: string): PersistedKeyStore {
    const storePath = KeyManagementService.getStorePath(customPath);
    try {
      if (fs.existsSync(storePath)) {
        const raw = fs.readFileSync(storePath, 'utf8');
        const parsed = JSON.parse(raw) as PersistedKeyStore;
        if (parsed && parsed.keysHex && parsed.activeEvidenceKeyId && parsed.activeVaultKeyId) {
          return parsed;
        }
      }
    } catch {
      // Fall through to initialize a fresh keystore
    }

    const now = new Date().toISOString();
    const evidenceKeyId = `wh-hmac-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
    const vaultKeyId = `wh-vault-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;

    const initialStore: PersistedKeyStore = {
      version: 1,
      activeEvidenceKeyId: evidenceKeyId,
      activeVaultKeyId: vaultKeyId,
      keysHex: {
        [evidenceKeyId]: {
          purpose: 'EVIDENCE_HMAC',
          secretHex: crypto.randomBytes(32).toString('hex'),
          createdAt: now,
          status: 'ACTIVE',
          rotatedAt: null,
        },
        [vaultKeyId]: {
          purpose: 'TOKEN_VAULT_AES256',
          secretHex: crypto.randomBytes(32).toString('hex'),
          createdAt: now,
          status: 'ACTIVE',
          rotatedAt: null,
        },
      },
      adminTokenSha256: process.env.WINHOOD_ADMIN_TOKEN
        ? crypto.createHash('sha256').update(process.env.WINHOOD_ADMIN_TOKEN, 'utf8').digest('hex')
        : null,
    };

    try {
      fs.mkdirSync(path.dirname(storePath), { recursive: true });
      fs.writeFileSync(storePath, JSON.stringify(initialStore, null, 2), {
        encoding: 'utf8',
        mode: 0o600,
      });
    } catch {
      KeyManagementService.memoryFallbackStore = initialStore;
    }

    return initialStore;
  }

  private static persistStore(store: PersistedKeyStore, customPath?: string): void {
    const storePath = KeyManagementService.getStorePath(customPath);
    try {
      fs.mkdirSync(path.dirname(storePath), { recursive: true });
      fs.writeFileSync(storePath, JSON.stringify(store, null, 2), {
        encoding: 'utf8',
        mode: 0o600,
      });
    } catch {
      KeyManagementService.memoryFallbackStore = store;
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

    const store =
      KeyManagementService.memoryFallbackStore || KeyManagementService.loadOrInitializeStore(customPath);
    const active = store.keysHex[store.activeEvidenceKeyId];
    return {
      keyId: store.activeEvidenceKeyId,
      secret: active.secretHex,
      origin: 'HOST_CSPRNG_KEYSTORE',
    };
  }

  public static getEvidenceSecretByKeyId(keyId: string, customPath?: string): string | null {
    const envSecret = process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
    const envKeyId = process.env.WINHOOD_EVIDENCE_KEY_ID || 'ENV-HMAC-KEY';
    if (envSecret && envSecret.trim().length >= 16 && keyId === envKeyId) {
      return envSecret.trim();
    }

    const store =
      KeyManagementService.memoryFallbackStore || KeyManagementService.loadOrInitializeStore(customPath);
    return store.keysHex[keyId]?.secretHex ?? null;
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

    const store =
      KeyManagementService.memoryFallbackStore || KeyManagementService.loadOrInitializeStore(customPath);
    const active = store.keysHex[store.activeVaultKeyId];
    return {
      keyId: store.activeVaultKeyId,
      keyBuffer: Buffer.from(active.secretHex, 'hex'),
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

    const store =
      KeyManagementService.memoryFallbackStore || KeyManagementService.loadOrInitializeStore(customPath);
    const entry = store.keysHex[keyId];
    return entry ? Buffer.from(entry.secretHex, 'hex') : null;
  }

  public static rotateKey(
    purpose: 'EVIDENCE_HMAC' | 'TOKEN_VAULT_AES256',
    customPath?: string
  ): ManagedKeyRecord {
    const store =
      KeyManagementService.memoryFallbackStore || KeyManagementService.loadOrInitializeStore(customPath);
    const now = new Date().toISOString();

    const prevKeyId =
      purpose === 'EVIDENCE_HMAC' ? store.activeEvidenceKeyId : store.activeVaultKeyId;
    if (store.keysHex[prevKeyId]) {
      store.keysHex[prevKeyId].status = 'RETIRED_VERIFY_ONLY';
      store.keysHex[prevKeyId].rotatedAt = now;
    }

    const prefix = purpose === 'EVIDENCE_HMAC' ? 'wh-hmac' : 'wh-vault';
    const newKeyId = `${prefix}-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
    const secretHex = crypto.randomBytes(32).toString('hex');

    store.keysHex[newKeyId] = {
      purpose,
      secretHex,
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
      fingerprintSha256: crypto.createHash('sha256').update(secretHex).digest('hex').slice(0, 16),
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
    const store =
      KeyManagementService.memoryFallbackStore || KeyManagementService.loadOrInitializeStore(customPath);
    if (!store.adminTokenSha256) {
      return false;
    }
    const providedSha = crypto.createHash('sha256').update(providedToken.trim(), 'utf8').digest('hex');
    const a = Buffer.from(providedSha, 'hex');
    const b = Buffer.from(store.adminTokenSha256, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  public static getStatus(customPath?: string): KeyManagementStatus {
    const store =
      KeyManagementService.memoryFallbackStore || KeyManagementService.loadOrInitializeStore(customPath);
    const hasEnvEvidence = Boolean(
      process.env.WINHOOD_EVIDENCE_HMAC_SECRET && process.env.WINHOOD_EVIDENCE_HMAC_SECRET.trim().length >= 16
    );
    const hasEnvVault = Boolean(
      (process.env.SONAR_SECRET_SALT || process.env.WINHOOD_VAULT_SECRET || '').trim().length >= 16
    );

    const keys: ManagedKeyRecord[] = Object.entries(store.keysHex).map(([keyId, info]) => ({
      keyId,
      purpose: info.purpose,
      createdAt: info.createdAt,
      rotatedAt: info.rotatedAt,
      status: info.status,
      fingerprintSha256: crypto.createHash('sha256').update(info.secretHex).digest('hex').slice(0, 16),
    }));

    return {
      keystorePath: KeyManagementService.getStorePath(customPath),
      keyOrigin: hasEnvEvidence || hasEnvVault ? 'ENV_EXTERNAL' : 'HOST_CSPRNG_KEYSTORE',
      activeEvidenceKeyId: store.activeEvidenceKeyId,
      activeVaultKeyId: store.activeVaultKeyId,
      adminTokenConfigured: Boolean(process.env.WINHOOD_ADMIN_TOKEN || store.adminTokenSha256),
      totalKeysTracked: keys.length,
      keys,
    };
  }
}
