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

export type KeystoreOperatingMode = 'PRODUCTION_SECURE' | 'DEVELOPMENT' | 'RECOVERY';

export type KekProtectionMechanism =
  | 'WINDOWS_DPAPI'
  | 'MACOS_KEYCHAIN'
  | 'LINUX_SECRET_SERVICE'
  | 'HKDF_EXTERNAL_ENV'
  | 'HKDF_LOCAL_KEK_FILE';

export interface ManagedKeyRecord {
  keyId: string;
  purpose: ManagedKeyPurpose;
  createdAt: string;
  rotatedAt: string | null;
  revokedAt?: string | null;
  status: 'ACTIVE' | 'RETIRED_VERIFY_ONLY' | 'REVOKED';
  fingerprintSha256: string;
  algorithm: 'HMAC-SHA256' | 'ED25519' | 'AES-256-GCM';
}

export interface AesGcmEnvelopeCiphertext {
  alg: 'AES-256-GCM';
  nonceHex: string; // 96-bit (12 bytes) CSPRNG nonce unique per operation
  authTagHex: string; // 128-bit (16 bytes) GCM authentication tag
  ciphertextHex: string;
  aadContext: string;
}

export interface WrappedDekEnvelope {
  envelopeVersion: 'WINHOOD-ENVELOPE-V2';
  kekMechanism: KekProtectionMechanism;
  hkdfSaltHex: string;
  hkdfInfo: string;
  dpapiProtectedBlobB64?: string;
  osKeyringAccount?: string;
  aesGcmWrappedDek?: AesGcmEnvelopeCiphertext;
  createdAt: string;
  rotatedAt: string | null;
}

export interface TrustedEd25519PublicKeyEntry {
  keyId: string;
  publicKeyPem: string;
  fingerprintSha256: string;
  validFrom: string;
  validUntil: string | null;
  revokedAt: string | null;
  revocationReason: string | null;
  status: 'ACTIVE' | 'ROTATED_VERIFY_ONLY' | 'REVOKED';
}

export interface PersistedTrustStore {
  version: number;
  rootAnchorFingerprintSha256: string | null;
  monotonicSequence: number;
  updatedAt: string;
  trustedPublicKeys: Record<string, TrustedEd25519PublicKeyEntry>;
  integrityMacHex?: string;
}

export interface KeyRotationAuditEntry {
  timestamp: string;
  purpose: ManagedKeyPurpose;
  previousKeyId: string | null;
  newKeyId: string;
  reason: string;
  monotonicSequence: number;
}

interface StoredHmacOrAesKey {
  purpose: 'EVIDENCE_HMAC' | 'TOKEN_VAULT_AES256';
  secretHex?: string; // Legacy v2 format compatibility
  envelopeCipher?: AesGcmEnvelopeCiphertext; // Envelope v3 format
  dpapiProtected?: boolean;
  createdAt: string;
  status: 'ACTIVE' | 'RETIRED_VERIFY_ONLY' | 'REVOKED';
  rotatedAt: string | null;
  revokedAt?: string | null;
}

interface StoredEd25519Key {
  purpose: 'EVIDENCE_ED25519';
  privateKeyPem?: string; // Legacy v2 format compatibility
  privateKeyEnvelope?: AesGcmEnvelopeCiphertext; // Envelope v3 format
  publicKeyPem: string;
  dpapiProtected?: boolean;
  createdAt: string;
  validFrom?: string;
  validUntil?: string | null;
  status: 'ACTIVE' | 'RETIRED_VERIFY_ONLY' | 'REVOKED';
  rotatedAt: string | null;
  revokedAt?: string | null;
  revocationReason?: string | null;
}

interface PersistedKeyStore {
  version: number;
  envelopeVersion?: 'WINHOOD-ENVELOPE-V2';
  operatingMode?: KeystoreOperatingMode;
  monotonicSequence?: number;
  wrappedDek?: WrappedDekEnvelope;
  activeEvidenceKeyId: string;
  activeEd25519KeyId: string;
  activeVaultKeyId: string;
  keysHex: Record<string, StoredHmacOrAesKey>;
  ed25519Keys: Record<string, StoredEd25519Key>;
  trustedPublicKeys?: Record<string, TrustedEd25519PublicKeyEntry>;
  rotationHistory?: KeyRotationAuditEntry[];
  adminTokenSha256: string | null;
  kekBoundIntegrityMacHex?: string;
}

export interface KeyManagementStatus {
  keystorePath: string;
  trustStorePath: string;
  integrityVerified: boolean;
  trustStoreSeparated: boolean;
  hardwareTpmOrRemoteAnchorAvailable: boolean;
  envelopeVersion: string;
  operatingMode: KeystoreOperatingMode;
  kekProtectionMechanism: KekProtectionMechanism;
  monotonicSequence: number;
  rollbackProtectionVerified: boolean;
  dpapiSupported: boolean;
  macosKeychainAvailable: boolean;
  linuxSecretServiceAvailable: boolean;
  keyOrigin: 'ENV_EXTERNAL' | 'HOST_CSPRNG_KEYSTORE';
  productionEnvSecretConfigured: boolean;
  securityWarnings: string[];
  activeEvidenceKeyId: string;
  activeEd25519KeyId: string;
  activeVaultKeyId: string;
  adminTokenConfigured: boolean;
  totalKeysTracked: number;
  trustedPublicKeysCount: number;
  keys: ManagedKeyRecord[];
  trustedPublicKeys: TrustedEd25519PublicKeyEntry[];
  rotationHistory: KeyRotationAuditEntry[];
}

export interface VaultReencryptContext {
  oldKeyId: string;
  oldKeyBuffer: Buffer;
  newKeyId: string;
  newKeyBuffer: Buffer;
}

export interface TrustedPublicKeyVerificationResult {
  trusted: boolean;
  keyId: string | null;
  publicKeyPem: string | null;
  status: 'ACTIVE' | 'ROTATED_VERIFY_ONLY' | 'REVOKED' | 'UNTRUSTED' | 'EXPIRED';
  reason: string;
}

function generateEd25519Pair(): { privateKeyPem: string; publicKeyPem: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

function resolvePowerShellExecutable(): { exePath: string; safeEnv: NodeJS.ProcessEnv } {
  const sysRoot = process.env.SystemRoot || 'C:\\Windows';
  const exePath = path.win32.join(sysRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const safeEnv: NodeJS.ProcessEnv = {
    SystemRoot: sysRoot,
    PATH: path.win32.join(sysRoot, 'System32'),
  };
  return { exePath, safeEnv };
}

function tryDpapiProtectBytes(rawBytes: Buffer): { protectedB64: string; usedDpapi: boolean } {
  if (process.env.WINHOOD_SIMULATE_DPAPI_UNAVAILABLE === 'true' || os.platform() !== 'win32') {
    return { protectedB64: '', usedDpapi: false };
  }
  try {
    const b64 = rawBytes.toString('base64');
    const ps = [
      'Add-Type -AssemblyName System.Security;',
      `$bytes = [Convert]::FromBase64String('${b64}');`,
      '$prot = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser);',
      '[Convert]::ToBase64String($prot)',
    ].join(' ');
    const { exePath, safeEnv } = resolvePowerShellExecutable();
    const res = spawnSync(exePath, ['-NoProfile', '-NonInteractive', '-Command', ps], {
      shell: false,
      encoding: 'utf8',
      timeout: 5000,
      env: safeEnv,
    });
    if (res.status === 0 && res.stdout && res.stdout.trim().length > 0) {
      return { protectedB64: res.stdout.trim(), usedDpapi: true };
    }
  } catch {
    // Explicit failure handled by caller according to operating mode
  }
  return { protectedB64: '', usedDpapi: false };
}

function tryDpapiUnprotectBytes(cipherB64: string): Buffer {
  if (process.env.WINHOOD_SIMULATE_DPAPI_UNAVAILABLE === 'true') {
    throw new Error('KEYSTORE_DPAPI_UNAVAILABLE: Windows DPAPI indisponível ou bloqueado.');
  }
  const ps = [
    'Add-Type -AssemblyName System.Security;',
    `$bytes = [Convert]::FromBase64String('${cipherB64}');`,
    '$unprot = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser);',
    '[Convert]::ToBase64String($unprot)',
  ].join(' ');
  const { exePath, safeEnv } = resolvePowerShellExecutable();
  const res = spawnSync(exePath, ['-NoProfile', '-NonInteractive', '-Command', ps], {
    shell: false,
    encoding: 'utf8',
    timeout: 5000,
    env: safeEnv,
  });
  if (res.status !== 0 || !res.stdout) {
    throw new Error('KEYSTORE_DPAPI_UNPROTECT_FAILED: Falha ao descriptografar DEK via Windows DPAPI.');
  }
  return Buffer.from(res.stdout.trim(), 'base64');
}

function tryDpapiUnprotectUtf8Legacy(cipherB64OrPlain: string, wasProtected?: boolean): string {
  if (!wasProtected || os.platform() !== 'win32') {
    return cipherB64OrPlain;
  }
  const ps = [
    'Add-Type -AssemblyName System.Security;',
    `$bytes = [Convert]::FromBase64String('${cipherB64OrPlain}');`,
    '$unprot = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser);',
    '[System.Text.Encoding]::UTF8.GetString($unprot)',
  ].join(' ');
  const { exePath, safeEnv } = resolvePowerShellExecutable();
  const res = spawnSync(exePath, ['-NoProfile', '-NonInteractive', '-Command', ps], {
    shell: false,
    encoding: 'utf8',
    timeout: 5000,
    env: safeEnv,
  });
  if (res.status !== 0 || !res.stdout) {
    throw new Error('KEYSTORE_DPAPI_UNPROTECT_FAILED: Falha ao descriptografar chave legada via Windows DPAPI.');
  }
  return res.stdout.trim();
}

/**
 * macOS Keychain integration via `/usr/bin/security` (execFile/spawnSync with shell: false).
 */
function tryMacosKeychainStoreOrLoadKek(accountName: string): { seedBuffer: Buffer | null; available: boolean } {
  if (process.env.WINHOOD_SIMULATE_KEYRING_UNAVAILABLE === 'true' || os.platform() !== 'darwin') {
    return { seedBuffer: null, available: false };
  }
  const securityBin = '/usr/bin/security';
  if (!fs.existsSync(securityBin)) {
    return { seedBuffer: null, available: false };
  }
  try {
    const findRes = spawnSync(
      securityBin,
      ['find-generic-password', '-a', accountName, '-s', 'winhood-keystore-kek', '-w'],
      { shell: false, encoding: 'utf8', timeout: 4000 }
    );
    if (findRes.status === 0 && findRes.stdout && findRes.stdout.trim().length >= 64) {
      return { seedBuffer: Buffer.from(findRes.stdout.trim(), 'hex'), available: true };
    }
    const newSeedHex = crypto.randomBytes(32).toString('hex');
    const addRes = spawnSync(
      securityBin,
      ['add-generic-password', '-U', '-a', accountName, '-s', 'winhood-keystore-kek', '-w', newSeedHex],
      { shell: false, encoding: 'utf8', timeout: 4000 }
    );
    if (addRes.status === 0) {
      return { seedBuffer: Buffer.from(newSeedHex, 'hex'), available: true };
    }
  } catch {
    // Handled by caller
  }
  return { seedBuffer: null, available: false };
}

/**
 * Linux Secret Service integration via `secret-tool` (D-Bus org.freedesktop.secrets, shell: false).
 */
function tryLinuxSecretServiceStoreOrLoadKek(accountName: string): { seedBuffer: Buffer | null; available: boolean } {
  if (process.env.WINHOOD_SIMULATE_KEYRING_UNAVAILABLE === 'true' || os.platform() !== 'linux') {
    return { seedBuffer: null, available: false };
  }
  if (!process.env.DBUS_SESSION_BUS_ADDRESS) {
    return { seedBuffer: null, available: false };
  }
  const secretToolBin = ['/usr/bin/secret-tool', '/bin/secret-tool', '/usr/local/bin/secret-tool'].find((p) =>
    fs.existsSync(p)
  );
  if (!secretToolBin) {
    return { seedBuffer: null, available: false };
  }
  const safeEnv = { ...process.env, PATH: '/usr/bin:/bin' };
  try {
    const lookupRes = spawnSync(
      secretToolBin,
      ['lookup', 'application', 'winhood-benchmarking', 'account', accountName],
      { shell: false, encoding: 'utf8', timeout: 3000, env: safeEnv }
    );
    if (lookupRes.status === 0 && lookupRes.stdout && lookupRes.stdout.trim().length >= 64) {
      return { seedBuffer: Buffer.from(lookupRes.stdout.trim(), 'hex'), available: true };
    }
    const newSeedHex = crypto.randomBytes(32).toString('hex');
    const storeRes = spawnSync(
      secretToolBin,
      ['store', '--label=WinHood Keystore KEK', 'application', 'winhood-benchmarking', 'account', accountName],
      { shell: false, input: newSeedHex, encoding: 'utf8', timeout: 3000, env: safeEnv }
    );
    if (storeRes.status === 0) {
      return { seedBuffer: Buffer.from(newSeedHex, 'hex'), available: true };
    }
  } catch {
    // Handled by caller
  }
  return { seedBuffer: null, available: false };
}

/**
 * Derives a 256-bit purpose-isolated symmetric key using HKDF-SHA256 (RFC 5869).
 * Prevents reuse of the same raw material across KEK, HMAC, and Vault operations.
 */
export function deriveHkdfPurposeKey(
  ikmBuffer: Buffer,
  saltHex: string,
  purposeInfo: string
): Buffer {
  const saltBuf = Buffer.from(saltHex, 'hex');
  const infoBuf = Buffer.from(purposeInfo, 'utf8');
  const derived = crypto.hkdfSync('sha256', ikmBuffer, saltBuf, infoBuf, 32);
  return Buffer.from(derived);
}

/**
 * Authenticated encryption with AES-256-GCM using a unique 96-bit CSPRNG nonce and AAD context.
 */
export function encryptWithAes256GcmEnvelope(
  plaintextUtf8: string,
  key32Bytes: Buffer,
  aadContext: string
): AesGcmEnvelopeCiphertext {
  if (key32Bytes.length !== 32) {
    throw new Error('KEYSTORE_INVALID_KEY_LENGTH: Chave AES-256-GCM deve possuir exatamente 32 bytes.');
  }
  const nonce = crypto.randomBytes(12); // 96-bit nonce required by NIST SP 800-38D for AES-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key32Bytes, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(aadContext, 'utf8'));
  const encrypted = Buffer.concat([cipher.update(plaintextUtf8, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    alg: 'AES-256-GCM',
    nonceHex: nonce.toString('hex'),
    authTagHex: authTag.toString('hex'),
    ciphertextHex: encrypted.toString('hex'),
    aadContext,
  };
}

/**
 * Authenticated decryption with AES-256-GCM. Throws on any nonce, AAD, or authTag tampering.
 */
export function decryptWithAes256GcmEnvelope(
  envelope: AesGcmEnvelopeCiphertext,
  key32Bytes: Buffer,
  expectedAadContext?: string
): string {
  if (!envelope || envelope.alg !== 'AES-256-GCM') {
    throw new Error('KEYSTORE_ENVELOPE_INVALID_ALG: Algoritmo de envelope inválido.');
  }
  if (expectedAadContext && envelope.aadContext !== expectedAadContext) {
    throw new Error(
      `KEYSTORE_ENVELOPE_AAD_MISMATCH: Contexto de finalidade divergente (${envelope.aadContext} !== ${expectedAadContext}).`
    );
  }
  const nonce = Buffer.from(envelope.nonceHex, 'hex');
  const authTag = Buffer.from(envelope.authTagHex, 'hex');
  if (nonce.length !== 12 || authTag.length !== 16) {
    throw new Error('KEYSTORE_ENVELOPE_CORRUPTED_NONCE_OR_TAG: Nonce de 96 bits ou AuthTag de 128 bits inválido.');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', key32Bytes, nonce, { authTagLength: 16 });
  decipher.setAAD(Buffer.from(envelope.aadContext, 'utf8'));
  decipher.setAuthTag(authTag);
  try {
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertextHex, 'hex')),
      decipher.final(),
    ]);
    return decrypted.toString('utf8');
  } catch {
    throw new Error(
      'KEYSTORE_GCM_AUTH_FAILED: Falha de autenticação AES-256-GCM — ciphertext, nonce, AAD ou chave corrompidos.'
    );
  }
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

  public static getTrustStorePath(customStorePath?: string): string {
    if (process.env.WINHOOD_TRUST_STORE_PATH && !customStorePath) {
      return process.env.WINHOOD_TRUST_STORE_PATH;
    }
    const baseStore = KeyManagementService.getStorePath(customStorePath);
    return path.join(path.dirname(baseStore), 'trust-store.json');
  }

  public static resolveOperatingMode(): KeystoreOperatingMode {
    const explicitMode = (process.env.WINHOOD_KEYSTORE_MODE || '').trim().toUpperCase();
    if (explicitMode === 'PRODUCTION_SECURE' || explicitMode === 'DEVELOPMENT' || explicitMode === 'RECOVERY') {
      return explicitMode;
    }
    if (process.env.NODE_ENV === 'production') {
      return 'PRODUCTION_SECURE';
    }
    return 'DEVELOPMENT';
  }

  private static computeSha256(content: string): string {
    return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  }

  /**
   * Validates strict domain separation across secret environment variables.
   * Rejects reuse of identical secret strings across different cryptographic purposes
   * and forbids SONAR_SECRET_SALT from acting as a keystore master secret.
   */
  public static assertSecretDomainSeparation(): void {
    const masterSecret = (process.env.WINHOOD_KEYSTORE_MASTER_SECRET || '').trim();
    const hmacSecret = (process.env.WINHOOD_EVIDENCE_HMAC_SECRET || '').trim();
    const vaultSecret = (process.env.WINHOOD_VAULT_SECRET || '').trim();
    const sonarSalt = (process.env.SONAR_SECRET_SALT || '').trim();

    if (masterSecret.length > 0 && sonarSalt.length > 0 && masterSecret === sonarSalt) {
      throw new Error(
        'KEYSTORE_SECRET_DOMAIN_VIOLATION: SONAR_SECRET_SALT é exclusivo de integração/migração legada e não pode ser reutilizado como WINHOOD_KEYSTORE_MASTER_SECRET.'
      );
    }
    if (masterSecret.length > 0 && hmacSecret.length > 0 && masterSecret === hmacSecret) {
      throw new Error(
        'KEYSTORE_SECRET_DOMAIN_VIOLATION: WINHOOD_KEYSTORE_MASTER_SECRET e WINHOOD_EVIDENCE_HMAC_SECRET devem ser segredos independentes.'
      );
    }
    if (masterSecret.length > 0 && vaultSecret.length > 0 && masterSecret === vaultSecret) {
      throw new Error(
        'KEYSTORE_SECRET_DOMAIN_VIOLATION: WINHOOD_KEYSTORE_MASTER_SECRET e WINHOOD_VAULT_SECRET devem ser segredos independentes.'
      );
    }
    if (hmacSecret.length > 0 && vaultSecret.length > 0 && hmacSecret === vaultSecret) {
      throw new Error(
        'KEYSTORE_SECRET_DOMAIN_VIOLATION: WINHOOD_EVIDENCE_HMAC_SECRET e WINHOOD_VAULT_SECRET devem ser segredos independentes.'
      );
    }
  }

  /**
   * Resolves the Key Encryption Key (KEK) used exclusively to wrap/unwrap the random Data Encryption Key (DEK).
   * Enforces fail-closed behavior in PRODUCTION_SECURE: never falls back to local .kek file in PRODUCTION_SECURE.
   */
  private static resolveKekForStore(
    storePath: string,
    hkdfSaltHex: string,
    hkdfInfo: string,
    expectedMechanism?: KekProtectionMechanism
  ): { kekBuffer: Buffer; mechanism: KekProtectionMechanism } {
    KeyManagementService.assertSecretDomainSeparation();
    const operatingMode = KeyManagementService.resolveOperatingMode();
    const accountId = KeyManagementService.computeSha256(storePath).slice(0, 16);

    // 1. Check canonical external master secret (or legacy WINHOOD_MASTER_KEY_SECRET alias for read/migration only)
    const canonicalMasterEnv = (process.env.WINHOOD_KEYSTORE_MASTER_SECRET || '').trim();
    const legacyMasterAlias = (process.env.WINHOOD_MASTER_KEY_SECRET || '').trim();
    const extMasterEnv = canonicalMasterEnv || legacyMasterAlias;
    const externalExplicitlyEnabled =
      process.env.WINHOOD_KEYSTORE_EXTERNAL_SECRET_ENABLED === 'true' ||
      operatingMode !== 'PRODUCTION_SECURE' ||
      canonicalMasterEnv.length >= 16;

    if (extMasterEnv.length >= 16 && externalExplicitlyEnabled) {
      const ikm = Buffer.from(extMasterEnv, 'utf8');
      return {
        kekBuffer: deriveHkdfPurposeKey(ikm, hkdfSaltHex, hkdfInfo),
        mechanism: 'HKDF_EXTERNAL_ENV',
      };
    }

    // 2. Check OS-native providers on macOS and Linux
    if (!expectedMechanism || expectedMechanism === 'MACOS_KEYCHAIN') {
      const macos = tryMacosKeychainStoreOrLoadKek(accountId);
      if (macos.available && macos.seedBuffer) {
        return {
          kekBuffer: deriveHkdfPurposeKey(macos.seedBuffer, hkdfSaltHex, hkdfInfo),
          mechanism: 'MACOS_KEYCHAIN',
        };
      }
    }

    if (!expectedMechanism || expectedMechanism === 'LINUX_SECRET_SERVICE') {
      const linuxSecret = tryLinuxSecretServiceStoreOrLoadKek(accountId);
      if (linuxSecret.available && linuxSecret.seedBuffer) {
        return {
          kekBuffer: deriveHkdfPurposeKey(linuxSecret.seedBuffer, hkdfSaltHex, hkdfInfo),
          mechanism: 'LINUX_SECRET_SERVICE',
        };
      }
    }

    // 3. In PRODUCTION_SECURE, strictly fail-closed before touching local .kek file
    if (operatingMode === 'PRODUCTION_SECURE') {
      throw new Error(
        'KEYSTORE_PRODUCTION_PROVIDER_REQUIRED: Modo PRODUCTION_SECURE exige Windows DPAPI, macOS Keychain, Linux Secret Service ou WINHOOD_KEYSTORE_MASTER_SECRET (>= 16 caracteres). Fallback para arquivo .kek local é proibido em produção.'
      );
    }

    // 4. DEVELOPMENT / RECOVERY local .kek file fallback
    const kekFilePath = `${storePath}.kek`;
    let rawKekSeed: Buffer;
    if (fs.existsSync(kekFilePath)) {
      const hex = fs.readFileSync(kekFilePath, 'utf8').trim();
      rawKekSeed = Buffer.from(hex, 'hex');
      if (rawKekSeed.length < 32) {
        throw new Error(`KEYSTORE_KEK_CORRUPTED: Arquivo KEK em ${kekFilePath} corrompido.`);
      }
    } else {
      fs.mkdirSync(path.dirname(kekFilePath), { recursive: true });
      rawKekSeed = crypto.randomBytes(32);
      const tmpKek = `${kekFilePath}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
      const fd = fs.openSync(tmpKek, 'w', 0o600);
      try {
        fs.writeFileSync(fd, rawKekSeed.toString('hex'), 'utf8');
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(tmpKek, kekFilePath);
      fs.chmodSync(kekFilePath, 0o600);
    }

    return {
      kekBuffer: deriveHkdfPurposeKey(rawKekSeed, hkdfSaltHex, hkdfInfo),
      mechanism: 'HKDF_LOCAL_KEK_FILE',
    };
  }

  /**
   * Wraps a random 256-bit DEK using OS DPAPI (when on Windows), macOS Keychain, Linux Secret Service,
   * or HKDF-derived KEK with AES-256-GCM.
   */
  private static wrapDekBuffer(dekBuffer: Buffer, storePath: string): WrappedDekEnvelope {
    KeyManagementService.assertSecretDomainSeparation();
    const operatingMode = KeyManagementService.resolveOperatingMode();
    const now = new Date().toISOString();
    const hkdfSaltHex = crypto.randomBytes(16).toString('hex');
    const hkdfInfo = 'winhood:keystore:kek-envelope:v2';

    if (os.platform() === 'win32' && !(process.env.WINHOOD_KEYSTORE_MASTER_SECRET || '').trim()) {
      const dpapiAttempt = tryDpapiProtectBytes(dekBuffer);
      if (dpapiAttempt.usedDpapi) {
        return {
          envelopeVersion: 'WINHOOD-ENVELOPE-V2',
          kekMechanism: 'WINDOWS_DPAPI',
          hkdfSaltHex,
          hkdfInfo,
          dpapiProtectedBlobB64: dpapiAttempt.protectedB64,
          createdAt: now,
          rotatedAt: null,
        };
      }
      if (operatingMode === 'PRODUCTION_SECURE') {
        throw new Error(
          'KEYSTORE_DPAPI_REQUIRED_IN_PRODUCTION: Windows DPAPI falhou ou está indisponível em PRODUCTION_SECURE e WINHOOD_KEYSTORE_MASTER_SECRET não foi definido.'
        );
      }
    }

    const { kekBuffer, mechanism } = KeyManagementService.resolveKekForStore(
      storePath,
      hkdfSaltHex,
      hkdfInfo
    );
    const wrappedCipher = encryptWithAes256GcmEnvelope(
      dekBuffer.toString('hex'),
      kekBuffer,
      'winhood:dek:wrap:v2'
    );
    return {
      envelopeVersion: 'WINHOOD-ENVELOPE-V2',
      kekMechanism: mechanism,
      hkdfSaltHex,
      hkdfInfo,
      osKeyringAccount:
        mechanism === 'MACOS_KEYCHAIN' || mechanism === 'LINUX_SECRET_SERVICE'
          ? KeyManagementService.computeSha256(storePath).slice(0, 16)
          : undefined,
      aesGcmWrappedDek: wrappedCipher,
      createdAt: now,
      rotatedAt: null,
    };
  }

  /**
   * Unwraps the 256-bit DEK from the keystore envelope.
   */
  private static unwrapDekBuffer(wrappedDek: WrappedDekEnvelope, storePath: string): Buffer {
    KeyManagementService.assertSecretDomainSeparation();
    const operatingMode = KeyManagementService.resolveOperatingMode();

    if (wrappedDek.kekMechanism === 'WINDOWS_DPAPI') {
      if (!wrappedDek.dpapiProtectedBlobB64) {
        throw new Error('KEYSTORE_DPAPI_BLOB_MISSING: Blob DPAPI ausente no envelope.');
      }
      return tryDpapiUnprotectBytes(wrappedDek.dpapiProtectedBlobB64);
    }

    if (operatingMode === 'PRODUCTION_SECURE' && wrappedDek.kekMechanism === 'HKDF_LOCAL_KEK_FILE') {
      const hasExternalMaster = (process.env.WINHOOD_KEYSTORE_MASTER_SECRET || '').trim().length >= 16;
      if (!hasExternalMaster) {
        throw new Error(
          'KEYSTORE_PRODUCTION_LOCAL_KEK_REJECTED: Keystore protegido por arquivo .kek local não é aceito em PRODUCTION_SECURE sem migração para provedor seguro ou WINHOOD_KEYSTORE_MASTER_SECRET.'
        );
      }
    }

    if (!wrappedDek.aesGcmWrappedDek) {
      throw new Error('KEYSTORE_DEK_ENVELOPE_MISSING: Envelope AES-256-GCM da DEK ausente.');
    }
    const { kekBuffer } = KeyManagementService.resolveKekForStore(
      storePath,
      wrappedDek.hkdfSaltHex,
      wrappedDek.hkdfInfo,
      wrappedDek.kekMechanism
    );
    const dekHex = decryptWithAes256GcmEnvelope(
      wrappedDek.aesGcmWrappedDek,
      kekBuffer,
      'winhood:dek:wrap:v2'
    );
    return Buffer.from(dekHex, 'hex');
  }

  /**
   *Persists and verifies the separated Ed25519 Trust Store (`trust-store.json`).
   */
  private static persistSeparatedTrustStore(
    storePath: string,
    trustedPublicKeys: Record<string, TrustedEd25519PublicKeyEntry>,
    monotonicSequence: number
  ): void {
    const trustStorePath = KeyManagementService.getTrustStorePath(storePath);
    fs.mkdirSync(path.dirname(trustStorePath), { recursive: true });
    const entries = Object.values(trustedPublicKeys);
    const firstActive = entries.find((e) => e.status === 'ACTIVE') || entries[0];
    const rootAnchor =
      (process.env.WINHOOD_TRUST_ROOT_FINGERPRINT_SHA256 || '').trim() ||
      firstActive?.fingerprintSha256 ||
      null;

    const trustPayload: PersistedTrustStore = {
      version: 2,
      rootAnchorFingerprintSha256: rootAnchor,
      monotonicSequence,
      updatedAt: new Date().toISOString(),
      trustedPublicKeys,
    };

    const canonicalBody = JSON.stringify({
      version: trustPayload.version,
      rootAnchorFingerprintSha256: trustPayload.rootAnchorFingerprintSha256,
      monotonicSequence: trustPayload.monotonicSequence,
      trustedPublicKeys: trustPayload.trustedPublicKeys,
    });

    const masterEnv = (process.env.WINHOOD_KEYSTORE_MASTER_SECRET || '').trim();
    const macKey =
      masterEnv.length >= 16
        ? deriveHkdfPurposeKey(
            Buffer.from(masterEnv, 'utf8'),
            '77696e686f6f642d74727573742d7374',
            'winhood:purpose:trust-store-mac:v2'
          )
        : Buffer.from(KeyManagementService.computeSha256(`winhood-trust-anchor:${storePath}`), 'hex');

    trustPayload.integrityMacHex = crypto
      .createHmac('sha256', macKey)
      .update(canonicalBody, 'utf8')
      .digest('hex');

    const json = JSON.stringify(trustPayload, null, 2);
    const tmpPath = `${trustStorePath}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
    const fd = fs.openSync(tmpPath, 'w', 0o600);
    try {
      fs.writeFileSync(fd, json, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmpPath, trustStorePath);
    fs.chmodSync(trustStorePath, 0o600);
  }

  private static readSeparatedTrustStore(
    storePath: string
  ): Record<string, TrustedEd25519PublicKeyEntry> | null {
    const trustStorePath = KeyManagementService.getTrustStorePath(storePath);
    if (!fs.existsSync(trustStorePath)) return null;

    const raw = fs.readFileSync(trustStorePath, 'utf8');
    let parsed: PersistedTrustStore;
    try {
      parsed = JSON.parse(raw) as PersistedTrustStore;
    } catch {
      throw new Error(`TRUST_STORE_CORRUPTED: JSON inválido em ${trustStorePath}.`);
    }
    if (!parsed || !parsed.trustedPublicKeys || typeof parsed.trustedPublicKeys !== 'object') {
      throw new Error(`TRUST_STORE_INVALID_SCHEMA: Estrutura de chaves públicas inválida em ${trustStorePath}.`);
    }

    const canonicalBody = JSON.stringify({
      version: parsed.version,
      rootAnchorFingerprintSha256: parsed.rootAnchorFingerprintSha256,
      monotonicSequence: parsed.monotonicSequence,
      trustedPublicKeys: parsed.trustedPublicKeys,
    });
    const masterEnv = (process.env.WINHOOD_KEYSTORE_MASTER_SECRET || '').trim();
    const macKey =
      masterEnv.length >= 16
        ? deriveHkdfPurposeKey(
            Buffer.from(masterEnv, 'utf8'),
            '77696e686f6f642d74727573742d7374',
            'winhood:purpose:trust-store-mac:v2'
          )
        : Buffer.from(KeyManagementService.computeSha256(`winhood-trust-anchor:${storePath}`), 'hex');
    const expectedMac = crypto.createHmac('sha256', macKey).update(canonicalBody, 'utf8').digest('hex');

    if (parsed.integrityMacHex && parsed.integrityMacHex !== expectedMac) {
      throw new Error(
        `TRUST_STORE_INTEGRITY_VIOLATION: Assinatura de integridade do Trust Store (${trustStorePath}) inválida ou adulterada.`
      );
    }

    // Verify each entry's publicKeyPem matches its recorded fingerprintSha256
    for (const [kId, entry] of Object.entries(parsed.trustedPublicKeys)) {
      const actualFp = KeyManagementService.computeSha256(entry.publicKeyPem);
      if (actualFp !== entry.fingerprintSha256) {
        throw new Error(
          `TRUST_STORE_FINGERPRINT_MISMATCH: Chave pública ${kId} no Trust Store não corresponde ao fingerprint SHA-256 registrado.`
        );
      }
    }

    const pinnedRootFp = (process.env.WINHOOD_TRUST_ROOT_FINGERPRINT_SHA256 || '').trim();
    if (pinnedRootFp && parsed.rootAnchorFingerprintSha256 !== pinnedRootFp) {
      throw new Error(
        'TRUST_STORE_ROOT_ANCHOR_MISMATCH: Fingerprint raiz do Trust Store diverge de WINHOOD_TRUST_ROOT_FINGERPRINT_SHA256.'
      );
    }

    return parsed.trustedPublicKeys;
  }

  private static writeAtomicWithChecksum(
    storePath: string,
    payloadJson: string,
    monotonicSequence: number
  ): void {
    const dir = path.dirname(storePath);
    fs.mkdirSync(dir, { recursive: true });
    const checksumPath = `${storePath}.sha256`;
    const seqPath = `${storePath}.seq`;
    const backupPath = `${storePath}.bak`;

    if (fs.existsSync(storePath)) {
      try {
        fs.copyFileSync(storePath, backupPath);
        fs.chmodSync(backupPath, 0o600);
      } catch {
        // Non-fatal if backup copy failed before first write
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

    // Persist monotonic sequence anchor to detect rollback of keystore.json
    const tmpSeq = `${seqPath}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
    const sfd = fs.openSync(tmpSeq, 'w', 0o600);
    try {
      fs.writeFileSync(sfd, String(monotonicSequence), 'utf8');
      fs.fsyncSync(sfd);
    } finally {
      fs.closeSync(sfd);
    }
    fs.renameSync(tmpSeq, seqPath);
    fs.chmodSync(seqPath, 0o600);
  }

  private static readVerifiedStoreFile(
    storePath: string
  ): { store: PersistedKeyStore; integrityVerified: boolean; rollbackVerified: boolean } | null {
    if (!fs.existsSync(storePath)) return null;

    const checksumPath = `${storePath}.sha256`;
    const seqPath = `${storePath}.seq`;
    const raw = fs.readFileSync(storePath, 'utf8');

    if (fs.existsSync(checksumPath)) {
      const expectedSha = fs.readFileSync(checksumPath, 'utf8').trim();
      const actualSha = KeyManagementService.computeSha256(raw);
      if (expectedSha !== actualSha) {
        const backupPath = `${storePath}.bak`;
        if (fs.existsSync(backupPath) && KeyManagementService.resolveOperatingMode() !== 'PRODUCTION_SECURE') {
          const bakRaw = fs.readFileSync(backupPath, 'utf8');
          const bakParsed = JSON.parse(bakRaw) as PersistedKeyStore;
          if (bakParsed && bakParsed.keysHex && bakParsed.activeEvidenceKeyId && bakParsed.activeVaultKeyId) {
            return { store: bakParsed, integrityVerified: false, rollbackVerified: false };
          }
        }
        throw new Error(`KEYSTORE_INTEGRITY_VIOLATION: Checksum SHA-256 de ${storePath} não confere.`);
      }
    }

    const parsed = JSON.parse(raw) as PersistedKeyStore;
    if (!parsed || !parsed.keysHex || !parsed.activeEvidenceKeyId || !parsed.activeVaultKeyId) {
      throw new Error(`KEYSTORE_CORRUPTED: Estrutura inválida em ${storePath}.`);
    }

    let rollbackVerified = true;
    if (fs.existsSync(seqPath) && typeof parsed.monotonicSequence === 'number') {
      const recordedSeq = Number.parseInt(fs.readFileSync(seqPath, 'utf8').trim(), 10);
      if (Number.isFinite(recordedSeq) && parsed.monotonicSequence < recordedSeq) {
        if (KeyManagementService.resolveOperatingMode() !== 'RECOVERY') {
          throw new Error(
            `KEYSTORE_ROLLBACK_DETECTED: Sequência monotônica do keystore (${parsed.monotonicSequence}) é anterior ao último estado confirmado (${recordedSeq}).`
          );
        }
        rollbackVerified = false;
      }
    }

    let upgraded = false;

    // Upgrade legacy v1/v2 keystore or re-wrap DEK when migrating from local .kek to external master secret
    if (
      !parsed.wrappedDek ||
      parsed.envelopeVersion !== 'WINHOOD-ENVELOPE-V2' ||
      (parsed.wrappedDek.kekMechanism === 'HKDF_LOCAL_KEK_FILE' &&
        (process.env.WINHOOD_KEYSTORE_MASTER_SECRET || '').trim().length >= 16)
    ) {
      let dekBuffer: Buffer;
      if (parsed.wrappedDek && parsed.envelopeVersion === 'WINHOOD-ENVELOPE-V2') {
        // Migrate existing DEK from local .kek file to external/OS KEK
        const kekFilePath = `${storePath}.kek`;
        if (fs.existsSync(kekFilePath) && parsed.wrappedDek.aesGcmWrappedDek) {
          const rawKekSeed = Buffer.from(fs.readFileSync(kekFilePath, 'utf8').trim(), 'hex');
          const oldKek = deriveHkdfPurposeKey(
            rawKekSeed,
            parsed.wrappedDek.hkdfSaltHex,
            parsed.wrappedDek.hkdfInfo
          );
          const dekHex = decryptWithAes256GcmEnvelope(
            parsed.wrappedDek.aesGcmWrappedDek,
            oldKek,
            'winhood:dek:wrap:v2'
          );
          dekBuffer = Buffer.from(dekHex, 'hex');
        } else {
          dekBuffer = crypto.randomBytes(32);
        }
      } else {
        dekBuffer = crypto.randomBytes(32);
      }

      parsed.wrappedDek = KeyManagementService.wrapDekBuffer(dekBuffer, storePath);
      parsed.envelopeVersion = 'WINHOOD-ENVELOPE-V2';
      parsed.operatingMode = KeyManagementService.resolveOperatingMode();
      parsed.monotonicSequence = (parsed.monotonicSequence || 0) + 1;

      for (const [kId, entry] of Object.entries(parsed.keysHex)) {
        if (!entry.envelopeCipher && entry.secretHex) {
          const plainHex = tryDpapiUnprotectUtf8Legacy(entry.secretHex, entry.dpapiProtected);
          entry.envelopeCipher = encryptWithAes256GcmEnvelope(
            plainHex,
            dekBuffer,
            `winhood:key:${kId}:${entry.purpose}`
          );
          delete entry.secretHex;
        }
      }

      if (!parsed.ed25519Keys || !parsed.activeEd25519KeyId) {
        const now = new Date().toISOString();
        const edId = `wh-ed25519-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
        const pair = generateEd25519Pair();
        parsed.ed25519Keys = {
          [edId]: {
            purpose: 'EVIDENCE_ED25519',
            privateKeyEnvelope: encryptWithAes256GcmEnvelope(
              pair.privateKeyPem,
              dekBuffer,
              `winhood:key:${edId}:EVIDENCE_ED25519`
            ),
            publicKeyPem: pair.publicKeyPem,
            createdAt: now,
            validFrom: now,
            validUntil: null,
            status: 'ACTIVE',
            rotatedAt: null,
            revokedAt: null,
          },
        };
        parsed.activeEd25519KeyId = edId;
      } else {
        for (const [edId, edEntry] of Object.entries(parsed.ed25519Keys)) {
          if (!edEntry.privateKeyEnvelope && edEntry.privateKeyPem) {
            const plainPem = tryDpapiUnprotectUtf8Legacy(edEntry.privateKeyPem, edEntry.dpapiProtected);
            edEntry.privateKeyEnvelope = encryptWithAes256GcmEnvelope(
              plainPem,
              dekBuffer,
              `winhood:key:${edId}:EVIDENCE_ED25519`
            );
            delete edEntry.privateKeyPem;
          }
        }
      }

      parsed.version = 3;
      upgraded = true;
    }

    if (!parsed.trustedPublicKeys) {
      parsed.trustedPublicKeys = {};
      upgraded = true;
    }
    for (const [edId, edEntry] of Object.entries(parsed.ed25519Keys || {})) {
      if (!parsed.trustedPublicKeys[edId]) {
        parsed.trustedPublicKeys[edId] = {
          keyId: edId,
          publicKeyPem: edEntry.publicKeyPem,
          fingerprintSha256: KeyManagementService.computeSha256(edEntry.publicKeyPem),
          validFrom: edEntry.validFrom || edEntry.createdAt,
          validUntil: edEntry.validUntil || null,
          revokedAt: edEntry.revokedAt || null,
          revocationReason: edEntry.revocationReason || null,
          status:
            edEntry.status === 'REVOKED'
              ? 'REVOKED'
              : edEntry.status === 'RETIRED_VERIFY_ONLY'
                ? 'ROTATED_VERIFY_ONLY'
                : 'ACTIVE',
        };
        upgraded = true;
      }
    }

    // Synchronize or verify separated Trust Store
    const trustStorePath = KeyManagementService.getTrustStorePath(storePath);
    if (!fs.existsSync(trustStorePath)) {
      KeyManagementService.persistSeparatedTrustStore(
        storePath,
        parsed.trustedPublicKeys,
        parsed.monotonicSequence || 1
      );
    } else {
      const separatedKeys = KeyManagementService.readSeparatedTrustStore(storePath);
      if (separatedKeys) {
        parsed.trustedPublicKeys = separatedKeys;
      }
    }

    if (!parsed.rotationHistory) {
      parsed.rotationHistory = [];
      upgraded = true;
    }

    if (upgraded || !fs.existsSync(checksumPath)) {
      KeyManagementService.persistStore(parsed, storePath);
    }

    return { store: parsed, integrityVerified: true, rollbackVerified };
  }

  private static loadOrInitializeStore(customPath?: string): {
    store: PersistedKeyStore;
    integrityVerified: boolean;
    rollbackVerified: boolean;
  } {
    KeyManagementService.assertSecretDomainSeparation();
    const storePath = KeyManagementService.getStorePath(customPath);
    const existing = KeyManagementService.readVerifiedStoreFile(storePath);
    if (existing) {
      return existing;
    }

    const now = new Date().toISOString();
    const evidenceKeyId = `wh-hmac-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
    const ed25519KeyId = `wh-ed25519-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
    const vaultKeyId = `wh-vault-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;

    // Generate CSPRNG 256-bit DEK independent of machine characteristics
    const dekBuffer = crypto.randomBytes(32);
    const wrappedDek = KeyManagementService.wrapDekBuffer(dekBuffer, storePath);

    const hmacSecretHex = crypto.randomBytes(32).toString('hex');
    const vaultSecretHex = crypto.randomBytes(32).toString('hex');
    const edPair = generateEd25519Pair();

    const initialStore: PersistedKeyStore = {
      version: 3,
      envelopeVersion: 'WINHOOD-ENVELOPE-V2',
      operatingMode: KeyManagementService.resolveOperatingMode(),
      monotonicSequence: 1,
      wrappedDek,
      activeEvidenceKeyId: evidenceKeyId,
      activeEd25519KeyId: ed25519KeyId,
      activeVaultKeyId: vaultKeyId,
      keysHex: {
        [evidenceKeyId]: {
          purpose: 'EVIDENCE_HMAC',
          envelopeCipher: encryptWithAes256GcmEnvelope(
            hmacSecretHex,
            dekBuffer,
            `winhood:key:${evidenceKeyId}:EVIDENCE_HMAC`
          ),
          createdAt: now,
          status: 'ACTIVE',
          rotatedAt: null,
          revokedAt: null,
        },
        [vaultKeyId]: {
          purpose: 'TOKEN_VAULT_AES256',
          envelopeCipher: encryptWithAes256GcmEnvelope(
            vaultSecretHex,
            dekBuffer,
            `winhood:key:${vaultKeyId}:TOKEN_VAULT_AES256`
          ),
          createdAt: now,
          status: 'ACTIVE',
          rotatedAt: null,
          revokedAt: null,
        },
      },
      ed25519Keys: {
        [ed25519KeyId]: {
          purpose: 'EVIDENCE_ED25519',
          privateKeyEnvelope: encryptWithAes256GcmEnvelope(
            edPair.privateKeyPem,
            dekBuffer,
            `winhood:key:${ed25519KeyId}:EVIDENCE_ED25519`
          ),
          publicKeyPem: edPair.publicKeyPem,
          createdAt: now,
          validFrom: now,
          validUntil: null,
          status: 'ACTIVE',
          rotatedAt: null,
          revokedAt: null,
        },
      },
      trustedPublicKeys: {
        [ed25519KeyId]: {
          keyId: ed25519KeyId,
          publicKeyPem: edPair.publicKeyPem,
          fingerprintSha256: KeyManagementService.computeSha256(edPair.publicKeyPem),
          validFrom: now,
          validUntil: null,
          revokedAt: null,
          revocationReason: null,
          status: 'ACTIVE',
        },
      },
      rotationHistory: [],
      adminTokenSha256: process.env.WINHOOD_ADMIN_TOKEN
        ? crypto.createHash('sha256').update(process.env.WINHOOD_ADMIN_TOKEN, 'utf8').digest('hex')
        : null,
    };

    KeyManagementService.persistStore(initialStore, storePath);
    return { store: initialStore, integrityVerified: true, rollbackVerified: true };
  }

  private static decryptSymmetricKeyHex(
    store: PersistedKeyStore,
    keyId: string,
    storePath: string
  ): string {
    const entry = store.keysHex[keyId];
    if (!entry) {
      throw new Error(`KEYSTORE_KEY_NOT_FOUND: Chave ${keyId} não encontrada.`);
    }
    if (entry.status === 'REVOKED') {
      throw new Error(`KEYSTORE_KEY_REVOKED: A chave ${keyId} foi revogada e não pode ser utilizada.`);
    }
    if (entry.envelopeCipher && store.wrappedDek) {
      const dekBuffer = KeyManagementService.unwrapDekBuffer(store.wrappedDek, storePath);
      return decryptWithAes256GcmEnvelope(
        entry.envelopeCipher,
        dekBuffer,
        `winhood:key:${keyId}:${entry.purpose}`
      );
    }
    if (entry.secretHex) {
      return tryDpapiUnprotectUtf8Legacy(entry.secretHex, entry.dpapiProtected);
    }
    throw new Error(`KEYSTORE_KEY_EMPTY: Material criptográfico ausente para ${keyId}.`);
  }

  private static decryptEd25519PrivateKeyPem(
    store: PersistedKeyStore,
    keyId: string,
    storePath: string
  ): string {
    const entry = store.ed25519Keys[keyId];
    if (!entry) {
      throw new Error(`KEYSTORE_ED25519_NOT_FOUND: Chave Ed25519 ${keyId} não encontrada.`);
    }
    if (entry.status === 'REVOKED') {
      throw new Error(`KEYSTORE_ED25519_REVOKED: Chave Ed25519 ${keyId} encontra-se revogada.`);
    }
    if (entry.privateKeyEnvelope && store.wrappedDek) {
      const dekBuffer = KeyManagementService.unwrapDekBuffer(store.wrappedDek, storePath);
      return decryptWithAes256GcmEnvelope(
        entry.privateKeyEnvelope,
        dekBuffer,
        `winhood:key:${keyId}:EVIDENCE_ED25519`
      );
    }
    if (entry.privateKeyPem) {
      return tryDpapiUnprotectUtf8Legacy(entry.privateKeyPem, entry.dpapiProtected);
    }
    throw new Error(`KEYSTORE_ED25519_EMPTY: Chave privada ausente para ${keyId}.`);
  }

  private static persistStore(store: PersistedKeyStore, customPath?: string): void {
    const storePath = KeyManagementService.getStorePath(customPath);
    const seq = (store.monotonicSequence || 0) + 1;
    store.monotonicSequence = seq;
    try {
      KeyManagementService.writeAtomicWithChecksum(storePath, JSON.stringify(store, null, 2), seq);
      if (store.trustedPublicKeys) {
        KeyManagementService.persistSeparatedTrustStore(storePath, store.trustedPublicKeys, seq);
      }
    } catch (err: any) {
      throw new Error(
        `KEYSTORE_PERSISTENCE_FAILED: Não foi possível persistir o keystore de forma segura em ${storePath}: ${err?.message || String(err)}`,
        { cause: err }
      );
    }
  }

  public static getActiveEvidenceHmacKey(customPath?: string): {
    keyId: string;
    secret: string;
    origin: 'ENV_EXTERNAL' | 'HOST_CSPRNG_KEYSTORE';
  } {
    KeyManagementService.assertSecretDomainSeparation();
    const envVal = process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
    if (envVal && envVal.trim().length >= 16) {
      const derived = deriveHkdfPurposeKey(
        Buffer.from(envVal.trim(), 'utf8'),
        '77696e686f6f642d65766964656e6365',
        'winhood:purpose:evidence-hmac:v2'
      );
      return {
        keyId: process.env.WINHOOD_EVIDENCE_KEY_ID || 'ENV-HMAC-KEY',
        secret: derived.toString('hex'),
        origin: 'ENV_EXTERNAL',
      };
    }

    if (process.env.WINHOOD_REQUIRE_ENV_SECRETS === 'true') {
      throw new Error(
        'KEY_MANAGEMENT_ENV_SECRET_REQUIRED: Defina WINHOOD_EVIDENCE_HMAC_SECRET (>= 16 caracteres) quando WINHOOD_REQUIRE_ENV_SECRETS=true.'
      );
    }

    const storePath = KeyManagementService.getStorePath(customPath);
    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    return {
      keyId: store.activeEvidenceKeyId,
      secret: KeyManagementService.decryptSymmetricKeyHex(store, store.activeEvidenceKeyId, storePath),
      origin: 'HOST_CSPRNG_KEYSTORE',
    };
  }

  public static getEvidenceSecretByKeyId(keyId: string, customPath?: string): string | null {
    KeyManagementService.assertSecretDomainSeparation();
    const envVal = process.env.WINHOOD_EVIDENCE_HMAC_SECRET;
    const envKeyId = process.env.WINHOOD_EVIDENCE_KEY_ID || 'ENV-HMAC-KEY';
    if (envVal && envVal.trim().length >= 16 && keyId === envKeyId) {
      const derived = deriveHkdfPurposeKey(
        Buffer.from(envVal.trim(), 'utf8'),
        '77696e686f6f642d65766964656e6365',
        'winhood:purpose:evidence-hmac:v2'
      );
      return derived.toString('hex');
    }

    const storePath = KeyManagementService.getStorePath(customPath);
    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    if (!store.keysHex[keyId] || store.keysHex[keyId].status === 'REVOKED') {
      return null;
    }
    return KeyManagementService.decryptSymmetricKeyHex(store, keyId, storePath);
  }

  public static getActiveEvidenceEd25519Key(customPath?: string): {
    keyId: string;
    privateKeyPem: string;
    publicKeyPem: string;
  } {
    const storePath = KeyManagementService.getStorePath(customPath);
    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    const active = store.ed25519Keys[store.activeEd25519KeyId];
    return {
      keyId: store.activeEd25519KeyId,
      privateKeyPem: KeyManagementService.decryptEd25519PrivateKeyPem(
        store,
        store.activeEd25519KeyId,
        storePath
      ),
      publicKeyPem: active.publicKeyPem,
    };
  }

  public static getEd25519PublicKeyByKeyId(keyId: string, customPath?: string): string | null {
    const storePath = KeyManagementService.getStorePath(customPath);
    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    const separatedTrust = KeyManagementService.readSeparatedTrustStore(storePath);
    const trusted = separatedTrust?.[keyId] || store.trustedPublicKeys?.[keyId];
    if (trusted) {
      if (trusted.status === 'REVOKED' || trusted.revokedAt) {
        return null;
      }
      return trusted.publicKeyPem;
    }
    const fallback = store.ed25519Keys?.[keyId];
    if (!fallback || fallback.status === 'REVOKED') return null;
    return fallback.publicKeyPem;
  }

  /**
   * Verifies an Ed25519 public key against the separated Trusted Public Key Registry (`trust-store.json`),
   * preventing a tampered manifest or keystore from substituting its own self-signed public key.
   */
  public static verifyTrustedEd25519PublicKey(
    keyId: string | undefined,
    attachedPublicKeyPem?: string,
    signedAtIso?: string,
    customPath?: string
  ): TrustedPublicKeyVerificationResult {
    const storePath = KeyManagementService.getStorePath(customPath);
    let trustMap: Record<string, TrustedEd25519PublicKeyEntry>;
    try {
      const separated = KeyManagementService.readSeparatedTrustStore(storePath);
      if (separated) {
        trustMap = separated;
      } else {
        const { store } = KeyManagementService.loadOrInitializeStore(customPath);
        trustMap = KeyManagementService.readSeparatedTrustStore(storePath) || store.trustedPublicKeys || {};
      }
    } catch (err: any) {
      return {
        trusted: false,
        keyId: keyId || null,
        publicKeyPem: null,
        status: 'UNTRUSTED',
        reason: err?.message || 'Falha de integridade no Trust Store separado.',
      };
    }

    if (!keyId) {
      return {
        trusted: false,
        keyId: null,
        publicKeyPem: null,
        status: 'UNTRUSTED',
        reason: 'Manifesto não declara identificador de chave Ed25519 (ed25519KeyId ausente).',
      };
    }

    const trustedEntry = trustMap[keyId];
    if (!trustedEntry) {
      return {
        trusted: false,
        keyId,
        publicKeyPem: null,
        status: 'UNTRUSTED',
        reason: `Chave Ed25519 ${keyId} não consta no Registro de Chaves Públicas Confiáveis (Trust Store).`,
      };
    }

    if (trustedEntry.status === 'REVOKED' || trustedEntry.revokedAt) {
      return {
        trusted: false,
        keyId,
        publicKeyPem: null,
        status: 'REVOKED',
        reason: `Chave Ed25519 ${keyId} revogada em ${trustedEntry.revokedAt || 'data registrada'} (${trustedEntry.revocationReason || 'sem motivo especificado'}).`,
      };
    }

    if (signedAtIso && trustedEntry.validUntil) {
      const signedTs = Date.parse(signedAtIso);
      const untilTs = Date.parse(trustedEntry.validUntil);
      if (Number.isFinite(signedTs) && Number.isFinite(untilTs) && signedTs > untilTs) {
        return {
          trusted: false,
          keyId,
          publicKeyPem: null,
          status: 'EXPIRED',
          reason: `Chave Ed25519 ${keyId} expirada em ${trustedEntry.validUntil}.`,
        };
      }
    }

    if (attachedPublicKeyPem && attachedPublicKeyPem.trim() !== trustedEntry.publicKeyPem.trim()) {
      return {
        trusted: false,
        keyId,
        publicKeyPem: null,
        status: 'UNTRUSTED',
        reason: `Chave pública anexada ao manifesto diverge da chave registrada no Trust Store para ${keyId}.`,
      };
    }

    return {
      trusted: true,
      keyId,
      publicKeyPem: trustedEntry.publicKeyPem,
      status: trustedEntry.status,
      reason: `Chave Ed25519 ${keyId} verificada no Trust Store separado (${trustedEntry.status}).`,
    };
  }

  public static revokeKey(
    keyId: string,
    reason = 'Revogação administrativa de segurança',
    customPath?: string
  ): void {
    const storePath = KeyManagementService.getStorePath(customPath);
    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    const now = new Date().toISOString();

    if (store.ed25519Keys?.[keyId]) {
      store.ed25519Keys[keyId].status = 'REVOKED';
      store.ed25519Keys[keyId].revokedAt = now;
      store.ed25519Keys[keyId].revocationReason = reason;
    }
    if (store.trustedPublicKeys?.[keyId]) {
      store.trustedPublicKeys[keyId].status = 'REVOKED';
      store.trustedPublicKeys[keyId].revokedAt = now;
      store.trustedPublicKeys[keyId].revocationReason = reason;
    }
    if (store.keysHex?.[keyId]) {
      store.keysHex[keyId].status = 'REVOKED';
      store.keysHex[keyId].revokedAt = now;
    }
    KeyManagementService.persistStore(store, storePath);
  }

  /**
   * Returns the active 256-bit AES-GCM Vault Key.
   * Strict Secret Policy: ONLY `WINHOOD_VAULT_SECRET` is accepted as an external vault secret for active encryption.
   * `SONAR_SECRET_SALT` is strictly forbidden as an active vault encryption secret (reserved for legacy decrypt-only migration).
   */
  public static getActiveVaultAesKey(customPath?: string): {
    keyId: string;
    keyBuffer: Buffer;
    origin: 'ENV_EXTERNAL' | 'HOST_CSPRNG_KEYSTORE';
  } {
    KeyManagementService.assertSecretDomainSeparation();
    const envVaultVal = (process.env.WINHOOD_VAULT_SECRET || '').trim();
    if (envVaultVal.length >= 16) {
      const derivedKey = deriveHkdfPurposeKey(
        Buffer.from(envVaultVal, 'utf8'),
        '77696e686f6f642d7661756c742d6165',
        'winhood:purpose:token-vault-aes256:v2'
      );
      return {
        keyId: 'ENV-VAULT-KEY',
        keyBuffer: derivedKey,
        origin: 'ENV_EXTERNAL',
      };
    }

    if (process.env.WINHOOD_REQUIRE_ENV_SECRETS === 'true') {
      throw new Error(
        'KEY_MANAGEMENT_ENV_SECRET_REQUIRED: Defina WINHOOD_VAULT_SECRET (>= 16 caracteres) quando WINHOOD_REQUIRE_ENV_SECRETS=true. SONAR_SECRET_SALT não é aceito como substituto de WINHOOD_VAULT_SECRET.'
      );
    }

    const storePath = KeyManagementService.getStorePath(customPath);
    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    const hex = KeyManagementService.decryptSymmetricKeyHex(store, store.activeVaultKeyId, storePath);
    return {
      keyId: store.activeVaultKeyId,
      keyBuffer: Buffer.from(hex, 'hex'),
      origin: 'HOST_CSPRNG_KEYSTORE',
    };
  }

  /**
   * Resolves a vault key by keyId for decryption.
   * Supports controlled read-only backward compatibility for legacy `ENV-VAULT-KEY` records encrypted under `SONAR_SECRET_SALT`.
   */
  public static getVaultKeyBufferByKeyId(keyId: string, customPath?: string): Buffer | null {
    KeyManagementService.assertSecretDomainSeparation();
    if (keyId === 'ENV-VAULT-KEY') {
      const envVaultVal = (process.env.WINHOOD_VAULT_SECRET || '').trim();
      if (envVaultVal.length >= 16) {
        return deriveHkdfPurposeKey(
          Buffer.from(envVaultVal, 'utf8'),
          '77696e686f6f642d7661756c742d6165',
          'winhood:purpose:token-vault-aes256:v2'
        );
      }
      const legacySonarSalt = (process.env.SONAR_SECRET_SALT || '').trim();
      if (legacySonarSalt.length >= 16) {
        return deriveHkdfPurposeKey(
          Buffer.from(legacySonarSalt, 'utf8'),
          '77696e686f6f642d7661756c742d6165',
          'winhood:purpose:token-vault-aes256:v2'
        );
      }
      return null;
    }

    if (keyId === 'LEGACY-SONAR-SALT-KEY') {
      const legacySonarSalt = (process.env.SONAR_SECRET_SALT || '').trim();
      if (legacySonarSalt.length >= 16) {
        return deriveHkdfPurposeKey(
          Buffer.from(legacySonarSalt, 'utf8'),
          '77696e686f6f642d7661756c742d6165',
          'winhood:purpose:token-vault-aes256:v2'
        );
      }
      return null;
    }

    const storePath = KeyManagementService.getStorePath(customPath);
    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    if (!store.keysHex[keyId] || store.keysHex[keyId].status === 'REVOKED') return null;
    const hex = KeyManagementService.decryptSymmetricKeyHex(store, keyId, storePath);
    return Buffer.from(hex, 'hex');
  }

  public static rotateKey(
    purpose: 'EVIDENCE_HMAC' | 'EVIDENCE_ED25519' | 'TOKEN_VAULT_AES256',
    customPath?: string,
    onVaultReencrypt?: (ctx: VaultReencryptContext) => void
  ): ManagedKeyRecord {
    const storePath = KeyManagementService.getStorePath(customPath);
    const { store } = KeyManagementService.loadOrInitializeStore(customPath);
    const now = new Date().toISOString();
    const dekBuffer = KeyManagementService.unwrapDekBuffer(store.wrappedDek!, storePath);

    if (purpose === 'EVIDENCE_ED25519') {
      const prevKeyId = store.activeEd25519KeyId;
      if (store.ed25519Keys[prevKeyId]) {
        store.ed25519Keys[prevKeyId].status = 'RETIRED_VERIFY_ONLY';
        store.ed25519Keys[prevKeyId].rotatedAt = now;
      }
      if (store.trustedPublicKeys?.[prevKeyId]) {
        store.trustedPublicKeys[prevKeyId].status = 'ROTATED_VERIFY_ONLY';
      }

      const newKeyId = `wh-ed25519-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
      const pair = generateEd25519Pair();

      store.ed25519Keys[newKeyId] = {
        purpose: 'EVIDENCE_ED25519',
        privateKeyEnvelope: encryptWithAes256GcmEnvelope(
          pair.privateKeyPem,
          dekBuffer,
          `winhood:key:${newKeyId}:EVIDENCE_ED25519`
        ),
        publicKeyPem: pair.publicKeyPem,
        createdAt: now,
        validFrom: now,
        validUntil: null,
        status: 'ACTIVE',
        rotatedAt: null,
        revokedAt: null,
      };
      store.trustedPublicKeys = store.trustedPublicKeys || {};
      store.trustedPublicKeys[newKeyId] = {
        keyId: newKeyId,
        publicKeyPem: pair.publicKeyPem,
        fingerprintSha256: KeyManagementService.computeSha256(pair.publicKeyPem),
        validFrom: now,
        validUntil: null,
        revokedAt: null,
        revocationReason: null,
        status: 'ACTIVE',
      };
      store.activeEd25519KeyId = newKeyId;
      store.rotationHistory = store.rotationHistory || [];
      store.rotationHistory.push({
        timestamp: now,
        purpose: 'EVIDENCE_ED25519',
        previousKeyId: prevKeyId,
        newKeyId,
        reason: 'Rotação programada de par assimétrico Ed25519 com preservação no Trust Store separado',
        monotonicSequence: (store.monotonicSequence || 0) + 1,
      });
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
        ? Buffer.from(KeyManagementService.decryptSymmetricKeyHex(store, prevKeyId, storePath), 'hex')
        : null;

    const prefix = purpose === 'EVIDENCE_HMAC' ? 'wh-hmac' : 'wh-vault';
    const newKeyId = `${prefix}-${now.slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
    const rawKeyHex = crypto.randomBytes(32).toString('hex');
    const newKeyBuffer = Buffer.from(rawKeyHex, 'hex');

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

    store.keysHex[newKeyId] = {
      purpose,
      envelopeCipher: encryptWithAes256GcmEnvelope(
        rawKeyHex,
        dekBuffer,
        `winhood:key:${newKeyId}:${purpose}`
      ),
      createdAt: now,
      status: 'ACTIVE',
      rotatedAt: null,
      revokedAt: null,
    };

    if (purpose === 'EVIDENCE_HMAC') {
      store.activeEvidenceKeyId = newKeyId;
    } else {
      store.activeVaultKeyId = newKeyId;
    }

    store.rotationHistory = store.rotationHistory || [];
    store.rotationHistory.push({
      timestamp: now,
      purpose,
      previousKeyId: prevKeyId,
      newKeyId,
      reason: `Rotação criptográfica de chave ${purpose} sob DEK Envelope V2`,
      monotonicSequence: (store.monotonicSequence || 0) + 1,
    });

    KeyManagementService.persistStore(store, customPath);

    return {
      keyId: newKeyId,
      purpose,
      createdAt: now,
      rotatedAt: null,
      status: 'ACTIVE',
      fingerprintSha256: KeyManagementService.computeSha256(rawKeyHex).slice(0, 16),
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
    const storePath = KeyManagementService.getStorePath(customPath);
    const trustStorePath = KeyManagementService.getTrustStorePath(customPath);
    const { store, integrityVerified, rollbackVerified } =
      KeyManagementService.loadOrInitializeStore(customPath);
    const hasEnvEvidence = Boolean(
      process.env.WINHOOD_EVIDENCE_HMAC_SECRET && process.env.WINHOOD_EVIDENCE_HMAC_SECRET.trim().length >= 16
    );
    const hasEnvVault = Boolean(
      process.env.WINHOOD_VAULT_SECRET && process.env.WINHOOD_VAULT_SECRET.trim().length >= 16
    );

    const symKeys: ManagedKeyRecord[] = Object.entries(store.keysHex).map(([keyId, info]) => {
      const fpSource = info.envelopeCipher
        ? info.envelopeCipher.ciphertextHex
        : info.secretHex || keyId;
      return {
        keyId,
        purpose: info.purpose,
        createdAt: info.createdAt,
        rotatedAt: info.rotatedAt,
        revokedAt: info.revokedAt || null,
        status: info.status,
        fingerprintSha256: KeyManagementService.computeSha256(fpSource).slice(0, 16),
        algorithm: info.purpose === 'EVIDENCE_HMAC' ? 'HMAC-SHA256' : 'AES-256-GCM',
      };
    });

    const asymKeys: ManagedKeyRecord[] = Object.entries(store.ed25519Keys || {}).map(([keyId, info]) => ({
      keyId,
      purpose: info.purpose,
      createdAt: info.createdAt,
      rotatedAt: info.rotatedAt,
      revokedAt: info.revokedAt || null,
      status: info.status,
      fingerprintSha256: KeyManagementService.computeSha256(info.publicKeyPem).slice(0, 16),
      algorithm: 'ED25519',
    }));

    const keys = [...symKeys, ...asymKeys];
    const trustedPublicKeys = Object.values(store.trustedPublicKeys || {});
    const operatingMode = store.operatingMode || KeyManagementService.resolveOperatingMode();
    const kekMechanism = store.wrappedDek?.kekMechanism || 'HKDF_LOCAL_KEK_FILE';

    const securityWarnings: string[] = [];
    if ((process.env.WINHOOD_MASTER_KEY_SECRET || '').trim().length >= 16) {
      securityWarnings.push(
        'Alias legado WINHOOD_MASTER_KEY_SECRET detectado; migre para o nome canônico WINHOOD_KEYSTORE_MASTER_SECRET.'
      );
    }
    if ((process.env.SONAR_SECRET_SALT || '').trim().length >= 16 && !hasEnvVault) {
      securityWarnings.push(
        'SONAR_SECRET_SALT detectado apenas para leitura retrocompatível; configure WINHOOD_VAULT_SECRET para cifragem ativa.'
      );
    }
    if (process.env.NODE_ENV === 'production' || operatingMode === 'PRODUCTION_SECURE') {
      if (!hasEnvEvidence) {
        securityWarnings.push(
          'Produção utilizando keystore local para HMAC de evidências; configure WINHOOD_EVIDENCE_HMAC_SECRET.'
        );
      }
      if (!hasEnvVault) {
        securityWarnings.push(
          'Produção utilizando keystore local para cofre AES-256; configure WINHOOD_VAULT_SECRET.'
        );
      }
    }
    securityWarnings.push(
      'Limitação física local: sem TPM ou âncora remota independente, um atacante com escrita administrativa total no diretório local pode substituir simultaneamente keystore.json, .sha256, .seq e trust-store.json.'
    );

    return {
      keystorePath: storePath,
      trustStorePath,
      integrityVerified,
      trustStoreSeparated: fs.existsSync(trustStorePath),
      hardwareTpmOrRemoteAnchorAvailable: Boolean(process.env.WINHOOD_TRUST_ROOT_FINGERPRINT_SHA256),
      envelopeVersion: store.envelopeVersion || 'WINHOOD-ENVELOPE-V2',
      operatingMode,
      kekProtectionMechanism: kekMechanism,
      monotonicSequence: store.monotonicSequence || 1,
      rollbackProtectionVerified: rollbackVerified,
      dpapiSupported: os.platform() === 'win32',
      macosKeychainAvailable: os.platform() === 'darwin' && fs.existsSync('/usr/bin/security'),
      linuxSecretServiceAvailable: os.platform() === 'linux' && Boolean(process.env.DBUS_SESSION_BUS_ADDRESS),
      keyOrigin: hasEnvEvidence || hasEnvVault ? 'ENV_EXTERNAL' : 'HOST_CSPRNG_KEYSTORE',
      productionEnvSecretConfigured: hasEnvEvidence && hasEnvVault,
      securityWarnings,
      activeEvidenceKeyId: store.activeEvidenceKeyId,
      activeEd25519KeyId: store.activeEd25519KeyId,
      activeVaultKeyId: store.activeVaultKeyId,
      adminTokenConfigured: Boolean(process.env.WINHOOD_ADMIN_TOKEN || store.adminTokenSha256),
      totalKeysTracked: keys.length,
      trustedPublicKeysCount: trustedPublicKeys.length,
      keys,
      trustedPublicKeys,
      rotationHistory: store.rotationHistory || [],
    };
  }
}
