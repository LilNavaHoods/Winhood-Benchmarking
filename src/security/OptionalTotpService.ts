import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { KeyManagementService, type VaultReencryptContext } from './KeyManagementService';
import type { OptionalTotpStatus } from '../shared/authTypes';

/**
 * OptionalTotpService — RFC-6238 Optional 2FA Lock for Local WinHood Workspace.
 *
 * Design principles:
 * - Unrestricted local access by default (`enabled: false`, `unlocked: true`).
 * - Zero user accounts, zero passwords, zero PINs, zero OAuth, zero WebAuthn, zero RBAC.
 * - When enabled by the user, protects the local workspace with RFC-6238 TOTP (6 digits, 30s)
 *   and 8 single-use recovery codes.
 * - TOTP secrets are encrypted at rest with AES-256-GCM via KeyManagementService.
 * - Recovery codes are stored solely as per-code salted SHA-256 hashes and verified with
 *   crypto.timingSafeEqual.
 * - Strict anti-replay on TOTP time steps (`lastAcceptedStep`) and sliding-window rate limiting.
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const TOTP_PERIOD_SECONDS = 30;
const UNLOCK_SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
const MAX_FAILED_ATTEMPTS = 5;
const RATE_LIMIT_WINDOW_MS = 60_000;

export interface SaltedRecoveryCodeHash {
  saltHex: string;
  hashHex: string;
}

interface PersistedTotpConfig {
  version: 1;
  enabled: boolean;
  encryptedSecret: string | null;
  encryptedPendingSecret: string | null;
  recoveryCodeHashes: SaltedRecoveryCodeHash[];
  pendingRecoveryCodeHashes: SaltedRecoveryCodeHash[];
  lastAcceptedStep: number | null;
  configuredAt: string | null;
  updatedAt: string;
}

interface UnlockSessionRecord {
  tokenHashHex: string;
  csrfToken: string;
  createdAtMs: number;
  expiresAtMs: number;
}

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export function base32Decode(str: string): Buffer {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function computeHotp(secretBase32: string, counter: number): string {
  const key = base32Decode(secretBase32);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter), 0);
  const hmac = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    (((hmac[offset]! & 0x7f) << 24) |
      ((hmac[offset + 1]! & 0xff) << 16) |
      ((hmac[offset + 2]! & 0xff) << 8) |
      (hmac[offset + 3]! & 0xff)) %
    1_000_000;
  return String(code).padStart(6, '0');
}

export function generateTotpCode(secretBase32: string, atMs = Date.now()): string {
  const step = Math.floor(atMs / 1000 / TOTP_PERIOD_SECONDS);
  return computeHotp(secretBase32, step);
}

export function verifyTotpCode(
  secretBase32: string,
  candidateCode: string,
  atMs = Date.now()
): boolean {
  const clean = (candidateCode || '').replace(/[\s-]/g, '').trim();
  if (!/^\d{6}$/.test(clean)) return false;
  const step = Math.floor(atMs / 1000 / TOTP_PERIOD_SECONDS);
  for (const delta of [-1, 0, 1]) {
    const expected = computeHotp(secretBase32, step + delta);
    if (crypto.timingSafeEqual(Buffer.from(clean, 'utf8'), Buffer.from(expected, 'utf8'))) {
      return true;
    }
  }
  return false;
}

function verifyTotpCodeWithReplayCheck(
  secretBase32: string,
  candidateCode: string,
  lastAcceptedStep: number | null,
  atMs = Date.now()
): { valid: boolean; matchedStep: number | null; replayRejected: boolean } {
  const clean = (candidateCode || '').replace(/[\s-]/g, '').trim();
  if (!/^\d{6}$/.test(clean)) {
    return { valid: false, matchedStep: null, replayRejected: false };
  }
  const currentStep = Math.floor(atMs / 1000 / TOTP_PERIOD_SECONDS);
  for (const delta of [-1, 0, 1]) {
    const candidateStep = currentStep + delta;
    const expected = computeHotp(secretBase32, candidateStep);
    if (crypto.timingSafeEqual(Buffer.from(clean, 'utf8'), Buffer.from(expected, 'utf8'))) {
      if (typeof lastAcceptedStep === 'number' && candidateStep <= lastAcceptedStep) {
        return { valid: false, matchedStep: candidateStep, replayRejected: true };
      }
      return { valid: true, matchedStep: candidateStep, replayRejected: false };
    }
  }
  return { valid: false, matchedStep: null, replayRejected: false };
}

function hashRecoveryCodeWithSalt(normalizedHex: string, saltHex: string): string {
  return crypto
    .createHash('sha256')
    .update(`winhood-totp-rc:v1:${saltHex}:${normalizedHex}`)
    .digest('hex');
}

function generateRecoveryCodesSet(count = 8): {
  plaintextCodes: string[];
  codeHashes: SaltedRecoveryCodeHash[];
} {
  const plaintextCodes: string[] = [];
  const codeHashes: SaltedRecoveryCodeHash[] = [];
  for (let i = 0; i < count; i++) {
    const rawHex = crypto.randomBytes(4).toString('hex').toUpperCase();
    const formatted = `${rawHex.slice(0, 4)}-${rawHex.slice(4, 8)}`;
    const saltHex = crypto.randomBytes(16).toString('hex');
    plaintextCodes.push(formatted);
    codeHashes.push({
      saltHex,
      hashHex: hashRecoveryCodeWithSalt(rawHex, saltHex),
    });
  }
  return { plaintextCodes, codeHashes };
}

function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function defaultPersistedConfig(): PersistedTotpConfig {
  return {
    version: 1,
    enabled: false,
    encryptedSecret: null,
    encryptedPendingSecret: null,
    recoveryCodeHashes: [],
    pendingRecoveryCodeHashes: [],
    lastAcceptedStep: null,
    configuredAt: null,
    updatedAt: new Date().toISOString(),
  };
}

export class OptionalTotpService {
  public static readonly SESSION_TTL_MS = UNLOCK_SESSION_TTL_MS;
  private readonly configPath: string;
  private config: PersistedTotpConfig;
  private readonly unlockSessions = new Map<string, UnlockSessionRecord>();
  private readonly failedAttemptsByIp = new Map<string, number[]>();

  constructor(private readonly dataDir: string) {
    fs.mkdirSync(this.dataDir, { recursive: true });
    this.configPath = path.join(this.dataDir, 'totp_config.json');
    this.config = this.loadConfig();
  }

  private loadConfig(): PersistedTotpConfig {
    if (!fs.existsSync(this.configPath)) {
      return defaultPersistedConfig();
    }
    try {
      const raw = fs.readFileSync(this.configPath, 'utf8');
      const parsed = JSON.parse(raw) as Partial<PersistedTotpConfig>;
      return {
        version: 1,
        enabled: Boolean(parsed.enabled && parsed.encryptedSecret),
        encryptedSecret: typeof parsed.encryptedSecret === 'string' ? parsed.encryptedSecret : null,
        encryptedPendingSecret:
          typeof parsed.encryptedPendingSecret === 'string' ? parsed.encryptedPendingSecret : null,
        recoveryCodeHashes: Array.isArray(parsed.recoveryCodeHashes)
          ? parsed.recoveryCodeHashes
          : [],
        pendingRecoveryCodeHashes: Array.isArray(parsed.pendingRecoveryCodeHashes)
          ? parsed.pendingRecoveryCodeHashes
          : [],
        lastAcceptedStep:
          typeof parsed.lastAcceptedStep === 'number' ? parsed.lastAcceptedStep : null,
        configuredAt: typeof parsed.configuredAt === 'string' ? parsed.configuredAt : null,
        updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date().toISOString(),
      };
    } catch {
      return defaultPersistedConfig();
    }
  }

  private saveConfig(): void {
    this.config.updatedAt = new Date().toISOString();
    const tmpPath = `${this.configPath}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(this.config, null, 2), {
      encoding: 'utf8',
      mode: 0o600,
    });
    fs.renameSync(tmpPath, this.configPath);
  }

  private encryptSecretAtRest(plainSecret: string): string {
    const { keyId, keyBuffer } = KeyManagementService.getActiveVaultAesKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
    const encrypted = Buffer.concat([cipher.update(plainSecret, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `whvault:v1:${keyId}:${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  private decryptSecretAtRest(stored: string | null | undefined): string | null {
    if (!stored) return null;
    if (!stored.startsWith('whvault:v1:')) {
      throw new Error('TOTP_SECRET_CORRUPTED: Segredo TOTP fora do formato criptografado AES-256-GCM.');
    }
    const parts = stored.split(':');
    if (parts.length !== 6) {
      throw new Error('TOTP_SECRET_CORRUPTED: Envelope AES-256-GCM inválido.');
    }
    const [, , keyId, ivHex, tagHex, dataHex] = parts;
    const keyBuffer = KeyManagementService.getVaultKeyBufferByKeyId(keyId!);
    if (!keyBuffer) {
      throw new Error(`TOTP_VAULT_KEY_MISSING: Chave "${keyId}" não encontrada no KeyManagementService.`);
    }
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, Buffer.from(ivHex!, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex!, 'hex'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(dataHex!, 'hex')),
      decipher.final(),
    ]);
    return decrypted.toString('utf8');
  }

  public reencryptTotpSecrets(ctx: VaultReencryptContext): number {
    let reencrypted = 0;
    const reencryptOne = (stored: string | null): string | null => {
      if (!stored || !stored.startsWith('whvault:v1:')) return stored;
      const parts = stored.split(':');
      if (parts.length !== 6) return stored;
      const [, , keyId, ivHex, tagHex, dataHex] = parts;
      if (keyId !== ctx.oldKeyId) return stored;
      const decipher = crypto.createDecipheriv('aes-256-gcm', ctx.oldKeyBuffer, Buffer.from(ivHex!, 'hex'));
      decipher.setAuthTag(Buffer.from(tagHex!, 'hex'));
      const plain = Buffer.concat([
        decipher.update(Buffer.from(dataHex!, 'hex')),
        decipher.final(),
      ]).toString('utf8');
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', ctx.newKeyBuffer, iv);
      const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();
      reencrypted += 1;
      return `whvault:v1:${ctx.newKeyId}:${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
    };

    this.config.encryptedSecret = reencryptOne(this.config.encryptedSecret);
    this.config.encryptedPendingSecret = reencryptOne(this.config.encryptedPendingSecret);
    if (reencrypted > 0) {
      this.saveConfig();
    }
    return reencrypted;
  }

  private assertNotRateLimited(ipKey: string, nowMs = Date.now()): void {
    const key = ipKey || 'local';
    const existing = (this.failedAttemptsByIp.get(key) || []).filter(
      (ts) => nowMs - ts < RATE_LIMIT_WINDOW_MS
    );
    if (existing.length >= MAX_FAILED_ATTEMPTS) {
      this.failedAttemptsByIp.set(key, existing);
      throw new Error(
        'TOTP_RATE_LIMITED: Muitas tentativas inválidas em sequência. Aguarde 60 segundos e tente novamente.'
      );
    }
    this.failedAttemptsByIp.set(key, existing);
  }

  private recordFailedAttempt(ipKey: string, nowMs = Date.now()): void {
    const key = ipKey || 'local';
    const existing = (this.failedAttemptsByIp.get(key) || []).filter(
      (ts) => nowMs - ts < RATE_LIMIT_WINDOW_MS
    );
    existing.push(nowMs);
    this.failedAttemptsByIp.set(key, existing);
  }

  private clearFailedAttempts(ipKey: string): void {
    this.failedAttemptsByIp.delete(ipKey || 'local');
  }

  private pruneExpiredSessions(nowMs = Date.now()): void {
    for (const [key, sess] of this.unlockSessions.entries()) {
      if (sess.expiresAtMs <= nowMs) {
        this.unlockSessions.delete(key);
      }
    }
  }

  private createUnlockSession(nowMs = Date.now()): { unlockToken: string; csrfToken: string } {
    this.pruneExpiredSessions(nowMs);
    const unlockToken = crypto.randomBytes(32).toString('hex');
    const csrfToken = crypto.randomBytes(24).toString('hex');
    const tokenHashHex = sha256Hex(unlockToken);
    this.unlockSessions.set(tokenHashHex, {
      tokenHashHex,
      csrfToken,
      createdAtMs: nowMs,
      expiresAtMs: nowMs + UNLOCK_SESSION_TTL_MS,
    });
    return { unlockToken, csrfToken };
  }

  private findSession(unlockToken: string | null | undefined, nowMs = Date.now()): UnlockSessionRecord | null {
    if (!unlockToken || unlockToken.length < 32) return null;
    this.pruneExpiredSessions(nowMs);
    const candidateHash = sha256Hex(unlockToken);
    const candidateBuf = Buffer.from(candidateHash, 'hex');
    for (const session of this.unlockSessions.values()) {
      const storedBuf = Buffer.from(session.tokenHashHex, 'hex');
      if (
        storedBuf.length === candidateBuf.length &&
        crypto.timingSafeEqual(storedBuf, candidateBuf)
      ) {
        if (session.expiresAtMs > nowMs) {
          return session;
        }
        this.unlockSessions.delete(session.tokenHashHex);
        return null;
      }
    }
    return null;
  }

  public isEnabled(): boolean {
    return Boolean(this.config.enabled && this.config.encryptedSecret);
  }

  public isRequestUnlocked(unlockToken?: string | null, nowMs = Date.now()): boolean {
    if (!this.isEnabled()) return true;
    return this.findSession(unlockToken, nowMs) !== null;
  }

  public getSessionCsrfToken(unlockToken?: string | null): string | null {
    const sess = this.findSession(unlockToken);
    return sess ? sess.csrfToken : null;
  }

  public validateCsrfToken(unlockToken: string | null | undefined, providedCsrf: string): boolean {
    const sess = this.findSession(unlockToken);
    if (!sess || !providedCsrf) return false;
    const expectedBuf = Buffer.from(sess.csrfToken, 'utf8');
    const providedBuf = Buffer.from(providedCsrf.trim(), 'utf8');
    return expectedBuf.length === providedBuf.length && crypto.timingSafeEqual(expectedBuf, providedBuf);
  }

  public getStatus(unlockToken?: string | null): OptionalTotpStatus {
    const enabled = this.isEnabled();
    const unlocked = enabled ? this.isRequestUnlocked(unlockToken) : true;
    return {
      enabled,
      unlocked,
      remainingRecoveryCodes: enabled ? this.config.recoveryCodeHashes.length : 0,
      configuredAt: enabled ? this.config.configuredAt : null,
      serverTimeIso: new Date().toISOString(),
      totpPeriodSeconds: TOTP_PERIOD_SECONDS,
    };
  }

  public beginSetup(): {
    secret: string;
    otpauthUrl: string;
    recoveryCodes: string[];
    serverTimeIso: string;
    totpPeriodSeconds: number;
  } {
    const secret = base32Encode(crypto.randomBytes(20));
    const recovery = generateRecoveryCodesSet(8);
    this.config.encryptedPendingSecret = this.encryptSecretAtRest(secret);
    this.config.pendingRecoveryCodeHashes = recovery.codeHashes;
    this.saveConfig();

    const otpauthUrl = `otpauth://totp/WinHood:LocalWorkspace?secret=${secret}&issuer=WinHood&algorithm=SHA1&digits=6&period=${TOTP_PERIOD_SECONDS}`;
    return {
      secret,
      otpauthUrl,
      recoveryCodes: recovery.plaintextCodes,
      serverTimeIso: new Date().toISOString(),
      totpPeriodSeconds: TOTP_PERIOD_SECONDS,
    };
  }

  public confirmSetup(
    totpCode: string,
    ipKey = 'local',
    atMs = Date.now()
  ): {
    ok: true;
    enabled: true;
    unlocked: true;
    unlockToken: string;
    csrfToken: string;
    remainingRecoveryCodes: number;
  } {
    this.assertNotRateLimited(ipKey, atMs);
    if (!this.config.encryptedPendingSecret) {
      throw new Error(
        'TOTP_SETUP_NOT_STARTED: Inicie a configuração TOTP (/api/totp/setup) antes de confirmar.'
      );
    }
    const pendingSecret = this.decryptSecretAtRest(this.config.encryptedPendingSecret);
    if (!pendingSecret) {
      throw new Error('TOTP_SETUP_NOT_STARTED: Segredo pendente indisponível.');
    }

    const check = verifyTotpCodeWithReplayCheck(pendingSecret, totpCode, null, atMs);
    if (!check.valid || check.matchedStep === null) {
      this.recordFailedAttempt(ipKey, atMs);
      throw new Error('TOTP_CODE_INVALID: Código TOTP de 6 dígitos inválido. Verifique o relógio do autenticador.');
    }

    this.clearFailedAttempts(ipKey);
    this.config.enabled = true;
    this.config.encryptedSecret = this.config.encryptedPendingSecret;
    this.config.encryptedPendingSecret = null;
    this.config.recoveryCodeHashes = this.config.pendingRecoveryCodeHashes;
    this.config.pendingRecoveryCodeHashes = [];
    this.config.lastAcceptedStep = check.matchedStep;
    this.config.configuredAt = new Date(atMs).toISOString();
    this.saveConfig();

    // Rotate unlock sessions on enable
    this.unlockSessions.clear();
    const { unlockToken, csrfToken } = this.createUnlockSession(atMs);

    return {
      ok: true,
      enabled: true,
      unlocked: true,
      unlockToken,
      csrfToken,
      remainingRecoveryCodes: this.config.recoveryCodeHashes.length,
    };
  }

  private verifyActiveSecretOrRecoveryCode(params: {
    code?: string;
    totpCode?: string;
    recoveryCode?: string;
    ipKey?: string;
    atMs?: number;
  }): { usedRecoveryCode: boolean; remainingRecoveryCodes: number } {
    const ipKey = params.ipKey || 'local';
    const atMs = params.atMs ?? Date.now();
    this.assertNotRateLimited(ipKey, atMs);

    if (!this.isEnabled() || !this.config.encryptedSecret) {
      throw new Error('TOTP_NOT_ENABLED: A proteção TOTP 2FA não está ativa.');
    }

    const activeSecret = this.decryptSecretAtRest(this.config.encryptedSecret);
    if (!activeSecret) {
      throw new Error('TOTP_SECRET_UNAVAILABLE: Segredo TOTP indisponível.');
    }

    const rawCandidate = String(params.totpCode || params.code || '').trim();
    const rawRecovery = String(params.recoveryCode || params.code || '').trim();

    // 1. Try 6-digit RFC-6238 TOTP if candidate looks like 6 digits
    const digitsOnly = rawCandidate.replace(/[\s-]/g, '');
    if (/^\d{6}$/.test(digitsOnly)) {
      const check = verifyTotpCodeWithReplayCheck(
        activeSecret,
        digitsOnly,
        this.config.lastAcceptedStep,
        atMs
      );
      if (check.replayRejected) {
        this.recordFailedAttempt(ipKey, atMs);
        throw new Error(
          'TOTP_REPLAY_REJECTED: Este código TOTP já foi utilizado nesta janela de 30s. Aguarde o próximo código.'
        );
      }
      if (check.valid && check.matchedStep !== null) {
        this.clearFailedAttempts(ipKey);
        this.config.lastAcceptedStep = check.matchedStep;
        this.saveConfig();
        return {
          usedRecoveryCode: false,
          remainingRecoveryCodes: this.config.recoveryCodeHashes.length,
        };
      }
    }

    // 2. Try single-use recovery code (8 hex chars, optional hyphen XXXX-XXXX)
    const normalizedRecovery = rawRecovery.toUpperCase().replace(/[^A-F0-9]/g, '');
    if (/^[A-F0-9]{8}$/.test(normalizedRecovery)) {
      let matchedIndex = -1;
      for (let i = 0; i < this.config.recoveryCodeHashes.length; i++) {
        const entry = this.config.recoveryCodeHashes[i]!;
        const candidateHashHex = hashRecoveryCodeWithSalt(normalizedRecovery, entry.saltHex);
        const a = Buffer.from(candidateHashHex, 'hex');
        const b = Buffer.from(entry.hashHex, 'hex');
        if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
          matchedIndex = i;
        }
      }
      if (matchedIndex >= 0) {
        this.clearFailedAttempts(ipKey);
        this.config.recoveryCodeHashes.splice(matchedIndex, 1);
        this.saveConfig();
        return {
          usedRecoveryCode: true,
          remainingRecoveryCodes: this.config.recoveryCodeHashes.length,
        };
      }
    }

    this.recordFailedAttempt(ipKey, atMs);
    throw new Error('TOTP_CODE_INVALID: Código TOTP ou código de recuperação inválido.');
  }

  public verifyUnlock(params: {
    code?: string;
    totpCode?: string;
    recoveryCode?: string;
    ipKey?: string;
    atMs?: number;
  }): {
    ok: true;
    enabled: true;
    unlocked: true;
    usedRecoveryCode: boolean;
    remainingRecoveryCodes: number;
    unlockToken: string;
    csrfToken: string;
  } {
    const atMs = params.atMs ?? Date.now();
    const verified = this.verifyActiveSecretOrRecoveryCode({ ...params, atMs });
    const { unlockToken, csrfToken } = this.createUnlockSession(atMs);
    return {
      ok: true,
      enabled: true,
      unlocked: true,
      usedRecoveryCode: verified.usedRecoveryCode,
      remainingRecoveryCodes: verified.remainingRecoveryCodes,
      unlockToken,
      csrfToken,
    };
  }

  public disable(params: {
    code?: string;
    totpCode?: string;
    recoveryCode?: string;
    ipKey?: string;
    atMs?: number;
  }): { ok: true; enabled: false; unlocked: true } {
    if (!this.isEnabled()) {
      this.config.encryptedPendingSecret = null;
      this.config.pendingRecoveryCodeHashes = [];
      this.saveConfig();
      return { ok: true, enabled: false, unlocked: true };
    }
    this.verifyActiveSecretOrRecoveryCode(params);
    this.config = defaultPersistedConfig();
    this.unlockSessions.clear();
    this.saveConfig();
    return { ok: true, enabled: false, unlocked: true };
  }

  public lock(unlockToken?: string | null): { ok: true; enabled: boolean; unlocked: boolean } {
    if (!this.isEnabled()) {
      return { ok: true, enabled: false, unlocked: true };
    }
    if (unlockToken) {
      const found = this.findSession(unlockToken);
      if (found) {
        this.unlockSessions.delete(found.tokenHashHex);
      }
    }
    // Always revoke all local unlock sessions when user explicitly locks the workspace
    this.unlockSessions.clear();
    return { ok: true, enabled: true, unlocked: false };
  }
}
