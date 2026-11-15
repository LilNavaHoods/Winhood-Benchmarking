import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { KeyManagementService, type VaultReencryptContext } from './KeyManagementService';

/**
 * Valida formato básico de e-mail em tempo linear O(n) sem backtracking super-linear (typescript:S8786).
 */
export function isValidEmailAddress(rawEmail: string): boolean {
  if (!rawEmail || rawEmail.length > 320 || /\s/.test(rawEmail)) {
    return false;
  }
  const atIndex = rawEmail.indexOf('@');
  if (atIndex <= 0 || atIndex !== rawEmail.lastIndexOf('@')) {
    return false;
  }
  const domain = rawEmail.slice(atIndex + 1);
  if (domain.startsWith('.') || domain.endsWith('.')) {
    return false;
  }
  const dotIndex = domain.indexOf('.');
  return dotIndex > 0 && dotIndex < domain.length - 1;
}

export type RbacRole = 'ADMIN' | 'SECURITY_LEAD' | 'QA_ENGINEER' | 'AUDITOR';

export type RbacPermission =
  | 'read:all'
  | 'audit:read'
  | 'reports:export'
  | 'projects:write'
  | 'runs:execute'
  | 'tests:run'
  | 'perf:run'
  | 'findings:triage'
  | 'security:ops'
  | 'sonar:config'
  | 'targets:manage'
  | 'keys:rotate'
  | 'users:manage'
  | 'auth:switch_role'
  | 'system:reset';

export const PERMISSIONS_MATRIX: Record<RbacRole, ReadonlySet<RbacPermission>> = {
  ADMIN: new Set<RbacPermission>([
    'read:all',
    'audit:read',
    'reports:export',
    'projects:write',
    'runs:execute',
    'tests:run',
    'perf:run',
    'findings:triage',
    'security:ops',
    'sonar:config',
    'targets:manage',
    'keys:rotate',
    'users:manage',
    'auth:switch_role',
    'system:reset',
  ]),
  SECURITY_LEAD: new Set<RbacPermission>([
    'read:all',
    'audit:read',
    'reports:export',
    'projects:write',
    'runs:execute',
    'tests:run',
    'perf:run',
    'findings:triage',
    'security:ops',
    'sonar:config',
    'targets:manage',
    'system:reset',
  ]),
  QA_ENGINEER: new Set<RbacPermission>([
    'read:all',
    'audit:read',
    'reports:export',
    'projects:write',
    'runs:execute',
    'tests:run',
    'perf:run',
    'findings:triage',
  ]),
  AUDITOR: new Set<RbacPermission>(['read:all', 'audit:read', 'reports:export']),
};

export interface UserAccountRecord {
  id: string;
  name: string;
  email: string;
  role: RbacRole;
  passwordHash: string; // scrypt:N=16384,r=8,p=1:<saltHex>:<hashHex>
  mfaEnabled: boolean;
  totpSecretBase32: string | null; // AES-256-GCM encrypted payload (whvault:v1:...) or legacy Base32
  pendingTotpSecretBase32?: string | null;
  lastAcceptedTotpStep?: number | null;
  recoveryCodeHashes?: string[];
  disabled: boolean;
  failedLoginAttempts: number;
  lockedUntil: string | null;
  recoveryTokenSha256: string | null;
  recoveryExpiresAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface PublicUserView {
  id: string;
  name: string;
  email: string;
  role: RbacRole;
  mfaEnabled: boolean;
  mfaVerified: boolean;
}

export interface AuthSessionRecord {
  sessionIdHash: string;
  userId: string;
  role: RbacRole;
  sessionRoleOverride?: RbacRole | null;
  csrfToken: string;
  mfaVerified: boolean;
  trustDevice?: boolean;
  idleTimeoutMs?: number;
  createdAt: string;
  lastActivityAt: string;
  expiresAt: string;
  revoked: boolean;
  ipAddress: string;
  userAgent: string;
}

interface PersistedAuthDatabase {
  schemaVersion: number;
  bootstrapTokenSha256: string | null;
  bootstrapTokenExpiresAt: string | null;
  bootstrapCompletedAt: string | null;
  users: UserAccountRecord[];
  sessions: AuthSessionRecord[];
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf: Buffer): string {
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

function base32Decode(str: string): Buffer {
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
  const step = Math.floor(atMs / 1000 / 30);
  return computeHotp(secretBase32, step);
}

export function verifyTotpCode(secretBase32: string, candidateCode: string, atMs = Date.now()): boolean {
  const clean = (candidateCode || '').replace(/[\s-]/g, '').trim();
  if (!/^\d{6}$/.test(clean)) return false;
  const step = Math.floor(atMs / 1000 / 30);
  for (const delta of [-1, 0, 1]) {
    const expected = computeHotp(secretBase32, step + delta);
    if (crypto.timingSafeEqual(Buffer.from(clean), Buffer.from(expected))) {
      return true;
    }
  }
  return false;
}

function verifyTotpCodeWithStep(
  secretBase32: string,
  candidateCode: string,
  lastAcceptedStep?: number | null,
  atMs = Date.now()
): { valid: boolean; matchedStep: number | null; replayRejected: boolean } {
  const clean = (candidateCode || '').replace(/[\s-]/g, '').trim();
  if (!/^\d{6}$/.test(clean)) {
    return { valid: false, matchedStep: null, replayRejected: false };
  }
  const currentStep = Math.floor(atMs / 1000 / 30);
  for (const delta of [-1, 0, 1]) {
    const candidateStep = currentStep + delta;
    const expected = computeHotp(secretBase32, candidateStep);
    if (crypto.timingSafeEqual(Buffer.from(clean), Buffer.from(expected))) {
      if (typeof lastAcceptedStep === 'number' && candidateStep <= lastAcceptedStep) {
        return { valid: false, matchedStep: candidateStep, replayRejected: true };
      }
      return { valid: true, matchedStep: candidateStep, replayRejected: false };
    }
  }
  return { valid: false, matchedStep: null, replayRejected: false };
}

function generateRecoveryCodesSet(count = 8): {
  plaintextCodes: string[];
  codeHashes: string[];
} {
  const plaintextCodes: string[] = [];
  const codeHashes: string[] = [];
  for (let i = 0; i < count; i++) {
    const rawHex = crypto.randomBytes(4).toString('hex').toUpperCase();
    const formatted = `${rawHex.slice(0, 4)}-${rawHex.slice(4, 8)}`;
    plaintextCodes.push(formatted);
    codeHashes.push(sha256(`winhood-rc:${rawHex}`));
  }
  return { plaintextCodes, codeHashes };
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
  return `scrypt:N=16384,r=8,p=1:${salt}:${derived}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 4 || parts[0] !== 'scrypt') return false;
  const salt = parts[2]!;
  const expectedHex = parts[3]!;
  const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(derived, expectedBuf);
}

function sha256(val: string): string {
  return crypto.createHash('sha256').update(val, 'utf8').digest('hex');
}

function atomicWriteSecretFile(filePath: string, content: string): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const tmpPath = `${filePath}.tmp.${crypto.randomBytes(4).toString('hex')}`;
  fs.writeFileSync(tmpPath, content, { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmpPath, filePath);
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    // Windows chmod is partial; ignore silently
  }
}

export class AuthService {
  private readonly authStorePath: string;
  private readonly bootstrapTokenFilePath: string;
  private readonly recoveryDir: string;
  private readonly keystorePath: string;
  private db: PersistedAuthDatabase;
  private ipRateLimits = new Map<string, { count: number; windowStartMs: number; blockedUntilMs: number }>();

  public static readonly SESSION_IDLE_MS = 30 * 60 * 1000;
  public static readonly SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
  public static readonly SESSION_TRUSTED_DEVICE_MS = 30 * 24 * 60 * 60 * 1000;
  public static readonly PREAUTH_TTL_MS = 5 * 60 * 1000;
  public static readonly MAX_LOGIN_ATTEMPTS = 5;
  public static readonly LOCKOUT_DURATION_MS = 5 * 60 * 1000;

  constructor(dataDir?: string) {
    const base = dataDir || path.resolve(process.cwd(), '.winhood_data');
    this.authStorePath = path.join(base, 'security', 'auth_users.json');
    this.bootstrapTokenFilePath = path.join(base, 'bootstrap_admin_token.txt');
    this.recoveryDir = path.join(base, 'security');
    this.keystorePath = path.join(base, 'keys', 'keystore.json');
    this.db = this.loadOrInit(base);
  }

  private encryptSecretAtRest(plainSecret: string): string {
    const { keyId, keyBuffer } = KeyManagementService.getActiveVaultAesKey(this.keystorePath);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
    const encrypted = Buffer.concat([cipher.update(plainSecret, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `whvault:v1:${keyId}:${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  private decryptSecretAtRest(stored: string | null | undefined): string | null {
    if (!stored) return null;
    if (!stored.startsWith('whvault:v1:')) {
      // Backward compatibility for pre-existing plaintext Base32 secrets
      return stored;
    }
    const parts = stored.split(':');
    if (parts.length !== 6) {
      throw new Error('TOTP_VAULT_CORRUPTED: Formato criptográfico do segredo TOTP inválido.');
    }
    const [, , keyId, ivHex, tagHex, cipherHex] = parts;
    const keyBuf =
      KeyManagementService.getVaultKeyBufferByKeyId(keyId!, this.keystorePath) ||
      KeyManagementService.getActiveVaultAesKey(this.keystorePath).keyBuffer;
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, Buffer.from(ivHex!, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex!, 'hex'));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(cipherHex!, 'hex')),
      decipher.final(),
    ]);
    return plain.toString('utf8');
  }

  public reencryptTotpSecrets(ctx: VaultReencryptContext): number {
    let updated = 0;
    const reencryptWithCtx = (stored: string | null | undefined): string | null | undefined => {
      if (!stored) return stored;
      let plain: string | null = null;
      if (stored.startsWith(`whvault:v1:${ctx.oldKeyId}:`)) {
        const parts = stored.split(':');
        if (parts.length === 6) {
          const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            ctx.oldKeyBuffer,
            Buffer.from(parts[3]!, 'hex')
          );
          decipher.setAuthTag(Buffer.from(parts[4]!, 'hex'));
          plain = Buffer.concat([
            decipher.update(Buffer.from(parts[5]!, 'hex')),
            decipher.final(),
          ]).toString('utf8');
        }
      } else if (!stored.startsWith('whvault:v1:')) {
        plain = stored;
      }
      if (!plain) return stored;
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', ctx.newKeyBuffer, iv);
      const encrypted = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();
      updated += 1;
      return `whvault:v1:${ctx.newKeyId}:${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
    };

    for (const user of this.db.users) {
      if (user.totpSecretBase32) {
        user.totpSecretBase32 = reencryptWithCtx(user.totpSecretBase32) || null;
      }
      if (user.pendingTotpSecretBase32) {
        user.pendingTotpSecretBase32 = reencryptWithCtx(user.pendingTotpSecretBase32) || null;
      }
    }
    if (updated > 0) {
      this.save();
    }
    return updated;
  }

  private createPreAuthToken(userId: string, email: string, trustDevice: boolean): string {
    const { keyId, secret } = KeyManagementService.getActiveEvidenceHmacKey(this.keystorePath);
    const payload = {
      keyId,
      uid: userId,
      email,
      scope: 'TOTP_CHALLENGE',
      trustDevice: Boolean(trustDevice),
      exp: Date.now() + AuthService.PREAUTH_TTL_MS,
      jti: crypto.randomBytes(8).toString('hex'),
    };
    const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const sig = crypto.createHmac('sha256', secret).update(encodedPayload, 'utf8').digest('base64url');
    return `whpa1.${encodedPayload}.${sig}`;
  }

  private verifyPreAuthToken(token: string): {
    uid: string;
    email: string;
    trustDevice: boolean;
  } {
    const parts = (token || '').trim().split('.');
    if (parts.length !== 3 || parts[0] !== 'whpa1') {
      throw new Error('AUTH_PREAUTH_INVALID: Token temporário de desafio MFA malformado.');
    }
    let decoded: {
      keyId?: string;
      uid?: string;
      email?: string;
      scope?: string;
      trustDevice?: boolean;
      exp?: number;
    };
    try {
      decoded = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
    } catch {
      throw new Error('AUTH_PREAUTH_INVALID: Payload do desafio MFA inválido.');
    }
    if (decoded.scope !== 'TOTP_CHALLENGE' || !decoded.uid || !decoded.keyId || !decoded.exp) {
      throw new Error('AUTH_PREAUTH_INVALID: Escopo do token de desafio MFA inválido.');
    }
    if (Date.now() > decoded.exp) {
      throw new Error('AUTH_PREAUTH_EXPIRED: Desafio TOTP expirado (5 minutos). Faça login novamente.');
    }
    const hmacSecret = KeyManagementService.getEvidenceSecretByKeyId(decoded.keyId, this.keystorePath);
    if (!hmacSecret) {
      throw new Error('AUTH_PREAUTH_INVALID: Chave de assinatura do desafio não reconhecida.');
    }
    const expectedSig = crypto
      .createHmac('sha256', hmacSecret)
      .update(parts[1]!, 'utf8')
      .digest('base64url');
    const a = Buffer.from(parts[2]!, 'utf8');
    const b = Buffer.from(expectedSig, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      throw new Error('AUTH_PREAUTH_INVALID: Assinatura HMAC do token de desafio MFA inválida.');
    }
    return {
      uid: decoded.uid,
      email: decoded.email || '',
      trustDevice: Boolean(decoded.trustDevice),
    };
  }

  private tryConsumeRecoveryCode(user: UserAccountRecord, rawCode: string): boolean {
    const clean = (rawCode || '').replace(/[\s-]/g, '').trim().toUpperCase();
    if (!/^[A-F0-9]{8}$/.test(clean) || !Array.isArray(user.recoveryCodeHashes) || user.recoveryCodeHashes.length === 0) {
      return false;
    }
    const candidateHashBuf = Buffer.from(sha256(`winhood-rc:${clean}`), 'hex');
    const matchIndex = user.recoveryCodeHashes.findIndex((storedHex) => {
      const storedBuf = Buffer.from(storedHex, 'hex');
      return (
        storedBuf.length === candidateHashBuf.length &&
        crypto.timingSafeEqual(storedBuf, candidateHashBuf)
      );
    });
    if (matchIndex === -1) return false;
    user.recoveryCodeHashes.splice(matchIndex, 1);
    return true;
  }

  private loadOrInit(baseDir: string): PersistedAuthDatabase {
    fs.mkdirSync(path.join(baseDir, 'security'), { recursive: true });
    if (fs.existsSync(this.authStorePath)) {
      try {
        const raw = fs.readFileSync(this.authStorePath, 'utf8');
        const parsed = JSON.parse(raw) as PersistedAuthDatabase;
        if (parsed && Array.isArray(parsed.users) && Array.isArray(parsed.sessions)) {
          if (parsed.users.length === 0 && !parsed.bootstrapTokenSha256) {
            return this.issueFreshBootstrapToken(parsed);
          }
          return parsed;
        }
      } catch {
        // Check backup
        const bak = `${this.authStorePath}.bak`;
        if (fs.existsSync(bak)) {
          const parsedBak = JSON.parse(fs.readFileSync(bak, 'utf8')) as PersistedAuthDatabase;
          return parsedBak;
        }
      }
    }

    const fresh: PersistedAuthDatabase = {
      schemaVersion: 1,
      bootstrapTokenSha256: null,
      bootstrapTokenExpiresAt: null,
      bootstrapCompletedAt: null,
      users: [],
      sessions: [],
    };
    return this.issueFreshBootstrapToken(fresh);
  }

  private issueFreshBootstrapToken(state: PersistedAuthDatabase): PersistedAuthDatabase {
    const envToken = process.env.WINHOOD_BOOTSTRAP_TOKEN?.trim();
    const rawToken =
      envToken && envToken.length >= 16
        ? envToken
        : `wh-boot-${crypto.randomBytes(24).toString('base64url')}`;
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    state.bootstrapTokenSha256 = sha256(rawToken);
    state.bootstrapTokenExpiresAt = expiresAt;
    this.save(state);

    atomicWriteSecretFile(
      this.bootstrapTokenFilePath,
      `# WinHood Initial Bootstrap Token (Single-Use — expira em ${expiresAt})\n${rawToken}\n`
    );

    if (process.env.NODE_ENV !== 'test') {
      console.log(
        `[WINHOOD AUTH] Primeira inicialização detectada: nenhum administrador cadastrado. Credencial temporária de bootstrap gravada em ${this.bootstrapTokenFilePath} (chmod 0600).`
      );
    }

    return state;
  }

  private save(state = this.db): void {
    if (fs.existsSync(this.authStorePath)) {
      try {
        fs.copyFileSync(this.authStorePath, `${this.authStorePath}.bak`);
      } catch {
        // Best-effort backup
      }
    }
    const serialized = JSON.stringify(state, null, 2);
    atomicWriteSecretFile(this.authStorePath, serialized);
    atomicWriteSecretFile(`${this.authStorePath}.sha256`, sha256(serialized));
  }

  public isBootstrapRequired(): boolean {
    return this.db.users.length === 0;
  }

  public getBootstrapMetadata(): {
    bootstrapRequired: boolean;
    bootstrapTokenFilePath: string;
    expiresAt: string | null;
  } {
    return {
      bootstrapRequired: this.isBootstrapRequired(),
      bootstrapTokenFilePath: this.bootstrapTokenFilePath,
      expiresAt: this.db.bootstrapTokenExpiresAt,
    };
  }

  public bootstrapInitialAdmin(params: {
    bootstrapToken: string;
    name: string;
    email: string;
    password: string;
    enableMfa?: boolean;
    ipAddress?: string;
    userAgent?: string;
  }): {
    user: PublicUserView;
    sessionId: string;
    csrfToken: string;
    totpSetup?: {
      secretBase32: string;
      secret?: string;
      otpauthUri: string;
      otpauthUrl?: string;
      recoveryCodes?: string[];
    };
  } {
    if (!this.isBootstrapRequired()) {
      throw new Error('BOOTSTRAP_ALREADY_COMPLETED: Administrador inicial já foi configurado.');
    }
    const provided = (params.bootstrapToken || '').trim();
    if (!provided || !this.db.bootstrapTokenSha256) {
      throw new Error('BOOTSTRAP_TOKEN_INVALID: Token de bootstrap obrigatório.');
    }
    if (
      this.db.bootstrapTokenExpiresAt &&
      Date.now() > Date.parse(this.db.bootstrapTokenExpiresAt)
    ) {
      this.issueFreshBootstrapToken(this.db);
      throw new Error('BOOTSTRAP_TOKEN_EXPIRED: Token expirado; novo token gerado no canal seguro.');
    }

    const providedSha = Buffer.from(sha256(provided), 'hex');
    const storedSha = Buffer.from(this.db.bootstrapTokenSha256, 'hex');
    if (providedSha.length !== storedSha.length || !crypto.timingSafeEqual(providedSha, storedSha)) {
      throw new Error('BOOTSTRAP_TOKEN_INVALID: Token de bootstrap incorreto.');
    }

    const cleanName = (params.name || '').trim();
    const cleanEmail = (params.email || '').trim().toLowerCase();
    const cleanPassword = params.password || '';
    if (cleanName.length < 2) {
      throw new Error('Nome do administrador deve possuir pelo menos 2 caracteres.');
    }
    if (!isValidEmailAddress(cleanEmail)) {
      throw new Error('E-mail inválido.');
    }
    if (cleanPassword.length < 10) {
      throw new Error('A senha deve possuir pelo menos 10 caracteres.');
    }

    const now = new Date().toISOString();
    const totpSecret = params.enableMfa ? base32Encode(crypto.randomBytes(20)) : null;
    const recoveryGen = totpSecret ? generateRecoveryCodesSet(8) : null;

    const adminUser: UserAccountRecord = {
      id: `usr-${crypto.randomUUID().slice(0, 8)}`,
      name: cleanName,
      email: cleanEmail,
      role: 'ADMIN',
      passwordHash: hashPassword(cleanPassword),
      mfaEnabled: Boolean(params.enableMfa),
      totpSecretBase32: totpSecret ? this.encryptSecretAtRest(totpSecret) : null,
      recoveryCodeHashes: recoveryGen ? recoveryGen.codeHashes : [],
      lastAcceptedTotpStep: null,
      disabled: false,
      failedLoginAttempts: 0,
      lockedUntil: null,
      recoveryTokenSha256: null,
      recoveryExpiresAt: null,
      createdAt: now,
      updatedAt: now,
    };

    this.db.users.push(adminUser);
    // Invalidate bootstrap token immediately
    this.db.bootstrapTokenSha256 = null;
    this.db.bootstrapTokenExpiresAt = null;
    this.db.bootstrapCompletedAt = now;
    try {
      if (fs.existsSync(this.bootstrapTokenFilePath)) {
        fs.unlinkSync(this.bootstrapTokenFilePath);
      }
    } catch {
      // Best-effort delete
    }

    const { sessionId, session } = this.createSessionRecord(
      adminUser,
      !adminUser.mfaEnabled,
      params.ipAddress || '127.0.0.1',
      params.userAgent || 'unknown'
    );
    this.save();

    return {
      user: {
        id: adminUser.id,
        name: adminUser.name,
        email: adminUser.email,
        role: adminUser.role,
        mfaEnabled: adminUser.mfaEnabled,
        mfaVerified: session.mfaVerified,
      },
      sessionId,
      csrfToken: session.csrfToken,
      ...(totpSecret
        ? {
            totpSetup: {
              secretBase32: totpSecret,
              secret: totpSecret,
              otpauthUri: `otpauth://totp/WinHood:${encodeURIComponent(cleanEmail)}?secret=${totpSecret}&issuer=WinHood`,
              otpauthUrl: `otpauth://totp/WinHood:${encodeURIComponent(cleanEmail)}?secret=${totpSecret}&issuer=WinHood`,
              recoveryCodes: recoveryGen?.plaintextCodes || [],
            },
          }
        : {}),
    };
  }

  private checkIpRateLimit(ipAddress: string): void {
    const entry = this.ipRateLimits.get(ipAddress);
    const now = Date.now();
    if (!entry) return;
    if (entry.blockedUntilMs > now) {
      throw new Error('AUTH_RATE_LIMITED: Muitas tentativas de autenticação. Aguarde antes de tentar novamente.');
    }
    if (now - entry.windowStartMs > 15 * 60 * 1000) {
      this.ipRateLimits.delete(ipAddress);
    }
  }

  private recordIpFailure(ipAddress: string): void {
    const now = Date.now();
    const entry = this.ipRateLimits.get(ipAddress);
    if (!entry || now - entry.windowStartMs > 15 * 60 * 1000) {
      this.ipRateLimits.set(ipAddress, { count: 1, windowStartMs: now, blockedUntilMs: 0 });
      return;
    }
    entry.count += 1;
    if (entry.count >= AuthService.MAX_LOGIN_ATTEMPTS * 2) {
      entry.blockedUntilMs = now + AuthService.LOCKOUT_DURATION_MS;
    }
  }

  public login(params: {
    email: string;
    password: string;
    totpCode?: string;
    trustDevice?: boolean;
    ipAddress?: string;
    userAgent?: string;
  }): {
    user: PublicUserView;
    sessionId: string;
    csrfToken: string;
    mfaRequired: boolean;
    requiresTotp: boolean;
    preAuthToken?: string;
    trustDevice: boolean;
    serverTimeIso: string;
    totpPeriodSeconds: number;
  } {
    const ipAddress = params.ipAddress || '127.0.0.1';
    this.checkIpRateLimit(ipAddress);

    const email = (params.email || '').trim().toLowerCase();
    const user = this.db.users.find((u) => u.email === email);
    if (!user || user.disabled) {
      this.recordIpFailure(ipAddress);
      throw new Error('AUTH_INVALID_CREDENTIALS: Credenciais inválidas.');
    }

    if (user.lockedUntil && Date.now() < Date.parse(user.lockedUntil)) {
      throw new Error('AUTH_ACCOUNT_LOCKED: Conta temporariamente bloqueada após tentativas excessivas.');
    }

    if (!verifyPassword(params.password || '', user.passwordHash)) {
      user.failedLoginAttempts += 1;
      if (user.failedLoginAttempts >= AuthService.MAX_LOGIN_ATTEMPTS) {
        user.lockedUntil = new Date(Date.now() + AuthService.LOCKOUT_DURATION_MS).toISOString();
      }
      this.recordIpFailure(ipAddress);
      this.save();
      throw new Error('AUTH_INVALID_CREDENTIALS: Credenciais inválidas.');
    }

    // Check TOTP if MFA enabled and inline code supplied
    const plainTotpSecret = this.decryptSecretAtRest(user.totpSecretBase32);
    let mfaVerified = !user.mfaEnabled;
    if (user.mfaEnabled && plainTotpSecret && params.totpCode) {
      const check = verifyTotpCodeWithStep(
        plainTotpSecret,
        params.totpCode,
        user.lastAcceptedTotpStep
      );
      if (check.replayRejected) {
        user.failedLoginAttempts += 1;
        this.save();
        throw new Error(
          'AUTH_TOTP_REPLAY: Código TOTP já utilizado nesta janela de 30s. Aguarde o próximo token.'
        );
      }
      if (!check.valid) {
        user.failedLoginAttempts += 1;
        this.save();
        throw new Error('AUTH_INVALID_MFA: Código TOTP MFA inválido.');
      }
      user.lastAcceptedTotpStep = check.matchedStep;
      mfaVerified = true;
    }

    user.failedLoginAttempts = 0;
    user.lockedUntil = null;
    user.updatedAt = new Date().toISOString();
    // Transparently upgrade legacy plaintext secret at rest
    if (user.totpSecretBase32 && !user.totpSecretBase32.startsWith('whvault:v1:')) {
      user.totpSecretBase32 = this.encryptSecretAtRest(user.totpSecretBase32);
    }

    const trustDevice = Boolean(params.trustDevice);
    const { sessionId, session } = this.createSessionRecord(
      user,
      mfaVerified,
      ipAddress,
      params.userAgent || 'unknown',
      { trustDevice }
    );
    this.save();

    const mfaRequired = user.mfaEnabled && !mfaVerified;
    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfaEnabled,
        mfaVerified: session.mfaVerified,
      },
      sessionId,
      csrfToken: session.csrfToken,
      mfaRequired,
      requiresTotp: mfaRequired,
      ...(mfaRequired
        ? { preAuthToken: this.createPreAuthToken(user.id, user.email, trustDevice) }
        : {}),
      trustDevice,
      serverTimeIso: new Date().toISOString(),
      totpPeriodSeconds: 30,
    };
  }

  public authenticateWithTotpPreAuth(params: {
    preAuthToken: string;
    totpCode?: string;
    recoveryCode?: string;
    trustDevice?: boolean;
    ipAddress?: string;
    userAgent?: string;
  }): {
    user: PublicUserView;
    sessionId: string;
    csrfToken: string;
    trustDevice: boolean;
    usedRecoveryCode: boolean;
    remainingRecoveryCodesCount: number;
  } {
    const ipAddress = params.ipAddress || '127.0.0.1';
    this.checkIpRateLimit(ipAddress);

    const verifiedChallenge = this.verifyPreAuthToken(params.preAuthToken);
    const user = this.db.users.find((u) => u.id === verifiedChallenge.uid);
    if (!user || user.disabled || !user.mfaEnabled) {
      throw new Error('AUTH_INVALID_MFA: Conta indisponível ou MFA não configurado.');
    }

    let usedRecoveryCode = false;
    const candidateRecovery = (params.recoveryCode || '').trim();
    const candidateTotp = (params.totpCode || '').trim();

    if (candidateRecovery) {
      if (!this.tryConsumeRecoveryCode(user, candidateRecovery)) {
        user.failedLoginAttempts += 1;
        this.recordIpFailure(ipAddress);
        this.save();
        throw new Error('AUTH_INVALID_RECOVERY_CODE: Código de recuperação inválido ou já utilizado.');
      }
      usedRecoveryCode = true;
    } else {
      const plainTotpSecret = this.decryptSecretAtRest(user.totpSecretBase32);
      if (!plainTotpSecret) {
        throw new Error('AUTH_INVALID_MFA: Segredo TOTP não localizado no cofre.');
      }
      const check = verifyTotpCodeWithStep(
        plainTotpSecret,
        candidateTotp,
        user.lastAcceptedTotpStep
      );
      if (check.replayRejected) {
        throw new Error(
          'AUTH_TOTP_REPLAY: Código TOTP já utilizado nesta janela de 30s. Aguarde o próximo token.'
        );
      }
      if (!check.valid) {
        user.failedLoginAttempts += 1;
        this.recordIpFailure(ipAddress);
        this.save();
        throw new Error('AUTH_INVALID_MFA: Código TOTP inválido.');
      }
      user.lastAcceptedTotpStep = check.matchedStep;
    }

    user.failedLoginAttempts = 0;
    user.lockedUntil = null;
    user.updatedAt = new Date().toISOString();

    const effectiveTrustDevice =
      typeof params.trustDevice === 'boolean' ? params.trustDevice : verifiedChallenge.trustDevice;
    const { sessionId, session } = this.createSessionRecord(
      user,
      true,
      ipAddress,
      params.userAgent || 'unknown',
      { trustDevice: effectiveTrustDevice }
    );
    this.save();

    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfaEnabled,
        mfaVerified: true,
      },
      sessionId,
      csrfToken: session.csrfToken,
      trustDevice: effectiveTrustDevice,
      usedRecoveryCode,
      remainingRecoveryCodesCount: user.recoveryCodeHashes?.length ?? 0,
    };
  }

  public verifySessionMfa(
    sessionId: string,
    totpCode: string,
    opts?: { recoveryCode?: string; trustDevice?: boolean }
  ): PublicUserView & { usedRecoveryCode?: boolean; remainingRecoveryCodesCount?: number } {
    const verified = this.validateSession(sessionId, { allowPendingMfa: true });
    if (!verified) {
      throw new Error('AUTH_SESSION_INVALID: Sessão inválida ou expirada.');
    }
    const user = this.db.users.find((u) => u.id === verified.user.id);
    const plainSecret = this.decryptSecretAtRest(user?.totpSecretBase32);
    if (!user || !user.mfaEnabled || !plainSecret) {
      throw new Error('MFA não habilitado para este usuário.');
    }

    let usedRecoveryCode = false;
    if (opts?.recoveryCode && opts.recoveryCode.trim().length > 0) {
      if (!this.tryConsumeRecoveryCode(user, opts.recoveryCode)) {
        throw new Error('AUTH_INVALID_RECOVERY_CODE: Código de recuperação inválido ou já utilizado.');
      }
      usedRecoveryCode = true;
    } else {
      const check = verifyTotpCodeWithStep(
        plainSecret,
        totpCode,
        user.lastAcceptedTotpStep
      );
      if (check.replayRejected) {
        throw new Error(
          'AUTH_TOTP_REPLAY: Código TOTP já utilizado nesta janela de 30s. Aguarde o próximo token.'
        );
      }
      if (!check.valid) {
        throw new Error('AUTH_INVALID_MFA: Código TOTP inválido.');
      }
      user.lastAcceptedTotpStep = check.matchedStep;
    }

    if (user.totpSecretBase32 && !user.totpSecretBase32.startsWith('whvault:v1:')) {
      user.totpSecretBase32 = this.encryptSecretAtRest(user.totpSecretBase32);
    }

    if (opts?.trustDevice) {
      const nowMs = Date.now();
      verified.session.trustDevice = true;
      verified.session.idleTimeoutMs = AuthService.SESSION_TRUSTED_DEVICE_MS;
      verified.session.expiresAt = new Date(nowMs + AuthService.SESSION_TRUSTED_DEVICE_MS).toISOString();
    }

    verified.session.mfaVerified = true;
    verified.session.lastActivityAt = new Date().toISOString();
    this.save();
    return {
      ...verified.user,
      mfaVerified: true,
      usedRecoveryCode,
      remainingRecoveryCodesCount: user.recoveryCodeHashes?.length ?? 0,
    };
  }

  public setupMfaForUser(userId: string): {
    secretBase32: string;
    secret: string;
    otpauthUri: string;
    otpauthUrl: string;
  } {
    const user = this.db.users.find((u) => u.id === userId);
    if (!user) throw new Error('Usuário não encontrado.');
    const secretBase32 = base32Encode(crypto.randomBytes(20));
    user.pendingTotpSecretBase32 = this.encryptSecretAtRest(secretBase32);
    user.updatedAt = new Date().toISOString();
    this.save();
    const otpauthUri = `otpauth://totp/WinHood:${encodeURIComponent(user.email)}?secret=${secretBase32}&issuer=WinHood&algorithm=SHA1&digits=6&period=30`;
    return {
      secretBase32,
      secret: secretBase32,
      otpauthUri,
      otpauthUrl: otpauthUri,
    };
  }

  public confirmMfaEnrollment(
    userId: string,
    totpCode: string
  ): PublicUserView & { recoveryCodes: string[] } {
    const user = this.db.users.find((u) => u.id === userId);
    if (!user) throw new Error('Usuário não encontrado.');
    const pendingPlain = this.decryptSecretAtRest(user.pendingTotpSecretBase32);
    if (!pendingPlain) {
      throw new Error('Nenhum setup de MFA pendente encontrado. Solicite a configuração primeiro.');
    }
    const check = verifyTotpCodeWithStep(pendingPlain, totpCode, null);
    if (!check.valid) {
      throw new Error('AUTH_INVALID_MFA: Código TOTP inválido. O MFA não foi ativado.');
    }
    const { plaintextCodes, codeHashes } = generateRecoveryCodesSet(8);
    user.totpSecretBase32 = this.encryptSecretAtRest(pendingPlain);
    user.mfaEnabled = true;
    user.pendingTotpSecretBase32 = null;
    user.lastAcceptedTotpStep = check.matchedStep;
    user.recoveryCodeHashes = codeHashes;
    user.updatedAt = new Date().toISOString();
    this.save();
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      mfaEnabled: true,
      mfaVerified: true,
      recoveryCodes: plaintextCodes,
    };
  }

  private createSessionRecord(
    user: UserAccountRecord,
    mfaVerified: boolean,
    ipAddress: string,
    userAgent: string,
    opts?: { trustDevice?: boolean }
  ): { sessionId: string; session: AuthSessionRecord } {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const nowMs = Date.now();
    const trustDevice = Boolean(opts?.trustDevice);
    const absoluteMs = trustDevice
      ? AuthService.SESSION_TRUSTED_DEVICE_MS
      : AuthService.SESSION_ABSOLUTE_MS;
    const idleTimeoutMs = trustDevice
      ? AuthService.SESSION_TRUSTED_DEVICE_MS
      : AuthService.SESSION_IDLE_MS;

    const session: AuthSessionRecord = {
      sessionIdHash: sha256(sessionId),
      userId: user.id,
      role: user.role,
      csrfToken: crypto.randomBytes(24).toString('hex'),
      mfaVerified,
      trustDevice,
      idleTimeoutMs,
      createdAt: new Date(nowMs).toISOString(),
      lastActivityAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + absoluteMs).toISOString(),
      revoked: false,
      ipAddress,
      userAgent,
    };
    // Keep up to 100 active sessions
    this.db.sessions = this.db.sessions
      .filter((s) => !s.revoked && Date.parse(s.expiresAt) > nowMs)
      .slice(-99);
    this.db.sessions.push(session);
    return { sessionId, session };
  }

  public validateSession(
    sessionId: string | undefined,
    opts?: { allowPendingMfa?: boolean }
  ): { user: PublicUserView; session: AuthSessionRecord } | null {
    if (!sessionId || sessionId.length < 32) return null;
    const targetHash = sha256(sessionId);
    const session = this.db.sessions.find((s) => s.sessionIdHash === targetHash);
    if (!session || session.revoked) return null;

    const nowMs = Date.now();
    if (nowMs > Date.parse(session.expiresAt)) {
      session.revoked = true;
      this.save();
      return null;
    }
    const effectiveIdleMs =
      session.idleTimeoutMs ||
      (session.trustDevice ? AuthService.SESSION_TRUSTED_DEVICE_MS : AuthService.SESSION_IDLE_MS);
    if (nowMs - Date.parse(session.lastActivityAt) > effectiveIdleMs) {
      session.revoked = true;
      this.save();
      return null;
    }

    const user = this.db.users.find((u) => u.id === session.userId);
    if (!user || user.disabled) return null;

    if (user.mfaEnabled && !session.mfaVerified && !opts?.allowPendingMfa) {
      return null;
    }

    const effectiveRole = session.sessionRoleOverride || user.role;
    session.lastActivityAt = new Date(nowMs).toISOString();
    session.role = effectiveRole;
    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: effectiveRole,
        mfaEnabled: user.mfaEnabled,
        mfaVerified: session.mfaVerified,
      },
      session,
    };
  }

  public switchSessionPreviewRole(sessionId: string, newRole: RbacRole): PublicUserView {
    const existing = this.validateSession(sessionId);
    if (!existing) {
      throw new Error('AUTH_SESSION_INVALID: Sessão inválida ou expirada.');
    }
    const dbUser = this.db.users.find((u) => u.id === existing.user.id);
    if (!dbUser || dbUser.role !== 'ADMIN') {
      throw new Error('ROLE_ELEVATION_BLOCKED: Apenas usuários com conta ADMIN podem alternar o perfil de sessão.');
    }
    existing.session.sessionRoleOverride = newRole === 'ADMIN' ? null : newRole;
    existing.session.role = newRole;
    this.save();
    return {
      id: dbUser.id,
      name: dbUser.name,
      email: dbUser.email,
      role: newRole,
      mfaEnabled: dbUser.mfaEnabled,
      mfaVerified: existing.session.mfaVerified,
    };
  }

  public renewSession(oldSessionId: string): { sessionId: string; csrfToken: string } | null {
    const existing = this.validateSession(oldSessionId);
    if (!existing) return null;
    const user = this.db.users.find((u) => u.id === existing.user.id);
    if (!user) return null;
    existing.session.revoked = true;
    const fresh = this.createSessionRecord(
      user,
      existing.session.mfaVerified,
      existing.session.ipAddress,
      existing.session.userAgent
    );
    this.save();
    return { sessionId: fresh.sessionId, csrfToken: fresh.session.csrfToken };
  }

  public revokeSession(sessionId: string | undefined): boolean {
    if (!sessionId) return false;
    const targetHash = sha256(sessionId);
    const session = this.db.sessions.find((s) => s.sessionIdHash === targetHash);
    if (!session) return false;
    session.revoked = true;
    this.save();
    return true;
  }

  public createUser(params: {
    name: string;
    email: string;
    password: string;
    role: RbacRole;
    enableMfa?: boolean;
  }): PublicUserView {
    const cleanEmail = (params.email || '').trim().toLowerCase();
    if (!isValidEmailAddress(cleanEmail)) {
      throw new Error('E-mail inválido.');
    }
    if ((params.password || '').length < 10) {
      throw new Error('A senha deve possuir pelo menos 10 caracteres.');
    }
    if (this.db.users.some((u) => u.email === cleanEmail)) {
      throw new Error('E-mail já cadastrado.');
    }
    const now = new Date().toISOString();
    const rawAdminCreatedTotp = params.enableMfa ? base32Encode(crypto.randomBytes(20)) : null;
    const user: UserAccountRecord = {
      id: `usr-${crypto.randomUUID().slice(0, 8)}`,
      name: params.name.trim(),
      email: cleanEmail,
      role: params.role,
      passwordHash: hashPassword(params.password),
      mfaEnabled: Boolean(params.enableMfa),
      totpSecretBase32: rawAdminCreatedTotp ? this.encryptSecretAtRest(rawAdminCreatedTotp) : null,
      recoveryCodeHashes: [],
      lastAcceptedTotpStep: null,
      disabled: false,
      failedLoginAttempts: 0,
      lockedUntil: null,
      recoveryTokenSha256: null,
      recoveryExpiresAt: null,
      createdAt: now,
      updatedAt: now,
    };
    this.db.users.push(user);
    this.save();
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      mfaEnabled: user.mfaEnabled,
      mfaVerified: false,
    };
  }

  public registerAccount(params: {
    name: string;
    email: string;
    password: string;
    role?: RbacRole;
    enableMfa?: boolean;
    ipAddress?: string;
    userAgent?: string;
  }): {
    user: PublicUserView;
    sessionId: string;
    csrfToken: string;
    totpSetup?: {
      secretBase32: string;
      secret: string;
      otpauthUri: string;
      otpauthUrl: string;
      recoveryCodes: string[];
    };
  } {
    const ipAddress = params.ipAddress || '127.0.0.1';
    this.checkIpRateLimit(ipAddress);

    const cleanName = (params.name || '').trim();
    const cleanEmail = (params.email || '').trim().toLowerCase();
    const cleanPassword = params.password || '';

    if (cleanName.length < 2) {
      throw new Error('INVALID_NAME: O nome completo deve possuir pelo menos 2 caracteres.');
    }
    if (!isValidEmailAddress(cleanEmail)) {
      throw new Error('INVALID_EMAIL: Informe um endereço de e-mail válido.');
    }
    if (cleanPassword.length < 10) {
      throw new Error('WEAK_PASSWORD: A senha deve possuir pelo menos 10 caracteres.');
    }
    if (this.db.users.some((u) => u.email === cleanEmail)) {
      this.recordIpFailure(ipAddress);
      throw new Error('EMAIL_ALREADY_EXISTS: Este e-mail já está cadastrado na plataforma.');
    }

    const isFirstUser = this.db.users.length === 0;
    const requestedRole: RbacRole = params.role || 'SECURITY_LEAD';
    if (!isFirstUser && requestedRole === 'ADMIN') {
      throw new Error(
        'ROLE_ELEVATION_BLOCKED: O perfil ADMIN exige provisionamento via Bootstrap ou atribuição por um Administrador existente.'
      );
    }
    const allowedSelfRoles: ReadonlyArray<RbacRole> = isFirstUser
      ? ['ADMIN', 'SECURITY_LEAD', 'QA_ENGINEER', 'AUDITOR']
      : ['SECURITY_LEAD', 'QA_ENGINEER', 'AUDITOR'];
    if (!allowedSelfRoles.includes(requestedRole)) {
      throw new Error('INVALID_ROLE: Perfil de acesso selecionado é inválido.');
    }
    const assignedRole: RbacRole = isFirstUser ? 'ADMIN' : requestedRole;

    const now = new Date().toISOString();
    const totpSecret = params.enableMfa ? base32Encode(crypto.randomBytes(20)) : null;
    const recoveryGen = totpSecret ? generateRecoveryCodesSet(8) : null;

    const newUser: UserAccountRecord = {
      id: `usr-${crypto.randomUUID().slice(0, 8)}`,
      name: cleanName,
      email: cleanEmail,
      role: assignedRole,
      passwordHash: hashPassword(cleanPassword),
      mfaEnabled: Boolean(params.enableMfa),
      totpSecretBase32: totpSecret ? this.encryptSecretAtRest(totpSecret) : null,
      recoveryCodeHashes: recoveryGen ? recoveryGen.codeHashes : [],
      lastAcceptedTotpStep: null,
      disabled: false,
      failedLoginAttempts: 0,
      lockedUntil: null,
      recoveryTokenSha256: null,
      recoveryExpiresAt: null,
      createdAt: now,
      updatedAt: now,
    };

    this.db.users.push(newUser);
    if (isFirstUser) {
      this.db.bootstrapTokenSha256 = null;
      this.db.bootstrapTokenExpiresAt = null;
      this.db.bootstrapCompletedAt = now;
      try {
        if (fs.existsSync(this.bootstrapTokenFilePath)) {
          fs.unlinkSync(this.bootstrapTokenFilePath);
        }
      } catch {
        // Ignore cleanup errors for ephemeral bootstrap file
      }
    }

    const { sessionId, session } = this.createSessionRecord(
      newUser,
      !newUser.mfaEnabled,
      ipAddress,
      params.userAgent || 'unknown'
    );
    this.save();

    return {
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        mfaEnabled: newUser.mfaEnabled,
        mfaVerified: session.mfaVerified,
      },
      sessionId,
      csrfToken: session.csrfToken,
      ...(totpSecret
        ? {
            totpSetup: {
              secretBase32: totpSecret,
              secret: totpSecret,
              otpauthUri: `otpauth://totp/WinHood:${encodeURIComponent(cleanEmail)}?secret=${totpSecret}&issuer=WinHood`,
              otpauthUrl: `otpauth://totp/WinHood:${encodeURIComponent(cleanEmail)}?secret=${totpSecret}&issuer=WinHood`,
              recoveryCodes: recoveryGen?.plaintextCodes || [],
            },
          }
        : {}),
    };
  }

  public listUsers(): Array<Omit<PublicUserView, 'mfaVerified'> & { createdAt: string; disabled: boolean }> {
    return this.db.users.map((u) => ({
      id: u.id,
      name: u.name,
      email: u.email,
      role: u.role,
      mfaEnabled: u.mfaEnabled,
      createdAt: u.createdAt,
      disabled: u.disabled,
    }));
  }

  public updateUserRole(userId: string, role: RbacRole): PublicUserView {
    const user = this.db.users.find((u) => u.id === userId);
    if (!user) throw new Error('Usuário não encontrado.');
    user.role = role;
    user.updatedAt = new Date().toISOString();
    for (const s of this.db.sessions) {
      if (s.userId === userId) s.role = role;
    }
    this.save();
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      mfaEnabled: user.mfaEnabled,
      mfaVerified: false,
    };
  }

  public requestPasswordRecovery(email: string): { recoveryFilePath: string | null } {
    const user = this.db.users.find((u) => u.email === email.trim().toLowerCase());
    if (!user) {
      return { recoveryFilePath: null };
    }
    const token = `wh-rec-${crypto.randomBytes(20).toString('base64url')}`;
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    user.recoveryTokenSha256 = sha256(token);
    user.recoveryExpiresAt = expiresAt;
    user.updatedAt = new Date().toISOString();
    this.save();
    const recPath = path.join(this.recoveryDir, `recovery_${user.id}.txt`);
    atomicWriteSecretFile(recPath, `# Recovery Token (expira em ${expiresAt})\n${token}\n`);
    return { recoveryFilePath: recPath };
  }

  public confirmPasswordRecovery(params: {
    email: string;
    recoveryToken: string;
    newPassword: string;
  }): void {
    const user = this.db.users.find((u) => u.email === params.email.trim().toLowerCase());
    if (!user || !user.recoveryTokenSha256 || !user.recoveryExpiresAt) {
      throw new Error('Token de recuperação inválido ou inexistente.');
    }
    if (Date.now() > Date.parse(user.recoveryExpiresAt)) {
      throw new Error('Token de recuperação expirado.');
    }
    const provided = Buffer.from(sha256((params.recoveryToken || '').trim()), 'hex');
    const stored = Buffer.from(user.recoveryTokenSha256, 'hex');
    if (provided.length !== stored.length || !crypto.timingSafeEqual(provided, stored)) {
      throw new Error('Token de recuperação inválido.');
    }
    if ((params.newPassword || '').length < 10) {
      throw new Error('Nova senha deve possuir pelo menos 10 caracteres.');
    }
    user.passwordHash = hashPassword(params.newPassword);
    user.recoveryTokenSha256 = null;
    user.recoveryExpiresAt = null;
    user.failedLoginAttempts = 0;
    user.lockedUntil = null;
    user.updatedAt = new Date().toISOString();
    // Revoke all existing sessions on password recovery
    for (const s of this.db.sessions) {
      if (s.userId === user.id) s.revoked = true;
    }
    this.save();
  }

  public static hasPermission(role: RbacRole, permission: RbacPermission): boolean {
    return PERMISSIONS_MATRIX[role]?.has(permission) ?? false;
  }
}
