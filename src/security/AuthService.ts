import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

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
  totpSecretBase32: string | null;
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
  const clean = (candidateCode || '').trim();
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
  private db: PersistedAuthDatabase;
  private ipRateLimits = new Map<string, { count: number; windowStartMs: number; blockedUntilMs: number }>();

  public static readonly SESSION_IDLE_MS = 30 * 60 * 1000;
  public static readonly SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
  public static readonly MAX_LOGIN_ATTEMPTS = 5;
  public static readonly LOCKOUT_DURATION_MS = 5 * 60 * 1000;

  constructor(dataDir?: string) {
    const base = dataDir || path.resolve(process.cwd(), '.winhood_data');
    this.authStorePath = path.join(base, 'security', 'auth_users.json');
    this.bootstrapTokenFilePath = path.join(base, 'bootstrap_admin_token.txt');
    this.recoveryDir = path.join(base, 'security');
    this.db = this.loadOrInit(base);
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
    totpSetup?: { secretBase32: string; otpauthUri: string };
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
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      throw new Error('E-mail inválido.');
    }
    if (cleanPassword.length < 10) {
      throw new Error('A senha deve possuir pelo menos 10 caracteres.');
    }

    const now = new Date().toISOString();
    const totpSecret = params.enableMfa ? base32Encode(crypto.randomBytes(20)) : null;

    const adminUser: UserAccountRecord = {
      id: `usr-${crypto.randomUUID().slice(0, 8)}`,
      name: cleanName,
      email: cleanEmail,
      role: 'ADMIN',
      passwordHash: hashPassword(cleanPassword),
      mfaEnabled: Boolean(params.enableMfa),
      totpSecretBase32: totpSecret,
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
              otpauthUri: `otpauth://totp/WinHood:${encodeURIComponent(cleanEmail)}?secret=${totpSecret}&issuer=WinHood`,
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
    ipAddress?: string;
    userAgent?: string;
  }): {
    user: PublicUserView;
    sessionId: string;
    csrfToken: string;
    mfaRequired: boolean;
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

    // Check TOTP if MFA enabled
    let mfaVerified = !user.mfaEnabled;
    if (user.mfaEnabled && user.totpSecretBase32 && params.totpCode) {
      if (!verifyTotpCode(user.totpSecretBase32, params.totpCode)) {
        user.failedLoginAttempts += 1;
        this.save();
        throw new Error('AUTH_INVALID_MFA: Código TOTP MFA inválido.');
      }
      mfaVerified = true;
    }

    user.failedLoginAttempts = 0;
    user.lockedUntil = null;
    user.updatedAt = new Date().toISOString();

    const { sessionId, session } = this.createSessionRecord(
      user,
      mfaVerified,
      ipAddress,
      params.userAgent || 'unknown'
    );
    this.save();

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
      mfaRequired: user.mfaEnabled && !mfaVerified,
    };
  }

  public verifySessionMfa(sessionId: string, totpCode: string): PublicUserView {
    const verified = this.validateSession(sessionId, { allowPendingMfa: true });
    if (!verified) {
      throw new Error('AUTH_SESSION_INVALID: Sessão inválida ou expirada.');
    }
    const user = this.db.users.find((u) => u.id === verified.user.id);
    if (!user || !user.mfaEnabled || !user.totpSecretBase32) {
      throw new Error('MFA não habilitado para este usuário.');
    }
    if (!verifyTotpCode(user.totpSecretBase32, totpCode)) {
      throw new Error('AUTH_INVALID_MFA: Código TOTP inválido.');
    }
    verified.session.mfaVerified = true;
    verified.session.lastActivityAt = new Date().toISOString();
    this.save();
    return {
      ...verified.user,
      mfaVerified: true,
    };
  }

  public setupMfaForUser(userId: string): { secretBase32: string; otpauthUri: string } {
    const user = this.db.users.find((u) => u.id === userId);
    if (!user) throw new Error('Usuário não encontrado.');
    const secretBase32 = base32Encode(crypto.randomBytes(20));
    user.totpSecretBase32 = secretBase32;
    user.mfaEnabled = true;
    user.updatedAt = new Date().toISOString();
    this.save();
    return {
      secretBase32,
      otpauthUri: `otpauth://totp/WinHood:${encodeURIComponent(user.email)}?secret=${secretBase32}&issuer=WinHood`,
    };
  }

  private createSessionRecord(
    user: UserAccountRecord,
    mfaVerified: boolean,
    ipAddress: string,
    userAgent: string
  ): { sessionId: string; session: AuthSessionRecord } {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const nowMs = Date.now();
    const session: AuthSessionRecord = {
      sessionIdHash: sha256(sessionId),
      userId: user.id,
      role: user.role,
      csrfToken: crypto.randomBytes(24).toString('hex'),
      mfaVerified,
      createdAt: new Date(nowMs).toISOString(),
      lastActivityAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + AuthService.SESSION_ABSOLUTE_MS).toISOString(),
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
    if (nowMs - Date.parse(session.lastActivityAt) > AuthService.SESSION_IDLE_MS) {
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
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      throw new Error('E-mail inválido.');
    }
    if ((params.password || '').length < 10) {
      throw new Error('A senha deve possuir pelo menos 10 caracteres.');
    }
    if (this.db.users.some((u) => u.email === cleanEmail)) {
      throw new Error('E-mail já cadastrado.');
    }
    const now = new Date().toISOString();
    const user: UserAccountRecord = {
      id: `usr-${crypto.randomUUID().slice(0, 8)}`,
      name: params.name.trim(),
      email: cleanEmail,
      role: params.role,
      passwordHash: hashPassword(params.password),
      mfaEnabled: Boolean(params.enableMfa),
      totpSecretBase32: params.enableMfa ? base32Encode(crypto.randomBytes(20)) : null,
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
