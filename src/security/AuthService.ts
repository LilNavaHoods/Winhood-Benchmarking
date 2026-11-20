import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { KeyManagementService, type VaultReencryptContext } from './KeyManagementService';

const execFileAsync = promisify(execFile);

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

export type AuthProviderKind = 'password' | 'pin' | 'github' | 'webauthn' | 'windows-hello-native';

export interface WebAuthnCredentialRecord {
  credentialId: string; // base64url
  publicKeySpkiBase64: string; // DER SubjectPublicKeyInfo in base64
  coseAlgorithm: -7 | -257; // -7 (ES256) or -257 (RS256)
  signCount: number;
  transports?: string[];
  label?: string;
  nativePrivateKeySealed?: string | null;
  createdAt: string;
  lastUsedAt?: string | null;
}

export interface UserAccountRecord {
  id: string;
  name: string;
  email: string;
  role: RbacRole;
  passwordHash: string; // scrypt:N=32768,r=8,p=1:<saltHex>:<hashHex> (legado N=16384 migrado transparentemente)
  pinHash?: string | null; // scrypt:N=32768,r=8,p=1:<saltHex>:<hashHex>
  pinEnabled?: boolean;
  webauthnCredentials?: WebAuthnCredentialRecord[];
  githubId?: number | null;
  githubLogin?: string | null;
  githubAvatarUrl?: string | null;
  authProviders?: AuthProviderKind[];
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
  pinEnabled?: boolean;
  webauthnEnabled?: boolean;
  githubLinked?: boolean;
  githubLogin?: string | null;
  githubAvatarUrl?: string | null;
  authProviders?: AuthProviderKind[];
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

export interface WebAuthnChallengeRecord {
  challengeId: string;
  challengeBase64Url: string;
  purpose: 'REGISTER_ACCOUNT' | 'LOGIN' | 'LINK_CREDENTIAL';
  rpId: string;
  expiresAtMs: number;
  userId?: string;
  registrationMeta?: {
    name: string;
    email: string;
    role?: RbacRole;
    userHandle: string;
  };
  email?: string;
}

/**
 * Valida PIN numérico rápido (6 a 8 dígitos), rejeitando repetições ('111111', '000000')
 * e sequências simples ascendentes ou descendentes ('123456', '654321').
 */
export function validateQuickPin(rawPin: string): string {
  const clean = (rawPin || '').trim();
  if (!/^\d{6,8}$/.test(clean)) {
    throw new Error('INVALID_PIN: O PIN rápido deve conter entre 6 e 8 dígitos numéricos.');
  }
  if (/^(\d)\1+$/.test(clean)) {
    throw new Error('WEAK_PIN: PIN com dígitos repetidos (ex.: 111111, 000000) não é permitido.');
  }
  let isAscending = true;
  let isDescending = true;
  for (let i = 1; i < clean.length; i++) {
    const prev = clean.charCodeAt(i - 1) - 48;
    const curr = clean.charCodeAt(i) - 48;
    if (curr - prev !== 1) isAscending = false;
    if (prev - curr !== 1) isDescending = false;
  }
  if (isAscending || isDescending) {
    throw new Error('WEAK_PIN: PIN em sequência simples (ex.: 123456, 654321) não é permitido.');
  }
  return clean;
}

function decodeBase64OrBase64Url(input: string): Buffer {
  const clean = (input || '').trim();
  if (!clean) return Buffer.alloc(0);
  const normalized = clean.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (normalized.length % 4)) % 4;
  return Buffer.from(normalized + '='.repeat(padLen), 'base64');
}

function decodeCborItem(buf: Buffer, offset = 0): { value: any; nextOffset: number } {
  if (offset >= buf.length) {
    throw new Error('WEBAUTHN_CBOR_INVALID: Fim inesperado do buffer CBOR.');
  }
  const initialByte = buf[offset]!;
  const majorType = initialByte >> 5;
  const additionalInfo = initialByte & 0x1f;
  let ptr = offset + 1;
  let lengthVal = 0;

  if (additionalInfo < 24) {
    lengthVal = additionalInfo;
  } else if (additionalInfo === 24) {
    if (ptr + 1 > buf.length) throw new Error('WEBAUTHN_CBOR_INVALID: Uint8 truncado.');
    lengthVal = buf.readUInt8(ptr);
    ptr += 1;
  } else if (additionalInfo === 25) {
    if (ptr + 2 > buf.length) throw new Error('WEBAUTHN_CBOR_INVALID: Uint16 truncado.');
    lengthVal = buf.readUInt16BE(ptr);
    ptr += 2;
  } else if (additionalInfo === 26) {
    if (ptr + 4 > buf.length) throw new Error('WEBAUTHN_CBOR_INVALID: Uint32 truncado.');
    lengthVal = buf.readUInt32BE(ptr);
    ptr += 4;
  } else if (additionalInfo === 27) {
    if (ptr + 8 > buf.length) throw new Error('WEBAUTHN_CBOR_INVALID: Uint64 truncado.');
    lengthVal = Number(buf.readBigUInt64BE(ptr));
    ptr += 8;
  } else {
    throw new Error('WEBAUTHN_CBOR_INVALID: Informação adicional CBOR não suportada.');
  }

  switch (majorType) {
    case 0:
      return { value: lengthVal, nextOffset: ptr };
    case 1:
      return { value: -1 - lengthVal, nextOffset: ptr };
    case 2: {
      if (ptr + lengthVal > buf.length) throw new Error('WEBAUTHN_CBOR_INVALID: ByteString truncada.');
      return { value: buf.subarray(ptr, ptr + lengthVal), nextOffset: ptr + lengthVal };
    }
    case 3: {
      if (ptr + lengthVal > buf.length) throw new Error('WEBAUTHN_CBOR_INVALID: TextString truncada.');
      return {
        value: buf.subarray(ptr, ptr + lengthVal).toString('utf8'),
        nextOffset: ptr + lengthVal,
      };
    }
    case 4: {
      const arr: any[] = [];
      let cur = ptr;
      for (let i = 0; i < lengthVal; i++) {
        const decoded = decodeCborItem(buf, cur);
        arr.push(decoded.value);
        cur = decoded.nextOffset;
      }
      return { value: arr, nextOffset: cur };
    }
    case 5: {
      const map = new Map<any, any>();
      let cur = ptr;
      for (let i = 0; i < lengthVal; i++) {
        const k = decodeCborItem(buf, cur);
        const v = decodeCborItem(buf, k.nextOffset);
        map.set(k.value, v.value);
        cur = v.nextOffset;
      }
      return { value: map, nextOffset: cur };
    }
    case 7: {
      if (additionalInfo === 20) return { value: false, nextOffset: ptr };
      if (additionalInfo === 21) return { value: true, nextOffset: ptr };
      if (additionalInfo === 22) return { value: null, nextOffset: ptr };
      return { value: lengthVal, nextOffset: ptr };
    }
    default:
      throw new Error(`WEBAUTHN_CBOR_INVALID: Major type ${majorType} não suportado.`);
  }
}

function cosePublicKeyToSpkiBase64(coseBytes: Buffer): {
  publicKeySpkiBase64: string;
  coseAlgorithm: -7 | -257;
} {
  const decoded = decodeCborItem(coseBytes, 0).value;
  if (!(decoded instanceof Map)) {
    throw new Error('WEBAUTHN_COSE_INVALID: Chave pública COSE não é um mapa CBOR válido.');
  }
  const kty = decoded.get(1);
  const alg = decoded.get(3);
  if (alg === -7 && kty === 2) {
    const crv = decoded.get(-1);
    const xBuf = decoded.get(-2);
    const yBuf = decoded.get(-3);
    if (crv !== 1 || !Buffer.isBuffer(xBuf) || !Buffer.isBuffer(yBuf)) {
      throw new Error('WEBAUTHN_COSE_INVALID: Coordenadas EC2 P-256 inválidas na chave COSE.');
    }
    const keyObj = crypto.createPublicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: xBuf.toString('base64url'),
        y: yBuf.toString('base64url'),
      },
      format: 'jwk',
    });
    const spkiDer = keyObj.export({ type: 'spki', format: 'der' }) as Buffer;
    return { publicKeySpkiBase64: spkiDer.toString('base64'), coseAlgorithm: -7 };
  }
  if (alg === -257 && kty === 3) {
    const nBuf = decoded.get(-1);
    const eBuf = decoded.get(-2);
    if (!Buffer.isBuffer(nBuf) || !Buffer.isBuffer(eBuf)) {
      throw new Error('WEBAUTHN_COSE_INVALID: Parâmetros RSA (n, e) inválidos na chave COSE.');
    }
    const keyObj = crypto.createPublicKey({
      key: {
        kty: 'RSA',
        n: nBuf.toString('base64url'),
        e: eBuf.toString('base64url'),
      },
      format: 'jwk',
    });
    const spkiDer = keyObj.export({ type: 'spki', format: 'der' }) as Buffer;
    return { publicKeySpkiBase64: spkiDer.toString('base64'), coseAlgorithm: -257 };
  }
  throw new Error(
    `WEBAUTHN_ALG_UNSUPPORTED: Algoritmo COSE ${String(alg)} não suportado (use ES256 -7 ou RS256 -257).`
  );
}

function normalizeWebAuthnRpId(rawRpId?: string): string {
  const clean = (rawRpId || '').trim().toLowerCase();
  if (!clean) return 'localhost';
  const withoutPort = clean.split(':')[0]!.trim();
  if (!withoutPort || withoutPort === '127.0.0.1' || withoutPort === '[::1]') {
    return 'localhost';
  }
  return withoutPort;
}

function validateWebAuthnOrigin(originStr: string, expectedRpId: string): { hostname: string } {
  let parsed: URL;
  try {
    parsed = new URL(originStr);
  } catch {
    throw new Error('WEBAUTHN_ORIGIN_INVALID: Origin malformado no clientDataJSON.');
  }
  const hostname = parsed.hostname.toLowerCase();
  const isLoopback = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
  if (isLoopback) {
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('WEBAUTHN_ORIGIN_INVALID: Protocolo de loopback inválido.');
    }
    return { hostname };
  }
  if (parsed.protocol !== 'https:') {
    throw new Error('WEBAUTHN_ORIGIN_INVALID: WebAuthn fora de loopback exige HTTPS.');
  }
  const rpClean = expectedRpId.toLowerCase();
  if (hostname !== rpClean && !hostname.endsWith(`.${rpClean}`)) {
    throw new Error(
      `WEBAUTHN_ORIGIN_MISMATCH: Origin "${hostname}" não corresponde ao rpId "${rpClean}".`
    );
  }
  return { hostname };
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

export interface ScryptCostParams {
  N: number;
  r: number;
  p: number;
  maxmem: number;
}

/**
 * Avaliação arquitetural Scrypt vs Argon2id (Fase 10):
 * - Node.js 22 (`node:crypto`) oferece `crypto.scryptSync` nativo (OpenSSL C) sem módulos nativos
 *   externos ou bindings WASM, preservando portabilidade e empacotamento determinístico Electron (Win/Linux).
 * - Parâmetros vigentes: N=32768, r=8, p=1 (~32 MiB memory-hard por derivação).
 * - O formato versionado `scrypt:N=...,r=...,p=...` garante agilidade criptográfica para futura adoção
 *   de `argon2id` quando suportado nativamente pelo runtime Node.js sem quebrar hashes legados.
 */
export const CURRENT_SCRYPT_PARAMS: ScryptCostParams = {
  N: 32768,
  r: 8,
  p: 1,
  maxmem: 64 * 1024 * 1024,
};

function parseScryptParamsSpec(spec: string): ScryptCostParams {
  const parsed: ScryptCostParams = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
  for (const token of (spec || '').split(',')) {
    const [k, v] = token.split('=');
    const num = Number.parseInt(v || '', 10);
    if (!Number.isFinite(num) || num <= 0) continue;
    if (k === 'N') parsed.N = num;
    if (k === 'r') parsed.r = num;
    if (k === 'p') parsed.p = num;
  }
  parsed.maxmem = Math.max(64 * 1024 * 1024, 256 * parsed.N * parsed.r);
  return parsed;
}

export function extractScryptParams(storedHash: string): ScryptCostParams | null {
  const parts = (storedHash || '').split(':');
  if (parts.length !== 4 || parts[0] !== 'scrypt') return null;
  return parseScryptParamsSpec(parts[1]!);
}

export function assertNoKdfDowngrade(
  previousHash: string | null | undefined,
  candidateHash: string
): void {
  const nextParams = extractScryptParams(candidateHash);
  if (!nextParams) {
    throw new Error('AUTH_KDF_DOWNGRADE_REJECTED: Formato de hash KDF candidato inválido.');
  }
  if (
    nextParams.N < CURRENT_SCRYPT_PARAMS.N ||
    nextParams.r < CURRENT_SCRYPT_PARAMS.r ||
    nextParams.p < CURRENT_SCRYPT_PARAMS.p
  ) {
    throw new Error(
      `AUTH_KDF_DOWNGRADE_REJECTED: Parâmetros KDF (N=${nextParams.N},r=${nextParams.r},p=${nextParams.p}) inferiores ao padrão mínimo N=${CURRENT_SCRYPT_PARAMS.N}.`
    );
  }
  if (previousHash) {
    const prevParams = extractScryptParams(previousHash);
    if (
      prevParams &&
      (nextParams.N < prevParams.N || nextParams.r < prevParams.r || nextParams.p < prevParams.p)
    ) {
      throw new Error(
        `AUTH_KDF_DOWNGRADE_REJECTED: Downgrade KDF bloqueado (${prevParams.N} -> ${nextParams.N}).`
      );
    }
  }
}

export function hashPassword(
  credentialValue: string,
  costParams: Partial<ScryptCostParams> = CURRENT_SCRYPT_PARAMS
): string {
  const N = costParams.N ?? CURRENT_SCRYPT_PARAMS.N;
  const r = costParams.r ?? CURRENT_SCRYPT_PARAMS.r;
  const p = costParams.p ?? CURRENT_SCRYPT_PARAMS.p;
  const maxmem = Math.max(64 * 1024 * 1024, 256 * N * r);
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(credentialValue, salt, 64, { N, r, p, maxmem }).toString('hex');
  return `scrypt:N=${N},r=${r},p=${p}:${salt}:${derived}`;
}

export function verifyPassword(credentialValue: string, storedHash: string): boolean {
  const parts = (storedHash || '').split(':');
  if (parts.length !== 4 || parts[0] !== 'scrypt') return false;
  const params = parseScryptParamsSpec(parts[1]!);
  const salt = parts[2]!;
  const expectedHex = parts[3]!;
  const derived = crypto.scryptSync(credentialValue, salt, 64, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: params.maxmem,
  });
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(derived, expectedBuf);
}

export function needsPasswordRehash(storedHash: string): boolean {
  const parts = (storedHash || '').split(':');
  if (parts.length !== 4 || parts[0] !== 'scrypt') return true;
  const params = parseScryptParamsSpec(parts[1]!);
  return (
    params.N < CURRENT_SCRYPT_PARAMS.N ||
    params.r < CURRENT_SCRYPT_PARAMS.r ||
    params.p < CURRENT_SCRYPT_PARAMS.p
  );
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
  private webauthnChallenges = new Map<string, WebAuthnChallengeRecord>();

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

  private bootstrapInProgress = false;
  private registrationInProgress = new Set<string>();

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
    if (this.bootstrapInProgress) {
      throw new Error('BOOTSTRAP_CONFLICT: Inicialização administrativa já está em processamento.');
    }
    this.bootstrapInProgress = true;
    try {
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
    } finally {
      this.bootstrapInProgress = false;
    }
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

    const prevPasswordHash = user.passwordHash;
    const prevTotpSecret = user.totpSecretBase32;
    const prevUpdatedAt = user.updatedAt;
    const prevSessionsSnapshot = [...this.db.sessions];

    user.failedLoginAttempts = 0;
    user.lockedUntil = null;
    user.updatedAt = new Date().toISOString();
    // Transparently upgrade legacy password hash cost parameters on successful login
    if (needsPasswordRehash(user.passwordHash)) {
      const upgradedHash = hashPassword(params.password);
      assertNoKdfDowngrade(user.passwordHash, upgradedHash);
      user.passwordHash = upgradedHash;
    }
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
    try {
      this.save();
    } catch (persistErr) {
      // Preserve pre-migration account integrity in memory if disk persistence fails
      user.passwordHash = prevPasswordHash;
      user.totpSecretBase32 = prevTotpSecret;
      user.updatedAt = prevUpdatedAt;
      this.db.sessions = prevSessionsSnapshot;
      throw persistErr;
    }

    const mfaRequired = user.mfaEnabled && !mfaVerified;
    return {
      user: this.toPublicUserView(user, session.mfaVerified),
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

  public loginWithPin(params: {
    email?: string;
    pin: string;
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
    let user: UserAccountRecord | undefined;
    if (email) {
      user = this.db.users.find((u) => u.email === email);
    } else {
      const pinUsers = this.db.users.filter((u) => !u.disabled && u.pinEnabled && u.pinHash);
      if (pinUsers.length === 1) {
        user = pinUsers[0];
      } else if (this.db.users.length === 1) {
        user = this.db.users[0];
      }
    }

    if (!user || user.disabled) {
      this.recordIpFailure(ipAddress);
      throw new Error('AUTH_INVALID_CREDENTIALS: E-mail ou PIN rápido inválido.');
    }

    if (user.lockedUntil && Date.now() < Date.parse(user.lockedUntil)) {
      throw new Error('AUTH_ACCOUNT_LOCKED: Conta temporariamente bloqueada após tentativas excessivas.');
    }

    const candidatePin = (params.pin || '').trim();
    if (
      !user.pinEnabled ||
      !user.pinHash ||
      !/^\d{6,8}$/.test(candidatePin) ||
      !verifyPassword(candidatePin, user.pinHash)
    ) {
      user.failedLoginAttempts += 1;
      if (user.failedLoginAttempts >= AuthService.MAX_LOGIN_ATTEMPTS) {
        user.lockedUntil = new Date(Date.now() + AuthService.LOCKOUT_DURATION_MS).toISOString();
      }
      this.recordIpFailure(ipAddress);
      this.save();
      throw new Error('AUTH_INVALID_CREDENTIALS: E-mail ou PIN rápido inválido.');
    }

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

    const prevPinHash = user.pinHash;
    const prevUpdatedAt = user.updatedAt;
    const prevSessionsSnapshot = [...this.db.sessions];

    user.failedLoginAttempts = 0;
    user.lockedUntil = null;
    user.updatedAt = new Date().toISOString();
    if (user.pinHash && needsPasswordRehash(user.pinHash)) {
      const upgradedPinHash = hashPassword(candidatePin);
      assertNoKdfDowngrade(user.pinHash, upgradedPinHash);
      user.pinHash = upgradedPinHash;
    }

    const trustDevice = Boolean(params.trustDevice);
    const { sessionId, session } = this.createSessionRecord(
      user,
      mfaVerified,
      ipAddress,
      params.userAgent || 'unknown',
      { trustDevice }
    );
    try {
      this.save();
    } catch (persistErr) {
      user.pinHash = prevPinHash;
      user.updatedAt = prevUpdatedAt;
      this.db.sessions = prevSessionsSnapshot;
      throw persistErr;
    }

    const mfaRequired = user.mfaEnabled && !mfaVerified;
    return {
      user: this.toPublicUserView(user, session.mfaVerified),
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

  public setupPinForUser(userId: string, rawPin: string): PublicUserView {
    const user = this.db.users.find((u) => u.id === userId);
    if (!user || user.disabled) {
      throw new Error('Usuário não encontrado.');
    }
    const validPin = validateQuickPin(rawPin);
    user.pinHash = hashPassword(validPin);
    user.pinEnabled = true;
    user.updatedAt = new Date().toISOString();
    this.save();
    return this.toPublicUserView(user, true);
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

  public disableMfaForUser(
    userId: string,
    verification: {
      password?: string;
      totpCode?: string;
      recoveryCode?: string;
    },
    currentSessionId?: string
  ): PublicUserView {
    const user = this.db.users.find((u) => u.id === userId);
    if (!user || user.disabled) {
      throw new Error('USER_NOT_FOUND: Usuário não encontrado.');
    }
    if (!user.mfaEnabled) {
      throw new Error('AUTH_MFA_NOT_ENABLED: Autenticação TOTP já está desabilitada para esta conta.');
    }

    const rawTotp = (verification?.totpCode || '').trim();
    const rawRecovery = (verification?.recoveryCode || '').trim();
    const rawPassword = verification?.password || '';

    let verified = false;
    if (rawTotp) {
      const plainSecret = this.decryptSecretAtRest(user.totpSecretBase32);
      if (!plainSecret) {
        throw new Error('AUTH_INVALID_MFA: Segredo TOTP não encontrado no cofre.');
      }
      const check = verifyTotpCodeWithStep(plainSecret, rawTotp, user.lastAcceptedTotpStep);
      if (check.replayRejected) {
        throw new Error(
          'AUTH_TOTP_REPLAY: Código TOTP já utilizado nesta janela de 30s. Aguarde o próximo token.'
        );
      }
      if (!check.valid) {
        throw new Error('AUTH_INVALID_MFA: Código TOTP inválido.');
      }
      verified = true;
    } else if (rawRecovery) {
      if (!this.tryConsumeRecoveryCode(user, rawRecovery)) {
        throw new Error('AUTH_INVALID_RECOVERY_CODE: Código de recuperação inválido ou já utilizado.');
      }
      verified = true;
    } else if (rawPassword) {
      if (!verifyPassword(rawPassword, user.passwordHash)) {
        throw new Error('AUTH_INVALID_CREDENTIALS: Senha de confirmação inválida.');
      }
      verified = true;
    }

    if (!verified) {
      throw new Error(
        'AUTH_MFA_VERIFICATION_REQUIRED: Confirme a senha atual, código TOTP ou código de recuperação para remover o 2FA.'
      );
    }

    user.mfaEnabled = false;
    user.totpSecretBase32 = null;
    user.pendingTotpSecretBase32 = null;
    user.recoveryCodeHashes = [];
    user.lastAcceptedTotpStep = null;
    user.updatedAt = new Date().toISOString();

    if (currentSessionId) {
      const targetHash = sha256(currentSessionId);
      const sess = this.db.sessions.find((s) => s.sessionIdHash === targetHash);
      if (sess && sess.userId === user.id) {
        sess.mfaVerified = true;
      }
    }

    this.save();
    return this.toPublicUserView(user, true);
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
        ...this.toPublicUserView(user, session.mfaVerified),
        role: effectiveRole,
      },
      session,
    };
  }

  private toPublicUserView(user: UserAccountRecord, mfaVerified: boolean): PublicUserView {
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      mfaEnabled: user.mfaEnabled,
      mfaVerified,
      pinEnabled: Boolean(user.pinEnabled && user.pinHash),
      webauthnEnabled: Boolean(user.webauthnCredentials && user.webauthnCredentials.length > 0),
      githubLinked: Boolean(user.githubId || user.githubLogin),
      githubLogin: user.githubLogin || null,
      githubAvatarUrl: user.githubAvatarUrl || null,
      authProviders: user.authProviders || [],
    };
  }

  public hasAnyWebAuthnCredentials(): boolean {
    return this.db.users.some(
      (u) => !u.disabled && Array.isArray(u.webauthnCredentials) && u.webauthnCredentials.length > 0
    );
  }

  private completeBootstrapOnFirstAccount(nowIso: string): void {
    this.db.bootstrapTokenSha256 = null;
    this.db.bootstrapTokenExpiresAt = null;
    this.db.bootstrapCompletedAt = nowIso;
    try {
      if (fs.existsSync(this.bootstrapTokenFilePath)) {
        fs.unlinkSync(this.bootstrapTokenFilePath);
      }
    } catch {
      // Best-effort delete
    }
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
    password?: string;
    pin?: string;
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
    const rawPin = (params.pin || '').trim();

    if (cleanName.length < 2) {
      throw new Error('INVALID_NAME: O nome completo deve possuir pelo menos 2 caracteres.');
    }
    if (!isValidEmailAddress(cleanEmail)) {
      throw new Error('INVALID_EMAIL: Informe um endereço de e-mail válido.');
    }

    const validatedPin = rawPin ? validateQuickPin(rawPin) : null;
    if (!validatedPin && cleanPassword.length < 10) {
      throw new Error('WEAK_PASSWORD: A senha deve possuir pelo menos 10 caracteres.');
    }
    if (validatedPin && cleanPassword.length > 0 && cleanPassword.length < 10) {
      throw new Error('WEAK_PASSWORD: A senha deve possuir pelo menos 10 caracteres.');
    }

    if (this.registrationInProgress.has(cleanEmail) || this.db.users.some((u) => u.email === cleanEmail)) {
      this.recordIpFailure(ipAddress);
      throw new Error('EMAIL_ALREADY_EXISTS: Este e-mail já está cadastrado na plataforma.');
    }

    const isFirstUser = this.db.users.length === 0;
    let assignedRole: RbacRole = 'ADMIN';

    if (!isFirstUser) {
      const requestedRole: RbacRole = params.role || 'SECURITY_LEAD';
      if (requestedRole === 'ADMIN') {
        throw new Error(
          'ROLE_ELEVATION_BLOCKED: Criação de perfil ADMIN exige privilégio administrativo ou bootstrap inicial.'
        );
      }
      const allowedSelfRoles: ReadonlyArray<RbacRole> = ['SECURITY_LEAD', 'QA_ENGINEER', 'AUDITOR'];
      if (!allowedSelfRoles.includes(requestedRole)) {
        throw new Error('INVALID_ROLE: Perfil de acesso selecionado é inválido.');
      }
      assignedRole = requestedRole;
    }

    this.registrationInProgress.add(cleanEmail);
    try {
      const now = new Date().toISOString();
      const totpSecret = params.enableMfa ? base32Encode(crypto.randomBytes(20)) : null;
      const recoveryGen = totpSecret ? generateRecoveryCodesSet(8) : null;
      const effectivePasswordToHash =
        cleanPassword.length >= 10
          ? cleanPassword
          : `wh-pin-fallback-${crypto.randomBytes(24).toString('base64url')}`;

      const newUser: UserAccountRecord = {
        id: `usr-${crypto.randomUUID().slice(0, 8)}`,
        name: cleanName,
        email: cleanEmail,
        role: assignedRole,
        passwordHash: hashPassword(effectivePasswordToHash),
        pinHash: validatedPin ? hashPassword(validatedPin) : null,
        pinEnabled: Boolean(validatedPin),
        webauthnCredentials: [],
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
        this.completeBootstrapOnFirstAccount(now);
      }

      const { sessionId, session } = this.createSessionRecord(
        newUser,
        !newUser.mfaEnabled,
        ipAddress,
        params.userAgent || 'unknown'
      );
      this.save();

      return {
        user: this.toPublicUserView(newUser, session.mfaVerified),
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
    } finally {
      this.registrationInProgress.delete(cleanEmail);
    }
  }

  private pruneExpiredWebAuthnChallenges(): void {
    const now = Date.now();
    for (const [id, ch] of this.webauthnChallenges.entries()) {
      if (now > ch.expiresAtMs) {
        this.webauthnChallenges.delete(id);
      }
    }
  }

  public beginWebAuthnAccountRegistration(params: {
    name: string;
    email: string;
    role?: RbacRole;
    rpId?: string;
    ipAddress?: string;
  }) {
    return this.createWebAuthnRegistrationOptions(params);
  }

  public createWebAuthnRegistrationOptions(params: {
    name: string;
    email: string;
    role?: RbacRole;
    rpId?: string;
    ipAddress?: string;
  }): {
    challengeId: string;
    rp: { name: string; id: string };
    user: { id: string; name: string; displayName: string };
    challenge: string;
    pubKeyCredParams: Array<{ type: 'public-key'; alg: -7 | -257 }>;
    timeout: number;
    attestation: 'none';
    authenticatorSelection: {
      authenticatorAttachment: 'platform';
      residentKey: 'required';
      requireResidentKey: true;
      userVerification: 'required';
    };
  } {
    const ipAddress = params.ipAddress || '127.0.0.1';
    this.checkIpRateLimit(ipAddress);
    this.pruneExpiredWebAuthnChallenges();

    const cleanName = (params.name || '').trim();
    const cleanEmail = (params.email || '').trim().toLowerCase();
    if (cleanName.length < 2) {
      throw new Error('INVALID_NAME: O nome completo deve possuir pelo menos 2 caracteres.');
    }
    if (!isValidEmailAddress(cleanEmail)) {
      throw new Error('INVALID_EMAIL: Informe um endereço de e-mail válido.');
    }
    if (this.db.users.some((u) => u.email === cleanEmail)) {
      throw new Error('EMAIL_ALREADY_EXISTS: Este e-mail já está cadastrado na plataforma.');
    }
    if (this.db.users.length > 0 && params.role === 'ADMIN') {
      throw new Error(
        'ROLE_ELEVATION_BLOCKED: Criação de perfil ADMIN exige privilégio administrativo ou bootstrap inicial.'
      );
    }

    const rpId = normalizeWebAuthnRpId(params.rpId);
    const challengeId = crypto.randomUUID();
    const challengeBase64Url = crypto.randomBytes(32).toString('base64url');
    const userHandle = crypto.randomBytes(16).toString('base64url');

    this.webauthnChallenges.set(challengeId, {
      challengeId,
      challengeBase64Url,
      purpose: 'REGISTER_ACCOUNT',
      rpId,
      expiresAtMs: Date.now() + AuthService.PREAUTH_TTL_MS,
      registrationMeta: {
        name: cleanName,
        email: cleanEmail,
        role: params.role,
        userHandle,
      },
    });

    return {
      challengeId,
      rp: {
        name: 'WinHood Benchmark Analyzer',
        id: rpId,
      },
      user: {
        id: userHandle,
        name: cleanEmail,
        displayName: cleanName,
      },
      challenge: challengeBase64Url,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      timeout: 60000,
      attestation: 'none',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
      },
    };
  }

  public verifyWebAuthnAccountRegistration(params: {
    challengeId?: string;
    credentialId: string;
    clientDataJSON: string;
    attestationObject?: string;
    authenticatorData?: string;
    publicKeySpkiBase64?: string;
    coseAlgorithm?: number;
    transports?: string[];
    trustDevice?: boolean;
    ipAddress?: string;
    userAgent?: string;
  }): {
    user: PublicUserView;
    sessionId: string;
    csrfToken: string;
    trustDevice: boolean;
  } {
    const ipAddress = params.ipAddress || '127.0.0.1';
    this.checkIpRateLimit(ipAddress);
    this.pruneExpiredWebAuthnChallenges();

    const clientDataBuf = decodeBase64OrBase64Url(params.clientDataJSON);
    let clientData: { type?: string; challenge?: string; origin?: string };
    try {
      clientData = JSON.parse(clientDataBuf.toString('utf8'));
    } catch {
      throw new Error('WEBAUTHN_CLIENT_DATA_INVALID: clientDataJSON malformado.');
    }
    if (clientData.type !== 'webauthn.create' || !clientData.challenge || !clientData.origin) {
      throw new Error('WEBAUTHN_CLIENT_DATA_INVALID: Tipo ou campos de clientDataJSON inválidos.');
    }

    let challengeRecord: WebAuthnChallengeRecord | undefined;
    if (params.challengeId) {
      challengeRecord = this.webauthnChallenges.get(params.challengeId);
    } else {
      for (const rec of this.webauthnChallenges.values()) {
        if (rec.purpose === 'REGISTER_ACCOUNT' && rec.challengeBase64Url === clientData.challenge) {
          challengeRecord = rec;
          break;
        }
      }
    }

    if (!challengeRecord || challengeRecord.purpose !== 'REGISTER_ACCOUNT') {
      throw new Error('WEBAUTHN_CHALLENGE_INVALID: Desafio WebAuthn ausente, expirado ou já utilizado.');
    }
    this.webauthnChallenges.delete(challengeRecord.challengeId);

    if (Date.now() > challengeRecord.expiresAtMs) {
      throw new Error('WEBAUTHN_CHALLENGE_EXPIRED: Desafio WebAuthn expirado (5 minutos).');
    }

    const expectedChallBuf = Buffer.from(challengeRecord.challengeBase64Url, 'utf8');
    const providedChallBuf = Buffer.from(clientData.challenge, 'utf8');
    if (
      expectedChallBuf.length !== providedChallBuf.length ||
      !crypto.timingSafeEqual(expectedChallBuf, providedChallBuf)
    ) {
      throw new Error('WEBAUTHN_CHALLENGE_MISMATCH: Desafio WebAuthn divergente.');
    }

    const { hostname: originHostname } = validateWebAuthnOrigin(
      clientData.origin,
      challengeRecord.rpId
    );

    let authDataBuf: Buffer | null = null;
    let publicKeySpkiBase64 = (params.publicKeySpkiBase64 || '').trim();
    let coseAlgorithm: -7 | -257 = params.coseAlgorithm === -257 ? -257 : -7;
    let extractedCredId = (params.credentialId || '').trim();

    if (params.attestationObject) {
      const attBuf = decodeBase64OrBase64Url(params.attestationObject);
      const attMap = decodeCborItem(attBuf, 0).value;
      if (attMap instanceof Map && Buffer.isBuffer(attMap.get('authData'))) {
        authDataBuf = attMap.get('authData') as Buffer;
      }
    }
    if (!authDataBuf && params.authenticatorData) {
      authDataBuf = decodeBase64OrBase64Url(params.authenticatorData);
    }
    if (!authDataBuf || authDataBuf.length < 37) {
      throw new Error('WEBAUTHN_AUTHDATA_INVALID: authenticatorData ausente ou truncado.');
    }

    const rpIdHash = authDataBuf.subarray(0, 32);
    const expectedRpHash = crypto.createHash('sha256').update(challengeRecord.rpId, 'utf8').digest();
    const originRpHash = crypto.createHash('sha256').update(originHostname, 'utf8').digest();
    const rpMatches =
      crypto.timingSafeEqual(rpIdHash, expectedRpHash) ||
      crypto.timingSafeEqual(rpIdHash, originRpHash);
    if (!rpMatches) {
      throw new Error('WEBAUTHN_RPID_MISMATCH: Hash do Relying Party (rpIdHash) inválido.');
    }

    const flags = authDataBuf[32]!;
    const userPresent = (flags & 0x01) !== 0;
    const userVerified = (flags & 0x04) !== 0;
    const attestedCredDataPresent = (flags & 0x40) !== 0;
    if (!userPresent || !userVerified) {
      throw new Error(
        'WEBAUTHN_UV_REQUIRED: Presença (UP) e verificação biométrica/PIN do Windows Hello (UV) são obrigatórias.'
      );
    }

    const signCount = authDataBuf.readUInt32BE(33);

    if (attestedCredDataPresent && authDataBuf.length >= 55) {
      const credIdLen = authDataBuf.readUInt16BE(53);
      if (authDataBuf.length < 55 + credIdLen) {
        throw new Error('WEBAUTHN_AUTHDATA_INVALID: attestedCredentialData truncado.');
      }
      const rawCredId = authDataBuf.subarray(55, 55 + credIdLen).toString('base64url');
      if (!extractedCredId) {
        extractedCredId = rawCredId;
      }
      const coseKeySlice = authDataBuf.subarray(55 + credIdLen);
      if (coseKeySlice.length > 0 && !publicKeySpkiBase64) {
        const parsedKey = cosePublicKeyToSpkiBase64(coseKeySlice);
        publicKeySpkiBase64 = parsedKey.publicKeySpkiBase64;
        coseAlgorithm = parsedKey.coseAlgorithm;
      }
    }

    if (!extractedCredId || !publicKeySpkiBase64) {
      throw new Error('WEBAUTHN_KEY_MISSING: Chave pública ou identificador da credencial WebAuthn ausente.');
    }

    // Validate SPKI public key is importable by node:crypto
    try {
      const spkiBuf = decodeBase64OrBase64Url(publicKeySpkiBase64);
      const keyObj = crypto.createPublicKey({ key: spkiBuf, format: 'der', type: 'spki' });
      publicKeySpkiBase64 = (keyObj.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64');
    } catch {
      throw new Error('WEBAUTHN_KEY_INVALID: Chave pública SPKI inválida.');
    }

    const regMeta = challengeRecord.registrationMeta!;
    if (this.db.users.some((u) => u.email === regMeta.email)) {
      throw new Error('EMAIL_ALREADY_EXISTS: Este e-mail já está cadastrado na plataforma.');
    }

    const isFirstUser = this.db.users.length === 0;
    let assignedRole: RbacRole = 'ADMIN';
    if (!isFirstUser) {
      const requestedRole: RbacRole = regMeta.role || 'SECURITY_LEAD';
      if (requestedRole === 'ADMIN') {
        throw new Error('ROLE_ELEVATION_BLOCKED: Criação de perfil ADMIN exige privilégio administrativo.');
      }
      assignedRole = requestedRole;
    }

    const now = new Date().toISOString();
    const newUser: UserAccountRecord = {
      id: `usr-${crypto.randomUUID().slice(0, 8)}`,
      name: regMeta.name,
      email: regMeta.email,
      role: assignedRole,
      passwordHash: hashPassword(`wh-webauthn-${crypto.randomBytes(24).toString('base64url')}`),
      pinHash: null,
      pinEnabled: false,
      webauthnCredentials: [
        {
          credentialId: extractedCredId,
          publicKeySpkiBase64,
          coseAlgorithm,
          signCount,
          transports: params.transports || ['internal'],
          createdAt: now,
          lastUsedAt: now,
        },
      ],
      mfaEnabled: false,
      totpSecretBase32: null,
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

    this.db.users.push(newUser);
    if (isFirstUser) {
      this.completeBootstrapOnFirstAccount(now);
    }

    const trustDevice = params.trustDevice !== false;
    const { sessionId, session } = this.createSessionRecord(
      newUser,
      true,
      ipAddress,
      params.userAgent || 'unknown',
      { trustDevice }
    );
    this.save();

    return {
      user: this.toPublicUserView(newUser, true),
      sessionId,
      csrfToken: session.csrfToken,
      trustDevice,
    };
  }

  public createWebAuthnLoginOptions(params?: {
    email?: string;
    rpId?: string;
    ipAddress?: string;
  }): {
    challengeId: string;
    challenge: string;
    rpId: string;
    timeout: number;
    userVerification: 'required';
    authenticatorAttachment: 'platform';
    allowCredentials: Array<{ type: 'public-key'; id: string; transports?: string[] }>;
  } {
    const ipAddress = params?.ipAddress || '127.0.0.1';
    this.checkIpRateLimit(ipAddress);
    this.pruneExpiredWebAuthnChallenges();

    const cleanEmail = (params?.email || '').trim().toLowerCase();
    const rpId = normalizeWebAuthnRpId(params?.rpId);
    const challengeId = crypto.randomUUID();
    const challengeBase64Url = crypto.randomBytes(32).toString('base64url');

    const allowCredentials: Array<{ type: 'public-key'; id: string; transports?: string[] }> = [];
    const candidateUsers = cleanEmail
      ? this.db.users.filter((u) => !u.disabled && u.email === cleanEmail)
      : this.db.users.filter((u) => !u.disabled);

    for (const u of candidateUsers) {
      for (const cred of u.webauthnCredentials || []) {
        allowCredentials.push({
          type: 'public-key',
          id: cred.credentialId,
          transports: cred.transports || ['internal'],
        });
      }
    }

    this.webauthnChallenges.set(challengeId, {
      challengeId,
      challengeBase64Url,
      purpose: 'LOGIN',
      rpId,
      expiresAtMs: Date.now() + AuthService.PREAUTH_TTL_MS,
      email: cleanEmail || undefined,
    });

    return {
      challengeId,
      challenge: challengeBase64Url,
      rpId,
      timeout: 60000,
      userVerification: 'required',
      authenticatorAttachment: 'platform',
      allowCredentials,
    };
  }

  public verifyWebAuthnLogin(params: {
    challengeId?: string;
    credentialId: string;
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    email?: string;
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
    this.pruneExpiredWebAuthnChallenges();

    const clientDataBuf = decodeBase64OrBase64Url(params.clientDataJSON);
    let clientData: { type?: string; challenge?: string; origin?: string };
    try {
      clientData = JSON.parse(clientDataBuf.toString('utf8'));
    } catch {
      throw new Error('WEBAUTHN_CLIENT_DATA_INVALID: clientDataJSON malformado.');
    }
    if (clientData.type !== 'webauthn.get' || !clientData.challenge || !clientData.origin) {
      throw new Error('WEBAUTHN_CLIENT_DATA_INVALID: Tipo ou campos de clientDataJSON inválidos.');
    }

    let challengeRecord: WebAuthnChallengeRecord | undefined;
    if (params.challengeId) {
      challengeRecord = this.webauthnChallenges.get(params.challengeId);
    } else {
      for (const rec of this.webauthnChallenges.values()) {
        if (rec.purpose === 'LOGIN' && rec.challengeBase64Url === clientData.challenge) {
          challengeRecord = rec;
          break;
        }
      }
    }

    if (!challengeRecord || challengeRecord.purpose !== 'LOGIN') {
      throw new Error('WEBAUTHN_CHALLENGE_INVALID: Desafio de login WebAuthn ausente, expirado ou já utilizado.');
    }
    this.webauthnChallenges.delete(challengeRecord.challengeId);

    if (Date.now() > challengeRecord.expiresAtMs) {
      throw new Error('WEBAUTHN_CHALLENGE_EXPIRED: Desafio de login WebAuthn expirado.');
    }

    const expectedChallBuf = Buffer.from(challengeRecord.challengeBase64Url, 'utf8');
    const providedChallBuf = Buffer.from(clientData.challenge, 'utf8');
    if (
      expectedChallBuf.length !== providedChallBuf.length ||
      !crypto.timingSafeEqual(expectedChallBuf, providedChallBuf)
    ) {
      throw new Error('WEBAUTHN_CHALLENGE_MISMATCH: Desafio de login WebAuthn divergente.');
    }

    const { hostname: originHostname } = validateWebAuthnOrigin(
      clientData.origin,
      challengeRecord.rpId
    );

    const credId = (params.credentialId || '').trim();
    const targetEmail = (params.email || challengeRecord.email || '').trim().toLowerCase();

    let matchedUser: UserAccountRecord | undefined;
    let matchedCred: WebAuthnCredentialRecord | undefined;
    for (const u of this.db.users) {
      if (u.disabled) continue;
      if (targetEmail && u.email !== targetEmail) continue;
      const found = (u.webauthnCredentials || []).find((c) => c.credentialId === credId);
      if (found) {
        matchedUser = u;
        matchedCred = found;
        break;
      }
    }

    if (!matchedUser || !matchedCred) {
      this.recordIpFailure(ipAddress);
      throw new Error('WEBAUTHN_CREDENTIAL_NOT_FOUND: Credencial Windows Hello não localizada.');
    }

    if (matchedUser.lockedUntil && Date.now() < Date.parse(matchedUser.lockedUntil)) {
      throw new Error('AUTH_ACCOUNT_LOCKED: Conta temporariamente bloqueada após tentativas excessivas.');
    }

    const authDataBuf = decodeBase64OrBase64Url(params.authenticatorData);
    if (authDataBuf.length < 37) {
      throw new Error('WEBAUTHN_AUTHDATA_INVALID: authenticatorData inválido.');
    }

    const rpIdHash = authDataBuf.subarray(0, 32);
    const expectedRpHash = crypto.createHash('sha256').update(challengeRecord.rpId, 'utf8').digest();
    const originRpHash = crypto.createHash('sha256').update(originHostname, 'utf8').digest();
    if (
      !crypto.timingSafeEqual(rpIdHash, expectedRpHash) &&
      !crypto.timingSafeEqual(rpIdHash, originRpHash)
    ) {
      throw new Error('WEBAUTHN_RPID_MISMATCH: Hash do Relying Party (rpIdHash) inválido.');
    }

    const flags = authDataBuf[32]!;
    if ((flags & 0x01) === 0 || (flags & 0x04) === 0) {
      throw new Error(
        'WEBAUTHN_UV_REQUIRED: Presença (UP) e verificação do usuário (UV) são obrigatórias no Windows Hello.'
      );
    }

    const signCount = authDataBuf.readUInt32BE(33);
    const clientDataHash = crypto.createHash('sha256').update(clientDataBuf).digest();
    const signedPayload = Buffer.concat([authDataBuf, clientDataHash]);
    const signatureBuf = decodeBase64OrBase64Url(params.signature);
    const pubKeyObj = crypto.createPublicKey({
      key: Buffer.from(matchedCred.publicKeySpkiBase64, 'base64'),
      format: 'der',
      type: 'spki',
    });

    const isSigValid = crypto.verify('sha256', signedPayload, pubKeyObj, signatureBuf);
    if (!isSigValid) {
      matchedUser.failedLoginAttempts += 1;
      if (matchedUser.failedLoginAttempts >= AuthService.MAX_LOGIN_ATTEMPTS) {
        matchedUser.lockedUntil = new Date(Date.now() + AuthService.LOCKOUT_DURATION_MS).toISOString();
      }
      this.recordIpFailure(ipAddress);
      this.save();
      throw new Error('WEBAUTHN_SIGNATURE_INVALID: Assinatura criptográfica WebAuthn inválida.');
    }

    if (matchedCred.signCount > 0 && signCount <= matchedCred.signCount) {
      this.recordIpFailure(ipAddress);
      throw new Error(
        'WEBAUTHN_REPLAY_DETECTED: Contador anti-replay WebAuthn regressivo ou repetido.'
      );
    }

    matchedCred.signCount = signCount;
    matchedCred.lastUsedAt = new Date().toISOString();
    matchedUser.failedLoginAttempts = 0;
    matchedUser.lockedUntil = null;
    matchedUser.updatedAt = new Date().toISOString();

    const mfaVerified = !matchedUser.mfaEnabled;
    const trustDevice = params.trustDevice !== false;
    const { sessionId, session } = this.createSessionRecord(
      matchedUser,
      mfaVerified,
      ipAddress,
      params.userAgent || 'unknown',
      { trustDevice }
    );
    this.save();

    const mfaRequired = matchedUser.mfaEnabled && !mfaVerified;
    return {
      user: this.toPublicUserView(matchedUser, session.mfaVerified),
      sessionId,
      csrfToken: session.csrfToken,
      mfaRequired,
      requiresTotp: mfaRequired,
      ...(mfaRequired
        ? { preAuthToken: this.createPreAuthToken(matchedUser.id, matchedUser.email, trustDevice) }
        : {}),
      trustDevice,
      serverTimeIso: new Date().toISOString(),
      totpPeriodSeconds: 30,
    };
  }

  public createWebAuthnLinkOptions(params: {
    userId: string;
    rpId?: string;
    ipAddress?: string;
  }) {
    const ipAddress = params.ipAddress || '127.0.0.1';
    this.checkIpRateLimit(ipAddress);
    this.pruneExpiredWebAuthnChallenges();

    const user = this.db.users.find((u) => u.id === params.userId && !u.disabled);
    if (!user) {
      throw new Error('USER_NOT_FOUND: Usuário não encontrado.');
    }

    const rpId = normalizeWebAuthnRpId(params.rpId);
    const challengeId = crypto.randomUUID();
    const challengeBase64Url = crypto.randomBytes(32).toString('base64url');
    const excludeCredentials = (user.webauthnCredentials || []).map((c) => ({
      type: 'public-key' as const,
      id: c.credentialId,
      transports: c.transports || ['internal'],
    }));

    this.webauthnChallenges.set(challengeId, {
      challengeId,
      challengeBase64Url,
      purpose: 'LINK_CREDENTIAL',
      rpId,
      expiresAtMs: Date.now() + AuthService.PREAUTH_TTL_MS,
      userId: user.id,
      email: user.email,
    });

    return {
      challengeId,
      rp: { name: 'WinHood Benchmark Analyzer', id: rpId },
      user: {
        id: Buffer.from(user.id, 'utf8').toString('base64url'),
        name: user.email,
        displayName: user.name,
      },
      challenge: challengeBase64Url,
      pubKeyCredParams: [
        { type: 'public-key' as const, alg: -7 as const },
        { type: 'public-key' as const, alg: -257 as const },
      ],
      timeout: 60000,
      attestation: 'none' as const,
      excludeCredentials,
      authenticatorSelection: {
        authenticatorAttachment: 'platform' as const,
        residentKey: 'required' as const,
        requireResidentKey: true,
        userVerification: 'required' as const,
      },
    };
  }

  public verifyWebAuthnLinkCredential(params: {
    userId: string;
    challengeId?: string;
    credentialId: string;
    clientDataJSON: string;
    attestationObject?: string;
    authenticatorData?: string;
    publicKeySpkiBase64?: string;
    coseAlgorithm?: number;
    transports?: string[];
    label?: string;
    ipAddress?: string;
  }): { user: PublicUserView; credentialId: string } {
    const ipAddress = params.ipAddress || '127.0.0.1';
    this.checkIpRateLimit(ipAddress);
    this.pruneExpiredWebAuthnChallenges();

    const clientDataBuf = decodeBase64OrBase64Url(params.clientDataJSON);
    let clientData: { type?: string; challenge?: string; origin?: string };
    try {
      clientData = JSON.parse(clientDataBuf.toString('utf8'));
    } catch {
      throw new Error('WEBAUTHN_CLIENT_DATA_INVALID: clientDataJSON malformado.');
    }
    if (clientData.type !== 'webauthn.create' || !clientData.challenge || !clientData.origin) {
      throw new Error('WEBAUTHN_CLIENT_DATA_INVALID: Tipo ou campos de clientDataJSON inválidos.');
    }

    let challengeRecord: WebAuthnChallengeRecord | undefined;
    if (params.challengeId) {
      challengeRecord = this.webauthnChallenges.get(params.challengeId);
    }
    if (!challengeRecord || challengeRecord.purpose !== 'LINK_CREDENTIAL' || challengeRecord.userId !== params.userId) {
      throw new Error('WEBAUTHN_CHALLENGE_INVALID: Desafio de vínculo WebAuthn inválido ou expirado.');
    }
    this.webauthnChallenges.delete(challengeRecord.challengeId);

    if (Date.now() > challengeRecord.expiresAtMs) {
      throw new Error('WEBAUTHN_CHALLENGE_EXPIRED: Desafio WebAuthn expirado.');
    }

    const expectedChallBuf = Buffer.from(challengeRecord.challengeBase64Url, 'utf8');
    const providedChallBuf = Buffer.from(clientData.challenge, 'utf8');
    if (
      expectedChallBuf.length !== providedChallBuf.length ||
      !crypto.timingSafeEqual(expectedChallBuf, providedChallBuf)
    ) {
      throw new Error('WEBAUTHN_CHALLENGE_MISMATCH: Desafio WebAuthn divergente.');
    }

    const { hostname: originHostname } = validateWebAuthnOrigin(
      clientData.origin,
      challengeRecord.rpId
    );

    let authDataBuf: Buffer | null = null;
    let publicKeySpkiBase64 = (params.publicKeySpkiBase64 || '').trim();
    let coseAlgorithm: -7 | -257 = params.coseAlgorithm === -257 ? -257 : -7;
    let extractedCredId = (params.credentialId || '').trim();

    if (params.attestationObject) {
      const attBuf = decodeBase64OrBase64Url(params.attestationObject);
      const attMap = decodeCborItem(attBuf, 0).value;
      if (attMap instanceof Map && Buffer.isBuffer(attMap.get('authData'))) {
        authDataBuf = attMap.get('authData') as Buffer;
      }
    }
    if (!authDataBuf && params.authenticatorData) {
      authDataBuf = decodeBase64OrBase64Url(params.authenticatorData);
    }
    if (!authDataBuf || authDataBuf.length < 37) {
      throw new Error('WEBAUTHN_AUTHDATA_INVALID: authenticatorData ausente ou truncado.');
    }

    const rpIdHash = authDataBuf.subarray(0, 32);
    const expectedRpHash = crypto.createHash('sha256').update(challengeRecord.rpId, 'utf8').digest();
    const originRpHash = crypto.createHash('sha256').update(originHostname, 'utf8').digest();
    if (
      !crypto.timingSafeEqual(rpIdHash, expectedRpHash) &&
      !crypto.timingSafeEqual(rpIdHash, originRpHash)
    ) {
      throw new Error('WEBAUTHN_RPID_MISMATCH: Hash do Relying Party (rpIdHash) inválido.');
    }

    const flags = authDataBuf[32]!;
    if ((flags & 0x01) === 0 || (flags & 0x04) === 0) {
      throw new Error(
        'WEBAUTHN_UV_REQUIRED: Presença (UP) e verificação do usuário (UV) são obrigatórias.'
      );
    }

    const signCount = authDataBuf.readUInt32BE(33);
    if ((flags & 0x40) !== 0 && authDataBuf.length >= 55) {
      const credIdLen = authDataBuf.readUInt16BE(53);
      if (authDataBuf.length >= 55 + credIdLen) {
        if (!extractedCredId) {
          extractedCredId = authDataBuf.subarray(55, 55 + credIdLen).toString('base64url');
        }
        const coseKeySlice = authDataBuf.subarray(55 + credIdLen);
        if (coseKeySlice.length > 0 && !publicKeySpkiBase64) {
          const parsedKey = cosePublicKeyToSpkiBase64(coseKeySlice);
          publicKeySpkiBase64 = parsedKey.publicKeySpkiBase64;
          coseAlgorithm = parsedKey.coseAlgorithm;
        }
      }
    }

    if (!extractedCredId || !publicKeySpkiBase64) {
      throw new Error('WEBAUTHN_KEY_MISSING: Chave pública ou identificador da credencial ausente.');
    }

    const spkiBuf = decodeBase64OrBase64Url(publicKeySpkiBase64);
    const keyObj = crypto.createPublicKey({ key: spkiBuf, format: 'der', type: 'spki' });
    publicKeySpkiBase64 = (keyObj.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64');

    const user = this.db.users.find((u) => u.id === params.userId && !u.disabled);
    if (!user) {
      throw new Error('USER_NOT_FOUND: Usuário não encontrado.');
    }
    user.webauthnCredentials = user.webauthnCredentials || [];
    if (user.webauthnCredentials.some((c) => c.credentialId === extractedCredId)) {
      throw new Error('WEBAUTHN_CREDENTIAL_EXISTS: Esta Passkey já está vinculada à conta.');
    }

    const now = new Date().toISOString();
    user.webauthnCredentials.push({
      credentialId: extractedCredId,
      publicKeySpkiBase64,
      coseAlgorithm,
      signCount,
      transports: params.transports || ['internal'],
      label: (params.label || 'Windows Hello / Passkey').trim().slice(0, 60),
      createdAt: now,
      lastUsedAt: now,
    });
    const providers = new Set<AuthProviderKind>(user.authProviders || []);
    providers.add('webauthn');
    user.authProviders = Array.from(providers);
    user.updatedAt = now;
    this.save();

    return {
      user: this.toPublicUserView(user, true),
      credentialId: extractedCredId,
    };
  }

  public static buildWindowsHelloPowerShellScript(): string {
    return [
      '$ErrorActionPreference = "Stop"',
      'Add-Type -AssemblyName System.Runtime.WindowsRuntime',
      '$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq "AsTask" -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq "IAsyncOperation`1" })[0]',
      'function Await-WinRtTask($WinRtTask, $ResultType) {',
      '  $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)',
      '  $netTask = $asTask.Invoke($null, @($WinRtTask))',
      '  $netTask.Wait(-1) | Out-Null',
      '  return $netTask.Result',
      '}',
      '[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null',
      '$avail = Await-WinRtTask ([Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])',
      'if ([int]$avail -ne 0) {',
      '  Write-Output ("UNAVAILABLE:" + [int]$avail + ":" + $avail.ToString())',
      '  exit 2',
      '}',
      '$prompt = $env:WINHOOD_HELLO_PROMPT',
      'if ([string]::IsNullOrWhiteSpace($prompt)) { $prompt = "WinHood Benchmark Analyzer - Windows Hello" }',
      '$res = Await-WinRtTask ([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($prompt)) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])',
      'if ([int]$res -eq 0) {',
      '  Write-Output "VERIFIED:0"',
      '  exit 0',
      '}',
      'Write-Output ("FAILED:" + [int]$res + ":" + $res.ToString())',
      'exit 1',
    ].join('\n');
  }

  public async verifyWindowsOsHelloPrompt(promptMessage: string): Promise<{
    verified: boolean;
    statusCode: number;
    statusName: string;
  }> {
    if (process.platform !== 'win32') {
      throw new Error(
        `WINDOWS_HELLO_OS_UNSUPPORTED: Verificação nativa do sistema operacional Windows Hello requer Windows (plataforma atual: ${process.platform}).`
      );
    }

    const sanitizedPrompt = (promptMessage || 'WinHood Benchmark Analyzer — Windows Hello')
      .replace(/[\r\n\0]/g, ' ')
      .trim()
      .slice(0, 160);

    const script = AuthService.buildWindowsHelloPowerShellScript();
    const encodedCommand = Buffer.from(script, 'utf16le').toString('base64');

    try {
      const winSysRoot = process.env.SystemRoot || 'C:\\Windows';
      const powerShellAbsPath = path.win32.join(
        winSysRoot,
        'System32',
        'WindowsPowerShell',
        'v1.0',
        'powershell.exe'
      );
      const { stdout } = await execFileAsync(
        powerShellAbsPath,
        ['-NoProfile', '-NonInteractive', '-STA', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodedCommand],
        {
          timeout: 65000,
          windowsHide: true,
          env: {
            ...process.env,
            WINHOOD_HELLO_PROMPT: sanitizedPrompt,
          },
        }
      );

      const line = String(stdout || '').trim().split(/\r?\n/).pop() || '';
      if (line.startsWith('VERIFIED:0')) {
        return { verified: true, statusCode: 0, statusName: 'Verified' };
      }
      throw new Error(`WINDOWS_HELLO_CANCELLED: Verificação do Windows Hello não confirmada (${line || 'Unknown'}).`);
    } catch (err: any) {
      const stdout = String(err?.stdout || '').trim();
      const stderr = String(err?.stderr || '').trim();
      const combined = `${stdout} ${stderr} ${err?.message || ''}`;
      if (stdout.startsWith('UNAVAILABLE:')) {
        throw new Error(
          `WINDOWS_HELLO_UNAVAILABLE: Windows Hello não está configurado ou disponível neste dispositivo Windows (${stdout}).`
        );
      }
      if (stdout.startsWith('FAILED:')) {
        throw new Error(
          `WINDOWS_HELLO_CANCELLED: Verificação do Windows Hello cancelada ou recusada na janela Segurança do Windows (${stdout}).`
        );
      }
      if (combined.startsWith('WINDOWS_HELLO_')) {
        throw err;
      }
      throw new Error(
        `WINDOWS_HELLO_EXECUTION_FAILED: Não foi possível acionar o prompt nativo do Windows Hello (${err?.message || 'Erro PowerShell'}).`
      );
    }
  }

  private deriveNativeHelloSealKey(keyBuffer: Buffer): Buffer {
    return crypto.createHash('sha256').update(keyBuffer).update(':winhello-native-ecdsa-v1').digest();
  }

  private sealNativeHelloPrivateKey(pkcs8Der: Buffer): string {
    const { keyId, keyBuffer } = KeyManagementService.getActiveVaultAesKey(this.keystorePath);
    const derivedKey = this.deriveNativeHelloSealKey(keyBuffer);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
    const encrypted = Buffer.concat([cipher.update(pkcs8Der), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `wh-hello-key-v1:${keyId}:${iv.toString('base64url')}:${tag.toString('base64url')}:${encrypted.toString('base64url')}`;
  }

  private unsealNativeHelloPrivateKey(sealed: string): crypto.KeyObject {
    const parts = (sealed || '').split(':');
    if (parts.length !== 5 || parts[0] !== 'wh-hello-key-v1') {
      throw new Error('WINDOWS_HELLO_KEY_CORRUPTED: Formato inválido da chave privada selada do Windows Hello.');
    }
    const [, keyId, ivB64, tagB64, cipherB64] = parts;
    const keyBuf =
      KeyManagementService.getVaultKeyBufferByKeyId(keyId!, this.keystorePath) ||
      KeyManagementService.getActiveVaultAesKey(this.keystorePath).keyBuffer;
    const derivedKey = this.deriveNativeHelloSealKey(keyBuf);
    try {
      const iv = Buffer.from(ivB64!, 'base64url');
      const tag = Buffer.from(tagB64!, 'base64url');
      const ciphertext = Buffer.from(cipherB64!, 'base64url');
      const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
      decipher.setAuthTag(tag);
      const pkcs8Der = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return crypto.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
    } catch {
      throw new Error('WINDOWS_HELLO_KEY_CORRUPTED: Chave criptográfica do Windows Hello inválida ou adulterada.');
    }
  }

  public async registerNativeWindowsHelloAccount(params: {
    name: string;
    email: string;
    role?: RbacRole;
    trustDevice?: boolean;
    ipAddress?: string;
    userAgent?: string;
    promptVerifier?: (promptMessage: string) => Promise<void>;
  }): Promise<{
    user: PublicUserView;
    sessionId: string;
    csrfToken: string;
    trustDevice: boolean;
    credentialId: string;
    keyAlgorithm: 'ES256';
  }> {
    const ipAddress = params.ipAddress || '127.0.0.1';
    this.checkIpRateLimit(ipAddress);

    const cleanName = (params.name || '').trim();
    const cleanEmail = (params.email || '').trim().toLowerCase();
    if (cleanName.length < 2) {
      throw new Error('INVALID_NAME: O nome completo deve possuir pelo menos 2 caracteres.');
    }
    if (!isValidEmailAddress(cleanEmail)) {
      throw new Error('INVALID_EMAIL: Informe um endereço de e-mail válido.');
    }
    if (this.registrationInProgress.has(cleanEmail) || this.db.users.some((u) => u.email === cleanEmail)) {
      throw new Error('EMAIL_ALREADY_EXISTS: Este e-mail já está cadastrado na plataforma.');
    }

    const isFirstUser = this.db.users.length === 0;
    let assignedRole: RbacRole = 'ADMIN';
    if (!isFirstUser) {
      const requestedRole: RbacRole = params.role || 'SECURITY_LEAD';
      if (requestedRole === 'ADMIN') {
        throw new Error(
          'ROLE_ELEVATION_BLOCKED: Criação de perfil ADMIN exige privilégio administrativo ou bootstrap inicial.'
        );
      }
      const allowedSelfRoles: ReadonlyArray<RbacRole> = ['SECURITY_LEAD', 'QA_ENGINEER', 'AUDITOR'];
      if (!allowedSelfRoles.includes(requestedRole)) {
        throw new Error('INVALID_ROLE: Perfil de acesso selecionado é inválido.');
      }
      assignedRole = requestedRole;
    }

    this.registrationInProgress.add(cleanEmail);
    try {
      const promptMsg = `WinHood Benchmark Analyzer: Confirmar cadastro com Windows Hello para ${cleanEmail}`;
      if (params.promptVerifier) {
        await params.promptVerifier(promptMsg);
      } else {
        await this.verifyWindowsOsHelloPrompt(promptMsg);
      }

      if (this.db.users.some((u) => u.email === cleanEmail)) {
        throw new Error('EMAIL_ALREADY_EXISTS: Este e-mail já está cadastrado na plataforma.');
      }

      // Gera par de chaves ECDSA P-256 (ES256) e sela a chave privada em repouso via AES-256-GCM
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const spkiBase64 = (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64');
      const pkcs8Der = privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
      const nativePrivateKeySealed = this.sealNativeHelloPrivateKey(pkcs8Der);
      const credentialId = `winhello-os-${crypto.randomBytes(16).toString('base64url')}`;

      const now = new Date().toISOString();
      const newUser: UserAccountRecord = {
        id: `usr-${crypto.randomUUID().slice(0, 8)}`,
        name: cleanName,
        email: cleanEmail,
        role: assignedRole,
        passwordHash: hashPassword(`wh-winhello-${crypto.randomBytes(24).toString('base64url')}`),
        pinHash: null,
        pinEnabled: false,
        webauthnCredentials: [
          {
            credentialId,
            publicKeySpkiBase64: spkiBase64,
            coseAlgorithm: -7,
            signCount: 1,
            transports: ['internal'],
            label: 'Windows Hello Nativo (OS)',
            nativePrivateKeySealed,
            createdAt: now,
            lastUsedAt: now,
          },
        ],
        authProviders: ['windows-hello-native'],
        mfaEnabled: false,
        totpSecretBase32: null,
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

      this.db.users.push(newUser);
      if (isFirstUser) {
        this.completeBootstrapOnFirstAccount(now);
      }

      const trustDevice = params.trustDevice !== false;
      const { sessionId, session } = this.createSessionRecord(
        newUser,
        true,
        ipAddress,
        params.userAgent || 'unknown',
        { trustDevice }
      );
      this.save();

      return {
        user: this.toPublicUserView(newUser, true),
        sessionId,
        csrfToken: session.csrfToken,
        trustDevice,
        credentialId,
        keyAlgorithm: 'ES256',
      };
    } finally {
      this.registrationInProgress.delete(cleanEmail);
    }
  }

  public async loginNativeWindowsHelloAccount(params?: {
    email?: string;
    trustDevice?: boolean;
    ipAddress?: string;
    userAgent?: string;
    promptVerifier?: (promptMessage: string) => Promise<void>;
  }): Promise<{
    user: PublicUserView;
    sessionId: string;
    csrfToken: string;
    mfaRequired: boolean;
    requiresTotp: boolean;
    preAuthToken?: string;
    trustDevice: boolean;
    serverTimeIso: string;
    totpPeriodSeconds: number;
  }> {
    const ipAddress = params?.ipAddress || '127.0.0.1';
    this.checkIpRateLimit(ipAddress);

    if (!params?.promptVerifier && process.platform !== 'win32') {
      throw new Error(
        `WINDOWS_HELLO_OS_UNSUPPORTED: Verificação nativa do sistema operacional Windows Hello requer Windows (plataforma atual: ${process.platform}).`
      );
    }

    const cleanEmail = (params?.email || '').trim().toLowerCase();
    let matchedUser: UserAccountRecord | undefined;
    if (cleanEmail) {
      matchedUser = this.db.users.find(
        (u) => !u.disabled && u.email === cleanEmail && Boolean(u.webauthnCredentials?.length)
      );
    } else {
      const helloUsers = this.db.users.filter(
        (u) => !u.disabled && Boolean(u.webauthnCredentials?.length)
      );
      if (helloUsers.length === 1) {
        matchedUser = helloUsers[0];
      }
    }

    if (!matchedUser) {
      this.recordIpFailure(ipAddress);
      throw new Error(
        cleanEmail
          ? 'WEBAUTHN_CREDENTIAL_NOT_FOUND: Nenhuma credencial Windows Hello cadastrada para este e-mail.'
          : 'WEBAUTHN_CREDENTIAL_NOT_FOUND: Informe o e-mail da conta Windows Hello (ou cadastre uma credencial primeiro).'
      );
    }

    if (matchedUser.lockedUntil && Date.now() < Date.parse(matchedUser.lockedUntil)) {
      throw new Error('AUTH_ACCOUNT_LOCKED: Conta temporariamente bloqueada após tentativas excessivas.');
    }

    const promptMsg = `WinHood Benchmark Analyzer: Autenticar acesso de ${matchedUser.email} com Windows Hello`;
    if (params?.promptVerifier) {
      await params.promptVerifier(promptMsg);
    } else {
      await this.verifyWindowsOsHelloPrompt(promptMsg);
    }

    const targetCred =
      matchedUser.webauthnCredentials?.find((c) => Boolean(c.nativePrivateKeySealed)) ||
      matchedUser.webauthnCredentials?.[0];
    if (targetCred?.nativePrivateKeySealed) {
      const challenge = crypto.randomBytes(32);
      const privKey = this.unsealNativeHelloPrivateKey(targetCred.nativePrivateKeySealed);
      const signature = crypto.sign('sha256', challenge, privKey);
      const pubKey = crypto.createPublicKey({
        key: Buffer.from(targetCred.publicKeySpkiBase64, 'base64'),
        format: 'der',
        type: 'spki',
      });
      const verified = crypto.verify('sha256', challenge, pubKey, signature);
      if (!verified) {
        this.recordIpFailure(ipAddress);
        throw new Error(
          'WINDOWS_HELLO_SIGNATURE_INVALID: Verificação criptográfica ES256 da credencial Windows Hello falhou.'
        );
      }
    }

    const now = new Date().toISOString();
    if (targetCred) {
      targetCred.signCount = (targetCred.signCount || 0) + 1;
      targetCred.lastUsedAt = now;
    }
    matchedUser.failedLoginAttempts = 0;
    matchedUser.lockedUntil = null;
    matchedUser.updatedAt = now;

    const mfaVerified = !matchedUser.mfaEnabled;
    const trustDevice = params?.trustDevice !== false;
    const { sessionId, session } = this.createSessionRecord(
      matchedUser,
      mfaVerified,
      ipAddress,
      params?.userAgent || 'unknown',
      { trustDevice }
    );
    this.save();

    const mfaRequired = matchedUser.mfaEnabled && !mfaVerified;
    return {
      user: this.toPublicUserView(matchedUser, session.mfaVerified),
      sessionId,
      csrfToken: session.csrfToken,
      mfaRequired,
      requiresTotp: mfaRequired,
      ...(mfaRequired
        ? { preAuthToken: this.createPreAuthToken(matchedUser.id, matchedUser.email, trustDevice) }
        : {}),
      trustDevice,
      serverTimeIso: new Date().toISOString(),
      totpPeriodSeconds: 30,
    };
  }

  public listUsers(): Array<Omit<PublicUserView, 'mfaVerified'> & { createdAt: string; disabled: boolean }> {
    return this.db.users.map((u) => ({
      id: u.id,
      name: u.name,
      email: u.email,
      role: u.role,
      mfaEnabled: u.mfaEnabled,
      pinEnabled: Boolean(u.pinEnabled && u.pinHash),
      webauthnEnabled: Boolean(u.webauthnCredentials && u.webauthnCredentials.length > 0),
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
    const nextHash = hashPassword(params.newPassword);
    assertNoKdfDowngrade(null, nextHash);
    user.passwordHash = nextHash;
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

  public deleteOwnAccount(
    userId: string,
    verification?: {
      password?: string;
      pin?: string;
    }
  ): {
    deletedUserId: string;
    email: string;
    revokedSessionsCount: number;
  } {
    const userIndex = this.db.users.findIndex((u) => u.id === userId);
    if (userIndex === -1) {
      throw new Error('USER_NOT_FOUND: Conta de usuário não encontrada.');
    }
    const user = this.db.users[userIndex]!;
    const rawPassword = (verification?.password || '').trim();
    const rawPin = (verification?.pin || '').trim();
    const hasPin = Boolean(user.pinEnabled && user.pinHash);
    const hasWebAuthn = Boolean(user.webauthnCredentials && user.webauthnCredentials.length > 0);

    if (rawPin) {
      if (!hasPin || !user.pinHash || !verifyPassword(rawPin, user.pinHash)) {
        throw new Error('AUTH_INVALID_CREDENTIALS: PIN de confirmação inválido.');
      }
    } else if (rawPassword) {
      if (!verifyPassword(rawPassword, user.passwordHash)) {
        throw new Error('AUTH_INVALID_CREDENTIALS: Senha de confirmação inválida.');
      }
    } else if (!hasWebAuthn) {
      throw new Error(
        'VERIFICATION_REQUIRED: Confirme sua senha ou PIN atual para excluir permanentemente sua conta.'
      );
    }

    let revokedSessionsCount = 0;
    for (const s of this.db.sessions) {
      if (s.userId === userId && !s.revoked) {
        s.revoked = true;
        revokedSessionsCount += 1;
      }
    }
    this.db.sessions = this.db.sessions.filter((s) => s.userId !== userId);
    this.db.users.splice(userIndex, 1);

    // Clean up any local recovery file if present
    try {
      const recPath = path.join(this.recoveryDir, `recovery_${user.id}.txt`);
      if (fs.existsSync(recPath)) {
        fs.unlinkSync(recPath);
      }
    } catch {
      // Best-effort cleanup
    }

    this.save();
    return {
      deletedUserId: user.id,
      email: user.email,
      revokedSessionsCount,
    };
  }

  public issueSoloLocalDesktopSession(params?: {
    operatorName?: string;
    ipAddress?: string;
    userAgent?: string;
  }): {
    user: PublicUserView;
    sessionId: string;
    csrfToken: string;
    trustDevice: boolean;
  } {
    const localEmail = 'solo-local@winhood.local';
    const now = new Date().toISOString();
    let user = this.db.users.find((u) => u.email === localEmail);
    if (!user) {
      const isFirstUser = this.db.users.length === 0;
      const cleanName = (params?.operatorName || process.env.USERNAME || process.env.USER || 'Operador Local')
        .replace(/[\r\n\0]/g, ' ')
        .trim()
        .slice(0, 80) || 'Operador Local';
      user = {
        id: `usr-local-${crypto.randomUUID().slice(0, 8)}`,
        name: cleanName,
        email: localEmail,
        role: 'ADMIN',
        passwordHash: hashPassword(`wh-solo-local-${crypto.randomBytes(24).toString('base64url')}`),
        pinHash: null,
        pinEnabled: false,
        webauthnCredentials: [],
        mfaEnabled: false,
        totpSecretBase32: null,
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
      if (isFirstUser) {
        this.completeBootstrapOnFirstAccount(now);
      }
    } else if (user.disabled) {
      throw new Error('AUTH_ACCOUNT_DISABLED: Conta local desabilitada pelo administrador.');
    }

    const { sessionId, session } = this.createSessionRecord(
      user,
      true,
      params?.ipAddress || '127.0.0.1',
      params?.userAgent || 'WinHood-Electron-Desktop',
      { trustDevice: true }
    );
    this.save();
    return {
      user: this.toPublicUserView(user, true),
      sessionId,
      csrfToken: session.csrfToken,
      trustDevice: true,
    };
  }

  public issueGitHubOAuthSession(params: {
    githubId?: number;
    githubLogin: string;
    name?: string;
    email?: string;
    avatarUrl?: string | null;
    ipAddress?: string;
    userAgent?: string;
  }): {
    user: PublicUserView;
    sessionId: string;
    csrfToken: string;
    trustDevice: boolean;
    isNewAccount: boolean;
  } {
    const cleanLogin = (params.githubLogin || '').trim().replace(/[^a-zA-Z0-9._-]/g, '');
    if (!cleanLogin) {
      throw new Error('GITHUB_PROFILE_INVALID: Login GitHub ausente na resposta OAuth.');
    }
    const fallbackNoreply =
      typeof params.githubId === 'number'
        ? `${params.githubId}+${cleanLogin}@users.noreply.github.com`
        : `${cleanLogin}@users.noreply.github.com`;
    const candidateEmail = (params.email || fallbackNoreply).trim().toLowerCase();
    const resolvedEmail = isValidEmailAddress(candidateEmail) ? candidateEmail : fallbackNoreply;
    const cleanName =
      (params.name || cleanLogin).replace(/[\r\n\0]/g, ' ').trim().slice(0, 80) || cleanLogin;
    const now = new Date().toISOString();

    let user =
      (typeof params.githubId === 'number'
        ? this.db.users.find((u) => u.githubId === params.githubId)
        : undefined) ||
      this.db.users.find((u) => u.githubLogin?.toLowerCase() === cleanLogin.toLowerCase()) ||
      this.db.users.find((u) => u.email === resolvedEmail);

    let isNewAccount = false;
    if (!user) {
      isNewAccount = true;
      const isFirstUser = this.db.users.length === 0;
      user = {
        id: `usr-gh-${crypto.randomUUID().slice(0, 8)}`,
        name: cleanName,
        email: resolvedEmail,
        role: isFirstUser ? 'ADMIN' : 'SECURITY_LEAD',
        passwordHash: hashPassword(`wh-gh-oauth-${crypto.randomBytes(24).toString('base64url')}`),
        pinHash: null,
        pinEnabled: false,
        webauthnCredentials: [],
        githubId: typeof params.githubId === 'number' ? params.githubId : null,
        githubLogin: cleanLogin,
        githubAvatarUrl: params.avatarUrl || null,
        authProviders: ['github'],
        mfaEnabled: false,
        totpSecretBase32: null,
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
      if (isFirstUser) {
        this.completeBootstrapOnFirstAccount(now);
      }
    } else if (user.disabled) {
      throw new Error('AUTH_ACCOUNT_DISABLED: Conta desabilitada pelo administrador.');
    } else {
      if (typeof params.githubId === 'number') {
        user.githubId = params.githubId;
      }
      user.githubLogin = cleanLogin;
      if (params.avatarUrl) {
        user.githubAvatarUrl = params.avatarUrl;
      }
      const providers = new Set<AuthProviderKind>(user.authProviders || []);
      providers.add('github');
      user.authProviders = Array.from(providers);
      user.updatedAt = now;
    }

    const { sessionId, session } = this.createSessionRecord(
      user,
      true,
      params.ipAddress || '127.0.0.1',
      params.userAgent || 'WinHood-GitHub-OAuth',
      { trustDevice: true }
    );
    this.save();
    return {
      user: this.toPublicUserView(user, true),
      sessionId,
      csrfToken: session.csrfToken,
      trustDevice: true,
      isNewAccount,
    };
  }

  public linkGitHubAccountToUser(
    userId: string,
    params: { githubId: number; githubLogin: string; avatarUrl?: string | null }
  ): PublicUserView {
    const user = this.db.users.find((u) => u.id === userId && !u.disabled);
    if (!user) {
      throw new Error('USER_NOT_FOUND: Usuário não encontrado.');
    }
    const cleanLogin = (params.githubLogin || '').trim().replace(/[^a-zA-Z0-9._-]/g, '');
    if (!cleanLogin) {
      throw new Error('GITHUB_PROFILE_INVALID: Login GitHub inválido.');
    }
    const conflictingUser = this.db.users.find(
      (u) => u.id !== userId && (u.githubId === params.githubId || u.githubLogin?.toLowerCase() === cleanLogin.toLowerCase())
    );
    if (conflictingUser) {
      throw new Error('GITHUB_ALREADY_LINKED: Esta conta GitHub já está vinculada a outro usuário.');
    }
    user.githubId = params.githubId;
    user.githubLogin = cleanLogin;
    if (params.avatarUrl) {
      user.githubAvatarUrl = params.avatarUrl;
    }
    const providers = new Set<AuthProviderKind>(user.authProviders || []);
    providers.add('github');
    user.authProviders = Array.from(providers);
    user.updatedAt = new Date().toISOString();
    this.save();
    return this.toPublicUserView(user, true);
  }

  public static hasPermission(role: RbacRole, permission: RbacPermission): boolean {
    return PERMISSIONS_MATRIX[role]?.has(permission) ?? false;
  }
}
