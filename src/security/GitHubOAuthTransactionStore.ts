import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { KeyManagementService } from './KeyManagementService';
import type { PublicUserView } from './AuthService';

export interface PersistedGitHubOAuthTx {
  state: string;
  codeVerifier: string;
  redirectUri: string;
  mode: 'popup' | 'redirect' | 'desktop';
  originHint: string;
  expiresAtMs: number;
  status: 'PENDING' | 'AUTHORIZED' | 'ERROR';
  consumed: boolean;
  stateCookieRequired: boolean;
  errorMessage?: string;
  sessionId?: string;
  csrfToken?: string;
  user?: PublicUserView;
  isNewAccount?: boolean;
}

interface StoredEncryptedTx {
  state: string;
  codeVerifierEnc: string;
  redirectUri: string;
  mode: 'popup' | 'redirect' | 'desktop';
  originHint: string;
  expiresAtMs: number;
  status: 'PENDING' | 'AUTHORIZED' | 'ERROR';
  consumed: boolean;
  stateCookieRequired: boolean;
  errorMessage?: string;
  sessionIdEnc?: string;
  csrfTokenEnc?: string;
  user?: PublicUserView;
  isNewAccount?: boolean;
}

interface OAuthTxStoreFile {
  schemaVersion: 1;
  updatedAt: string;
  transactions: Record<string, StoredEncryptedTx>;
  consumedCodeHashes: Record<string, number>;
}

const DEFAULT_CODE_REPLAY_TTL_MS = 15 * 60 * 1000;

function sha256Hex(raw: string): string {
  return crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
}

/**
 * Armazenamento persistente e atômico de transações GitHub OAuth 2.0 + PKCE S256.
 * - Persiste estado pendente e hashes de authorization codes já consumidos em disco (chmod 0600).
 * - Nunca persiste authorization codes em texto claro (apenas SHA-256) e cifra codeVerifier/tokens em repouso.
 * - Compatível com reinicializações e múltiplas instâncias compartilhando o mesmo diretório de dados.
 */
export class GitHubOAuthTransactionStore {
  private readonly storeFilePath: string;
  private readonly keystorePath: string;

  constructor(dataDir: string) {
    this.storeFilePath = path.join(dataDir, 'security', 'github_oauth_transactions.json');
    this.keystorePath = path.join(dataDir, 'keys', 'keystore.json');
  }

  private encryptValue(plain: string): string {
    const { keyId, keyBuffer } = KeyManagementService.getActiveVaultAesKey(this.keystorePath);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
    const encrypted = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `whoauth:v1:${keyId}:${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  private decryptValue(stored?: string): string | undefined {
    if (!stored) return undefined;
    if (!stored.startsWith('whoauth:v1:')) return stored;
    const parts = stored.split(':');
    if (parts.length !== 6) return undefined;
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

  private readStore(): OAuthTxStoreFile {
    const empty: OAuthTxStoreFile = {
      schemaVersion: 1,
      updatedAt: new Date().toISOString(),
      transactions: {},
      consumedCodeHashes: {},
    };
    try {
      if (!fs.existsSync(this.storeFilePath)) return empty;
      const raw = fs.readFileSync(this.storeFilePath, 'utf8');
      const parsed = JSON.parse(raw) as Partial<OAuthTxStoreFile>;
      return {
        schemaVersion: 1,
        updatedAt: parsed.updatedAt || new Date().toISOString(),
        transactions:
          parsed.transactions && typeof parsed.transactions === 'object' ? parsed.transactions : {},
        consumedCodeHashes:
          parsed.consumedCodeHashes && typeof parsed.consumedCodeHashes === 'object'
            ? parsed.consumedCodeHashes
            : {},
      };
    } catch {
      return empty;
    }
  }

  private writeStoreAtomic(data: OAuthTxStoreFile): void {
    const dir = path.dirname(this.storeFilePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    data.updatedAt = new Date().toISOString();
    const tmpPath = `${this.storeFilePath}.tmp.${process.pid}.${crypto.randomBytes(4).toString('hex')}`;
    fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmpPath, this.storeFilePath);
    try {
      fs.chmodSync(this.storeFilePath, 0o600);
    } catch {
      // Windows chmod is partial
    }
  }

  private pruneInPlace(store: OAuthTxStoreFile, nowMs = Date.now()): boolean {
    let changed = false;
    for (const [key, tx] of Object.entries(store.transactions)) {
      if (!tx || typeof tx.expiresAtMs !== 'number' || nowMs > tx.expiresAtMs) {
        delete store.transactions[key];
        changed = true;
      }
    }
    for (const [codeHash, expMs] of Object.entries(store.consumedCodeHashes)) {
      if (typeof expMs !== 'number' || nowMs > expMs) {
        delete store.consumedCodeHashes[codeHash];
        changed = true;
      }
    }
    return changed;
  }

  private toRuntimeTx(stored: StoredEncryptedTx): PersistedGitHubOAuthTx | undefined {
    try {
      const codeVerifier = this.decryptValue(stored.codeVerifierEnc);
      if (!codeVerifier) return undefined;
      return {
        state: stored.state,
        codeVerifier,
        redirectUri: stored.redirectUri,
        mode: stored.mode,
        originHint: stored.originHint,
        expiresAtMs: stored.expiresAtMs,
        status: stored.status,
        consumed: stored.consumed,
        stateCookieRequired: stored.stateCookieRequired,
        errorMessage: stored.errorMessage,
        sessionId: this.decryptValue(stored.sessionIdEnc),
        csrfToken: this.decryptValue(stored.csrfTokenEnc),
        user: stored.user,
        isNewAccount: stored.isNewAccount,
      };
    } catch {
      return undefined;
    }
  }

  private toStoredTx(tx: PersistedGitHubOAuthTx): StoredEncryptedTx {
    return {
      state: tx.state,
      codeVerifierEnc: this.encryptValue(tx.codeVerifier),
      redirectUri: tx.redirectUri,
      mode: tx.mode,
      originHint: tx.originHint,
      expiresAtMs: tx.expiresAtMs,
      status: tx.status,
      consumed: tx.consumed,
      stateCookieRequired: tx.stateCookieRequired,
      errorMessage: tx.errorMessage,
      sessionIdEnc: tx.sessionId ? this.encryptValue(tx.sessionId) : undefined,
      csrfTokenEnc: tx.csrfToken ? this.encryptValue(tx.csrfToken) : undefined,
      user: tx.user,
      isNewAccount: tx.isNewAccount,
    };
  }

  private findMatchingKeyTimingSafe(store: OAuthTxStoreFile, rawState: string): string | undefined {
    const providedBuf = Buffer.from(rawState, 'utf8');
    if (providedBuf.length === 0) return undefined;
    for (const key of Object.keys(store.transactions)) {
      const expectedBuf = Buffer.from(key, 'utf8');
      if (
        expectedBuf.length === providedBuf.length &&
        crypto.timingSafeEqual(expectedBuf, providedBuf)
      ) {
        return key;
      }
    }
    return undefined;
  }

  public pruneExpired(): void {
    const store = this.readStore();
    if (this.pruneInPlace(store)) {
      this.writeStoreAtomic(store);
    }
  }

  public saveTransaction(tx: PersistedGitHubOAuthTx): void {
    const store = this.readStore();
    this.pruneInPlace(store);
    store.transactions[tx.state] = this.toStoredTx(tx);
    this.writeStoreAtomic(store);
  }

  public getTransactionByState(rawState: string): PersistedGitHubOAuthTx | undefined {
    const store = this.readStore();
    const pruned = this.pruneInPlace(store);
    const matchedKey = this.findMatchingKeyTimingSafe(store, rawState);
    if (pruned) {
      this.writeStoreAtomic(store);
    }
    if (!matchedKey) return undefined;
    const stored = store.transactions[matchedKey];
    return stored ? this.toRuntimeTx(stored) : undefined;
  }

  /**
   * Consome de forma atômica e síncrona o par (state, code) antes de qualquer I/O externo.
   * Bloqueia replay de state ou authorization code mesmo após reinicialização do processo.
   */
  public consumeTransactionAtomically(
    rawState: string,
    rawCode: string,
    codeReplayTtlMs = DEFAULT_CODE_REPLAY_TTL_MS
  ):
    | { ok: true; tx: PersistedGitHubOAuthTx }
    | { ok: false; reason: 'INVALID_STATE' | 'REPLAYED_CODE'; tx?: PersistedGitHubOAuthTx } {
    const store = this.readStore();
    const now = Date.now();
    this.pruneInPlace(store, now);

    const matchedKey = this.findMatchingKeyTimingSafe(store, rawState);
    if (!matchedKey) {
      this.writeStoreAtomic(store);
      return { ok: false, reason: 'INVALID_STATE' };
    }
    const stored = store.transactions[matchedKey];
    if (!stored || now > stored.expiresAtMs) {
      delete store.transactions[matchedKey];
      this.writeStoreAtomic(store);
      return { ok: false, reason: 'INVALID_STATE' };
    }

    const codeHash = sha256Hex(rawCode);
    const runtimeTx = this.toRuntimeTx(stored);
    if (!runtimeTx) {
      delete store.transactions[matchedKey];
      this.writeStoreAtomic(store);
      return { ok: false, reason: 'INVALID_STATE' };
    }

    if (stored.consumed || Boolean(store.consumedCodeHashes[codeHash])) {
      delete store.transactions[matchedKey];
      this.writeStoreAtomic(store);
      return { ok: false, reason: 'REPLAYED_CODE', tx: runtimeTx };
    }

    stored.consumed = true;
    store.consumedCodeHashes[codeHash] = now + codeReplayTtlMs;
    this.writeStoreAtomic(store);
    runtimeTx.consumed = true;
    return { ok: true, tx: runtimeTx };
  }

  public updateTransaction(
    rawState: string,
    patch: Partial<Omit<PersistedGitHubOAuthTx, 'state' | 'codeVerifier'>>
  ): void {
    const store = this.readStore();
    const matchedKey = this.findMatchingKeyTimingSafe(store, rawState);
    if (!matchedKey) return;
    const existing = store.transactions[matchedKey];
    if (!existing) return;
    const runtime = this.toRuntimeTx(existing);
    if (!runtime) return;
    const merged: PersistedGitHubOAuthTx = { ...runtime, ...patch };
    store.transactions[matchedKey] = this.toStoredTx(merged);
    this.writeStoreAtomic(store);
  }

  public deleteTransaction(rawState: string): void {
    const store = this.readStore();
    const matchedKey = this.findMatchingKeyTimingSafe(store, rawState);
    if (!matchedKey) return;
    delete store.transactions[matchedKey];
    this.writeStoreAtomic(store);
  }
}
