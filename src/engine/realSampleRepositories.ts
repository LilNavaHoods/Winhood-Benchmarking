export const VAULTCORE_INTERNAL_FILES: Record<string, string> = {
  'package.json': JSON.stringify(
    {
      name: 'vaultcore-internal-enterprise',
      version: '2.5.0',
      description:
        'Cofre corporativo de senhas remediado com KDF PBKDF2-SHA512 (600k iterações), cifra autenticada AES-256-GCM e trilha de auditoria append-only',
      main: 'src/domain/cryptoVault.ts',
      dependencies: {
        jsonwebtoken: '9.0.2',
        sqlite3: '5.1.7',
      },
    },
    null,
    2
  ),
  'README.md': `# VaultCore Internal v2.5.0 (Remediated Enterprise Edition)
Cofre corporativo de senhas auditado para estações Windows 11 e servidores Linux.
- Derivação de chave criptográfica: PBKDF2-HMAC-SHA512 com 600.000 iterações e salt CSPRNG de 256 bits.
- Cifragem autenticada em repouso: AES-256-GCM com verificação obrigatória de Authentication Tag (128 bits).
- Persistência parametrizada (Prepared Statements) e trilha de auditoria imutável append-only assinada por SHA-256.
- Plano de Recuperação de Desastres (DRP): snapshots criptografados verificados sem artefatos residuais em disco.`,
  'src/domain/cryptoVault.ts': `import crypto from 'node:crypto';
import { saveEncryptedVaultEntry, queryVaultEntryById, appendVaultAuditRecord } from '../db/vaultRepository';

export interface SealedVaultPayload {
  ciphertextHex: string;
  ivHex: string;
  authTagHex: string;
  saltHex: string;
}

export function deriveMasterVaultKey(password: string, salt: Buffer, iterations = 600000): Buffer {
  if (iterations < 600000) {
    throw new Error('Política criptográfica exige no mínimo 600.000 iterações PBKDF2-SHA512.');
  }
  return crypto.pbkdf2Sync(Buffer.from(password, 'utf8'), salt, iterations, 32, 'sha512');
}

export function sealCredentialPayload(plaintext: string, masterPassword: string): SealedVaultPayload {
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const key = deriveMasterVaultKey(masterPassword, salt, 600000);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertextHex: encrypted.toString('hex'),
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
    saltHex: salt.toString('hex'),
  };
}

export function generateUnlockToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function registerAndFindVaultCredential(id: string, title: string, secret: string, masterPassword: string) {
  const sealed = sealCredentialPayload(secret, masterPassword);
  saveEncryptedVaultEntry({
    id,
    title,
    ciphertextHex: sealed.ciphertextHex,
    ivHex: sealed.ivHex,
    authTagHex: sealed.authTagHex,
    kdfSaltHex: sealed.saltHex,
  });
  appendVaultAuditRecord(id, 'VAULT_ENTRY_SEALED');
  return queryVaultEntryById(id);
}
`,
  'src/ui/vaultController.ts': `import { generateUnlockToken, registerAndFindVaultCredential } from '../domain/cryptoVault';

export interface SessionStateResult {
  active: boolean;
  token: string;
  issuedAt: string;
}

export function syncSessionState(token: string): SessionStateResult | null {
  try {
    if (!token || token.trim().length < 32) {
      return null;
    }
    return {
      active: true,
      token,
      issuedAt: new Date().toISOString(),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Erro inesperado na validação de sessão';
    throw new Error(\`Falha controlada ao sincronizar sessão: \${message}\`);
  }
}

export function searchCredentialsController(entryId: string, title: string, secret: string, masterPassword: string) {
  const sessionToken = generateUnlockToken();
  const session = syncSessionState(sessionToken);
  if (!session) {
    throw new Error('Sessão inválida para operação no cofre.');
  }
  return registerAndFindVaultCredential(entryId, title, secret, masterPassword);
}
`,
  'src/db/vaultRepository.ts': `import crypto from 'node:crypto';

export interface VaultEncryptedRow {
  id: string;
  title: string;
  ciphertextHex: string;
  ivHex: string;
  authTagHex: string;
  kdfSaltHex: string;
}

const preparedStore = new Map<string, VaultEncryptedRow>();
const auditLogStore: Array<{ id: string; action: string; timestamp: string; appendOnly: true; digest: string }> = [];

export function saveEncryptedVaultEntry(row: VaultEncryptedRow): { sql: string; params: string[] } {
  const parameterizedSql =
    'INSERT INTO vault_entries (id, title, ciphertext_hex, iv_hex, auth_tag_hex, kdf_salt_hex) VALUES (?, ?, ?, ?, ?, ?)';
  preparedStore.set(row.id, row);
  return {
    sql: parameterizedSql,
    params: [row.id, row.title, row.ciphertextHex, row.ivHex, row.authTagHex, row.kdfSaltHex],
  };
}

export function queryVaultEntryById(entryId: string): VaultEncryptedRow | null {
  const parameterizedQuery =
    'SELECT id, title, ciphertext_hex, iv_hex, auth_tag_hex, kdf_salt_hex FROM vault_entries WHERE id = ?';
  if (!parameterizedQuery.includes('?')) {
    throw new Error('Prepared statement obrigatório.');
  }
  return preparedStore.get(entryId) || null;
}

export function appendVaultAuditRecord(entryId: string, action: string) {
  const timestamp = new Date().toISOString();
  const digest = crypto.createHash('sha256').update(\`\${entryId}|\${action}|\${timestamp}\`).digest('hex');
  const entry = { id: entryId, action, timestamp, appendOnly: true as const, digest };
  auditLogStore.push(entry);
  return entry;
}
`,
  'src/db/schema.sql': `CREATE TABLE vault_entries (
  id VARCHAR(64) PRIMARY KEY NOT NULL,
  title VARCHAR(180) NOT NULL,
  ciphertext_hex TEXT NOT NULL,
  iv_hex CHAR(24) NOT NULL,
  auth_tag_hex CHAR(32) NOT NULL,
  kdf_salt_hex CHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_vault_entries_title ON vault_entries(title);
`,
  'tests/vault.spec.ts': `import { deriveMasterVaultKey, sealCredentialPayload, generateUnlockToken, registerAndFindVaultCredential } from '../src/domain/cryptoVault';
import { searchCredentialsController, syncSessionState } from '../src/ui/vaultController';
import crypto from 'node:crypto';

export function testVaultKdfAndEncryption(): boolean {
  const salt = crypto.randomBytes(32);
  const key = deriveMasterVaultKey('StrongCorpPassphrase#2026', salt, 600000);
  const sealed = sealCredentialPayload('secret-db-token', 'StrongCorpPassphrase#2026');
  const token = generateUnlockToken();
  const session = syncSessionState(token);
  const record = searchCredentialsController('id-01', 'Prod DB', 'secret-db-token', 'StrongCorpPassphrase#2026');
  const directRecord = registerAndFindVaultCredential('id-02', 'Backup Key', 'payload', 'StrongCorpPassphrase#2026');
  return Boolean(
    key.length === 32 &&
      sealed.authTagHex.length === 32 &&
      session?.active &&
      record?.id === 'id-01' &&
      directRecord?.id === 'id-02'
  );
}
`,
};

/**
 * Snapshot legado com vulnerabilidades reais (SQLi, RCE execSync, Hardcoded Master Key,
 * MD5, Math.random, Empty Catch, Ciclo de Dependência e Violação de Camada UI->DB)
 * preservado para testes determinísticos de regressão SAST/SCA/Secrets e Penalty Caps.
 */
export const LEGACY_VULNERABLE_VAULT_FILES: Record<string, string> = {
  'package.json': JSON.stringify(
    {
      name: 'vaultcore-legacy-vulnerable',
      version: '2.4.0',
      description: 'Cofre corporativo legado com vulnerabilidades para bateria de regressão SAST',
      main: 'src/index.ts',
      dependencies: {
        'crypto-js': '4.1.1',
        jsonwebtoken: '8.5.1',
        sqlite3: '5.1.7',
      },
    },
    null,
    2
  ),
  'README.md': `# VaultCore Internal v2.4.0
Cofre de senhas interno corporativo.
Nota: Documentação de recuperação de desastres ainda em revisão.`,
  'src/domain/cryptoVault.ts': `import crypto from 'node:crypto';
import { syncSessionState } from '../ui/vaultController';

// Chave mestra legado de fallback em contingência
const masterKey = "VC_PROD_MASTER_99481029384756_SECRET";

export function hashMasterPassword(password: string): string {
  // FIXME: migrar de MD5 para Argon2id na próxima sprint
  return crypto.createHash('md5').update(password + masterKey).digest('hex');
}

export function generateUnlockToken(): string {
  const nonce = Math.random().toString(36).substring(2);
  syncSessionState(nonce);
  return nonce;
}
`,
  'src/ui/vaultController.ts': `import { hashMasterPassword } from '../domain/cryptoVault';
import { queryVaultEntriesRaw } from '../db/vaultRepository';

export function syncSessionState(token: any): any {
  try {
    if (!token) return null;
    return { active: true, token };
  } catch (err) {}
}

export function searchCredentialsController(userInput: string): any {
  // Acesso direto da camada UI ao banco sem passar por Application Service
  const hashed = hashMasterPassword(userInput);
  return queryVaultEntriesRaw(userInput, hashed);
}
`,
  'src/db/vaultRepository.ts': `import { execSync } from 'node:child_process';

export function queryVaultEntriesRaw(titleFilter: string, userHash: string) {
  const sql = "SELECT * FROM vault_entries WHERE title = '" + titleFilter + "' AND owner_hash = '" + userHash + "'";
  return { sql, executed: true };
}

export function exportDiagnosticDump(targetPath: string) {
  // TODO: validar caminho antes de chamar shell
  return execSync(\`tar -czf \${targetPath} ./vault_data\`);
}
`,
  'src/db/schema.sql': `CREATE TABLE vault_entries (
  id INTEGER PRIMARY KEY,
  title TEXT,
  username TEXT,
  password_plain TEXT,
  owner_hash TEXT,
  created_at DATETIME
);

-- Consulta padrão de auditoria interna
SELECT * FROM vault_entries;
`,
  'tests/vault.spec.ts': `import { generateUnlockToken } from '../src/domain/cryptoVault';
export const smokeTest = () => Boolean(generateUnlockToken());
`,
};

export const KEESAFE_OPEN_FILES: Record<string, string> = {
  'package.json': JSON.stringify(
    {
      name: 'keesafe-open-kdbx',
      version: '2.56.0',
      description: 'Implementação auditável compatível com KDBX 4.1 usando AES-256-GCM e PBKDF2-SHA512',
      main: 'src/index.ts',
      dependencies: {
        sqlite3: '5.1.7',
      },
    },
    null,
    2
  ),
  'README.md': `# KeeSafe Open (KDBX 4.1 Reference) v2.56.0
Arquitetura modular Zero-Knowledge para gerenciamento seguro de credenciais corporativas e chaves SSH.
- Derivação de chave: PBKDF2-HMAC-SHA512 (600.000 iterações) / Argon2id.
- Cifragem autenticada em repouso: AES-256-GCM com verificação de tag de autenticação de 128 bits.
- Trilha de auditoria append-only assinada criptograficamente com SHA-256.
- Desinstalação limpa verificada sem resíduos em registro ou diretórios temporários.`,
  'src/domain/kdfEngine.ts': `import crypto from 'node:crypto';

export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  authTag: string;
  salt: string;
}

export function deriveVaultKeyPbkdf2(masterSecret: Buffer, salt: Buffer, iterations = 600000): Buffer {
  if (iterations < 10000) {
    throw new Error('Iterações insuficientes para derivação segura.');
  }
  return crypto.pbkdf2Sync(masterSecret, salt, iterations, 32, 'sha512');
}

export function encryptEntryAes256Gcm(plaintext: Buffer, key: Buffer): EncryptedPayload {
  const iv = crypto.randomBytes(12);
  const salt = crypto.randomBytes(32);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    ciphertext: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    salt: salt.toString('hex'),
  };
}
`,
  'src/service/vaultApplicationService.ts': `import crypto from 'node:crypto';
import { deriveVaultKeyPbkdf2, encryptEntryAes256Gcm } from '../domain/kdfEngine';
import { saveEncryptedRecordPrepared, findRecordByIdPrepared } from '../db/kdbxStorageRepo';

export interface AuditRecord {
  eventId: string;
  timestamp: string;
  action: string;
  recordId: string;
  integrityHash: string;
}

export function storeCredentialUseCase(params: {
  id: string;
  title: string;
  secretPayload: string;
  masterSecret: Buffer;
  salt: Buffer;
}): AuditRecord {
  const derivedKey = deriveVaultKeyPbkdf2(params.masterSecret, params.salt, 600000);
  const encrypted = encryptEntryAes256Gcm(Buffer.from(params.secretPayload, 'utf8'), derivedKey);

  saveEncryptedRecordPrepared({
    id: params.id,
    title: params.title,
    ciphertextHex: encrypted.ciphertext,
    ivHex: encrypted.iv,
    authTagHex: encrypted.authTag,
  });

  const timestamp = new Date().toISOString();
  const integrityHash = crypto
    .createHash('sha256')
    .update(\`\${params.id}|\${timestamp}|\${encrypted.authTag}\`)
    .digest('hex');

  return {
    eventId: crypto.randomBytes(16).toString('hex'),
    timestamp,
    action: 'CREDENTIAL_SEALED_AES256GCM',
    recordId: params.id,
    integrityHash,
  };
}

export function readCredentialMetadataUseCase(recordId: string) {
  return findRecordByIdPrepared(recordId);
}
`,
  'src/ui/unlockViewController.ts': `import { readCredentialMetadataUseCase } from '../service/vaultApplicationService';

export function handleRecordLookupRequest(recordId: string) {
  if (!recordId || recordId.trim().length === 0) {
    throw new Error('Identificador de registro obrigatório.');
  }
  return readCredentialMetadataUseCase(recordId.trim());
}
`,
  'src/db/kdbxStorageRepo.ts': `export interface StoredKdbxRow {
  id: string;
  title: string;
  ciphertextHex: string;
  ivHex: string;
  authTagHex: string;
}

const memoryStore = new Map<string, StoredKdbxRow>();

export function saveEncryptedRecordPrepared(row: StoredKdbxRow): { parameterizedSql: string; boundParams: string[] } {
  const parameterizedSql =
    'INSERT INTO encrypted_vault_records (id, title, ciphertext_hex, iv_hex, auth_tag_hex) VALUES (?, ?, ?, ?, ?)';
  memoryStore.set(row.id, row);
  return {
    parameterizedSql,
    boundParams: [row.id, row.title, row.ciphertextHex, row.ivHex, row.authTagHex],
  };
}

export function findRecordByIdPrepared(id: string): StoredKdbxRow | null {
  return memoryStore.get(id) ?? null;
}
`,
  'src/db/schema.sql': `CREATE TABLE encrypted_vault_records (
  id VARCHAR(64) PRIMARY KEY NOT NULL,
  vault_id VARCHAR(64) NOT NULL,
  title VARCHAR(180) NOT NULL,
  ciphertext_hex TEXT NOT NULL,
  iv_hex CHAR(24) NOT NULL,
  auth_tag_hex CHAR(32) NOT NULL,
  kdf_salt_hex CHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_encrypted_vault_records_vault_id ON encrypted_vault_records(vault_id);
`,
  'tests/kdfEngine.test.ts': `import { deriveVaultKeyPbkdf2, encryptEntryAes256Gcm } from '../src/domain/kdfEngine';
import crypto from 'node:crypto';

export function verifyDeterministicDerivation() {
  const secret = Buffer.from('HighEntropyPassphrase#2026', 'utf8');
  const salt = crypto.randomBytes(32);
  const key = deriveVaultKeyPbkdf2(secret, salt, 10000);
  const sealed = encryptEntryAes256Gcm(Buffer.from('secret-entry'), key);
  return sealed.authTag.length === 32 && key.length === 32;
}
`,
  'tests/vaultService.test.ts': `import { storeCredentialUseCase, readCredentialMetadataUseCase } from '../src/service/vaultApplicationService';
import crypto from 'node:crypto';

export function verifyStoreAndReadUseCase() {
  const salt = crypto.randomBytes(32);
  const masterSecret = Buffer.from('TestMasterKey!9981', 'utf8');
  const saved = storeCredentialUseCase({
    id: 'rec-001',
    title: 'Production SSH Key',
    secretPayload: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5',
    masterSecret,
    salt,
  });
  const loaded = readCredentialMetadataUseCase('rec-001');
  return Boolean(saved && loaded && loaded.id === 'rec-001');
}
`,
  'coverage/lcov.info': `TN:keesafe-open-kdbx
SF:src/domain/kdfEngine.ts
LF:20
LH:19
BRF:4
BRH:4
end_of_record
SF:src/service/vaultApplicationService.ts
LF:24
LH:22
BRF:2
BRH:2
end_of_record
SF:src/ui/unlockViewController.ts
LF:8
LH:7
BRF:2
BRH:2
end_of_record
SF:src/db/kdbxStorageRepo.ts
LF:12
LH:12
BRF:2
BRH:2
end_of_record
`,
};

const ALL_12_ENABLED = [
  'functionality',
  'code_quality',
  'security',
  'performance',
  'architecture',
  'database',
  'reliability',
  'compatibility',
  'usability',
  'installation',
  'privacy',
  'documentation',
] as const;

const VAULTCORE_META = {
  domainTags: ['Segurança & Criptografia', 'Cofre Corporativo', 'Persistência SQL', 'Arquitetura Multi-Camada'],
  defaultQualityProfileIds: ['qp-sonar-way-ts', 'qp-sonar-way-sql'],
  defaultQualityGateId: 'qg-sonar-way',
  enabledCategories: [...ALL_12_ENABLED],
};

const KEESAFE_META = {
  domainTags: ['Segurança & Criptografia', 'Zero-Knowledge KDBX', 'AES-256-GCM & PBKDF2', 'Clean Architecture'],
  defaultQualityProfileIds: ['qp-sonar-way-ts', 'qp-sonar-way-sql'],
  defaultQualityGateId: 'qg-sonar-way',
  enabledCategories: [...ALL_12_ENABLED],
};

export const DEMO_FIXTURE_METADATA = {
  dataOrigin: 'DEMO_FIXTURE' as const,
  executionMode: 'DEMONSTRATION' as const,
  isDemoOnly: true,
  domainTags: VAULTCORE_META.domainTags,
  defaultQualityProfileIds: VAULTCORE_META.defaultQualityProfileIds,
  defaultQualityGateId: 'qg-sonar-way',
  enabledCategories: ALL_12_ENABLED,
  VAULTCORE: VAULTCORE_META,
  KEESAFE: KEESAFE_META,
  vaultCore: VAULTCORE_META,
  keeSafe: KEESAFE_META,
  description: 'Fixtures demonstrativas de repositórios para validação offline e modo demonstração transversal nas 12 categorias.',
};
