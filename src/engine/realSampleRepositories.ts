export const VAULTCORE_INTERNAL_FILES: Record<string, string> = {
  'package.json': JSON.stringify(
    {
      name: 'vaultcore-internal- enterprise',
      version: '2.4.0',
      description: 'Cofre corporativo de senhas desenvolvido internamente para estações Windows e Web',
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

export function queryVaultEntriesRaw(searchTerm: string, callerHash: string) {
  const sqlQuery = "SELECT * FROM vault_entries WHERE title = '" + searchTerm + "' AND owner_hash = '" + callerHash + "'";
  return { sqlQuery };
}

export function exportDiagnosticArchive(targetFile: string) {
  // TODO: remover chamada direta ao shell do sistema operacional
  return execSync(\`tar -czf /tmp/backup_\${targetFile}.tar.gz /var/vault\`);
}
`,
  'src/db/schema.sql': `-- Schema do Cofre Interno VaultCore v2.4.0
CREATE TABLE vault_entries (
  id TEXT PRIMARY KEY,
  folder_id TEXT NOT NULL,
  title TEXT NOT NULL,
  username TEXT NOT NULL,
  password_plain TEXT NOT NULL,
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

SELECT * FROM vault_entries;
`,
  'tests/vault.spec.ts': `// Suite básica de verificação de cofre
export function testUnlock() {
  return true;
}
`,
};

export const KEESAFE_OPEN_FILES: Record<string, string> = {
  'package.json': JSON.stringify(
    {
      name: 'keesafe-open-kdbx',
      version: '2.56.0',
      description: 'Gerenciador e cofre de senhas open-source compatível com KDBX 4.1 (Argon2id + AES-256-GCM)',
      main: 'src/index.ts',
      dependencies: {
        argon2: '0.41.1',
        zod: '3.23.8',
      },
    },
    null,
    2
  ),
  'README.md': `# KeeSafe Open (KeePass KDBX 4.1 Architecture) v2.56.0
Arquitetura de segurança zero-knowledge para armazenamento local e sincronizado de credenciais críticas.
- Derivação de chave: Argon2id / PBKDF2-HMAC-SHA512
- Cifra autenticada: AES-256-GCM e ChaCha20-Poly1305
- Proteção de memória e limpeza determinística de buffers
- Trilha de auditoria append-only verificada por SHA-256`,
  'src/domain/kdfEngine.ts': `import crypto from 'node:crypto';

export interface KdfParams {
  iterations: number;
  memoryKiB: number;
  parallelism: number;
}

export function deriveVaultKeyPbkdf2(masterSecret: Buffer, salt: Buffer, iterations = 600000): Buffer {
  if (salt.length < 32) {
    throw new Error('Salt criptográfico deve possuir no mínimo 256 bits.');
  }
  return crypto.pbkdf2Sync(masterSecret, salt, iterations, 32, 'sha512');
}

export function encryptEntryAes256Gcm(plaintext: Buffer, key: Buffer): {
  iv: string;
  ciphertext: string;
  authTag: string;
} {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString('hex'),
    ciphertext: encrypted.toString('hex'),
    authTag: authTag.toString('hex'),
  };
}
`,
  'src/service/vaultApplicationService.ts': `import { deriveVaultKeyPbkdf2, encryptEntryAes256Gcm } from '../domain/kdfEngine';
import { saveEncryptedRecord, findRecordById } from '../db/kdbxStorageRepo';

export function storeCredentialUseCase(params: {
  id: string;
  title: string;
  secretPayload: string;
  masterSecret: Buffer;
  salt: Buffer;
}) {
  const key = deriveVaultKeyPbkdf2(params.masterSecret, params.salt, 600000);
  const envelope = encryptEntryAes256Gcm(Buffer.from(params.secretPayload, 'utf8'), key);
  const auditTrail = {
    action: 'RECORD_STORED_AES_256_GCM',
    timestamp: new Date().toISOString(),
    appendOnly: true,
  };
  return saveEncryptedRecord({
    id: params.id,
    title: params.title,
    cipherEnvelope: JSON.stringify(envelope),
    auditTrail,
  });
}

export function readCredentialMetadataUseCase(recordId: string) {
  return findRecordById(recordId);
}
`,
  'src/ui/unlockViewController.ts': `import { readCredentialMetadataUseCase } from '../service/vaultApplicationService';

export function handleInspectRecord(recordId: string) {
  if (!recordId || recordId.trim().length === 0) {
    throw new Error('Identificador de registro obrigatório.');
  }
  return readCredentialMetadataUseCase(recordId.trim());
}
`,
  'src/db/kdbxStorageRepo.ts': `export interface EncryptedRecordRow {
  id: string;
  title: string;
  cipherEnvelope: string;
  auditTrail: { action: string; timestamp: string; appendOnly: boolean };
}

const memoryStore = new Map<string, EncryptedRecordRow>();

export function saveEncryptedRecord(row: EncryptedRecordRow): EncryptedRecordRow {
  memoryStore.set(row.id, row);
  return row;
}

export function findRecordById(id: string): EncryptedRecordRow | undefined {
  return memoryStore.get(id);
}
`,
  'src/db/schema.sql': `-- Schema Normalizado KDBX 4.1 com Criptografia Autenticada
CREATE TABLE encrypted_vault_records (
  id UUID PRIMARY KEY NOT NULL,
  vault_id UUID NOT NULL,
  title_hmac VARCHAR(128) NOT NULL,
  cipher_envelope_aes256gcm TEXT NOT NULL,
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
};

export const DEMO_FIXTURE_METADATA = {
  dataOrigin: 'DEMO_FIXTURE' as const,
  executionMode: 'DEMONSTRATION' as const,
  isDemoOnly: true,
  description: 'Fixtures demonstrativas de repositórios para validação offline e modo demonstração.',
};
