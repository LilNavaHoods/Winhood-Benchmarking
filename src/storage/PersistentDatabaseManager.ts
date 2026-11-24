import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { KeyManagementService } from '../security/KeyManagementService';

export interface PersistentReadOutcome<T> {
  data: T | null;
  recoveredFromBackup: boolean;
  storageKind: 'ATOMIC_CHECKSUMMED_JSON_STORE';
  integrityStatus: 'VERIFIED' | 'RECOVERED_FROM_BACKUP' | 'MISSING' | 'CORRUPTED';
  errorMessage?: string;
}

export interface StorageEncryptionInspectionReport {
  encryptedAtRest: boolean;
  algorithm: 'AES-256-GCM + ZLIB-DEFLATE';
  envelopeVersion: 'whdb:enc:v2';
  activeKeyId: string;
  keyStorageMode: string;
  totalSoftwareCount: number;
  encryptedSoftwareCount: number;
  plaintextFilesExposedOnDisk: number;
  sha256SidecarVerified: boolean;
  databaseSha256: string | null;
  verifiedAt: string;
}

function sha256Hex(raw: string): string {
  return crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
}

function fsyncAndRename(tmpPath: string, targetPath: string): void {
  const fd = fs.openSync(tmpPath, 'r+');
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmpPath, targetPath);
}

/**
 * PersistentDatabaseManager
 * Persistência atômica (temp + fsync + rename), checksum SHA-256 sidecar,
 * cifragem autenticada em repouso (AES-256-GCM + DEFLATE) dos mapas de código-fonte,
 * backup automático (.bak) e fila sequencial de escrita para winhood_persistent_db.json.
 */
export class PersistentDatabaseManager {
  public static readonly SCHEMA_VERSION = 5;
  public static readonly STORAGE_KIND = 'ATOMIC_CHECKSUMMED_JSON_STORE' as const;
  public static readonly ENVELOPE_PREFIX = 'whdb:enc:v2:';

  private readonly pendingQueues = new Map<string, Promise<void>>();

  /**
   * Comprime com DEFLATE e cifra um mapa de arquivos-fonte com AES-256-GCM autenticado.
   * Formato do envelope: whdb:enc:v2:<keyId>:<ivHex>:<authTagHex>:<cipherBase64>
   */
  public static encryptSourceFilesMap(filesMap: Record<string, string> | undefined | null): string {
    const safeMap = filesMap && typeof filesMap === 'object' ? filesMap : {};
    const rawJson = JSON.stringify(safeMap);
    const compressed = zlib.deflateSync(Buffer.from(rawJson, 'utf8'));
    const { keyId, keyBuffer } = KeyManagementService.getActiveVaultAesKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
    const encrypted = Buffer.concat([cipher.update(compressed), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return `${PersistentDatabaseManager.ENVELOPE_PREFIX}${keyId}:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('base64')}`;
  }

  /**
   * Decifra um envelope whdb:enc:v2:... (ou preserva objetos legados em claro durante migração).
   * Lança erro explícito e tipado em caso de falha de autenticação AES-256-GCM, chave inválida,
   * versão incompatível ou corrupção estrutural (nunca retorna {} silenciosamente em falha).
   */
  public static decryptSourceFilesMap(
    envelopeOrMap: string | Record<string, string> | undefined | null,
    explicitKeyBuffer?: Buffer
  ): Record<string, string> {
    if (envelopeOrMap === undefined || envelopeOrMap === null || envelopeOrMap === '') {
      return {};
    }
    if (typeof envelopeOrMap === 'object' && !Array.isArray(envelopeOrMap)) {
      return envelopeOrMap;
    }
    if (typeof envelopeOrMap !== 'string') {
      throw new Error('DECRYPTION_FORMAT_INVALID: Formato de sourceFilesMap inválido.');
    }

    if (envelopeOrMap.startsWith(PersistentDatabaseManager.ENVELOPE_PREFIX)) {
      const parts = envelopeOrMap.slice(PersistentDatabaseManager.ENVELOPE_PREFIX.length).split(':');
      if (parts.length !== 4) {
        throw new Error(
          'DECRYPTION_FORMAT_INVALID: Envelope criptográfico whdb:enc:v2 malformado ou truncado.'
        );
      }
      const [keyId, ivHex, authTagHex, cipherBase64] = parts;
      if (
        !keyId ||
        !/^[0-9a-fA-F]+$/.test(ivHex) ||
        !/^[0-9a-fA-F]+$/.test(authTagHex) ||
        !cipherBase64
      ) {
        throw new Error(
          'DECRYPTION_FORMAT_INVALID: Campos hexadecimais/base64 ausentes ou corrompidos no envelope whdb:enc:v2.'
        );
      }

      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');
      const ciphertext = Buffer.from(cipherBase64, 'base64');

      if (iv.length !== 12 || authTag.length !== 16) {
        throw new Error(
          `DECRYPTION_FORMAT_INVALID: Tamanho inválido de IV (${iv.length}B) ou AuthTag (${authTag.length}B) para AES-256-GCM.`
        );
      }

      const keyBuffer =
        explicitKeyBuffer ||
        KeyManagementService.getVaultKeyBufferByKeyId(keyId) ||
        KeyManagementService.getActiveVaultAesKey().keyBuffer;

      if (!keyBuffer || keyBuffer.length !== 32) {
        throw new Error(
          `DECRYPTION_KEY_MISSING: Chave AES-256-GCM (${keyId}) inválida ou indisponível no KMS.`
        );
      }

      let compressed: Buffer;
      try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
        decipher.setAuthTag(authTag);
        compressed = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      } catch (err: any) {
        throw new Error(
          `DECRYPTION_AUTH_FAILED: Falha de integridade ou autenticação AES-256-GCM (${err?.message || 'auth tag mismatch'}).`,
          { cause: err }
        );
      }

      let inflated: string;
      try {
        inflated = zlib.inflateSync(compressed).toString('utf8');
      } catch (err: any) {
        throw new Error(
          `DECRYPTION_PAYLOAD_CORRUPTED: Falha ao descomprimir payload zlib após decifragem (${err?.message || 'inflate error'}).`,
          { cause: err }
        );
      }

      try {
        const parsed = JSON.parse(inflated);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('Conteúdo decifrado não é um objeto chave-valor válido.');
        }
        return parsed as Record<string, string>;
      } catch (err: any) {
        throw new Error(
          `DECRYPTION_PAYLOAD_CORRUPTED: JSON decifrado inválido (${err?.message || 'json parse error'}).`,
          { cause: err }
        );
      }
    }

    if (envelopeOrMap.startsWith('whdb:enc:')) {
      throw new Error(
        `DECRYPTION_VERSION_UNSUPPORTED: Versão de envelope criptográfico não suportada (${envelopeOrMap.slice(0, 16)}).`
      );
    }

    try {
      const parsed = JSON.parse(envelopeOrMap);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Objeto JSON esperado.');
      }
      return parsed as Record<string, string>;
    } catch (err: any) {
      throw new Error(
        `DECRYPTION_FORMAT_INVALID: JSON bruto inválido em sourceFilesMap (${err?.message || 'parse error'}).`,
        { cause: err }
      );
    }
  }

  private static preparePayloadForDisk<T>(data: T): T {
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      return data;
    }
    const record = data as Record<string, any>;
    if (!Array.isArray(record.softwares)) {
      return {
        schemaVersion: record.schemaVersion || PersistentDatabaseManager.SCHEMA_VERSION,
        storageKind: PersistentDatabaseManager.STORAGE_KIND,
        ...record,
      } as unknown as T;
    }

    const { keyId } = KeyManagementService.getActiveVaultAesKey();
    const encryptedSoftwares = record.softwares.map((sw: any) => {
      if (!sw || typeof sw !== 'object') return sw;
      const inMemoryFiles: Record<string, string> =
        sw.sourceFilesContent && typeof sw.sourceFilesContent === 'object'
          ? sw.sourceFilesContent
          : typeof sw.encryptedSourceFilesEnvelope === 'string'
            ? PersistentDatabaseManager.decryptSourceFilesMap(sw.encryptedSourceFilesEnvelope)
            : {};
      const envelope = PersistentDatabaseManager.encryptSourceFilesMap(inMemoryFiles);
      return {
        ...sw,
        sourceFilesContent: {},
        encryptedSourceFilesEnvelope: envelope,
        sourceFilesEncryptedAtRest: true,
        sourceFilesEncryptionKeyId: keyId,
      };
    });

    return {
      schemaVersion: record.schemaVersion || PersistentDatabaseManager.SCHEMA_VERSION,
      storageKind: PersistentDatabaseManager.STORAGE_KIND,
      ...record,
      softwares: encryptedSoftwares,
    } as unknown as T;
  }

  private static hydratePayloadFromDisk<T>(parsed: T): T {
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return parsed;
    }
    const record = parsed as Record<string, any>;
    if (!Array.isArray(record.softwares)) {
      return parsed;
    }

    for (const sw of record.softwares) {
      if (!sw || typeof sw !== 'object') continue;
      if (typeof sw.encryptedSourceFilesEnvelope === 'string' && sw.encryptedSourceFilesEnvelope) {
        sw.sourceFilesContent = PersistentDatabaseManager.decryptSourceFilesMap(
          sw.encryptedSourceFilesEnvelope
        );
      } else if (typeof sw.sourceFilesContent === 'string') {
        sw.sourceFilesContent = PersistentDatabaseManager.decryptSourceFilesMap(
          sw.sourceFilesContent
        );
      } else if (!sw.sourceFilesContent || typeof sw.sourceFilesContent !== 'object') {
        sw.sourceFilesContent = {};
      }
    }
    return parsed;
  }

  public writeAtomicChecksummed<T>(targetPath: string, data: T): { sha256: string } {
    const dir = path.dirname(targetPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const wrapped = PersistentDatabaseManager.preparePayloadForDisk(data);
    const serialized = JSON.stringify(wrapped, null, 2);
    const checksum = sha256Hex(serialized);
    const checksumPath = `${targetPath}.sha256`;
    const backupPath = `${targetPath}.bak`;

    if (fs.existsSync(targetPath)) {
      try {
        const currentRaw = fs.readFileSync(targetPath, 'utf8');
        // Only promote current file to .bak if it parses as valid JSON
        JSON.parse(currentRaw);
        fs.copyFileSync(targetPath, backupPath);
      } catch {
        // Do not overwrite a valid .bak with corrupted primary data
      }
    }

    const tmpFile = `${targetPath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmpFile, serialized, { encoding: 'utf8', mode: 0o600 });
    fsyncAndRename(tmpFile, targetPath);

    const tmpSha = `${checksumPath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmpSha, `${checksum}\n`, { encoding: 'utf8', mode: 0o600 });
    fsyncAndRename(tmpSha, checksumPath);

    return { sha256: checksum };
  }

  public enqueueAtomicWrite<T>(targetPath: string, data: T): Promise<{ sha256: string }> {
    const prev = this.pendingQueues.get(targetPath) ?? Promise.resolve();
    let resultSha = '';
    const next = prev
      .catch(() => undefined)
      .then(() => {
        resultSha = this.writeAtomicChecksummed(targetPath, data).sha256;
      });
    this.pendingQueues.set(targetPath, next);
    return next.then(() => ({ sha256: resultSha }));
  }

  public readWithChecksumRecovery<T>(targetPath: string): PersistentReadOutcome<T> {
    const checksumPath = `${targetPath}.sha256`;
    const backupPath = `${targetPath}.bak`;

    const tryReadPrimary = (): T | null => {
      if (!fs.existsSync(targetPath)) return null;
      const raw = fs.readFileSync(targetPath, 'utf8');
      if (fs.existsSync(checksumPath)) {
        const expected = fs.readFileSync(checksumPath, 'utf8').trim();
        const actual = sha256Hex(raw);
        if (expected.length === 64 && actual !== expected) {
          throw new Error(`Checksum SHA-256 divergente em ${path.basename(targetPath)}`);
        }
      }
      return PersistentDatabaseManager.hydratePayloadFromDisk(JSON.parse(raw) as T);
    };

    if (!fs.existsSync(targetPath) && !fs.existsSync(backupPath)) {
      return {
        data: null,
        recoveredFromBackup: false,
        storageKind: PersistentDatabaseManager.STORAGE_KIND,
        integrityStatus: 'MISSING',
      };
    }

    try {
      const primary = tryReadPrimary();
      if (primary !== null) {
        return {
          data: primary,
          recoveredFromBackup: false,
          storageKind: PersistentDatabaseManager.STORAGE_KIND,
          integrityStatus: 'VERIFIED',
        };
      }
    } catch (primaryErr: any) {
      // Attempt automatic recovery from .bak
      if (fs.existsSync(backupPath)) {
        try {
          const bakRaw = fs.readFileSync(backupPath, 'utf8');
          const bakParsed = PersistentDatabaseManager.hydratePayloadFromDisk(
            JSON.parse(bakRaw) as T
          );
          this.writeAtomicChecksummed(targetPath, bakParsed);
          return {
            data: bakParsed,
            recoveredFromBackup: true,
            storageKind: PersistentDatabaseManager.STORAGE_KIND,
            integrityStatus: 'RECOVERED_FROM_BACKUP',
            errorMessage: `Arquivo primário corrompido (${primaryErr?.message || 'parse/checksum'}); recuperado a partir de .bak.`,
          };
        } catch (bakErr: any) {
          return {
            data: null,
            recoveredFromBackup: false,
            storageKind: PersistentDatabaseManager.STORAGE_KIND,
            integrityStatus: 'CORRUPTED',
            errorMessage: `Arquivo primário e backup corrompidos: ${bakErr?.message || 'erro desconhecido'}`,
          };
        }
      }
      return {
        data: null,
        recoveredFromBackup: false,
        storageKind: PersistentDatabaseManager.STORAGE_KIND,
        integrityStatus: 'CORRUPTED',
        errorMessage: primaryErr?.message || 'Arquivo corrompido sem backup disponível.',
      };
    }

    return {
      data: null,
      recoveredFromBackup: false,
      storageKind: PersistentDatabaseManager.STORAGE_KIND,
      integrityStatus: 'MISSING',
    };
  }

  public inspectEncryptionAtRest(targetPath: string): StorageEncryptionInspectionReport {
    const { keyId } = KeyManagementService.getActiveVaultAesKey();
    const kmsStatus = KeyManagementService.getStatus();
    const storageMode = kmsStatus.dpapiSupported ? 'WINDOWS_DPAPI_KEYSTORE' : kmsStatus.keyOrigin;
    const checksumPath = `${targetPath}.sha256`;

    if (!fs.existsSync(targetPath)) {
      return {
        encryptedAtRest: true,
        algorithm: 'AES-256-GCM + ZLIB-DEFLATE',
        envelopeVersion: 'whdb:enc:v2',
        activeKeyId: keyId,
        keyStorageMode: storageMode,
        totalSoftwareCount: 0,
        encryptedSoftwareCount: 0,
        plaintextFilesExposedOnDisk: 0,
        sha256SidecarVerified: false,
        databaseSha256: null,
        verifiedAt: new Date().toISOString(),
      };
    }

    try {
      const raw = fs.readFileSync(targetPath, 'utf8');
      const actualSha = sha256Hex(raw);
      const expectedSha = fs.existsSync(checksumPath)
        ? fs.readFileSync(checksumPath, 'utf8').trim()
        : '';
      const parsed = JSON.parse(raw) as Record<string, any>;
      const softwares: any[] = Array.isArray(parsed.softwares) ? parsed.softwares : [];
      let encryptedCount = 0;
      let plaintextExposed = 0;

      for (const sw of softwares) {
        if (
          typeof sw?.encryptedSourceFilesEnvelope === 'string' &&
          sw.encryptedSourceFilesEnvelope.startsWith(PersistentDatabaseManager.ENVELOPE_PREFIX)
        ) {
          encryptedCount += 1;
        }
        if (sw?.sourceFilesContent && typeof sw.sourceFilesContent === 'object') {
          plaintextExposed += Object.keys(sw.sourceFilesContent).length;
        }
      }

      return {
        encryptedAtRest: plaintextExposed === 0 && encryptedCount === softwares.length,
        algorithm: 'AES-256-GCM + ZLIB-DEFLATE',
        envelopeVersion: 'whdb:enc:v2',
        activeKeyId: keyId,
        keyStorageMode: storageMode,
        totalSoftwareCount: softwares.length,
        encryptedSoftwareCount: encryptedCount,
        plaintextFilesExposedOnDisk: plaintextExposed,
        sha256SidecarVerified: Boolean(expectedSha && expectedSha === actualSha),
        databaseSha256: actualSha,
        verifiedAt: new Date().toISOString(),
      };
    } catch {
      return {
        encryptedAtRest: false,
        algorithm: 'AES-256-GCM + ZLIB-DEFLATE',
        envelopeVersion: 'whdb:enc:v2',
        activeKeyId: keyId,
        keyStorageMode: storageMode,
        totalSoftwareCount: 0,
        encryptedSoftwareCount: 0,
        plaintextFilesExposedOnDisk: 0,
        sha256SidecarVerified: false,
        databaseSha256: null,
        verifiedAt: new Date().toISOString(),
      };
    }
  }
}

