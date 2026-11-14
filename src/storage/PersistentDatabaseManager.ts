import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export interface PersistentReadOutcome<T> {
  data: T | null;
  recoveredFromBackup: boolean;
  storageKind: 'ATOMIC_CHECKSUMMED_JSON_STORE';
  integrityStatus: 'VERIFIED' | 'RECOVERED_FROM_BACKUP' | 'MISSING' | 'CORRUPTED';
  errorMessage?: string;
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
 * backup automático (.bak) e fila sequencial de escrita para winhood_db.json / tools_db.json.
 */
export class PersistentDatabaseManager {
  public static readonly SCHEMA_VERSION = 4;
  public static readonly STORAGE_KIND = 'ATOMIC_CHECKSUMMED_JSON_STORE' as const;

  private readonly pendingQueues = new Map<string, Promise<void>>();

  public writeAtomicChecksummed<T>(targetPath: string, data: T): { sha256: string } {
    const dir = path.dirname(targetPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const wrapped =
      data && typeof data === 'object' && !Array.isArray(data)
        ? {
            schemaVersion: (data as any).schemaVersion || PersistentDatabaseManager.SCHEMA_VERSION,
            storageKind: PersistentDatabaseManager.STORAGE_KIND,
            ...data,
          }
        : data;

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
    const prev = this.pendingQueues.get(targetPath) || Promise.resolve();
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
      return JSON.parse(raw) as T;
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
          const bakParsed = JSON.parse(bakRaw) as T;
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
}
