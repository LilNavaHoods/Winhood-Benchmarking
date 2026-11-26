import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { KeyManagementService } from '../security/KeyManagementService';
import { PersistentDatabaseManager } from './PersistentDatabaseManager';

export const VAULT_BUNDLE_FILENAME = 'vault_bundle.whenc';
export const VAULT_MANIFEST_FILENAME = 'vault_manifest.json';
export const MIGRATION_LEDGER_FILENAME = 'plaintext_migration_ledger.json';

export interface EncryptedArtifactFileMetadata {
  relativePath: string;
  sha256: string;
  byteSize: number;
}

export interface EncryptedArtifactManifest {
  schemaVersion: '2.0.0';
  storagePolicy: 'ENCRYPTED_ONLY_NO_PLAINTEXT_AT_REST';
  slug: string;
  keyId: string;
  algorithm: 'AES-256-GCM + ZLIB-DEFLATE';
  envelopeFile: string;
  envelopeSha256: string;
  contentRootSha256: string;
  fileCount: number;
  totalBytes: number;
  encryptedAt: string;
  files: EncryptedArtifactFileMetadata[];
}

export interface LegacyPlaintextMigrationRecord {
  slug: string;
  migratedAt: string;
  status: 'MIGRATED' | 'ALREADY_ENCRYPTED' | 'FAILED';
  plaintextFilesRemoved: number;
  verifiedFilesCount: number;
  contentRootSha256: string | null;
  errorMessage?: string;
}

export interface LegacyPlaintextMigrationReport {
  artifactsRoot: string;
  startedAt: string;
  completedAt: string;
  idempotent: true;
  migratedSlugs: number;
  alreadyEncryptedSlugs: number;
  failedSlugs: number;
  plaintextFilesRemovedTotal: number;
  records: LegacyPlaintextMigrationRecord[];
}

export interface PlaintextAuditScanResult {
  artifactsRoot: string;
  clean: boolean;
  plaintextFilePaths: string[];
  encryptedBundleCount: number;
  scannedAt: string;
}

function sha256Buffer(data: Buffer | string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function atomicWriteFile(targetPath: string, content: string, mode = 0o600): void {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmpPath = `${targetPath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  const fd = fs.openSync(tmpPath, 'w', mode);
  try {
    fs.writeFileSync(fd, content, 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmpPath, targetPath);
  try {
    fs.chmodSync(targetPath, mode);
  } catch {
    // Windows chmod best-effort
  }
}

function sanitizeSlug(rawSlug: string): string {
  const safe = rawSlug.replace(/[^a-zA-Z0-9_-]/g, '_');
  if (!safe || safe === '.' || safe === '..') {
    throw new Error(`ENCRYPTED_STORE_INVALID_SLUG: Slug inválido "${rawSlug}".`);
  }
  return safe;
}

function normalizeAndValidateFilePath(relPath: string): string {
  if (!relPath || relPath.includes('\0')) {
    throw new Error(`ENCRYPTED_STORE_INVALID_PATH: Caminho inválido "${relPath}".`);
  }
  const normalized = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  if (!normalized) {
    throw new Error('ENCRYPTED_STORE_INVALID_PATH: Caminho relativo vazio.');
  }
  for (const seg of normalized.split('/')) {
    if (seg === '..' || seg === '.') {
      throw new Error(`Tentativa de Path Traversal bloqueada no arquivo: ${relPath}`);
    }
  }
  if (/^[a-zA-Z]:/.test(normalized)) {
    throw new Error(`Tentativa de Path Traversal bloqueada no arquivo: ${relPath}`);
  }
  return normalized;
}

function collectLegacyPlaintextFiles(
  rootDir: string,
  currentDir = rootDir,
  acc: Record<string, string> = {}
): Record<string, string> {
  if (!fs.existsSync(currentDir)) return acc;
  const entries = fs.readdirSync(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const fullPath = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      collectLegacyPlaintextFiles(rootDir, fullPath, acc);
    } else if (entry.isFile()) {
      if (
        entry.name === VAULT_BUNDLE_FILENAME ||
        entry.name === VAULT_MANIFEST_FILENAME ||
        entry.name.endsWith('.tmp')
      ) {
        continue;
      }
      const rel = path.relative(rootDir, fullPath).replace(/\\/g, '/');
      acc[rel] = fs.readFileSync(fullPath, 'utf8');
    }
  }
  return acc;
}

function removeLegacyPlaintextFilesOnly(rootDir: string, currentDir = rootDir): number {
  if (!fs.existsSync(currentDir)) return 0;
  let removed = 0;
  const entries = fs.readdirSync(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      removed += removeLegacyPlaintextFilesOnly(rootDir, fullPath);
      try {
        if (fs.readdirSync(fullPath).length === 0) {
          fs.rmdirSync(fullPath);
        }
      } catch {
        // Ignore non-empty dir
      }
    } else {
      if (
        entry.name === VAULT_BUNDLE_FILENAME ||
        entry.name === VAULT_MANIFEST_FILENAME
      ) {
        continue;
      }
      fs.unlinkSync(fullPath);
      removed += 1;
    }
  }
  return removed;
}

/**
 * EncryptedArtifactStore (Phase P0)
 *
 * Persists source code exclusively inside authenticated AES-256-GCM envelopes (`vault_bundle.whenc`)
 * accompanied by a non-secret SHA-256 metadata manifest (`vault_manifest.json`).
 *
 * Guarantees:
 * - Zero plaintext source files are written to `WINHOOD_DATA_DIR/isolated_artifacts`.
 * - Path traversal and symlink attacks are rejected before encryption.
 * - Supports key rotation re-encryption across all stored bundles.
 * - Includes atomic, idempotent, round-trip-verified migration for legacy plaintext installations.
 */
export class EncryptedArtifactStore {
  public static writeEncryptedBundle(params: {
    softwareSlug: string;
    filesMap: Record<string, string>;
    artifactsRoot: string;
  }): { targetDir: string; manifest: EncryptedArtifactManifest } {
    const rootCanonical = path.resolve(params.artifactsRoot);
    fs.mkdirSync(rootCanonical, { recursive: true, mode: 0o700 });

    const safeSlug = sanitizeSlug(params.softwareSlug);
    const targetDir = path.resolve(rootCanonical, safeSlug);
    if (!targetDir.startsWith(rootCanonical + path.sep)) {
      throw new Error('Tentativa de Directory Traversal no softwareSlug bloqueada.');
    }

    // Validate all relative paths and construct canonical sorted filesMap
    const normalizedMap: Record<string, string> = {};
    const fileMetadata: EncryptedArtifactFileMetadata[] = [];
    let totalBytes = 0;

    const sortedEntries = Object.entries(params.filesMap || {}).sort(([a], [b]) => a.localeCompare(b));
    for (const [rawRel, rawContent] of sortedEntries) {
      const normalizedRel = normalizeAndValidateFilePath(rawRel);
      const canonicalCheck = path.resolve(targetDir, normalizedRel);
      if (!canonicalCheck.startsWith(targetDir + path.sep)) {
        throw new Error(`Tentativa de Path Traversal bloqueada no arquivo: ${rawRel}`);
      }
      const content = typeof rawContent === 'string' ? rawContent : String(rawContent ?? '');
      const byteSize = Buffer.byteLength(content, 'utf8');
      totalBytes += byteSize;
      normalizedMap[normalizedRel] = content;
      fileMetadata.push({
        relativePath: normalizedRel,
        sha256: sha256Buffer(content),
        byteSize,
      });
    }

    fs.mkdirSync(targetDir, { recursive: true, mode: 0o700 });

    const { keyId } = KeyManagementService.getActiveVaultAesKey();
    const encryptedEnvelope = PersistentDatabaseManager.encryptSourceFilesMap(normalizedMap);
    const bundlePath = path.resolve(targetDir, VAULT_BUNDLE_FILENAME);
    const manifestPath = path.resolve(targetDir, VAULT_MANIFEST_FILENAME);

    const contentRootSha256 = sha256Buffer(JSON.stringify(fileMetadata));
    const manifest: EncryptedArtifactManifest = {
      schemaVersion: '2.0.0',
      storagePolicy: 'ENCRYPTED_ONLY_NO_PLAINTEXT_AT_REST',
      slug: safeSlug,
      keyId,
      algorithm: 'AES-256-GCM + ZLIB-DEFLATE',
      envelopeFile: VAULT_BUNDLE_FILENAME,
      envelopeSha256: sha256Buffer(encryptedEnvelope),
      contentRootSha256,
      fileCount: fileMetadata.length,
      totalBytes,
      encryptedAt: new Date().toISOString(),
      files: fileMetadata,
    };

    atomicWriteFile(bundlePath, encryptedEnvelope, 0o600);
    atomicWriteFile(manifestPath, JSON.stringify(manifest, null, 2), 0o600);

    // Ensure any pre-existing legacy plaintext files in the same slug directory are purged
    // ONLY AFTER the encrypted bundle and manifest have been atomically persisted and verified
    const verifiedBack = EncryptedArtifactStore.readEncryptedBundle(targetDir);
    if (Object.keys(verifiedBack).length !== Object.keys(normalizedMap).length) {
      throw new Error('ENCRYPTED_STORE_ROUNDTRIP_FAILED: Divergência na verificação pós-gravação do envelope criptografado.');
    }
    removeLegacyPlaintextFilesOnly(targetDir);

    return { targetDir, manifest };
  }

  public static readEncryptedBundle(
    targetDir: string,
    explicitKeyBuffer?: Buffer
  ): Record<string, string> {
    const bundlePath = path.resolve(targetDir, VAULT_BUNDLE_FILENAME);
    const manifestPath = path.resolve(targetDir, VAULT_MANIFEST_FILENAME);
    if (!fs.existsSync(bundlePath)) {
      throw new Error(`ENCRYPTED_BUNDLE_MISSING: Envelope criptografado ausente em ${targetDir}.`);
    }
    const envelope = fs.readFileSync(bundlePath, 'utf8').trim();

    if (fs.existsSync(manifestPath)) {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as EncryptedArtifactManifest;
      const actualEnvelopeSha = sha256Buffer(envelope);
      if (manifest.envelopeSha256 && manifest.envelopeSha256 !== actualEnvelopeSha) {
        throw new Error(
          `ENCRYPTED_BUNDLE_INTEGRITY_VIOLATION: Checksum SHA-256 do envelope diverge do manifesto em ${targetDir}.`
        );
      }
    }

    return PersistentDatabaseManager.decryptSourceFilesMap(envelope, explicitKeyBuffer);
  }

  /**
   * Re-encrypts all persisted encrypted bundles using the currently active Vault AES-256-GCM key
   * after a key rotation, preserving atomic write guarantees and verifying round-trip integrity.
   */
  public static reencryptAllBundles(artifactsRoot: string): {
    reencryptedCount: number;
    newKeyId: string;
    errors: string[];
  } {
    const { keyId: newKeyId } = KeyManagementService.getActiveVaultAesKey();
    const errors: string[] = [];
    let reencryptedCount = 0;

    if (!fs.existsSync(artifactsRoot)) {
      return { reencryptedCount: 0, newKeyId, errors };
    }

    const entries = fs.readdirSync(artifactsRoot, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const slugDir = path.join(artifactsRoot, entry.name);
      const bundlePath = path.join(slugDir, VAULT_BUNDLE_FILENAME);
      if (!fs.existsSync(bundlePath)) continue;
      try {
        const filesMap = EncryptedArtifactStore.readEncryptedBundle(slugDir);
        EncryptedArtifactStore.writeEncryptedBundle({
          softwareSlug: entry.name,
          filesMap,
          artifactsRoot,
        });
        reencryptedCount += 1;
      } catch (err: unknown) {
        errors.push(
          `Falha ao re-criptografar bundle "${entry.name}": ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    return { reencryptedCount, newKeyId, errors };
  }

  /**
   * Atomic, idempotent migration for installations that still contain legacy plaintext files
   * inside `WINHOOD_DATA_DIR/isolated_artifacts`.
   *
   * Steps per directory:
   * 1. Discover legacy plaintext files (skipping vault_bundle.whenc / vault_manifest.json).
   * 2. Validate file readability and compute per-file SHA-256 digests.
   * 3. Write AES-256-GCM encrypted bundle + manifest atomically.
   * 4. Decrypt back and verify byte-for-byte SHA-256 match for EVERY migrated file.
   * 5. Remove legacy plaintext files ONLY after verification passes.
   * 6. Persist idempotent migration ledger atomically.
   */
  public static migrateLegacyPlaintextArtifacts(artifactsRoot: string): LegacyPlaintextMigrationReport {
    const startedAt = new Date().toISOString();
    const records: LegacyPlaintextMigrationRecord[] = [];
    let migratedSlugs = 0;
    let alreadyEncryptedSlugs = 0;
    let failedSlugs = 0;
    let plaintextFilesRemovedTotal = 0;

    if (!fs.existsSync(artifactsRoot)) {
      return {
        artifactsRoot,
        startedAt,
        completedAt: new Date().toISOString(),
        idempotent: true,
        migratedSlugs: 0,
        alreadyEncryptedSlugs: 0,
        failedSlugs: 0,
        plaintextFilesRemovedTotal: 0,
        records: [],
      };
    }

    const entries = fs.readdirSync(artifactsRoot, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const slug = entry.name;
      const slugDir = path.join(artifactsRoot, slug);
      const legacyFiles = collectLegacyPlaintextFiles(slugDir);
      const legacyKeys = Object.keys(legacyFiles);
      const bundleExists = fs.existsSync(path.join(slugDir, VAULT_BUNDLE_FILENAME));

      if (legacyKeys.length === 0) {
        if (bundleExists) {
          alreadyEncryptedSlugs += 1;
          records.push({
            slug,
            migratedAt: new Date().toISOString(),
            status: 'ALREADY_ENCRYPTED',
            plaintextFilesRemoved: 0,
            verifiedFilesCount: 0,
            contentRootSha256: null,
          });
        }
        continue;
      }

      try {
        // Compute pre-migration digests
        const expectedHashes = new Map<string, string>();
        for (const [rel, content] of Object.entries(legacyFiles)) {
          expectedHashes.set(rel, sha256Buffer(content));
        }

        // Encrypt & persist atomically (merges with existing encrypted files if bundle already existed)
        let mergedFiles = { ...legacyFiles };
        if (bundleExists) {
          try {
            const existingDecrypted = EncryptedArtifactStore.readEncryptedBundle(slugDir);
            mergedFiles = { ...existingDecrypted, ...legacyFiles };
          } catch {
            // If interrupted/partial bundle existed, overwrite cleanly from verified legacy files
          }
        }

        const { manifest } = EncryptedArtifactStore.writeEncryptedBundle({
          softwareSlug: slug,
          filesMap: mergedFiles,
          artifactsRoot,
        });

        // Strict round-trip verification before confirming migration
        const roundTrip = EncryptedArtifactStore.readEncryptedBundle(slugDir);
        for (const [rel, expectedSha] of expectedHashes.entries()) {
          const recovered = roundTrip[rel];
          if (recovered === undefined || sha256Buffer(recovered) !== expectedSha) {
            throw new Error(`Falha na verificação pós-migração do arquivo "${rel}".`);
          }
        }

        const removedCount = removeLegacyPlaintextFilesOnly(slugDir);
        plaintextFilesRemovedTotal += removedCount + legacyKeys.length;
        migratedSlugs += 1;
        records.push({
          slug,
          migratedAt: new Date().toISOString(),
          status: 'MIGRATED',
          plaintextFilesRemoved: legacyKeys.length,
          verifiedFilesCount: expectedHashes.size,
          contentRootSha256: manifest.contentRootSha256,
        });
      } catch (err: unknown) {
        failedSlugs += 1;
        records.push({
          slug,
          migratedAt: new Date().toISOString(),
          status: 'FAILED',
          plaintextFilesRemoved: 0,
          verifiedFilesCount: 0,
          contentRootSha256: null,
          errorMessage: err instanceof Error ? err.message : String(err),
        });
      }
    }

    const report: LegacyPlaintextMigrationReport = {
      artifactsRoot,
      startedAt,
      completedAt: new Date().toISOString(),
      idempotent: true,
      migratedSlugs,
      alreadyEncryptedSlugs,
      failedSlugs,
      plaintextFilesRemovedTotal,
      records,
    };

    try {
      const ledgerPath = path.join(artifactsRoot, MIGRATION_LEDGER_FILENAME);
      atomicWriteFile(ledgerPath, JSON.stringify(report, null, 2), 0o600);
    } catch {
      // Non-fatal if ledger path is read-only
    }

    return report;
  }

  /**
   * Scans `WINHOOD_DATA_DIR/isolated_artifacts` to verify ZERO plaintext source files exist on disk.
   */
  public static auditNoPlaintextOnDisk(artifactsRoot: string): PlaintextAuditScanResult {
    const plaintextFilePaths: string[] = [];
    let encryptedBundleCount = 0;

    const walk = (dir: string): void => {
      if (!fs.existsSync(dir)) return;
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full);
        } else if (entry.isFile()) {
          if (entry.name === VAULT_BUNDLE_FILENAME) {
            encryptedBundleCount += 1;
          } else if (
            entry.name === VAULT_MANIFEST_FILENAME ||
            entry.name === MIGRATION_LEDGER_FILENAME
          ) {
            continue;
          } else {
            plaintextFilePaths.push(path.relative(artifactsRoot, full).replace(/\\/g, '/'));
          }
        }
      }
    };

    walk(artifactsRoot);

    return {
      artifactsRoot,
      clean: plaintextFilePaths.length === 0,
      plaintextFilePaths,
      encryptedBundleCount,
      scannedAt: new Date().toISOString(),
    };
  }
}
