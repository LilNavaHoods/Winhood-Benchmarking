import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type { Project, Software } from '../../types/benchmark';
import { resolveWinHoodDataRoot } from '../../storage/WinHoodPaths';

export interface ProjectBackupManifest {
  backupId: string;
  projectId: string;
  projectName: string;
  createdAt: string;
  schemaVersion: number;
  formatVersion: string;
  softwaresCount: number;
  filesCount: number;
  totalSizeBytes: number;
  filesSha256: Record<string, string>;
  manifestSha256?: string;
  integrityVerified: boolean;
}

export interface BackupRecordSummary {
  backupId: string;
  projectId: string;
  projectName: string;
  createdAt: string;
  filesCount: number;
  totalSizeBytes: number;
  integrityVerified: boolean;
}

const BACKUP_ID_ALLOWLIST = /^bkp-\d+-[a-f0-9]{8}$/i;
const MAX_BACKUP_ID_LENGTH = 128;

export class ProjectBackupService {
  private readonly backupsRootDir: string;

  constructor(dataDir?: string) {
    const root = dataDir || resolveWinHoodDataRoot();
    this.backupsRootDir = path.resolve(root, 'backups', 'projects');
    if (!fs.existsSync(this.backupsRootDir)) {
      fs.mkdirSync(this.backupsRootDir, { recursive: true, mode: 0o700 });
    }
  }

  private computeSha256(buf: Buffer): string {
    return crypto.createHash('sha256').update(buf).digest('hex');
  }

  private assertSafeBackupId(backupId: string): string {
    if (typeof backupId !== 'string') {
      throw new Error('INVALID_BACKUP_ID: O identificador do backup deve ser uma string válida.');
    }

    const trimmed = backupId.trim();
    if (!trimmed || trimmed.length > MAX_BACKUP_ID_LENGTH || trimmed.includes('\0')) {
      throw new Error('INVALID_BACKUP_ID: Identificador de backup vazio ou com tamanho inválido.');
    }

    if (!BACKUP_ID_ALLOWLIST.test(trimmed)) {
      throw new Error(
        `INVALID_BACKUP_ID: Formato de backupId não autorizado (${trimmed.slice(0, 32)}).`
      );
    }

    const rootResolved = path.resolve(this.backupsRootDir);
    const resolvedTarget = path.resolve(rootResolved, trimmed);
    const expectedPrefix = rootResolved.endsWith(path.sep)
      ? rootResolved
      : `${rootResolved}${path.sep}`;

    if (
      !resolvedTarget.startsWith(expectedPrefix) ||
      path.dirname(resolvedTarget) !== rootResolved
    ) {
      throw new Error(
        'PATH_TRAVERSAL_BLOCKED: Caminho do backup fora do diretório isolado autorizado.'
      );
    }

    return trimmed;
  }

  private resolveBackupDirectory(backupId: string): string {
    const safeId = this.assertSafeBackupId(backupId);
    const rootResolved = path.resolve(this.backupsRootDir);
    const targetDir = path.resolve(rootResolved, safeId);
    const expectedPrefix = rootResolved.endsWith(path.sep)
      ? rootResolved
      : `${rootResolved}${path.sep}`;

    if (!targetDir.startsWith(expectedPrefix) || path.dirname(targetDir) !== rootResolved) {
      throw new Error(
        'PATH_TRAVERSAL_BLOCKED: Resolução de diretório fora do boundary de backups.'
      );
    }

    return targetDir;
  }

  private resolveSafeChildPath(baseDir: string, rawRelativePath: string): {
    absPath: string;
    relPathNormalized: string;
  } {
    if (
      typeof rawRelativePath !== 'string' ||
      rawRelativePath.length === 0 ||
      rawRelativePath.includes('\0')
    ) {
      throw new Error('PATH_TRAVERSAL_BLOCKED: Caminho de arquivo inválido no pacote de backup.');
    }

    const cleaned = rawRelativePath.replace(/^[/\\]+/, '').replace(/\\/g, '/');
    const segments = cleaned.split('/').filter(Boolean);
    if (
      segments.length === 0 ||
      segments.some((seg) => seg === '.' || seg === '..' || seg.includes(':'))
    ) {
      throw new Error(
        `PATH_TRAVERSAL_BLOCKED: Segmento de caminho proibido no pacote (${rawRelativePath}).`
      );
    }

    const rootResolved = path.resolve(baseDir);
    const absPath = path.resolve(rootResolved, ...segments);
    const expectedPrefix = rootResolved.endsWith(path.sep)
      ? rootResolved
      : `${rootResolved}${path.sep}`;

    if (!absPath.startsWith(expectedPrefix)) {
      throw new Error(
        `PATH_TRAVERSAL_BLOCKED: Tentativa de acesso fora do diretório isolado (${rawRelativePath}).`
      );
    }

    return {
      absPath,
      relPathNormalized: segments.join('/'),
    };
  }

  public createBackup(
    project: Project,
    softwares: Software[],
    sourceFilesMap?: Record<string, string>
  ): ProjectBackupManifest {
    const backupId = `bkp-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const backupDir = this.resolveBackupDirectory(backupId);
    fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });

    const filesSha256: Record<string, string> = {};
    let totalSizeBytes = 0;
    let filesCount = 0;

    // 1. Save project & software metadata json
    const metaPayload = JSON.stringify({ project, softwares }, null, 2);
    const metaBuf = Buffer.from(metaPayload, 'utf8');
    const metaRelPath = 'metadata.json';
    const metaAbsPath = this.resolveSafeChildPath(backupDir, metaRelPath).absPath;
    fs.writeFileSync(metaAbsPath, metaBuf);
    filesSha256[metaRelPath] = this.computeSha256(metaBuf);
    totalSizeBytes += metaBuf.length;
    filesCount += 1;

    // 2. Save source files if provided (with strict boundary protection)
    if (sourceFilesMap && typeof sourceFilesMap === 'object') {
      const srcDir = this.resolveSafeChildPath(backupDir, 'source_files').absPath;
      fs.mkdirSync(srcDir, { recursive: true, mode: 0o700 });
      for (const [filePath, content] of Object.entries(sourceFilesMap)) {
        const { absPath, relPathNormalized } = this.resolveSafeChildPath(srcDir, filePath);
        fs.mkdirSync(path.dirname(absPath), { recursive: true, mode: 0o700 });
        const fileBuf = Buffer.from(String(content || ''), 'utf8');
        fs.writeFileSync(absPath, fileBuf);
        const relKey = `source_files/${relPathNormalized}`;
        filesSha256[relKey] = this.computeSha256(fileBuf);
        totalSizeBytes += fileBuf.length;
        filesCount += 1;
      }
    }

    const manifest: ProjectBackupManifest = {
      backupId,
      projectId: project.id,
      projectName: project.name,
      createdAt: new Date().toISOString(),
      schemaVersion: 1,
      formatVersion: 'WINHOOD-BACKEND-v3.0',
      softwaresCount: softwares.length,
      filesCount,
      totalSizeBytes,
      filesSha256,
      integrityVerified: true,
    };

    const manifestBuf = Buffer.from(JSON.stringify(manifest, null, 2), 'utf8');
    manifest.manifestSha256 = this.computeSha256(manifestBuf);
    const manifestAbsPath = this.resolveSafeChildPath(backupDir, 'manifest.json').absPath;
    fs.writeFileSync(manifestAbsPath, JSON.stringify(manifest, null, 2), 'utf8');

    return manifest;
  }

  public listBackups(): BackupRecordSummary[] {
    if (!fs.existsSync(this.backupsRootDir)) return [];
    const entries = fs.readdirSync(this.backupsRootDir, { withFileTypes: true });
    const summaries: BackupRecordSummary[] = [];

    for (const entry of entries) {
      if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
      let backupDir: string;
      try {
        backupDir = this.resolveBackupDirectory(entry.name);
      } catch {
        continue;
      }
      const manifestPath = path.join(backupDir, 'manifest.json');
      if (!fs.existsSync(manifestPath)) continue;
      try {
        const raw = fs.readFileSync(manifestPath, 'utf8');
        const m = JSON.parse(raw) as ProjectBackupManifest;
        summaries.push({
          backupId: m.backupId || entry.name,
          projectId: m.projectId,
          projectName: m.projectName,
          createdAt: m.createdAt,
          filesCount: m.filesCount,
          totalSizeBytes: m.totalSizeBytes,
          integrityVerified: m.integrityVerified,
        });
      } catch {
        // Skip corrupted manifest
      }
    }

    summaries.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
    return summaries;
  }

  public verifyBackup(
    backupId: string
  ): { valid: boolean; manifest: ProjectBackupManifest | null; errors: string[] } {
    this.assertSafeBackupId(backupId);
    const backupDir = this.resolveBackupDirectory(backupId);
    const manifestPath = path.join(backupDir, 'manifest.json');
    const errors: string[] = [];

    if (!fs.existsSync(manifestPath)) {
      return {
        valid: false,
        manifest: null,
        errors: ['MANIFEST_NOT_FOUND: Arquivo manifest.json ausente.'],
      };
    }

    let manifest: ProjectBackupManifest;
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as ProjectBackupManifest;
    } catch {
      return {
        valid: false,
        manifest: null,
        errors: ['MANIFEST_CORRUPTED: Não foi possível decodificar o JSON do manifesto.'],
      };
    }

    if (!manifest.filesSha256 || typeof manifest.filesSha256 !== 'object') {
      errors.push('INVALID_MANIFEST: Dicionário filesSha256 ausente no manifesto.');
      return { valid: false, manifest, errors };
    }

    for (const [relPath, expectedHash] of Object.entries(manifest.filesSha256)) {
      let targetPath: string;
      try {
        targetPath = this.resolveSafeChildPath(backupDir, relPath).absPath;
      } catch (err: any) {
        errors.push(err?.message || `PATH_TRAVERSAL_BLOCKED: ${relPath}`);
        continue;
      }

      if (!fs.existsSync(targetPath)) {
        errors.push(
          `FILE_MISSING: Arquivo documentado no manifesto não foi encontrado: ${relPath}`
        );
        continue;
      }
      try {
        const fileBuf = fs.readFileSync(targetPath);
        const actualHash = this.computeSha256(fileBuf);
        if (actualHash !== expectedHash) {
          errors.push(
            `HASH_MISMATCH: O arquivo ${relPath} foi modificado ou corrompido (esperado ${expectedHash.slice(0, 10)}..., obtido ${actualHash.slice(0, 10)}...).`
          );
        }
      } catch (err: any) {
        errors.push(`READ_ERROR: Falha ao ler arquivo ${relPath}: ${err?.message}`);
      }
    }

    const valid = errors.length === 0;
    return { valid, manifest, errors };
  }

  public restoreBackup(
    backupId: string
  ): { restoredProject: Project; restoredSoftwares: Software[]; sourceFilesMap: Record<string, string> } {
    this.assertSafeBackupId(backupId);
    const verification = this.verifyBackup(backupId);
    if (!verification.valid || !verification.manifest) {
      throw new Error(
        `BACKUP_INTEGRITY_FAILED: Impossível restaurar backup corrompido ou inválido. Erros: ${verification.errors.join(' | ')}`
      );
    }

    const backupDir = this.resolveBackupDirectory(backupId);
    const metaPath = this.resolveSafeChildPath(backupDir, 'metadata.json').absPath;
    if (!fs.existsSync(metaPath)) {
      throw new Error('METADATA_NOT_FOUND: metadata.json ausente no backup.');
    }

    const metaRaw = JSON.parse(fs.readFileSync(metaPath, 'utf8')) as {
      project: Project;
      softwares: Software[];
    };
    const oldProj = metaRaw.project;
    const oldSoftwares = metaRaw.softwares || [];

    const newProjId = `proj-restored-${crypto.randomUUID().slice(0, 8)}`;
    const now = new Date().toISOString();

    const restoredProject: Project = {
      ...oldProj,
      id: newProjId,
      name: `${oldProj.name} (Restaurado)`,
      createdAt: now,
      updatedAt: now,
    };

    const restoredSoftwares: Software[] = oldSoftwares.map((sw) => ({
      ...sw,
      id: `sw-restored-${crypto.randomUUID().slice(0, 8)}`,
      projectId: newProjId,
      createdAt: now,
      updatedAt: now,
    }));

    const sourceFilesMap: Record<string, string> = {};
    const srcDir = this.resolveSafeChildPath(backupDir, 'source_files').absPath;
    if (fs.existsSync(srcDir)) {
      const walk = (dir: string, baseRel = '') => {
        const items = fs.readdirSync(dir, { withFileTypes: true });
        for (const item of items) {
          if (item.isSymbolicLink()) continue;
          const rel = baseRel ? `${baseRel}/${item.name}` : item.name;
          const full = this.resolveSafeChildPath(srcDir, rel).absPath;
          if (item.isDirectory()) {
            walk(full, rel);
          } else if (item.isFile()) {
            try {
              sourceFilesMap[rel] = fs.readFileSync(full, 'utf8');
            } catch {
              // Ignore binary read errors
            }
          }
        }
      };
      walk(srcDir);
    }

    return { restoredProject, restoredSoftwares, sourceFilesMap };
  }

  public deleteBackup(backupId: string): boolean {
    this.assertSafeBackupId(backupId);
    const backupDir = this.resolveBackupDirectory(backupId);
    if (!fs.existsSync(backupDir)) return false;
    fs.rmSync(backupDir, { recursive: true, force: true });
    return true;
  }
}
