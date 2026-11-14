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

export class ProjectBackupService {
  private readonly backupsRootDir: string;

  constructor(dataDir?: string) {
    const root = dataDir || resolveWinHoodDataRoot();
    this.backupsRootDir = path.join(root, 'backups', 'projects');
    if (!fs.existsSync(this.backupsRootDir)) {
      fs.mkdirSync(this.backupsRootDir, { recursive: true, mode: 0o700 });
    }
  }

  private computeSha256(buf: Buffer): string {
    return crypto.createHash('sha256').update(buf).digest('hex');
  }

  public createBackup(
    project: Project,
    softwares: Software[],
    sourceFilesMap?: Record<string, string>
  ): ProjectBackupManifest {
    const backupId = `bkp-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const backupDir = path.join(this.backupsRootDir, backupId);
    fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });

    const filesSha256: Record<string, string> = {};
    let totalSizeBytes = 0;
    let filesCount = 0;

    // 1. Save project & software metadata json
    const metaPayload = JSON.stringify({ project, softwares }, null, 2);
    const metaBuf = Buffer.from(metaPayload, 'utf8');
    const metaRelPath = 'metadata.json';
    fs.writeFileSync(path.join(backupDir, metaRelPath), metaBuf);
    filesSha256[metaRelPath] = this.computeSha256(metaBuf);
    totalSizeBytes += metaBuf.length;
    filesCount += 1;

    // 2. Save source files if provided
    if (sourceFilesMap && typeof sourceFilesMap === 'object') {
      const srcDir = path.join(backupDir, 'source_files');
      fs.mkdirSync(srcDir, { recursive: true, mode: 0o700 });
      for (const [filePath, content] of Object.entries(sourceFilesMap)) {
        const cleanRel = filePath.replace(/^[/\\]+/, '').replace(/\\/g, '/');
        const absPath = path.join(srcDir, cleanRel);
        fs.mkdirSync(path.dirname(absPath), { recursive: true, mode: 0o700 });
        const fileBuf = Buffer.from(String(content || ''), 'utf8');
        fs.writeFileSync(absPath, fileBuf);
        const relKey = `source_files/${cleanRel}`;
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
    fs.writeFileSync(path.join(backupDir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');

    return manifest;
  }

  public listBackups(): BackupRecordSummary[] {
    if (!fs.existsSync(this.backupsRootDir)) return [];
    const entries = fs.readdirSync(this.backupsRootDir, { withFileTypes: true });
    const summaries: BackupRecordSummary[] = [];

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const backupId = entry.name;
      const manifestPath = path.join(this.backupsRootDir, backupId, 'manifest.json');
      if (!fs.existsSync(manifestPath)) continue;
      try {
        const raw = fs.readFileSync(manifestPath, 'utf8');
        const m = JSON.parse(raw) as ProjectBackupManifest;
        summaries.push({
          backupId: m.backupId || backupId,
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

  public verifyBackup(backupId: string): { valid: boolean; manifest: ProjectBackupManifest | null; errors: string[] } {
    const backupDir = path.join(this.backupsRootDir, backupId);
    const manifestPath = path.join(backupDir, 'manifest.json');
    const errors: string[] = [];

    if (!fs.existsSync(manifestPath)) {
      return { valid: false, manifest: null, errors: ['MANIFEST_NOT_FOUND: Arquivo manifest.json ausente.'] };
    }

    let manifest: ProjectBackupManifest;
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as ProjectBackupManifest;
    } catch {
      return { valid: false, manifest: null, errors: ['MANIFEST_CORRUPTED: Não foi possível decodificar o JSON do manifesto.'] };
    }

    if (!manifest.filesSha256 || typeof manifest.filesSha256 !== 'object') {
      errors.push('INVALID_MANIFEST: Dicionário filesSha256 ausente no manifesto.');
      return { valid: false, manifest, errors };
    }

    for (const [relPath, expectedHash] of Object.entries(manifest.filesSha256)) {
      const targetPath = path.join(backupDir, relPath);
      if (!fs.existsSync(targetPath)) {
        errors.push(`FILE_MISSING: Arquivo documentado no manifesto não foi encontrado: ${relPath}`);
        continue;
      }
      try {
        const fileBuf = fs.readFileSync(targetPath);
        const actualHash = this.computeSha256(fileBuf);
        if (actualHash !== expectedHash) {
          errors.push(`HASH_MISMATCH: O arquivo ${relPath} foi modificado ou corrompido (esperado ${expectedHash.slice(0, 10)}..., obtido ${actualHash.slice(0, 10)}...).`);
        }
      } catch (err: any) {
        errors.push(`READ_ERROR: Falha ao ler arquivo ${relPath}: ${err?.message}`);
      }
    }

    const valid = errors.length === 0;
    return { valid, manifest, errors };
  }

  public restoreBackup(backupId: string): { restoredProject: Project; restoredSoftwares: Software[]; sourceFilesMap: Record<string, string> } {
    const verification = this.verifyBackup(backupId);
    if (!verification.valid || !verification.manifest) {
      throw new Error(`BACKUP_INTEGRITY_FAILED: Impossível restaurar backup corrompido ou inválido. Erros: ${verification.errors.join(' | ')}`);
    }

    const backupDir = path.join(this.backupsRootDir, backupId);
    const metaPath = path.join(backupDir, 'metadata.json');
    if (!fs.existsSync(metaPath)) {
      throw new Error('METADATA_NOT_FOUND: metadata.json ausente no backup.');
    }

    const metaRaw = JSON.parse(fs.readFileSync(metaPath, 'utf8')) as { project: Project; softwares: Software[] };
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
    const srcDir = path.join(backupDir, 'source_files');
    if (fs.existsSync(srcDir)) {
      const walk = (dir: string, baseRel = '') => {
        const items = fs.readdirSync(dir, { withFileTypes: true });
        for (const item of items) {
          const rel = baseRel ? `${baseRel}/${item.name}` : item.name;
          const full = path.join(dir, item.name);
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
    const backupDir = path.join(this.backupsRootDir, backupId);
    if (!fs.existsSync(backupDir)) return false;
    fs.rmSync(backupDir, { recursive: true, force: true });
    return true;
  }
}
