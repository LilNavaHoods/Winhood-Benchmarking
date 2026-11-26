import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export interface EphemeralWorkspaceLimits {
  maxFiles: number;
  maxTotalBytes: number;
  maxSingleFileBytes: number;
}

export interface EphemeralWorkspaceHandle {
  workspaceId: string;
  jobId: string;
  rootPath: string;
  filesWritten: number;
  totalBytes: number;
  createdAt: string;
  cleanup: () => { cleaned: boolean; residualExists: boolean };
}

export const DEFAULT_EPHEMERAL_WORKSPACE_LIMITS: EphemeralWorkspaceLimits = {
  maxFiles: 5_000,
  maxTotalBytes: 64 * 1024 * 1024, // 64 MiB
  maxSingleFileBytes: 10 * 1024 * 1024, // 10 MiB
};

const ACTIVE_WORKSPACES = new Set<string>();

/**
 * Resolves the ephemeral workspace base directory.
 * In Docker, defaults to `WINHOOD_TEMP_WORKSPACE_DIR` (mounted on tmpfs `/tmp/winhood-workspaces`).
 * Never resolves inside `WINHOOD_DATA_DIR` so unencrypted analysis inputs never touch persistent volumes.
 */
export function resolveEphemeralWorkspaceRoot(explicitBaseDir?: string): string {
  const fromArg = (explicitBaseDir || '').trim();
  const fromEnv = (process.env.WINHOOD_TEMP_WORKSPACE_DIR || '').trim();
  const candidate = fromArg || fromEnv || path.join(os.tmpdir(), 'winhood-ephemeral-workspaces');
  const resolved = path.resolve(candidate);

  const persistentDataDir = (process.env.WINHOOD_DATA_DIR || '').trim();
  if (persistentDataDir) {
    const resolvedDataDir = path.resolve(persistentDataDir);
    if (
      resolved === resolvedDataDir ||
      resolved.startsWith(resolvedDataDir + path.sep)
    ) {
      throw new Error(
        'EPHEMERAL_WORKSPACE_POLICY_VIOLATION: O workspace temporário de análise não pode residir dentro do diretório de armazenamento persistente WINHOOD_DATA_DIR.'
      );
    }
  }
  return resolved;
}

function validateRelativeWorkspacePath(relPath: string): string {
  if (!relPath || typeof relPath !== 'string') {
    throw new Error('EPHEMERAL_WORKSPACE_INVALID_PATH: Caminho de arquivo vazio.');
  }
  if (relPath.includes('\0')) {
    throw new Error(`EPHEMERAL_WORKSPACE_NULL_BYTE: Caractere nulo proibido no caminho: ${relPath}`);
  }
  const normalized = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  if (!normalized) {
    throw new Error('EPHEMERAL_WORKSPACE_INVALID_PATH: Caminho relativo normalizado vazio.');
  }
  const segments = normalized.split('/');
  for (const seg of segments) {
    if (seg === '..' || seg === '.') {
      throw new Error(`EPHEMERAL_WORKSPACE_PATH_TRAVERSAL: Path traversal bloqueado: ${relPath}`);
    }
  }
  if (/^[a-zA-Z]:/.test(normalized)) {
    throw new Error(`EPHEMERAL_WORKSPACE_ABSOLUTE_DRIVE: Caminho absoluto bloqueado: ${relPath}`);
  }
  return normalized;
}

/**
 * EphemeralWorkspaceManager
 *
 * Isolates per-job temporary source code materialization strictly outside persistent storage:
 * - Creates an exclusive `0o700` directory per job/execution.
 * - Rejects symlinks, path traversal, null bytes, and enforces file count & byte quotas.
 * - Cleans up deterministically on completion, cancellation, timeout, failure, or process shutdown.
 * - Note: SSD deletion is not claimed as physical secure overwrite; protection relies on ephemeral
 *   filesystem (tmpfs in Docker) + AES-256-GCM encryption at rest on persistent storage.
 */
export class EphemeralWorkspaceManager {
  public static getActiveWorkspaceCount(): number {
    return ACTIVE_WORKSPACES.size;
  }

  public static listActiveWorkspaces(): string[] {
    return Array.from(ACTIVE_WORKSPACES.values());
  }

  public static createWorkspace(params: {
    jobId: string;
    filesMap: Record<string, string>;
    baseDir?: string;
    limits?: Partial<EphemeralWorkspaceLimits>;
  }): EphemeralWorkspaceHandle {
    const limits: EphemeralWorkspaceLimits = {
      ...DEFAULT_EPHEMERAL_WORKSPACE_LIMITS,
      ...(params.limits || {}),
    };
    const entries = Object.entries(params.filesMap || {});
    if (entries.length > limits.maxFiles) {
      throw new Error(
        `EPHEMERAL_WORKSPACE_QUOTA_EXCEEDED: Quantidade de arquivos (${entries.length}) excede o limite (${limits.maxFiles}).`
      );
    }

    const baseRoot = resolveEphemeralWorkspaceRoot(params.baseDir);
    fs.mkdirSync(baseRoot, { recursive: true, mode: 0o700 });
    try {
      fs.chmodSync(baseRoot, 0o700);
    } catch {
      // Best-effort on Windows
    }

    const safeJobId = String(params.jobId || 'job').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 48);
    const workspaceId = `ws-${safeJobId}-${crypto.randomBytes(8).toString('hex')}`;
    const rawWsDir = path.join(baseRoot, workspaceId);
    fs.mkdirSync(rawWsDir, { recursive: true, mode: 0o700 });
    const rootPath = fs.realpathSync(rawWsDir);
    ACTIVE_WORKSPACES.add(rootPath);

    let filesWritten = 0;
    let totalBytes = 0;

    try {
      for (const [relPath, content] of entries) {
        const cleanRel = validateRelativeWorkspacePath(relPath);
        const contentStr = typeof content === 'string' ? content : String(content ?? '');
        const byteLen = Buffer.byteLength(contentStr, 'utf8');
        if (byteLen > limits.maxSingleFileBytes) {
          throw new Error(
            `EPHEMERAL_WORKSPACE_FILE_TOO_LARGE: Arquivo "${cleanRel}" (${byteLen} bytes) excede limite por arquivo (${limits.maxSingleFileBytes} bytes).`
          );
        }
        totalBytes += byteLen;
        if (totalBytes > limits.maxTotalBytes) {
          throw new Error(
            `EPHEMERAL_WORKSPACE_SIZE_EXCEEDED: Tamanho acumulado (${totalBytes} bytes) excede o limite do workspace (${limits.maxTotalBytes} bytes).`
          );
        }

        const resolvedTarget = path.resolve(rootPath, cleanRel);
        if (!resolvedTarget.startsWith(rootPath + path.sep)) {
          throw new Error(`EPHEMERAL_WORKSPACE_PATH_TRAVERSAL: Fronteira violada: ${relPath}`);
        }

        // Verify no parent segment is a symlink inside the workspace
        const parentDir = path.dirname(resolvedTarget);
        fs.mkdirSync(parentDir, { recursive: true, mode: 0o700 });
        const realParent = fs.realpathSync(parentDir);
        if (realParent !== rootPath && !realParent.startsWith(rootPath + path.sep)) {
          throw new Error(`EPHEMERAL_WORKSPACE_SYMLINK_ESCAPE: Symlink detectado fora do workspace: ${relPath}`);
        }

        if (fs.existsSync(resolvedTarget)) {
          const stat = fs.lstatSync(resolvedTarget);
          if (stat.isSymbolicLink()) {
            throw new Error(`EPHEMERAL_WORKSPACE_SYMLINK_FORBIDDEN: Symlink proibido em ${relPath}`);
          }
        }

        fs.writeFileSync(resolvedTarget, contentStr, { encoding: 'utf8', mode: 0o600 });
        filesWritten += 1;
      }
    } catch (err) {
      EphemeralWorkspaceManager.cleanupWorkspacePath(rootPath);
      throw err;
    }

    const cleanup = (): { cleaned: boolean; residualExists: boolean } => {
      return EphemeralWorkspaceManager.cleanupWorkspacePath(rootPath);
    };

    return {
      workspaceId,
      jobId: safeJobId,
      rootPath,
      filesWritten,
      totalBytes,
      createdAt: new Date().toISOString(),
      cleanup,
    };
  }

  public static cleanupWorkspacePath(rootPath: string): { cleaned: boolean; residualExists: boolean } {
    try {
      if (fs.existsSync(rootPath)) {
        fs.rmSync(rootPath, { recursive: true, force: true });
      }
      const residualExists = fs.existsSync(rootPath);
      if (!residualExists) {
        ACTIVE_WORKSPACES.delete(rootPath);
      }
      return { cleaned: !residualExists, residualExists };
    } catch {
      return { cleaned: false, residualExists: fs.existsSync(rootPath) };
    }
  }

  public static async withWorkspace<T>(
    params: {
      jobId: string;
      filesMap: Record<string, string>;
      baseDir?: string;
      limits?: Partial<EphemeralWorkspaceLimits>;
    },
    fn: (handle: EphemeralWorkspaceHandle) => Promise<T> | T
  ): Promise<{ result: T; cleanupVerified: boolean }> {
    const handle = EphemeralWorkspaceManager.createWorkspace(params);
    try {
      const result = await fn(handle);
      const cleanupOutcome = handle.cleanup();
      return { result, cleanupVerified: cleanupOutcome.cleaned };
    } catch (err) {
      handle.cleanup();
      throw err;
    }
  }

  public static cleanupAllActiveWorkspaces(): { cleanedCount: number; failedPaths: string[] } {
    let cleanedCount = 0;
    const failedPaths: string[] = [];
    for (const wsPath of Array.from(ACTIVE_WORKSPACES)) {
      const res = EphemeralWorkspaceManager.cleanupWorkspacePath(wsPath);
      if (res.cleaned) {
        cleanedCount += 1;
      } else {
        failedPaths.push(wsPath);
      }
    }
    return { cleanedCount, failedPaths };
  }
}
