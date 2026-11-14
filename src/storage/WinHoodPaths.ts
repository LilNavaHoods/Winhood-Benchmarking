import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export interface WinHoodDirectoryLayout {
  rootDataDir: string;
  databaseDir: string;
  securityDir: string;
  keysDir: string;
  reportsDir: string;
  sonarDir: string;
  cacheDir: string;
  logsDir: string;
  isolatedArtifactsDir: string;
  toolsRootDir: string;
}

export interface NodeSubprocessRuntimeSpec {
  executablePath: string;
  envOverrides: Record<string, string>;
  isBundledElectronRuntime: boolean;
}

/**
 * Resolves the writable per-user application data directory across Windows, Linux, and macOS.
 * On Windows desktop, defaults to `%APPDATA%\WinHood` (or `WINHOOD_DATA_DIR` / `userData` when provided by Electron).
 * Never writes mutable state to `Program Files` or read-only bundle paths.
 */
export function resolveWinHoodDataRoot(explicitDataDir?: string): string {
  const fromArg = (explicitDataDir || '').trim();
  if (fromArg) {
    return path.resolve(fromArg);
  }
  const fromEnv = (process.env.WINHOOD_DATA_DIR || '').trim();
  if (fromEnv) {
    return path.resolve(fromEnv);
  }
  const electronUserData = (process.env.WINHOOD_ELECTRON_USER_DATA || '').trim();
  if (electronUserData) {
    return path.resolve(electronUserData);
  }
  if (process.platform === 'win32' && process.env.WINHOOD_RUNTIME_ENV === 'ELECTRON_DESKTOP') {
    const appData = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
    return path.join(appData, 'WinHood');
  }
  return path.resolve(process.cwd(), '.winhood_data');
}

export function resolveWinHoodToolsRoot(explicitToolsDir?: string): string {
  const fromArg = (explicitToolsDir || '').trim();
  if (fromArg) {
    return path.resolve(fromArg);
  }
  const fromEnv = (process.env.WINHOOD_TOOLS_DIR || '').trim();
  if (fromEnv) {
    return path.resolve(fromEnv);
  }
  if (process.platform === 'win32') {
    const localAppData =
      process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    return path.join(localAppData, 'WinHood', 'tools');
  }
  return path.join(resolveWinHoodDataRoot(), 'tools');
}

export function getWinHoodDirectoryLayout(
  explicitDataDir?: string,
  explicitToolsDir?: string
): WinHoodDirectoryLayout {
  const rootDataDir = resolveWinHoodDataRoot(explicitDataDir);
  const toolsRootDir = resolveWinHoodToolsRoot(explicitToolsDir);
  return {
    rootDataDir,
    databaseDir: path.join(rootDataDir, 'database'),
    securityDir: path.join(rootDataDir, 'security'),
    keysDir: path.join(rootDataDir, 'keys'),
    reportsDir: path.join(rootDataDir, 'reports'),
    sonarDir: path.join(rootDataDir, 'sonar'),
    cacheDir: path.join(rootDataDir, 'cache'),
    logsDir: path.join(rootDataDir, 'logs'),
    isolatedArtifactsDir: path.join(rootDataDir, 'isolated_artifacts'),
    toolsRootDir,
  };
}

export function ensureWinHoodDirectories(
  explicitDataDir?: string,
  explicitToolsDir?: string
): WinHoodDirectoryLayout {
  const layout = getWinHoodDirectoryLayout(explicitDataDir, explicitToolsDir);
  const dirs = [
    layout.rootDataDir,
    layout.databaseDir,
    layout.securityDir,
    layout.keysDir,
    layout.reportsDir,
    layout.sonarDir,
    layout.cacheDir,
    layout.logsDir,
    layout.isolatedArtifactsDir,
  ];
  for (const dir of dirs) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
  }
  try {
    if (!fs.existsSync(layout.toolsRootDir)) {
      fs.mkdirSync(layout.toolsRootDir, { recursive: true, mode: 0o700 });
    }
  } catch {
    // Fallback if LOCALAPPDATA is restricted in container environments
  }
  return layout;
}

/**
 * Verifies that a target path is not inside `Program Files` or `Program Files (x86)` on Windows.
 */
export function isReadOnlyProgramFilesPath(targetPath: string): boolean {
  const normalized = targetPath.replace(/\//g, '\\').toLowerCase();
  return (
    normalized.includes('\\program files\\') ||
    normalized.includes('\\program files (x86)\\')
  );
}

/**
 * Resolves the Node.js runtime executable for child processes (`SandboxExecutor`, `ControlledTestAndPerfRunner`, etc.).
 * When packaged inside Electron on Windows (`process.versions.electron` is present), uses `process.execPath`
 * with `ELECTRON_RUN_AS_NODE=1` so the user does NOT need Node.js installed externally on Windows.
 */
export function resolveNodeRuntimeForSubprocess(): NodeSubprocessRuntimeSpec {
  const isElectronProcess = Boolean(
    process.versions && typeof process.versions.electron === 'string' && process.versions.electron.length > 0
  );
  if (isElectronProcess) {
    return {
      executablePath: process.execPath,
      envOverrides: {
        ELECTRON_RUN_AS_NODE: '1',
      },
      isBundledElectronRuntime: true,
    };
  }
  return {
    executablePath: process.execPath,
    envOverrides: {},
    isBundledElectronRuntime: false,
  };
}
