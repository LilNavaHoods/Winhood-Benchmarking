/**
 * WinHood Enterprise — Windows Desktop Main Process (Electron + Embedded Backend)
 *
 * Implements the mandatory sequential Local-First desktop lifecycle:
 * 1. Resolve writable per-user directory (`app.getPath('userData')` / `%APPDATA%\WinHood`).
 * 2. Ensure directory hierarchy (`database/`, `security/`, `keys/`, `reports/`, `sonar/`, `cache/`, `logs/`, `isolated_artifacts/`).
 * 3. Start embedded Express backend on `127.0.0.1` (port 3000 or dynamic fallback port if 3000 is busy).
 * 4. Poll `GET http://127.0.0.1:<port>/api/health` until `status === 'ONLINE' && ready === true`.
 * 5. Register validated IPC handlers with senderFrame origin verification.
 * 6. Create hardened `BrowserWindow` (`nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, `webSecurity: true`) and open directly in the workspace.
 * 7. Block unauthorized navigation and popups; cleanly close backend on application exit.
 */

import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer, type StartedWinHoodServer } from './server';
import {
  ensureWinHoodDirectories,
  isReadOnlyProgramFilesPath,
  resolveWinHoodDataRoot,
} from './src/storage/WinHoodPaths';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const ELECTRON_SECURITY_WEB_PREFERENCES = Object.freeze({
  nodeIntegration: false,
  contextIsolation: true,
  sandbox: true,
  webSecurity: true,
  allowRunningInsecureContent: false,
});

export interface DesktopHealthCheckResult {
  healthy: boolean;
  status: string;
  port: number;
  url: string;
  attempts: number;
  errorMessage?: string;
}

export function stripTrailingSlashes(rawUrl: string): string {
  let end = rawUrl.length;
  while (end > 0 && rawUrl.charCodeAt(end - 1) === 47) {
    end -= 1;
  }
  return end === rawUrl.length ? rawUrl : rawUrl.slice(0, end);
}

export async function waitForBackendHealth(params: {
  baseUrl: string;
  port: number;
  maxAttempts?: number;
  intervalMs?: number;
}): Promise<DesktopHealthCheckResult> {
  const maxAttempts = params.maxAttempts ?? 40;
  const intervalMs = params.intervalMs ?? 200;
  const healthUrl = `${stripTrailingSlashes(params.baseUrl)}/api/health`;
  let lastError = 'Health check ainda não respondeu.';

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 1500);
      const res = await fetch(healthUrl, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (res.ok) {
        const data = (await res.json()) as {
          status?: string;
          healthStatus?: string;
          ready?: boolean;
        };
        if (
          (data.status === 'ONLINE' || data.status === 'HEALTHY' || data.healthStatus === 'HEALTHY') &&
          data.ready !== false
        ) {
          return {
            healthy: true,
            status: 'ONLINE',
            port: params.port,
            url: params.baseUrl,
            attempts: attempt,
          };
        }
      } else {
        lastError = `HTTP ${res.status} em ${healthUrl}`;
      }
    } catch (err: any) {
      lastError = err?.message || 'Falha de conexão local.';
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }

  return {
    healthy: false,
    status: 'OFFLINE',
    port: params.port,
    url: params.baseUrl,
    attempts: maxAttempts,
    errorMessage: lastError,
  };
}

export function isAuthorizedLoopbackSender(
  senderUrl: string | undefined,
  expectedOrigin: string
): boolean {
  if (!senderUrl) return false;
  try {
    const parsedSender = new URL(senderUrl);
    const parsedExpected = new URL(expectedOrigin);
    if (parsedSender.protocol !== 'http:' || parsedExpected.protocol !== 'http:') {
      return false;
    }
    const senderPort = parsedSender.port || '80';
    const expectedPort = parsedExpected.port || '80';
    if (senderPort !== expectedPort) {
      return false;
    }
    const isSenderLoopback =
      parsedSender.hostname === 'localhost' || parsedSender.hostname === '127.0.0.1';
    const isExpectedLoopback =
      parsedExpected.hostname === 'localhost' || parsedExpected.hostname === '127.0.0.1';
    if (isSenderLoopback && isExpectedLoopback) {
      return true;
    }
    return parsedSender.origin === parsedExpected.origin;
  } catch {
    return false;
  }
}

/**
 * Allows opening external HTTPS repository/documentation URLs on github.com
 * while blocking OAuth/login redirect routes and non-HTTPS schemes.
 */
export function isAllowedExternalRepoUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:') return false;
    const host = parsed.hostname.toLowerCase();
    if (host !== 'github.com' && host !== 'www.github.com') return false;
    const lowerPath = parsed.pathname.toLowerCase();
    if (lowerPath.startsWith('/login/oauth') || lowerPath.startsWith('/login/device')) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

function loadElectronRuntime(): any | null {
  try {
    const req = createRequire(import.meta.url);
    const mod = req('electron');
    if (mod && typeof mod === 'object' && mod.app) {
      return mod;
    }
  } catch {
    // Not running inside Electron binary
  }
  return null;
}

function appendDesktopLog(logsDir: string, message: string): void {
  try {
    fs.mkdirSync(logsDir, { recursive: true });
    const logFile = path.join(logsDir, 'desktop-bootstrap.log');
    fs.appendFileSync(logFile, `[${new Date().toISOString()}] ${message}\n`, 'utf8');
  } catch {
    // Best-effort diagnostic logging
  }
}

export function writeDesktopRuntimeStatus(
  logsDir: string,
  payload: {
    pid: number;
    port: number;
    url: string;
    windowUrl: string;
    healthUrl: string;
    ready: boolean;
    startedAt: string;
    dataDir: string;
  }
): string {
  fs.mkdirSync(logsDir, { recursive: true });
  const statusFile = path.join(logsDir, 'runtime-status.json');
  const tmpFile = `${statusFile}.tmp-${process.pid}`;
  fs.writeFileSync(tmpFile, JSON.stringify(payload, null, 2), 'utf8');
  fs.renameSync(tmpFile, statusFile);
  return statusFile;
}

export function removeDesktopRuntimeStatus(logsDir: string): void {
  try {
    const statusFile = path.join(logsDir, 'runtime-status.json');
    if (fs.existsSync(statusFile)) {
      fs.unlinkSync(statusFile);
    }
  } catch {
    // Best-effort cleanup on shutdown
  }
}

export async function bootstrapWindowsDesktop(options?: {
  customDataDir?: string;
  preferredPort?: number;
  headlessCheckOnly?: boolean;
  readyTimeoutMs?: number;
  electronOverride?: any;
}) {
  process.env.WINHOOD_RUNTIME_ENV = 'ELECTRON_DESKTOP';
  const electron = options?.electronOverride ?? loadElectronRuntime();
  const isElectronBinary = Boolean(electron?.app && electron?.BrowserWindow);

  // 0. Acquire Single-Instance Lock BEFORE initializing data dirs, starting backend, or touching runtime-status.json (WH-AUD-008)
  let activeMainWindow: {
    isMinimized?: () => boolean;
    restore?: () => void;
    show?: () => void;
    focus?: () => void;
  } | null = null;

  if (isElectronBinary && !options?.headlessCheckOnly) {
    const hasSingleInstanceLock = electron.app.requestSingleInstanceLock?.() ?? true;
    if (!hasSingleInstanceLock) {
      electron.app.quit?.();
      return null;
    }
    electron.app.on?.('second-instance', () => {
      if (activeMainWindow) {
        if (activeMainWindow.isMinimized?.()) {
          activeMainWindow.restore?.();
        }
        activeMainWindow.show?.();
        activeMainWindow.focus?.();
      }
    });
  }

  // 1. Resolve writable userData directory (honors explicit customDataDir & WINHOOD_DATA_DIR, never Program Files)
  const envDataDir = (process.env.WINHOOD_DATA_DIR || '').trim();
  const rawUserData =
    options?.customDataDir ||
    envDataDir ||
    (isElectronBinary ? electron.app.getPath('userData') : resolveWinHoodDataRoot());

  if (isReadOnlyProgramFilesPath(rawUserData)) {
    throw new Error(
      `FATAL_STORAGE_POLICY: Diretório de dados não pode residir em Program Files (${rawUserData}).`
    );
  }

  const layout = ensureWinHoodDirectories(rawUserData);
  process.env.WINHOOD_DATA_DIR = layout.rootDataDir;
  appendDesktopLog(
    layout.logsDir,
    `Starting WinHood Desktop bootstrap (pid=${process.pid}, electron=${isElectronBinary}, dataDir=${layout.rootDataDir})`
  );

  // 2. Resolve frontend dist directory
  const candidateDistPaths = [
    path.resolve(__dirname, 'dist'),
    path.resolve(__dirname, '..', 'dist'),
    path.resolve(process.cwd(), 'dist'),
  ];
  const resolvedDistPath =
    candidateDistPaths.find((p) => fs.existsSync(path.join(p, 'index.html'))) ||
    candidateDistPaths[0];

  // 3. Start embedded backend on loopback 127.0.0.1
  const envPreferredPort = Number.parseInt(process.env.WINHOOD_DESKTOP_PORT || '', 10);
  const preferredPort =
    options?.preferredPort !== undefined
      ? options.preferredPort
      : Number.isInteger(envPreferredPort) && envPreferredPort >= 0 && envPreferredPort <= 65535
        ? envPreferredPort
        : 3000;

  const startedBackend: StartedWinHoodServer = await startServer({
    dataDir: layout.rootDataDir,
    host: '127.0.0.1',
    port: preferredPort,
    distPath: resolvedDistPath,
    deploymentMode: 'LOCAL_DESKTOP',
    environment: 'ELECTRON_DESKTOP',
    enableVite: false,
  });

  // 4. Verify real /api/health endpoint before opening window
  const timeoutMs =
    options?.readyTimeoutMs ??
    Math.max(
      2000,
      Number.parseInt(process.env.WINHOOD_BACKEND_READY_TIMEOUT_MS || '20000', 10) || 20000
    );
  const intervalMs = 200;
  const maxAttempts = Math.max(5, Math.ceil(timeoutMs / intervalMs));

  const health = await waitForBackendHealth({
    baseUrl: startedBackend.url,
    port: startedBackend.port,
    maxAttempts,
    intervalMs,
  });

  if (!health.healthy) {
    appendDesktopLog(
      layout.logsDir,
      `FATAL_BACKEND_HEALTH: ${startedBackend.url}/api/health failed after ${health.attempts} attempts (${health.errorMessage || 'unknown'})`
    );
    await startedBackend.close().catch(() => {});
    throw new Error(
      `FATAL_BACKEND_HEALTH: Backend não respondeu em ${startedBackend.url}/api/health após ${health.attempts} tentativas (${health.errorMessage}).`
    );
  }

  const desktopWindowUrl = `http://localhost:${startedBackend.port}`;
  const healthUrl = `${stripTrailingSlashes(startedBackend.url)}/api/health`;
  const runtimeStatusPath = writeDesktopRuntimeStatus(layout.logsDir, {
    pid: process.pid,
    port: startedBackend.port,
    url: startedBackend.url,
    windowUrl: desktopWindowUrl,
    healthUrl,
    ready: true,
    startedAt: new Date().toISOString(),
    dataDir: layout.rootDataDir,
  });
  appendDesktopLog(
    layout.logsDir,
    `Backend healthy on ${healthUrl} (attempts=${health.attempts}, statusFile=${runtimeStatusPath})`
  );

  if (!isElectronBinary || options?.headlessCheckOnly) {
    const originalClose = startedBackend.close;
    startedBackend.close = async () => {
      removeDesktopRuntimeStatus(layout.logsDir);
      await originalClose();
    };
    return {
      mode: 'HEADLESS_VERIFIED' as const,
      backend: startedBackend,
      windowUrl: desktopWindowUrl,
      runtimeStatusPath,
      health,
      layout,
      securityWebPreferences: ELECTRON_SECURITY_WEB_PREFERENCES,
    };
  }

  const { app, BrowserWindow, ipcMain, session, shell } = electron;

  await app.whenReady();

  // Strict permission allowlist for loopback Electron desktop window
  if (session?.defaultSession) {
    const allowedPermissions = new Set(['clipboard-sanitized-write', 'clipboard-read']);
    session.defaultSession.setPermissionCheckHandler?.(
      (webContents: any, permission: string, requestingOrigin: string) => {
        const originToCheck = requestingOrigin || webContents?.getURL?.() || '';
        if (!isAuthorizedLoopbackSender(originToCheck, startedBackend.url)) {
          return false;
        }
        return allowedPermissions.has(permission);
      }
    );
    session.defaultSession.setPermissionRequestHandler?.(
      (webContents: any, permission: string, callback: (granted: boolean) => void, details: any) => {
        const originToCheck = details?.requestingUrl || webContents?.getURL?.() || '';
        if (!isAuthorizedLoopbackSender(originToCheck, startedBackend.url)) {
          callback(false);
          return;
        }
        callback(allowedPermissions.has(permission));
      }
    );
  }

  // 6. Register validated IPC handlers
  const preloadCandidates = [
    path.resolve(__dirname, 'electron-preload.cjs'),
    path.resolve(__dirname, 'electron-preload.js'),
    path.resolve(__dirname, 'dist-desktop', 'electron-preload.cjs'),
  ];
  const resolvedPreloadPath =
    preloadCandidates.find((p) => fs.existsSync(p)) || preloadCandidates[0];

  if (ipcMain?.handle) {
    ipcMain.handle('winhood:get-runtime-info', (event: any) => {
      const senderUrl = event?.senderFrame?.url;
      if (!isAuthorizedLoopbackSender(senderUrl, startedBackend.url)) {
        throw new Error('UNAUTHORIZED_IPC_SENDER');
      }
      return {
        platform: process.platform,
        arch: process.arch,
        electronVersion: process.versions.electron || null,
        nodeVersion: process.versions.node,
        backendUrl: desktopWindowUrl,
        backendPort: startedBackend.port,
        userDataDir: layout.rootDataDir,
      };
    });

    ipcMain.handle('winhood:get-backend-health', async (event: any) => {
      const senderUrl = event?.senderFrame?.url;
      if (!isAuthorizedLoopbackSender(senderUrl, startedBackend.url)) {
        throw new Error('UNAUTHORIZED_IPC_SENDER');
      }
      return waitForBackendHealth({
        baseUrl: startedBackend.url,
        port: startedBackend.port,
        maxAttempts: 3,
        intervalMs: 100,
      });
    });

    ipcMain.handle('winhood:open-logs-folder', async (event: any) => {
      const senderUrl = event?.senderFrame?.url;
      if (!isAuthorizedLoopbackSender(senderUrl, startedBackend.url)) {
        throw new Error('UNAUTHORIZED_IPC_SENDER');
      }
      if (shell?.openPath) {
        await shell.openPath(layout.logsDir);
      }
      return { opened: true, logsDir: layout.logsDir };
    });

    ipcMain.handle('winhood:open-external-url', async (event: any, payload?: { url?: string }) => {
      const senderUrl = event?.senderFrame?.url;
      if (!isAuthorizedLoopbackSender(senderUrl, startedBackend.url)) {
        throw new Error('UNAUTHORIZED_IPC_SENDER');
      }
      const targetUrl = typeof payload?.url === 'string' ? payload.url.trim() : '';
      if (!isAllowedExternalRepoUrl(targetUrl)) {
        throw new Error(
          'EXTERNAL_URL_FORBIDDEN: Apenas URLs HTTPS de repositórios públicos do GitHub são permitidas.'
        );
      }
      if (shell?.openExternal) {
        await shell.openExternal(targetUrl);
      }
      return { opened: true };
    });
  }

  // 7. Create hardened BrowserWindow
  const mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#0b1120',
    title: 'WinHood Benchmark & Quality Analyzer',
    show: false,
    webPreferences: {
      ...ELECTRON_SECURITY_WEB_PREFERENCES,
      preload: resolvedPreloadPath,
    },
  });
  activeMainWindow = mainWindow;

  // 8. Navigation and popup hardening
  mainWindow.webContents.setWindowOpenHandler?.(({ url }: { url: string }) => {
    if (isAllowedExternalRepoUrl(url) && shell?.openExternal) {
      void shell.openExternal(url);
    }
    return { action: 'deny' };
  });
  mainWindow.webContents.on?.('will-navigate', (event: any, navigationUrl: string) => {
    if (!isAuthorizedLoopbackSender(navigationUrl, startedBackend.url)) {
      event.preventDefault();
    }
  });

  await mainWindow.loadURL(desktopWindowUrl);
  mainWindow.show();

  let shuttingDown = false;
  const shutdownCleanly = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    appendDesktopLog(layout.logsDir, `Shutting down embedded backend on port ${startedBackend.port}`);
    removeDesktopRuntimeStatus(layout.logsDir);
    await startedBackend.close().catch(() => {});
  };

  app.on('before-quit', () => {
    void shutdownCleanly();
  });

  app.on('window-all-closed', () => {
    void shutdownCleanly().finally(() => {
      if (process.platform !== 'darwin') {
        app.quit();
      }
    });
  });

  return {
    mode: 'ELECTRON_WINDOW_ACTIVE' as const,
    backend: startedBackend,
    windowUrl: desktopWindowUrl,
    runtimeStatusPath,
    health,
    layout,
    securityWebPreferences: ELECTRON_SECURITY_WEB_PREFERENCES,
  };
}

const isDirectEntry =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  Boolean(process.argv[1]) &&
  path.resolve(process.argv[1]) === __filename;

// In packaged Windows/macOS/Linux Electron executables, process.argv[1] is omitted (defaultApp !== true).
const isPackagedElectronMain =
  typeof process !== 'undefined' &&
  Boolean(process.versions?.electron) &&
  !process.env.NODE_TEST_CONTEXT &&
  (process as NodeJS.Process & { defaultApp?: boolean }).defaultApp !== true;

if (isDirectEntry || isPackagedElectronMain || process.env.WINHOOD_DESKTOP_RUN === 'true') {
  bootstrapWindowsDesktop().catch((err) => {
    const fallbackLogsDir = path.join(
      process.env.WINHOOD_DATA_DIR || resolveWinHoodDataRoot(),
      'logs'
    );
    appendDesktopLog(
      fallbackLogsDir,
      `FATAL_BOOTSTRAP_ERROR: ${err instanceof Error ? err.message : String(err)}`
    );
    console.error('[WinHood Desktop Fatal Error]:', err);
    process.exitCode = 1;
  });
}
