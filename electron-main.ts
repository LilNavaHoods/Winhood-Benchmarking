/**
 * WinHood Enterprise — Windows Desktop Main Process (Electron + Embedded Backend)
 *
 * Implements the mandatory sequential desktop lifecycle (Seções 9, 10, 11 e 13):
 * 1. Resolve writable per-user directory (`app.getPath('userData')` / `%APPDATA%\WinHood`).
 * 2. Ensure directory hierarchy (`database/`, `security/`, `keys/`, `reports/`, `sonar/`, `cache/`, `logs/`, `isolated_artifacts/`).
 * 3. Start embedded Express backend on `127.0.0.1` (port 3000 or dynamic fallback port if 3000 is busy).
 * 4. Poll `GET http://127.0.0.1:<port>/api/health` until `status === 'ONLINE' && ready === true`.
 * 5. Register validated IPC handlers with senderFrame origin verification.
 * 6. Create hardened `BrowserWindow` (`nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, `webSecurity: true`) and load `http://127.0.0.1:<port>`.
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

export function isAllowedExternalAuthUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:') return false;
    const host = parsed.hostname.toLowerCase();
    return host === 'github.com' || host === 'www.github.com';
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

export async function bootstrapWindowsDesktop(options?: {
  customDataDir?: string;
  preferredPort?: number;
  headlessCheckOnly?: boolean;
}) {
  process.env.WINHOOD_RUNTIME_ENV = 'ELECTRON_DESKTOP';
  const electron = loadElectronRuntime();
  const isElectronBinary = Boolean(electron?.app && electron?.BrowserWindow);

  // 1. Resolve writable userData directory (never inside Program Files)
  const rawUserData =
    options?.customDataDir ||
    (isElectronBinary ? electron.app.getPath('userData') : resolveWinHoodDataRoot());

  if (isReadOnlyProgramFilesPath(rawUserData)) {
    throw new Error(
      `FATAL_STORAGE_POLICY: Diretório de dados não pode residir em Program Files (${rawUserData}).`
    );
  }

  const layout = ensureWinHoodDirectories(rawUserData);
  process.env.WINHOOD_DATA_DIR = layout.rootDataDir;

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
  const startedBackend: StartedWinHoodServer = await startServer({
    dataDir: layout.rootDataDir,
    host: '127.0.0.1',
    port: options?.preferredPort ?? 3000,
    distPath: resolvedDistPath,
    environment: 'ELECTRON_DESKTOP',
    enableVite: false,
  });

  // 4. Verify real /api/health endpoint before opening window
  const health = await waitForBackendHealth({
    baseUrl: startedBackend.url,
    port: startedBackend.port,
  });

  if (!health.healthy) {
    await startedBackend.close().catch(() => {});
    throw new Error(
      `FATAL_BACKEND_HEALTH: Backend não respondeu em ${startedBackend.url}/api/health após ${health.attempts} tentativas (${health.errorMessage}).`
    );
  }

  const desktopWindowUrl = `http://localhost:${startedBackend.port}`;

  if (!isElectronBinary || options?.headlessCheckOnly) {
    return {
      mode: 'HEADLESS_VERIFIED' as const,
      backend: startedBackend,
      windowUrl: desktopWindowUrl,
      health,
      layout,
      securityWebPreferences: ELECTRON_SECURITY_WEB_PREFERENCES,
    };
  }

  const { app, BrowserWindow, ipcMain, session, shell } = electron;

  const hasSingleInstanceLock = app.requestSingleInstanceLock?.() ?? true;
  if (!hasSingleInstanceLock) {
    await startedBackend.close().catch(() => {});
    app.quit();
    return null;
  }

  await app.whenReady();

  // Ensure WebAuthn / FIDO2 / Windows Hello permissions on authorized loopback origin are not blocked
  if (session?.defaultSession) {
    const allowedPermissions = new Set([
      'publickey-credentials-get',
      'publickey-credentials-create',
      'clipboard-sanitized-write',
      'clipboard-read',
      'hid',
      'usb',
    ]);
    session.defaultSession.setPermissionCheckHandler?.(
      (webContents: any, permission: string, requestingOrigin: string) => {
        const originToCheck = requestingOrigin || webContents?.getURL?.() || '';
        if (!isAuthorizedLoopbackSender(originToCheck, startedBackend.url)) {
          return false;
        }
        return allowedPermissions.has(permission) || permission.startsWith('publickey');
      }
    );
    session.defaultSession.setPermissionRequestHandler?.(
      (webContents: any, permission: string, callback: (granted: boolean) => void, details: any) => {
        const originToCheck = details?.requestingUrl || webContents?.getURL?.() || '';
        if (!isAuthorizedLoopbackSender(originToCheck, startedBackend.url)) {
          callback(false);
          return;
        }
        callback(allowedPermissions.has(permission) || permission.startsWith('publickey'));
      }
    );
  }

  // 5. Register validated IPC handlers
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
      if (!isAllowedExternalAuthUrl(targetUrl)) {
        throw new Error('EXTERNAL_URL_FORBIDDEN: Apenas URLs HTTPS oficiais do GitHub são permitidas.');
      }
      if (shell?.openExternal) {
        await shell.openExternal(targetUrl);
      }
      return { opened: true };
    });
  }

  // 6. Create hardened BrowserWindow
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

  // 7. Navigation and popup hardening
  mainWindow.webContents.setWindowOpenHandler?.(({ url }: { url: string }) => {
    if (isAllowedExternalAuthUrl(url) && shell?.openExternal) {
      void shell.openExternal(url);
    }
    return { action: 'deny' };
  });
  mainWindow.webContents.on?.('will-navigate', (event: any, navigationUrl: string) => {
    if (!isAuthorizedLoopbackSender(navigationUrl, startedBackend.url)) {
      event.preventDefault();
    }
  });

  // Load via http://localhost:<port> so Windows Hello / WebAuthn FIDO2 accepts valid rpId="localhost"
  await mainWindow.loadURL(desktopWindowUrl);
  mainWindow.show();

  let shuttingDown = false;
  const shutdownCleanly = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
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

if (isDirectEntry || process.env.WINHOOD_DESKTOP_RUN === 'true') {
  bootstrapWindowsDesktop().catch((err) => {
    console.error('[WinHood Desktop Fatal Error]:', err);
    process.exitCode = 1;
  });
}
