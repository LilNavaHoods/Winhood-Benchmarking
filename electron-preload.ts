/**
 * WinHood Benchmark Analyzer — Secure Electron Preload Script
 *
 * Security Contract (Seção 11 & 13):
 * - Runs with contextIsolation: true, nodeIntegration: false, sandbox: true.
 * - Never exposes ipcRenderer, require, process, child_process, or fs to the renderer.
 * - Exposes only an explicit allowlist of read-only / controlled operations via contextBridge.
 */

import { createRequire } from 'node:module';

const ALLOWED_CHANNELS = new Set([
  'winhood:get-runtime-info',
  'winhood:get-backend-health',
  'winhood:open-logs-folder',
]);

function invokeAllowedChannel(
  ipcRenderer: { invoke: (channel: string, ...args: unknown[]) => Promise<unknown> },
  channel: string,
  payload?: Record<string, unknown>
): Promise<unknown> {
  if (!ALLOWED_CHANNELS.has(channel)) {
    return Promise.reject(new Error(`IPC_CHANNEL_FORBIDDEN: ${channel}`));
  }
  return ipcRenderer.invoke(channel, payload ?? {});
}

export function createWinHoodPreloadBridge(ipcRenderer: {
  invoke: (channel: string, ...args: unknown[]) => Promise<unknown>;
}) {
  return Object.freeze({
    isElectronDesktop: true,
    getRuntimeInfo: () => invokeAllowedChannel(ipcRenderer, 'winhood:get-runtime-info'),
    getBackendHealth: () => invokeAllowedChannel(ipcRenderer, 'winhood:get-backend-health'),
    openLogsFolder: () => invokeAllowedChannel(ipcRenderer, 'winhood:open-logs-folder'),
  });
}

try {
  const req =
    typeof require === 'function'
      ? require
      : createRequire(typeof __filename !== 'undefined' ? __filename : import.meta.url);
  const electron = req('electron') as {
    contextBridge?: {
      exposeInMainWorld: (apiKey: string, api: unknown) => void;
    };
    ipcRenderer?: {
      invoke: (channel: string, ...args: unknown[]) => Promise<unknown>;
    };
  };

  if (electron?.contextBridge && electron?.ipcRenderer) {
    const bridge = createWinHoodPreloadBridge(electron.ipcRenderer);
    electron.contextBridge.exposeInMainWorld('winhoodDesktop', bridge);
  }
} catch {
  // Executed outside Electron preload context (e.g., unit test validation)
}
