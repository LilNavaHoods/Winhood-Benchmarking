import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  ensureWinHoodDirectories,
  isReadOnlyProgramFilesPath,
  resolveNodeRuntimeForSubprocess,
} from '../storage/WinHoodPaths';
import { createWinHoodPreloadBridge } from '../../electron-preload';
import {
  ELECTRON_SECURITY_WEB_PREFERENCES,
  bootstrapWindowsDesktop,
  isAuthorizedLoopbackSender,
} from '../../electron-main';

describe('Windows Desktop Architecture, Electron Security & Lifecycle Suite (FASE 3, 4, 5 & Seção 15.2)', () => {
  it('1. WinHoodPaths creates complete per-user directory hierarchy and blocks Program Files paths', () => {
    const tmpUserData = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-userdata-'));
    try {
      const layout = ensureWinHoodDirectories(tmpUserData);
      assert.ok(fs.existsSync(layout.rootDataDir));
      assert.ok(fs.existsSync(layout.databaseDir));
      assert.ok(fs.existsSync(layout.securityDir));
      assert.ok(fs.existsSync(layout.keysDir));
      assert.ok(fs.existsSync(layout.reportsDir));
      assert.ok(fs.existsSync(layout.sonarDir));
      assert.ok(fs.existsSync(layout.cacheDir));
      assert.ok(fs.existsSync(layout.logsDir));
      assert.ok(fs.existsSync(layout.isolatedArtifactsDir));

      assert.equal(isReadOnlyProgramFilesPath('C:\\Program Files\\WinHood\\data'), true);
      assert.equal(isReadOnlyProgramFilesPath('C:\\Program Files (x86)\\WinHood\\data'), true);
      assert.equal(
        isReadOnlyProgramFilesPath('C:\\Users\\Alice\\AppData\\Roaming\\WinHood'),
        false
      );

      const runtimeSpec = resolveNodeRuntimeForSubprocess();
      assert.equal(typeof runtimeSpec.executablePath, 'string');
      assert.ok(runtimeSpec.executablePath.length > 0);
    } finally {
      fs.rmSync(tmpUserData, { recursive: true, force: true });
    }
  });

  it('2. Electron Preload Bridge enforces strict IPC channel allowlist and freezes API surface', async () => {
    const invoked: Array<{ channel: string; payload: unknown }> = [];
    const mockIpcRenderer = {
      invoke: async (channel: string, payload?: unknown) => {
        invoked.push({ channel, payload });
        return { ok: true, channel };
      },
    };

    const bridge = createWinHoodPreloadBridge(mockIpcRenderer);
    assert.equal(Object.isFrozen(bridge), true);
    assert.equal(bridge.isElectronDesktop, true);

    const res1 = (await bridge.getRuntimeInfo()) as { channel: string };
    assert.equal(res1.channel, 'winhood:get-runtime-info');

    const res2 = (await bridge.getBackendHealth()) as { channel: string };
    assert.equal(res2.channel, 'winhood:get-backend-health');

    const res3 = (await bridge.openLogsFolder()) as { channel: string };
    assert.equal(res3.channel, 'winhood:open-logs-folder');

    assert.equal(invoked.length, 3);
    // Ensure raw ipcRenderer or require is NOT exposed on bridge
    assert.equal('ipcRenderer' in bridge, false);
    assert.equal('require' in bridge, false);
  });

  it('3. Electron Main enforces hardened webPreferences and validates loopback IPC sender origin', () => {
    assert.equal(ELECTRON_SECURITY_WEB_PREFERENCES.nodeIntegration, false);
    assert.equal(ELECTRON_SECURITY_WEB_PREFERENCES.contextIsolation, true);
    assert.equal(ELECTRON_SECURITY_WEB_PREFERENCES.sandbox, true);
    assert.equal(ELECTRON_SECURITY_WEB_PREFERENCES.webSecurity, true);
    assert.equal(ELECTRON_SECURITY_WEB_PREFERENCES.allowRunningInsecureContent, false);

    assert.equal(
      isAuthorizedLoopbackSender('http://127.0.0.1:3000/index.html', 'http://127.0.0.1:3000'),
      true
    );
    assert.equal(
      isAuthorizedLoopbackSender('https://malicious.example.com/', 'http://127.0.0.1:3000'),
      false
    );
    assert.equal(isAuthorizedLoopbackSender(undefined, 'http://127.0.0.1:3000'), false);
  });

  it('4. bootstrapWindowsDesktop executes sequential startup, verifies /api/health, and falls back when preferred port is occupied', async () => {
    const tmpUserData = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-desktop-boot-'));

    // Occupy an ephemeral port to verify dynamic fallback when EADDRINUSE occurs
    const blockerServer = net.createServer();
    await new Promise<void>((resolve) =>
      blockerServer.listen(0, '127.0.0.1', () => resolve())
    );
    const occupiedPort = (blockerServer.address() as net.AddressInfo).port;

    let desktopInstance: Awaited<ReturnType<typeof bootstrapWindowsDesktop>> | null = null;
    try {
      desktopInstance = await bootstrapWindowsDesktop({
        customDataDir: tmpUserData,
        preferredPort: occupiedPort,
        headlessCheckOnly: true,
      });

      assert.ok(desktopInstance);
      assert.equal(desktopInstance.mode, 'HEADLESS_VERIFIED');
      assert.equal(desktopInstance.health.healthy, true);
      assert.equal(desktopInstance.health.status, 'ONLINE');
      assert.equal(desktopInstance.backend.host, '127.0.0.1');
      assert.notEqual(desktopInstance.backend.port, occupiedPort);
      assert.ok(desktopInstance.backend.port > 0);

      // Verify bootstrap_admin_token.txt was written inside per-user WinHoodPaths.rootDataDir
      const bootstrapTokenFile = path.join(
        desktopInstance.layout.rootDataDir,
        'bootstrap_admin_token.txt'
      );
      assert.equal(fs.existsSync(bootstrapTokenFile), true);
      const bootstrapToken =
        fs
          .readFileSync(bootstrapTokenFile, 'utf8')
          .split(/\r?\n/)
          .map((l) => l.trim())
          .find((l) => l && !l.startsWith('#')) || '';

      const bootRes = await fetch(`${desktopInstance.backend.url}/api/auth/bootstrap-admin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          bootstrapToken,
          name: 'Desktop Admin',
          email: 'desktop.admin@winhood.local',
          password: 'DesktopStrongPassword!2026',
        }),
      });
      assert.equal(bootRes.status, 201);
      const setCookies =
        typeof (bootRes.headers as any).getSetCookie === 'function'
          ? ((bootRes.headers as any).getSetCookie() as string[])
          : [bootRes.headers.get('set-cookie') || ''];
      const sessionCookie = setCookies
        .map((c) => c.split(';')[0].trim())
        .filter(Boolean)
        .join('; ');

      // Verify /api/sonar/methodology-summary is reachable on the desktop backend with real session cookie
      const methRes = await fetch(
        `${desktopInstance.backend.url}/api/sonar/methodology-summary`,
        {
          headers: { Cookie: sessionCookie },
        }
      );
      assert.equal(methRes.status, 200);
      const methJson = (await methRes.json()) as {
        scoreSeparation?: {
          nativeSonarMetrics?: { source?: string };
          winhoodCalculatedScore?: { source?: string };
        };
      };
      assert.equal(
        methJson.scoreSeparation?.winhoodCalculatedScore?.source,
        'WINHOOD_CALCULATED'
      );

      // Verify Program Files path is rejected by bootstrapWindowsDesktop
      await assert.rejects(
        () =>
          bootstrapWindowsDesktop({
            customDataDir: 'C:\\Program Files\\WinHood\\ForbiddenData',
            headlessCheckOnly: true,
          }),
        /FATAL_STORAGE_POLICY/
      );
    } finally {
      delete process.env.WINHOOD_RUNTIME_ENV;
      if (desktopInstance?.backend) {
        await desktopInstance.backend.close().catch(() => {});
      }
      await new Promise<void>((resolve) => blockerServer.close(() => resolve()));
      fs.rmSync(tmpUserData, { recursive: true, force: true });
    }
  });
});
