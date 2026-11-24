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
  isAllowedExternalRepoUrl,
  isAuthorizedLoopbackSender,
  stripTrailingSlashes,
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

    const res4 = (await bridge.openExternalUrl('https://github.com/LilNavaHoods/Winhood-Benchmarking')) as unknown as {
      channel: string;
    };
    assert.equal(res4.channel, 'winhood:open-external-url');

    assert.equal(invoked.length, 4);
    assert.deepEqual(invoked[3], {
      channel: 'winhood:open-external-url',
      payload: { url: 'https://github.com/LilNavaHoods/Winhood-Benchmarking' },
    });
    // Ensure raw ipcRenderer or require is NOT exposed on bridge
    assert.equal('ipcRenderer' in bridge, false);
    assert.equal('require' in bridge, false);

    // Verify strict HTTPS GitHub repository allowlist for shell.openExternal (OAuth/Device URLs blocked)
    assert.equal(isAllowedExternalRepoUrl('https://github.com/LilNavaHoods/Winhood-Benchmarking'), true);
    assert.equal(isAllowedExternalRepoUrl('https://www.github.com/facebook/react'), true);
    assert.equal(isAllowedExternalRepoUrl('https://github.com/login/oauth/authorize?client_id=abc'), false);
    assert.equal(isAllowedExternalRepoUrl('https://www.github.com/login/device'), false);
    assert.equal(isAllowedExternalRepoUrl('https://evil.example.com/repo'), false);
    assert.equal(isAllowedExternalRepoUrl('http://github.com/facebook/react'), false);
    assert.equal(isAllowedExternalRepoUrl(`${'javascript'}:alert(1)`), false);
    assert.equal(isAllowedExternalRepoUrl('not-a-valid-url'), false);
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
      isAuthorizedLoopbackSender('http://localhost:3000/index.html', 'http://127.0.0.1:3000'),
      true
    );
    assert.equal(
      isAuthorizedLoopbackSender('http://127.0.0.1:3000/index.html', 'http://localhost:3000'),
      true
    );
    assert.equal(
      isAuthorizedLoopbackSender('http://localhost:4999/index.html', 'http://127.0.0.1:3000'),
      false
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
      assert.equal(desktopInstance.windowUrl, `http://localhost:${desktopInstance.backend.port}`);
      assert.ok(desktopInstance.runtimeStatusPath && fs.existsSync(desktopInstance.runtimeStatusPath));
      const runtimeStatus = JSON.parse(fs.readFileSync(desktopInstance.runtimeStatusPath, 'utf8')) as {
        port: number;
        ready: boolean;
        healthUrl: string;
      };
      assert.equal(runtimeStatus.port, desktopInstance.backend.port);
      assert.equal(runtimeStatus.ready, true);
      assert.equal(runtimeStatus.healthUrl, `${desktopInstance.backend.url}/api/health`);

      // Verify unrestricted local desktop access (no bootstrap_admin_token.txt or login gate)
      const healthRes = await fetch(`${desktopInstance.backend.url}/api/health`);
      assert.equal(healthRes.status, 200);
      const healthJson = (await healthRes.json()) as {
        accessMode?: string;
        deploymentMode?: string;
        totpEnabled?: boolean;
      };
      assert.equal(healthJson.accessMode, 'UNRESTRICTED_LOCAL');
      assert.equal(healthJson.deploymentMode, 'LOCAL_DESKTOP');
      assert.equal(healthJson.totpEnabled, false);

      // Verify /api/sonar/methodology-summary is reachable directly on the desktop backend without login
      const methRes = await fetch(
        `${desktopInstance.backend.url}/api/sonar/methodology-summary`
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
      const statusFilePath = desktopInstance?.runtimeStatusPath;
      if (desktopInstance?.backend) {
        await desktopInstance.backend.close().catch(() => {});
      }
      if (statusFilePath) {
        assert.equal(fs.existsSync(statusFilePath), false, 'runtime-status.json must be removed on clean shutdown');
      }
      await new Promise<void>((resolve) => blockerServer.close(() => resolve()));
      fs.rmSync(tmpUserData, { recursive: true, force: true });
    }
  });

  it('5. stripTrailingSlashes removes trailing slashes deterministically without super-linear regex backtracking', () => {
    assert.equal(stripTrailingSlashes('http://127.0.0.1:3000'), 'http://127.0.0.1:3000');
    assert.equal(stripTrailingSlashes('http://127.0.0.1:3000/'), 'http://127.0.0.1:3000');
    assert.equal(stripTrailingSlashes('http://127.0.0.1:3000///'), 'http://127.0.0.1:3000');
    assert.equal(stripTrailingSlashes('///'), '');
    assert.equal(stripTrailingSlashes(''), '');

    const startedAt = performance.now();
    const longInput = `http://127.0.0.1:3000${'/'.repeat(50000)}`;
    assert.equal(stripTrailingSlashes(longInput), 'http://127.0.0.1:3000');
    assert.ok(performance.now() - startedAt < 50);
  });

  it('6. Electron Builder, Inno Setup (.iss), build-exe.ps1, package.json and package-lock.json are 100% aligned on version 4.4.0 and release-windows paths', () => {
    const repoRoot = path.resolve(process.cwd());
    const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8')) as {
      name: string;
      version: string;
      scripts: Record<string, string>;
    };
    const lock = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package-lock.json'), 'utf8')) as {
      name: string;
      version: string;
    };
    const eb = JSON.parse(fs.readFileSync(path.join(repoRoot, 'electron-builder.json'), 'utf8')) as {
      directories?: { output?: string };
      files?: string[];
    };
    const iss = fs.readFileSync(path.join(repoRoot, 'installer', 'WinHoodBenchmarking.iss'), 'utf8');
    const ps1 = fs.readFileSync(path.join(repoRoot, 'build-exe.ps1'), 'utf8');
    const rootBat = fs.readFileSync(path.join(repoRoot, 'start-winhood-desktop.bat'), 'utf8');
    const scriptsBat = fs.readFileSync(
      path.join(repoRoot, 'scripts', 'windows', 'run-winhood-desktop.bat'),
      'utf8'
    );
    const termsMd = fs.readFileSync(path.join(repoRoot, 'TERMS.md'), 'utf8');
    const privacyMd = fs.readFileSync(path.join(repoRoot, 'PRIVACY.md'), 'utf8');
    const securityMd = fs.readFileSync(path.join(repoRoot, 'SECURITY.md'), 'utf8');

    assert.equal(pkg.name, 'winhood-benchmarking');
    assert.equal(lock.name, pkg.name);
    assert.equal(lock.version, pkg.version);
    assert.equal(eb.directories?.output, 'release-windows');
    assert.ok(Array.isArray(eb.files));
    for (const legalFile of ['LICENSE', 'PRIVACY.md', 'TERMS.md', 'SECURITY.md']) {
      assert.equal(eb.files.includes(legalFile), true, `Missing ${legalFile} in electron-builder.json files`);
    }

    // Verify multi-resolution public/icon.ico (16, 24, 32, 48, 64, 128, 256)
    const icoBuf = fs.readFileSync(path.join(repoRoot, 'public', 'icon.ico'));
    assert.equal(icoBuf.readUInt16LE(0), 0);
    assert.equal(icoBuf.readUInt16LE(2), 1);
    const icoCount = icoBuf.readUInt16LE(4);
    assert.equal(icoCount, 7);
    const icoSizes: number[] = [];
    for (let i = 0; i < icoCount; i++) {
      const w = icoBuf[6 + i * 16] || 256;
      icoSizes.push(w);
    }
    assert.deepEqual(icoSizes, [16, 24, 32, 48, 64, 128, 256]);

    // Verify TERMS.md, PRIVACY.md, SECURITY.md point to official GitHub issues/advisories without personal email
    assert.match(termsMd, /https:\/\/github\.com\/LilNavaHoods\/Winhood-Benchmarking\/issues/);
    assert.match(privacyMd, /https:\/\/github\.com\/LilNavaHoods\/Winhood-Benchmarking\/issues/);
    assert.match(securityMd, /https:\/\/github\.com\/LilNavaHoods\/Winhood-Benchmarking\/security\/advisories/);
    assert.equal(termsMd.includes('lohansilva351@gmail.com'), false);
    assert.equal(privacyMd.includes('lohansilva351@gmail.com'), false);
    assert.equal(securityMd.includes('lohansilva351@gmail.com'), false);

    assert.match(iss, /#define MyAppVersion "4\.4\.0"/);
    assert.match(iss, /LicenseFile=\.\.\\LICENSE/);
    assert.match(iss, /SetupIconFile=\.\.\\public\\icon\.ico/);
    assert.match(iss, /OutputDir=\.\.\\release-windows\\installer/);
    assert.match(iss, /OutputBaseFilename=WinHood-Benchmarking-Setup/);
    assert.match(iss, /Source: "\.\.\\release-windows\\win-unpacked\\\*"/);

    assert.equal(fs.existsSync(path.join(repoRoot, 'LICENSE')), true);
    assert.equal(fs.existsSync(path.join(repoRoot, 'PRIVACY.md')), true);
    assert.equal(fs.existsSync(path.join(repoRoot, 'TERMS.md')), true);
    assert.equal(fs.existsSync(path.join(repoRoot, 'SECURITY.md')), true);

    assert.match(ps1, /npm install/);
    assert.match(ps1, /release-windows\\win-unpacked/);
    assert.match(ps1, /release-windows\\installer\\WinHood-Benchmarking-Setup\.exe/);
    assert.match(rootBat, /release-windows\\win-unpacked\\WinHood Benchmark Analyzer\.exe/);
    assert.match(rootBat, /http:\/\/localhost:3000/);
    assert.match(scriptsBat, /start http:\/\/localhost:3000/);
    assert.ok(pkg.scripts['desktop:compile']);
    assert.ok(pkg.scripts['pack:win']);
    assert.ok(pkg.scripts['installer:win']);
    assert.ok(pkg.scripts['release:win']);
  });

  it('7. HairlineAnimatedFigure clock lifecycle respects prefers-reduced-motion, pauses on hidden visibilityState, and cleans up subscribers on unmount', async () => {
    const {
      subscribeClock,
      getHairlineClockDiagnostics,
    } = await import('../components/HairlineAnimatedFigure');

    const prevWindow = (globalThis as any).window;
    const prevDocument = (globalThis as any).document;

    let reducedMotionMatches = false;
    let docVisibilityState: 'visible' | 'hidden' = 'visible';
    const docListeners = new Map<string, Set<() => void>>();
    let nextRafId = 1;
    const activeRafs = new Map<number, (now: number) => void>();

    (globalThis as any).window = {
      matchMedia: () => ({
        get matches() {
          return reducedMotionMatches;
        },
        addEventListener: () => {},
        removeEventListener: () => {},
      }),
      requestAnimationFrame: (cb: (now: number) => void) => {
        const id = nextRafId++;
        activeRafs.set(id, cb);
        return id;
      },
      cancelAnimationFrame: (id: number) => {
        activeRafs.delete(id);
      },
    };

    (globalThis as any).document = {
      get visibilityState() {
        return docVisibilityState;
      },
      get hidden() {
        return docVisibilityState === 'hidden';
      },
      addEventListener: (evt: string, fn: () => void) => {
        if (!docListeners.has(evt)) docListeners.set(evt, new Set());
        docListeners.get(evt)!.add(fn);
      },
      removeEventListener: (evt: string, fn: () => void) => {
        docListeners.get(evt)?.delete(fn);
      },
    };

    try {
      // 1. When prefers-reduced-motion: reduce is active, subscribeClock is a no-op
      reducedMotionMatches = true;
      const unsubReduced = subscribeClock(() => {});
      assert.equal(getHairlineClockDiagnostics().subscriberCount, 0);
      assert.equal(getHairlineClockDiagnostics().isRunning, false);
      unsubReduced();

      // 2. Normal motion subscribes and starts single RAF loop
      reducedMotionMatches = false;
      let ticks = 0;
      const unsub1 = subscribeClock(() => {
        ticks += 1;
      });
      const unsub2 = subscribeClock(() => {
        ticks += 1;
      });
      assert.equal(getHairlineClockDiagnostics().subscriberCount, 2);
      assert.equal(getHairlineClockDiagnostics().isRunning, true);
      assert.equal(activeRafs.size, 1);

      // Step one frame (>32ms)
      const firstRaf = [...activeRafs.values()][0];
      activeRafs.clear();
      firstRaf(100);
      assert.equal(ticks, 2);

      // 3. Document becomes hidden -> visibilitychange stops RAF loop
      docVisibilityState = 'hidden';
      for (const fn of docListeners.get('visibilitychange') || []) {
        fn();
      }
      assert.equal(getHairlineClockDiagnostics().isRunning, false);
      assert.equal(activeRafs.size, 0);

      // 4. Document becomes visible -> visibilitychange resumes RAF loop
      docVisibilityState = 'visible';
      for (const fn of docListeners.get('visibilitychange') || []) {
        fn();
      }
      assert.equal(getHairlineClockDiagnostics().isRunning, true);

      // 5. Unmount all subscribers -> stops RAF and detaches visibilitychange listener
      unsub1();
      unsub2();
      assert.equal(getHairlineClockDiagnostics().subscriberCount, 0);
      assert.equal(getHairlineClockDiagnostics().isRunning, false);
      assert.equal(getHairlineClockDiagnostics().visibilityListenerAttached, false);
    } finally {
      if (prevWindow === undefined) delete (globalThis as any).window;
      else (globalThis as any).window = prevWindow;
      if (prevDocument === undefined) delete (globalThis as any).document;
      else (globalThis as any).document = prevDocument;
    }
  });
});
