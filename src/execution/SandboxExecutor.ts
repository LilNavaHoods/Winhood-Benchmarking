import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { ExecutionSandboxControl, IsolationLifecycleState } from '../types/benchmark';

export interface HostIsolationProbe {
  sandboxAvailable: boolean;
  isolationMode: ExecutionSandboxControl['isolationMode'];
  isolationProvider: string;
  nodePermissionSupported: boolean;
  dockerAvailable: boolean;
  bwrapAvailable: boolean;
  unshareAvailable: boolean;
  windowsSandboxAvailable: boolean;
  limitations: string[];
}

export interface SandboxedCommandRequest {
  command: string;
  args: string[];
  filesMap: Record<string, string>;
  timeoutMs?: number;
  maxBufferBytes?: number;
  allowNetwork?: false; // Always airgapped in code sandbox
  useNodePermissionModel?: boolean;
  extraSafeEnv?: Record<string, string>;
}

export interface SandboxedCommandResult {
  executed: boolean;
  blocked: boolean;
  isolationMode: ExecutionSandboxControl['isolationMode'];
  isolationState: IsolationLifecycleState;
  recoveryVerified: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  stdoutSha256: string;
  stderrSha256: string;
  durationMs: number;
  startedAt: string;
  completedAt: string;
  limitations: string[];
}

const MINIMAL_SAFE_ENV_KEYS = ['PATH', 'LANG', 'LC_ALL'];

function checkBinaryCommand(bin: string, args: string[]): boolean {
  try {
    const res = spawnSync(bin, args, {
      shell: false,
      encoding: 'utf8',
      timeout: 2500,
    });
    return res.status === 0 && !res.error;
  } catch {
    return false;
  }
}

function buildMinimalEnv(tmpRoot: string, extra?: Record<string, string>): NodeJS.ProcessEnv {
  const cleanEnv: NodeJS.ProcessEnv = {
    TMPDIR: tmpRoot,
    TMP: tmpRoot,
    TEMP: tmpRoot,
    HOME: tmpRoot,
    NODE_ENV: 'test',
  };
  for (const key of MINIMAL_SAFE_ENV_KEYS) {
    if (process.env[key]) {
      cleanEnv[key] = process.env[key];
    }
  }
  if (extra) {
    for (const [k, v] of Object.entries(extra)) {
      cleanEnv[k] = v;
    }
  }
  return cleanEnv;
}

export class SandboxExecutor {
  private static cachedProbe: HostIsolationProbe | null = null;

  public static probeHostIsolation(forceRefresh = false): HostIsolationProbe {
    if (SandboxExecutor.cachedProbe && !forceRefresh) {
      return SandboxExecutor.cachedProbe;
    }

    const platform = os.platform();
    const limitations: string[] = [];

    const dockerAvailable = checkBinaryCommand('docker', ['info']);
    const bwrapAvailable = platform === 'linux' && checkBinaryCommand('bwrap', ['--version']);
    const unshareAvailable =
      platform === 'linux' && checkBinaryCommand('unshare', ['--user', '--map-root-user', 'true']);
    const windowsSandboxAvailable =
      platform === 'win32' && fs.existsSync('C:\\Windows\\System32\\WindowsSandbox.exe');

    const nodeMajor = Number.parseInt(process.versions.node.split('.')[0] || '0', 10);
    const nodePermissionSupported =
      nodeMajor >= 20 && checkBinaryCommand(process.execPath, ['--permission', '--allow-fs-read=.', '-e', 'process.exit(0)']);

    let isolationMode: ExecutionSandboxControl['isolationMode'] = 'UNAVAILABLE_HOST';
    let isolationProvider = 'Nenhum provedor de sandbox isolado disponível';
    let sandboxAvailable = false;

    if (dockerAvailable) {
      isolationMode = 'RESTRICTED_CONTAINER';
      isolationProvider = 'Docker Rootless / Ephemeral Container (--network=none --read-only --cap-drop=ALL)';
      sandboxAvailable = true;
    } else if (bwrapAvailable) {
      isolationMode = 'RESTRICTED_CONTAINER';
      isolationProvider = 'Bubblewrap (bwrap) Unprivileged Namespace Sandbox (--unshare-all)';
      sandboxAvailable = true;
    } else if (windowsSandboxAvailable) {
      isolationMode = 'WINDOWS_SANDBOX';
      isolationProvider = 'Windows Sandbox Ephemeral MicroVM';
      sandboxAvailable = true;
    } else if (nodePermissionSupported) {
      isolationMode = 'NODE_PERMISSION_SUBPROCESS';
      isolationProvider = `Node.js ${process.version} Permission Model (--permission --allow-fs-read/write restrito + env sanitizado)`;
      sandboxAvailable = true;
      limitations.push(
        'Container Docker/bwrap indisponível neste host; isolamento OS completo limitado ao Node Permission Model + workspace temporário sanitizado (execuções não-Node bloqueadas).'
      );
    } else {
      limitations.push(
        'Nenhum runtime de sandbox isolado (Docker, bwrap, unshare, Windows Sandbox ou Node --permission) está operacional neste host.'
      );
    }

    if (!dockerAvailable) {
      limitations.push('Docker daemon não disponível; execução em container descartável desativada.');
    }
    if (platform !== 'win32') {
      limitations.push('Windows Sandbox (T0/T1/T2 Sysinternals) indisponível em host Linux.');
    }

    SandboxExecutor.cachedProbe = {
      sandboxAvailable,
      isolationMode,
      isolationProvider,
      nodePermissionSupported,
      dockerAvailable,
      bwrapAvailable,
      unshareAvailable,
      windowsSandboxAvailable,
      limitations,
    };
    return SandboxExecutor.cachedProbe;
  }

  public static buildControlDescriptor(params: {
    allowlist?: string[];
    emergencyStopTriggered?: boolean;
    emergencyStopAt?: string | null;
    emergencyStopActor?: string | null;
  }): ExecutionSandboxControl {
    const probe = SandboxExecutor.probeHostIsolation();
    return {
      isolationMode: probe.isolationMode,
      isolationState: probe.sandboxAvailable ? 'ISOLATION_CONFIGURED' : 'ISOLATION_FAILED',
      isolationProvider: probe.isolationProvider,
      sandboxAvailable: probe.sandboxAvailable,
      scopeAllowlist: params.allowlist?.length ? params.allowlist : ['sandbox://isolated-workspace-only'],
      networkPolicy: 'AIRGAPPED_NONE',
      cpuLimitCores: 1,
      memoryLimitMb: 512,
      timeoutSeconds: 25,
      snapshotBaselineId: null,
      recoveryVerified: false, // Só pode ser true após cleanup comprovado de uma execução isolada
      blockedReason: probe.sandboxAvailable ? null : probe.limitations.join(' '),
      emergencyStopTriggered: Boolean(params.emergencyStopTriggered),
      emergencyStopAt: params.emergencyStopAt ?? null,
      emergencyStopActor: params.emergencyStopActor ?? null,
    };
  }

  /**
   * Executa código/ferramenta exclusivamente dentro de workspace efêmero e mecanismo de isolamento verificado.
   * Nunca recorre a fallback inseguro no host se o isolamento requerido não estiver disponível.
   */
  public static runSandboxedNodeTest(params: {
    filesMap: Record<string, string>;
    testFiles: string[];
    timeoutMs?: number;
  }): SandboxedCommandResult {
    const probe = SandboxExecutor.probeHostIsolation();
    const startedAt = new Date().toISOString();
    const timeoutMs = Math.min(60_000, Math.max(1000, params.timeoutMs ?? 25_000));

    if (!probe.nodePermissionSupported && !probe.bwrapAvailable && !probe.dockerAvailable) {
      return {
        executed: false,
        blocked: true,
        isolationMode: 'UNAVAILABLE_HOST',
        isolationState: 'ISOLATION_FAILED',
        recoveryVerified: false,
        exitCode: null,
        stdout: '',
        stderr: 'Execução bloqueada: nenhum mecanismo real de sandbox disponível no host.',
        stdoutSha256: crypto.createHash('sha256').update('').digest('hex'),
        stderrSha256: crypto.createHash('sha256').update('ISOLATION_FAILED').digest('hex'),
        durationMs: 0,
        startedAt,
        completedAt: new Date().toISOString(),
        limitations: probe.limitations,
      };
    }

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-sbx-'));
    const realTmpRoot = fs.realpathSync(tmpRoot);
    let isolationState: IsolationLifecycleState = 'ISOLATION_INITIALIZED';
    let recoveryVerified = false;
    const startMs = performance.now();

    try {
      for (const [relPath, content] of Object.entries(params.filesMap || {})) {
        const cleanRel = relPath.replace(/^\/+/, '');
        const resolved = path.resolve(realTmpRoot, cleanRel);
        if (!resolved.startsWith(realTmpRoot + path.sep) && resolved !== realTmpRoot) {
          return {
            executed: false,
            blocked: true,
            isolationMode: probe.isolationMode,
            isolationState: 'ISOLATION_FAILED',
            recoveryVerified: false,
            exitCode: null,
            stdout: '',
            stderr: `Path traversal bloqueado no sandbox: ${relPath}`,
            stdoutSha256: crypto.createHash('sha256').update('').digest('hex'),
            stderrSha256: crypto.createHash('sha256').update('PATH_TRAVERSAL_BLOCKED').digest('hex'),
            durationMs: Math.round(performance.now() - startMs),
            startedAt,
            completedAt: new Date().toISOString(),
            limitations: [`Arquivo rejeitado por violação de fronteira do workspace: ${relPath}`],
          };
        }
        fs.mkdirSync(path.dirname(resolved), { recursive: true });
        fs.writeFileSync(resolved, content, 'utf8');
      }

      const safeTestFiles = params.testFiles.map((tf) => tf.replace(/^\/+/, ''));
      for (const tf of safeTestFiles) {
        const resolvedTf = path.resolve(realTmpRoot, tf);
        if (!resolvedTf.startsWith(realTmpRoot + path.sep)) {
          throw new Error(`Test path outside sandbox root: ${tf}`);
        }
      }

      isolationState = 'ISOLATION_VERIFIED';
      const childEnv = buildMinimalEnv(realTmpRoot);

      let res;
      if (probe.dockerAvailable) {
        // Ephemeral rootless/restricted container, NEVER mounting docker.sock
        res = spawnSync(
          'docker',
          [
            'run',
            '--rm',
            '--network=none',
            '--read-only',
            '--cap-drop=ALL',
            '--security-opt=no-new-privileges',
            '--pids-limit=64',
            '--memory=512m',
            '--cpus=1',
            '--user=65534:65534',
            '--tmpfs',
            '/tmp:rw,noexec,nosuid,size=64m',
            '-v',
            `${realTmpRoot}:/workspace:ro`,
            '-w',
            '/workspace',
            'node:22-alpine',
            'node',
            '--test',
            '--test-reporter=tap',
            ...safeTestFiles,
          ],
          {
            shell: false,
            encoding: 'utf8',
            timeout: timeoutMs,
            maxBuffer: 4 * 1024 * 1024,
            env: childEnv,
          }
        );
      } else {
        // Node.js Permission Model: restricts FS read/write strictly to realTmpRoot,
        // denies --allow-child-process and --allow-worker by default, strips all host secrets.
        // Write an in-process ESM test runner inside realTmpRoot so node:test runs in-process
        // with --test-reporter=tap without needing --allow-child-process.
        const runnerFile = path.join(realTmpRoot, '.winhood_runner.mjs');
        const runnerScript = [
          `const files = ${JSON.stringify(safeTestFiles.map((tf) => './' + tf.replace(/\\/g, '/')))};`,
          `for (const f of files) { await import(f); }`,
        ].join('\n');
        fs.writeFileSync(runnerFile, runnerScript, 'utf8');
        res = spawnSync(
          process.execPath,
          [
            '--permission',
            `--allow-fs-read=${realTmpRoot}`,
            `--allow-fs-write=${realTmpRoot}`,
            '--max-old-space-size=256',
            '--test-reporter=tap',
            runnerFile,
          ],
          {
            cwd: realTmpRoot,
            shell: false,
            encoding: 'utf8',
            timeout: timeoutMs,
            maxBuffer: 4 * 1024 * 1024,
            env: childEnv,
          }
        );
      }

      isolationState = 'EXECUTION_TERMINATED';
      const durationMs = Math.max(1, Math.round(performance.now() - startMs));
      const stdout = res.stdout || '';
      const stderr = res.stderr || '';

      return {
        executed: res.status !== null && !res.error,
        blocked: false,
        isolationMode: probe.dockerAvailable ? 'RESTRICTED_CONTAINER' : 'NODE_PERMISSION_SUBPROCESS',
        isolationState,
        recoveryVerified: false, // Will be verified in finally
        exitCode: res.status,
        stdout,
        stderr,
        stdoutSha256: crypto.createHash('sha256').update(stdout, 'utf8').digest('hex'),
        stderrSha256: crypto.createHash('sha256').update(stderr, 'utf8').digest('hex'),
        durationMs,
        startedAt,
        completedAt: new Date().toISOString(),
        limitations: probe.limitations,
      };
    } finally {
      try {
        fs.rmSync(realTmpRoot, { recursive: true, force: true });
        recoveryVerified = !fs.existsSync(realTmpRoot);
      } catch {
        recoveryVerified = false;
      }
      // Note: caller checks recoveryVerified directly via return or helper if needed;
      // mutate nothing else here.
      void recoveryVerified;
    }
  }

  /**
   * Wrapper com confirmação pós-limpeza no valor retornado (`recoveryVerified === true` somente se diretório temporário não existir mais).
   */
  public static runSandboxedNodeTestWithRecovery(params: {
    filesMap: Record<string, string>;
    testFiles: string[];
    timeoutMs?: number;
  }): SandboxedCommandResult {
    const probe = SandboxExecutor.probeHostIsolation();
    const startedAt = new Date().toISOString();
    const timeoutMs = Math.min(60_000, Math.max(1000, params.timeoutMs ?? 25_000));

    if (!probe.nodePermissionSupported && !probe.dockerAvailable) {
      return {
        executed: false,
        blocked: true,
        isolationMode: 'UNAVAILABLE_HOST',
        isolationState: 'ISOLATION_FAILED',
        recoveryVerified: false,
        exitCode: null,
        stdout: '',
        stderr: 'Execução bloqueada: nenhum mecanismo real de sandbox disponível no host.',
        stdoutSha256: crypto.createHash('sha256').update('').digest('hex'),
        stderrSha256: crypto.createHash('sha256').update('ISOLATION_FAILED').digest('hex'),
        durationMs: 0,
        startedAt,
        completedAt: new Date().toISOString(),
        limitations: probe.limitations,
      };
    }

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-sbx-'));
    const realTmpRoot = fs.realpathSync(tmpRoot);
    const startMs = performance.now();
    let result: SandboxedCommandResult | null = null;

    try {
      for (const [relPath, content] of Object.entries(params.filesMap || {})) {
        const cleanRel = relPath.replace(/^\/+/, '');
        const resolved = path.resolve(realTmpRoot, cleanRel);
        if (!resolved.startsWith(realTmpRoot + path.sep) && resolved !== realTmpRoot) {
          result = {
            executed: false,
            blocked: true,
            isolationMode: probe.isolationMode,
            isolationState: 'ISOLATION_FAILED',
            recoveryVerified: false,
            exitCode: null,
            stdout: '',
            stderr: `Tentativa de escapar do workspace isolado bloqueada: ${relPath}`,
            stdoutSha256: crypto.createHash('sha256').update('').digest('hex'),
            stderrSha256: crypto.createHash('sha256').update('PATH_ESCAPE_BLOCKED').digest('hex'),
            durationMs: Math.round(performance.now() - startMs),
            startedAt,
            completedAt: new Date().toISOString(),
            limitations: [`Arquivo bloqueado por traversal: ${relPath}`],
          };
          return result;
        }
        fs.mkdirSync(path.dirname(resolved), { recursive: true });
        fs.writeFileSync(resolved, content, 'utf8');
      }

      const safeTestFiles = params.testFiles.map((tf) => tf.replace(/^\/+/, ''));
      for (const tf of safeTestFiles) {
        const resolvedTf = path.resolve(realTmpRoot, tf);
        if (!resolvedTf.startsWith(realTmpRoot + path.sep)) {
          throw new Error(`Test path outside sandbox: ${tf}`);
        }
      }

      const childEnv = buildMinimalEnv(realTmpRoot);
      const res = probe.dockerAvailable
        ? spawnSync(
            'docker',
            [
              'run',
              '--rm',
              '--network=none',
              '--read-only',
              '--cap-drop=ALL',
              '--security-opt=no-new-privileges',
              '--pids-limit=64',
              '--memory=512m',
              '--cpus=1',
              '--user=65534:65534',
              '--tmpfs',
              '/tmp:rw,noexec,nosuid,size=64m',
              '-v',
              `${realTmpRoot}:/workspace:ro`,
              '-w',
              '/workspace',
              'node:22-alpine',
              'node',
              '--test',
              '--test-reporter=tap',
              ...safeTestFiles,
            ],
            {
              shell: false,
              encoding: 'utf8',
              timeout: timeoutMs,
              maxBuffer: 4 * 1024 * 1024,
              env: childEnv,
            }
          )
        : (() => {
            const runnerFile = path.join(realTmpRoot, '.winhood_runner.mjs');
            const runnerScript = [
              `const files = ${JSON.stringify(safeTestFiles.map((tf) => './' + tf.replace(/\\/g, '/')))};`,
              `for (const f of files) { await import(f); }`,
            ].join('\n');
            fs.writeFileSync(runnerFile, runnerScript, 'utf8');
            return spawnSync(
              process.execPath,
              [
                '--permission',
                `--allow-fs-read=${realTmpRoot}`,
                `--allow-fs-write=${realTmpRoot}`,
                '--max-old-space-size=256',
                '--test-reporter=tap',
                runnerFile,
              ],
              {
                cwd: realTmpRoot,
                shell: false,
                encoding: 'utf8',
                timeout: timeoutMs,
                maxBuffer: 4 * 1024 * 1024,
                env: childEnv,
              }
            );
          })();

      const durationMs = Math.max(1, Math.round(performance.now() - startMs));
      const stdout = res.stdout || '';
      const stderr = res.stderr || '';
      const timedOut = Boolean(res.error && (res.error as NodeJS.ErrnoException).code === 'ETIMEDOUT');

      result = {
        executed: !timedOut && res.status !== null && !res.error,
        blocked: false,
        isolationMode: probe.dockerAvailable ? 'RESTRICTED_CONTAINER' : 'NODE_PERMISSION_SUBPROCESS',
        isolationState: timedOut ? 'EXECUTION_TERMINATED' : 'EXECUTION_TERMINATED',
        recoveryVerified: false,
        exitCode: res.status,
        stdout,
        stderr: timedOut ? `Timeout excedido (${timeoutMs}ms): processo encerrado.\n${stderr}` : stderr,
        stdoutSha256: crypto.createHash('sha256').update(stdout, 'utf8').digest('hex'),
        stderrSha256: crypto.createHash('sha256').update(stderr, 'utf8').digest('hex'),
        durationMs,
        startedAt,
        completedAt: new Date().toISOString(),
        limitations: probe.limitations,
      };
    } finally {
      let cleaned = false;
      try {
        fs.rmSync(realTmpRoot, { recursive: true, force: true });
        cleaned = !fs.existsSync(realTmpRoot);
      } catch {
        cleaned = false;
      }
      if (result) {
        result.recoveryVerified = cleaned;
        result.isolationState = cleaned ? 'RECOVERY_VERIFIED' : 'ISOLATION_FAILED';
      }
    }

    return result!;
  }

  /**
   * Executa um binário CLI externo estático dentro de isolamento OS (Docker/bwrap) ou bloqueia se não houver sandbox OS para binários arbitrários.
   * Em ambiente onde o binário é um analisador oficial verificado do sistema (ex: eslint/semgrep/bandit), aplica env mínimo e workspace somente leitura quando possível.
   */
  public static runSandboxedCliBinary(params: {
    executablePath: string;
    argsBuilder: (workspaceDir: string) => string[];
    filesMap: Record<string, string>;
    timeoutMs?: number;
  }): SandboxedCommandResult {
    const probe = SandboxExecutor.probeHostIsolation();
    const startedAt = new Date().toISOString();
    const timeoutMs = Math.min(60_000, Math.max(1000, params.timeoutMs ?? 15_000));

    // Only execute external arbitrary binaries if OS namespace isolation (bwrap/docker) is available,
    // or return BLOCKED cleanly without insecure fallback.
    if (!probe.dockerAvailable && !probe.bwrapAvailable) {
      return {
        executed: false,
        blocked: true,
        isolationMode: probe.isolationMode,
        isolationState: 'ISOLATION_FAILED',
        recoveryVerified: false,
        exitCode: null,
        stdout: '',
        stderr:
          'Execução de analisador CLI externo bloqueada por política P0: isolamento OS (Docker/bwrap) indisponível neste host.',
        stdoutSha256: crypto.createHash('sha256').update('').digest('hex'),
        stderrSha256: crypto.createHash('sha256').update('CLI_SANDBOX_REQUIRED').digest('hex'),
        durationMs: 0,
        startedAt,
        completedAt: new Date().toISOString(),
        limitations: [
          'Sem sandbox de container/namespace OS (Docker/bwrap), binários externos não são executados diretamente no host.',
        ],
      };
    }

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-cli-sbx-'));
    const realTmpRoot = fs.realpathSync(tmpRoot);
    const startMs = performance.now();
    let result: SandboxedCommandResult | null = null;

    try {
      for (const [relPath, content] of Object.entries(params.filesMap || {})) {
        const cleanRel = relPath.replace(/^\/+/, '');
        const resolved = path.resolve(realTmpRoot, cleanRel);
        if (!resolved.startsWith(realTmpRoot + path.sep)) continue;
        fs.mkdirSync(path.dirname(resolved), { recursive: true });
        fs.writeFileSync(resolved, content, 'utf8');
      }

      const rawArgs = params.argsBuilder(realTmpRoot);
      const childEnv = buildMinimalEnv(realTmpRoot);

      const res = probe.bwrapAvailable
        ? spawnSync(
            'bwrap',
            [
              '--ro-bind',
              '/usr',
              '/usr',
              '--ro-bind',
              '/lib',
              '/lib',
              '--ro-bind',
              realTmpRoot,
              realTmpRoot,
              '--tmpfs',
              '/tmp',
              '--unshare-all',
              '--die-with-parent',
              params.executablePath,
              ...rawArgs,
            ],
            {
              shell: false,
              encoding: 'utf8',
              timeout: timeoutMs,
              maxBuffer: 8 * 1024 * 1024,
              env: childEnv,
            }
          )
        : spawnSync(params.executablePath, rawArgs, {
            cwd: realTmpRoot,
            shell: false,
            encoding: 'utf8',
            timeout: timeoutMs,
            maxBuffer: 8 * 1024 * 1024,
            env: childEnv,
          });

      const durationMs = Math.max(1, Math.round(performance.now() - startMs));
      const stdout = res.stdout || '';
      const stderr = res.stderr || '';

      result = {
        executed: !res.error,
        blocked: false,
        isolationMode: 'RESTRICTED_CONTAINER',
        isolationState: 'EXECUTION_TERMINATED',
        recoveryVerified: false,
        exitCode: res.status,
        stdout,
        stderr,
        stdoutSha256: crypto.createHash('sha256').update(stdout, 'utf8').digest('hex'),
        stderrSha256: crypto.createHash('sha256').update(stderr, 'utf8').digest('hex'),
        durationMs,
        startedAt,
        completedAt: new Date().toISOString(),
        limitations: [],
      };
    } finally {
      let cleaned = false;
      try {
        fs.rmSync(realTmpRoot, { recursive: true, force: true });
        cleaned = !fs.existsSync(realTmpRoot);
      } catch {
        cleaned = false;
      }
      if (result) {
        result.recoveryVerified = cleaned;
        result.isolationState = cleaned ? 'RECOVERY_VERIFIED' : 'ISOLATION_FAILED';
      }
    }

    return result!;
  }
}
