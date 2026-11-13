import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import type { SonarScannerType } from '../../types/benchmark';

export interface SonarReportTaskMetadata {
  projectKey: string;
  serverUrl: string;
  serverVersion?: string;
  dashboardUrl?: string;
  ceTaskId: string;
  ceTaskUrl?: string;
  reportTaskPath: string;
}

export interface ExecuteSonarScannerParams {
  scannerType: SonarScannerType;
  executablePath: string;
  projectBaseDir: string;
  propertiesContent: string;
  sonarToken?: string;
  timeoutMs?: number;
  maxMemoryMb?: number;
}

export interface ExecuteSonarScannerResult {
  executed: boolean;
  exitCode: number | null;
  timedOut: boolean;
  durationMs: number;
  stdout: string;
  stderr: string;
  reportTask: SonarReportTaskMetadata | null;
  errorMessage: string | null;
}

/**
 * SonarScannerExecutor (P0)
 * Executes an official SonarScanner binary in an isolated child process (shell: false),
 * passes SONAR_TOKEN strictly via environment variables (never CLI args or properties file),
 * enforces timeout and memory bounds, and parses .scannerwork/report-task.txt to recover
 * the real Compute Engine ceTaskId.
 */
export class SonarScannerExecutor {
  public static parseReportTaskFile(reportTaskPath: string): SonarReportTaskMetadata | null {
    try {
      if (!fs.existsSync(reportTaskPath)) return null;
      const raw = fs.readFileSync(reportTaskPath, 'utf8');
      const map: Record<string, string> = {};
      for (const line of raw.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eq = trimmed.indexOf('=');
        if (eq > 0) {
          map[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
        }
      }
      if (!map.ceTaskId || !map.projectKey) return null;
      return {
        projectKey: map.projectKey,
        serverUrl: map.serverUrl || '',
        serverVersion: map.serverVersion,
        dashboardUrl: map.dashboardUrl,
        ceTaskId: map.ceTaskId,
        ceTaskUrl: map.ceTaskUrl,
        reportTaskPath,
      };
    } catch {
      return null;
    }
  }

  public static async executeIsolatedScanner(
    params: ExecuteSonarScannerParams
  ): Promise<ExecuteSonarScannerResult> {
    const startMs = performance.now();
    const timeoutMs = params.timeoutMs ?? 120_000;
    const maxMemMb = params.maxMemoryMb ?? 1024;

    if (!params.projectBaseDir || !fs.existsSync(params.projectBaseDir)) {
      return {
        executed: false,
        exitCode: null,
        timedOut: false,
        durationMs: 0,
        stdout: '',
        stderr: '',
        reportTask: null,
        errorMessage: `Diretório base do projeto não existe no host: ${params.projectBaseDir}`,
      };
    }

    if (!params.executablePath) {
      return {
        executed: false,
        exitCode: null,
        timedOut: false,
        durationMs: 0,
        stdout: '',
        stderr: '',
        reportTask: null,
        errorMessage: `Executável do scanner (${params.scannerType}) não localizado.`,
      };
    }

    // Write sonar-project.properties safely (never includes SONAR_TOKEN)
    const propsFilePath = path.join(params.projectBaseDir, 'sonar-project.properties');
    fs.writeFileSync(propsFilePath, params.propertiesContent, 'utf8');

    const childEnv: NodeJS.ProcessEnv = {
      ...process.env,
      SONAR_SCANNER_OPTS: `-Xmx${maxMemMb}m`,
    };
    if (params.sonarToken && params.sonarToken.trim().length > 0) {
      childEnv.SONAR_TOKEN = params.sonarToken.trim();
    } else {
      delete childEnv.SONAR_TOKEN;
    }

    let command = params.executablePath;
    let args: string[] = [`-Dproject.settings=${propsFilePath}`];

    if (params.scannerType === 'SONAR_SCANNER_MAVEN') {
      command = params.executablePath;
      args = ['sonar:sonar', '-B'];
    } else if (params.scannerType === 'SONAR_SCANNER_GRADLE') {
      command = params.executablePath;
      args = ['sonar', '--no-daemon'];
    } else if (params.scannerType === 'SONAR_SCANNER_NPM') {
      command = 'npx';
      args = ['--yes', '@sonar/scan', `-Dproject.settings=${propsFilePath}`];
    }

    return new Promise((resolve) => {
      let stdout = '';
      let stderr = '';
      let timedOut = false;

      let child;
      try {
        child = spawn(command, args, {
          cwd: params.projectBaseDir,
          env: childEnv,
          shell: false,
          stdio: ['ignore', 'pipe', 'pipe'],
        });
      } catch (err: any) {
        resolve({
          executed: false,
          exitCode: null,
          timedOut: false,
          durationMs: Math.round(performance.now() - startMs),
          stdout: '',
          stderr: '',
          reportTask: null,
          errorMessage: `Falha ao iniciar processo isolado do scanner: ${err?.message || String(err)}`,
        });
        return;
      }

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
      }, timeoutMs);

      child.stdout?.on('data', (chunk: Buffer) => {
        if (stdout.length < 32_000) stdout += chunk.toString('utf8');
      });
      child.stderr?.on('data', (chunk: Buffer) => {
        if (stderr.length < 16_000) stderr += chunk.toString('utf8');
      });

      const redact = (s: string) =>
        params.sonarToken
          ? s.split(params.sonarToken).join('[SONAR_TOKEN_REDACTED]')
          : s;

      child.on('error', (err) => {
        clearTimeout(timer);
        resolve({
          executed: false,
          exitCode: null,
          timedOut,
          durationMs: Math.round(performance.now() - startMs),
          stdout: redact(stdout),
          stderr: redact(stderr),
          reportTask: null,
          errorMessage: err.message,
        });
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        const durationMs = Math.max(1, Math.round(performance.now() - startMs));
        const reportTaskCandidates = [
          path.join(params.projectBaseDir, '.scannerwork', 'report-task.txt'),
          path.join(params.projectBaseDir, 'target', 'sonar', 'report-task.txt'),
          path.join(params.projectBaseDir, 'build', 'sonar', 'report-task.txt'),
        ];
        let reportTask: SonarReportTaskMetadata | null = null;
        for (const candidate of reportTaskCandidates) {
          const parsed = SonarScannerExecutor.parseReportTaskFile(candidate);
          if (parsed) {
            reportTask = parsed;
            break;
          }
        }

        resolve({
          executed: true,
          exitCode: code,
          timedOut,
          durationMs,
          stdout: redact(stdout),
          stderr: redact(stderr),
          reportTask,
          errorMessage: timedOut
            ? `Scanner excedeu o timeout configurado de ${timeoutMs}ms.`
            : code !== 0
              ? `Scanner retornou código de saída ${code}.`
              : null,
        });
      });
    });
  }
}
