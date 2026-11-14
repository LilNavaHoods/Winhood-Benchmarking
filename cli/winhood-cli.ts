#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { AnalyzerRegistry } from '../src/analyzers/AnalyzerRegistry';
import { RULE_ENGINE_VERSION, RuleRegistry } from '../src/analyzers/RuleRegistry';
import { SarifCodec } from '../src/analyzers/SarifCodec';
import { SbomGenerator } from '../src/analyzers/sca/SbomGenerator';
import { DEFAULT_ENTERPRISE_LICENSE_POLICY, ScaCorrelator } from '../src/analyzers/sca/ScaCorrelator';
import { QualityGateEngine } from '../src/gate/QualityGateEngine';
import type { Software } from '../src/types/benchmark';

export const WINHOOD_CLI_VERSION = '4.3.0';

const SUPPORTED_EXTS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.java', '.go', '.cs', '.rs', '.sql',
  '.tf', '.tfvars', '.yaml', '.yml', '.dockerfile',
  '.json', '.toml', '.xml', '.csproj', '.txt',
]);

function collectFilesRecursively(rootDir: string, currentDir = rootDir, acc: Record<string, string> = {}): Record<string, string> {
  const entries = fs.readdirSync(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist' || entry.name === 'dist-desktop') {
      continue;
    }
    const full = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      collectFilesRecursively(rootDir, full, acc);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      const base = entry.name.toLowerCase();
      if (SUPPORTED_EXTS.has(ext) || base === 'dockerfile' || base === 'requirements.txt' || base === 'go.mod') {
        const rel = path.relative(rootDir, full).replace(/\\/g, '/');
        const stat = fs.statSync(full);
        if (stat.size <= 512 * 1024) {
          acc[rel] = fs.readFileSync(full, 'utf8');
        }
      }
    }
  }
  return acc;
}

export interface CliResult {
  exitCode: 0 | 1 | 2 | 3;
  stdout: string;
  stderr: string;
}

export async function runCli(argv: string[]): Promise<CliResult> {
  const [command = 'help', ...rest] = argv;
  const argsMap = new Map<string, string>();
  const flags = new Set<string>();
  const positional: string[] = [];

  for (let i = 0; i < rest.length; i++) {
    const token = rest[i]!;
    if (token.startsWith('--')) {
      const eq = token.indexOf('=');
      if (eq > 0) {
        argsMap.set(token.slice(2, eq), token.slice(eq + 1));
      } else {
        const next = rest[i + 1];
        if (next && !next.startsWith('--')) {
          argsMap.set(token.slice(2), next);
          i += 1;
        } else {
          flags.add(token.slice(2));
        }
      }
    } else {
      positional.push(token);
    }
  }

  try {
    if (command === '--version' || command === 'version') {
      return {
        exitCode: 0,
        stdout: JSON.stringify({ cliVersion: WINHOOD_CLI_VERSION, engineVersion: RULE_ENGINE_VERSION }),
        stderr: '',
      };
    }

    if (command === 'rules') {
      const snapshot = RuleRegistry.getCatalogSnapshot();
      return { exitCode: 0, stdout: JSON.stringify(snapshot, null, 2), stderr: '' };
    }

    if (command === 'sarif-import') {
      const file = argsMap.get('input') || positional[0];
      if (!file || !fs.existsSync(file)) {
        return { exitCode: 3, stdout: '', stderr: 'Missing or unreadable --input <sarif.json> path.' };
      }
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      const imported = SarifCodec.importSarif210(raw, {
        runId: argsMap.get('run-id') || 'cli-sarif-import',
        softwareId: 'cli-target',
        softwareName: path.basename(path.dirname(path.resolve(file))),
        softwareVersion: 'local',
      });
      return {
        exitCode: imported.valid ? 0 : 3,
        stdout: JSON.stringify(imported, null, 2),
        stderr: imported.valid ? '' : imported.errors.join('; '),
      };
    }

    if (command === 'analyze' || command === 'gate' || command === 'sbom') {
      const targetDir = path.resolve(argsMap.get('path') || positional[0] || '.');
      if (!fs.existsSync(targetDir)) {
        return { exitCode: 3, stdout: '', stderr: `Target path does not exist: ${targetDir}` };
      }
      const filesMap = collectFilesRecursively(targetDir);
      const deterministicTs = argsMap.get('deterministic-ts') || (flags.has('deterministic') ? '2026-11-14T00:00:00.000Z' : undefined);
      const softwareName = argsMap.get('name') || path.basename(targetDir);
      const softwareVersion = argsMap.get('software-version') || '1.0.0';

      const swStub = {
        id: 'cli-sw',
        projectId: 'cli-proj',
        name: softwareName,
        vendor: 'Local',
        description: 'CLI analyzed workspace',
        version: softwareVersion,
        languages: [],
        architecture: 'Unknown',
        operatingSystem: process.platform,
        distributionModel: 'Source',
        licenseType: 'Unknown',
        officialUrl: '',
        repositoryUrl: '',
        documentationUrl: '',
        owner: 'cli',
        notes: '',
        sourceType: 'LOCAL_AUTHORIZED',
        commitHash: 'LOCAL_HEAD',
        packageSha256: 'LOCAL_WORKSPACE',
        createdAt: deterministicTs || new Date().toISOString(),
        inventory: {
          totalFiles: Object.keys(filesMap).length,
          eligibleFiles: Object.keys(filesMap).length,
          totalLinesOfCode: 0,
          totalSizeBytes: 0,
          languageBreakdown: {},
          files: [],
          isolatedStoragePath: targetDir,
          verifiedIntegrity: true,
        },
        sourceFilesContent: filesMap,
      } as Software;

      const sbom = SbomGenerator.generateFromSoftware(swStub, {
        deterministicTimestamp: deterministicTs,
        signSbom: !flags.has('no-sign'),
      });

      if (command === 'sbom') {
        const format = argsMap.get('format') || 'cyclonedx';
        const out = format === 'spdx' ? sbom.spdx23Json : format === 'bundle' ? sbom : sbom.cyclonedx15Json;
        if (argsMap.get('out')) {
          fs.writeFileSync(argsMap.get('out')!, JSON.stringify(out, null, 2), 'utf8');
        }
        return { exitCode: 0, stdout: JSON.stringify(out, null, 2), stderr: '' };
      }

      const pipelineRes = AnalyzerRegistry.runNativeAstAndTaintPipeline(
        {
          runId: argsMap.get('run-id') || 'cli-run',
          softwareId: swStub.id,
          softwareName,
          softwareVersion,
          commitHash: 'LOCAL_HEAD',
          filesMap,
        },
        { deterministicTimestamp: deterministicTs }
      );

      const scaRes = ScaCorrelator.correlateSbom({
        software: swStub,
        sbom,
        runId: argsMap.get('run-id') || 'cli-run',
        licensePolicy: flags.has('check-licenses') ? DEFAULT_ENTERPRISE_LICENSE_POLICY : undefined,
        deterministicTimestamp: deterministicTs,
      });

      const allFindings = [...pipelineRes.findings, ...scaRes.findings];
      const gateId = argsMap.get('gate') || 'winhood-standard-v2';
      const fileCount = Object.keys(filesMap).length;
      const scopeCov = fileCount > 0 ? Math.round((pipelineRes.execution.filesProcessed / fileCount) * 100) : 0;

      const gateEval = QualityGateEngine.evaluate({
        gateId,
        findings: allFindings,
        scopeCoveragePercent: scopeCov,
        evidenceConfidence: fileCount > 0 ? 'HIGH' : 'LOW',
        evidenceVerified: true,
        deterministicTimestamp: deterministicTs,
      });

      const format = (argsMap.get('format') || 'json').toLowerCase();
      let outputStr: string;
      if (format === 'sarif') {
        outputStr = JSON.stringify(
          SarifCodec.exportSarif210(allFindings, {
            toolVersion: RULE_ENGINE_VERSION,
          }),
          null,
          2
        );
      } else {
        outputStr = JSON.stringify(
          {
            cliVersion: WINHOOD_CLI_VERSION,
            engineVersion: RULE_ENGINE_VERSION,
            deterministicDigestSha256: pipelineRes.deterministicDigestSha256,
            ruleCatalogSha256: pipelineRes.ruleCatalogSha256,
            gate: gateEval,
            sbomSummary: {
              componentsCount: sbom.componentsCount,
              cyclonedxSha256: sbom.cyclonedxSha256,
              spdxSha256: sbom.spdxSha256,
              signatureAlgorithm: sbom.signature?.algorithm || null,
            },
            findingsCount: allFindings.length,
            findings: command === 'gate' ? undefined : allFindings,
          },
          null,
          2
        );
      }

      if (argsMap.get('out')) {
        fs.writeFileSync(argsMap.get('out')!, outputStr, 'utf8');
      }

      return {
        exitCode: command === 'gate' || flags.has('enforce-gate') ? gateEval.cliExitCode : 0,
        stdout: outputStr,
        stderr: '',
      };
    }

    return {
      exitCode: 0,
      stdout: [
        `WinHood CLI v${WINHOOD_CLI_VERSION} (Engine v${RULE_ENGINE_VERSION})`,
        'Usage:',
        '  winhood analyze --path <dir> [--format json|sarif] [--gate <id>] [--enforce-gate] [--deterministic] [--check-licenses] [--out <file>]',
        '  winhood gate --path <dir> [--gate winhood-standard-v2|winhood-zero-trust-v2] [--deterministic]',
        '  winhood sbom --path <dir> [--format cyclonedx|spdx|bundle] [--out <file>]',
        '  winhood rules',
        '  winhood sarif-import --input <file.sarif>',
        'Exit codes: 0=APPROVED/APPROVED_WITH_RESERVATIONS, 1=BLOCKED/REJECTED, 2=INCONCLUSIVE, 3=ERROR',
      ].join('\n'),
      stderr: '',
    };
  } catch (err: any) {
    return { exitCode: 3, stdout: '', stderr: err?.message || String(err) };
  }
}

// Execute when invoked directly as CLI entrypoint
const isMain = process.argv[1] && (process.argv[1].endsWith('winhood-cli.ts') || process.argv[1].endsWith('winhood-cli.mjs'));
if (isMain) {
  runCli(process.argv.slice(2)).then((res) => {
    if (res.stdout) process.stdout.write(`${res.stdout}\n`);
    if (res.stderr) process.stderr.write(`${res.stderr}\n`);
    process.exit(res.exitCode);
  });
}
