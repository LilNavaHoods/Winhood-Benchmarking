import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import type http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { runCli, WINHOOD_CLI_VERSION } from '../../cli/winhood-cli';
import { buildOpenApiSpec } from '../api/openApiSpec';
import { PrDecorationAdapter } from '../integrations/ci/PrDecorationAdapter';
import { createWinHoodApp } from '../../server';


test('WinHood CLI executes rules, analyze --deterministic, gate exit codes (0/1/3), and sbom', async () => {
  const ver = await runCli(['--version']);
  assert.equal(ver.exitCode, 0);
  assert.equal(JSON.parse(ver.stdout).cliVersion, WINHOOD_CLI_VERSION);

  const rulesRes = await runCli(['rules']);
  assert.equal(rulesRes.exitCode, 0);
  const rulesJson = JSON.parse(rulesRes.stdout);
  assert.ok(rulesJson.totalRules >= 15);
  assert.ok(rulesJson.catalogSha256);

  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-cli-repo-'));
  try {
    fs.writeFileSync(
      path.join(tmpRepo, 'vuln.ts'),
      'export function q(id: string, db: any) { return db.query("SELECT * FROM u WHERE id=" + id); }\n',
      'utf8'
    );
    fs.writeFileSync(
      path.join(tmpRepo, 'package.json'),
      JSON.stringify({ name: 'cli-sample', version: '1.0.0', dependencies: { lodash: '4.17.15' } }),
      'utf8'
    );

    const a1 = await runCli(['analyze', '--path', tmpRepo, '--deterministic', '--name', 'CliSample']);
    const a2 = await runCli(['analyze', '--path', tmpRepo, '--deterministic', '--name', 'CliSample']);
    assert.equal(a1.exitCode, 0);
    assert.equal(a1.stdout, a2.stdout, 'CLI deterministic analyze output must be identical');

    const gateBlocked = await runCli(['gate', '--path', tmpRepo, '--gate', 'winhood-standard-v2', '--deterministic']);
    assert.equal(gateBlocked.exitCode, 1, 'Vulnerable sample must block gate with exit code 1');

    const sarifOut = await runCli(['analyze', '--path', tmpRepo, '--format', 'sarif', '--deterministic']);
    assert.equal(sarifOut.exitCode, 0);
    const sarifJson = JSON.parse(sarifOut.stdout);
    assert.equal(sarifJson.version, '2.1.0');

    const sbomRes = await runCli(['sbom', '--path', tmpRepo, '--format', 'cyclonedx', '--deterministic']);
    assert.equal(sbomRes.exitCode, 0);
    const sbomJson = JSON.parse(sbomRes.stdout);
    assert.equal(sbomJson.bomFormat, 'CycloneDX');

    const missingPath = await runCli(['gate', '--path', path.join(tmpRepo, 'does-not-exist')]);
    assert.equal(missingPath.exitCode, 3);
  } finally {
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }
});

test('OpenAPI 3.0.3 spec and Express REST governance/catalog/PDF/SARIF endpoints work end-to-end', async () => {
  const spec = buildOpenApiSpec('http://localhost:3000') as {
    openapi: string;
    paths: Record<string, unknown>;
  };
  assert.equal(spec.openapi, '3.0.3');
  assert.ok(spec.paths['/api/quality-gates']);
  assert.ok(spec.paths['/api/compliance/{runId}/matrix']);
  assert.ok(spec.paths['/api/portfolio/summary']);

  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-api-test-'));
  let server: http.Server | null = null;
  try {
    const { app } = await createWinHoodApp({ dataDir: tmpDataDir });
    server = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    // 1. Public OpenAPI & Health
    const apiRes = await fetch(`${baseUrl}/api/openapi.json`);
    assert.equal(apiRes.status, 200);
    const apiJson = (await apiRes.json()) as { openapi: string };
    assert.equal(apiJson.openapi, '3.0.3');

    // 2. Verify Unrestricted Local Access by default (TOTP optional disabled)
    const totpStatusRes = await fetch(`${baseUrl}/api/totp/status`);
    assert.equal(totpStatusRes.status, 200);
    const totpStatusJson = (await totpStatusRes.json()) as { enabled: boolean; unlocked: boolean };
    assert.equal(totpStatusJson.enabled, false);
    assert.equal(totpStatusJson.unlocked, true);

    const jsonHeaders = {
      'Content-Type': 'application/json',
    };

    // 3. Seed real workspace directly without login so we have a completed BenchmarkRun
    const seedRes = await fetch(`${baseUrl}/api/system/seed-real-workspace`, {
      method: 'POST',
      headers: jsonHeaders,
    });
    assert.equal(seedRes.status, 200);

    const dashRes = await fetch(`${baseUrl}/api/bootstrap`);
    assert.equal(dashRes.status, 200);
    const dashJson = (await dashRes.json()) as { dashboard?: { latestRun?: { id: string } } };
    const runId = dashJson.dashboard?.latestRun?.id;
    assert.ok(runId);

    // 4. Rules & Secrets catalogs
    const rulesRes = await fetch(`${baseUrl}/api/rules/catalog`);
    assert.equal(rulesRes.status, 200);
    const rulesData = (await rulesRes.json()) as { totalRules: number; plugins: unknown[] };
    assert.ok(rulesData.totalRules >= 15);
    assert.ok(rulesData.plugins.length >= 2);

    const secretsRes = await fetch(`${baseUrl}/api/secrets/catalog`);
    assert.equal(secretsRes.status, 200);
    const secretsData = (await secretsRes.json()) as { patternsCount: number };
    assert.ok(secretsData.patternsCount >= 5);

    // 5. Quality Gates list, evaluation, signed webhook preview, PR decoration
    const gatesRes = await fetch(`${baseUrl}/api/quality-gates`);
    assert.equal(gatesRes.status, 200);

    const evalRes = await fetch(`${baseUrl}/api/quality-gates/evaluate`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ runId, gateId: 'winhood-standard-v2' }),
    });
    assert.equal(evalRes.status, 200);
    const evalData = (await evalRes.json()) as { evaluation: { decision: string; gateVersion: string } };
    assert.ok(evalData.evaluation.decision);
    assert.ok(evalData.evaluation.gateVersion);

    const hookRes = await fetch(`${baseUrl}/api/webhooks/sign-test`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ runId, gateId: 'winhood-standard-v2' }),
    });
    assert.equal(hookRes.status, 200);
    const hookData = (await hookRes.json()) as { mode: string; signedPayload: { signatureHeader: string } };
    assert.equal(hookData.mode, 'SIGNED_PREVIEW');
    assert.ok(hookData.signedPayload.signatureHeader.startsWith('t='));

    const prRes = await fetch(`${baseUrl}/api/integrations/pr-decoration`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ runId, provider: 'GITHUB', repository: 'winhood/demo' }),
    });
    assert.equal(prRes.status, 200);
    const prData = (await prRes.json()) as { decoration: { markdownComment: string } };
    assert.ok(prData.decoration.markdownComment.includes('WinHood'));

    // 6. Compliance Matrix, Portfolio Summary, Signed SBOM & Binary PDF Export
    const compRes = await fetch(`${baseUrl}/api/compliance/${runId}/matrix`);
    assert.equal(compRes.status, 200);

    const portRes = await fetch(`${baseUrl}/api/portfolio/summary`);
    assert.equal(portRes.status, 200);

    const sbomRes = await fetch(`${baseUrl}/api/runs/${runId}/sbom?format=cyclonedx`);
    assert.equal(sbomRes.status, 200);
    const sbomBody = (await sbomRes.json()) as { signatureVerification: { valid: boolean } };
    assert.equal(sbomBody.signatureVerification.valid, true);

    const pdfRes = await fetch(`${baseUrl}/api/reports/${runId}/export?format=pdf`);
    assert.equal(pdfRes.status, 200);
    assert.equal(pdfRes.headers.get('content-type')?.includes('application/pdf'), true);
    const pdfBuf = Buffer.from(await pdfRes.arrayBuffer());
    assert.ok(pdfBuf.toString('latin1').startsWith('%PDF-1.4'));

    // 7. Native SARIF endpoint
    const sarifAnalyzeRes = await fetch(`${baseUrl}/api/analyze/sarif`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({
        softwareName: 'InlineTarget',
        filesMap: { 'src/app.ts': 'export function f(x: any) { return eval(x); }\n' },
        deterministicTimestamp: '2026-11-14T00:00:00.000Z',
      }),
    });
    assert.equal(sarifAnalyzeRes.status, 200);
    const sarifAnalyzeData = (await sarifAnalyzeRes.json()) as { sarif: { version: string } };
    assert.equal(sarifAnalyzeData.sarif.version, '2.1.0');
  } finally {
    if (server) {
      await new Promise<void>((resolve) => server!.close(() => resolve()));
    }
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
  }
});

test('PrDecorationAdapter calculates new findings delta cleanly', () => {
  const dec = PrDecorationAdapter.buildDecoration({
    provider: 'GITLAB',
    repository: 'org/repo',
    pullRequestOrMrId: 42,
    run: {
      id: 'run-new',
      projectId: 'p1',
      projectName: 'Repo',
      profileId: 'std',
      profileName: 'Std',
      algorithmVersion: '4.3.0',
      softwareIds: ['s1'],
      startedAt: '2026-11-14T00:00:00Z',
      completedAt: '2026-11-14T00:01:00Z',
      status: 'COMPLETED',
      weightsUsed: {} as any,
      equivalenceEnvironment: {
        cpuCoresLimit: 2,
        memoryMbLimit: 1024,
        osTarget: 'linux',
        workloadConcurrency: 1,
      },
      environmentEquivalent: true,
      scoreCards: [],
      findings: [],
      toolExecutions: [],
      veracityResults: [],
      architectureGraphs: [],
      functionalMatrix: [],
      sandboxDiffs: [],
      evidenceChain: [],
      winnerSoftwareId: null,
      evidenceVerification: {
        valid: true,
        verificationState: 'VERIFIED',
        verifiedAt: '2026-11-14T00:01:00Z',
        tamperedIndices: [],
        message: 'OK',
      },
      executiveSummary: 'Clean MR',
    },
  });
  assert.equal(dec.provider, 'GITLAB');
  assert.equal(dec.pullRequestOrMrId, 42);
  assert.ok(dec.markdownComment.includes('org/repo'));
});

test('winhood report --format=pdf|html|sarif|json generates all 4 formats with cryptographic PDF signature and E2E PR gate BLOCKED blocks merge', async () => {
  const { spawnSync } = await import('node:child_process');
  const { ReportExporter } = await import('../reports/ReportExporter');
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-report-e2e-'));

  try {
    fs.writeFileSync(
      path.join(tmpRepo, 'vuln.ts'),
      'export function runUnsafe(userSql: string, db: any) { return db.query("SELECT * FROM accounts WHERE name=" + userSql); }\n',
      'utf8'
    );

    for (const fmt of ['pdf', 'html', 'sarif', 'json'] as const) {
      const outPath = path.join(tmpRepo, `out.${fmt}`);
      const res = await runCli([
        'report',
        `--format=${fmt}`,
        '--path',
        tmpRepo,
        '--deterministic',
        '--out',
        outPath,
      ]);
      assert.equal(res.exitCode, 0);
      assert.equal(fs.existsSync(outPath), true, `Expected ${outPath} to be created`);

      if (fmt === 'pdf') {
        const pdfBuf = fs.readFileSync(outPath);
        const verification = ReportExporter.verifyPdfIntegrity(pdfBuf);
        assert.equal(verification.valid, true, 'CLI PDF report must have valid SHA-256 and HMAC signature');
      } else if (fmt === 'html') {
        const html = fs.readFileSync(outPath, 'utf8');
        assert.ok(html.includes('id="winhood-provenance-footer"'));
      } else if (fmt === 'sarif') {
        const sarif = JSON.parse(fs.readFileSync(outPath, 'utf8'));
        assert.equal(sarif.version, '2.1.0');
      } else if (fmt === 'json') {
        const j = JSON.parse(fs.readFileSync(outPath, 'utf8'));
        assert.ok(j.provenanceFooter.hmacSignature);
      }
    }

    // E2E PR simulation with gate BLOCKED: canonical exit code must be 2 and GitHub Action entrypoint must block merge
    const ciBlocked = await runCli([
      'gate',
      '--path',
      tmpRepo,
      '--gate',
      'winhood-standard-v2',
      '--ci-exit-codes',
      '--deterministic',
    ]);
    assert.equal(ciBlocked.exitCode, 2, 'Canonical CI exit code for BLOCKED gate must be 2');

    const ghOutputFile = path.join(tmpRepo, 'gh_output.txt');
    const ghSummaryFile = path.join(tmpRepo, 'gh_summary.md');
    const sarifOutFile = path.join(tmpRepo, 'pr-audit.sarif');

    const actionRun = spawnSync(
      process.execPath,
      [path.resolve(process.cwd(), 'integrations/github-action/entrypoint.mjs')],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          INPUT_PATH: tmpRepo,
          INPUT_GATE: 'winhood-standard-v2',
          INPUT_PROFILE: 'mqr-strict',
          'INPUT_FAIL-ON': 'BLOCKED',
          'INPUT_SARIF-OUTPUT': sarifOutFile,
          'INPUT_ENFORCE-GATE': 'true',
          GITHUB_EVENT_NAME: 'pull_request',
          GITHUB_OUTPUT: ghOutputFile,
          GITHUB_STEP_SUMMARY: ghSummaryFile,
        },
      }
    );

    assert.equal(actionRun.status, 2, 'GitHub Action must exit with non-zero code 2 to block PR merge when gate is BLOCKED');
    const ghOutText = fs.readFileSync(ghOutputFile, 'utf8');
    assert.ok(ghOutText.includes('decision=BLOCKED'));
    const ghSumText = fs.readFileSync(ghSummaryFile, 'utf8');
    assert.ok(ghSumText.includes('MERGE BLOCKED'));
  } finally {
    fs.rmSync(path.resolve(process.cwd(), 'winhood-pr-comment.md'), { force: true });
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }
});

