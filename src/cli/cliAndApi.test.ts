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

function readBootstrapTokenFromFile(filePath: string): string {
  const raw = fs.readFileSync(filePath, 'utf8');
  return raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))[0] || '';
}

function extractCookieHeader(res: Response): string {
  const anyHeaders = res.headers as unknown as { getSetCookie?: () => string[] };
  const rawList: string[] =
    typeof anyHeaders.getSetCookie === 'function'
      ? anyHeaders.getSetCookie()
      : res.headers.get('set-cookie')
        ? [res.headers.get('set-cookie') as string]
        : [];
  return rawList.map((line) => line.split(';')[0]).join('; ');
}

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

    // 2. Bootstrap Admin session
    const token = readBootstrapTokenFromFile(path.join(tmpDataDir, 'bootstrap_admin_token.txt'));
    const bsRes = await fetch(`${baseUrl}/api/auth/bootstrap-admin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        bootstrapToken: token,
        name: 'Test Admin',
        email: 'admin@winhood.local',
        password: 'WinHood#StrongPassword2026!',
      }),
    });
    assert.equal(bsRes.status, 201);
    const cookieHeader = extractCookieHeader(bsRes);
    const bsBody = (await bsRes.json()) as { csrfToken: string };
    const authHeaders = {
      Cookie: cookieHeader,
      'X-WinHood-CSRF': bsBody.csrfToken,
      'Content-Type': 'application/json',
    };

    // 3. Seed real workspace so we have a completed BenchmarkRun
    const seedRes = await fetch(`${baseUrl}/api/system/seed-real-workspace`, {
      method: 'POST',
      headers: authHeaders,
    });
    assert.equal(seedRes.status, 200);

    const dashRes = await fetch(`${baseUrl}/api/bootstrap`, { headers: { Cookie: cookieHeader } });
    assert.equal(dashRes.status, 200);
    const dashJson = (await dashRes.json()) as { dashboard?: { latestRun?: { id: string } } };
    const runId = dashJson.dashboard?.latestRun?.id;
    assert.ok(runId);

    // 4. Rules & Secrets catalogs
    const rulesRes = await fetch(`${baseUrl}/api/rules/catalog`, { headers: { Cookie: cookieHeader } });
    assert.equal(rulesRes.status, 200);
    const rulesData = (await rulesRes.json()) as { totalRules: number; plugins: unknown[] };
    assert.ok(rulesData.totalRules >= 15);
    assert.ok(rulesData.plugins.length >= 2);

    const secretsRes = await fetch(`${baseUrl}/api/secrets/catalog`, { headers: { Cookie: cookieHeader } });
    assert.equal(secretsRes.status, 200);
    const secretsData = (await secretsRes.json()) as { patternsCount: number };
    assert.ok(secretsData.patternsCount >= 5);

    // 5. Quality Gates list, evaluation, signed webhook preview, PR decoration
    const gatesRes = await fetch(`${baseUrl}/api/quality-gates`, { headers: { Cookie: cookieHeader } });
    assert.equal(gatesRes.status, 200);

    const evalRes = await fetch(`${baseUrl}/api/quality-gates/evaluate`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ runId, gateId: 'winhood-standard-v2' }),
    });
    assert.equal(evalRes.status, 200);
    const evalData = (await evalRes.json()) as { evaluation: { decision: string; gateVersion: string } };
    assert.ok(evalData.evaluation.decision);
    assert.ok(evalData.evaluation.gateVersion);

    const hookRes = await fetch(`${baseUrl}/api/webhooks/sign-test`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ runId, gateId: 'winhood-standard-v2' }),
    });
    assert.equal(hookRes.status, 200);
    const hookData = (await hookRes.json()) as { mode: string; signedPayload: { signatureHeader: string } };
    assert.equal(hookData.mode, 'SIGNED_PREVIEW');
    assert.ok(hookData.signedPayload.signatureHeader.startsWith('t='));

    const prRes = await fetch(`${baseUrl}/api/integrations/pr-decoration`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ runId, provider: 'GITHUB', repository: 'winhood/demo' }),
    });
    assert.equal(prRes.status, 200);
    const prData = (await prRes.json()) as { decoration: { markdownComment: string } };
    assert.ok(prData.decoration.markdownComment.includes('WinHood'));

    // 6. Compliance Matrix, Portfolio Summary, Signed SBOM & Binary PDF Export
    const compRes = await fetch(`${baseUrl}/api/compliance/${runId}/matrix`, { headers: { Cookie: cookieHeader } });
    assert.equal(compRes.status, 200);

    const portRes = await fetch(`${baseUrl}/api/portfolio/summary`, { headers: { Cookie: cookieHeader } });
    assert.equal(portRes.status, 200);

    const sbomRes = await fetch(`${baseUrl}/api/runs/${runId}/sbom?format=cyclonedx`, {
      headers: { Cookie: cookieHeader },
    });
    assert.equal(sbomRes.status, 200);
    const sbomBody = (await sbomRes.json()) as { signatureVerification: { valid: boolean } };
    assert.equal(sbomBody.signatureVerification.valid, true);

    const pdfRes = await fetch(`${baseUrl}/api/reports/${runId}/export?format=pdf`, {
      headers: { Cookie: cookieHeader },
    });
    assert.equal(pdfRes.status, 200);
    assert.equal(pdfRes.headers.get('content-type')?.includes('application/pdf'), true);
    const pdfBuf = Buffer.from(await pdfRes.arrayBuffer());
    assert.ok(pdfBuf.toString('latin1').startsWith('%PDF-1.4'));

    // 7. Native SARIF endpoint
    const sarifAnalyzeRes = await fetch(`${baseUrl}/api/analyze/sarif`, {
      method: 'POST',
      headers: authHeaders,
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
