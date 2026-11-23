import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import type http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import {
  buildHoverMarkdown,
  computeDeterministicQuickFix,
  executeAuditWithOfflineFallback,
  normalizeSarifFindings,
  resolveGateStatusBarStyle,
} from '../src/extension';

test('VS Code Extension MVP: normalizes SARIF findings, builds Hover Markdown, computes deterministic Quick Fix, and maps Gate StatusBar colors', () => {
  const findings = normalizeSarifFindings([
    {
      ruleId: 'typescript:S2077',
      level: 'error',
      message: { text: 'SQL Injection via concatenated query parameter.' },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: 'src/repo.ts' },
            region: { startLine: 14, startColumn: 10, endLine: 14, endColumn: 68 },
          },
        },
      ],
    },
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.cwe, 'CWE-89');
  assert.equal(findings[0]!.owasp, 'A03:2021-Injection');
  assert.equal(findings[0]!.startLine, 14);
  assert.equal(findings[0]!.startColumn, 10);

  const hoverMd = buildHoverMarkdown(findings[0]!);
  assert.ok(hoverMd.includes('typescript:S2077'));
  assert.ok(hoverMd.includes('CWE-89'));
  assert.ok(hoverMd.includes('Remediação Sugerida'));
  assert.ok(hoverMd.includes('RULE_CATALOG.md'));

  const fixEval = computeDeterministicQuickFix('typescript:S1523', 'const out = eval(userInput);');
  assert.ok(fixEval);
  assert.ok(fixEval!.replacementLine.includes('JSON.parse(String(userInput))'));

  assert.equal(resolveGateStatusBarStyle('APPROVED').statusColorCategory, 'GREEN');
  assert.equal(resolveGateStatusBarStyle('APPROVED_WITH_RESERVATIONS').statusColorCategory, 'YELLOW');
  assert.equal(resolveGateStatusBarStyle('BLOCKED').statusColorCategory, 'RED');
  assert.equal(resolveGateStatusBarStyle('REJECTED').statusColorCategory, 'RED');
  assert.equal(resolveGateStatusBarStyle('INCONCLUSIVE').statusColorCategory, 'GRAY');
});

test('VS Code Extension MVP: integrates with live WinHood API and automatically falls back to offline embedded CLI when API is unreachable', async () => {
  const { createWinHoodApp } = await import('../../../server');
  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-vscode-ext-api-'));
  let server: http.Server | null = null;
  try {
    const { app } = await createWinHoodApp({ dataDir: tmpDataDir });
    server = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const port = (server.address() as AddressInfo).port;
    const baseUrl = `http://127.0.0.1:${port}`;

    // Live WinHood API works directly without login under Unrestricted Local Access
    const liveSarifRes = await fetch(`${baseUrl}/api/analyze/sarif`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        softwareName: 'IdeLiveSample',
        filesMap: { 'app.ts': 'export function run(input: string) { return eval(input); }\n' },
        deterministicTimestamp: '2026-11-14T00:00:00.000Z',
      }),
    });
    assert.equal(liveSarifRes.status, 200);
    const liveSarifJson = (await liveSarifRes.json()) as { sarif?: { version?: string } };
    assert.equal(liveSarifJson.sarif?.version, '2.1.0');

    // Offline fallback test against an unreachable port
    const tmpWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-vscode-ws-'));
    try {
      fs.writeFileSync(
        path.join(tmpWorkspace, 'app.ts'),
        'export function run(input: string) { return eval(input); }\n',
        'utf8'
      );

      const offlineRes = await executeAuditWithOfflineFallback({
        apiBaseUrl: 'http://127.0.0.1:59999',
        gateId: 'winhood-standard-v2',
        profile: 'mqr-strict',
        softwareName: 'OfflineIdeSample',
        filesMap: { 'app.ts': 'export function run(input: string) { return eval(input); }\n' },
        workspaceRoot: tmpWorkspace,
        offlineCliFallback: true,
      });

      assert.equal(offlineRes.mode, 'OFFLINE_CLI');
      assert.ok(offlineRes.findings.length >= 1);
      assert.equal(offlineRes.decision, 'BLOCKED');
    } finally {
      fs.rmSync(tmpWorkspace, { recursive: true, force: true });
    }
  } finally {
    if (server) {
      await new Promise<void>((resolve) => server!.close(() => resolve()));
    }
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
  }
});
