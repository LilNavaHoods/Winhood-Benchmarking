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

      // Direct API mode through executeAuditWithOfflineFallback
      const liveApiRes = await executeAuditWithOfflineFallback({
        apiBaseUrl: baseUrl,
        apiToken: 'local-optional-token',
        gateId: 'winhood-standard-v2',
        profile: 'mqr-strict',
        softwareName: 'LiveIdeSample',
        filesMap: { 'app.ts': 'export function run(input: string) { return eval(input); }\n' },
        workspaceRoot: tmpWorkspace,
        offlineCliFallback: false,
      });
      assert.equal(liveApiRes.mode, 'API');
      assert.ok(liveApiRes.findings.length >= 1);

      // Explicit failure when API unreachable and offlineCliFallback is disabled
      await assert.rejects(
        () =>
          executeAuditWithOfflineFallback({
            apiBaseUrl: 'http://127.0.0.1:59999',
            gateId: 'winhood-standard-v2',
            profile: 'mqr-strict',
            softwareName: 'FailNoFallback',
            filesMap: { 'app.ts': 'export const ok = 1;\n' },
            workspaceRoot: tmpWorkspace,
            offlineCliFallback: false,
          }),
        /fetch failed|ECONNREFUSED|HTTP/i
      );
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

test('VS Code Extension Host: deterministic quick fixes, normalize defaults, activate(), commands, hover, code actions, and deactivate()', async () => {
  // Cover remaining quick fixes and SARIF normalization defaults
  const sqliFix = computeDeterministicQuickFix(
    ['javascript', 'S2077'].join(':'),
    'db.query("SELECT * FROM users WHERE id = " + userId);'
  );
  assert.ok(sqliFix?.replacementLine.includes('$1'));

  const tsSqliFix = computeDeterministicQuickFix(
    'typescript:S2077',
    'db.query("SELECT * FROM accounts WHERE id = " + accId);'
  );
  assert.ok(tsSqliFix?.replacementLine.includes('$1'));

  const secretFix = computeDeterministicQuickFix(
    'secrets:S6418',
    'const apiKey = "super-secret-value-123";'
  );
  assert.ok(secretFix?.replacementLine.includes('WINHOOD_MANAGED_SECRET'));

  const genericEvalFix = computeDeterministicQuickFix('custom:rule', 'return eval(rawPayload);');
  assert.ok(genericEvalFix?.replacementLine.includes('JSON.parse'));

  const dockerFix = computeDeterministicQuickFix('docker:S6596', 'FROM node:latest');
  assert.ok(dockerFix?.replacementLine.includes(':20-alpine'));

  assert.equal(computeDeterministicQuickFix('unknown:rule', 'const x = 1;'), null);

  const normalizedMixed = normalizeSarifFindings([
    { ruleId: 'custom:warn', level: 'warning', message: { text: 'Warning finding' } },
    { ruleId: 'custom:note', level: 'note', message: { text: '' } },
  ]);
  assert.equal(normalizedMixed[0]?.severity, 'WARNING');
  assert.equal(normalizedMixed[1]?.severity, 'INFO');
  assert.equal(normalizedMixed[1]?.filePath, 'unknown');
  assert.equal(normalizedMixed[1]?.message, 'custom:note');

  // Exercise activate() and deactivate() against an in-memory VS Code host harness + real WinHood HTTP server
  const ModuleMod = await import('node:module');
  const modAny = ModuleMod.default as unknown as {
    _load: (request: string, parent: unknown, isMain: boolean) => unknown;
  };
  const originalLoad = modAny._load;

  const { createWinHoodApp } = await import('../../../server');
  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-vscode-host-data-'));
  const tmpWs = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-vscode-host-ws-'));
  let server: http.Server | null = null;

  try {
    const sampleFile = path.join(tmpWs, 'vuln.ts');
    fs.writeFileSync(sampleFile, 'export function run(x: string) { return eval(x); }\n', 'utf8');

    const { app } = await createWinHoodApp({ dataDir: tmpDataDir });
    server = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const port = (server.address() as AddressInfo).port;
    const apiBaseUrl = `http://127.0.0.1:${port}`;

    const registeredCommands = new Map<string, (...args: unknown[]) => Promise<void> | void>();
    const warnings: string[] = [];
    const errors: string[] = [];
    const setDiagnostics = new Map<string, unknown[]>();
    const providers: {
      hover: { provideHover: (doc: unknown, pos: unknown) => unknown } | null;
      codeAction: {
        provideCodeActions: (doc: unknown, range: unknown, ctx: unknown) => unknown[];
      } | null;
    } = { hover: null, codeAction: null };
    let activeEditor: { document: { uri: { fsPath: string } } } | undefined = undefined;
    let workspaceFolders: Array<{ uri: { fsPath: string } }> = [];

    const mockVscode = {
      StatusBarAlignment: { Left: 1 },
      DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2 },
      CodeActionKind: { QuickFix: 'quickfix' },
      Uri: { file: (fp: string) => ({ fsPath: fp }) },
      Range: class {
        constructor(
          public startLine: number,
          public startCol: number,
          public endLine: number,
          public endCol: number
        ) {}
      },
      Diagnostic: class {
        public source = '';
        public code = '';
        constructor(public range: unknown, public message: string, public severity: number) {}
      },
      MarkdownString: class {
        public isTrusted = false;
        constructor(public value: string) {}
      },
      Hover: class {
        constructor(public contents: unknown) {}
      },
      WorkspaceEdit: class {
        public edits: Array<{ uri: unknown; range: unknown; text: string }> = [];
        replace(uri: unknown, range: unknown, text: string) {
          this.edits.push({ uri, range, text });
        }
      },
      CodeAction: class {
        public diagnostics: unknown[] = [];
        public isPreferred = false;
        public edit: unknown = null;
        constructor(public title: string, public kind: string) {}
      },
      languages: {
        createDiagnosticCollection: () => ({
          clear: () => setDiagnostics.clear(),
          set: (uri: { fsPath: string }, list: unknown[]) => setDiagnostics.set(uri.fsPath, list),
          dispose: () => {},
        }),
        registerHoverProvider: (_selector: unknown, provider: NonNullable<typeof providers.hover>) => {
          providers.hover = provider;
          return { dispose: () => {} };
        },
        registerCodeActionsProvider: (
          _selector: unknown,
          provider: NonNullable<typeof providers.codeAction>
        ) => {
          providers.codeAction = provider;
          return { dispose: () => {} };
        },
      },
      window: {
        get activeTextEditor() {
          return activeEditor;
        },
        createStatusBarItem: () => ({
          command: '',
          text: '',
          color: '',
          tooltip: '',
          show: () => {},
          dispose: () => {},
        }),
        showWarningMessage: (msg: string) => warnings.push(msg),
        showErrorMessage: (msg: string) => errors.push(msg),
      },
      workspace: {
        get workspaceFolders() {
          return workspaceFolders;
        },
        getConfiguration: () => ({
          get: (key: string, def: unknown) => {
            if (key === 'apiBaseUrl') return apiBaseUrl;
            if (key === 'offlineCliFallback') return false;
            return def;
          },
        }),
        findFiles: async () => [{ fsPath: sampleFile }],
      },
      commands: {
        registerCommand: (id: string, cb: (...args: unknown[]) => Promise<void> | void) => {
          registeredCommands.set(id, cb);
          return { dispose: () => {} };
        },
      },
    };

    modAny._load = function (request: string, parent: unknown, isMain: boolean) {
      if (request === 'vscode') return mockVscode;
      return originalLoad.call(this, request, parent, isMain);
    };

    const { activate, deactivate } = await import('../src/extension');
    const subscriptions: unknown[] = [];
    activate({ subscriptions });
    assert.equal(subscriptions.length, 7);

    // 1. No workspace & no active editor warnings
    await registeredCommands.get('winhood.analyzeCurrentFile')!();
    await registeredCommands.get('winhood.analyzeWorkspace')!();
    assert.ok(warnings.length >= 2);

    // 2. Analyze workspace with real file
    workspaceFolders = [{ uri: { fsPath: tmpWs } }];
    await registeredCommands.get('winhood.analyzeWorkspace')!();
    assert.ok(setDiagnostics.size >= 1, 'Workspace audit must publish diagnostics');

    // 3. Analyze current file & legacy runAudit
    activeEditor = { document: { uri: { fsPath: sampleFile } } };
    await registeredCommands.get('winhood.analyzeCurrentFile')!();
    await registeredCommands.get('winhood.runAudit')!();

    // 4. Hover provider (matching line & non-matching line)
    assert.ok(providers.hover);
    const hoverHit = providers.hover.provideHover({ uri: { fsPath: sampleFile } }, { line: 0 });
    assert.ok(hoverHit);
    const hoverMiss = providers.hover.provideHover({ uri: { fsPath: sampleFile } }, { line: 99 });
    assert.equal(hoverMiss, null);

    // 5. CodeAction provider
    assert.ok(providers.codeAction);
    const docStub = {
      uri: { fsPath: sampleFile },
      lineAt: () => ({
        text: 'export function run(x: string) { return eval(x); }',
        range: { start: 0, end: 50 },
      }),
    };
    const actions = providers.codeAction.provideCodeActions(
      docStub,
      { start: { line: 0 } },
      {
        diagnostics: [
          { source: 'OtherTool', code: 'x' },
          { source: 'WinHood Audit (MQR)', code: 'typescript:S1523' },
        ],
      }
    );
    assert.equal(actions.length, 1);

    deactivate();
    assert.equal(errors.length, 0);
  } finally {
    modAny._load = originalLoad;
    if (server) {
      await new Promise<void>((resolve) => server!.close(() => resolve()));
    }
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
    fs.rmSync(tmpWs, { recursive: true, force: true });
  }
});
