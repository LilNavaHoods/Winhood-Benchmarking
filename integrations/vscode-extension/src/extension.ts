import * as vscode from 'vscode';
import * as fs from 'node:fs';
import * as path from 'node:path';

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: { startLine?: number };
    };
  }>;
}

export function activate(context: vscode.ExtensionContext) {
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('winhood');
  const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = 'winhood.runAudit';
  statusBarItem.text = '$(shield) WinHood: Ready';
  statusBarItem.show();

  const disposable = vscode.commands.registerCommand('winhood.runAudit', async () => {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
      vscode.window.showWarningMessage('WinHood: Open a workspace folder first.');
      return;
    }

    const rootPath = folders[0].uri.fsPath;
    const cfg = vscode.workspace.getConfiguration('winhood');
    const apiBaseUrl = cfg.get<string>('apiBaseUrl', 'http://localhost:3000').replace(/\/$/, '');
    const gateId = cfg.get<string>('qualityGateId', 'winhood-standard-v2');
    const apiToken = cfg.get<string>('apiToken', '');

    const filesMap: Record<string, string> = {};
    const uris = await vscode.workspace.findFiles(
      '**/*.{ts,tsx,js,jsx,py,java,go,sql,tf,yaml,yml,Dockerfile}',
      '{**/node_modules/**,**/.git/**,**/dist/**}',
      200
    );

    for (const uri of uris) {
      try {
        const rel = path.relative(rootPath, uri.fsPath).replace(/\\/g, '/');
        filesMap[rel] = fs.readFileSync(uri.fsPath, 'utf8');
      } catch {
        // Ignore unreadable file
      }
    }

    statusBarItem.text = '$(sync~spin) WinHood: Auditing...';
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (apiToken) headers.Authorization = `Bearer ${apiToken}`;

      const resp = await fetch(`${apiBaseUrl}/api/analyze/sarif`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          softwareName: path.basename(rootPath),
          gateId,
          filesMap,
        }),
      });
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
      }
      const data = (await resp.json()) as {
        sarif?: { runs?: Array<{ results?: SarifResult[] }> };
        gateEvaluation?: { decision: string; gateVersion: string; cliExitCode: number };
      };

      diagnosticCollection.clear();
      const byFile = new Map<string, vscode.Diagnostic[]>();
      const results = data.sarif?.runs?.[0]?.results || [];

      for (const r of results) {
        const uriRel = r.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
        const startLine = Math.max(0, (r.locations?.[0]?.physicalLocation?.region?.startLine || 1) - 1);
        if (!uriRel) continue;
        const fullPath = path.join(rootPath, uriRel);
        const sev =
          r.level === 'error'
            ? vscode.DiagnosticSeverity.Error
            : r.level === 'warning'
              ? vscode.DiagnosticSeverity.Warning
              : vscode.DiagnosticSeverity.Information;
        const diag = new vscode.Diagnostic(
          new vscode.Range(startLine, 0, startLine, 120),
          `[${r.ruleId}] ${r.message.text}`,
          sev
        );
        diag.source = 'WinHood Audit';
        const list = byFile.get(fullPath) || [];
        list.push(diag);
        byFile.set(fullPath, list);
      }

      for (const [fp, diags] of byFile.entries()) {
        diagnosticCollection.set(vscode.Uri.file(fp), diags);
      }

      const decision = data.gateEvaluation?.decision || 'INCONCLUSIVE';
      statusBarItem.text = `$(shield) WinHood Gate: ${decision}`;
      vscode.window.showInformationMessage(
        `WinHood Audit completed: Gate ${decision} (${results.length} findings).`
      );
    } catch (err: any) {
      statusBarItem.text = '$(alert) WinHood: Error';
      vscode.window.showErrorMessage(`WinHood Audit failed: ${err?.message || String(err)}`);
    }
  });

  context.subscriptions.push(diagnosticCollection, statusBarItem, disposable);
}

export function deactivate() {}
