import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

export interface SarifFindingItem {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: {
        startLine?: number;
        startColumn?: number;
        endLine?: number;
        endColumn?: number;
      };
    };
  }>;
  properties?: {
    cwe?: string;
    owasp?: string;
    remediation?: string;
    severity?: string;
    helpUri?: string;
  };
}

export interface NormalizedIdeFinding {
  ruleId: string;
  severity: 'ERROR' | 'WARNING' | 'INFO';
  cwe: string;
  owasp: string;
  message: string;
  remediation: string;
  docUrl: string;
  filePath: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

export interface GateStatusBarStyle {
  text: string;
  colorHex: string;
  statusColorCategory: 'GREEN' | 'YELLOW' | 'RED' | 'GRAY';
  tooltip: string;
}

const SAFE_SQL_CONCAT_QUICKFIX_REGEX = /["'`]SELECT\s[^+;\r\n]{1,200}\+\s{0,10}([a-zA-Z0-9_$.]{1,80})["'`]?/i;

const DEFAULT_REMEDIATIONS: Record<string, { cwe: string; owasp: string; remediation: string; quickFixReplacement?: (lineText: string) => string | null }> = {
  'javascript:S2077': {
    cwe: 'CWE-89',
    owasp: 'A03:2021-Injection',
    remediation: 'Substitua concatenação de strings SQL por consultas parametrizadas ($1, ?).',
    quickFixReplacement: (line) =>
      line.replace(SAFE_SQL_CONCAT_QUICKFIX_REGEX, '"SELECT * FROM records WHERE id = $1", [$1]'),
  },
  'typescript:S2077': {
    cwe: 'CWE-89',
    owasp: 'A03:2021-Injection',
    remediation: 'Utilize prepared statements / parâmetros posicionais ($1) em vez de interpolação direta.',
    quickFixReplacement: (line) =>
      line.replace(SAFE_SQL_CONCAT_QUICKFIX_REGEX, '"SELECT * FROM records WHERE id = $1", [$1]'),
  },
  'javascript:S1523': {
    cwe: 'CWE-95',
    owasp: 'A03:2021-Injection',
    remediation: 'Remova o uso de eval() ou Function() e utilize JSON.parse() ou despacho seguro.',
    quickFixReplacement: (line) => line.replace(/\beval\s*\(([^)]+)\)/g, 'JSON.parse(String($1))'),
  },
  'typescript:S1523': {
    cwe: 'CWE-95',
    owasp: 'A03:2021-Injection',
    remediation: 'Remova o uso de eval() ou Function() e utilize JSON.parse() ou despacho seguro.',
    quickFixReplacement: (line) => line.replace(/\beval\s*\(([^)]+)\)/g, 'JSON.parse(String($1))'),
  },
  'secrets:S6418': {
    cwe: 'CWE-798',
    owasp: 'A07:2021-Identification and Authentication Failures',
    remediation: 'Mova o segredo hardcoded para variável de ambiente (process.env) ou cofre de chaves.',
    quickFixReplacement: (line) =>
      line.replace(/(password|secret|apiKey|token)\s*[:=]\s*["'`][^"'`]+["'`]/i, '$1: process.env.WINHOOD_MANAGED_SECRET || ""'),
  },
};

export function normalizeSarifFindings(results: SarifFindingItem[]): NormalizedIdeFinding[] {
  return results.map((r) => {
    const loc = r.locations?.[0]?.physicalLocation;
    const filePath = loc?.artifactLocation?.uri || 'unknown';
    const startLine = Math.max(1, loc?.region?.startLine || 1);
    const startColumn = Math.max(1, loc?.region?.startColumn || 1);
    const endLine = Math.max(startLine, loc?.region?.endLine || startLine);
    const endColumn = Math.max(startColumn + 1, loc?.region?.endColumn || 120);
    const meta = DEFAULT_REMEDIATIONS[r.ruleId];

    const cwe = r.properties?.cwe || meta?.cwe || 'CWE-710';
    const owasp = r.properties?.owasp || meta?.owasp || 'A04:2021-Insecure Design';
    const remediation =
      r.properties?.remediation ||
      meta?.remediation ||
      'Consulte a recomendação determinística no catálogo de regras do WinHood.';
    const docUrl =
      r.properties?.helpUri ||
      `https://winhood.local/docs/RULE_CATALOG.md#${encodeURIComponent(r.ruleId)}`;

    return {
      ruleId: r.ruleId,
      severity: r.level === 'error' ? 'ERROR' : r.level === 'warning' ? 'WARNING' : 'INFO',
      cwe,
      owasp,
      message: r.message?.text || r.ruleId,
      remediation,
      docUrl,
      filePath,
      startLine,
      startColumn,
      endLine,
      endColumn,
    };
  });
}

export function buildHoverMarkdown(finding: NormalizedIdeFinding): string {
  return [
    `### WinHood Audit — \`${finding.ruleId}\` (${finding.severity})`,
    `- **Classificação Aberta:** \`${finding.cwe}\` · \`${finding.owasp}\``,
    `- **Descrição:** ${finding.message}`,
    `- **Remediação Sugerida:** ${finding.remediation}`,
    `- **Documentação da Regra:** [Catálogo de Regras WinHood (${finding.ruleId})](${finding.docUrl})`,
  ].join('\n');
}

export function computeDeterministicQuickFix(
  ruleId: string,
  lineText: string
): { title: string; replacementLine: string } | null {
  const meta = DEFAULT_REMEDIATIONS[ruleId];
  if (meta?.quickFixReplacement) {
    const replaced = meta.quickFixReplacement(lineText);
    if (replaced && replaced !== lineText) {
      return {
        title: `WinHood Quick Fix: Aplicar correção determinística (${ruleId})`,
        replacementLine: replaced,
      };
    }
  }
  if (/\beval\s*\(/.test(lineText)) {
    return {
      title: `WinHood Quick Fix: Substituir eval() por JSON.parse() (${ruleId})`,
      replacementLine: lineText.replace(/\beval\s*\(([^)]+)\)/g, 'JSON.parse(String($1))'),
    };
  }
  if (/FROM\s+\S+:latest/i.test(lineText)) {
    return {
      title: `WinHood Quick Fix: Fixar versão imutável da imagem base (${ruleId})`,
      replacementLine: lineText.replace(/:latest\b/i, ':20-alpine'),
    };
  }
  return null;
}

export function resolveGateStatusBarStyle(decision: string): GateStatusBarStyle {
  const normalized = (decision || 'INCONCLUSIVE').toUpperCase();
  if (normalized === 'APPROVED') {
    return {
      text: '$(shield) WinHood Gate: APPROVED',
      colorHex: '#10b981',
      statusColorCategory: 'GREEN',
      tooltip: 'WinHood Quality Gate aprovado (Exit Code 0).',
    };
  }
  if (normalized === 'APPROVED_WITH_RESERVATIONS') {
    return {
      text: '$(warning) WinHood Gate: APPROVED_WITH_RESERVATIONS',
      colorHex: '#f59e0b',
      statusColorCategory: 'YELLOW',
      tooltip: 'WinHood Quality Gate aprovado com ressalvas (Exit Code 1).',
    };
  }
  if (normalized === 'BLOCKED' || normalized === 'REJECTED') {
    return {
      text: `$(error) WinHood Gate: ${normalized}`,
      colorHex: '#ef4444',
      statusColorCategory: 'RED',
      tooltip: `WinHood Quality Gate bloqueado (${normalized} — Exit Code 2).`,
    };
  }
  return {
    text: '$(question) WinHood Gate: INCONCLUSIVE',
    colorHex: '#94a3b8',
    statusColorCategory: 'GRAY',
    tooltip: 'WinHood Quality Gate inconclusivo (Exit Code 3).',
  };
}

export async function executeAuditWithOfflineFallback(params: {
  apiBaseUrl: string;
  apiToken?: string;
  gateId: string;
  profile: string;
  softwareName: string;
  filesMap: Record<string, string>;
  workspaceRoot: string;
  offlineCliFallback?: boolean;
}): Promise<{
  mode: 'API' | 'OFFLINE_CLI';
  decision: string;
  findings: NormalizedIdeFinding[];
}> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (params.apiToken) {
    headers.Authorization = `Bearer ${params.apiToken}`;
  }

  try {
    const resp = await fetch(`${params.apiBaseUrl.replace(/\/$/, '')}/api/analyze/sarif`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        softwareName: params.softwareName,
        gateId: params.gateId,
        profile: params.profile,
        filesMap: params.filesMap,
      }),
    });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }
    const data = (await resp.json()) as {
      sarif?: { runs?: Array<{ results?: SarifFindingItem[] }> };
      gateEvaluation?: { decision: string };
    };
    const results = data.sarif?.runs?.[0]?.results || [];
    return {
      mode: 'API',
      decision: data.gateEvaluation?.decision || 'APPROVED',
      findings: normalizeSarifFindings(results),
    };
  } catch (apiErr) {
    if (params.offlineCliFallback === false) {
      throw apiErr;
    }
    const cliCandidates = [
      path.resolve(params.workspaceRoot, 'cli/winhood-cli.ts'),
      path.resolve(__dirname, '../../../cli/winhood-cli.ts'),
    ];
    const cliPath = cliCandidates.find((p) => fs.existsSync(p));
    if (!cliPath) {
      throw apiErr;
    }
    const rawOut = execFileSync(
      process.execPath,
      [
        '--import',
        'tsx',
        cliPath,
        'report',
        '--path',
        params.workspaceRoot,
        '--gate',
        params.gateId,
        '--profile',
        params.profile,
        '--format',
        'sarif',
        '--deterministic',
      ],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
    );
    const sarif = JSON.parse(rawOut) as {
      runs?: Array<{
        results?: SarifFindingItem[];
        properties?: { gateDecision?: string };
      }>;
    };
    const run = sarif.runs?.[0];
    return {
      mode: 'OFFLINE_CLI',
      decision: run?.properties?.gateDecision || 'APPROVED',
      findings: normalizeSarifFindings(run?.results || []),
    };
  }
}

// Lazy VS Code runtime bindings when loaded inside the VS Code Extension Host
export function activate(context: any) {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const vscode = require('vscode') as any;
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('winhood');
  const findingsByFile = new Map<string, NormalizedIdeFinding[]>();

  const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = 'winhood.analyzeWorkspace';
  statusBarItem.text = '$(shield) WinHood: Ready';
  statusBarItem.show();

  const runAnalysis = async (singleFileUri?: { fsPath: string }) => {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
      vscode.window.showWarningMessage('WinHood: Abra uma pasta de workspace primeiro.');
      return;
    }
    const rootPath = folders[0].uri.fsPath;
    const cfg = vscode.workspace.getConfiguration('winhood');
    const apiBaseUrl = cfg.get('apiBaseUrl', 'http://localhost:3000');
    const apiToken = cfg.get('apiToken', '');
    const profile = cfg.get('analysisProfile', 'mqr-strict');
    const gateId = cfg.get('qualityGateId', 'winhood-standard-v2');
    const offlineCliFallback = cfg.get('offlineCliFallback', true);

    const filesMap: Record<string, string> = {};
    if (singleFileUri) {
      const rel = path.relative(rootPath, singleFileUri.fsPath).replace(/\\/g, '/');
      filesMap[rel] = fs.readFileSync(singleFileUri.fsPath, 'utf8');
    } else {
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
    }

    statusBarItem.text = '$(sync~spin) WinHood: Analisando...';
    try {
      const result = await executeAuditWithOfflineFallback({
        apiBaseUrl,
        apiToken,
        gateId,
        profile,
        softwareName: path.basename(rootPath),
        filesMap,
        workspaceRoot: rootPath,
        offlineCliFallback,
      });

      if (!singleFileUri) {
        diagnosticCollection.clear();
        findingsByFile.clear();
      }

      const diagMap = new Map<string, any[]>();
      for (const f of result.findings) {
        const fullPath = path.resolve(rootPath, f.filePath);
        const lineZero = Math.max(0, f.startLine - 1);
        const colZero = Math.max(0, f.startColumn - 1);
        const endLineZero = Math.max(lineZero, f.endLine - 1);
        const endColZero = Math.max(colZero + 1, f.endColumn);

        const sev =
          f.severity === 'ERROR'
            ? vscode.DiagnosticSeverity.Error
            : f.severity === 'WARNING'
              ? vscode.DiagnosticSeverity.Warning
              : vscode.DiagnosticSeverity.Information;

        const diag = new vscode.Diagnostic(
          new vscode.Range(lineZero, colZero, endLineZero, endColZero),
          `[${f.ruleId}] (${f.cwe} | ${f.owasp}) ${f.message}`,
          sev
        );
        diag.source = 'WinHood Audit (MQR)';
        diag.code = f.ruleId;

        const list = diagMap.get(fullPath) || [];
        list.push(diag);
        diagMap.set(fullPath, list);

        const fList = findingsByFile.get(fullPath) || [];
        fList.push(f);
        findingsByFile.set(fullPath, fList);
      }

      for (const [fp, diags] of diagMap.entries()) {
        diagnosticCollection.set(vscode.Uri.file(fp), diags);
      }

      const style = resolveGateStatusBarStyle(result.decision);
      statusBarItem.text = style.text;
      statusBarItem.color = style.colorHex;
      statusBarItem.tooltip = `${style.tooltip} (Modo: ${result.mode})`;
    } catch (err: any) {
      statusBarItem.text = '$(alert) WinHood: Erro';
      vscode.window.showErrorMessage(`WinHood falhou: ${err?.message || String(err)}`);
    }
  };

  const cmdCurrent = vscode.commands.registerCommand('winhood.analyzeCurrentFile', async () => {
    const active = vscode.window.activeTextEditor?.document.uri;
    if (!active) {
      vscode.window.showWarningMessage('WinHood: Nenhum arquivo ativo no editor.');
      return;
    }
    await runAnalysis(active);
  });

  const cmdWorkspace = vscode.commands.registerCommand('winhood.analyzeWorkspace', async () => {
    await runAnalysis();
  });

  const cmdLegacy = vscode.commands.registerCommand('winhood.runAudit', async () => {
    await runAnalysis();
  });

  const hoverProvider = vscode.languages.registerHoverProvider({ scheme: 'file' }, {
    provideHover(document: any, position: any) {
      const list = findingsByFile.get(document.uri.fsPath) || [];
      const match = list.find((f) => f.startLine === position.line + 1);
      if (!match) return null;
      const md = new vscode.MarkdownString(buildHoverMarkdown(match));
      md.isTrusted = true;
      return new vscode.Hover(md);
    },
  });

  const codeActionProvider = vscode.languages.registerCodeActionsProvider(
    { scheme: 'file' },
    {
      provideCodeActions(document: any, range: any, codeActionContext: any) {
        const actions: any[] = [];
        for (const diag of codeActionContext.diagnostics) {
          if (diag.source !== 'WinHood Audit (MQR)') continue;
          const ruleId = String(diag.code || '');
          const lineText = document.lineAt(range.start.line).text;
          const fix = computeDeterministicQuickFix(ruleId, lineText);
          if (fix) {
            const action = new vscode.CodeAction(fix.title, vscode.CodeActionKind.QuickFix);
            action.diagnostics = [diag];
            action.isPreferred = true;
            const edit = new vscode.WorkspaceEdit();
            edit.replace(
              document.uri,
              document.lineAt(range.start.line).range,
              fix.replacementLine
            );
            action.edit = edit;
            actions.push(action);
          }
        }
        return actions;
      },
    },
    { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
  );

  context.subscriptions.push(
    diagnosticCollection,
    statusBarItem,
    cmdCurrent,
    cmdWorkspace,
    cmdLegacy,
    hoverProvider,
    codeActionProvider
  );
}

export function deactivate() {}
