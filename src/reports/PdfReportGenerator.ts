import crypto from 'node:crypto';
import { ComplianceMapper } from '../evidence/ComplianceMapper';
import { QualityGateEngine } from '../gate/QualityGateEngine';
import { RULE_ENGINE_VERSION, RuleRegistry } from '../analyzers/RuleRegistry';
import { SarifCodec } from '../analyzers/SarifCodec';
import type { BenchmarkRun } from '../types/benchmark';

export interface ReportProvenanceFooter {
  engineVersion: string;
  ruleCatalogVersion: string;
  ruleCatalogSha256: string;
  codeHashSha256: string;
  artifactHashes: Record<string, string>;
  appliedGateId: string;
  appliedGateVersion: string;
  appliedGateHashSha256: string;
  reportContentSha256: string;
  hmacAlgorithm: 'HMAC-SHA256';
  hmacSignature: string;
  generatedAt: string;
}

const DEFAULT_REPORT_HMAC_KEY =
  process.env.WINHOOD_REPORT_HMAC_KEY || 'winhood-deterministic-audit-report-hmac-key-v4';

function sha256Hex(input: string | Buffer): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function computeHmacSha256(payload: string, secret = DEFAULT_REPORT_HMAC_KEY): string {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function toPdfAscii(text: string): string {
  const normalized = text
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^\x20-\x7e]/g, ' ');
  return normalized
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

function wrapText(line: string, maxChars = 88): string[] {
  if (line.length <= maxChars) return [line];
  const out: string[] = [];
  let remaining = line;
  while (remaining.length > maxChars) {
    let splitIdx = remaining.lastIndexOf(' ', maxChars);
    if (splitIdx <= 10) splitIdx = maxChars;
    out.push(remaining.slice(0, splitIdx).trimEnd());
    remaining = remaining.slice(splitIdx).trimStart();
  }
  if (remaining.length > 0) out.push(remaining);
  return out;
}

export class PdfReportGenerator {
  public static buildProvenanceFooter(
    run: BenchmarkRun,
    hmacSecret = DEFAULT_REPORT_HMAC_KEY
  ): ReportProvenanceFooter {
    const gateEval = QualityGateEngine.evaluateFromRun(run);
    const catalogSnapshot = RuleRegistry.getCatalogSnapshot();
    const sm = run.signedManifest;

    const engineVersion = sm?.engineVersion || run.algorithmVersion || RULE_ENGINE_VERSION;
    const ruleCatalogVersion = sm?.rulePackVersions?.core || catalogSnapshot.engineVersion || RULE_ENGINE_VERSION;
    const ruleCatalogSha256 = sm?.ruleCatalogSha256 || catalogSnapshot.catalogSha256;

    const findingsDigest = sha256Hex(
      JSON.stringify(
        (run.findings || []).map((f) => ({
          id: f.originalRuleId,
          file: f.filePath,
          line: f.lineNumber,
          sev: f.severity,
        }))
      )
    );
    const codeHashSha256 =
      sm?.artifactHashes?.workspaceCodeSha256 ||
      sm?.merkleOrChainRootSha256 ||
      sha256Hex(`${run.id}:${run.projectId}:${findingsDigest}`);

    const artifactHashes: Record<string, string> = {
      findingsDigestSha256: findingsDigest,
      gateDecisionSha256: gateEval.gateHash,
      ...(sm?.artifactHashes || {}),
    };

    const generatedAt = run.completedAt || run.startedAt || '2026-11-14T00:00:00.000Z';
    const canonicalPayload = JSON.stringify({
      runId: run.id,
      projectName: run.projectName,
      engineVersion,
      ruleCatalogVersion,
      ruleCatalogSha256,
      codeHashSha256,
      artifactHashes,
      appliedGateId: gateEval.gateId,
      appliedGateVersion: gateEval.gateVersion,
      appliedGateHashSha256: gateEval.gateHash,
      decision: gateEval.decision,
      findingsCount: (run.findings || []).length,
      generatedAt,
    });

    const reportContentSha256 = sha256Hex(canonicalPayload);
    const hmacSignature = computeHmacSha256(
      `${reportContentSha256}:${engineVersion}:${ruleCatalogSha256}:${codeHashSha256}:${gateEval.gateHash}`,
      hmacSecret
    );

    return {
      engineVersion,
      ruleCatalogVersion,
      ruleCatalogSha256,
      codeHashSha256,
      artifactHashes,
      appliedGateId: gateEval.gateId,
      appliedGateVersion: gateEval.gateVersion,
      appliedGateHashSha256: gateEval.gateHash,
      reportContentSha256,
      hmacAlgorithm: 'HMAC-SHA256',
      hmacSignature,
      generatedAt,
    };
  }

  /**
   * Verifies the cryptographic integrity (Report SHA-256 and HMAC-SHA256 signature)
   * embedded inside a generated PDF buffer.
   */
  public static verifyPdfIntegrity(
    pdfBuffer: Buffer,
    hmacSecret = DEFAULT_REPORT_HMAC_KEY
  ): {
    valid: boolean;
    reportContentSha256: string | null;
    hmacSignature: string | null;
    engineVersion: string | null;
    ruleCatalogSha256: string | null;
    codeHashSha256: string | null;
    appliedGateHashSha256: string | null;
  } {
    const raw = pdfBuffer.toString('latin1');
    const extract = (label: string): string | null => {
      const re = new RegExp(`${label}:\\s*([a-f0-9A-Za-z._-]+)`);
      const m = raw.match(re);
      return m ? m[1]! : null;
    };

    const reportContentSha256 = extract('Report-SHA256');
    const hmacSignature = extract('Report-HMAC-SHA256');
    const engineVersion = extract('Provenance-Engine-Version');
    const ruleCatalogSha256 = extract('Provenance-RuleCatalog-SHA256');
    const codeHashSha256 = extract('Provenance-Code-SHA256');
    const appliedGateHashSha256 = extract('Provenance-Gate-SHA256');

    if (
      !reportContentSha256 ||
      !hmacSignature ||
      !engineVersion ||
      !ruleCatalogSha256 ||
      !codeHashSha256 ||
      !appliedGateHashSha256
    ) {
      return {
        valid: false,
        reportContentSha256,
        hmacSignature,
        engineVersion,
        ruleCatalogSha256,
        codeHashSha256,
        appliedGateHashSha256,
      };
    }

    const expectedHmac = computeHmacSha256(
      `${reportContentSha256}:${engineVersion}:${ruleCatalogSha256}:${codeHashSha256}:${appliedGateHashSha256}`,
      hmacSecret
    );

    return {
      valid:
        raw.startsWith('%PDF-1.4') &&
        expectedHmac === hmacSignature &&
        reportContentSha256.length === 64,
      reportContentSha256,
      hmacSignature,
      engineVersion,
      ruleCatalogSha256,
      codeHashSha256,
      appliedGateHashSha256,
    };
  }

  /**
   * Generates a self-contained HTML5 report (100% inline CSS, zero external requests)
   * with executive summary, findings table, quality gate state, evidence chain, and provenance footer.
   */
  public static generateSelfContainedHtml(
    run: BenchmarkRun,
    hmacSecret = DEFAULT_REPORT_HMAC_KEY
  ): string {
    const gateEval = QualityGateEngine.evaluateFromRun(run);
    const provenance = this.buildProvenanceFooter(run, hmacSecret);
    const findings = run.findings || [];
    const chain = run.evidenceChain || [];

    const decisionColor =
      gateEval.decision === 'APPROVED'
        ? '#10b981'
        : gateEval.decision === 'APPROVED_WITH_RESERVATIONS'
          ? '#f59e0b'
          : gateEval.decision === 'INCONCLUSIVE'
            ? '#94a3b8'
            : '#ef4444';

    const findingsRows =
      findings.length === 0
        ? '<tr><td colspan="6" style="text-align:center;color:#94a3b8;">Nenhum apontamento detectado no escopo analisado.</td></tr>'
        : findings
            .slice(0, 100)
            .map(
              (f) => `<tr>
          <td><span class="sev sev-${escapeHtml(f.severity.toLowerCase())}">${escapeHtml(f.severity)}</span></td>
          <td><code>${escapeHtml(f.originalRuleId)}</code></td>
          <td>${escapeHtml(f.cwe || f.category || 'N/A')}</td>
          <td>${escapeHtml((f as { owaspCategory?: string; owasp?: string }).owaspCategory || (f as { owasp?: string }).owasp || 'N/A')}</td>
          <td><code>${escapeHtml(f.filePath)}:${f.lineNumber}</code></td>
          <td>${escapeHtml(f.title)}</td>
        </tr>`
            )
            .join('\n');

    const chainRows =
      chain.length === 0
        ? '<tr><td colspan="4" style="text-align:center;color:#94a3b8;">Trilha resumida no manifesto assinado abaixo.</td></tr>'
        : chain
            .slice(0, 25)
            .map(
              (b, idx) => `<tr>
          <td>#${idx + 1}</td>
          <td>${escapeHtml((b as { title?: string }).title || b.toolName || 'STEP')}</td>
          <td><code>${escapeHtml(((b as { previousHash?: string }).previousHash || 'GENESIS').slice(0, 20))}...</code></td>
          <td><code>${escapeHtml(((b as { sha256?: string }).sha256 || '').slice(0, 32))}...</code></td>
        </tr>`
            )
            .join('\n');

    const artifactRows = Object.entries(provenance.artifactHashes)
      .map(
        ([k, v]) =>
          `<li><strong>${escapeHtml(k)}:</strong> <code>${escapeHtml(v)}</code></li>`
      )
      .join('\n');

    return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>WinHood Audit Report — ${escapeHtml(run.projectName)} (${escapeHtml(run.id)})</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 32px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Ubuntu, monospace;
      background: #080b10;
      color: #e2e8f0;
      line-height: 1.5;
    }
    .container { max-width: 1180px; margin: 0 auto; }
    header {
      border: 1px solid #1e293b;
      background: #0f172a;
      padding: 24px;
      border-radius: 8px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 16px;
    }
    h1 { margin: 0 0 8px 0; font-size: 22px; color: #f8fafc; }
    h2 {
      font-size: 16px;
      color: #38bdf8;
      border-bottom: 1px solid #1e293b;
      padding-bottom: 8px;
      margin-top: 28px;
    }
    .gate-badge {
      display: inline-block;
      padding: 8px 16px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 14px;
      background: ${decisionColor}22;
      color: ${decisionColor};
      border: 1px solid ${decisionColor};
    }
    .card {
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 18px;
      margin-bottom: 16px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      background: #0f172a;
      border: 1px solid #1e293b;
    }
    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid #1e293b;
      text-align: left;
      vertical-align: top;
    }
    th { background: #1e293b; color: #cbd5e1; font-weight: 600; }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      background: #1e293b;
      padding: 2px 5px;
      border-radius: 4px;
      color: #38bdf8;
    }
    .sev {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
    }
    .sev-blocker, .sev-critical { background: #7f1d1d; color: #fecaca; }
    .sev-high { background: #7c2d12; color: #fed7aa; }
    .sev-medium { background: #78350f; color: #fde68a; }
    .sev-low, .sev-info { background: #1e3a8a; color: #bfdbfe; }
    footer.provenance-footer {
      margin-top: 36px;
      padding: 20px;
      border: 1px solid #334155;
      background: #090d16;
      border-radius: 8px;
      font-size: 12px;
      color: #94a3b8;
    }
    footer.provenance-footer ul { margin: 8px 0; padding-left: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>WINHOOD BENCHMARKING — RELATÓRIO DE AUDITORIA INDEPENDENTE (MODO MQR)</h1>
        <div>Execução: <code>${escapeHtml(run.id)}</code> | Projeto: <strong>${escapeHtml(run.projectName)}</strong></div>
        <div>Início: ${escapeHtml(run.startedAt)} | Conclusão: ${escapeHtml(run.completedAt || provenance.generatedAt)}</div>
      </div>
      <div>
        <div class="gate-badge">QUALITY GATE: ${escapeHtml(gateEval.decision)} (Exit Code ${gateEval.cliExitCode})</div>
      </div>
    </header>

    <section>
      <h2>1. Sumário Executivo</h2>
      <div class="card">
        <p>${escapeHtml(run.executiveSummary || 'Auditoria estática, fluxo de dados (Taint Analysis), segredos, IaC e composição de software (SCA/SBOM) concluída de forma determinística.')}</p>
      </div>
    </section>

    <section>
      <h2>2. Estado do Quality Gate (${escapeHtml(gateEval.gateName)} — v${escapeHtml(gateEval.gateVersion)})</h2>
      <table>
        <thead>
          <tr>
            <th>Condição</th>
            <th>Operador / Limite</th>
            <th>Valor Medido</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${gateEval.conditions
            .map(
              (c) => `<tr>
            <td>${escapeHtml(c.label)}</td>
            <td><code>${escapeHtml(c.operator)} ${escapeHtml(String(c.threshold))}</code></td>
            <td><code>${escapeHtml(String(c.actualValue ?? 'NOT_MEASURED'))}</code></td>
            <td><strong>${c.passed ? 'PASS' : c.inconclusive ? 'INCONCLUSIVE' : 'FAIL'}</strong></td>
          </tr>`
            )
            .join('\n')}
        </tbody>
      </table>
    </section>

    <section>
      <h2>3. Tabela de Achados (${findings.length} total)</h2>
      <table>
        <thead>
          <tr>
            <th>Severidade</th>
            <th>Regra</th>
            <th>CWE</th>
            <th>OWASP</th>
            <th>Localização</th>
            <th>Descrição</th>
          </tr>
        </thead>
        <tbody>
          ${findingsRows}
        </tbody>
      </table>
    </section>

    <section>
      <h2>4. Trilha Criptográfica de Evidência</h2>
      <table>
        <thead>
          <tr>
            <th>Bloco</th>
            <th>Etapa</th>
            <th>Hash Anterior (SHA-256)</th>
            <th>Hash do Elo (SHA-256)</th>
          </tr>
        </thead>
        <tbody>
          ${chainRows}
        </tbody>
      </table>
    </section>

    <footer class="provenance-footer" id="winhood-provenance-footer">
      <strong>RODAPÉ DE PROVENIÊNCIA CRIPTOGRÁFICA E ASSINATURA DO RELATÓRIO</strong>
      <ul>
        <li><strong>Versão do Motor (Engine Version):</strong> <code>${escapeHtml(provenance.engineVersion)}</code></li>
        <li><strong>Versão do Catálogo de Regras:</strong> <code>${escapeHtml(provenance.ruleCatalogVersion)}</code> (SHA-256: <code>${escapeHtml(provenance.ruleCatalogSha256)}</code>)</li>
        <li><strong>Hash do Código Analisado (Code SHA-256):</strong> <code>${escapeHtml(provenance.codeHashSha256)}</code></li>
        <li><strong>Versão do Quality Gate Aplicado:</strong> <code>${escapeHtml(provenance.appliedGateId)} v${escapeHtml(provenance.appliedGateVersion)}</code> (Gate SHA-256: <code>${escapeHtml(provenance.appliedGateHashSha256)}</code>)</li>
        <li><strong>Hash Canônico do Relatório (Report SHA-256):</strong> <code>${escapeHtml(provenance.reportContentSha256)}</code></li>
        <li><strong>Assinatura Criptográfica (${escapeHtml(provenance.hmacAlgorithm)}):</strong> <code>${escapeHtml(provenance.hmacSignature)}</code></li>
      </ul>
      <div><strong>Hashes dos Artefatos Vinculados:</strong></div>
      <ul>
        ${artifactRows}
      </ul>
    </footer>
  </div>
</body>
</html>`;
  }

  /**
   * Generates a deterministic, audit-grade binary PDF 1.4 document (%PDF-1.4)
   * with valid byte-accurate xref offsets, multi-page pagination, provenance footer,
   * embedded Report SHA-256, and HMAC-SHA256 signature.
   */
  public static generateFromRun(
    run: BenchmarkRun,
    hmacSecret = DEFAULT_REPORT_HMAC_KEY
  ): Buffer {
    const gateEval = QualityGateEngine.evaluateFromRun(run);
    const provenance = this.buildProvenanceFooter(run, hmacSecret);
    const compliance = ComplianceMapper.buildTraceabilityMatrix({
      runId: run.id,
      findings: run.findings || [],
      deterministicTimestamp: run.completedAt || run.startedAt,
    });

    const rawLines: Array<{ text: string; bold?: boolean; size?: number }> = [];
    const pushSection = (title: string) => {
      rawLines.push({ text: '' });
      rawLines.push({ text: title, bold: true, size: 12 });
      rawLines.push({ text: '-'.repeat(84) });
    };
    const pushLine = (text: string, bold = false, size = 10) => {
      for (const w of wrapText(text, 88)) {
        rawLines.push({ text: w, bold, size });
      }
    };

    pushLine('WINHOOD INDEPENDENT SOFTWARE AUDIT & BENCHMARKING REPORT (MQR MODE)', true, 14);
    pushLine(`Run ID: ${run.id} | Project: ${run.projectName} | Algorithm: ${run.algorithmVersion}`);
    pushLine(`Started: ${run.startedAt} | Completed: ${run.completedAt || provenance.generatedAt}`);

    pushSection('1. QUALITY GATE DECISION & VERSIONING');
    pushLine(`Gate: ${gateEval.gateName} (${gateEval.gateId} v${gateEval.gateVersion})`, true);
    pushLine(`Decision: ${gateEval.decision} | CLI Exit Code: ${gateEval.cliExitCode}`);
    pushLine(`Gate Hash (SHA-256): ${gateEval.gateHash}`);
    for (const cond of gateEval.conditions) {
      pushLine(
        `  [${cond.passed ? 'PASS' : cond.inconclusive ? 'INCONCLUSIVE' : 'FAIL'}] ${cond.label}: actual=${cond.actualValue ?? 'NOT_MEASURED'} (${cond.operator} ${cond.threshold})`
      );
    }

    pushSection('2. EXECUTIVE SUMMARY & SCORECARDS');
    pushLine(run.executiveSummary || 'No executive summary provided.');
    for (const sc of run.scoreCards || []) {
      const scoreStr =
        sc.separatedIndicators?.technicalScore !== null && sc.separatedIndicators?.technicalScore !== undefined
          ? `${sc.separatedIndicators.technicalScore.toFixed(2)} / 5.00`
          : 'NOT_MEASURED';
      pushLine(
        `- ${sc.softwareName} (${sc.softwareVersion}): Score=${scoreStr} | ScopeCov=${sc.separatedIndicators?.scopeCoveragePercent ?? 0}% | Confidence=${sc.separatedIndicators?.evidenceConfidence ?? 'LOW'} | Vulns=${sc.metricsSummary?.vulnerabilities ?? 0} | Secrets=${sc.metricsSummary?.secretsExposed ?? 0}`
      );
    }

    pushSection('3. SIGNED EVIDENCE PROVENANCE & ARTIFACT HASHES');
    if (run.signedManifest) {
      const sm = run.signedManifest;
      pushLine(`Manifest ID: ${sm.manifestId} | Signature Algorithm: ${sm.signatureAlgorithm || 'HMAC-SHA256'}`);
      pushLine(`Verification State: ${run.evidenceVerification?.verificationState || sm.verificationState} | Valid: ${Boolean(run.evidenceVerification?.valid)}`);
      pushLine(`Engine Version: ${sm.engineVersion || run.algorithmVersion} | Rule Catalog SHA-256: ${sm.ruleCatalogSha256 || provenance.ruleCatalogSha256}`);
      pushLine(`Root Chain SHA-256: ${sm.merkleOrChainRootSha256}`);
      pushLine(`Manifest Payload SHA-256: ${sm.manifestPayloadSha256}`);
      if (sm.artifactHashes) {
        for (const [k, v] of Object.entries(sm.artifactHashes)) {
          pushLine(`  Artifact [${k}]: ${v}`);
        }
      }
    } else {
      pushLine('Signed provenance computed directly from deterministic run state.');
    }

    pushSection('4. COMPLIANCE TRACEABILITY MATRIX (NON-CERTIFICATION)');
    pushLine(compliance.disclaimer);
    for (const [fw, entries] of Object.entries(compliance.byFramework)) {
      const detected = entries.filter((e) => e.findingsCount > 0);
      pushLine(`Framework ${fw}: ${detected.length}/${entries.length} controls with findings in analyzed scope`, true);
      for (const e of detected.slice(0, 8)) {
        pushLine(
          `  - ${e.controlId} (${e.controlTitle}): ${e.findingsCount} finding(s), CWEs=[${e.matchedCwes.join(', ')}]`
        );
      }
    }

    pushSection('5. FINDINGS SUMMARY (TOP 30 BY SEVERITY)');
    const sevOrder: Record<string, number> = {
      BLOCKER: 0,
      CRITICAL: 1,
      HIGH: 2,
      MEDIUM: 3,
      LOW: 4,
      INFO: 5,
    };
    const topFindings = [...(run.findings || [])]
      .sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9))
      .slice(0, 30);

    if (topFindings.length === 0) {
      pushLine('No active findings detected in analyzed scope.');
    } else {
      for (const f of topFindings) {
        pushLine(
          `[${f.severity}] ${f.originalRuleId} (${f.cwe || f.category}) - ${f.filePath}:${f.lineNumber} | ${f.title}`
        );
      }
    }

    pushSection('6. PROVENANCE FOOTER & CRYPTOGRAPHIC REPORT SIGNATURE');
    rawLines.push({ text: `Provenance-Engine-Version: ${provenance.engineVersion}`, bold: true, size: 10 });
    rawLines.push({ text: `Provenance-RuleCatalog-Version: ${provenance.ruleCatalogVersion}`, size: 10 });
    rawLines.push({ text: `Provenance-RuleCatalog-SHA256: ${provenance.ruleCatalogSha256}`, size: 10 });
    rawLines.push({ text: `Provenance-Code-SHA256: ${provenance.codeHashSha256}`, size: 10 });
    rawLines.push({
      text: `Provenance-Applied-Gate: ${provenance.appliedGateId} v${provenance.appliedGateVersion}`,
      size: 10,
    });
    rawLines.push({ text: `Provenance-Gate-SHA256: ${provenance.appliedGateHashSha256}`, size: 10 });
    for (const [k, v] of Object.entries(provenance.artifactHashes)) {
      rawLines.push({ text: `Provenance-Artifact-${k}: ${v}`, size: 10 });
    }
    rawLines.push({ text: `Report-SHA256: ${provenance.reportContentSha256}`, bold: true, size: 10 });
    rawLines.push({ text: `Report-HMAC-SHA256: ${provenance.hmacSignature}`, bold: true, size: 10 });

    const linesPerPage = 48;
    const pages: Array<typeof rawLines> = [];
    for (let i = 0; i < rawLines.length; i += linesPerPage) {
      pages.push(rawLines.slice(i, i + linesPerPage));
    }
    if (pages.length === 0) {
      pages.push([{ text: 'WinHood Empty Report' }]);
    }

    const objects: string[] = [];
    const pageObjIds: number[] = [];

    for (let p = 0; p < pages.length; p++) {
      const pageObjId = 5 + p * 2;
      const contentObjId = pageObjId + 1;
      pageObjIds.push(pageObjId);

      const pageLines = pages[p]!;
      const streamLines: string[] = ['BT', '/F1 10 Tf', '42 752 Td'];
      let currentY = 752;
      for (const item of pageLines) {
        const fontRef = item.bold ? '/F2' : '/F1';
        const fontSize = item.size || 10;
        const step = fontSize >= 12 ? 15 : 13;
        streamLines.push(`${fontRef} ${fontSize} Tf`);
        streamLines.push(`(${toPdfAscii(item.text)}) Tj`);
        streamLines.push(`0 -${step} Td`);
        currentY -= step;
        if (currentY < 45) break;
      }
      streamLines.push(
        `(${toPdfAscii(`WinHood Signed Audit Report - Page ${p + 1}/${pages.length} | SHA256:${provenance.reportContentSha256.slice(0, 16)}`)}) Tj`
      );
      streamLines.push('ET');
      const streamContent = streamLines.join('\n');

      objects[pageObjId - 1] =
        `${pageObjId} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentObjId} 0 R >>\nendobj\n`;
      objects[contentObjId - 1] =
        `${contentObjId} 0 obj\n<< /Length ${Buffer.byteLength(streamContent, 'latin1')} >>\nstream\n${streamContent}\nendstream\nendobj\n`;
    }

    objects[0] = `1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n`;
    objects[1] = `2 0 obj\n<< /Type /Pages /Kids [${pageObjIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${pageObjIds.length} >>\nendobj\n`;
    objects[2] = `3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n`;
    objects[3] = `4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n`;

    const chunks: string[] = ['%PDF-1.4\n'];
    const offsets: number[] = [0];
    let byteCursor = Buffer.byteLength(chunks[0]!, 'latin1');

    for (let i = 0; i < objects.length; i++) {
      offsets.push(byteCursor);
      const objStr = objects[i]!;
      chunks.push(objStr);
      byteCursor += Buffer.byteLength(objStr, 'latin1');
    }

    const xrefOffset = byteCursor;
    const xrefLines: string[] = [`xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`];
    for (let i = 1; i <= objects.length; i++) {
      xrefLines.push(`${String(offsets[i]).padStart(10, '0')} 00000 n \n`);
    }
    const trailer = `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;

    chunks.push(xrefLines.join(''), trailer);
    return Buffer.from(chunks.join(''), 'latin1');
  }

  /**
   * Unified multi-format ReportExporter supporting pdf, html, sarif, and json.
   */
  public static exportReport(
    run: BenchmarkRun,
    format: 'pdf' | 'html' | 'sarif' | 'json',
    hmacSecret = DEFAULT_REPORT_HMAC_KEY
  ): { contentType: string; buffer: Buffer; provenance: ReportProvenanceFooter } {
    const provenance = this.buildProvenanceFooter(run, hmacSecret);
    const gateEval = QualityGateEngine.evaluateFromRun(run);

    if (format === 'pdf') {
      const buf = this.generateFromRun(run, hmacSecret);
      return { contentType: 'application/pdf', buffer: buf, provenance };
    }

    if (format === 'html') {
      const html = this.generateSelfContainedHtml(run, hmacSecret);
      return {
        contentType: 'text/html; charset=utf-8',
        buffer: Buffer.from(html, 'utf8'),
        provenance,
      };
    }

    if (format === 'sarif') {
      const sarif = SarifCodec.exportSarif210(run.findings || [], {
        toolVersion: provenance.engineVersion,
      }) as unknown as Record<string, unknown>;
      const runs = (sarif.runs as Array<Record<string, unknown>>) || [];
      if (runs[0]) {
        runs[0].properties = {
          ...((runs[0].properties as Record<string, unknown>) || {}),
          gateDecision: gateEval.decision,
          gateVersion: gateEval.gateVersion,
          provenanceFooter: provenance,
        };
      }
      return {
        contentType: 'application/sarif+json; charset=utf-8',
        buffer: Buffer.from(JSON.stringify(sarif, null, 2), 'utf8'),
        provenance,
      };
    }

    const jsonReport = {
      schemaVersion: 'winhood-audit-report/v4.4.0',
      runId: run.id,
      projectName: run.projectName,
      startedAt: run.startedAt,
      completedAt: run.completedAt || provenance.generatedAt,
      executiveSummary: run.executiveSummary,
      qualityGate: gateEval,
      scoreCards: run.scoreCards,
      findingsCount: (run.findings || []).length,
      findings: run.findings || [],
      evidenceVerification: run.evidenceVerification,
      signedManifest: run.signedManifest,
      provenanceFooter: provenance,
    };

    return {
      contentType: 'application/json; charset=utf-8',
      buffer: Buffer.from(JSON.stringify(jsonReport, null, 2), 'utf8'),
      provenance,
    };
  }
}

export const ReportExporter = PdfReportGenerator;
