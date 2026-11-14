import { ComplianceMapper } from '../evidence/ComplianceMapper';
import { QualityGateEngine } from '../gate/QualityGateEngine';
import type { BenchmarkRun } from '../types/benchmark';

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
  /**
   * Generates a deterministic, audit-grade binary PDF 1.4 document (%PDF-1.4)
   * with valid byte-accurate xref offsets and multi-page pagination.
   */
  public static generateFromRun(run: BenchmarkRun): Buffer {
    const gateEval = QualityGateEngine.evaluateFromRun(run);
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

    pushLine('WINHOOD INDEPENDENT SOFTWARE AUDIT & BENCHMARKING REPORT', true, 14);
    pushLine(`Run ID: ${run.id} | Project: ${run.projectName} | Algorithm: ${run.algorithmVersion}`);
    pushLine(`Started: ${run.startedAt} | Completed: ${run.completedAt}`);

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
      pushLine(`Engine Version: ${sm.engineVersion || run.algorithmVersion} | Rule Catalog SHA-256: ${sm.ruleCatalogSha256 || 'N/A'}`);
      pushLine(`Root Chain SHA-256: ${sm.merkleOrChainRootSha256}`);
      pushLine(`Manifest Payload SHA-256: ${sm.manifestPayloadSha256}`);
      if (sm.artifactHashes) {
        for (const [k, v] of Object.entries(sm.artifactHashes)) {
          pushLine(`  Artifact [${k}]: ${v}`);
        }
      }
    } else {
      pushLine('No signed evidence manifest attached to this run.');
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

    // Paginate lines across US Letter (612 x 792 pt)
    const linesPerPage = 52;
    const pages: Array<typeof rawLines> = [];
    for (let i = 0; i < rawLines.length; i += linesPerPage) {
      pages.push(rawLines.slice(i, i + linesPerPage));
    }
    if (pages.length === 0) {
      pages.push([{ text: 'WinHood Empty Report' }]);
    }

    // Build PDF objects:
    // 1: Catalog, 2: Pages, 3: Font Helvetica, 4: Font Helvetica-Bold
    // Then pairs of (Page, ContentStream) for each page
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
      streamLines.push(`(${toPdfAscii(`WinHood Audit Report - Page ${p + 1}/${pages.length}`)}) Tj`);
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
}
