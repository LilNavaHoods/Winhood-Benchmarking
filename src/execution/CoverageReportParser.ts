import crypto from 'node:crypto';
import type { ParsedCoverageReportSummary } from '../types/benchmark';

/**
 * Real Test Coverage Report Parser (P0/P1/AC-07)
 * Parses LCOV (lcov.info), JaCoCo XML, Cobertura XML, and Istanbul coverage-final.json.
 * - Never fabricates line counts when Cobertura only reports `line-rate`.
 * - Deduplicates repeated SF/file entries across multiple aggregated reports.
 * - Marks malformed or empty reports explicitly as FAILED / INCONCLUSIVE.
 */
export class CoverageReportParser {
  public static parseFromFilesMap(filesMap: Record<string, string>): ParsedCoverageReportSummary {
    const entries = Object.entries(filesMap || {});

    // 1. LCOV (lcov.info, *.lcov)
    const lcovFiles = entries.filter(([p]) => {
      const lower = p.toLowerCase();
      return lower.endsWith('lcov.info') || lower.endsWith('.lcov');
    });
    if (lcovFiles.length > 0) {
      return CoverageReportParser.parseMultipleLcov(lcovFiles);
    }

    // 2. JaCoCo XML (jacoco.xml / jacocoTestReport.xml)
    const jacocoFiles = entries.filter(([p, c]) => {
      const lower = p.toLowerCase();
      return (
        (lower.includes('jacoco') && lower.endsWith('.xml')) ||
        (lower.endsWith('.xml') && c.includes('<report') && c.includes('<counter type="LINE"'))
      );
    });
    if (jacocoFiles.length > 0) {
      return CoverageReportParser.parseMultipleJacocoXml(jacocoFiles);
    }

    // 3. Cobertura XML (cobertura.xml / coverage.xml)
    const coberturaFiles = entries.filter(([p, c]) => {
      const lower = p.toLowerCase();
      return (
        (lower.includes('cobertura') && lower.endsWith('.xml')) ||
        (lower.endsWith('.xml') && c.includes('<coverage') && (c.includes('line-rate=') || c.includes('lines-valid=')))
      );
    });
    if (coberturaFiles.length > 0) {
      return CoverageReportParser.parseCoberturaXml(
        coberturaFiles.map(([p]) => p),
        coberturaFiles[0]![1]
      );
    }

    // 4. Istanbul coverage-final.json
    const istanbulFiles = entries.filter(([p, c]) => {
      const lower = p.toLowerCase();
      return lower.endsWith('coverage-final.json') || (lower.endsWith('.json') && c.includes('"statementMap"') && c.includes('"s":{'));
    });
    if (istanbulFiles.length > 0) {
      return CoverageReportParser.parseMultipleIstanbulJson(istanbulFiles);
    }

    return {
      found: false,
      format: 'NONE',
      sourceFiles: [],
      linesFound: null,
      linesHit: null,
      branchesFound: null,
      branchesHit: null,
      lineCoveragePercent: null,
      branchCoveragePercent: null,
      state: 'NOT_MEASURED',
      evidenceHash: null,
      limitations: ['Nenhum relatório real de cobertura (LCOV, JaCoCo, Cobertura, Istanbul) encontrado.'],
    };
  }

  private static parseMultipleLcov(files: Array<[string, string]>): ParsedCoverageReportSummary {
    const sourceFiles = files.map(([p]) => p);
    const combinedRaw = files.map(([, c]) => c).join('\n');
    return CoverageReportParser.parseLcov(sourceFiles, combinedRaw);
  }

  public static parseLcov(sourceFiles: string[], content: string): ParsedCoverageReportSummary {
    if (!content || !content.trim()) {
      return {
        found: false,
        format: 'LCOV',
        sourceFiles,
        linesFound: null,
        linesHit: null,
        branchesFound: null,
        branchesHit: null,
        lineCoveragePercent: null,
        branchCoveragePercent: null,
        state: 'INCONCLUSIVE',
        evidenceHash: crypto.createHash('sha256').update(content || '', 'utf8').digest('hex'),
        limitations: ['Relatório LCOV vazio.'],
      };
    }

    // Aggregate per SF (source file) deduplicating repeated blocks across multiple reports
    const fileLinesMap = new Map<string, Map<number, number>>();
    const fileBranchesMap = new Map<string, Map<string, number>>();
    let fallbackLf = 0;
    let fallbackLh = 0;
    let fallbackBrf = 0;
    let fallbackBrh = 0;
    let currentSf = '__default__';
    let sawDaLines = false;

    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) continue;
      if (line.startsWith('SF:')) {
        currentSf = line.slice(3).trim() || '__default__';
        if (!fileLinesMap.has(currentSf)) fileLinesMap.set(currentSf, new Map());
        if (!fileBranchesMap.has(currentSf)) fileBranchesMap.set(currentSf, new Map());
      } else if (line.startsWith('DA:')) {
        const parts = line.slice(3).split(',');
        const lineNum = Number.parseInt(parts[0] || '', 10);
        const hits = Number.parseInt(parts[1] || '0', 10) || 0;
        if (!Number.isNaN(lineNum)) {
          sawDaLines = true;
          if (!fileLinesMap.has(currentSf)) fileLinesMap.set(currentSf, new Map());
          const perFile = fileLinesMap.get(currentSf)!;
          perFile.set(lineNum, Math.max(perFile.get(lineNum) ?? 0, hits));
        }
      } else if (line.startsWith('BRDA:')) {
        const parts = line.slice(5).split(',');
        if (parts.length >= 4) {
          const key = `${parts[0]}:${parts[1]}:${parts[2]}`;
          const taken = parts[3] === '-' ? 0 : Number.parseInt(parts[3] || '0', 10) || 0;
          if (!fileBranchesMap.has(currentSf)) fileBranchesMap.set(currentSf, new Map());
          const bf = fileBranchesMap.get(currentSf)!;
          bf.set(key, Math.max(bf.get(key) ?? 0, taken));
        }
      } else if (line.startsWith('LF:')) {
        fallbackLf += Number.parseInt(line.slice(3), 10) || 0;
      } else if (line.startsWith('LH:')) {
        fallbackLh += Number.parseInt(line.slice(3), 10) || 0;
      } else if (line.startsWith('BRF:')) {
        fallbackBrf += Number.parseInt(line.slice(4), 10) || 0;
      } else if (line.startsWith('BRH:')) {
        fallbackBrh += Number.parseInt(line.slice(4), 10) || 0;
      }
    }

    let linesFound = 0;
    let linesHit = 0;
    if (sawDaLines) {
      for (const perFile of fileLinesMap.values()) {
        for (const hits of perFile.values()) {
          linesFound += 1;
          if (hits > 0) linesHit += 1;
        }
      }
    } else {
      linesFound = fallbackLf;
      linesHit = fallbackLh;
    }

    let branchesFound = 0;
    let branchesHit = 0;
    for (const bf of fileBranchesMap.values()) {
      for (const hits of bf.values()) {
        branchesFound += 1;
        if (hits > 0) branchesHit += 1;
      }
    }
    if (branchesFound === 0 && fallbackBrf > 0) {
      branchesFound = fallbackBrf;
      branchesHit = fallbackBrh;
    }

    const linePct = linesFound > 0 ? Math.round((linesHit / linesFound) * 1000) / 10 : null;
    const branchPct = branchesFound > 0 ? Math.round((branchesHit / branchesFound) * 1000) / 10 : null;

    return {
      found: linesFound > 0,
      format: 'LCOV',
      sourceFiles,
      linesFound: linesFound > 0 ? linesFound : null,
      linesHit: linesFound > 0 ? linesHit : null,
      branchesFound: branchesFound > 0 ? branchesFound : null,
      branchesHit: branchesFound > 0 ? branchesHit : null,
      lineCoveragePercent: linePct,
      branchCoveragePercent: branchPct,
      state: linesFound > 0 ? 'MEASURED' : 'INCONCLUSIVE',
      evidenceHash: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
    };
  }

  private static parseMultipleJacocoXml(files: Array<[string, string]>): ParsedCoverageReportSummary {
    let totalLinesMissed = 0;
    let totalLinesCovered = 0;
    let totalBranchesMissed = 0;
    let totalBranchesCovered = 0;

    for (const [, c] of files) {
      const parsed = CoverageReportParser.parseJacocoXml([], c);
      if (parsed.linesFound !== null && parsed.linesHit !== null) {
        totalLinesCovered += parsed.linesHit;
        totalLinesMissed += parsed.linesFound - parsed.linesHit;
      }
      if (parsed.branchesFound !== null && parsed.branchesHit !== null) {
        totalBranchesCovered += parsed.branchesHit;
        totalBranchesMissed += parsed.branchesFound - parsed.branchesHit;
      }
    }

    const linesFound = totalLinesMissed + totalLinesCovered;
    const branchesFound = totalBranchesMissed + totalBranchesCovered;
    const combinedRaw = files.map(([, c]) => c).join('\n');

    return {
      found: linesFound > 0,
      format: 'JACOCO_XML',
      sourceFiles: files.map(([p]) => p),
      linesFound: linesFound > 0 ? linesFound : null,
      linesHit: linesFound > 0 ? totalLinesCovered : null,
      branchesFound: branchesFound > 0 ? branchesFound : null,
      branchesHit: branchesFound > 0 ? totalBranchesCovered : null,
      lineCoveragePercent: linesFound > 0 ? Math.round((totalLinesCovered / linesFound) * 1000) / 10 : null,
      branchCoveragePercent:
        branchesFound > 0 ? Math.round((totalBranchesCovered / branchesFound) * 1000) / 10 : null,
      state: linesFound > 0 ? 'MEASURED' : 'INCONCLUSIVE',
      evidenceHash: crypto.createHash('sha256').update(combinedRaw, 'utf8').digest('hex'),
    };
  }

  public static parseJacocoXml(sourceFiles: string[], content: string): ParsedCoverageReportSummary {
    const lineMatches = [...content.matchAll(/<counter\s+type="LINE"\s+missed="(\d+)"\s+covered="(\d+)"\s*\/>/g)];
    const branchMatches = [...content.matchAll(/<counter\s+type="BRANCH"\s+missed="(\d+)"\s+covered="(\d+)"\s*\/>/g)];

    if (lineMatches.length === 0) {
      return {
        found: false,
        format: 'JACOCO_XML',
        sourceFiles,
        linesFound: null,
        linesHit: null,
        branchesFound: null,
        branchesHit: null,
        lineCoveragePercent: null,
        branchCoveragePercent: null,
        state: 'INCONCLUSIVE',
        evidenceHash: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
        limitations: ['Relatório JaCoCo XML não contém contadores <counter type="LINE"/>.'],
      };
    }

    const lastLine = lineMatches[lineMatches.length - 1]!;
    const linesMissed = Number.parseInt(lastLine[1]!, 10) || 0;
    const linesCovered = Number.parseInt(lastLine[2]!, 10) || 0;

    let branchesMissed = 0;
    let branchesCovered = 0;
    if (branchMatches.length > 0) {
      const lastBranch = branchMatches[branchMatches.length - 1]!;
      branchesMissed = Number.parseInt(lastBranch[1]!, 10) || 0;
      branchesCovered = Number.parseInt(lastBranch[2]!, 10) || 0;
    }

    const linesFound = linesMissed + linesCovered;
    const branchesFound = branchesMissed + branchesCovered;

    return {
      found: linesFound > 0,
      format: 'JACOCO_XML',
      sourceFiles,
      linesFound: linesFound > 0 ? linesFound : null,
      linesHit: linesFound > 0 ? linesCovered : null,
      branchesFound: branchesFound > 0 ? branchesFound : null,
      branchesHit: branchesFound > 0 ? branchesCovered : null,
      lineCoveragePercent: linesFound > 0 ? Math.round((linesCovered / linesFound) * 1000) / 10 : null,
      branchCoveragePercent: branchesFound > 0 ? Math.round((branchesCovered / branchesFound) * 1000) / 10 : null,
      state: linesFound > 0 ? 'MEASURED' : 'INCONCLUSIVE',
      evidenceHash: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
    };
  }

  public static parseCoberturaXml(sourceFiles: string[], content: string): ParsedCoverageReportSummary {
    const linesValidM = content.match(/lines-valid="(\d+)"/);
    const linesCovM = content.match(/lines-covered="(\d+)"/);
    const branchesValidM = content.match(/branches-valid="(\d+)"/);
    const branchesCovM = content.match(/branches-covered="(\d+)"/);
    const lineRateM = content.match(/line-rate="([0-9.]+)"/);
    const branchRateM = content.match(/branch-rate="([0-9.]+)"/);

    // NEVER synthesize linesFound = 100 when lines-valid is absent (P0.4 / AC-07)
    const linesFound: number | null = linesValidM ? Number.parseInt(linesValidM[1]!, 10) : null;
    const linesHit: number | null = linesCovM ? Number.parseInt(linesCovM[1]!, 10) : null;
    const branchesFound: number | null = branchesValidM ? Number.parseInt(branchesValidM[1]!, 10) : null;
    const branchesHit: number | null = branchesCovM ? Number.parseInt(branchesCovM[1]!, 10) : null;

    let linePct: number | null = null;
    const limitations: string[] = [];

    if (linesFound !== null && linesHit !== null && linesFound > 0) {
      linePct = Math.round((linesHit / linesFound) * 1000) / 10;
    } else if (lineRateM) {
      const rate = Number.parseFloat(lineRateM[1]!);
      if (!Number.isNaN(rate) && rate >= 0 && rate <= 1) {
        linePct = Math.round(rate * 1000) / 10;
        limitations.push(
          'Cobertura XML informou apenas line-rate agregado sem lines-valid/lines-covered; contagem absoluta de linhas permanece null.'
        );
      }
    }

    let branchPct: number | null = null;
    if (branchesFound !== null && branchesHit !== null && branchesFound > 0) {
      branchPct = Math.round((branchesHit / branchesFound) * 1000) / 10;
    } else if (branchRateM) {
      const bRate = Number.parseFloat(branchRateM[1]!);
      if (!Number.isNaN(bRate) && bRate >= 0 && bRate <= 1) {
        branchPct = Math.round(bRate * 1000) / 10;
      }
    }

    return {
      found: linePct !== null,
      format: 'COBERTURA_XML',
      sourceFiles,
      linesFound,
      linesHit,
      branchesFound,
      branchesHit,
      lineCoveragePercent: linePct,
      branchCoveragePercent: branchPct,
      state: linePct !== null ? 'MEASURED' : 'INCONCLUSIVE',
      evidenceHash: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
      limitations: limitations.length > 0 ? limitations : undefined,
    };
  }

  private static parseMultipleIstanbulJson(files: Array<[string, string]>): ParsedCoverageReportSummary {
    const merged: Record<string, { s?: Record<string, number>; b?: Record<string, number[]> }> = {};
    for (const [, content] of files) {
      try {
        const parsed = JSON.parse(content) as Record<
          string,
          { s?: Record<string, number>; b?: Record<string, number[]> }
        >;
        for (const [fp, entry] of Object.entries(parsed)) {
          if (!merged[fp]) {
            merged[fp] = entry;
          } else {
            // Merge hit counts taking max without duplicating statement keys
            const prevS = merged[fp]!.s || {};
            const nextS = entry.s || {};
            for (const [k, v] of Object.entries(nextS)) {
              prevS[k] = Math.max(prevS[k] ?? 0, v);
            }
            merged[fp]!.s = prevS;
          }
        }
      } catch {
        return {
          found: false,
          format: 'ISTANBUL_JSON',
          sourceFiles: files.map(([p]) => p),
          linesFound: null,
          linesHit: null,
          branchesFound: null,
          branchesHit: null,
          lineCoveragePercent: null,
          branchCoveragePercent: null,
          state: 'FAILED',
          evidenceHash: crypto.createHash('sha256').update(files.map(([, c]) => c).join('\n'), 'utf8').digest('hex'),
          limitations: ['Falha ao interpretar JSON de cobertura Istanbul (arquivo corrompido ou malformado).'],
        };
      }
    }

    return CoverageReportParser.parseIstanbulJson(
      files.map(([p]) => p),
      JSON.stringify(merged)
    );
  }

  public static parseIstanbulJson(sourceFiles: string[], content: string): ParsedCoverageReportSummary {
    try {
      const parsed = JSON.parse(content) as Record<
        string,
        { s?: Record<string, number>; b?: Record<string, number[]> }
      >;
      let linesFound = 0;
      let linesHit = 0;
      let branchesFound = 0;
      let branchesHit = 0;

      for (const fileCov of Object.values(parsed)) {
        if (fileCov?.s) {
          const vals = Object.values(fileCov.s);
          linesFound += vals.length;
          linesHit += vals.filter((count) => count > 0).length;
        }
        if (fileCov?.b) {
          for (const branchCounts of Object.values(fileCov.b)) {
            if (Array.isArray(branchCounts)) {
              branchesFound += branchCounts.length;
              branchesHit += branchCounts.filter((c) => c > 0).length;
            }
          }
        }
      }

      return {
        found: linesFound > 0,
        format: 'ISTANBUL_JSON',
        sourceFiles,
        linesFound: linesFound > 0 ? linesFound : null,
        linesHit: linesFound > 0 ? linesHit : null,
        branchesFound: branchesFound > 0 ? branchesFound : null,
        branchesHit: branchesFound > 0 ? branchesHit : null,
        lineCoveragePercent: linesFound > 0 ? Math.round((linesHit / linesFound) * 1000) / 10 : null,
        branchCoveragePercent: branchesFound > 0 ? Math.round((branchesHit / branchesFound) * 1000) / 10 : null,
        state: linesFound > 0 ? 'MEASURED' : 'INCONCLUSIVE',
        evidenceHash: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
      };
    } catch {
      return {
        found: false,
        format: 'ISTANBUL_JSON',
        sourceFiles,
        linesFound: null,
        linesHit: null,
        branchesFound: null,
        branchesHit: null,
        lineCoveragePercent: null,
        branchCoveragePercent: null,
        state: 'FAILED',
        evidenceHash: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
        limitations: ['JSON de cobertura Istanbul malformado.'],
      };
    }
  }
}
