import crypto from 'node:crypto';
import type { ParsedCoverageReportSummary } from '../types/benchmark';

/**
 * Real Test Coverage Report Parser (P0/P3)
 * Parses LCOV (lcov.info), JaCoCo XML, Cobertura XML, and Istanbul coverage-final.json.
 * Never fabricates test coverage from file counts when no report is present.
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
      return CoverageReportParser.parseLcov(lcovFiles.map(([p]) => p), lcovFiles.map(([, c]) => c).join('\n'));
    }

    // 2. JaCoCo XML (jacoco.xml / jacocoTestReport.xml)
    const jacocoFiles = entries.filter(([p, c]) => {
      const lower = p.toLowerCase();
      return (lower.includes('jacoco') && lower.endsWith('.xml')) || (lower.endsWith('.xml') && c.includes('<report name=') && c.includes('<counter type="LINE"'));
    });
    if (jacocoFiles.length > 0) {
      return CoverageReportParser.parseJacocoXml(jacocoFiles.map(([p]) => p), jacocoFiles.map(([, c]) => c).join('\n'));
    }

    // 3. Cobertura XML (cobertura.xml / coverage.xml)
    const coberturaFiles = entries.filter(([p, c]) => {
      const lower = p.toLowerCase();
      return (lower.includes('cobertura') && lower.endsWith('.xml')) || (lower.endsWith('.xml') && c.includes('<coverage') && c.includes('line-rate='));
    });
    if (coberturaFiles.length > 0) {
      return CoverageReportParser.parseCoberturaXml(coberturaFiles.map(([p]) => p), coberturaFiles[0]![1]);
    }

    // 4. Istanbul coverage-final.json
    const istanbulFiles = entries.filter(([p, c]) => {
      const lower = p.toLowerCase();
      return lower.endsWith('coverage-final.json') || (lower.endsWith('.json') && c.includes('"statementMap"') && c.includes('"s":{'));
    });
    if (istanbulFiles.length > 0) {
      return CoverageReportParser.parseIstanbulJson(istanbulFiles.map(([p]) => p), istanbulFiles[0]![1]);
    }

    return {
      found: false,
      format: 'NONE',
      sourceFiles: [],
      linesFound: 0,
      linesHit: 0,
      branchesFound: 0,
      branchesHit: 0,
      lineCoveragePercent: null,
      branchCoveragePercent: null,
      state: 'NOT_MEASURED',
      evidenceHash: null,
    };
  }

  public static parseLcov(sourceFiles: string[], content: string): ParsedCoverageReportSummary {
    let linesFound = 0;
    let linesHit = 0;
    let branchesFound = 0;
    let branchesHit = 0;
    let daTotal = 0;
    let daHit = 0;

    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (line.startsWith('LF:')) {
        linesFound += Number.parseInt(line.slice(3), 10) || 0;
      } else if (line.startsWith('LH:')) {
        linesHit += Number.parseInt(line.slice(3), 10) || 0;
      } else if (line.startsWith('BRF:')) {
        branchesFound += Number.parseInt(line.slice(4), 10) || 0;
      } else if (line.startsWith('BRH:')) {
        branchesHit += Number.parseInt(line.slice(4), 10) || 0;
      } else if (line.startsWith('DA:')) {
        const parts = line.slice(3).split(',');
        if (parts.length >= 2) {
          daTotal += 1;
          if ((Number.parseInt(parts[1], 10) || 0) > 0) daHit += 1;
        }
      }
    }

    if (linesFound === 0 && daTotal > 0) {
      linesFound = daTotal;
      linesHit = daHit;
    }

    const linePct = linesFound > 0 ? Math.round((linesHit / linesFound) * 1000) / 10 : null;
    const branchPct = branchesFound > 0 ? Math.round((branchesHit / branchesFound) * 1000) / 10 : null;

    return {
      found: linesFound > 0,
      format: 'LCOV',
      sourceFiles,
      linesFound,
      linesHit,
      branchesFound,
      branchesHit,
      lineCoveragePercent: linePct,
      branchCoveragePercent: branchPct,
      state: linesFound > 0 ? 'MEASURED' : 'INCONCLUSIVE',
      evidenceHash: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
    };
  }

  public static parseJacocoXml(sourceFiles: string[], content: string): ParsedCoverageReportSummary {
    // Parse top-level or summed <counter type="LINE" missed="..." covered="..."/>
    let linesMissed = 0;
    let linesCovered = 0;
    let branchesMissed = 0;
    let branchesCovered = 0;

    // Prefer report-level counters (after </package>) if present, else sum class/package counters safely
    const lineMatches = [...content.matchAll(/<counter\s+type="LINE"\s+missed="(\d+)"\s+covered="(\d+)"\s*\/>/g)];
    const branchMatches = [...content.matchAll(/<counter\s+type="BRANCH"\s+missed="(\d+)"\s+covered="(\d+)"\s*\/>/g)];

    if (lineMatches.length > 0) {
      // Last LINE counter inside <report> is the aggregated report-level counter in JaCoCo schema
      const last = lineMatches[lineMatches.length - 1]!;
      linesMissed = Number.parseInt(last[1]!, 10) || 0;
      linesCovered = Number.parseInt(last[2]!, 10) || 0;
    }
    if (branchMatches.length > 0) {
      const last = branchMatches[branchMatches.length - 1]!;
      branchesMissed = Number.parseInt(last[1]!, 10) || 0;
      branchesCovered = Number.parseInt(last[2]!, 10) || 0;
    }

    const linesFound = linesMissed + linesCovered;
    const branchesFound = branchesMissed + branchesCovered;

    return {
      found: linesFound > 0,
      format: 'JACOCO_XML',
      sourceFiles,
      linesFound,
      linesHit: linesCovered,
      branchesFound,
      branchesHit: branchesCovered,
      lineCoveragePercent: linesFound > 0 ? Math.round((linesCovered / linesFound) * 1000) / 10 : null,
      branchCoveragePercent: branchesFound > 0 ? Math.round((branchesCovered / branchesFound) * 1000) / 10 : null,
      state: linesFound > 0 ? 'MEASURED' : 'INCONCLUSIVE',
      evidenceHash: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
    };
  }

  public static parseCoberturaXml(sourceFiles: string[], content: string): ParsedCoverageReportSummary {
    const linesValidM = content.match(/lines-valid="(\d+)"/);
    const linesCovM = content.match(/lines-covered="(\d+)"/);
    const lineRateM = content.match(/line-rate="([0-9.]+)"/);
    const branchRateM = content.match(/branch-rate="([0-9.]+)"/);

    let linesFound = linesValidM ? Number.parseInt(linesValidM[1]!, 10) : 0;
    let linesHit = linesCovM ? Number.parseInt(linesCovM[1]!, 10) : 0;
    let linePct: number | null = null;

    if (linesFound > 0) {
      linePct = Math.round((linesHit / linesFound) * 1000) / 10;
    } else if (lineRateM) {
      const rate = Number.parseFloat(lineRateM[1]!);
      if (!Number.isNaN(rate)) {
        linePct = Math.round(rate * 1000) / 10;
        linesFound = 100;
        linesHit = Math.round(linePct);
      }
    }

    const branchPct = branchRateM
      ? Math.round((Number.parseFloat(branchRateM[1]!) || 0) * 1000) / 10
      : null;

    return {
      found: linePct !== null,
      format: 'COBERTURA_XML',
      sourceFiles,
      linesFound,
      linesHit,
      branchesFound: 0,
      branchesHit: 0,
      lineCoveragePercent: linePct,
      branchCoveragePercent: branchPct,
      state: linePct !== null ? 'MEASURED' : 'INCONCLUSIVE',
      evidenceHash: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
    };
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
        linesFound,
        linesHit,
        branchesFound,
        branchesHit,
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
        linesFound: 0,
        linesHit: 0,
        branchesFound: 0,
        branchesHit: 0,
        lineCoveragePercent: null,
        branchCoveragePercent: null,
        state: 'FAILED',
        evidenceHash: crypto.createHash('sha256').update(content, 'utf8').digest('hex'),
      };
    }
  }
}
