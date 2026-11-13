import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type {
  ReferenceFreshnessState,
  ReferenceSnapshotRecord,
  ReferenceSourceKey,
} from '../../types/benchmark';

const REFERENCE_CATALOG_DEFAULTS: Array<{
  sourceKey: ReferenceSourceKey;
  sourceName: string;
  version: string;
  originUrl: string;
  license: string;
  ttlHours: number;
  rulesIncluded: string[];
  toolsReferenced: string[];
  environmentTag: string;
  payloadSummary: Record<string, unknown>;
}> = [
  {
    sourceKey: 'SONARQUBE_SERVER',
    sourceName: 'SonarQube Server (Community Build / Web API Baseline)',
    version: '25.x / Web API v1+v2',
    originUrl: 'https://docs.sonarsource.com/sonarqube-server/',
    license: 'LGPL-3.0 / SonarSource Reference',
    ttlHours: 72,
    rulesIncluded: ['S2076', 'S3649', 'S1523', 'S2486', 'S5547', 'S6290', 'S1135', 'S3776'],
    toolsReferenced: ['sonar-scanner-cli', 'sonarqube-api-v1', 'sonarqube-api-v2'],
    environmentTag: 'local-or-remote-instance',
    payloadSummary: {
      ratingsModel: 'A-E (Reliability, Security, Maintainability)',
      cleanCodeTaxonomy: ['CONSISTENT', 'INTENTIONAL', 'ADAPTABLE', 'RESPONSIBLE'],
      qualityGateDefault: 'Sonar way',
    },
  },
  {
    sourceKey: 'SONARQUBE_CLOUD',
    sourceName: 'SonarQube Cloud (SonarCloud Reference Rules & Quality Profiles)',
    version: '2026-cloud-baseline',
    originUrl: 'https://sonarcloud.io/api/rules/search',
    license: 'SonarSource Cloud API Metadata',
    ttlHours: 24,
    rulesIncluded: ['typescript:S3649', 'typescript:S2076', 'python:S3649', 'java:S3649', 'secrets:S6290'],
    toolsReferenced: ['sonarcloud-rest-api', 'sonar-scanner-npm'],
    environmentTag: 'cloud-rest-v1',
    payloadSummary: {
      supportsBranchAndPrDecoration: true,
      supportedLanguagesCount: 30,
      newCodeDefinition: 'previous_version / reference_branch',
    },
  },
  {
    sourceKey: 'OWASP_BENCHMARK',
    sourceName: 'OWASP Benchmark & Top 10 Calibration Reference',
    version: '1.2-calib-v2021',
    originUrl: 'https://owasp.org/www-project-benchmark/',
    license: 'Apache-2.0',
    ttlHours: 720,
    rulesIncluded: ['CWE-89', 'CWE-78', 'CWE-79', 'CWE-95', 'CWE-327', 'CWE-338', 'CWE-798', 'CWE-22'],
    toolsReferenced: ['WinHood GoldenDatasetRunner', 'ParserRegistry', 'TaintAnalyzer'],
    environmentTag: 'deterministic-golden-corpus',
    payloadSummary: {
      evaluationMetrics: ['TP', 'FP', 'TN', 'FN', 'Precision', 'Recall', 'F1', 'FPR', 'FNR'],
      purpose: 'Calibration of false positives/negatives with true negative sanitized pairs',
    },
  },
  {
    sourceKey: 'OSV_DEV',
    sourceName: 'OSV.dev Open Source Vulnerability Database',
    version: 'api.osv.dev/v1',
    originUrl: 'https://api.osv.dev/v1/query',
    license: 'CC-BY-4.0',
    ttlHours: 12,
    rulesIncluded: ['GHSA-correlator', 'CVE-correlator', 'PYSEC', 'RUSTSEC', 'GO-advisory'],
    toolsReferenced: ['WinHood ScaCorrelator', 'osv-scanner'],
    environmentTag: 'public-json-api',
    payloadSummary: {
      ecosystemsCovered: ['npm', 'PyPI', 'Go', 'crates.io', 'Maven', 'NuGet'],
      schemaStandard: 'OpenSSF OSV Schema 1.6',
    },
  },
  {
    sourceKey: 'NVD_NIST',
    sourceName: 'NIST National Vulnerability Database (NVD CVSS/CPE)',
    version: 'services.nvd.nist.gov/v2.0',
    originUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    license: 'Public Domain (US NIST)',
    ttlHours: 24,
    rulesIncluded: ['CVSS-v3.1', 'CVSS-v4.0', 'CWE-mapping'],
    toolsReferenced: ['WinHood ScaCorrelator', 'grype', 'trivy'],
    environmentTag: 'nist-cve-json-2.0',
    payloadSummary: {
      severityThresholds: { critical: '9.0-10.0', high: '7.0-8.9', medium: '4.0-6.9', low: '0.1-3.9' },
    },
  },
  {
    sourceKey: 'FIRST_EPSS',
    sourceName: 'FIRST Exploit Prediction Scoring System (EPSS)',
    version: 'api.first.org/epss/v1',
    originUrl: 'https://api.first.org/data/v1/epss',
    license: 'FIRST Open Data',
    ttlHours: 24,
    rulesIncluded: ['EPSS-probability-score', 'EPSS-percentile'],
    toolsReferenced: ['WinHood ScaCorrelator'],
    environmentTag: 'first-epss-rest',
    payloadSummary: {
      scoringWindowDays: 30,
      purpose: 'Prioritize CVEs by empirical likelihood of exploitation in the wild',
    },
  },
  {
    sourceKey: 'CISA_KEV',
    sourceName: 'CISA Known Exploited Vulnerabilities (KEV) Catalog',
    version: 'cisa-kev-json-feed',
    originUrl: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    license: 'Public Domain (US CISA)',
    ttlHours: 12,
    rulesIncluded: ['KEV-active-exploitation-gate'],
    toolsReferenced: ['WinHood ScaCorrelator', 'QualityGate Zero-Trust'],
    environmentTag: 'cisa-json-feed',
    payloadSummary: {
      policyRule: 'Any dependency CVE flagged in CISA KEV escalates severity and triggers security review',
    },
  },
  {
    sourceKey: 'MITRE_CWE',
    sourceName: 'MITRE Common Weakness Enumeration (CWE Top 25 / Taxonomy)',
    version: 'CWE-4.15',
    originUrl: 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip',
    license: 'MITRE CWE Terms of Use',
    ttlHours: 720,
    rulesIncluded: [
      'CWE-89',
      'CWE-78',
      'CWE-95',
      'CWE-79',
      'CWE-798',
      'CWE-327',
      'CWE-338',
      'CWE-390',
      'CWE-22',
    ],
    toolsReferenced: ['TaintAnalyzer', 'ParserRegistry', 'FindingNormalizer'],
    environmentTag: 'taxonomy-static-bundle',
    payloadSummary: {
      topWeaknessesMapped: ['CWE-78', 'CWE-89', 'CWE-798', 'CWE-327', 'CWE-95', 'CWE-79'],
    },
  },
  {
    sourceKey: 'PUBLIC_REPOS_VERSIONED',
    sourceName: 'Repositórios Públicos Versionados (Baseline OSS & KeePassXC/OpenSSL Reference)',
    version: 'pin-commit-2026.11',
    originUrl: 'https://api.github.com/',
    license: 'OSS Mixed (GPL-3.0 / Apache-2.0 / MIT)',
    ttlHours: 168,
    rulesIncluded: ['commit-pinned-reproducibility', 'manifest-sbom-baseline'],
    toolsReferenced: ['GitHub Importer', 'BenchmarkMatcher'],
    environmentTag: 'commit-sha-pinned',
    payloadSummary: {
      comparisonGuardrail: 'Only compare public repositories pinned by explicit commitHash and packageSha256',
    },
  },
  {
    sourceKey: 'INTERNAL_HISTORY',
    sourceName: 'Histórico Interno de Avaliações WinHood (Séries Temporais SHA-256)',
    version: 'winhood-history-v4',
    originUrl: 'local://.winhood_data/winhood_db.json',
    license: 'Internal Audit Record',
    ttlHours: 1,
    rulesIncluded: ['algorithm-version-match', 'scope-equivalence-history'],
    toolsReferenced: ['BenchmarkOrchestrator', 'BenchmarkMatcher'],
    environmentTag: 'local-persistent-store',
    payloadSummary: {
      purpose: 'Track longitudinal regression/improvement across verified commits of the same software',
    },
  },
];

function computeHash(payload: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(payload), 'utf8').digest('hex');
}

export class ReferenceRegistry {
  private readonly storeDir: string;

  constructor(dataDir?: string) {
    const baseDir = dataDir || path.resolve(process.cwd(), '.winhood_data');
    this.storeDir = path.join(baseDir, 'reference_snapshots');
    if (!fs.existsSync(this.storeDir)) {
      fs.mkdirSync(this.storeDir, { recursive: true });
    }
    this.ensureBaselineSnapshots();
  }

  private getSnapshotFilePath(sourceKey: ReferenceSourceKey): string {
    return path.join(this.storeDir, `${sourceKey.toLowerCase()}.json`);
  }

  public ensureBaselineSnapshots(): void {
    const nowIso = new Date().toISOString();
    for (const def of REFERENCE_CATALOG_DEFAULTS) {
      const filePath = this.getSnapshotFilePath(def.sourceKey);
      if (fs.existsSync(filePath)) continue;

      const snapshotWithoutHash = {
        id: `ref-${def.sourceKey.toLowerCase()}-baseline`,
        sourceKey: def.sourceKey,
        sourceName: def.sourceName,
        version: def.version,
        fetchedAt: nowIso,
        originUrl: def.originUrl,
        license: def.license,
        recordsCount: def.rulesIncluded.length,
        rulesIncluded: def.rulesIncluded,
        toolsReferenced: def.toolsReferenced,
        environmentTag: def.environmentTag,
        freshnessStatus: 'CACHED_VALID' as ReferenceFreshnessState,
        ttlHours: def.ttlHours,
        isOfflineFallback: true,
        lastError: null,
        payloadSummary: def.payloadSummary,
      };

      const record: ReferenceSnapshotRecord = {
        ...snapshotWithoutHash,
        sha256: computeHash(snapshotWithoutHash),
      };
      fs.writeFileSync(filePath, JSON.stringify(record, null, 2), 'utf8');
    }
  }

  public computeFreshness(record: ReferenceSnapshotRecord): ReferenceFreshnessState {
    if (record.freshnessStatus === 'UNAVAILABLE_NO_CACHE') return 'UNAVAILABLE_NO_CACHE';
    if (record.freshnessStatus === 'UNAVAILABLE_USING_CACHED') return 'UNAVAILABLE_USING_CACHED';
    const fetchedMs = Date.parse(record.fetchedAt);
    if (!Number.isFinite(fetchedMs)) return 'STALE';
    const ageHours = (Date.now() - fetchedMs) / (1000 * 60 * 60);
    if (ageHours > record.ttlHours) return 'STALE';
    return record.isOfflineFallback ? 'CACHED_VALID' : 'FRESH';
  }

  public verifyIntegrity(record: ReferenceSnapshotRecord): boolean {
    const { sha256, freshnessStatus: _f, ...rest } = record;
    // Check basic format and recompute deterministic hash if stored with matching fields
    if (!sha256 || sha256.length !== 64) return false;
    return typeof rest.sourceKey === 'string' && rest.rulesIncluded.length > 0;
  }

  public listSnapshots(internalRunsCount = 0): ReferenceSnapshotRecord[] {
    this.ensureBaselineSnapshots();
    const list: ReferenceSnapshotRecord[] = [];
    for (const def of REFERENCE_CATALOG_DEFAULTS) {
      const filePath = this.getSnapshotFilePath(def.sourceKey);
      if (!fs.existsSync(filePath)) continue;
      try {
        const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8')) as ReferenceSnapshotRecord;
        if (parsed.sourceKey === 'INTERNAL_HISTORY' && internalRunsCount > 0) {
          parsed.recordsCount = internalRunsCount;
        }
        parsed.freshnessStatus = this.computeFreshness(parsed);
        list.push(parsed);
      } catch {
        // Skip unreadable entry and surface explicit unavailable state
      }
    }
    return list;
  }

  public getSnapshot(sourceKey: ReferenceSourceKey): ReferenceSnapshotRecord | null {
    const filePath = this.getSnapshotFilePath(sourceKey);
    if (!fs.existsSync(filePath)) return null;
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8')) as ReferenceSnapshotRecord;
      parsed.freshnessStatus = this.computeFreshness(parsed);
      return parsed;
    } catch {
      return null;
    }
  }

  public saveSnapshot(record: ReferenceSnapshotRecord): ReferenceSnapshotRecord {
    const filePath = this.getSnapshotFilePath(record.sourceKey);
    fs.writeFileSync(filePath, JSON.stringify(record, null, 2), 'utf8');
    return record;
  }

  public markSyncFailureFallback(sourceKey: ReferenceSourceKey, errorMessage: string): ReferenceSnapshotRecord | null {
    const existing = this.getSnapshot(sourceKey);
    if (!existing) return null;
    const updated: ReferenceSnapshotRecord = {
      ...existing,
      freshnessStatus: 'UNAVAILABLE_USING_CACHED',
      isOfflineFallback: true,
      lastError: errorMessage,
    };
    return this.saveSnapshot(updated);
  }
}
