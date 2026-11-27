import crypto from 'node:crypto';
import { SandboxExecutor } from '../../execution/SandboxExecutor';
import { ReferenceRegistry } from '../../intelligence/reference/ReferenceRegistry';
import { ToolAvailabilityService } from '../../services/tools/ToolAvailabilityService';
import type {
  NormalizedFinding,
  SbomComponentRecord,
  SbomDocumentBundle,
  ScaVulnerabilityCorrelation,
  Software,
} from '../../types/benchmark';
import { enrichLegacyOrExternalFinding } from '../../engine/scoringEngine';

interface VulnerabilityAdvisorySeed {
  ecosystem: SbomComponentRecord['ecosystem'];
  packageName: string;
  cveId: string;
  ghsaId: string;
  cweIds: string[];
  cvssScore: number;
  epssScore: number;
  epssPercentile: number;
  cisaKev: boolean;
  affectedVersionRange: string;
  fixedVersion: string;
  isVulnerable: (version: string) => boolean;
  severity: ScaVulnerabilityCorrelation['severity'];
  licenseHint: string;
  summary: string;
}

export type ScaFreshnessStatus =
  | 'LIVE_FEED_FRESH'
  | 'VALID_CACHE'
  | 'OFFLINE_LIMITED_BASELINE'
  | 'STALE_DATA'
  | 'SOURCE_UNAVAILABLE';

/**
 * Spec-compliant SemVer 2.0.0 comparator:
 * - Correctly orders prereleases below stable releases (`1.0.0-alpha.1 < 1.0.0`).
 * - Compares numeric prerelease identifiers numerically and alphanumeric identifiers lexically.
 * - Ignores `+build` metadata for precedence per SemVer §10.
 */
export function compareSemver(a: string, b: string): number {
  const parse = (raw: string) => {
    const clean = raw.trim().replace(/^[v=]+/i, '').split('+')[0] || '';
    const dashIdx = clean.indexOf('-');
    const core = dashIdx >= 0 ? clean.slice(0, dashIdx) : clean;
    const pre = dashIdx >= 0 ? clean.slice(dashIdx + 1) : '';
    const nums = core.split('.').map((n) => Number.parseInt(n || '0', 10));
    return {
      major: Number.isFinite(nums[0]) ? nums[0]! : 0,
      minor: Number.isFinite(nums[1]) ? nums[1]! : 0,
      patch: Number.isFinite(nums[2]) ? nums[2]! : 0,
      prerelease: pre ? pre.split('.') : [],
    };
  };
  const pa = parse(a);
  const pb = parse(b);
  if (pa.major !== pb.major) return pa.major < pb.major ? -1 : 1;
  if (pa.minor !== pb.minor) return pa.minor < pb.minor ? -1 : 1;
  if (pa.patch !== pb.patch) return pa.patch < pb.patch ? -1 : 1;

  const aPre = pa.prerelease;
  const bPre = pb.prerelease;
  if (aPre.length === 0 && bPre.length === 0) return 0;
  if (aPre.length === 0) return 1; // stable > prerelease
  if (bPre.length === 0) return -1;

  const len = Math.max(aPre.length, bPre.length);
  for (let i = 0; i < len; i++) {
    const ai = aPre[i];
    const bi = bPre[i];
    if (ai === undefined) return -1;
    if (bi === undefined) return 1;
    const aNum = /^\d+$/.test(ai);
    const bNum = /^\d+$/.test(bi);
    if (aNum && bNum) {
      const diff = Number(ai) - Number(bi);
      if (diff !== 0) return diff < 0 ? -1 : 1;
    } else if (aNum !== bNum) {
      return aNum ? -1 : 1; // SemVer §11.4.3: numeric < non-numeric
    } else if (ai !== bi) {
      return ai < bi ? -1 : 1;
    }
  }
  return 0;
}

/**
 * PEP 440 version comparator for PyPI packages:
 * Handles epoch (`1!2.0`), release segments (`2.3.1`), `.devN`, `aN`/`bN`/`rcN`, `.postN`.
 * Precedence: dev < a < b < rc < final < post.
 */
export function comparePep440(a: string, b: string): number {
  const parse = (raw: string) => {
    const clean = raw.trim().toLowerCase().replace(/^v/, '').split('+')[0] || '';
    const emptyResult = { epoch: 0, release: [0], phaseRank: 4, preNum: 0, postNum: 0, devNum: 0, raw: clean };
    if (!clean || clean.length > 128) {
      return { ...emptyResult, phaseRank: 0 };
    }

    let rest = clean;
    let epoch = 0;
    const bangIdx = rest.indexOf('!');
    if (bangIdx > 0) {
      const epochPart = rest.slice(0, bangIdx);
      if (!/^\d+$/.test(epochPart)) return { ...emptyResult, phaseRank: 0 };
      epoch = Number(epochPart);
      rest = rest.slice(bangIdx + 1);
    }

    // Extract leading dotted numeric release segments linearly (e.g., "2.3.1")
    let relEnd = 0;
    while (relEnd < rest.length) {
      const code = rest.charCodeAt(relEnd);
      const isDigit = code >= 48 && code <= 57;
      const isDot = code === 46;
      if (!isDigit && !isDot) break;
      relEnd += 1;
    }
    const relRaw = rest.slice(0, relEnd).replace(/\.+$/, '');
    if (!relRaw) return { ...emptyResult, phaseRank: 0 };
    const relParts = relRaw.split('.');
    if (relParts.some((seg) => !/^\d+$/.test(seg))) {
      return { ...emptyResult, phaseRank: 0 };
    }
    const release = relParts.map((seg) => Number(seg));
    let tail = rest.slice(relRaw.length);

    let preTag = '';
    let preNum = 0;
    let hasPost = false;
    let postNum = 0;
    let hasDev = false;
    let devNum = 0;

    // Optional pre-release tag: alpha|preview|beta|pre|rc|a|b|c + digits
    const preMatch = /^(?:alpha|preview|beta|pre|rc|a|b|c)/.exec(tail);
    if (preMatch) {
      preTag = preMatch[0];
      tail = tail.slice(preTag.length);
      const numMatch = /^\d+/.exec(tail);
      if (numMatch) {
        preNum = Number(numMatch[0]);
        tail = tail.slice(numMatch[0].length);
      }
    }

    // Optional .postN / postN
    if (tail.startsWith('.post') || tail.startsWith('post')) {
      hasPost = true;
      tail = tail.startsWith('.post') ? tail.slice(5) : tail.slice(4);
      const numMatch = /^\d+/.exec(tail);
      if (numMatch) {
        postNum = Number(numMatch[0]);
        tail = tail.slice(numMatch[0].length);
      }
    }

    // Optional .devN / devN
    if (tail.startsWith('.dev') || tail.startsWith('dev')) {
      hasDev = true;
      tail = tail.startsWith('.dev') ? tail.slice(4) : tail.slice(3);
      const numMatch = /^\d+/.exec(tail);
      if (numMatch) {
        devNum = Number(numMatch[0]);
        tail = tail.slice(numMatch[0].length);
      }
    }

    if (tail.length > 0) {
      return { ...emptyResult, phaseRank: 0 };
    }

    let phaseRank = 4; // final
    if (hasDev && !preTag && !hasPost) phaseRank = 0;
    else if (preTag === 'a' || preTag === 'alpha') phaseRank = 1;
    else if (preTag === 'b' || preTag === 'beta') phaseRank = 2;
    else if (preTag === 'rc' || preTag === 'c' || preTag === 'pre' || preTag === 'preview') phaseRank = 3;
    else if (hasPost) phaseRank = 5;

    return { epoch, release, phaseRank, preNum, postNum, devNum, raw: clean };
  };

  const pa = parse(a);
  const pb = parse(b);
  if (pa.epoch !== pb.epoch) return pa.epoch < pb.epoch ? -1 : 1;
  const maxLen = Math.max(pa.release.length, pb.release.length);
  for (let i = 0; i < maxLen; i++) {
    const va = pa.release[i] ?? 0;
    const vb = pb.release[i] ?? 0;
    if (va !== vb) return va < vb ? -1 : 1;
  }
  if (pa.phaseRank !== pb.phaseRank) return pa.phaseRank < pb.phaseRank ? -1 : 1;
  if (pa.preNum !== pb.preNum) return pa.preNum < pb.preNum ? -1 : 1;
  if (pa.postNum !== pb.postNum) return pa.postNum < pb.postNum ? -1 : 1;
  if (pa.devNum !== pb.devNum) return pa.devNum < pb.devNum ? -1 : 1;
  return 0;
}

/**
 * Maven ComparableVersion semantics:
 * alpha < beta < milestone < rc/cr < snapshot < (empty/final/ga/release) < sp.
 */
export function compareMavenVersion(a: string, b: string): number {
  const qualifierRank = (q: string): number => {
    const lower = q.toLowerCase();
    if (lower === 'a' || lower === 'alpha') return 1;
    if (lower === 'b' || lower === 'beta') return 2;
    if (lower === 'm' || lower === 'milestone') return 3;
    if (lower === 'rc' || lower === 'cr') return 4;
    if (lower === 'snapshot') return 5;
    if (lower === '' || lower === 'ga' || lower === 'final' || lower === 'release') return 6;
    if (lower === 'sp') return 7;
    return 6;
  };
  const parse = (raw: string) => {
    const clean = raw.trim();
    const dashIdx = clean.indexOf('-');
    const core = dashIdx >= 0 ? clean.slice(0, dashIdx) : clean;
    const qualRaw = dashIdx >= 0 ? clean.slice(dashIdx + 1) : '';
    const qualParts = qualRaw ? qualRaw.split(/[-.]/) : [];
    const nums = core.split('.').map((n) => Number.parseInt(n || '0', 10));
    return {
      nums,
      qualRank: qualifierRank(qualParts[0] || ''),
      qualNum: qualParts[1] && /^\d+$/.test(qualParts[1]) ? Number(qualParts[1]) : 0,
      qualRaw: qualRaw.toLowerCase(),
    };
  };
  const pa = parse(a);
  const pb = parse(b);
  const len = Math.max(pa.nums.length, pb.nums.length);
  for (let i = 0; i < len; i++) {
    const va = Number.isFinite(pa.nums[i]) ? pa.nums[i]! : 0;
    const vb = Number.isFinite(pb.nums[i]) ? pb.nums[i]! : 0;
    if (va !== vb) return va < vb ? -1 : 1;
  }
  if (pa.qualRank !== pb.qualRank) return pa.qualRank < pb.qualRank ? -1 : 1;
  if (pa.qualNum !== pb.qualNum) return pa.qualNum < pb.qualNum ? -1 : 1;
  return pa.qualRaw.localeCompare(pb.qualRaw);
}

/**
 * NuGet version comparator (supports 4-part Revision `major.minor.patch.revision` + SemVer 2 prerelease).
 */
export function compareNugetVersion(a: string, b: string): number {
  const parse = (raw: string) => {
    const clean = raw.trim().split('+')[0] || '';
    const dashIdx = clean.indexOf('-');
    const core = dashIdx >= 0 ? clean.slice(0, dashIdx) : clean;
    const pre = dashIdx >= 0 ? clean.slice(dashIdx + 1).toLowerCase() : '';
    const nums = core.split('.').map((n) => Number.parseInt(n || '0', 10));
    return {
      nums: [nums[0] || 0, nums[1] || 0, nums[2] || 0, nums[3] || 0],
      pre,
    };
  };
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 4; i++) {
    if (pa.nums[i]! !== pb.nums[i]!) return pa.nums[i]! < pb.nums[i]! ? -1 : 1;
  }
  if (!pa.pre && !pb.pre) return 0;
  if (!pa.pre) return 1;
  if (!pb.pre) return -1;
  return pa.pre.localeCompare(pb.pre);
}

export function compareEcosystemVersion(
  ecosystem: SbomComponentRecord['ecosystem'],
  a: string,
  b: string
): number {
  switch (ecosystem) {
    case 'pypi':
      return comparePep440(a, b);
    case 'maven':
      return compareMavenVersion(a, b);
    case 'nuget':
      return compareNugetVersion(a, b);
    case 'npm':
    case 'golang':
    case 'cargo':
    default:
      return compareSemver(a, b);
  }
}

export function satisfiesVersionRange(
  ecosystem: SbomComponentRecord['ecosystem'],
  version: string,
  rangeExpr: string
): boolean {
  const cleanVer = version.trim();
  if (!cleanVer || cleanVer === 'UNPINNED' || cleanVer === 'MANAGED') return false;
  const rawRange = rangeExpr.trim();
  if (!rawRange || rawRange === '*') return true;
  const orBranches = rawRange.split('||').map((s) => s.trim()).filter(Boolean);
  return orBranches.some((branch) => {
    const clauses = branch
      .split(/\s*,\s*|\s+(?=[<>=!])/)
      .map((c) => c.trim())
      .filter(Boolean);
    return clauses.every((clause) => {
      const m = clause.match(/^(<=|>=|==|!=|<|>|=)\s*(.+)$/);
      if (!m) {
        return compareEcosystemVersion(ecosystem, cleanVer, clause) === 0;
      }
      const op = m[1]!;
      const target = m[2]!.trim();
      const cmp = compareEcosystemVersion(ecosystem, cleanVer, target);
      switch (op) {
        case '==':
        case '=':
          return cmp === 0;
        case '!=':
          return cmp !== 0;
        case '<':
          return cmp < 0;
        case '<=':
          return cmp <= 0;
        case '>':
          return cmp > 0;
        case '>=':
          return cmp >= 0;
        default:
          return false;
      }
    });
  });
}

const ADVISORY_INTELLIGENCE_DB: VulnerabilityAdvisorySeed[] = [
  {
    ecosystem: 'npm',
    packageName: 'jsonwebtoken',
    cveId: 'CVE-2022-23529',
    ghsaId: 'GHSA-27h2-hvpr-p74q',
    cweIds: ['CWE-20', 'CWE-347'],
    cvssScore: 7.6,
    epssScore: 0.412,
    epssPercentile: 0.973,
    cisaKev: false,
    affectedVersionRange: '< 9.0.0',
    fixedVersion: '9.0.0',
    isVulnerable: (v) => satisfiesVersionRange('npm', v, '< 9.0.0'),
    severity: 'HIGH',
    licenseHint: 'MIT',
    summary: 'Improper signature/key validation allowing arbitrary code or token bypass in jsonwebtoken < 9.0.0.',
  },
  {
    ecosystem: 'npm',
    packageName: 'crypto-js',
    cveId: 'CVE-2023-46233',
    ghsaId: 'GHSA-xwcq-pm8m-c4vf',
    cweIds: ['CWE-328', 'CWE-916'],
    cvssScore: 9.1,
    epssScore: 0.184,
    epssPercentile: 0.958,
    cisaKev: false,
    affectedVersionRange: '< 4.2.0',
    fixedVersion: '4.2.0',
    isVulnerable: (v) => satisfiesVersionRange('npm', v, '< 4.2.0'),
    severity: 'CRITICAL',
    licenseHint: 'MIT',
    summary: 'PBKDF2 default SHA-1 with 1 iteration in crypto-js < 4.2.0 enables fast offline cracking.',
  },
  {
    ecosystem: 'npm',
    packageName: 'lodash',
    cveId: 'CVE-2021-23337',
    ghsaId: 'GHSA-35jh-r3h4-6jhm',
    cweIds: ['CWE-94', 'CWE-1321'],
    cvssScore: 7.2,
    epssScore: 0.625,
    epssPercentile: 0.981,
    cisaKev: false,
    affectedVersionRange: '< 4.17.21',
    fixedVersion: '4.17.21',
    isVulnerable: (v) => satisfiesVersionRange('npm', v, '< 4.17.21'),
    severity: 'HIGH',
    licenseHint: 'MIT',
    summary: 'Command Injection via template function in lodash < 4.17.21.',
  },
  {
    ecosystem: 'maven',
    packageName: 'org.apache.logging.log4j:log4j-core',
    cveId: 'CVE-2021-44228',
    ghsaId: 'GHSA-jfh8-c2jp-5v3q',
    cweIds: ['CWE-502', 'CWE-917'],
    cvssScore: 10.0,
    epssScore: 0.975,
    epssPercentile: 0.999,
    cisaKev: true,
    affectedVersionRange: '>= 2.0-beta9, < 2.17.1',
    fixedVersion: '2.17.1',
    isVulnerable: (v) => satisfiesVersionRange('maven', v, '>= 2.0-beta9, < 2.17.1'),
    severity: 'BLOCKER',
    licenseHint: 'Apache-2.0',
    summary: 'Log4Shell JNDI remote code execution vulnerability (CISA KEV actively exploited).',
  },
  {
    ecosystem: 'pypi',
    packageName: 'pyyaml',
    cveId: 'CVE-2020-14343',
    ghsaId: 'GHSA-8q59-q68h-6hv4',
    cweIds: ['CWE-502'],
    cvssScore: 9.8,
    epssScore: 0.742,
    epssPercentile: 0.989,
    cisaKev: false,
    affectedVersionRange: '< 5.4',
    fixedVersion: '5.4',
    isVulnerable: (v) => satisfiesVersionRange('pypi', v, '< 5.4'),
    severity: 'CRITICAL',
    licenseHint: 'MIT',
    summary: 'Arbitrary code execution via FullLoader in PyYAML < 5.4.',
  },
];

function scoreToSeverity(cvss: number | null, kev: boolean): ScaVulnerabilityCorrelation['severity'] {
  if (kev || (cvss !== null && cvss >= 9.5)) return 'BLOCKER';
  if (cvss !== null && cvss >= 8.5) return 'CRITICAL';
  if (cvss !== null && cvss >= 7.0) return 'HIGH';
  if (cvss !== null && cvss >= 4.0) return 'MEDIUM';
  return 'LOW';
}

export class ScaCorrelator {
  public static getScaToolsAvailability() {
    const tools = ['syft', 'grype', 'osv-scanner', 'trivy'];
    return tools.map((name) => {
      const probe = ToolAvailabilityService.checkBinaryInPath(name);
      return {
        toolId: name,
        binaryDetected: probe.detected,
        executablePath: probe.executablePath,
        version: probe.versionOutput,
      };
    });
  }

  public static correlateSbom(params: {
    software: Software;
    sbom: SbomDocumentBundle;
    dbVersion?: string;
    runId?: string;
    dataDir?: string;
    licensePolicy?: LicensePolicyConfig;
    deterministicTimestamp?: string;
  }): {
    correlations: ScaVulnerabilityCorrelation[];
    findings: NormalizedFinding[];
    toolsAvailability: ReturnType<typeof ScaCorrelator.getScaToolsAvailability>;
    advisoryFeedMetadata: {
      dbVersion: string;
      cacheMode: 'LIVE_SYNCED_CACHE' | 'OFFLINE_VERIFIED_SNAPSHOT';
      freshnessStatus: ScaFreshnessStatus;
      lastSyncedAt: string;
      isStale: boolean;
      retentionPolicyDays: number;
      snapshotSha256: string;
      isComprehensiveDatabase: boolean;
      limitations: string[];
      feeds: Array<{
        source: string;
        snapshotVersion: string;
        lastUpdated: string;
        recordsCount: number;
        isStale: boolean;
      }>;
    };
  } {
    const {
      software,
      sbom,
      dbVersion = 'OSV-NVD-EPSS-KEV-2026.11',
      runId = 'sca-scan',
      dataDir,
      deterministicTimestamp,
    } = params;
    const toolsAvailability = ScaCorrelator.getScaToolsAvailability();
    const correlations: ScaVulnerabilityCorrelation[] = [];
    const findings: NormalizedFinding[] = [];
    const seenKeys = new Set<string>();
    const nowIso = deterministicTimestamp || new Date().toISOString();

    // Load live-synced OSV/NVD/EPSS/KEV cache from ReferenceRegistry if available
    let syncedBundle = {
      updatedAt: '',
      advisories: [] as any[],
      kevCveIds: [] as string[],
      epssByCve: {} as Record<string, { epss: number; percentile: number }>,
      nvdByCve: {} as Record<string, { cvssScore: number | null; summary: string; cweIds: string[] }>,
    };
    try {
      const reg = new ReferenceRegistry(dataDir);
      syncedBundle = reg.loadSyncedAdvisoryCache();
    } catch {
      // Ignore if snapshot dir unavailable
    }

    // Run osv-scanner inside SandboxExecutor ONLY when binary + OS sandbox available
    const osvInstalled = toolsAvailability.find((t) => t.toolId === 'osv-scanner' && t.binaryDetected);
    if (osvInstalled && software.sourceFilesContent && Object.keys(software.sourceFilesContent).length > 0) {
      const manifestFiles: Record<string, string> = {};
      for (const [rel, content] of Object.entries(software.sourceFilesContent)) {
        if (
          rel.endsWith('package-lock.json') ||
          rel.endsWith('requirements.txt') ||
          rel.endsWith('go.mod') ||
          rel.endsWith('Cargo.toml')
        ) {
          manifestFiles[rel] = content;
        }
      }
      if (Object.keys(manifestFiles).length > 0) {
        const sbxRes = SandboxExecutor.runSandboxedCliBinary({
          executablePath: osvInstalled.executablePath,
          argsBuilder: (dir) => ['--format=json', '-r', dir],
          filesMap: manifestFiles,
          timeoutMs: 8000,
        });
        if (sbxRes.executed && sbxRes.stdout.trim()) {
          try {
            const osvCliJson = JSON.parse(sbxRes.stdout);
            for (const res of osvCliJson?.results || []) {
              for (const pkgEntry of res?.packages || []) {
                const pkgName = String(pkgEntry?.package?.name || '');
                const pkgVer = String(pkgEntry?.package?.version || '');
                for (const vuln of pkgEntry?.vulnerabilities || []) {
                  const idStr = String(vuln?.id || 'OSV-ADVISORY');
                  const key = `${pkgName}@${pkgVer}:${idStr}`;
                  if (seenKeys.has(key)) continue;
                  seenKeys.add(key);

                  const cve = (vuln?.aliases || []).find((a: string) => /^CVE-/i.test(a)) || null;
                  const kev = cve ? syncedBundle.kevCveIds.includes(cve) : false;
                  const epssEntry = cve ? syncedBundle.epssByCve[cve] : undefined;
                  const nvdEntry = cve ? syncedBundle.nvdByCve[cve] : undefined;
                  const cvss = nvdEntry?.cvssScore ?? null;
                  const severity = scoreToSeverity(cvss, kev);

                  const evidenceSha256 = crypto
                    .createHash('sha256')
                    .update(JSON.stringify({ softwareId: software.id, pkgName, pkgVer, idStr, source: 'osv-scanner' }))
                    .digest('hex');

                  correlations.push({
                    id: `sca-${software.id}-${idStr}`,
                    softwareId: software.id,
                    packageName: pkgName,
                    installedVersion: pkgVer,
                    ecosystem: 'npm',
                    dependencyScope: 'TRANSITIVE',
                    license: 'UNKNOWN',
                    cveId: cve,
                    ghsaId: idStr.startsWith('GHSA-') ? idStr : null,
                    cweIds: nvdEntry?.cweIds || ['CWE-1395'],
                    cvssScore: cvss,
                    epssScore: epssEntry?.epss ?? null,
                    epssPercentile: epssEntry?.percentile ?? null,
                    cisaKev: kev,
                    affectedVersionRange: `== ${pkgVer}`,
                    fixedVersion: null,
                    severity,
                    dbSource: 'OSV_SCANNER',
                    dbVersion: osvInstalled.version || dbVersion,
                    dbSnapshotAt: nowIso,
                    summary: String(vuln?.summary || nvdEntry?.summary || idStr),
                    evidenceSha256,
                  });
                }
              }
            }
          } catch {
            // Invalid CLI JSON ignored safely
          }
        }
      }
    }

    // Correlate against live-synced OSV cache + curated baseline
    for (const comp of sbom.components) {
      // 1. Live-synced OSV entries matched via ecosystem-aware version range comparator
      for (const adv of syncedBundle.advisories) {
        const rangeExpr = String(adv.affectedVersionRange || '').trim();
        const matchesRange =
          rangeExpr === `== ${comp.version}` ||
          (rangeExpr.length > 0 && satisfiesVersionRange(comp.ecosystem, comp.version, rangeExpr));
        if (adv.packageName?.toLowerCase() === comp.name.toLowerCase() && matchesRange) {
          const idKey = `${comp.name}@${comp.version}:${adv.cveId || adv.ghsaId}`;
          if (seenKeys.has(idKey)) continue;
          seenKeys.add(idKey);

          const cve = adv.cveId;
          const kev = cve ? syncedBundle.kevCveIds.includes(cve) || adv.cisaKev : false;
          const epssEntry = cve ? syncedBundle.epssByCve[cve] : undefined;
          const nvdEntry = cve ? syncedBundle.nvdByCve[cve] : undefined;
          const cvss = nvdEntry?.cvssScore ?? adv.cvssScore ?? null;
          const severity = scoreToSeverity(cvss, kev);

          const evidenceSha256 = crypto
            .createHash('sha256')
            .update(JSON.stringify({ softwareId: software.id, pkg: comp.name, ver: comp.version, cve, ghsa: adv.ghsaId, syncedAt: adv.syncedAt }))
            .digest('hex');

          const corr: ScaVulnerabilityCorrelation = {
            id: `sca-${software.id}-${cve || adv.ghsaId || comp.name}`,
            softwareId: software.id,
            packageName: comp.name,
            installedVersion: comp.version,
            ecosystem: comp.ecosystem,
            dependencyScope: comp.dependencyScope,
            license: comp.license,
            cveId: cve,
            ghsaId: adv.ghsaId,
            cweIds: nvdEntry?.cweIds?.length ? nvdEntry.cweIds : adv.cweIds || ['CWE-1395'],
            cvssScore: cvss,
            epssScore: epssEntry?.epss ?? adv.epssScore ?? null,
            epssPercentile: epssEntry?.percentile ?? adv.epssPercentile ?? null,
            cisaKev: kev,
            affectedVersionRange: adv.affectedVersionRange || `== ${comp.version}`,
            fixedVersion: adv.fixedVersion ?? null,
            severity,
            dbSource: 'OSV.dev',
            dbVersion: `LIVE_SYNCED@${adv.syncedAt.slice(0, 10)}`,
            dbSnapshotAt: adv.syncedAt || nowIso,
            summary: nvdEntry?.summary || adv.summary,
            evidenceSha256,
          };
          correlations.push(corr);

          findings.push(
            enrichLegacyOrExternalFinding({
              id: `f-sca-${runId}-${software.id}-${cve || adv.ghsaId || comp.name}`,
              runId,
              softwareId: software.id,
              softwareName: software.name,
              softwareVersion: software.version,
              toolName: 'WinHood SCA & SBOM Correlator (Live Synced OSV/NVD/EPSS/KEV)',
              toolVersion: corr.dbVersion,
              originType: 'WINHOOD_SCA_ENGINE',
              detectionMethod: 'SBOM_CORRELATION',
              originalRuleId: cve || adv.ghsaId || 'OSV-ADVISORY',
              category: 'SCA',
              cwe: corr.cweIds[0] || 'CWE-1395',
              severity: corr.severity,
              confidence: 'HIGH',
              validationStatus: 'VALIDATED',
              lifecycleState: 'CONFIRMED',
              title: `${cve || adv.ghsaId} em ${comp.name}@${comp.version} [${comp.dependencyScope}]`,
              description: `${corr.summary} Origem: ${corr.dbSource} (${corr.dbVersion})${kev ? ' | CISA KEV ATIVO' : ''}.`,
              filePath: comp.manifestFile,
              lineNumber: 1,
              snippet: `"${comp.name}": "${comp.version}"`,
              remediation: corr.fixedVersion
                ? `Atualizar "${comp.name}" para >= ${corr.fixedVersion}.`
                : `Revisar advisory OSV/NVD para "${comp.name}@${comp.version}" e atualizar para release corrigida.`,
              remediationEffortMinutes: 20,
              collectedAt: nowIso,
            })
          );
        }
      }

      // 2. Deterministic offline cached advisory baseline enriched with any live KEV/EPSS/NVD updates
      for (const adv of ADVISORY_INTELLIGENCE_DB) {
        if (
          comp.ecosystem === adv.ecosystem &&
          comp.name.toLowerCase() === adv.packageName.toLowerCase() &&
          adv.isVulnerable(comp.version)
        ) {
          const idKey = `${comp.name}@${comp.version}:${adv.cveId}`;
          if (seenKeys.has(idKey)) continue;
          seenKeys.add(idKey);

          const kev = syncedBundle.kevCveIds.includes(adv.cveId) || adv.cisaKev;
          const epssLive = syncedBundle.epssByCve[adv.cveId];
          const nvdLive = syncedBundle.nvdByCve[adv.cveId];
          const cvssScore = nvdLive?.cvssScore ?? adv.cvssScore;
          const epssScore = epssLive?.epss ?? adv.epssScore;
          const epssPercentile = epssLive?.percentile ?? adv.epssPercentile;
          const sourceLabel = syncedBundle.updatedAt ? `${dbVersion} (CACHED+KEV/EPSS)` : `${dbVersion} (CACHED_BASELINE)`;

          const payloadForHash = {
            softwareId: software.id,
            pkg: comp.name,
            ver: comp.version,
            cve: adv.cveId,
            ghsa: adv.ghsaId,
            dbVersion: sourceLabel,
          };
          const evidenceSha256 = crypto
            .createHash('sha256')
            .update(JSON.stringify(payloadForHash))
            .digest('hex');

          const corr: ScaVulnerabilityCorrelation = {
            id: `sca-${software.id}-${adv.cveId}`,
            softwareId: software.id,
            packageName: comp.name,
            installedVersion: comp.version,
            ecosystem: comp.ecosystem,
            dependencyScope: comp.dependencyScope,
            license: comp.license !== 'UNKNOWN' && comp.license !== 'NOASSERTION' ? comp.license : adv.licenseHint,
            cveId: adv.cveId,
            ghsaId: adv.ghsaId,
            cweIds: adv.cweIds,
            cvssScore,
            epssScore,
            epssPercentile,
            cisaKev: kev,
            affectedVersionRange: adv.affectedVersionRange,
            fixedVersion: adv.fixedVersion,
            severity: kev ? 'BLOCKER' : adv.severity,
            dbSource: 'OSV.dev',
            dbVersion: sourceLabel,
            dbSnapshotAt: syncedBundle.updatedAt || nowIso,
            summary: nvdLive?.summary || adv.summary,
            evidenceSha256,
          };
          correlations.push(corr);

          findings.push(
            enrichLegacyOrExternalFinding({
              id: `f-sca-${runId}-${software.id}-${adv.cveId}`,
              runId,
              softwareId: software.id,
              softwareName: software.name,
              softwareVersion: software.version,
              toolName: 'WinHood SCA & SBOM Correlator (OSV/NVD/EPSS/KEV)',
              toolVersion: sourceLabel,
              originType: 'WINHOOD_SCA_ENGINE',
              detectionMethod: 'SBOM_CORRELATION',
              originalRuleId: adv.cveId,
              category: 'SCA',
              cwe: adv.cweIds[0] || 'CWE-1395',
              severity: corr.severity,
              confidence: 'HIGH',
              validationStatus: 'VALIDATED',
              lifecycleState: 'CONFIRMED',
              title: `${adv.cveId} (${adv.ghsaId}) em ${comp.name}@${comp.version} [${comp.dependencyScope}]`,
              description: `${corr.summary} CVSS ${cvssScore} | EPSS ${(epssScore * 100).toFixed(1)}%${kev ? ' | CISA KEV ATIVO' : ''}. Origem: ${corr.dbSource} (${sourceLabel}).`,
              filePath: comp.manifestFile,
              lineNumber: 1,
              snippet: `"${comp.name}": "${comp.version}" (Corrigido em >= ${adv.fixedVersion})`,
              remediation: `Atualizar "${comp.name}" para >= ${adv.fixedVersion}.`,
              remediationEffortMinutes: 20,
              collectedAt: nowIso,
            })
          );
        }
      }
    }

    if (params.licensePolicy) {
      const licEval = ScaCorrelator.evaluateLicensePolicy({
        sbom,
        software,
        policy: params.licensePolicy,
        runId,
        collectedAt: nowIso,
      });
      findings.push(...licEval.findings);
    }

    const hasLiveSync = Boolean(syncedBundle.updatedAt && syncedBundle.advisories.length > 0);
    const snapshotTimestamp = syncedBundle.updatedAt || '2026-11-14T00:00:00Z';
    const ageMs = Math.max(0, Date.parse(nowIso) - Date.parse(snapshotTimestamp));
    const retentionPolicyDays = 30;
    const isStale = ageMs > retentionPolicyDays * 24 * 60 * 60 * 1000;
    const isFreshLive = hasLiveSync && ageMs <= 24 * 60 * 60 * 1000;
    const freshnessStatus: ScaFreshnessStatus = hasLiveSync
      ? isStale
        ? 'STALE_DATA'
        : isFreshLive
          ? 'LIVE_FEED_FRESH'
          : 'VALID_CACHE'
      : isStale
        ? 'STALE_DATA'
        : 'OFFLINE_LIMITED_BASELINE';

    const snapshotSha256 = crypto
      .createHash('sha256')
      .update(
        JSON.stringify({
          dbVersion,
          hasLiveSync,
          snapshotTimestamp,
          syncedAdvisoriesCount: syncedBundle.advisories.length,
          baselineAdvisoriesCount: ADVISORY_INTELLIGENCE_DB.length,
        }),
        'utf8'
      )
      .digest('hex');

    const limitations: string[] = [];
    if (!hasLiveSync) {
      limitations.push(
        `Operando com baseline offline limitada (${ADVISORY_INTELLIGENCE_DB.length} advisories curados) sem sincronização ativa OSV/NVD/EPSS/KEV. Este modo NÃO representa varredura SCA abrangente.`
      );
    }
    if (isStale) {
      limitations.push(
        `Snapshot SCA ultrapassou a política de retenção de ${retentionPolicyDays} dias (última atualização: ${snapshotTimestamp}).`
      );
    }
    if (!osvInstalled) {
      limitations.push(
        'Binário osv-scanner não detectado neste ambiente; execute via winhood-scanner-worker isolado ou sincronize o cache OSV/NVD.'
      );
    }

    const advisoryFeedMetadata = {
      dbVersion,
      cacheMode: hasLiveSync ? ('LIVE_SYNCED_CACHE' as const) : ('OFFLINE_VERIFIED_SNAPSHOT' as const),
      freshnessStatus,
      lastSyncedAt: snapshotTimestamp,
      isStale,
      retentionPolicyDays,
      snapshotSha256,
      isComprehensiveDatabase: Boolean(hasLiveSync || osvInstalled),
      limitations,
      feeds: [
        {
          source: 'OSV.dev',
          snapshotVersion: dbVersion,
          lastUpdated: snapshotTimestamp,
          recordsCount: hasLiveSync ? syncedBundle.advisories.length : ADVISORY_INTELLIGENCE_DB.length,
          isStale,
        },
        {
          source: 'NVD',
          snapshotVersion: dbVersion,
          lastUpdated: snapshotTimestamp,
          recordsCount: Object.keys(syncedBundle.nvdByCve).length || ADVISORY_INTELLIGENCE_DB.length,
          isStale,
        },
        {
          source: 'FIRST_EPSS',
          snapshotVersion: dbVersion,
          lastUpdated: snapshotTimestamp,
          recordsCount: Object.keys(syncedBundle.epssByCve).length || ADVISORY_INTELLIGENCE_DB.length,
          isStale,
        },
        {
          source: 'CISA_KEV',
          snapshotVersion: dbVersion,
          lastUpdated: snapshotTimestamp,
          recordsCount:
            syncedBundle.kevCveIds.length ||
            ADVISORY_INTELLIGENCE_DB.filter((a) => a.cisaKev).length,
          isStale,
        },
      ],
    };

    return { correlations, findings, toolsAvailability, advisoryFeedMetadata };
  }

  public static evaluateLicensePolicy(params: {
    sbom: SbomDocumentBundle;
    software: Software;
    policy: LicensePolicyConfig;
    runId?: string;
    collectedAt?: string;
  }): {
    violations: LicensePolicyViolation[];
    findings: NormalizedFinding[];
    compliant: boolean;
  } {
    const {
      sbom,
      software,
      policy,
      runId = 'sca-license',
      collectedAt = new Date().toISOString(),
    } = params;
    const violations: LicensePolicyViolation[] = [];
    const findings: NormalizedFinding[] = [];
    const deniedUpper = new Set(policy.deniedLicenses.map((l) => l.toUpperCase()));
    const restrictedUpper = new Set(policy.restrictedCopyleftLicenses.map((l) => l.toUpperCase()));
    const allowedUpper = new Set(policy.allowedLicenses.map((l) => l.toUpperCase()));

    for (const comp of sbom.components) {
      const lic = (comp.license || 'UNKNOWN').trim();
      const licUpper = lic.toUpperCase();
      const isUnasserted = licUpper === 'UNKNOWN' || licUpper === 'NOASSERTION';
      let reason: LicensePolicyViolation['reason'] | null = null;
      let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' = 'MEDIUM';

      if (deniedUpper.has(licUpper)) {
        reason = 'DENIED_LICENSE';
        severity = 'CRITICAL';
      } else if (restrictedUpper.has(licUpper)) {
        reason = 'RESTRICTED_COPYLEFT';
        severity = 'HIGH';
      } else if (isUnasserted && policy.failOnUnknownLicense) {
        reason = 'UNKNOWN_LICENSE';
        severity = 'MEDIUM';
      } else if (allowedUpper.size > 0 && !isUnasserted && !allowedUpper.has(licUpper)) {
        reason = 'NOT_IN_ALLOWLIST';
        severity = 'HIGH';
      }

      if (!reason) continue;

      violations.push({
        packageName: comp.name,
        version: comp.version,
        ecosystem: comp.ecosystem,
        license: lic,
        reason,
        severity,
        manifestFile: comp.manifestFile,
      });

      findings.push(
        enrichLegacyOrExternalFinding({
          id: `f-lic-${runId}-${software.id}-${comp.name}-${comp.version}`.replace(/[^a-zA-Z0-9_-]/g, '_'),
          runId,
          softwareId: software.id,
          softwareName: software.name,
          softwareVersion: software.version,
          toolName: 'WinHood SCA License Policy Gate',
          toolVersion: '4.3.0',
          originType: 'WINHOOD_SCA_ENGINE',
          detectionMethod: 'SBOM_CORRELATION',
          originalRuleId: 'sca:LIC-001',
          category: 'SCA',
          cwe: 'CWE-1104',
          severity,
          confidence: 'HIGH',
          validationStatus: 'VALIDATED',
          lifecycleState: 'CONFIRMED',
          title: `Violação de política de licença (${lic}) em ${comp.name}@${comp.version}`,
          description: `Dependência ${comp.name}@${comp.version} possui licença "${lic}" (${reason}) em desacordo com a política "${policy.policyId}".`,
          filePath: comp.manifestFile,
          lineNumber: 1,
          snippet: `"${comp.name}": "${comp.version}" /* license: ${lic} */`,
          remediation: 'Substituir dependência por pacote com licença compatível ou registrar exceção formal.',
          remediationEffortMinutes: 30,
          collectedAt,
        })
      );
    }

    return {
      violations,
      findings,
      compliant: violations.length === 0,
    };
  }

  public static mergeIncrementalAdvisories<
    T extends { packageName: string; affectedVersionRange: string; cveId?: string | null; ghsaId?: string | null; syncedAt?: string }
  >(existing: T[], incoming: T[]): { merged: T[]; addedCount: number; updatedCount: number } {
    const map = new Map<string, T>();
    const makeKey = (item: T) =>
      `${item.packageName.toLowerCase()}::${item.affectedVersionRange}::${item.cveId || item.ghsaId || 'NO_ID'}`;
    for (const item of existing) {
      map.set(makeKey(item), item);
    }
    let addedCount = 0;
    let updatedCount = 0;
    for (const item of incoming) {
      const k = makeKey(item);
      if (map.has(k)) {
        map.set(k, item);
        updatedCount += 1;
      } else {
        map.set(k, item);
        addedCount += 1;
      }
    }
    return {
      merged: Array.from(map.values()),
      addedCount,
      updatedCount,
    };
  }
}

export interface LicensePolicyConfig {
  policyId: string;
  name: string;
  allowedLicenses: string[];
  deniedLicenses: string[];
  restrictedCopyleftLicenses: string[];
  failOnUnknownLicense: boolean;
}

export interface LicensePolicyViolation {
  packageName: string;
  version: string;
  ecosystem: SbomComponentRecord['ecosystem'];
  license: string;
  reason: 'DENIED_LICENSE' | 'RESTRICTED_COPYLEFT' | 'UNKNOWN_LICENSE' | 'NOT_IN_ALLOWLIST';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  manifestFile: string;
}

export const DEFAULT_ENTERPRISE_LICENSE_POLICY: LicensePolicyConfig = {
  policyId: 'winhood-enterprise-license-v1',
  name: 'Enterprise Permissive & Weak-Copyleft Policy',
  allowedLicenses: ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MPL-2.0', '0BSD', 'CC0-1.0', 'Unlicense'],
  deniedLicenses: ['AGPL-3.0', 'AGPL-3.0-only', 'GPL-3.0', 'GPL-3.0-only', 'SSPL-1.0'],
  restrictedCopyleftLicenses: ['GPL-2.0', 'LGPL-3.0', 'EUPL-1.2'],
  failOnUnknownLicense: false,
};
