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

function compareSemverTuple(a: string, b: string): number {
  const pa = a.replace(/[^0-9.]/g, '').split('.').map((n) => Number.parseInt(n || '0', 10));
  const pb = b.replace(/[^0-9.]/g, '').split('.').map((n) => Number.parseInt(n || '0', 10));
  for (let i = 0; i < 3; i++) {
    const va = pa[i] || 0;
    const vb = pb[i] || 0;
    if (va < vb) return -1;
    if (va > vb) return 1;
  }
  return 0;
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
    isVulnerable: (v) => compareSemverTuple(v, '9.0.0') < 0,
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
    isVulnerable: (v) => compareSemverTuple(v, '4.2.0') < 0,
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
    isVulnerable: (v) => compareSemverTuple(v, '4.17.21') < 0,
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
    affectedVersionRange: '< 2.17.1',
    fixedVersion: '2.17.1',
    isVulnerable: (v) => compareSemverTuple(v, '2.17.1') < 0,
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
    isVulnerable: (v) => compareSemverTuple(v, '5.4.0') < 0,
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
  }): {
    correlations: ScaVulnerabilityCorrelation[];
    findings: NormalizedFinding[];
    toolsAvailability: ReturnType<typeof ScaCorrelator.getScaToolsAvailability>;
  } {
    const {
      software,
      sbom,
      dbVersion = 'OSV-NVD-EPSS-KEV-2026.11',
      runId = 'sca-scan',
      dataDir,
    } = params;
    const toolsAvailability = ScaCorrelator.getScaToolsAvailability();
    const correlations: ScaVulnerabilityCorrelation[] = [];
    const findings: NormalizedFinding[] = [];
    const seenKeys = new Set<string>();
    const nowIso = new Date().toISOString();

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
      // 1. Live-synced OSV entries for exact package + version
      for (const adv of syncedBundle.advisories) {
        if (
          adv.packageName?.toLowerCase() === comp.name.toLowerCase() &&
          adv.affectedVersionRange === `== ${comp.version}`
        ) {
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
            license: comp.license !== 'UNKNOWN' ? comp.license : adv.licenseHint,
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

    return { correlations, findings, toolsAvailability };
  }
}
