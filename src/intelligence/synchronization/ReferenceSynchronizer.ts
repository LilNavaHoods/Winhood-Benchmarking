import crypto from 'node:crypto';
import type { ReferenceSnapshotRecord, ReferenceSourceKey, SbomComponentRecord } from '../../types/benchmark';
import {
  ReferenceRegistry,
  type SyncedAdvisoryCacheEntry,
} from '../reference/ReferenceRegistry';

export interface ReferenceSyncOutcome {
  syncedAt: string;
  snapshots: ReferenceSnapshotRecord[];
  liveFetchedSources: ReferenceSourceKey[];
  cachedFallbackSources: ReferenceSourceKey[];
}

async function fetchJsonWithHeaders(
  url: string,
  init?: RequestInit,
  timeoutMs = 4500
): Promise<{ json: any; etag: string | null }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }
    const etag = res.headers.get('etag');
    const json = await res.json();
    return { json, etag };
  } finally {
    clearTimeout(timer);
  }
}

function mapEcosystemToOsv(eco: string): string | null {
  switch (eco.toLowerCase()) {
    case 'npm':
      return 'npm';
    case 'pypi':
      return 'PyPI';
    case 'maven':
      return 'Maven';
    case 'golang':
      return 'Go';
    case 'cargo':
      return 'crates.io';
    case 'nuget':
      return 'NuGet';
    default:
      return null;
  }
}

export class ReferenceSynchronizer {
  private readonly registry: ReferenceRegistry;

  constructor(dataDir?: string) {
    this.registry = new ReferenceRegistry(dataDir);
  }

  public getRegistry(): ReferenceRegistry {
    return this.registry;
  }

  public async syncSources(params?: {
    sources?: ReferenceSourceKey[];
    sonarServerUrl?: string;
    sonarToken?: string;
    internalRunsCount?: number;
    sbomPackages?: Array<{
      name: string;
      ecosystem: SbomComponentRecord['ecosystem'];
      version: string;
    }>;
    cveIds?: string[];
  }): Promise<ReferenceSyncOutcome> {
    const targetSources: ReferenceSourceKey[] =
      params?.sources && params.sources.length > 0
        ? params.sources
        : [
            'SONARQUBE_SERVER',
            'SONARQUBE_CLOUD',
            'OWASP_BENCHMARK',
            'OSV_DEV',
            'NVD_NIST',
            'FIRST_EPSS',
            'CISA_KEV',
            'MITRE_CWE',
            'PUBLIC_REPOS_VERSIONED',
            'INTERNAL_HISTORY',
          ];

    const liveFetchedSources: ReferenceSourceKey[] = [];
    const cachedFallbackSources: ReferenceSourceKey[] = [];
    const nowIso = new Date().toISOString();

    const advisoryCache = this.registry.loadSyncedAdvisoryCache();
    const discoveredCves = new Set<string>(params?.cveIds || []);

    for (const sourceKey of targetSources) {
      const existing = this.registry.getSnapshot(sourceKey);
      if (!existing) continue;

      try {
        if (sourceKey === 'CISA_KEV') {
          const { json: kevData, etag } = await fetchJsonWithHeaders(
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            undefined,
            5000
          );
          const vulns = Array.isArray(kevData?.vulnerabilities) ? kevData.vulnerabilities : [];
          const kevIds: string[] = vulns
            .map((v: any) => String(v?.cveID || '').trim())
            .filter((id: string) => /^CVE-\d{4}-\d+$/i.test(id));

          advisoryCache.kevCveIds = Array.from(new Set(kevIds));
          advisoryCache.updatedAt = nowIso;
          this.registry.saveSyncedAdvisoryCache(advisoryCache);

          const updatedBase = {
            ...existing,
            version: String(kevData?.catalogVersion || existing.version),
            fetchedAt: nowIso,
            etag: etag || existing.etag || null,
            recordsCount: vulns.length || existing.recordsCount,
            freshnessStatus: 'FRESH' as const,
            isOfflineFallback: false,
            lastError: null,
            payloadSummary: {
              ...existing.payloadSummary,
              dateReleased: kevData?.dateReleased || nowIso,
              catalogTitle: kevData?.title || 'CISA KEV Catalog',
              vulnerabilitiesCount: vulns.length,
              indexedKevCveIdsCount: advisoryCache.kevCveIds.length,
            },
          };
          const sha256 = crypto.createHash('sha256').update(JSON.stringify(updatedBase), 'utf8').digest('hex');
          this.registry.saveSnapshot({ ...updatedBase, sha256 });
          liveFetchedSources.push(sourceKey);
        } else if (sourceKey === 'OSV_DEV') {
          const queryTargets = (params?.sbomPackages || [])
            .map((pkg) => ({
              pkg,
              osvEco: mapEcosystemToOsv(pkg.ecosystem),
            }))
            .filter((x) => x.osvEco && x.pkg.version && x.pkg.version !== '0.0.0')
            .slice(0, 25);

          const fallbackProbe = [
            { pkg: { name: 'lodash', ecosystem: 'npm' as const, version: '4.17.20' }, osvEco: 'npm' },
            { pkg: { name: 'jsonwebtoken', ecosystem: 'npm' as const, version: '8.5.1' }, osvEco: 'npm' },
          ];
          const batchList = queryTargets.length > 0 ? queryTargets : fallbackProbe;

          const { json: batchResp, etag } = await fetchJsonWithHeaders(
            'https://api.osv.dev/v1/querybatch',
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                queries: batchList.map((item) => ({
                  package: { name: item.pkg.name, ecosystem: item.osvEco },
                  version: item.pkg.version,
                })),
              }),
            },
            5000
          );

          const results = Array.isArray(batchResp?.results) ? batchResp.results : [];
          const newEntries: SyncedAdvisoryCacheEntry[] = [];
          results.forEach((resItem: any, idx: number) => {
            const target = batchList[idx]?.pkg;
            if (!target) return;
            const vulns = Array.isArray(resItem?.vulns) ? resItem.vulns : [];
            for (const v of vulns) {
              const idStr = String(v?.id || '');
              const aliases: string[] = Array.isArray(v?.aliases) ? v.aliases : [];
              const cve = [idStr, ...aliases].find((a) => /^CVE-\d{4}-\d+$/i.test(a)) || null;
              const ghsa = [idStr, ...aliases].find((a) => /^GHSA-/i.test(a)) || (idStr.startsWith('GHSA-') ? idStr : null);
              if (cve) discoveredCves.add(cve);

              newEntries.push({
                source: 'OSV.dev',
                ecosystem: target.ecosystem,
                packageName: target.name,
                affectedVersionRange: `== ${target.version}`,
                fixedVersion: null,
                cveId: cve,
                ghsaId: ghsa,
                cweIds: Array.isArray(v?.database_specific?.cwe_ids) ? v.database_specific.cwe_ids : [],
                cvssScore: null,
                epssScore: null,
                epssPercentile: null,
                cisaKev: cve ? advisoryCache.kevCveIds.includes(cve) : false,
                summary: String(v?.summary || v?.details || `OSV advisory ${idStr}`).slice(0, 300),
                syncedAt: nowIso,
              });
            }
          });

          if (newEntries.length > 0) {
            const merged = [...advisoryCache.advisories.filter((a) => a.source !== 'OSV.dev'), ...newEntries];
            advisoryCache.advisories = merged.slice(-300);
            advisoryCache.updatedAt = nowIso;
            this.registry.saveSyncedAdvisoryCache(advisoryCache);
          }

          const updatedBase = {
            ...existing,
            fetchedAt: nowIso,
            etag: etag || existing.etag || null,
            recordsCount: newEntries.length > 0 ? newEntries.length : existing.recordsCount,
            freshnessStatus: 'FRESH' as const,
            isOfflineFallback: false,
            lastError: null,
            payloadSummary: {
              ...existing.payloadSummary,
              queriedPackagesCount: batchList.length,
              advisoriesReturned: newEntries.length,
              usedProjectSbom: queryTargets.length > 0,
            },
          };
          const sha256 = crypto.createHash('sha256').update(JSON.stringify(updatedBase), 'utf8').digest('hex');
          this.registry.saveSnapshot({ ...updatedBase, sha256 });
          liveFetchedSources.push(sourceKey);
        } else if (sourceKey === 'NVD_NIST') {
          const targetCves = Array.from(discoveredCves).slice(0, 5);
          const nvdUrl =
            targetCves.length > 0
              ? `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(targetCves[0]!)}`
              : 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5';
          const headers: Record<string, string> = {};
          if (process.env.NVD_API_KEY) {
            headers['apiKey'] = process.env.NVD_API_KEY;
          }
          const { json: nvdData, etag } = await fetchJsonWithHeaders(nvdUrl, { headers }, 5500);
          const vulnerabilities = Array.isArray(nvdData?.vulnerabilities) ? nvdData.vulnerabilities : [];
          for (const item of vulnerabilities) {
            const cveObj = item?.cve;
            const cveId = String(cveObj?.id || '');
            if (!cveId) continue;
            discoveredCves.add(cveId);
            const metricsV31 = cveObj?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore;
            const metricsV30 = cveObj?.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore;
            const cvssScore =
              typeof metricsV31 === 'number' ? metricsV31 : typeof metricsV30 === 'number' ? metricsV30 : null;
            const desc = cveObj?.descriptions?.find((d: any) => d.lang === 'en')?.value || '';
            const cweIds: string[] = [];
            for (const w of cveObj?.weaknesses || []) {
              for (const wd of w?.description || []) {
                if (typeof wd?.value === 'string' && wd.value.startsWith('CWE-')) cweIds.push(wd.value);
              }
            }
            advisoryCache.nvdByCve[cveId] = {
              cvssScore,
              summary: String(desc).slice(0, 300),
              cweIds,
            };
          }
          advisoryCache.updatedAt = nowIso;
          this.registry.saveSyncedAdvisoryCache(advisoryCache);

          const updatedBase = {
            ...existing,
            fetchedAt: nowIso,
            etag: etag || existing.etag || null,
            recordsCount: Number(nvdData?.totalResults || vulnerabilities.length || existing.recordsCount),
            freshnessStatus: 'FRESH' as const,
            isOfflineFallback: false,
            lastError: null,
            payloadSummary: {
              ...existing.payloadSummary,
              nvdTotalResults: nvdData?.totalResults ?? vulnerabilities.length,
              cachedCvesCount: Object.keys(advisoryCache.nvdByCve).length,
            },
          };
          const sha256 = crypto.createHash('sha256').update(JSON.stringify(updatedBase), 'utf8').digest('hex');
          this.registry.saveSnapshot({ ...updatedBase, sha256 });
          liveFetchedSources.push(sourceKey);
        } else if (sourceKey === 'FIRST_EPSS') {
          const queryCves =
            discoveredCves.size > 0
              ? Array.from(discoveredCves).slice(0, 20)
              : ['CVE-2021-23337', 'CVE-2022-23529', 'CVE-2021-44228'];
          const { json: epssData, etag } = await fetchJsonWithHeaders(
            `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(queryCves.join(','))}`,
            undefined,
            4500
          );
          const rows = Array.isArray(epssData?.data) ? epssData.data : [];
          for (const row of rows) {
            if (row?.cve) {
              advisoryCache.epssByCve[String(row.cve)] = {
                epss: Number.parseFloat(row.epss || '0'),
                percentile: Number.parseFloat(row.percentile || '0'),
              };
            }
          }
          advisoryCache.updatedAt = nowIso;
          this.registry.saveSyncedAdvisoryCache(advisoryCache);

          const updatedBase = {
            ...existing,
            version: String(epssData?.['model-version'] || existing.version),
            fetchedAt: nowIso,
            etag: etag || existing.etag || null,
            recordsCount: Math.max(existing.recordsCount, rows.length),
            freshnessStatus: 'FRESH' as const,
            isOfflineFallback: false,
            lastError: null,
            payloadSummary: {
              ...existing.payloadSummary,
              queriedCvesCount: queryCves.length,
              sampleScores: rows.slice(0, 5),
            },
          };
          const sha256 = crypto.createHash('sha256').update(JSON.stringify(updatedBase), 'utf8').digest('hex');
          this.registry.saveSnapshot({ ...updatedBase, sha256 });
          liveFetchedSources.push(sourceKey);
        } else if (sourceKey === 'SONARQUBE_CLOUD') {
          const { json: scData, etag } = await fetchJsonWithHeaders(
            'https://sonarcloud.io/api/rules/search?ps=10&languages=ts',
            undefined,
            4500
          );
          const rules = Array.isArray(scData?.rules) ? scData.rules.map((r: any) => String(r.key)) : existing.rulesIncluded;
          const updatedBase = {
            ...existing,
            fetchedAt: nowIso,
            etag: etag || existing.etag || null,
            recordsCount: Number(scData?.total || rules.length || existing.recordsCount),
            rulesIncluded: rules.length > 0 ? rules : existing.rulesIncluded,
            freshnessStatus: 'FRESH' as const,
            isOfflineFallback: false,
            lastError: null,
            payloadSummary: {
              ...existing.payloadSummary,
              totalTypeScriptRules: scData?.total ?? null,
            },
          };
          const sha256 = crypto.createHash('sha256').update(JSON.stringify(updatedBase), 'utf8').digest('hex');
          this.registry.saveSnapshot({ ...updatedBase, sha256 });
          liveFetchedSources.push(sourceKey);
        } else if (sourceKey === 'SONARQUBE_SERVER') {
          const baseServer = (params?.sonarServerUrl || 'http://127.0.0.1:9000').replace(/\/+$/, '');
          const headers: Record<string, string> = {};
          if (params?.sonarToken) {
            headers['Authorization'] = `Basic ${Buffer.from(`${params.sonarToken}:`).toString('base64')}`;
          }
          const { json: statusData, etag } = await fetchJsonWithHeaders(
            `${baseServer}/api/system/status`,
            { headers },
            2500
          );
          const updatedBase = {
            ...existing,
            version: String(statusData?.version || existing.version),
            originUrl: params?.sonarServerUrl || existing.originUrl,
            fetchedAt: nowIso,
            etag: etag || existing.etag || null,
            freshnessStatus: 'FRESH' as const,
            isOfflineFallback: false,
            lastError: null,
            payloadSummary: {
              ...existing.payloadSummary,
              serverStatus: statusData?.status || 'UP',
            },
          };
          const sha256 = crypto.createHash('sha256').update(JSON.stringify(updatedBase), 'utf8').digest('hex');
          this.registry.saveSnapshot({ ...updatedBase, sha256 });
          liveFetchedSources.push(sourceKey);
        } else if (sourceKey === 'INTERNAL_HISTORY') {
          const updatedBase = {
            ...existing,
            fetchedAt: nowIso,
            recordsCount: params?.internalRunsCount ?? existing.recordsCount,
            freshnessStatus: 'FRESH' as const,
            isOfflineFallback: false,
            lastError: null,
          };
          const sha256 = crypto.createHash('sha256').update(JSON.stringify(updatedBase), 'utf8').digest('hex');
          this.registry.saveSnapshot({ ...updatedBase, sha256 });
          liveFetchedSources.push(sourceKey);
        } else {
          // Local deterministic taxonomies (OWASP_BENCHMARK, MITRE_CWE, PUBLIC_REPOS_VERSIONED): NEVER falsely marked 'FRESH' without remote HTTP check
          const updatedBase = {
            ...existing,
            fetchedAt: nowIso,
            freshnessStatus: 'CACHED_VALID' as const,
            isOfflineFallback: true,
            lastError: null,
          };
          const sha256 = crypto.createHash('sha256').update(JSON.stringify(updatedBase), 'utf8').digest('hex');
          this.registry.saveSnapshot({ ...updatedBase, sha256 });
          cachedFallbackSources.push(sourceKey);
        }
      } catch (err: any) {
        this.registry.markSyncFailureFallback(
          sourceKey,
          `Falha ao consultar fonte externa (${err?.message || 'Timeout/Rede indisponível'}). Preservado último snapshot válido em cache.`
        );
        cachedFallbackSources.push(sourceKey);
      }
    }

    return {
      syncedAt: nowIso,
      snapshots: this.registry.listSnapshots(params?.internalRunsCount ?? 0),
      liveFetchedSources,
      cachedFallbackSources,
    };
  }
}
