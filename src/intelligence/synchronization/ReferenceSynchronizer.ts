import crypto from 'node:crypto';
import type { ReferenceSnapshotRecord, ReferenceSourceKey } from '../../types/benchmark';
import { ReferenceRegistry } from '../reference/ReferenceRegistry';

export interface ReferenceSyncOutcome {
  syncedAt: string;
  snapshots: ReferenceSnapshotRecord[];
  liveFetchedSources: ReferenceSourceKey[];
  cachedFallbackSources: ReferenceSourceKey[];
}

async function fetchJsonWithTimeout(url: string, init?: RequestInit, timeoutMs = 4500): Promise<any> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }
    return await res.json();
  } finally {
    clearTimeout(timer);
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
    internalRunsCount?: number;
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

    for (const sourceKey of targetSources) {
      const existing = this.registry.getSnapshot(sourceKey);
      if (!existing) continue;

      try {
        if (sourceKey === 'CISA_KEV') {
          const kevData = await fetchJsonWithTimeout(
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            undefined,
            4500
          );
          const count = Array.isArray(kevData?.vulnerabilities) ? kevData.vulnerabilities.length : existing.recordsCount;
          const updatedBase = {
            ...existing,
            version: String(kevData?.catalogVersion || existing.version),
            fetchedAt: nowIso,
            recordsCount: count,
            freshnessStatus: 'FRESH' as const,
            isOfflineFallback: false,
            lastError: null,
            payloadSummary: {
              ...existing.payloadSummary,
              dateReleased: kevData?.dateReleased || nowIso,
              catalogTitle: kevData?.title || 'CISA KEV Catalog',
              vulnerabilitiesCount: count,
            },
          };
          const sha256 = crypto.createHash('sha256').update(JSON.stringify(updatedBase), 'utf8').digest('hex');
          this.registry.saveSnapshot({ ...updatedBase, sha256 });
          liveFetchedSources.push(sourceKey);
        } else if (sourceKey === 'FIRST_EPSS') {
          const epssData = await fetchJsonWithTimeout(
            'https://api.first.org/data/v1/epss?cve=CVE-2021-23337,CVE-2021-44906',
            undefined,
            4500
          );
          const rows = Array.isArray(epssData?.data) ? epssData.data : [];
          const updatedBase = {
            ...existing,
            version: String(epssData?.['model-version'] || existing.version),
            fetchedAt: nowIso,
            recordsCount: Math.max(existing.recordsCount, rows.length),
            freshnessStatus: 'FRESH' as const,
            isOfflineFallback: false,
            lastError: null,
            payloadSummary: {
              ...existing.payloadSummary,
              sampleScores: rows.slice(0, 3),
            },
          };
          const sha256 = crypto.createHash('sha256').update(JSON.stringify(updatedBase), 'utf8').digest('hex');
          this.registry.saveSnapshot({ ...updatedBase, sha256 });
          liveFetchedSources.push(sourceKey);
        } else if (sourceKey === 'OSV_DEV') {
          const osvData = await fetchJsonWithTimeout(
            'https://api.osv.dev/v1/query',
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' }),
            },
            4500
          );
          const vulns = Array.isArray(osvData?.vulns) ? osvData.vulns : [];
          const updatedBase = {
            ...existing,
            fetchedAt: nowIso,
            recordsCount: Math.max(existing.recordsCount, vulns.length),
            freshnessStatus: 'FRESH' as const,
            isOfflineFallback: false,
            lastError: null,
            payloadSummary: {
              ...existing.payloadSummary,
              probePackage: 'npm:lodash@4.17.20',
              advisoriesReturned: vulns.length,
            },
          };
          const sha256 = crypto.createHash('sha256').update(JSON.stringify(updatedBase), 'utf8').digest('hex');
          this.registry.saveSnapshot({ ...updatedBase, sha256 });
          liveFetchedSources.push(sourceKey);
        } else if (sourceKey === 'SONARQUBE_CLOUD') {
          const scData = await fetchJsonWithTimeout(
            'https://sonarcloud.io/api/rules/search?ps=5&languages=ts',
            undefined,
            4500
          );
          const rules = Array.isArray(scData?.rules) ? scData.rules.map((r: any) => String(r.key)) : existing.rulesIncluded;
          const updatedBase = {
            ...existing,
            fetchedAt: nowIso,
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
          const url = `${(params?.sonarServerUrl || 'http://localhost:9000').replace(/\/+$/, '')}/api/system/status`;
          const statusData = await fetchJsonWithTimeout(url, undefined, 2500);
          const updatedBase = {
            ...existing,
            version: String(statusData?.version || existing.version),
            originUrl: params?.sonarServerUrl || existing.originUrl,
            fetchedAt: nowIso,
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
          // Local deterministic taxonomies (OWASP_BENCHMARK, MITRE_CWE, NVD_NIST, PUBLIC_REPOS_VERSIONED)
          const updatedBase = {
            ...existing,
            fetchedAt: nowIso,
            freshnessStatus: 'CACHED_VALID' as const,
            isOfflineFallback: existing.isOfflineFallback,
            lastError: null,
          };
          const sha256 = crypto.createHash('sha256').update(JSON.stringify(updatedBase), 'utf8').digest('hex');
          this.registry.saveSnapshot({ ...updatedBase, sha256 });
          cachedFallbackSources.push(sourceKey);
        }
      } catch (err: any) {
        // Graceful fallback: never delete previous valid snapshot; mark UNAVAILABLE_USING_CACHED
        this.registry.markSyncFailureFallback(
          sourceKey,
          `Falha ao consultar fonte externa (${err?.message || 'Timeout/Rede indisponível'}). Preservado último snapshot válido.`
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
