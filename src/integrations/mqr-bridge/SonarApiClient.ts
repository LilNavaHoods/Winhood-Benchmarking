import type { SonarPaginationSummary } from '../../types/benchmark';
import { computeSha256 } from '../../engine/scoringEngine';
import { SsrfGuard } from '../../execution/SsrfGuard';

export interface SonarApiClientConfig {
  serverUrl: string;
  token?: string;
  organizationKey?: string;
  timeoutMs?: number;
}

export interface RawSonarIssueApiItem {
  key: string;
  rule: string;
  severity: 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';
  component: string;
  project: string;
  line?: number;
  message: string;
  effort?: string;
  type: 'BUG' | 'VULNERABILITY' | 'CODE_SMELL';
  externalRuleEngine?: string;
}

export interface RawSonarHotspotApiItem {
  key: string;
  component: string;
  project: string;
  securityCategory: string;
  vulnerabilityProbability: 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'TO_REVIEW' | 'REVIEWED';
  resolution?: 'FIXED' | 'SAFE' | 'ACKNOWLEDGED' | 'VULNERABLE';
  line?: number;
  message: string;
  ruleKey?: string;
}

/**
 * MqrBridgeApiClient (Seções 5, 8.2 e 12)
 * Cliente oficial da Web API do MqrBridge Community Build / MqrBridge Server / MqrBridge Cloud.
 * - Não utiliza web scraping; consome exclusivamente endpoints documentados com autenticação Bearer.
 * - Implementa paginação completa para `/api/issues/search` e `/api/hotspots/search` com controle
 *   estrito de completude (`COMPLETE`, `PARTIAL`, `FAILED`, `NOT_AVAILABLE`).
 */
function stripTrailingSlashes(url: string): string {
  let s = url.trim();
  while (s.endsWith('/')) {
    s = s.slice(0, -1);
  }
  return s;
}

export const DEFAULT_SONAR_METRIC_KEYS: string[] = [
  // Standard Experience & Overall Code
  'bugs',
  'vulnerabilities',
  'security_hotspots',
  'security_hotspots_reviewed',
  'code_smells',
  'complexity',
  'cognitive_complexity',
  'duplicated_lines_density',
  'duplicated_blocks',
  'duplicated_lines',
  'ncloc',
  'sqale_index',
  'sqale_debt_ratio',
  'sqale_rating',
  'reliability_rating',
  'security_rating',
  'security_review_rating',
  // Coverage (Separadas: agregada, linha, branch/condição)
  'coverage',
  'line_coverage',
  'branch_coverage',
  'lines_to_cover',
  'uncovered_lines',
  'conditions_to_cover',
  'uncovered_conditions',
  // New Code Metrics
  'new_bugs',
  'new_vulnerabilities',
  'new_security_hotspots',
  'new_security_hotspots_reviewed',
  'new_code_smells',
  'new_coverage',
  'new_line_coverage',
  'new_branch_coverage',
  'new_lines_to_cover',
  'new_uncovered_lines',
  'new_conditions_to_cover',
  'new_uncovered_conditions',
  'new_duplicated_lines_density',
  'new_duplicated_lines',
  'new_lines',
  'new_technical_debt',
  'new_sqale_debt_ratio',
  'new_maintainability_rating',
  'new_reliability_rating',
  'new_security_rating',
  'new_security_review_rating',
  // Multi-Quality Rule (MQR) Mode Metrics
  'software_quality_reliability_issues',
  'software_quality_security_issues',
  'software_quality_maintainability_issues',
  'software_quality_reliability_rating',
  'software_quality_security_rating',
  'software_quality_maintainability_rating',
  'new_software_quality_reliability_rating',
  'new_software_quality_security_rating',
  'new_software_quality_maintainability_rating',
];

export class MqrBridgeApiClient {
  private baseUrl: string;
  private token?: string;
  private organizationKey?: string;
  private timeoutMs: number;

  constructor(config: SonarApiClientConfig) {
    this.baseUrl = stripTrailingSlashes(config.serverUrl);
    this.token = config.token?.trim();
    this.organizationKey = config.organizationKey?.trim();
    this.timeoutMs = config.timeoutMs ?? 8000;
  }

  private buildHeaders(contentType?: string): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'User-Agent': 'WinHood-MqrBridgeApiClient/3.0',
    };
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }
    if (contentType) {
      headers['Content-Type'] = contentType;
    }
    return headers;
  }

  private async requestJson<T>(
    endpointPath: string,
    options: RequestInit = {}
  ): Promise<{ ok: boolean; status: number; data: T | null; rawHash: string; error?: string }> {
    const url = `${this.baseUrl}${endpointPath.startsWith('/') ? endpointPath : `/${endpointPath}`}`;
    const allowExplicitLoopback = SsrfGuard.isExplicitLoopbackUrl(this.baseUrl);

    try {
      const mergedHeaders: Record<string, string> = {
        ...this.buildHeaders(),
        ...(options.headers as Record<string, string> | undefined),
      };
      const bodyPayload =
        typeof options.body === 'string' || Buffer.isBuffer(options.body)
          ? options.body
          : undefined;

      const res = await SsrfGuard.pinnedSafeRequest({
        targetUrl: url,
        method: options.method || 'GET',
        headers: mergedHeaders,
        body: bodyPayload,
        timeoutMs: this.timeoutMs,
        allowExplicitLoopback,
        followRedirects: false,
        maxRedirects: 0,
      });

      const rawText = res.bodyText;
      const rawHash = computeSha256(rawText || `STATUS_${res.statusCode}`);

      if (!res.ok) {
        return {
          ok: false,
          status: res.statusCode,
          data: null,
          rawHash,
          error: `HTTP ${res.statusCode}: ${rawText.slice(0, 200)}`,
        };
      }

      if (!rawText || rawText.trim().length === 0) {
        return {
          ok: true,
          status: res.statusCode,
          data: null,
          rawHash,
        };
      }

      const parsed = JSON.parse(rawText) as T;
      return {
        ok: true,
        status: res.statusCode,
        data: parsed,
        rawHash,
      };
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : 'Falha de conexão HTTP';
      if (errMsg.startsWith('SSRF_BLOCKED')) {
        return {
          ok: false,
          status: 403,
          data: null,
          rawHash: computeSha256(`SSRF_BLOCKED|${url}`),
          error: errMsg,
        };
      }
      if (errMsg.startsWith('SSRF_REDIRECT_BLOCKED')) {
        return {
          ok: false,
          status: 302,
          data: null,
          rawHash: computeSha256(`SSRF_REDIRECT_BLOCKED|${url}`),
          error: errMsg,
        };
      }
      const isTimeout = errMsg.startsWith('Timeout after');
      return {
        ok: false,
        status: isTimeout ? 408 : 0,
        data: null,
        rawHash: computeSha256(`ERR|${url}|${errMsg}`),
        error: isTimeout
          ? 'TIMEOUT: Requisição excedeu o tempo limite configurado.'
          : errMsg,
      };
    }
  }

  public async createProject(projectKey: string, name: string, mainBranch = 'main') {
    const params = new URLSearchParams({
      project: projectKey,
      name,
      mainBranch,
    });
    if (this.organizationKey) {
      params.set('organization', this.organizationKey);
    }
    return this.requestJson<{
      project?: { key: string; name: string; qualifier: string };
    }>(`/api/projects/create?${params.toString()}`, { method: 'POST' });
  }

  public async getComputeEngineTask(ceTaskId: string) {
    return this.requestJson<{
      task?: {
        id: string;
        type: string;
        componentKey: string;
        status: 'PENDING' | 'IN_PROGRESS' | 'SUCCESS' | 'FAILED' | 'CANCELED';
        submittedAt: string;
        startedAt?: string;
        executedAt?: string;
        executionTimeMs?: number;
        analysisId?: string;
        errorMessage?: string;
        errorType?: string;
      };
    }>(`/api/ce/task?id=${encodeURIComponent(ceTaskId)}`);
  }

  public async getComponentMeasures(projectKey: string, metricKeys?: string[]) {
    const keys = metricKeys && metricKeys.length > 0 ? metricKeys : DEFAULT_SONAR_METRIC_KEYS;
    const params = new URLSearchParams({
      component: projectKey,
      metricKeys: keys.join(','),
      additionalFields: 'periods,period',
    });
    return this.requestJson<{
      component?: {
        key: string;
        name: string;
        measures?: Array<{
          metric: string;
          value?: string;
          period?: { value?: string; index?: number; mode?: string; date?: string; parameter?: string };
          periods?: Array<{ value?: string; index?: number; mode?: string; date?: string; parameter?: string }>;
        }>;
      };
      period?: {
        mode?: string;
        date?: string;
        parameter?: string;
      };
      periods?: Array<{
        index?: number;
        mode?: string;
        date?: string;
        parameter?: string;
      }>;
    }>(`/api/measures/component?${params.toString()}`);
  }

  public async searchProjectIssues(projectKey: string, pageSize = 100, page = 1) {
    const safePageSize = Math.min(500, Math.max(1, pageSize));
    const safePage = Math.max(1, page);
    const params = new URLSearchParams({
      componentKeys: projectKey,
      ps: String(safePageSize),
      p: String(safePage),
    });
    if (this.organizationKey) {
      params.set('organization', this.organizationKey);
    }
    return this.requestJson<{
      total?: number;
      p?: number;
      ps?: number;
      paging?: { pageIndex: number; pageSize: number; total: number };
      issues?: RawSonarIssueApiItem[];
    }>(`/api/issues/search?${params.toString()}`);
  }

  /**
   * Busca paginada completa de issues (/api/issues/search) (Seção 12).
   * - Não apresenta 100 itens como se fossem a totalidade quando `total > 100`.
   * - Registra estado de completude (`COMPLETE`, `PARTIAL`, `FAILED`), `totalExpected`, `totalReceived` e `pendingCount`.
   */
  public async fetchAllProjectIssues(
    projectKey: string,
    options?: { pageSize?: number; maxPages?: number }
  ): Promise<{
    ok: boolean;
    status: number;
    issues: RawSonarIssueApiItem[];
    pagination: SonarPaginationSummary;
    rawHash: string;
    error?: string;
  }> {
    const pageSize = Math.min(500, Math.max(1, options?.pageSize ?? 100));
    const maxPages = Math.max(1, options?.maxPages ?? 50); // até 25.000 itens ou limite de 10.000 da API
    const allIssues: RawSonarIssueApiItem[] = [];
    const pageHashes: string[] = [];

    const firstRes = await this.searchProjectIssues(projectKey, pageSize, 1);
    pageHashes.push(firstRes.rawHash);

    if (!firstRes.ok || !firstRes.data) {
      return {
        ok: false,
        status: firstRes.status,
        issues: [],
        rawHash: firstRes.rawHash,
        error: firstRes.error || 'Falha ao consultar primeira página de /api/issues/search.',
        pagination: {
          endpoint: '/api/issues/search',
          pageSize,
          pagesFetched: 0,
          totalExpected: null,
          totalReceived: 0,
          pendingCount: null,
          completeness: 'FAILED',
          errorMessage: firstRes.error || `HTTP ${firstRes.status}`,
        },
      };
    }

    const firstPageIssues = firstRes.data.issues || [];
    allIssues.push(...firstPageIssues);

    const totalExpected =
      typeof firstRes.data.paging?.total === 'number'
        ? firstRes.data.paging.total
        : typeof firstRes.data.total === 'number'
          ? firstRes.data.total
          : firstPageIssues.length;

    let pagesFetched = 1;
    let partialError: string | null = null;

    // A API de busca do MqrBridge/SonarCloud limita paginação direta a 10.000 registros
    const apiWindowLimit = Math.min(totalExpected, 10_000);
    const totalPagesNeeded = Math.ceil(apiWindowLimit / pageSize);

    while (
      pagesFetched < totalPagesNeeded &&
      pagesFetched < maxPages &&
      allIssues.length < totalExpected &&
      firstPageIssues.length > 0
    ) {
      const nextPage = pagesFetched + 1;
      const pageRes = await this.searchProjectIssues(projectKey, pageSize, nextPage);
      pageHashes.push(pageRes.rawHash);

      if (!pageRes.ok || !pageRes.data) {
        partialError =
          pageRes.error || `Falha na página ${nextPage} de /api/issues/search (HTTP ${pageRes.status}).`;
        break;
      }

      const items = pageRes.data.issues || [];
      pagesFetched += 1;
      if (items.length === 0) {
        break;
      }
      allIssues.push(...items);
    }

    const totalReceived = allIssues.length;
    const pendingCount = Math.max(0, totalExpected - totalReceived);
    const isComplete = pendingCount === 0 && !partialError;

    if (!isComplete && !partialError && totalExpected > 10_000 && totalReceived >= 10_000) {
      partialError =
        'Limite de janela de busca da Web API do MqrBridge/SonarCloud (10.000 registros) atingido; consulta classificada como PARTIAL.';
    } else if (!isComplete && !partialError) {
      partialError = `Paginação interrompida após ${pagesFetched} página(s): recebidos ${totalReceived} de ${totalExpected} registros esperados.`;
    }

    return {
      ok: true,
      status: firstRes.status,
      issues: allIssues,
      rawHash: computeSha256(pageHashes.join('|')),
      pagination: {
        endpoint: '/api/issues/search',
        pageSize,
        pagesFetched,
        totalExpected,
        totalReceived,
        pendingCount,
        completeness: isComplete ? 'COMPLETE' : 'PARTIAL',
        errorMessage: partialError,
      },
    };
  }

  public async searchSecurityHotspots(projectKey: string, pageSize = 100, page = 1) {
    const safePageSize = Math.min(500, Math.max(1, pageSize));
    const safePage = Math.max(1, page);
    const params = new URLSearchParams({
      projectKey,
      ps: String(safePageSize),
      p: String(safePage),
    });
    if (this.organizationKey) {
      params.set('organization', this.organizationKey);
    }
    return this.requestJson<{
      paging?: { pageIndex: number; pageSize: number; total: number };
      hotspots?: RawSonarHotspotApiItem[];
    }>(`/api/hotspots/search?${params.toString()}`);
  }

  /**
   * Busca paginada completa de Security Hotspots (/api/hotspots/search) (Seções 10 e 12).
   */
  public async fetchAllSecurityHotspots(
    projectKey: string,
    options?: { pageSize?: number; maxPages?: number }
  ): Promise<{
    ok: boolean;
    status: number;
    hotspots: RawSonarHotspotApiItem[];
    pagination: SonarPaginationSummary;
    rawHash: string;
    error?: string;
  }> {
    const pageSize = Math.min(500, Math.max(1, options?.pageSize ?? 100));
    const maxPages = Math.max(1, options?.maxPages ?? 50);
    const allHotspots: RawSonarHotspotApiItem[] = [];
    const pageHashes: string[] = [];

    const firstRes = await this.searchSecurityHotspots(projectKey, pageSize, 1);
    pageHashes.push(firstRes.rawHash);

    if (!firstRes.ok || !firstRes.data) {
      return {
        ok: false,
        status: firstRes.status,
        hotspots: [],
        rawHash: firstRes.rawHash,
        error: firstRes.error || 'Falha ao consultar primeira página de /api/hotspots/search.',
        pagination: {
          endpoint: '/api/hotspots/search',
          pageSize,
          pagesFetched: 0,
          totalExpected: null,
          totalReceived: 0,
          pendingCount: null,
          completeness: 'FAILED',
          errorMessage: firstRes.error || `HTTP ${firstRes.status}`,
        },
      };
    }

    const firstPageItems = firstRes.data.hotspots || [];
    allHotspots.push(...firstPageItems);

    const totalExpected =
      typeof firstRes.data.paging?.total === 'number'
        ? firstRes.data.paging.total
        : firstPageItems.length;

    let pagesFetched = 1;
    let partialError: string | null = null;
    const totalPagesNeeded = Math.ceil(Math.min(totalExpected, 10_000) / pageSize);

    while (
      pagesFetched < totalPagesNeeded &&
      pagesFetched < maxPages &&
      allHotspots.length < totalExpected &&
      firstPageItems.length > 0
    ) {
      const nextPage = pagesFetched + 1;
      const pageRes = await this.searchSecurityHotspots(projectKey, pageSize, nextPage);
      pageHashes.push(pageRes.rawHash);

      if (!pageRes.ok || !pageRes.data) {
        partialError =
          pageRes.error || `Falha na página ${nextPage} de /api/hotspots/search (HTTP ${pageRes.status}).`;
        break;
      }

      const items = pageRes.data.hotspots || [];
      pagesFetched += 1;
      if (items.length === 0) {
        break;
      }
      allHotspots.push(...items);
    }

    const totalReceived = allHotspots.length;
    const pendingCount = Math.max(0, totalExpected - totalReceived);
    const isComplete = pendingCount === 0 && !partialError;

    if (!isComplete && !partialError) {
      partialError = `Paginação de hotspots incompleta: recebidos ${totalReceived} de ${totalExpected} esperados.`;
    }

    return {
      ok: true,
      status: firstRes.status,
      hotspots: allHotspots,
      rawHash: computeSha256(pageHashes.join('|')),
      pagination: {
        endpoint: '/api/hotspots/search',
        pageSize,
        pagesFetched,
        totalExpected,
        totalReceived,
        pendingCount,
        completeness: isComplete ? 'COMPLETE' : 'PARTIAL',
        errorMessage: partialError,
      },
    };
  }

  public async getQualityGateProjectStatus(projectKey: string) {
    const params = new URLSearchParams({
      projectKey,
    });
    return this.requestJson<{
      projectStatus?: {
        status: 'OK' | 'ERROR' | 'WARN' | 'NONE';
        ignoredConditions?: boolean;
        conditions?: Array<{
          status: 'OK' | 'ERROR' | 'WARN';
          metricKey: string;
          comparator: 'GT' | 'LT' | 'EQ' | 'NE';
          errorThreshold: string;
          actualValue: string;
        }>;
      };
    }>(`/api/qualitygates/project_status?${params.toString()}`);
  }

  public async getProjectQualityGate(projectKey: string) {
    const params = new URLSearchParams({
      project: projectKey,
    });
    if (this.organizationKey) {
      params.set('organization', this.organizationKey);
    }
    return this.requestJson<{
      qualityGate?: {
        id?: string | number;
        name: string;
        default?: boolean;
      };
    }>(`/api/qualitygates/get_by_project?${params.toString()}`);
  }

  public async searchQualityProfiles(projectKey?: string) {
    const params = new URLSearchParams();
    if (projectKey) params.set('project', projectKey);
    if (this.organizationKey) params.set('organization', this.organizationKey);
    const qs = params.toString();
    return this.requestJson<{
      profiles?: Array<{
        key: string;
        name: string;
        language: string;
        languageName?: string;
        activeRuleCount: number;
        isDefault: boolean;
        isBuiltIn?: boolean;
        parentKey?: string;
        parentName?: string;
        rulesUpdatedAt: string;
      }>;
    }>(`/api/qualityprofiles/search${qs ? `?${qs}` : ''}`);
  }
}
