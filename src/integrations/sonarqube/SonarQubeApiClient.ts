import { computeSha256 } from '../../engine/scoringEngine';

export interface SonarApiClientConfig {
  serverUrl: string;
  token?: string;
  organizationKey?: string;
  timeoutMs?: number;
}

/**
 * SonarQubeApiClient (Seção 5 e 8.2)
 * Cliente oficial da Web API do SonarQube Community Build / SonarQube Cloud.
 * Não utiliza web scraping; consome exclusivamente endpoints documentados com autenticação Bearer.
 */
function stripTrailingSlashes(url: string): string {
  let s = url.trim();
  while (s.endsWith('/')) {
    s = s.slice(0, -1);
  }
  return s;
}

export class SonarQubeApiClient {
  private baseUrl: string;
  private token?: string;
  private organizationKey?: string;
  private timeoutMs: number;

  constructor(config: SonarApiClientConfig) {
    this.baseUrl = stripTrailingSlashes(config.serverUrl);
    this.token = config.token?.trim();
    this.organizationKey = config.organizationKey?.trim();
    this.timeoutMs = config.timeoutMs ?? 6000;
  }

  private buildHeaders(contentType?: string): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'User-Agent': 'WinHood-SonarQubeApiClient/2.0',
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
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const url = `${this.baseUrl}${endpointPath.startsWith('/') ? endpointPath : `/${endpointPath}`}`;

    try {
      const res = await fetch(url, {
        ...options,
        headers: {
          ...this.buildHeaders(),
          ...(options.headers as Record<string, string> | undefined),
        },
        signal: controller.signal,
      });
      clearTimeout(timer);
      const rawText = await res.text();
      const rawHash = computeSha256(rawText || `STATUS_${res.status}`);

      if (!res.ok) {
        return {
          ok: false,
          status: res.status,
          data: null,
          rawHash,
          error: `HTTP ${res.status}: ${rawText.slice(0, 200)}`,
        };
      }

      if (!rawText || rawText.trim().length === 0) {
        return {
          ok: true,
          status: res.status,
          data: null,
          rawHash,
        };
      }

      const parsed = JSON.parse(rawText) as T;
      return {
        ok: true,
        status: res.status,
        data: parsed,
        rawHash,
      };
    } catch (err: any) {
      clearTimeout(timer);
      const isAbort = err?.name === 'AbortError';
      return {
        ok: false,
        status: isAbort ? 408 : 0,
        data: null,
        rawHash: computeSha256(`ERR|${url}|${err?.message || 'NETWORK_ERR'}`),
        error: isAbort ? 'TIMEOUT: Requisição excedeu o tempo limite configurado.' : err?.message || 'Falha de conexão HTTP',
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
    const keys = metricKeys || [
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
      'sqale_rating',
      'reliability_rating',
      'security_rating',
      'coverage',
      'lines_to_cover',
      'uncovered_lines',
      'conditions_to_cover',
      'new_coverage',
    ];
    const params = new URLSearchParams({
      component: projectKey,
      metricKeys: keys.join(','),
    });
    return this.requestJson<{
      component?: {
        key: string;
        name: string;
        measures?: Array<{
          metric: string;
          value?: string;
          period?: { value?: string };
        }>;
      };
    }>(`/api/measures/component?${params.toString()}`);
  }

  public async searchProjectIssues(projectKey: string, pageSize = 100) {
    const params = new URLSearchParams({
      componentKeys: projectKey,
      ps: String(pageSize),
    });
    if (this.organizationKey) {
      params.set('organization', this.organizationKey);
    }
    return this.requestJson<{
      total?: number;
      issues?: Array<{
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
      }>;
    }>(`/api/issues/search?${params.toString()}`);
  }

  public async searchSecurityHotspots(projectKey: string) {
    const params = new URLSearchParams({
      projectKey,
    });
    return this.requestJson<{
      hotspots?: Array<{
        key: string;
        component: string;
        project: string;
        securityCategory: string;
        vulnerabilityProbability: 'HIGH' | 'MEDIUM' | 'LOW';
        status: 'TO_REVIEW' | 'REVIEWED';
        resolution?: 'FIXED' | 'SAFE' | 'ACKNOWLEDGED';
        line?: number;
        message: string;
        ruleKey?: string;
      }>;
    }>(`/api/hotspots/search?${params.toString()}`);
  }

  public async getQualityGateProjectStatus(projectKey: string) {
    const params = new URLSearchParams({
      projectKey,
    });
    return this.requestJson<{
      projectStatus?: {
        status: 'OK' | 'ERROR' | 'WARN' | 'NONE';
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
        activeRuleCount: number;
        isDefault: boolean;
        rulesUpdatedAt: string;
      }>;
    }>(`/api/qualityprofiles/search${qs ? `?${qs}` : ''}`);
  }
}
