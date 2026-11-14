import { SsrfGuard } from '../../execution/SsrfGuard';

/**
 * GitarApiClient (Seção 9.2)
 * Implementa exclusivamente operações documentadas na referência oficial da API Gitar:
 * - Verificação de saúde da instalação (/health)
 * - Onboarding e listagem de repositórios (/projects)
 * - Consulta do status de Merge Requests / Pull Requests (/merge-requests/status)
 * - Consulta de revisões e falhas de CI
 * Não inventa endpoints nem realiza scraping de dashboard.
 */
function stripTrailingSlashes(url: string): string {
  let s = url.trim();
  while (s.endsWith('/')) {
    s = s.slice(0, -1);
  }
  return s;
}

export class GitarApiClient {
  private apiBaseUrl: string;
  private token: string;

  constructor(apiBaseUrl: string, token: string) {
    this.apiBaseUrl = stripTrailingSlashes(apiBaseUrl);
    this.token = token.trim();
  }

  private async getJson<T>(path: string): Promise<{ ok: boolean; status: number; data: T | null; error?: string }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const targetUrl = `${this.apiBaseUrl}${path.startsWith('/') ? path : `/${path}`}`;
    try {
      const ssrf = await SsrfGuard.validateUrl({
        targetUrl,
        allowExplicitLoopback: SsrfGuard.isExplicitLoopbackUrl(this.apiBaseUrl),
      });
      if (!ssrf.allowed) {
        clearTimeout(timer);
        return { ok: false, status: 403, data: null, error: `SSRF_BLOCKED: ${ssrf.reason}` };
      }

      const res = await fetch(targetUrl, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${this.token}`,
          'User-Agent': 'WinHood-GitarApiClient/2.0',
        },
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (res.status >= 300 && res.status < 400) {
        return { ok: false, status: res.status, data: null, error: `SSRF_REDIRECT_BLOCKED: HTTP ${res.status}` };
      }
      if (!res.ok) {
        return { ok: false, status: res.status, data: null, error: `HTTP ${res.status}` };
      }
      const data = (await res.json()) as T;
      return { ok: true, status: res.status, data };
    } catch (err: any) {
      clearTimeout(timer);
      return { ok: false, status: 0, data: null, error: err?.message || 'Network failure' };
    }
  }

  public async listOnboardedRepositories() {
    return this.getJson<{ repositories?: string[] }>('/projects');
  }

  public async getMergeRequestReviewStatus(repository: string, prNumber: number) {
    const params = new URLSearchParams({
      repository,
      prNumber: String(prNumber),
    });
    return this.getJson<{
      status?: string;
      reviews?: Array<any>;
      ciFailures?: Array<any>;
    }>(`/merge-requests/status?${params.toString()}`);
  }
}
