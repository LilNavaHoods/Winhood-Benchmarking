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
    const targetUrl = `${this.apiBaseUrl}${path.startsWith('/') ? path : `/${path}`}`;
    const allowExplicitLoopback = SsrfGuard.isExplicitLoopbackUrl(this.apiBaseUrl);
    try {
      const res = await SsrfGuard.pinnedSafeRequest({
        targetUrl,
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${this.token}`,
          'User-Agent': 'WinHood-GitarApiClient/2.0',
        },
        timeoutMs: 4000,
        allowExplicitLoopback,
        followRedirects: false,
        maxRedirects: 0,
      });
      if (!res.ok) {
        return { ok: false, status: res.statusCode, data: null, error: `HTTP ${res.statusCode}` };
      }
      const data = res.json<T>();
      return { ok: true, status: res.statusCode, data };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Network failure';
      if (msg.startsWith('SSRF_BLOCKED')) {
        return { ok: false, status: 403, data: null, error: msg };
      }
      if (msg.startsWith('SSRF_REDIRECT_BLOCKED')) {
        return { ok: false, status: 302, data: null, error: msg };
      }
      return { ok: false, status: 0, data: null, error: msg };
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
