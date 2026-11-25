import type { GitarConnectionState, GitProviderType } from '../../types/benchmark';
import { SsrfGuard } from '../../execution/SsrfGuard';

export interface GitarHealthStatus {
  healthy: boolean;
  state: GitarConnectionState;
  provider: GitProviderType;
  apiBaseUrl: string;
  checkedAt: string;
  latencyMs: number;
  message: string;
}

/**
 * GitarInstallationHealth (Seção 9.2)
 * Verifica a saúde da instalação e integração do Gitar AI na API documentada (https://docs.gitar.ai/api-reference/overview).
 */
export class GitarInstallationHealth {
  public static async checkInstallationHealth(params: {
    apiBaseUrl: string;
    token?: string | null;
    provider: GitProviderType;
    explicitConsent: boolean;
  }): Promise<GitarHealthStatus> {
    const nowIso = new Date().toISOString();
    const start = performance.now();

    if (!params.token || params.token.trim().length === 0) {
      return {
        healthy: false,
        state: 'NOT_CONFIGURED',
        provider: params.provider,
        apiBaseUrl: params.apiBaseUrl,
        checkedAt: nowIso,
        latencyMs: 0,
        message: 'NOT_CONFIGURED: Credencial Bearer da API Gitar não foi configurada.',
      };
    }

    if (!params.explicitConsent) {
      return {
        healthy: false,
        state: 'NOT_CONFIGURED',
        provider: params.provider,
        apiBaseUrl: params.apiBaseUrl,
        checkedAt: nowIso,
        latencyMs: 0,
        message:
          'NOT_CONFIGURED: É necessário autorizar explicitamente o envio de metadados de Pull Request/CI ao serviço externo Gitar AI.',
      };
    }

    let cleanUrl = params.apiBaseUrl.trim();
    while (cleanUrl.endsWith('/')) {
      cleanUrl = cleanUrl.slice(0, -1);
    }

    const healthUrl = `${cleanUrl}/health`;
    const allowExplicitLoopback = SsrfGuard.isExplicitLoopbackUrl(cleanUrl);
    const ssrf = await SsrfGuard.validateUrl({
      targetUrl: healthUrl,
      allowExplicitLoopback,
    });
    if (!ssrf.allowed) {
      const latencyMs = Math.round((performance.now() - start) * 10) / 10;
      return {
        healthy: false,
        state: 'PROVIDER_UNAVAILABLE',
        provider: params.provider,
        apiBaseUrl: cleanUrl,
        checkedAt: nowIso,
        latencyMs,
        message: `SSRF_BLOCKED: ${ssrf.reason}`,
      };
    }

    try {
      const res = await SsrfGuard.pinnedSafeRequest({
        targetUrl: healthUrl,
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${params.token.trim()}`,
          'User-Agent': 'WinHood-GitarAdapter/2.0',
        },
        timeoutMs: 3500,
        allowExplicitLoopback,
        followRedirects: false,
        maxRedirects: 0,
      });
      const latencyMs = Math.round((performance.now() - start) * 10) / 10;

      if (res.statusCode === 401 || res.statusCode === 403) {
        return {
          healthy: false,
          state: 'AUTH_FAILED',
          provider: params.provider,
          apiBaseUrl: cleanUrl,
          checkedAt: nowIso,
          latencyMs,
          message: `Falha de autenticação HTTP ${res.statusCode} na API Gitar (${healthUrl}).`,
        };
      }

      if (!res.ok) {
        return {
          healthy: false,
          state: 'PROVIDER_UNAVAILABLE',
          provider: params.provider,
          apiBaseUrl: cleanUrl,
          checkedAt: nowIso,
          latencyMs,
          message: `Endpoint Gitar respondeu com HTTP ${res.statusCode}.`,
        };
      }

      return {
        healthy: true,
        state: 'CONNECTED',
        provider: params.provider,
        apiBaseUrl: cleanUrl,
        checkedAt: nowIso,
        latencyMs,
        message: `Integração Gitar AI (${params.provider}) autenticada e operacional (${latencyMs}ms).`,
      };
    } catch (err: unknown) {
      const latencyMs = Math.round((performance.now() - start) * 10) / 10;
      const errMsg = err instanceof Error ? err.message : 'Erro de conexão';
      if (errMsg.startsWith('SSRF_REDIRECT_BLOCKED') || errMsg.startsWith('SSRF_BLOCKED')) {
        return {
          healthy: false,
          state: 'PROVIDER_UNAVAILABLE',
          provider: params.provider,
          apiBaseUrl: cleanUrl,
          checkedAt: nowIso,
          latencyMs,
          message: errMsg,
        };
      }
      return {
        healthy: false,
        state: 'PROVIDER_UNAVAILABLE',
        provider: params.provider,
        apiBaseUrl: cleanUrl,
        checkedAt: nowIso,
        latencyMs,
        message: `API Gitar (${cleanUrl}) indisponível ou sem rota ativa: ${errMsg}.`,
      };
    }
  }
}
