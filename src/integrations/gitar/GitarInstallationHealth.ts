import type { GitarConnectionState, GitProviderType } from '../../types/benchmark';

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

    const cleanUrl = params.apiBaseUrl.trim().replace(/\/+$/, '');
    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), 3500);
      const res = await fetch(`${cleanUrl}/health`, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${params.token.trim()}`,
          'User-Agent': 'WinHood-GitarAdapter/2.0',
        },
        signal: controller.signal,
      });
      clearTimeout(t);
      const latencyMs = Math.round((performance.now() - start) * 10) / 10;

      if (res.status === 401 || res.status === 403) {
        return {
          healthy: false,
          state: 'AUTH_FAILED',
          provider: params.provider,
          apiBaseUrl: cleanUrl,
          checkedAt: nowIso,
          latencyMs,
          message: `Falha de autenticação HTTP ${res.status} na API Gitar (${cleanUrl}/health).`,
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
          message: `Endpoint Gitar respondeu com HTTP ${res.status}.`,
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
    } catch (err: any) {
      const latencyMs = Math.round((performance.now() - start) * 10) / 10;
      return {
        healthy: false,
        state: 'PROVIDER_UNAVAILABLE',
        provider: params.provider,
        apiBaseUrl: cleanUrl,
        checkedAt: nowIso,
        latencyMs,
        message: `API Gitar (${cleanUrl}) indisponível ou sem rota ativa: ${err?.message || 'Erro de conexão'}.`,
      };
    }
  }
}
