import crypto from 'node:crypto';
import type { SonarConnectionState, SonarInstallationMode, SonarInstanceRecord } from '../../types/benchmark';

export interface ProbeSonarQubeOptions {
  serverUrl: string;
  token?: string;
  mode: SonarInstallationMode;
  organizationKey?: string;
  timeoutMs?: number;
}

export interface ProbeSonarQubeResult {
  connectionState: SonarConnectionState;
  httpReachable: boolean;
  authenticated: boolean;
  version: string | null;
  edition: SonarInstanceRecord['edition'];
  systemStatus: string | null;
  apiCompatibility: SonarInstanceRecord['apiCompatibility'];
  permissions: SonarInstanceRecord['permissionsVerified'];
  tokenExpiresAt: string | null;
  latencyMs: number;
  errorMessage: string | null;
}

/**
 * SonarQubeConnection & probeSonarQube() (Seção 3.4, 4.1 e 4.2)
 * - Nunca exibe CONNECTED apenas porque uma URL foi cadastrada.
 * - Exige resposta HTTP real e válida do servidor SonarQube (/api/system/status, /api/authentication/validate).
 * - Mantém tokens criptografados no backend e usa cabeçalho Authorization: Bearer <token>.
 */
export class SonarQubeConnection {
  private static readonly SECRET_KEY = crypto
    .createHash('sha256')
    .update(process.env.SONAR_SECRET_SALT || 'winhood-sonar-vault-key-2026')
    .digest();

  public static maskToken(token?: string): string {
    if (!token || token.trim().length === 0) return 'Não configurado';
    const clean = token.trim();
    if (clean.length <= 8) return '••••••••';
    return `${clean.slice(0, 4)}••••••••${clean.slice(-4)}`;
  }

  public static encryptToken(plainToken: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', SonarQubeConnection.SECRET_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(plainToken, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  public static decryptToken(cipherText: string): string | null {
    try {
      const [ivHex, tagHex, dataHex] = cipherText.split(':');
      if (!ivHex || !tagHex || !dataHex) return null;
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        SonarQubeConnection.SECRET_KEY,
        Buffer.from(ivHex, 'hex')
      );
      decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(dataHex, 'hex')),
        decipher.final(),
      ]);
      return decrypted.toString('utf8');
    } catch {
      return null;
    }
  }

  public static async probeSonarQube(
    options: ProbeSonarQubeOptions
  ): Promise<ProbeSonarQubeResult> {
    const start = performance.now();
    const rawUrl = (options.serverUrl || '').trim().replace(/\/+$/, '');
    const timeoutMs = options.timeoutMs ?? 4000;

    if (!rawUrl) {
      return {
        connectionState: 'NOT_CONFIGURED',
        httpReachable: false,
        authenticated: false,
        version: null,
        edition: null,
        systemStatus: null,
        apiCompatibility: 'UNKNOWN',
        permissions: {
          browse: false,
          executeAnalysis: false,
          administerQualityGates: false,
          provisioning: false,
        },
        tokenExpiresAt: null,
        latencyMs: 0,
        errorMessage: 'URL do servidor SonarQube não foi configurada.',
      };
    }

    const headers: Record<string, string> = {
      Accept: 'application/json',
      'User-Agent': 'WinHood-SonarQubeIntegrationService/2.0',
    };
    if (options.token && options.token.trim().length > 0) {
      headers.Authorization = `Bearer ${options.token.trim()}`;
    }

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      const statusRes = await fetch(`${rawUrl}/api/system/status`, {
        method: 'GET',
        headers,
        signal: controller.signal,
      });
      clearTimeout(timer);

      const latencyMs = Math.round((performance.now() - start) * 10) / 10;

      if (statusRes.status === 401 || statusRes.status === 403) {
        return {
          connectionState: 'AUTH_FAILED',
          httpReachable: true,
          authenticated: false,
          version: null,
          edition: null,
          systemStatus: 'AUTH_REQUIRED',
          apiCompatibility: 'UNKNOWN',
          permissions: {
            browse: false,
            executeAnalysis: false,
            administerQualityGates: false,
            provisioning: false,
          },
          tokenExpiresAt: null,
          latencyMs,
          errorMessage: `Falha de autenticação HTTP ${statusRes.status}: token Bearer inválido ou ausente.`,
        };
      }

      if (!statusRes.ok) {
        return {
          connectionState: 'SERVER_UNAVAILABLE',
          httpReachable: false,
          authenticated: false,
          version: null,
          edition: null,
          systemStatus: `HTTP_${statusRes.status}`,
          apiCompatibility: 'UNKNOWN',
          permissions: {
            browse: false,
            executeAnalysis: false,
            administerQualityGates: false,
            provisioning: false,
          },
          tokenExpiresAt: null,
          latencyMs,
          errorMessage: `Servidor respondeu com status inesperado HTTP ${statusRes.status}.`,
        };
      }

      const statusJson = (await statusRes.json()) as {
        id?: string;
        version?: string;
        status?: string;
      };

      const version = statusJson.version || null;
      const systemStatus = statusJson.status || 'UNKNOWN';

      // Verificar compatibilidade de versão (exigir >= 9.9 ou formato 24.x / 25.x / 26.x)
      if (version) {
        const major = parseInt(version.split('.')[0], 10);
        if (!Number.isNaN(major) && major < 9) {
          return {
            connectionState: 'VERSION_UNSUPPORTED',
            httpReachable: true,
            authenticated: false,
            version,
            edition: 'Community Build',
            systemStatus,
            apiCompatibility: 'UNSUPPORTED',
            permissions: {
              browse: false,
              executeAnalysis: false,
              administerQualityGates: false,
              provisioning: false,
            },
            tokenExpiresAt: null,
            latencyMs,
            errorMessage: `Versão do SonarQube (${version}) não é suportada. Utilize SonarQube Community Build 24.12+ / 26.11+ ou 9.9+ LTS.`,
          };
        }
      }

      if (systemStatus !== 'UP') {
        return {
          connectionState: systemStatus === 'STARTING' ? 'CONNECTING' : 'SERVER_UNAVAILABLE',
          httpReachable: true,
          authenticated: false,
          version,
          edition: options.mode === 'CLOUD' ? 'SonarQube Cloud' : 'Community Build',
          systemStatus,
          apiCompatibility: 'WEB_API_V2_AND_V1',
          permissions: {
            browse: false,
            executeAnalysis: false,
            administerQualityGates: false,
            provisioning: false,
          },
          tokenExpiresAt: null,
          latencyMs,
          errorMessage: `Servidor SonarQube alcançado, mas estado operacional atual é "${systemStatus}" (aguardando UP).`,
        };
      }

      // Validar autenticação se token foi fornecido
      let authenticated = false;
      let tokenExpiresAt: string | null = null;
      if (options.token && options.token.trim().length > 0) {
        const authRes = await fetch(`${rawUrl}/api/authentication/validate`, {
          method: 'GET',
          headers,
        });
        if (authRes.status === 401 || authRes.status === 403) {
          return {
            connectionState: 'AUTH_FAILED',
            httpReachable: true,
            authenticated: false,
            version,
            edition: options.mode === 'CLOUD' ? 'SonarQube Cloud' : 'Community Build',
            systemStatus,
            apiCompatibility: 'WEB_API_V2_AND_V1',
            permissions: {
              browse: false,
              executeAnalysis: false,
              administerQualityGates: false,
              provisioning: false,
            },
            tokenExpiresAt: null,
            latencyMs,
            errorMessage: 'Token SonarQube rejeitado pelo endpoint /api/authentication/validate.',
          };
        }
        if (authRes.ok) {
          const authJson = (await authRes.json()) as { valid?: boolean; tokenExpiresAt?: string };
          authenticated = Boolean(authJson.valid);
          if (authJson.tokenExpiresAt) {
            tokenExpiresAt = authJson.tokenExpiresAt;
          }
          if (!authenticated) {
            return {
              connectionState: 'AUTH_FAILED',
              httpReachable: true,
              authenticated: false,
              version,
              edition: options.mode === 'CLOUD' ? 'SonarQube Cloud' : 'Community Build',
              systemStatus,
              apiCompatibility: 'WEB_API_V2_AND_V1',
              permissions: {
                browse: false,
                executeAnalysis: false,
                administerQualityGates: false,
                provisioning: false,
              },
              tokenExpiresAt: null,
              latencyMs,
              errorMessage: 'Token SonarQube inválido (valid: false em /api/authentication/validate).',
            };
          }
        }
      }

      const majorVer = version ? parseInt(version.split('.')[0], 10) : 26;
      const apiCompatibility: SonarInstanceRecord['apiCompatibility'] =
        majorVer >= 10 ? 'WEB_API_V2_AND_V1' : 'WEB_API_V1_LEGACY';

      return {
        connectionState: authenticated ? 'READY' : 'CONNECTED',
        httpReachable: true,
        authenticated,
        version,
        edition: options.mode === 'CLOUD' ? 'SonarQube Cloud' : 'Community Build',
        systemStatus,
        apiCompatibility,
        permissions: {
          browse: true,
          executeAnalysis: authenticated,
          administerQualityGates: authenticated,
          provisioning: authenticated,
        },
        tokenExpiresAt,
        latencyMs,
        errorMessage: authenticated
          ? null
          : 'Servidor UP, mas nenhum token Bearer válido foi autenticado para execução de análises.',
      };
    } catch (err: any) {
      const latencyMs = Math.round((performance.now() - start) * 10) / 10;
      const isLocal =
        rawUrl.includes('localhost') || rawUrl.includes('127.0.0.1');
      return {
        connectionState: isLocal ? 'NOT_INSTALLED' : 'SERVER_UNAVAILABLE',
        httpReachable: false,
        authenticated: false,
        version: null,
        edition: null,
        systemStatus: 'UNREACHABLE',
        apiCompatibility: 'UNKNOWN',
        permissions: {
          browse: false,
          executeAnalysis: false,
          administerQualityGates: false,
          provisioning: false,
        },
        tokenExpiresAt: null,
        latencyMs,
        errorMessage: isLocal
          ? `Nenhum servidor SonarQube em execução em ${rawUrl} (${err?.message || 'ECONNREFUSED'}). O servidor não é iniciado automaticamente nem simulado.`
          : `Servidor SonarQube remoto inacessível em ${rawUrl}: ${err?.message || 'Falha de conexão'}.`,
      };
    }
  }
}
