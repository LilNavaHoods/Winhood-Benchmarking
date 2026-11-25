import crypto from 'node:crypto';
import { KeyManagementService } from '../../security/KeyManagementService';
import { SsrfGuard } from '../../execution/SsrfGuard';
import type { SonarConnectionState, SonarInstallationMode, SonarInstanceRecord } from '../../types/benchmark';

export interface ProbeMqrBridgeOptions {
  serverUrl: string;
  token?: string;
  mode: SonarInstallationMode;
  organizationKey?: string;
  timeoutMs?: number;
}

export interface ProbeMqrBridgeResult {
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
 * MqrBridgeConnection & probeMqrBridge() (Seção 3.4, 4.1 e 4.2)
 * - Nunca exibe CONNECTED apenas porque uma URL foi cadastrada.
 * - Exige resposta HTTP real e válida do servidor MqrBridge (/api/system/status, /api/authentication/validate).
 * - Utiliza gerenciamento externo de chaves AES-256-GCM (KeyManagementService) com suporte a rotação.
 */
export class MqrBridgeConnection {
  public static maskToken(token?: string): string {
    if (!token || token.trim().length === 0) return 'Não configurado';
    const clean = token.trim();
    if (clean.length <= 8) return '••••••••';
    return `${clean.slice(0, 4)}••••••••${clean.slice(-4)}`;
  }

  public static encryptToken(plainToken: string): string {
    const active = KeyManagementService.getActiveVaultAesKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', active.keyBuffer, iv);
    const encrypted = Buffer.concat([cipher.update(plainToken, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return `${active.keyId}:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  public static decryptToken(cipherText: string): string | null {
    try {
      const parts = cipherText.split(':');
      let keyBuffer: Buffer | null = null;
      let ivHex = '';
      let tagHex = '';
      let dataHex = '';

      if (parts.length === 4) {
        const [keyId, iv, tag, data] = parts;
        keyBuffer = KeyManagementService.getVaultKeyBufferByKeyId(keyId!);
        ivHex = iv!;
        tagHex = tag!;
        dataHex = data!;
      } else if (parts.length === 3) {
        keyBuffer = KeyManagementService.getActiveVaultAesKey().keyBuffer;
        [ivHex, tagHex, dataHex] = parts as [string, string, string];
      } else {
        return null;
      }

      if (!keyBuffer || !ivHex || !tagHex || !dataHex) return null;
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        keyBuffer,
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

  public static reencryptToken(
    cipherText: string,
    ctx: {
      oldKeyId: string;
      oldKeyBuffer: Buffer;
      newKeyId: string;
      newKeyBuffer: Buffer;
    }
  ): string | null {
    try {
      const parts = cipherText.split(':');
      let keyBuffer: Buffer | null = null;
      let ivHex = '';
      let tagHex = '';
      let dataHex = '';

      if (parts.length === 4) {
        const [keyId, iv, tag, data] = parts;
        keyBuffer =
          keyId === ctx.oldKeyId
            ? ctx.oldKeyBuffer
            : KeyManagementService.getVaultKeyBufferByKeyId(keyId!);
        ivHex = iv!;
        tagHex = tag!;
        dataHex = data!;
      } else if (parts.length === 3) {
        keyBuffer = ctx.oldKeyBuffer;
        [ivHex, tagHex, dataHex] = parts as [string, string, string];
      } else {
        return null;
      }

      if (!keyBuffer || !ivHex || !tagHex || !dataHex) return null;
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        keyBuffer,
        Buffer.from(ivHex, 'hex')
      );
      decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(dataHex, 'hex')),
        decipher.final(),
      ]).toString('utf8');

      const newIv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', ctx.newKeyBuffer, newIv);
      const encrypted = Buffer.concat([cipher.update(decrypted, 'utf8'), cipher.final()]);
      const authTag = cipher.getAuthTag();
      return `${ctx.newKeyId}:${newIv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
    } catch {
      return null;
    }
  }

  private static stripTrailingSlashes(url: string): string {
    let s = url.trim();
    while (s.endsWith('/')) {
      s = s.slice(0, -1);
    }
    return s;
  }

  public static async probeMqrBridge(
    options: ProbeMqrBridgeOptions
  ): Promise<ProbeMqrBridgeResult> {
    const start = performance.now();
    const rawUrl = MqrBridgeConnection.stripTrailingSlashes(options.serverUrl || '');
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
        errorMessage: 'URL do servidor MqrBridge não foi configurada.',
      };
    }

    const allowExplicitLoopback = SsrfGuard.isExplicitLoopbackUrl(rawUrl);
    const ssrf = await SsrfGuard.validateUrl({
      targetUrl: rawUrl,
      allowExplicitLoopback,
    });
    if (!ssrf.allowed) {
      return {
        connectionState: 'SERVER_UNAVAILABLE',
        httpReachable: false,
        authenticated: false,
        version: null,
        edition: null,
        systemStatus: 'SSRF_BLOCKED',
        apiCompatibility: 'UNKNOWN',
        permissions: {
          browse: false,
          executeAnalysis: false,
          administerQualityGates: false,
          provisioning: false,
        },
        tokenExpiresAt: null,
        latencyMs: Math.round((performance.now() - start) * 10) / 10,
        errorMessage: `SSRF_BLOCKED: ${ssrf.reason}`,
      };
    }

    const headers: Record<string, string> = {
      Accept: 'application/json',
      'User-Agent': 'WinHood-MqrBridgeIntegrationService/2.0',
    };
    if (options.token && options.token.trim().length > 0) {
      headers.Authorization = `Bearer ${options.token.trim()}`;
    }

    try {
      const statusRes = await SsrfGuard.pinnedSafeRequest({
        targetUrl: `${rawUrl}/api/system/status`,
        method: 'GET',
        headers,
        timeoutMs,
        allowExplicitLoopback,
        followRedirects: false,
        maxRedirects: 0,
      });

      const latencyMs = Math.round((performance.now() - start) * 10) / 10;

      if (statusRes.statusCode === 401 || statusRes.statusCode === 403) {
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
          errorMessage: `Falha de autenticação HTTP ${statusRes.statusCode}: token Bearer inválido ou ausente.`,
        };
      }

      if (!statusRes.ok) {
        return {
          connectionState: 'SERVER_UNAVAILABLE',
          httpReachable: false,
          authenticated: false,
          version: null,
          edition: null,
          systemStatus: `HTTP_${statusRes.statusCode}`,
          apiCompatibility: 'UNKNOWN',
          permissions: {
            browse: false,
            executeAnalysis: false,
            administerQualityGates: false,
            provisioning: false,
          },
          tokenExpiresAt: null,
          latencyMs,
          errorMessage: `Servidor respondeu com status inesperado HTTP ${statusRes.statusCode}.`,
        };
      }

      const statusJson = statusRes.json<{
        id?: string;
        version?: string;
        status?: string;
      }>();

      const version = statusJson.version || null;
      const systemStatus = statusJson.status || 'UNKNOWN';

      const isCloudInstance =
        options.mode === 'CLOUD' ||
        rawUrl.toLowerCase().includes('sonarcloud.io') ||
        rawUrl.toLowerCase().includes('mqr-bridge.us') ||
        Boolean(version && (version.startsWith('8.0.0') || version.startsWith('8.0.')));

      // Verificar compatibilidade de versão (SonarCloud SaaS 8.0+ aprovado automaticamente; on-premise exige >= 9.9 ou 24.x/26.x)
      if (version && !isCloudInstance) {
        const major = Number.parseInt(version.split('.')[0], 10);
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
            errorMessage: `Versão do MqrBridge (${version}) não é suportada. Utilize MqrBridge Community Build 24.12+ / 26.11+ ou 9.9+ LTS.`,
          };
        }
      }

      if (systemStatus !== 'UP') {
        return {
          connectionState: systemStatus === 'STARTING' ? 'CONNECTING' : 'SERVER_UNAVAILABLE',
          httpReachable: true,
          authenticated: false,
          version,
          edition: isCloudInstance ? 'MqrBridge Cloud' : 'Community Build',
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
          errorMessage: `Servidor MqrBridge alcançado, mas estado operacional atual é "${systemStatus}" (aguardando UP).`,
        };
      }

      // Validar autenticação se token foi fornecido
      let authenticated = false;
      let tokenExpiresAt: string | null = null;
      if (options.token && options.token.trim().length > 0) {
        const authRes = await SsrfGuard.pinnedSafeRequest({
          targetUrl: `${rawUrl}/api/authentication/validate`,
          method: 'GET',
          headers,
          timeoutMs,
          allowExplicitLoopback,
          followRedirects: false,
          maxRedirects: 0,
        });
        if (authRes.statusCode === 401 || authRes.statusCode === 403) {
          return {
            connectionState: 'AUTH_FAILED',
            httpReachable: true,
            authenticated: false,
            version,
            edition: options.mode === 'CLOUD' ? 'MqrBridge Cloud' : 'Community Build',
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
            errorMessage: 'Token MqrBridge rejeitado pelo endpoint /api/authentication/validate.',
          };
        }
        if (authRes.ok) {
          const authJson = authRes.json<{ valid?: boolean; tokenExpiresAt?: string }>();
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
              edition: options.mode === 'CLOUD' ? 'MqrBridge Cloud' : 'Community Build',
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
              errorMessage: 'Token MqrBridge inválido (valid: false em /api/authentication/validate).',
            };
          }
        }
      }

      // Consultar permissões reais via /api/users/current quando autenticado
      let verifiedPerms: SonarInstanceRecord['permissionsVerified'] = {
        browse: true,
        executeAnalysis: authenticated,
        administerQualityGates: false,
        provisioning: false,
      };
      if (authenticated) {
        try {
          const userRes = await SsrfGuard.pinnedSafeRequest({
            targetUrl: `${rawUrl}/api/users/current`,
            method: 'GET',
            headers,
            timeoutMs,
            allowExplicitLoopback,
            followRedirects: false,
            maxRedirects: 0,
          });
          if (userRes.ok) {
            const userJson = userRes.json<{ permissions?: { global?: string[] } }>();
            const globalPerms = userJson.permissions?.global;
            if (Array.isArray(globalPerms)) {
              verifiedPerms = {
                browse: true,
                executeAnalysis: globalPerms.includes('scan') || globalPerms.includes('admin'),
                administerQualityGates:
                  globalPerms.includes('gateadmin') || globalPerms.includes('admin'),
                provisioning:
                  globalPerms.includes('provisioning') || globalPerms.includes('admin'),
              };
            } else {
              verifiedPerms = {
                browse: true,
                executeAnalysis: true,
                administerQualityGates: true,
                provisioning: true,
              };
            }
          }
        } catch {
          // Keep scan permission only if /api/users/current is unavailable
        }
      }

      const majorVer = version ? Number.parseInt(version.split('.')[0], 10) : 26;
      const apiCompatibility: SonarInstanceRecord['apiCompatibility'] =
        majorVer >= 10 ? 'WEB_API_V2_AND_V1' : 'WEB_API_V1_LEGACY';

      return {
        connectionState: authenticated ? 'READY' : 'CONNECTED',
        httpReachable: true,
        authenticated,
        version,
        edition: options.mode === 'CLOUD' ? 'MqrBridge Cloud' : 'Community Build',
        systemStatus,
        apiCompatibility,
        permissions: verifiedPerms,
        tokenExpiresAt,
        latencyMs,
        errorMessage: authenticated
          ? null
          : 'Servidor UP, mas nenhum token Bearer válido foi autenticado para execução de análises.',
      };
    } catch (err: unknown) {
      const latencyMs = Math.round((performance.now() - start) * 10) / 10;
      const errMsg = err instanceof Error ? err.message : 'Falha de conexão';
      if (errMsg.startsWith('SSRF_REDIRECT_BLOCKED')) {
        return {
          connectionState: 'SERVER_UNAVAILABLE',
          httpReachable: false,
          authenticated: false,
          version: null,
          edition: null,
          systemStatus: 'REDIRECT_BLOCKED',
          apiCompatibility: 'UNKNOWN',
          permissions: {
            browse: false,
            executeAnalysis: false,
            administerQualityGates: false,
            provisioning: false,
          },
          tokenExpiresAt: null,
          latencyMs,
          errorMessage: errMsg,
        };
      }
      if (errMsg.startsWith('SSRF_BLOCKED')) {
        return {
          connectionState: 'SERVER_UNAVAILABLE',
          httpReachable: false,
          authenticated: false,
          version: null,
          edition: null,
          systemStatus: 'SSRF_BLOCKED',
          apiCompatibility: 'UNKNOWN',
          permissions: {
            browse: false,
            executeAnalysis: false,
            administerQualityGates: false,
            provisioning: false,
          },
          tokenExpiresAt: null,
          latencyMs,
          errorMessage: errMsg,
        };
      }
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
          ? `Nenhum servidor MqrBridge em execução em ${rawUrl} (${errMsg || 'ECONNREFUSED'}). O servidor não é iniciado automaticamente nem simulado.`
          : `Servidor MqrBridge remoto inacessível em ${rawUrl}: ${errMsg || 'Falha de conexão'}.`,
      };
    }
  }
}
