import crypto from 'node:crypto';

export type WinHoodAccessMode = 'SOLO_LOCAL_DESKTOP' | 'LOCKED_VAULT' | 'TEAM_SERVER';

export interface SoloLocalPolicyCheck {
  allowed: boolean;
  mode: WinHoodAccessMode;
  reason: string;
}

export function evaluateSoloLocalAutoSession(params: {
  runtimeEnv: string | undefined;
  remoteAddress: string | undefined;
  hostHeader?: string;
  isHostedPreview?: boolean;
  nodeEnv?: string;
  vaultLockEnabled: boolean;
  teamServerMode: boolean;
}): SoloLocalPolicyCheck {
  if (params.teamServerMode) {
    return {
      allowed: false,
      mode: 'TEAM_SERVER',
      reason: 'Modo Servidor de Equipe ativo: autenticação explícita e RBAC são obrigatórios.',
    };
  }
  if (params.vaultLockEnabled) {
    return {
      allowed: false,
      mode: 'LOCKED_VAULT',
      reason: 'Bloqueio de cofre ativado pelo usuário: desbloqueie com Windows Hello, Passkey ou PIN.',
    };
  }

  const isElectron = params.runtimeEnv === 'ELECTRON_DESKTOP';
  const ip = (params.remoteAddress || '').replace(/^::ffff:/, '').trim().toLowerCase();
  const host = (params.hostHeader || '').split(':')[0].trim().toLowerCase();
  const isLoopbackIp = ip === '127.0.0.1' || ip === '::1' || ip === 'localhost';
  const isLoopbackHost = host === 'localhost' || host === '127.0.0.1' || host === '::1';
  const isDevOrPreview =
    params.isHostedPreview === true ||
    process.env.WINHOOD_ALLOW_PREVIEW_SOLO === 'true' ||
    (params.nodeEnv || process.env.NODE_ENV) !== 'production';

  if (isElectron && (isLoopbackIp || isLoopbackHost)) {
    return {
      allowed: true,
      mode: 'SOLO_LOCAL_DESKTOP',
      reason: 'Sessão local autorizada via conta do sistema operacional (loopback Electron).',
    };
  }

  if (isLoopbackIp || isLoopbackHost) {
    return {
      allowed: true,
      mode: 'SOLO_LOCAL_DESKTOP',
      reason: 'Sessão local autorizada em loopback (127.0.0.1 / localhost).',
    };
  }

  if (isDevOrPreview) {
    return {
      allowed: true,
      mode: 'SOLO_LOCAL_DESKTOP',
      reason: 'Sessão local autorizada em ambiente de desenvolvimento/preview.',
    };
  }

  return {
    allowed: false,
    mode: 'TEAM_SERVER',
    reason: 'Acesso remoto em produção exige autenticação explícita (GitHub, Passkey ou Credenciais).',
  };
}

export interface GitHubDeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}

export async function startGitHubDeviceAuth(
  clientId: string,
  scope = 'read:user user:email repo'
): Promise<GitHubDeviceCodeResponse> {
  if (!clientId || clientId.trim().length < 8) {
    throw new Error('GITHUB_CLIENT_ID_MISSING: Configure WINHOOD_GITHUB_OAUTH_CLIENT_ID.');
  }
  const res = await fetch('https://github.com/login/device/code', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ client_id: clientId.trim(), scope }),
  });
  if (!res.ok) {
    throw new Error(`GITHUB_DEVICE_FLOW_HTTP_${res.status}`);
  }
  return (await res.json()) as GitHubDeviceCodeResponse;
}

export interface GitHubDeviceTokenPollResult {
  status: 'AUTHORIZED' | 'PENDING' | 'SLOW_DOWN' | 'EXPIRED' | 'ACCESS_DENIED' | 'ERROR';
  accessToken?: string;
  tokenType?: string;
  scope?: string;
  errorDescription?: string;
}

export async function pollGitHubDeviceToken(
  clientId: string,
  deviceCode: string
): Promise<GitHubDeviceTokenPollResult> {
  if (!clientId || clientId.trim().length < 8) {
    throw new Error('GITHUB_CLIENT_ID_MISSING: Configure WINHOOD_GITHUB_OAUTH_CLIENT_ID.');
  }
  if (!deviceCode || deviceCode.trim().length < 8) {
    throw new Error('GITHUB_DEVICE_CODE_INVALID: Código de dispositivo ausente ou inválido.');
  }
  const res = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: clientId.trim(),
      device_code: deviceCode.trim(),
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    }),
  });
  if (!res.ok) {
    throw new Error(`GITHUB_DEVICE_POLL_HTTP_${res.status}`);
  }
  const data = (await res.json()) as {
    access_token?: string;
    token_type?: string;
    scope?: string;
    error?: string;
    error_description?: string;
  };
  if (data.access_token) {
    return {
      status: 'AUTHORIZED',
      accessToken: data.access_token,
      tokenType: data.token_type || 'bearer',
      scope: data.scope || '',
    };
  }
  switch (data.error) {
    case 'authorization_pending':
      return { status: 'PENDING', errorDescription: data.error_description };
    case 'slow_down':
      return { status: 'SLOW_DOWN', errorDescription: data.error_description };
    case 'expired_token':
      return { status: 'EXPIRED', errorDescription: data.error_description };
    case 'access_denied':
      return { status: 'ACCESS_DENIED', errorDescription: data.error_description };
    default:
      return {
        status: 'ERROR',
        errorDescription: data.error_description || data.error || 'Erro desconhecido no OAuth Device Flow.',
      };
  }
}

export interface GitHubOAuthPkcePair {
  state: string;
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
}

export interface GitHubAuthenticatedProfile {
  id: number;
  login: string;
  name: string;
  email: string;
  avatarUrl: string | null;
}

export function generateGitHubOAuthPkce(): GitHubOAuthPkcePair {
  const state = crypto.randomBytes(32).toString('base64url');
  const codeVerifier = crypto.randomBytes(48).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier, 'ascii')
    .digest('base64url');
  return {
    state,
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256',
  };
}

export function buildGitHubOAuthAuthorizeUrl(params: {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  scope?: string;
}): string {
  const qs = new URLSearchParams({
    client_id: params.clientId.trim(),
    redirect_uri: params.redirectUri,
    scope: params.scope || 'read:user user:email',
    state: params.state,
    code_challenge: params.codeChallenge,
    code_challenge_method: 'S256',
    allow_signup: 'true',
  });
  return `https://github.com/login/oauth/authorize?${qs.toString()}`;
}

export async function exchangeGitHubOAuthCode(params: {
  clientId: string;
  clientSecret: string;
  code: string;
  redirectUri: string;
  codeVerifier: string;
}): Promise<{ accessToken: string; tokenType: string; scope: string }> {
  if (!params.clientId.trim() || !params.clientSecret.trim()) {
    throw new Error(
      'GITHUB_OAUTH_CONFIG_MISSING: Configure WINHOOD_GITHUB_OAUTH_CLIENT_ID e WINHOOD_GITHUB_OAUTH_CLIENT_SECRET.'
    );
  }
  const res = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: params.clientId.trim(),
      client_secret: params.clientSecret.trim(),
      code: params.code.trim(),
      redirect_uri: params.redirectUri,
      code_verifier: params.codeVerifier,
    }),
  });
  if (!res.ok) {
    throw new Error(`GITHUB_OAUTH_EXCHANGE_HTTP_${res.status}`);
  }
  const data = (await res.json()) as {
    access_token?: string;
    token_type?: string;
    scope?: string;
    error?: string;
    error_description?: string;
  };
  if (!data.access_token) {
    throw new Error(
      `GITHUB_OAUTH_EXCHANGE_FAILED: ${data.error_description || data.error || 'Token ausente.'}`
    );
  }
  return {
    accessToken: data.access_token,
    tokenType: data.token_type || 'bearer',
    scope: data.scope || '',
  };
}

export async function fetchGitHubAuthenticatedProfile(
  accessToken: string
): Promise<GitHubAuthenticatedProfile> {
  const headers = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${accessToken.trim()}`,
    'User-Agent': 'WinHood-Benchmarking/4.4.0',
  };
  const userRes = await fetch('https://api.github.com/user', { headers });
  if (userRes.status === 401 || userRes.status === 403) {
    throw new Error(
      'GITHUB_TOKEN_UNAUTHORIZED: Token GitHub rejeitado pela API oficial (HTTP 401/403).'
    );
  }
  if (!userRes.ok) {
    throw new Error(`GITHUB_PROFILE_FETCH_FAILED: HTTP ${userRes.status}`);
  }
  const userJson = (await userRes.json()) as {
    id?: number;
    login?: string;
    name?: string | null;
    email?: string | null;
    avatar_url?: string | null;
  };
  if (!userJson.login || typeof userJson.id !== 'number') {
    throw new Error('GITHUB_PROFILE_INCOMPLETE: API do GitHub não retornou id/login.');
  }

  let resolvedEmail = (userJson.email || '').trim().toLowerCase();
  if (!resolvedEmail) {
    try {
      const emailsRes = await fetch('https://api.github.com/user/emails', { headers });
      if (emailsRes.ok) {
        const emails = (await emailsRes.json()) as Array<{
          email?: string;
          primary?: boolean;
          verified?: boolean;
        }>;
        if (Array.isArray(emails)) {
          const primaryVerified = emails.find((e) => e.primary && e.verified && e.email);
          const anyVerified = emails.find((e) => e.verified && e.email);
          const primaryAny = emails.find((e) => e.primary && e.email);
          resolvedEmail = String(
            primaryVerified?.email || anyVerified?.email || primaryAny?.email || ''
          )
            .trim()
            .toLowerCase();
        }
      }
    } catch {
      // Escopo user:email pode estar ausente em PAT read:user; fallback determinístico abaixo
    }
  }
  if (!resolvedEmail) {
    resolvedEmail = `${userJson.id}+${userJson.login}@users.noreply.github.com`;
  }

  return {
    id: userJson.id,
    login: userJson.login,
    name: (userJson.name || userJson.login).trim(),
    email: resolvedEmail,
    avatarUrl: userJson.avatar_url || null,
  };
}

export const GITHUB_OAUTH_APP_DOCS_URL =
  'https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app';
export const GITHUB_OAUTH_DEVELOPER_SETTINGS_URL = 'https://github.com/settings/developers';

export interface GitHubOAuthAdminConfigStatus {
  connectionStatus: 'ACTIVE' | 'PARTIAL' | 'NOT_CONFIGURED';
  configSource: 'ADMIN_VAULT' | 'ENVIRONMENT' | 'NONE';
  vaultOverrideConfigured: boolean;
  oauthDirectReady: boolean;
  deviceFlowReady: boolean;
  clientIdConfigured: boolean;
  clientSecretConfigured: boolean;
  callbackUrlOverrideConfigured: boolean;
  clientIdPreview: string | null;
  callbackUrlEffective: string;
  requiredScopes: string[];
  pkceMethod: 'S256';
  docsUrl: string;
  githubDeveloperSettingsUrl: string;
  updatedAt: string | null;
  checkedAt: string;
}

export interface GitHubOAuthConnectionVerificationResult {
  verified: boolean;
  status:
    | 'VERIFIED'
    | 'INVALID_CREDENTIALS'
    | 'NOT_CONFIGURED'
    | 'NETWORK_UNREACHABLE'
    | 'API_ERROR';
  httpStatus: number | null;
  githubErrorCode: string | null;
  latencyMs: number;
  endpointTested: string;
  pkceAuthorizeReady: boolean;
  clientIdPreview: string | null;
  message: string;
  checkedAt: string;
}

export function maskOAuthClientIdPreview(rawClientId: string): string | null {
  const clean = rawClientId.trim();
  if (clean.length < 8) return null;
  return `${clean.slice(0, 4)}••••${clean.slice(-4)}`;
}

export function validateOAuthCredentialInput(
  raw: string,
  fieldLabel: string
): { valid: true; value: string } | { valid: false; error: string } {
  const trimmed = raw.trim();
  if (trimmed.length < 8 || trimmed.length > 256) {
    return {
      valid: false,
      error: `${fieldLabel} deve possuir entre 8 e 256 caracteres.`,
    };
  }
  if (/[\s\r\n\0]/.test(trimmed)) {
    return {
      valid: false,
      error: `${fieldLabel} não pode conter espaços ou caracteres de controle.`,
    };
  }
  return { valid: true, value: trimmed };
}

export function inspectGitHubOAuthServerStatus(params?: {
  env?: NodeJS.ProcessEnv;
  callbackUrl?: string;
  overrideCredentials?: {
    clientId?: string | null;
    clientSecret?: string | null;
    updatedAt?: string | null;
  } | null;
}): GitHubOAuthAdminConfigStatus {
  const env = params?.env || process.env;
  const overrideClientId = (params?.overrideCredentials?.clientId || '').trim();
  const overrideClientSecret = (params?.overrideCredentials?.clientSecret || '').trim();
  const envClientId = (env.WINHOOD_GITHUB_OAUTH_CLIENT_ID || '').trim();
  const envClientSecret = (env.WINHOOD_GITHUB_OAUTH_CLIENT_SECRET || '').trim();
  const rawCallbackOverride = (env.WINHOOD_GITHUB_OAUTH_CALLBACK_URL || '').trim();

  const rawClientId = overrideClientId || envClientId;
  const rawClientSecret = overrideClientSecret || envClientSecret;

  const clientIdConfigured = rawClientId.length >= 8;
  const clientSecretConfigured = rawClientSecret.length >= 8;
  const oauthDirectReady = clientIdConfigured && clientSecretConfigured;
  const deviceFlowReady = clientIdConfigured;
  const vaultOverrideConfigured =
    overrideClientId.length >= 8 || overrideClientSecret.length >= 8;

  let configSource: GitHubOAuthAdminConfigStatus['configSource'] = 'NONE';
  if (vaultOverrideConfigured) {
    configSource = 'ADMIN_VAULT';
  } else if (envClientId.length >= 8 || envClientSecret.length >= 8) {
    configSource = 'ENVIRONMENT';
  }

  let connectionStatus: GitHubOAuthAdminConfigStatus['connectionStatus'] = 'NOT_CONFIGURED';
  if (oauthDirectReady) {
    connectionStatus = 'ACTIVE';
  } else if (clientIdConfigured || clientSecretConfigured) {
    connectionStatus = 'PARTIAL';
  }

  return {
    connectionStatus,
    configSource,
    vaultOverrideConfigured,
    oauthDirectReady,
    deviceFlowReady,
    clientIdConfigured,
    clientSecretConfigured,
    callbackUrlOverrideConfigured: rawCallbackOverride.length > 0,
    clientIdPreview: maskOAuthClientIdPreview(rawClientId),
    callbackUrlEffective:
      params?.callbackUrl ||
      rawCallbackOverride ||
      'http://localhost:3000/api/auth/github/oauth/callback',
    requiredScopes: ['read:user', 'user:email'],
    pkceMethod: 'S256',
    docsUrl: GITHUB_OAUTH_APP_DOCS_URL,
    githubDeveloperSettingsUrl: GITHUB_OAUTH_DEVELOPER_SETTINGS_URL,
    updatedAt: vaultOverrideConfigured ? params?.overrideCredentials?.updatedAt || null : null,
    checkedAt: new Date().toISOString(),
  };
}

export async function verifyGitHubOAuthConnection(params: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  fetchImpl?: typeof fetch;
}): Promise<GitHubOAuthConnectionVerificationResult> {
  const endpointTested = 'https://github.com/login/oauth/access_token';
  const checkedAt = new Date().toISOString();
  const cleanClientId = (params.clientId || '').trim();
  const cleanClientSecret = (params.clientSecret || '').trim();

  if (cleanClientId.length < 8 || cleanClientSecret.length < 8) {
    const missing: string[] = [];
    if (cleanClientId.length < 8) missing.push('WINHOOD_GITHUB_OAUTH_CLIENT_ID');
    if (cleanClientSecret.length < 8) missing.push('WINHOOD_GITHUB_OAUTH_CLIENT_SECRET');
    return {
      verified: false,
      status: 'NOT_CONFIGURED',
      httpStatus: null,
      githubErrorCode: 'CREDENTIALS_MISSING',
      latencyMs: 0,
      endpointTested,
      pkceAuthorizeReady: false,
      clientIdPreview: maskOAuthClientIdPreview(cleanClientId),
      message: `Configuração incompleta: informe ${missing.join(' e ')} antes de verificar a conexão.`,
      checkedAt,
    };
  }

  const pkce = generateGitHubOAuthPkce();
  const authorizeUrl = buildGitHubOAuthAuthorizeUrl({
    clientId: cleanClientId,
    redirectUri: params.redirectUri,
    state: pkce.state,
    codeChallenge: pkce.codeChallenge,
  });
  const pkceAuthorizeReady = authorizeUrl.startsWith('https://github.com/login/oauth/authorize?');

  const startedAt = Date.now();
  const fetcher = params.fetchImpl || fetch;
  try {
    const res = await fetcher(endpointTested, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'WinHood-Benchmarking/4.4.0',
      },
      body: new URLSearchParams({
        client_id: cleanClientId,
        client_secret: cleanClientSecret,
        code: 'winhood_oauth_probe_0000000000',
        redirect_uri: params.redirectUri,
      }),
      signal: typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function'
        ? AbortSignal.timeout(10000)
        : undefined,
    });
    const latencyMs = Math.max(1, Date.now() - startedAt);
    const data = (await res.json().catch(() => ({}))) as {
      error?: string;
      error_description?: string;
    };
    const errorCode = typeof data.error === 'string' ? data.error : null;

    if (res.ok && errorCode === 'bad_verification_code') {
      return {
        verified: true,
        status: 'VERIFIED',
        httpStatus: res.status,
        githubErrorCode: errorCode,
        latencyMs,
        endpointTested,
        pkceAuthorizeReady,
        clientIdPreview: maskOAuthClientIdPreview(cleanClientId),
        message:
          'Conexão verificada com o GitHub: Client ID e Client Secret foram autenticados pelo endpoint oficial OAuth 2.0 (PKCE S256 pronto).',
        checkedAt: new Date().toISOString(),
      };
    }

    if (
      errorCode === 'incorrect_client_credentials' ||
      errorCode === 'application_suspended' ||
      res.status === 401 ||
      res.status === 403 ||
      res.status === 404
    ) {
      const detailMessage =
        res.status === 404
          ? 'OAuth App não encontrado no GitHub (HTTP 404). Verifique se WINHOOD_GITHUB_OAUTH_CLIENT_ID corresponde a um OAuth App válido e ativo.'
          : `Credenciais rejeitadas pelo GitHub (${errorCode || `HTTP ${res.status}`}). Revise WINHOOD_GITHUB_OAUTH_CLIENT_ID e WINHOOD_GITHUB_OAUTH_CLIENT_SECRET.`;
      return {
        verified: false,
        status: 'INVALID_CREDENTIALS',
        httpStatus: res.status,
        githubErrorCode: errorCode || `HTTP_${res.status}`,
        latencyMs,
        endpointTested,
        pkceAuthorizeReady,
        clientIdPreview: maskOAuthClientIdPreview(cleanClientId),
        message: detailMessage,
        checkedAt: new Date().toISOString(),
      };
    }

    return {
      verified: false,
      status: 'API_ERROR',
      httpStatus: res.status,
      githubErrorCode: errorCode || `HTTP_${res.status}`,
      latencyMs,
      endpointTested,
      pkceAuthorizeReady,
      clientIdPreview: maskOAuthClientIdPreview(cleanClientId),
      message: `Resposta inesperada do GitHub OAuth (HTTP ${res.status}${errorCode ? ` · ${errorCode}` : ''}).`,
      checkedAt: new Date().toISOString(),
    };
  } catch (err: unknown) {
    const latencyMs = Math.max(1, Date.now() - startedAt);
    const errMsg = err instanceof Error ? err.message : 'Erro de rede ao contatar github.com.';
    return {
      verified: false,
      status: 'NETWORK_UNREACHABLE',
      httpStatus: null,
      githubErrorCode: 'NETWORK_ERROR',
      latencyMs,
      endpointTested,
      pkceAuthorizeReady,
      clientIdPreview: maskOAuthClientIdPreview(cleanClientId),
      message: `Não foi possível alcançar o endpoint oficial do GitHub (${errMsg}).`,
      checkedAt: new Date().toISOString(),
    };
  }
}


