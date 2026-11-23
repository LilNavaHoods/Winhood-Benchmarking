/**
 * WinHood Shared Auth Types & Error Maps (Browser-Safe)
 *
 * Strictly compatible with both browser (Vite) and Node.js runtimes.
 * Never import Node.js built-ins or server-only security modules here.
 */

export type WinHoodAccessMode = 'SOLO_LOCAL_DESKTOP' | 'LOCKED_VAULT' | 'TEAM_SERVER';

export type GitHubOAuthAvailabilityState = 'LOADING' | 'CONFIGURED' | 'NOT_CONFIGURED' | 'ERROR';

export type GitHubOAuthCallbackErrorCode =
  | 'not_configured'
  | 'access_denied'
  | 'invalid_state'
  | 'expired_state'
  | 'replayed_code'
  | 'invalid_redirect'
  | 'signup_disabled'
  | 'account_disabled'
  | 'email_unverified'
  | 'github_already_linked'
  | 'exchange_failed'
  | 'profile_failed'
  | 'rate_limited'
  | 'oauth_error';

export const GITHUB_OAUTH_ERROR_MESSAGES: Record<GitHubOAuthCallbackErrorCode, string> = {
  not_configured:
    'Login com GitHub indisponível. O administrador ainda não configurou a autenticação GitHub para esta instalação. Tente novamente mais tarde ou utilize outro método de autenticação disponível.',
  access_denied:
    'Autorização GitHub cancelada ou recusada. Nenhuma alteração foi feita na sua conta.',
  invalid_state:
    'Solicitação de autenticação GitHub inválida ou expirada (verificação de segurança state). Tente entrar novamente.',
  expired_state:
    'O tempo limite de autenticação com o GitHub expirou. Clique em "Entrar ou cadastrar com GitHub" para iniciar novamente.',
  replayed_code:
    'Este código de autorização GitHub já foi utilizado. Inicie uma nova autenticação.',
  invalid_redirect:
    'A URL de retorno (callback) configurada para o GitHub OAuth é inválida. Contate o administrador.',
  signup_disabled:
    'O cadastro de novas contas via GitHub está desabilitado pelo administrador desta instalação. Utilize uma conta já vinculada ou outro método autorizado.',
  account_disabled:
    'Esta conta foi desabilitada pelo administrador. Entre em contato com o responsável pela instalação.',
  email_unverified:
    'Não foi possível vincular automaticamente sua conta GitHub porque o endereço de e-mail não está verificado no GitHub. Verifique seu e-mail no GitHub ou vincule sua conta nas Configurações após autenticar.',
  github_already_linked:
    'Esta conta GitHub já está vinculada a outro usuário nesta instalação.',
  exchange_failed:
    'Não foi possível concluir a validação do código de autorização com o GitHub. Tente novamente em instantes.',
  profile_failed:
    'Não foi possível obter os dados de perfil da conta GitHub. Tente novamente em instantes.',
  rate_limited:
    'Muitas tentativas de login com GitHub em sequência. Aguarde alguns segundos e tente novamente.',
  oauth_error:
    'Não foi possível concluir o login com GitHub. Tente novamente ou utilize outro método disponível.',
};

export const GITHUB_OAUTH_START_URL = '/api/auth/github/oauth/start?mode=redirect' as const;

export const GITHUB_OAUTH_UNAVAILABLE_NOTICE = {
  title: 'Login com GitHub indisponível',
  description:
    'O administrador ainda não configurou a autenticação GitHub para esta instalação.',
  guidance:
    'Tente novamente mais tarde ou utilize outro método de autenticação disponível.',
} as const;

export interface GitHubOAuthCallbackFeedback {
  code: string;
  kind: 'unavailable' | 'warning' | 'error';
  title: string;
  message: string;
}

const GITHUB_OAUTH_FEEDBACK_TITLES: Record<GitHubOAuthCallbackErrorCode, string> = {
  not_configured: GITHUB_OAUTH_UNAVAILABLE_NOTICE.title,
  access_denied: 'Autorização GitHub cancelada',
  invalid_state: 'Sessão de autenticação inválida',
  expired_state: 'Tempo de autenticação expirado',
  replayed_code: 'Código de autorização já utilizado',
  invalid_redirect: 'URL de retorno inválida',
  signup_disabled: 'Cadastro via GitHub desabilitado',
  account_disabled: 'Conta desabilitada',
  email_unverified: 'E-mail não verificado no GitHub',
  github_already_linked: 'Conta GitHub já vinculada',
  exchange_failed: 'Falha ao validar login no GitHub',
  profile_failed: 'Falha ao consultar perfil no GitHub',
  rate_limited: 'Muitas tentativas em sequência',
  oauth_error: 'Erro na autenticação GitHub',
};

export function resolveGitHubOAuthCallbackFeedback(
  code: string | null | undefined
): GitHubOAuthCallbackFeedback | null {
  if (!code) return null;
  const normalized = code.trim().toLowerCase();
  if (!normalized) return null;
  const known = Object.prototype.hasOwnProperty.call(GITHUB_OAUTH_ERROR_MESSAGES, normalized);
  const typedCode = (known ? normalized : 'oauth_error') as GitHubOAuthCallbackErrorCode;
  const kind: GitHubOAuthCallbackFeedback['kind'] =
    typedCode === 'not_configured'
      ? 'unavailable'
      : typedCode === 'signup_disabled' ||
          typedCode === 'access_denied' ||
          typedCode === 'rate_limited'
        ? 'warning'
        : 'error';
  return {
    code: normalized,
    kind,
    title: GITHUB_OAUTH_FEEDBACK_TITLES[typedCode],
    message: GITHUB_OAUTH_ERROR_MESSAGES[typedCode],
  };
}

export function resolveGitHubOAuthErrorMessage(code: string | null | undefined): string | null {
  if (!code) return null;
  const normalized = code.trim().toLowerCase() as GitHubOAuthCallbackErrorCode;
  if (Object.prototype.hasOwnProperty.call(GITHUB_OAUTH_ERROR_MESSAGES, normalized)) {
    return GITHUB_OAUTH_ERROR_MESSAGES[normalized];
  }
  return 'Não foi possível concluir o login com GitHub. Tente novamente ou utilize outro método disponível.';
}

export interface ParsedGitHubOAuthSearchError {
  errorCode: string | null;
  isNotConfigured: boolean;
  message: string | null;
  cleanedSearch: string;
}

export function extractGitHubOAuthErrorFromSearch(search: string): ParsedGitHubOAuthSearchError {
  const params = new URLSearchParams(search || '');
  const rawCode = params.get('github_oauth_error');
  if (!rawCode) {
    return {
      errorCode: null,
      isNotConfigured: false,
      message: null,
      cleanedSearch: search || '',
    };
  }
  const normalized = rawCode.trim().toLowerCase();
  params.delete('github_oauth_error');
  const nextQuery = params.toString();
  return {
    errorCode: normalized,
    isNotConfigured: normalized === 'not_configured',
    message: resolveGitHubOAuthErrorMessage(normalized),
    cleanedSearch: nextQuery ? `?${nextQuery}` : '',
  };
}

export function resolveGitHubOAuthCtaLabel(params: {
  redirecting: boolean;
  signupAllowed?: boolean;
}): string {
  if (params.redirecting) {
    return 'Redirecionando ao GitHub...';
  }
  return params.signupAllowed === false ? 'Entrar com GitHub' : 'Entrar ou cadastrar com GitHub';
}
