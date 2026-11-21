/**
 * WinHood Shared Auth Types & Error Maps (Browser-Safe)
 *
 * Strictly compatible with both browser (Vite) and Node.js runtimes.
 * Never import Node.js built-ins or server-only security modules here.
 */

export type WinHoodAccessMode = 'SOLO_LOCAL_DESKTOP' | 'LOCKED_VAULT' | 'TEAM_SERVER';

export type GitHubOAuthCallbackErrorCode =
  | 'not_configured'
  | 'access_denied'
  | 'invalid_state'
  | 'expired_state'
  | 'replayed_code'
  | 'signup_disabled'
  | 'account_disabled'
  | 'exchange_failed'
  | 'profile_failed';

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
  signup_disabled:
    'O cadastro de novas contas via GitHub está desabilitado pelo administrador desta instalação. Utilize uma conta já vinculada ou outro método autorizado.',
  account_disabled:
    'Esta conta foi desabilitada pelo administrador. Entre em contato com o responsável pela instalação.',
  exchange_failed:
    'Não foi possível concluir a validação do código de autorização com o GitHub. Tente novamente em instantes.',
  profile_failed:
    'Não foi possível obter os dados de perfil da conta GitHub. Tente novamente em instantes.',
};

export function resolveGitHubOAuthErrorMessage(code: string | null | undefined): string | null {
  if (!code) return null;
  const normalized = code.trim().toLowerCase() as GitHubOAuthCallbackErrorCode;
  if (Object.prototype.hasOwnProperty.call(GITHUB_OAUTH_ERROR_MESSAGES, normalized)) {
    return GITHUB_OAUTH_ERROR_MESSAGES[normalized];
  }
  return 'Não foi possível concluir o login com GitHub. Tente novamente ou utilize outro método disponível.';
}
