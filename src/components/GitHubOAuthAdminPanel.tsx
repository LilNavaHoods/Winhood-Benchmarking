import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  ExternalLink,
  Eye,
  EyeOff,
  Github,
  KeyRound,
  Lock,
  PlugZap,
  RefreshCw,
  Save,
  Trash2,
  XCircle,
} from 'lucide-react';

export interface GitHubOAuthAdminStatusView {
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

export interface GitHubOAuthVerificationView {
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

export interface GitHubOAuthAdminPanelProps {
  status: GitHubOAuthAdminStatusView | null;
  loading: boolean;
  saving: boolean;
  verifying: boolean;
  clearing: boolean;
  error: string | null;
  verificationResult: GitHubOAuthVerificationView | null;
  copiedCallbackUrl: boolean;
  onRefresh: () => void;
  onCopyCallbackUrl: () => void;
  onSaveCredentials: (payload: {
    clientId?: string;
    clientSecret?: string;
  }) => Promise<boolean>;
  onVerifyConnection: (payload: {
    clientId?: string;
    clientSecret?: string;
  }) => Promise<void>;
  onClearCredentials: () => Promise<void>;
}

const DEFAULT_DOCS_URL =
  'https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app';
const DEFAULT_DEV_SETTINGS_URL = 'https://github.com/settings/developers';

const FOCUS_RING =
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#31d6c4] focus-visible:ring-offset-1 focus-visible:ring-offset-white dark:focus-visible:ring-offset-[#0f141c]';

export const GitHubOAuthAdminPanel: React.FC<GitHubOAuthAdminPanelProps> = ({
  status,
  loading,
  saving,
  verifying,
  clearing,
  error,
  verificationResult,
  copiedCallbackUrl,
  onRefresh,
  onCopyCallbackUrl,
  onSaveCredentials,
  onVerifyConnection,
  onClearCredentials,
}) => {
  const [clientIdInput, setClientIdInput] = useState<string>('');
  const [clientSecretInput, setClientSecretInput] = useState<string>('');
  const [showClientId, setShowClientId] = useState<boolean>(false);
  const [showClientSecret, setShowClientSecret] = useState<boolean>(false);
  const [localValidationError, setLocalValidationError] = useState<string | null>(null);

  const trimmedClientId = clientIdInput.trim();
  const trimmedClientSecret = clientSecretInput.trim();
  const hasDraftInput = trimmedClientId.length > 0 || trimmedClientSecret.length > 0;
  const busy = loading || saving || verifying || clearing;

  const handleSubmitCredentials = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLocalValidationError(null);

    if (!hasDraftInput) {
      setLocalValidationError(
        'Informe WINHOOD_GITHUB_OAUTH_CLIENT_ID e/ou WINHOOD_GITHUB_OAUTH_CLIENT_SECRET para salvar.'
      );
      return;
    }
    if (trimmedClientId.length > 0 && trimmedClientId.length < 8) {
      setLocalValidationError(
        'WINHOOD_GITHUB_OAUTH_CLIENT_ID deve possuir ao menos 8 caracteres.'
      );
      return;
    }
    if (trimmedClientSecret.length > 0 && trimmedClientSecret.length < 8) {
      setLocalValidationError(
        'WINHOOD_GITHUB_OAUTH_CLIENT_SECRET deve possuir ao menos 8 caracteres.'
      );
      return;
    }

    const ok = await onSaveCredentials({
      ...(trimmedClientId ? { clientId: trimmedClientId } : {}),
      ...(trimmedClientSecret ? { clientSecret: trimmedClientSecret } : {}),
    });
    if (ok) {
      setClientIdInput('');
      setClientSecretInput('');
      setShowClientId(false);
      setShowClientSecret(false);
    }
  };

  const handleVerifyClick = async () => {
    setLocalValidationError(null);
    await onVerifyConnection({
      ...(trimmedClientId ? { clientId: trimmedClientId } : {}),
      ...(trimmedClientSecret ? { clientSecret: trimmedClientSecret } : {}),
    });
  };

  const sourceBadgeLabel =
    status?.configSource === 'ADMIN_VAULT'
      ? 'Cofre Cifrado (Admin)'
      : status?.configSource === 'ENVIRONMENT'
        ? 'Variável de Ambiente'
        : 'Sem Credenciais';

  const verificationBannerTone = !verificationResult
    ? ''
    : verificationResult.status === 'VERIFIED'
      ? 'border-emerald-500/40 bg-emerald-50 dark:bg-emerald-950/35 text-emerald-950 dark:text-emerald-200'
      : verificationResult.status === 'NOT_CONFIGURED'
        ? 'border-amber-500/40 bg-amber-50 dark:bg-amber-950/35 text-amber-950 dark:text-amber-200'
        : 'border-rose-500/40 bg-rose-50 dark:bg-rose-950/35 text-rose-950 dark:text-rose-200';

  return (
    <section
      aria-label="Configuração e Status do GitHub OAuth 2.0"
      className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4"
    >
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <Github className="w-4 h-4 text-[#0d9488] dark:text-[#31d6c4]" aria-hidden="true" />
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
              GitHub OAuth 2.0 — Conexão e Credenciais do Servidor
            </h2>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 border border-slate-300 dark:border-slate-700">
              ADMIN ONLY
            </span>
            {status && (
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-slate-100 dark:bg-slate-800/80 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700">
                Origem: {sourceBadgeLabel}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-600 dark:text-slate-400">
            Configure, atualize no cofre AES-256-GCM e verifique em tempo real as credenciais{' '}
            <code className="font-mono">WINHOOD_GITHUB_OAUTH_CLIENT_ID</code> e{' '}
            <code className="font-mono">WINHOOD_GITHUB_OAUTH_CLIENT_SECRET</code> no backend (Authorization Code + PKCE S256).
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {loading ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700">
              <RefreshCw className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
              <span>Verificando...</span>
            </span>
          ) : status?.connectionStatus === 'ACTIVE' ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-bold bg-emerald-500/15 text-emerald-800 dark:text-emerald-300 border border-emerald-500/30">
              <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
              <span>CONECTADO · ATIVO (PKCE S256)</span>
            </span>
          ) : status?.connectionStatus === 'PARTIAL' ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-bold bg-amber-500/15 text-amber-800 dark:text-amber-300 border border-amber-500/30">
              <AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" />
              <span>PARCIAL · APENAS DEVICE FLOW</span>
            </span>
          ) : status ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-bold bg-rose-500/15 text-rose-800 dark:text-rose-300 border border-rose-500/30">
              <XCircle className="w-3.5 h-3.5" aria-hidden="true" />
              <span>NÃO CONFIGURADO</span>
            </span>
          ) : null}

          <button
            type="button"
            disabled={busy}
            onClick={onRefresh}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:border-[#31d6c4] transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
          >
            <RefreshCw
              className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`}
              aria-hidden="true"
            />
            <span>Verificar Status</span>
          </button>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="p-3 rounded-lg border border-rose-500/40 bg-rose-50 dark:bg-rose-950/40 text-xs text-rose-900 dark:text-rose-200 flex items-center gap-2"
        >
          <XCircle className="w-4 h-4 shrink-0" aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}

      {status && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono font-bold text-slate-900 dark:text-slate-100">
                WINHOOD_GITHUB_OAUTH_CLIENT_ID
              </span>
              <span
                className={`px-1.5 py-0.5 rounded font-mono text-[11px] font-bold ${
                  status.clientIdConfigured
                    ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                    : 'bg-rose-500/15 text-rose-700 dark:text-rose-300'
                }`}
              >
                {status.clientIdConfigured ? 'ATIVO' : 'INATIVO'}
              </span>
            </div>
            <p className="text-[11px] text-slate-600 dark:text-slate-400 font-mono">
              {status.clientIdPreview
                ? `Prévia: ${status.clientIdPreview}`
                : 'Credencial ausente ou inferior a 8 caracteres.'}
            </p>
          </div>

          <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono font-bold text-slate-900 dark:text-slate-100">
                WINHOOD_GITHUB_OAUTH_CLIENT_SECRET
              </span>
              <span
                className={`px-1.5 py-0.5 rounded font-mono text-[11px] font-bold ${
                  status.clientSecretConfigured
                    ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                    : 'bg-rose-500/15 text-rose-700 dark:text-rose-300'
                }`}
              >
                {status.clientSecretConfigured ? 'ATIVO' : 'INATIVO'}
              </span>
            </div>
            <p className="text-[11px] text-slate-600 dark:text-slate-400">
              {status.clientSecretConfigured
                ? 'Segredo protegido exclusivamente no backend (cifrado em repouso, nunca exposto na API).'
                : 'Necessário no backend para trocar o código OAuth 2.0 PKCE.'}
            </p>
          </div>

          <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                <KeyRound className="w-3.5 h-3.5 text-[#0d9488] dark:text-[#31d6c4]" aria-hidden="true" />
                <span>Authorization Callback URL</span>
              </span>
              <button
                type="button"
                onClick={onCopyCallbackUrl}
                aria-label="Copiar Callback URL do GitHub OAuth"
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] text-[11px] font-medium text-slate-700 dark:text-slate-200 hover:border-[#31d6c4] cursor-pointer ${FOCUS_RING}`}
              >
                <Copy className="w-3 h-3" aria-hidden="true" />
                <span>{copiedCallbackUrl ? 'Copiado' : 'Copiar'}</span>
              </button>
            </div>
            <p className="text-[11px] font-mono text-slate-700 dark:text-slate-300 break-all">
              {status.callbackUrlEffective}
            </p>
            <p className="text-[10px] font-mono text-slate-500 dark:text-slate-400 break-all">
              Homepage URL:{' '}
              {(() => {
                try {
                  return new URL(status.callbackUrlEffective).origin;
                } catch {
                  return typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';
                }
              })()}
            </p>
          </div>
        </div>
      )}

      {/* Dedicated Admin Configuration Form */}
      <form
        onSubmit={handleSubmitCredentials}
        aria-label="Formulário de configuração GitHub OAuth 2.0"
        className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] p-4 space-y-4"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-[#0d9488] dark:text-[#31d6c4]" aria-hidden="true" />
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
              Configurar Credenciais do GitHub OAuth App
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-600 dark:text-slate-400">
            Campos mascarados · Cifragem AES-256-GCM no cofre do servidor
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label
              htmlFor="winhood-admin-github-client-id"
              className="block text-xs font-mono font-bold text-slate-800 dark:text-slate-200"
            >
              WINHOOD_GITHUB_OAUTH_CLIENT_ID
            </label>
            <div className="relative">
              <input
                id="winhood-admin-github-client-id"
                name="githubOAuthClientId"
                type={showClientId ? 'text' : 'password'}
                value={clientIdInput}
                onChange={(e) => {
                  setClientIdInput(e.target.value);
                  if (localValidationError) setLocalValidationError(null);
                }}
                autoComplete="off"
                spellCheck={false}
                placeholder={
                  status?.clientIdPreview
                    ? `Atual: ${status.clientIdPreview} (digite para atualizar)`
                    : 'Ex.: Ov23li... (mínimo 8 caracteres)'
                }
                disabled={busy}
                className={`w-full pr-10 px-3 py-2 rounded-lg text-xs font-mono border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] text-slate-900 dark:text-slate-100 placeholder:text-slate-500 dark:placeholder:text-slate-400 disabled:opacity-60 ${FOCUS_RING}`}
              />
              <button
                type="button"
                onClick={() => setShowClientId((prev) => !prev)}
                aria-label={
                  showClientId
                    ? 'Ocultar WINHOOD_GITHUB_OAUTH_CLIENT_ID'
                    : 'Mostrar WINHOOD_GITHUB_OAUTH_CLIENT_ID'
                }
                className={`absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white cursor-pointer ${FOCUS_RING}`}
              >
                {showClientId ? (
                  <EyeOff className="w-4 h-4" aria-hidden="true" />
                ) : (
                  <Eye className="w-4 h-4" aria-hidden="true" />
                )}
              </button>
            </div>
            <p className="text-[11px] text-slate-600 dark:text-slate-400">
              Deixe em branco para manter o Client ID atual ao atualizar apenas o Client Secret.
            </p>
          </div>

          <div className="space-y-1.5">
            <label
              htmlFor="winhood-admin-github-client-secret"
              className="block text-xs font-mono font-bold text-slate-800 dark:text-slate-200"
            >
              WINHOOD_GITHUB_OAUTH_CLIENT_SECRET
            </label>
            <div className="relative">
              <input
                id="winhood-admin-github-client-secret"
                name="githubOAuthClientSecret"
                type={showClientSecret ? 'text' : 'password'}
                value={clientSecretInput}
                onChange={(e) => {
                  setClientSecretInput(e.target.value);
                  if (localValidationError) setLocalValidationError(null);
                }}
                autoComplete="new-password"
                spellCheck={false}
                placeholder={
                  status?.clientSecretConfigured
                    ? 'Segredo ativo no servidor (digite para rotacionar)'
                    : 'Cole o Client Secret gerado no GitHub OAuth App'
                }
                disabled={busy}
                className={`w-full pr-10 px-3 py-2 rounded-lg text-xs font-mono border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] text-slate-900 dark:text-slate-100 placeholder:text-slate-500 dark:placeholder:text-slate-400 disabled:opacity-60 ${FOCUS_RING}`}
              />
              <button
                type="button"
                onClick={() => setShowClientSecret((prev) => !prev)}
                aria-label={
                  showClientSecret
                    ? 'Ocultar WINHOOD_GITHUB_OAUTH_CLIENT_SECRET'
                    : 'Mostrar WINHOOD_GITHUB_OAUTH_CLIENT_SECRET'
                }
                className={`absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white cursor-pointer ${FOCUS_RING}`}
              >
                {showClientSecret ? (
                  <EyeOff className="w-4 h-4" aria-hidden="true" />
                ) : (
                  <Eye className="w-4 h-4" aria-hidden="true" />
                )}
              </button>
            </div>
            <p className="text-[11px] text-slate-600 dark:text-slate-400">
              Transmitido via CSRF protegido e selado em repouso. Nunca retornado ao navegador.
            </p>
          </div>
        </div>

        {localValidationError && (
          <div
            role="alert"
            className="p-2.5 rounded-lg border border-rose-500/40 bg-rose-50 dark:bg-rose-950/40 text-xs text-rose-900 dark:text-rose-200 flex items-center gap-2"
          >
            <XCircle className="w-4 h-4 shrink-0" aria-hidden="true" />
            <span>{localValidationError}</span>
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="submit"
              disabled={busy || !hasDraftInput}
              className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${FOCUS_RING}`}
            >
              <Save className="w-3.5 h-3.5" aria-hidden="true" />
              <span>{saving ? 'Salvando no Cofre...' : 'Salvar Credenciais'}</span>
            </button>

            <button
              type="button"
              disabled={busy}
              onClick={handleVerifyClick}
              className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-bold border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] text-slate-900 dark:text-slate-100 hover:border-[#31d6c4] transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
            >
              {verifying ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#0d9488] dark:text-[#31d6c4]" aria-hidden="true" />
              ) : (
                <PlugZap className="w-3.5 h-3.5 text-[#0d9488] dark:text-[#31d6c4]" aria-hidden="true" />
              )}
              <span>{verifying ? 'Verificando Conexão...' : 'Verificar Conexão'}</span>
            </button>

            {status?.vaultOverrideConfigured && (
              <button
                type="button"
                disabled={busy}
                onClick={() => void onClearCredentials()}
                className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border border-rose-500/40 bg-rose-50 dark:bg-rose-950/30 text-rose-800 dark:text-rose-200 hover:bg-rose-100 dark:hover:bg-rose-950/60 transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
              >
                <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                <span>{clearing ? 'Removendo...' : 'Limpar Credenciais Salvas'}</span>
              </button>
            )}
          </div>

          {status?.updatedAt && (
            <span className="text-[11px] font-mono text-slate-600 dark:text-slate-400">
              Atualizado em: {new Date(status.updatedAt).toLocaleString()}
            </span>
          )}
        </div>

        <div aria-live="polite" className="min-h-0">
          {verificationResult && (
            <div
              className={`p-3 rounded-lg border text-xs space-y-1.5 ${verificationBannerTone}`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 font-bold">
                  {verificationResult.status === 'VERIFIED' ? (
                    <CheckCircle2 className="w-4 h-4 shrink-0" aria-hidden="true" />
                  ) : verificationResult.status === 'NOT_CONFIGURED' ? (
                    <AlertTriangle className="w-4 h-4 shrink-0" aria-hidden="true" />
                  ) : (
                    <XCircle className="w-4 h-4 shrink-0" aria-hidden="true" />
                  )}
                  <span>
                    Teste de Conexão GitHub OAuth:{' '}
                    <code className="font-mono">{verificationResult.status}</code>
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
                  {verificationResult.httpStatus !== null && (
                    <span>HTTP {verificationResult.httpStatus}</span>
                  )}
                  {verificationResult.githubErrorCode && (
                    <span>GitHub: {verificationResult.githubErrorCode}</span>
                  )}
                  <span>{verificationResult.latencyMs} ms</span>
                </div>
              </div>
              <p className="leading-relaxed">{verificationResult.message}</p>
            </div>
          )}
        </div>
      </form>

      <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
        <p className="text-xs text-slate-600 dark:text-slate-400">
          Escopos solicitados: <code className="font-mono">read:user user:email</code> · Configuração única pelo administrador: usuários finais entram clicando diretamente em &quot;Entrar ou cadastrar com GitHub&quot;, sem PAT ou Client ID manual.
        </p>

        <div className="flex flex-wrap items-center gap-2">
          <a
            href={status?.docsUrl || DEFAULT_DOCS_URL}
            target="_blank"
            rel="noopener noreferrer"
            className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors ${FOCUS_RING}`}
          >
            <span>Documentação: Criar OAuth App no GitHub</span>
            <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
          </a>

          <a
            href={status?.githubDeveloperSettingsUrl || DEFAULT_DEV_SETTINGS_URL}
            target="_blank"
            rel="noopener noreferrer"
            className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:border-[#31d6c4] transition-colors ${FOCUS_RING}`}
          >
            <span>GitHub Developer Settings</span>
            <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
          </a>
        </div>
      </div>
    </section>
  );
};
