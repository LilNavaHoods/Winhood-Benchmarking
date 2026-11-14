import React, { useState } from 'react';
import {
  AlertTriangle,
  KeyRound,
  Lock,
  LogOut,
  ShieldCheck,
  UserPlus,
} from 'lucide-react';
import { WinHoodLogo } from './WinHoodLogo';

export interface AuthUserView {
  id: string;
  name: string;
  email: string;
  role: 'ADMIN' | 'SECURITY_LEAD' | 'AUDITOR' | 'QA_ENGINEER';
  mfaEnabled: boolean;
  mfaVerified: boolean;
}

interface AuthGateModalProps {
  bootstrapRequired: boolean;
  bootstrapTokenFileHint: string;
  mfaRequired: boolean;
  pendingUser: AuthUserView | null;
  onAuthenticated: (user: AuthUserView) => void;
  onRefreshSession: () => Promise<void>;
}

type GateMode = 'BOOTSTRAP' | 'LOGIN' | 'MFA' | 'RECOVERY';

export const AuthGateModal: React.FC<AuthGateModalProps> = ({
  bootstrapRequired,
  bootstrapTokenFileHint,
  mfaRequired,
  pendingUser,
  onAuthenticated,
  onRefreshSession,
}) => {
  const initialMode: GateMode = bootstrapRequired
    ? 'BOOTSTRAP'
    : mfaRequired
      ? 'MFA'
      : 'LOGIN';

  const [mode, setMode] = useState<GateMode>(initialMode);
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [infoMsg, setInfoMsg] = useState<string | null>(null);

  // Bootstrap fields
  const [bsName, setBsName] = useState('');
  const [bsEmail, setBsEmail] = useState('');
  const [bsPassword, setBsPassword] = useState('');
  const [bsToken, setBsToken] = useState('');
  const [bsEnableMfa, setBsEnableMfa] = useState(false);
  const [totpSetupInfo, setTotpSetupInfo] = useState<{
    secret: string;
    otpauthUrl: string;
  } | null>(null);

  // Login fields
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginTotp, setLoginTotp] = useState('');

  // MFA verification field
  const [mfaCode, setMfaCode] = useState('');

  // Recovery fields
  const [recEmail, setRecEmail] = useState('');
  const [recToken, setRecToken] = useState('');
  const [recNewPassword, setRecNewPassword] = useState('');
  const [recStepRequested, setRecStepRequested] = useState(false);
  const [recHintPath, setRecHintPath] = useState<string | null>(null);

  React.useEffect(() => {
    if (bootstrapRequired && mode !== 'BOOTSTRAP') {
      setMode('BOOTSTRAP');
    } else if (!bootstrapRequired && mfaRequired && mode !== 'MFA') {
      setMode('MFA');
    } else if (!bootstrapRequired && !mfaRequired && mode === 'BOOTSTRAP') {
      setMode('LOGIN');
    }
  }, [bootstrapRequired, mfaRequired, mode]);

  const handleBootstrapSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setInfoMsg(null);
    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/bootstrap-admin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: bsName.trim(),
          email: bsEmail.trim(),
          password: bsPassword,
          bootstrapToken: bsToken.trim(),
          enableMfa: bsEnableMfa,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || 'Falha no provisionamento do administrador.');
        return;
      }
      if (data.totpSetup) {
        setTotpSetupInfo({
          secret: data.totpSetup.secret,
          otpauthUrl: data.totpSetup.otpauthUrl,
        });
        setMode('MFA');
        setInfoMsg(
          'Administrador criado! Registre a chave TOTP abaixo no seu autenticador e informe o código de 6 dígitos.'
        );
        return;
      }
      if (data.user) {
        onAuthenticated(data.user);
      } else {
        await onRefreshSession();
      }
    } catch {
      setErrorMsg('Erro de comunicação ao executar bootstrap inicial.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setInfoMsg(null);
    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: loginEmail.trim(),
          password: loginPassword,
          totpCode: loginTotp.trim() || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || 'Credenciais inválidas ou conta bloqueada.');
        return;
      }
      if (data.mfaRequired) {
        setMode('MFA');
        setInfoMsg('Informe o código TOTP de 6 dígitos do seu aplicativo autenticador.');
        return;
      }
      if (data.user) {
        onAuthenticated(data.user);
      } else {
        await onRefreshSession();
      }
    } catch {
      setErrorMsg('Erro de comunicação ao autenticar.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleVerifyMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ totpCode: mfaCode.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || 'Código TOTP inválido ou expirado.');
        return;
      }
      if (data.user) {
        onAuthenticated(data.user);
      } else {
        await onRefreshSession();
      }
    } catch {
      setErrorMsg('Erro ao verificar token MFA.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancelMfaLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    setTotpSetupInfo(null);
    setMode('LOGIN');
    await onRefreshSession();
  };

  const handleRequestRecovery = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setInfoMsg(null);
    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/recovery/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: recEmail.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || 'Erro ao solicitar recuperação.');
        return;
      }
      setRecStepRequested(true);
      setRecHintPath(data.recoveryChannelHint || null);
      setInfoMsg(
        data.message ||
          'Token temporário emitido no canal local seguro (.winhood_data).'
      );
    } catch {
      setErrorMsg('Erro ao solicitar recuperação de senha.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleConfirmRecovery = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/recovery/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: recEmail.trim(),
          recoveryToken: recToken.trim(),
          newPassword: recNewPassword,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || 'Token inválido ou nova senha fraca.');
        return;
      }
      setMode('LOGIN');
      setRecStepRequested(false);
      setRecToken('');
      setRecNewPassword('');
      setInfoMsg('Senha redefinida com sucesso. Faça login com a nova senha.');
    } catch {
      setErrorMsg('Erro ao confirmar redefinição de senha.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="winhood-auth-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/85 backdrop-blur-sm p-4"
    >
      <div className="w-full max-w-lg rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0c1017] shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-[#080b10]">
          <div className="flex items-center gap-3">
            <WinHoodLogo size={36} className="shrink-0" />
            <div>
              <h2
                id="winhood-auth-title"
                className="text-base font-bold text-slate-900 dark:text-slate-100"
              >
                {mode === 'BOOTSTRAP' && 'Provisionamento Inicial do Administrador'}
                {mode === 'LOGIN' && 'Autenticação WinHood Platform'}
                {mode === 'MFA' && 'Verificação em Duas Etapas (TOTP MFA)'}
                {mode === 'RECOVERY' && 'Recuperação Segura de Senha'}
              </h2>
              <p className="text-[11px] font-mono text-[#0e9f8e] dark:text-[#31d6c4]">
                Sessão HttpOnly · CSRF Double-Submit · Scrypt + RBAC
              </p>
            </div>
          </div>
          <Lock className="w-5 h-5 text-[#31d6c4]" />
        </div>

        {/* Body */}
        <div className="p-6 space-y-4">
          {errorMsg && (
            <div
              role="alert"
              className="p-3 rounded-lg border border-rose-500/40 bg-rose-500/10 text-xs text-rose-600 dark:text-rose-300 flex items-start gap-2"
            >
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{errorMsg}</span>
            </div>
          )}

          {infoMsg && (
            <div className="p-3 rounded-lg border border-[#31d6c4]/40 bg-[#31d6c4]/10 text-xs text-emerald-700 dark:text-[#31d6c4] flex items-start gap-2">
              <ShieldCheck className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{infoMsg}</span>
            </div>
          )}

          {mode === 'BOOTSTRAP' && (
            <form onSubmit={handleBootstrapSubmit} className="space-y-3.5 text-xs">
              <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300 space-y-1">
                <div className="font-bold flex items-center gap-1.5">
                  <KeyRound className="w-3.5 h-3.5" />
                  <span>Nenhum administrador provisionado neste ambiente</span>
                </div>
                <p className="text-[11px]">
                  Leia o token CSPRNG de uso único gerado no arquivo local:{' '}
                  <code className="font-mono font-bold underline">
                    {bootstrapTokenFileHint || '.winhood_data/bootstrap_admin_token.txt'}
                  </code>
                </p>
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Nome Completo do Administrador
                </label>
                <input
                  type="text"
                  required
                  value={bsName}
                  onChange={(e) => setBsName(e.target.value)}
                  placeholder="Ex.: Engenheiro Responsável"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  E-mail Corporativo
                </label>
                <input
                  type="email"
                  required
                  value={bsEmail}
                  onChange={(e) => setBsEmail(e.target.value)}
                  placeholder="admin@organizacao.com"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Senha Forte (mínimo 10 caracteres)
                </label>
                <input
                  type="password"
                  required
                  minLength={10}
                  value={bsPassword}
                  onChange={(e) => setBsPassword(e.target.value)}
                  placeholder="Mínimo 10 caracteres"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Token Single-Use de Bootstrap
                </label>
                <input
                  type="text"
                  required
                  value={bsToken}
                  onChange={(e) => setBsToken(e.target.value)}
                  placeholder="Cole o token de bootstrap_admin_token.txt"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 font-mono text-slate-900 dark:text-slate-100"
                />
              </div>

              <label className="flex items-center gap-2 text-slate-700 dark:text-slate-300 cursor-pointer pt-1">
                <input
                  type="checkbox"
                  checked={bsEnableMfa}
                  onChange={(e) => setBsEnableMfa(e.target.checked)}
                  className="rounded border-slate-400"
                />
                <span>Ativar autenticação multifator (TOTP MFA) imediatamente</span>
              </label>

              <button
                type="submit"
                disabled={submitting}
                className="w-full py-2.5 rounded-lg font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                <UserPlus className="w-4 h-4" />
                <span>
                  {submitting ? 'Provisionando...' : 'Criar Conta ADMIN & Iniciar Sessão'}
                </span>
              </button>
            </form>
          )}

          {mode === 'LOGIN' && (
            <form onSubmit={handleLoginSubmit} className="space-y-3.5 text-xs">
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  E-mail
                </label>
                <input
                  type="email"
                  required
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  placeholder="usuario@organizacao.com"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Senha
                </label>
                <input
                  type="password"
                  required
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="••••••••••"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Código TOTP MFA (opcional se não habilitado)
                </label>
                <input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={loginTotp}
                  onChange={(e) => setLoginTotp(e.target.value)}
                  placeholder="000000"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 font-mono text-slate-900 dark:text-slate-100"
                />
              </div>

              <button
                type="submit"
                disabled={submitting}
                className="w-full py-2.5 rounded-lg font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-50"
              >
                {submitting ? 'Autenticando...' : 'Entrar no WinHood'}
              </button>

              <div className="flex items-center justify-between pt-1">
                <button
                  type="button"
                  onClick={() => {
                    setErrorMsg(null);
                    setInfoMsg(null);
                    setMode('RECOVERY');
                  }}
                  className="text-[11px] font-semibold text-[#0e9f8e] dark:text-[#31d6c4] hover:underline cursor-pointer"
                >
                  Esqueci minha senha / Recuperar acesso
                </button>
              </div>
            </form>
          )}

          {mode === 'MFA' && (
            <form onSubmit={handleVerifyMfaSubmit} className="space-y-4 text-xs">
              {pendingUser && (
                <div className="p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] font-mono text-[11px]">
                  Sessão pendente para: <strong>{pendingUser.email}</strong> ({pendingUser.role})
                </div>
              )}

              {totpSetupInfo && (
                <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-1.5 text-[11px]">
                  <div className="font-bold text-slate-800 dark:text-slate-200">
                    Segredo Base32 para Autenticador (RFC-6238):
                  </div>
                  <div className="font-mono text-[#0e9f8e] dark:text-[#31d6c4] break-all select-all">
                    {totpSetupInfo.secret}
                  </div>
                  <div className="font-mono text-[10px] text-slate-500 break-all">
                    {totpSetupInfo.otpauthUrl}
                  </div>
                </div>
              )}

              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Código TOTP (6 dígitos)
                </label>
                <input
                  type="text"
                  required
                  inputMode="numeric"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  placeholder="123456"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 font-mono text-base tracking-widest text-center text-slate-900 dark:text-slate-100"
                />
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="submit"
                  disabled={submitting}
                  className="flex-1 py-2.5 rounded-lg font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-50"
                >
                  {submitting ? 'Validando...' : 'Validar MFA & Acessar'}
                </button>
                <button
                  type="button"
                  onClick={handleCancelMfaLogout}
                  className="px-3 py-2.5 rounded-lg font-semibold border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:border-rose-400 flex items-center gap-1 cursor-pointer"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Sair</span>
                </button>
              </div>
            </form>
          )}

          {mode === 'RECOVERY' && (
            <div className="space-y-4 text-xs">
              {!recStepRequested ? (
                <form onSubmit={handleRequestRecovery} className="space-y-3">
                  <p className="text-slate-600 dark:text-slate-400">
                    Informe seu e-mail cadastrado. Um token temporário de uso único será gravado no canal local seguro (<code className="font-mono">.winhood_data</code>).
                  </p>
                  <input
                    type="email"
                    required
                    value={recEmail}
                    onChange={(e) => setRecEmail(e.target.value)}
                    placeholder="usuario@organizacao.com"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                  />
                  <div className="flex items-center gap-2">
                    <button
                      type="submit"
                      disabled={submitting}
                      className="flex-1 py-2.5 rounded-lg font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] cursor-pointer disabled:opacity-50"
                    >
                      Emitir Token de Recuperação
                    </button>
                    <button
                      type="button"
                      onClick={() => setMode('LOGIN')}
                      className="px-3 py-2.5 rounded-lg font-semibold border border-slate-300 dark:border-slate-700 cursor-pointer"
                    >
                      Voltar
                    </button>
                  </div>
                </form>
              ) : (
                <form onSubmit={handleConfirmRecovery} className="space-y-3">
                  {recHintPath && (
                    <div className="p-2.5 rounded border border-amber-500/30 bg-amber-500/10 font-mono text-[11px] text-amber-600 dark:text-amber-300">
                      Arquivo local de recuperação: {recHintPath}
                    </div>
                  )}
                  <input
                    type="text"
                    required
                    value={recToken}
                    onChange={(e) => setRecToken(e.target.value)}
                    placeholder="Token de recuperação de uso único"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 font-mono text-slate-900 dark:text-slate-100"
                  />
                  <input
                    type="password"
                    required
                    minLength={10}
                    value={recNewPassword}
                    onChange={(e) => setRecNewPassword(e.target.value)}
                    placeholder="Nova senha forte (mín. 10 caracteres)"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                  />
                  <div className="flex items-center gap-2">
                    <button
                      type="submit"
                      disabled={submitting}
                      className="flex-1 py-2.5 rounded-lg font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] cursor-pointer disabled:opacity-50"
                    >
                      Confirmar Redefinição de Senha
                    </button>
                    <button
                      type="button"
                      onClick={() => setMode('LOGIN')}
                      className="px-3 py-2.5 rounded-lg font-semibold border border-slate-300 dark:border-slate-700 cursor-pointer"
                    >
                      Cancelar
                    </button>
                  </div>
                </form>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
