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
import { csrfFetch as fetch } from '../utils/csrfFetch';
import QRCode from 'qrcode';

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

type GateMode = 'BOOTSTRAP' | 'LOGIN' | 'REGISTER' | 'MFA' | 'RECOVERY';

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
  const [qrCodeDataUrl, setQrCodeDataUrl] = useState<string | null>(null);

  React.useEffect(() => {
    if (totpSetupInfo?.otpauthUrl) {
      QRCode.toDataURL(totpSetupInfo.otpauthUrl, { width: 180, margin: 2 })
        .then((url) => setQrCodeDataUrl(url))
        .catch(() => setQrCodeDataUrl(null));
    } else {
      setQrCodeDataUrl(null);
    }
  }, [totpSetupInfo]);

  // Login fields
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginTotp, setLoginTotp] = useState('');

  // Register (Cadastro) fields
  const [regName, setRegName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regRole, setRegRole] = useState<'SECURITY_LEAD' | 'QA_ENGINEER' | 'AUDITOR'>('SECURITY_LEAD');
  const [regPassword, setRegPassword] = useState('');
  const [regPasswordConfirm, setRegPasswordConfirm] = useState('');
  const [regEnableMfa, setRegEnableMfa] = useState(false);

  // MFA verification field
  const [mfaCode, setMfaCode] = useState('');

  // Recovery fields
  const [recEmail, setRecEmail] = useState('');
  const [recToken, setRecToken] = useState('');
  const [recNewPassword, setRecNewPassword] = useState('');
  const [recStepRequested, setRecStepRequested] = useState(false);
  const [recHintPath, setRecHintPath] = useState<string | null>(null);

  React.useEffect(() => {
    if (bootstrapRequired && mode !== 'BOOTSTRAP' && mode !== 'REGISTER') {
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
          secret: data.totpSetup.secret || data.totpSetup.secretBase32,
          otpauthUrl: data.totpSetup.otpauthUrl || data.totpSetup.otpauthUri,
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

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setInfoMsg(null);

    if (regName.trim().length < 2) {
      setErrorMsg('Informe seu nome completo (mínimo 2 caracteres).');
      return;
    }
    if (regPassword.length < 10) {
      setErrorMsg('A senha deve possuir no mínimo 10 caracteres.');
      return;
    }
    if (regPassword !== regPasswordConfirm) {
      setErrorMsg('A confirmação de senha não coincide com a senha informada.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: regName.trim(),
          email: regEmail.trim(),
          role: regRole,
          password: regPassword,
          enableMfa: regEnableMfa,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || 'Não foi possível concluir o cadastro.');
        return;
      }
      if (data.totpSetup) {
        setTotpSetupInfo({
          secret: data.totpSetup.secret || data.totpSetup.secretBase32,
          otpauthUrl: data.totpSetup.otpauthUrl || data.totpSetup.otpauthUri,
        });
        setMode('MFA');
        setInfoMsg(
          'Conta criada com sucesso! Registre a chave TOTP abaixo no seu autenticador e informe o código de 6 dígitos para concluir o acesso.'
        );
        return;
      }
      if (data.user) {
        onAuthenticated(data.user);
      } else {
        await onRefreshSession();
      }
    } catch {
      setErrorMsg('Erro de comunicação ao realizar o cadastro.');
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

  const switchModeClean = (nextMode: GateMode) => {
    setErrorMsg(null);
    setInfoMsg(null);
    setMode(nextMode);
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
                {mode === 'REGISTER' && 'Cadastro de Novo Acesso WinHood'}
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

        {/* Mode Switcher Tabs (Login vs Cadastro / Bootstrap) */}
        {mode !== 'MFA' && (
          <div
            role="tablist"
            aria-label="Opções de acesso"
            className="grid grid-cols-2 border-b border-slate-200 dark:border-slate-800 bg-slate-100/70 dark:bg-[#080b10]/60 text-xs font-bold"
          >
            {bootstrapRequired ? (
              <button
                type="button"
                role="tab"
                aria-selected={mode === 'BOOTSTRAP'}
                onClick={() => switchModeClean('BOOTSTRAP')}
                className={`py-2.5 px-4 flex items-center justify-center gap-1.5 border-b-2 transition-colors cursor-pointer ${
                  mode === 'BOOTSTRAP'
                    ? 'border-[#31d6c4] text-[#0e9f8e] dark:text-[#31d6c4] bg-white dark:bg-[#0c1017]'
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>Bootstrap Admin</span>
              </button>
            ) : (
              <button
                type="button"
                role="tab"
                aria-selected={mode === 'LOGIN' || mode === 'RECOVERY'}
                onClick={() => switchModeClean('LOGIN')}
                className={`py-2.5 px-4 flex items-center justify-center gap-1.5 border-b-2 transition-colors cursor-pointer ${
                  mode === 'LOGIN' || mode === 'RECOVERY'
                    ? 'border-[#31d6c4] text-[#0e9f8e] dark:text-[#31d6c4] bg-white dark:bg-[#0c1017]'
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Entrar (Login)</span>
              </button>
            )}

            <button
              type="button"
              role="tab"
              aria-selected={mode === 'REGISTER'}
              onClick={() => switchModeClean('REGISTER')}
              className={`py-2.5 px-4 flex items-center justify-center gap-1.5 border-b-2 transition-colors cursor-pointer ${
                mode === 'REGISTER'
                  ? 'border-[#31d6c4] text-[#0e9f8e] dark:text-[#31d6c4] bg-white dark:bg-[#0c1017]'
                  : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <UserPlus className="w-3.5 h-3.5" />
              <span>Criar Nova Conta</span>
            </button>
          </div>
        )}

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
                <label
                  htmlFor="bs-name-input"
                  className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Nome Completo do Administrador
                </label>
                <input
                  id="bs-name-input"
                  type="text"
                  required
                  value={bsName}
                  onChange={(e) => setBsName(e.target.value)}
                  placeholder="Ex.: Engenheiro Responsável"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label
                  htmlFor="bs-email-input"
                  className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  E-mail Corporativo
                </label>
                <input
                  id="bs-email-input"
                  type="email"
                  required
                  value={bsEmail}
                  onChange={(e) => setBsEmail(e.target.value)}
                  placeholder="admin@organizacao.com"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label
                  htmlFor="bs-password-input"
                  className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Senha Forte (mínimo 10 caracteres)
                </label>
                <input
                  id="bs-password-input"
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
                <label
                  htmlFor="bs-token-input"
                  className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Token Single-Use de Bootstrap
                </label>
                <input
                  id="bs-token-input"
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
                <label
                  htmlFor="login-email-input"
                  className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  E-mail
                </label>
                <input
                  id="login-email-input"
                  type="email"
                  required
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  placeholder="usuario@organizacao.com"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label
                  htmlFor="login-password-input"
                  className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Senha
                </label>
                <input
                  id="login-password-input"
                  type="password"
                  required
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="••••••••••"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label
                  htmlFor="login-totp-input"
                  className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Código TOTP MFA (opcional se não habilitado)
                </label>
                <input
                  id="login-totp-input"
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

              <div className="flex items-center justify-between pt-2 border-t border-slate-200 dark:border-slate-800/80">
                <button
                  type="button"
                  onClick={() => switchModeClean('RECOVERY')}
                  className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 hover:text-[#0e9f8e] dark:hover:text-[#31d6c4] hover:underline cursor-pointer"
                >
                  Esqueci minha senha / Recuperar acesso
                </button>
                <button
                  type="button"
                  onClick={() => switchModeClean('REGISTER')}
                  className="text-[11px] font-bold text-[#0e9f8e] dark:text-[#31d6c4] hover:underline flex items-center gap-1 cursor-pointer"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  <span>Não possui conta? Cadastre-se</span>
                </button>
              </div>
            </form>
          )}

          {mode === 'REGISTER' && (
            <form onSubmit={handleRegisterSubmit} className="space-y-3 text-xs">
              <div>
                <label
                  htmlFor="reg-name-input"
                  className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Nome Completo
                </label>
                <input
                  id="reg-name-input"
                  type="text"
                  required
                  minLength={2}
                  value={regName}
                  onChange={(e) => setRegName(e.target.value)}
                  placeholder="Ex.: Ana Costa"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label
                  htmlFor="reg-email-input"
                  className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  E-mail Corporativo
                </label>
                <input
                  id="reg-email-input"
                  type="email"
                  required
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                  placeholder="ana.costa@organizacao.com"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label
                  htmlFor="reg-role-select"
                  className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Perfil Funcional (RBAC)
                </label>
                <select
                  id="reg-role-select"
                  value={regRole}
                  onChange={(e) =>
                    setRegRole(
                      e.target.value as 'SECURITY_LEAD' | 'QA_ENGINEER' | 'AUDITOR'
                    )
                  }
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                >
                  <option value="SECURITY_LEAD">
                    SECURITY_LEAD — AppSec, SAST, SonarQube, Projetos & Benchmarks
                  </option>
                  <option value="QA_ENGINEER">
                    QA_ENGINEER — Qualidade, Testes, Performance & Projetos
                  </option>
                  <option value="AUDITOR">
                    AUDITOR — Auditoria de Evidências & Relatórios (Somente Leitura)
                  </option>
                </select>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label
                    htmlFor="reg-password-input"
                    className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                  >
                    Senha Forte (mín. 10 caracteres)
                  </label>
                  <input
                    id="reg-password-input"
                    type="password"
                    required
                    minLength={10}
                    value={regPassword}
                    onChange={(e) => setRegPassword(e.target.value)}
                    placeholder="Mínimo 10 caracteres"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                  />
                </div>

                <div>
                  <label
                    htmlFor="reg-password-confirm-input"
                    className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                  >
                    Confirmar Senha
                  </label>
                  <input
                    id="reg-password-confirm-input"
                    type="password"
                    required
                    minLength={10}
                    value={regPasswordConfirm}
                    onChange={(e) => setRegPasswordConfirm(e.target.value)}
                    placeholder="Repita a senha"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                  />
                </div>
              </div>

              <label className="flex items-center gap-2 text-slate-700 dark:text-slate-300 cursor-pointer pt-1">
                <input
                  type="checkbox"
                  checked={regEnableMfa}
                  onChange={(e) => setRegEnableMfa(e.target.checked)}
                  className="rounded border-slate-400"
                />
                <span>Ativar autenticação multifator (TOTP MFA) na minha conta</span>
              </label>

              <button
                type="submit"
                disabled={submitting}
                className="w-full py-2.5 rounded-lg font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                <UserPlus className="w-4 h-4" />
                <span>
                  {submitting ? 'Cadastrando conta...' : 'Criar Conta & Acessar WinHood'}
                </span>
              </button>

              {!bootstrapRequired && (
                <div className="flex items-center justify-end pt-2 border-t border-slate-200 dark:border-slate-800/80">
                  <button
                    type="button"
                    onClick={() => switchModeClean('LOGIN')}
                    className="text-[11px] font-bold text-[#0e9f8e] dark:text-[#31d6c4] hover:underline cursor-pointer"
                  >
                    Já possui uma conta? Fazer login
                  </button>
                </div>
              )}
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
                <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-2 text-[11px] text-center">
                  <div className="font-bold text-slate-800 dark:text-slate-200">
                    Escaneie o QR Code no seu Aplicativo Autenticador (Google Authenticator, Authy):
                  </div>
                  {qrCodeDataUrl ? (
                    <div className="flex justify-center p-2 bg-white rounded shadow-inner">
                      <img src={qrCodeDataUrl} alt="QR Code TOTP MFA" className="w-36 h-36 object-contain" />
                    </div>
                  ) : (
                    <div className="text-slate-400">Gerando QR Code criptográfico...</div>
                  )}
                  <div className="text-left space-y-1 pt-1">
                    <div className="text-slate-500 font-semibold">Chave Base32 (Configuração Manual):</div>
                    <div className="font-mono text-[#0e9f8e] dark:text-[#31d6c4] break-all select-all p-1 bg-slate-100 dark:bg-slate-900 rounded">
                      {totpSetupInfo.secret}
                    </div>
                  </div>
                </div>
              )}

              <div>
                <label
                  htmlFor="mfa-code-input"
                  className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Código TOTP (6 dígitos)
                </label>
                <input
                  id="mfa-code-input"
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
                      onClick={() => switchModeClean('LOGIN')}
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
                      onClick={() => switchModeClean('LOGIN')}
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
