import React, { useState } from 'react';
import { KeyRound, Lock, ShieldCheck, XCircle } from 'lucide-react';
import {
  csrfFetch as fetch,
  setGlobalCsrfToken,
  setGlobalSessionToken,
} from '../utils/csrfFetch';
import type { TotpVerifyResponse } from '../shared/authTypes';

export interface TotpUnlockModalProps {
  onUnlocked: (res: TotpVerifyResponse) => void;
}

export const TotpUnlockModal: React.FC<TotpUnlockModalProps> = ({ onUnlocked }) => {
  const [code, setCode] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const submitCode = async (rawValue: string) => {
    const trimmed = rawValue.trim();
    if (!trimmed) {
      setErrorMessage('Informe o código TOTP de 6 dígitos ou um código de recuperação (XXXX-XXXX).');
      return;
    }
    setSubmitting(true);
    setErrorMessage(null);
    try {
      const res = await fetch('/api/totp/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: trimmed }),
      });
      const data = (await res.json().catch(() => ({}))) as TotpVerifyResponse & {
        error?: string;
        message?: string;
      };
      if (!res.ok || !data.ok) {
        setErrorMessage(
          data.message || data.error || 'Código TOTP ou código de recuperação inválido.'
        );
        return;
      }
      if (data.csrfToken) setGlobalCsrfToken(data.csrfToken, false);
      if (data.unlockToken) setGlobalSessionToken(data.unlockToken, false);
      setCode('');
      onUnlocked(data);
    } catch {
      setErrorMessage('Não foi possível conectar ao servidor local para validar o código 2FA.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await submitCode(code);
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="totp-unlock-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4"
    >
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0c1017] p-6 space-y-4 shadow-2xl text-xs"
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#31d6c4]/15 border border-[#31d6c4]/30 flex items-center justify-center shrink-0">
            <Lock className="w-5 h-5 text-[#0e9f8e] dark:text-[#31d6c4]" />
          </div>
          <div>
            <h2
              id="totp-unlock-title"
              className="text-sm font-bold text-slate-900 dark:text-slate-100"
            >
              Sessão Protegida por 2FA (TOTP)
            </h2>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Informe o código do seu autenticador para desbloquear o workspace local.
            </p>
          </div>
        </div>

        {errorMessage && (
          <div
            role="alert"
            className="p-2.5 rounded-lg border border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300 flex items-start gap-2"
          >
            <XCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{errorMessage}</span>
          </div>
        )}

        <div className="space-y-1.5">
          <label
            htmlFor="totp-unlock-code"
            className="block font-semibold text-slate-700 dark:text-slate-200"
          >
            Código TOTP (6 dígitos) ou Código de Recuperação
          </label>
          <input
            id="totp-unlock-code"
            name="one-time-code"
            type="text"
            autoFocus
            autoComplete="one-time-code"
            value={code}
            onChange={(e) => {
              const next = e.target.value.toUpperCase().slice(0, 12);
              setCode(next);
              if (errorMessage) setErrorMessage(null);
            }}
            placeholder="000000 ou XXXX-XXXX"
            className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2.5 font-mono text-center text-base tracking-[0.25em] text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#31d6c4]"
          />
        </div>

        <button
          type="submit"
          disabled={submitting || !code.trim()}
          className="w-full py-2.5 rounded-lg font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors inline-flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
        >
          {submitting ? (
            <span>Verificando...</span>
          ) : (
            <>
              <ShieldCheck className="w-4 h-4" />
              <span>Desbloquear WinHood</span>
            </>
          )}
        </button>

        <div className="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400 pt-1">
          <KeyRound className="w-3.5 h-3.5 text-[#31d6c4] shrink-0" />
          <span>RFC-6238 (30s) · Acesso 100% local, sem login ou cadastro.</span>
        </div>
      </form>
    </div>
  );
};
