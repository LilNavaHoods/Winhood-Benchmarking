import React, { useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronUp,
  Clock,
  Copy,
  Download,
  Eye,
  EyeOff,
  Fingerprint,
  Hash,
  KeyRound,
  Lock,
  LogOut,
  ShieldCheck,
  UserPlus,
} from 'lucide-react';
import { WinHoodLogo } from './WinHoodLogo';
import { HairlineAnimatedFigure } from './HairlineAnimatedFigure';
import { PrivacyAndTermsModal } from './PrivacyAndTermsModal';
import {
  clearClientAuthTokens,
  csrfFetch as fetch,
  setGlobalCsrfToken,
  setGlobalSessionToken,
} from '../utils/csrfFetch';
import QRCode from 'qrcode';

export interface AuthUserView {
  id: string;
  name: string;
  email: string;
  role: 'ADMIN' | 'SECURITY_LEAD' | 'AUDITOR' | 'QA_ENGINEER';
  mfaEnabled: boolean;
  mfaVerified: boolean;
  pinEnabled?: boolean;
  webauthnEnabled?: boolean;
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
type RegisterAuthMethod = 'PASSWORD' | 'PIN' | 'WEBAUTHN';
type LoginAuthMethod = 'PASSWORD' | 'PIN';

function base64UrlToUint8Array(base64Url: string): Uint8Array<ArrayBuffer> {
  const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(new ArrayBuffer(rawData.length));
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function evaluatePinClientStatus(pin: string): { valid: boolean; reason: string } {
  const clean = pin.trim();
  if (clean.length < 6 || clean.length > 8 || !/^\d{6,8}$/.test(clean)) {
    return { valid: false, reason: 'Digite de 6 a 8 dígitos numéricos' };
  }
  if (/^(\d)\1+$/.test(clean)) {
    return { valid: false, reason: 'Dígitos repetidos (ex.: 111111) não são permitidos' };
  }
  let asc = true;
  let desc = true;
  for (let i = 1; i < clean.length; i++) {
    const prev = clean.charCodeAt(i - 1) - 48;
    const curr = clean.charCodeAt(i) - 48;
    if (curr - prev !== 1) asc = false;
    if (prev - curr !== 1) desc = false;
  }
  if (asc || desc) {
    return { valid: false, reason: 'Sequências simples (ex.: 123456) não são permitidas' };
  }
  return { valid: true, reason: 'PIN forte válido (Scrypt N=16384)' };
}

interface PasswordStrengthReport {
  level: 0 | 1 | 2 | 3 | 4;
  label: string;
  barColor: string;
  textColor: string;
  checks: {
    minLength: boolean;
    mixedCase: boolean;
    hasDigit: boolean;
    hasSymbol: boolean;
  };
}

function evaluatePasswordStrength(password: string): PasswordStrengthReport {
  const checks = {
    minLength: password.length >= 10,
    mixedCase: /[a-z]/.test(password) && /[A-Z]/.test(password),
    hasDigit: /\d/.test(password),
    hasSymbol: /[^a-zA-Z0-9\s]/.test(password),
  };

  if (!password) {
    return {
      level: 0,
      label: 'Aguardando senha (mín. 10 caracteres)',
      barColor: 'bg-slate-300 dark:bg-slate-700',
      textColor: 'text-slate-500',
      checks,
    };
  }

  let score = 0;
  if (checks.minLength) score += 1;
  if (checks.mixedCase) score += 1;
  if (checks.hasDigit) score += 1;
  if (checks.hasSymbol) score += 1;
  if (password.length >= 14 && score >= 3) score += 1;

  if (!checks.minLength || score <= 1) {
    return {
      level: 1,
      label: 'Fraca',
      barColor: 'bg-rose-500',
      textColor: 'text-rose-500',
      checks,
    };
  }
  if (score === 2) {
    return {
      level: 2,
      label: 'Razoável',
      barColor: 'bg-amber-500',
      textColor: 'text-amber-500',
      checks,
    };
  }
  if (score === 3 || score === 4) {
    return {
      level: 3,
      label: 'Forte',
      barColor: 'bg-emerald-500',
      textColor: 'text-emerald-500',
      checks,
    };
  }
  return {
    level: 4,
    label: 'Excelente — Pronta para Cofre AES-256',
    barColor: 'bg-[#31d6c4]',
    textColor: 'text-[#0e9f8e] dark:text-[#31d6c4]',
    checks,
  };
}

export const AuthGateModal: React.FC<AuthGateModalProps> = ({
  bootstrapRequired,
  bootstrapTokenFileHint,
  mfaRequired,
  pendingUser,
  onAuthenticated,
  onRefreshSession,
}) => {
  const initialMode: GateMode = mfaRequired
    ? 'MFA'
    : bootstrapRequired
      ? 'REGISTER'
      : 'LOGIN';

  const [mode, setMode] = useState<GateMode>(initialMode);
  const [submitting, setSubmitting] = useState(false);
  const submittingRef = useRef(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [infoMsg, setInfoMsg] = useState<string | null>(null);
  const [isPrivacyModalOpen, setIsPrivacyModalOpen] = useState(false);
  const [webAuthnIframeFallback, setWebAuthnIframeFallback] = useState<'register' | 'login' | null>(
    null
  );

  const isRunningInIframe = (): boolean => {
    if (typeof window === 'undefined') return false;
    try {
      return window.self !== window.top;
    } catch {
      return true;
    }
  };

  const ensureWebAuthnEnvironmentReady = (): boolean => {
    if (typeof window === 'undefined') return false;

    if (window.location.hostname === '127.0.0.1' && !isRunningInIframe()) {
      const targetPort = window.location.port ? `:${window.location.port}` : ':3000';
      const targetUrl = `http://localhost${targetPort}${window.location.pathname}${window.location.search}`;
      setInfoMsg(
        `O Windows Hello exige o hostname válido "localhost" (não aceita IP literal 127.0.0.1). Redirecionando para ${targetUrl}...`
      );
      window.location.assign(targetUrl);
      return false;
    }

    return true;
  };

  // Bootstrap fields
  const [bsName, setBsName] = useState('');
  const [bsEmail, setBsEmail] = useState('');
  const [bsPassword, setBsPassword] = useState('');
  const [showBsPassword, setShowBsPassword] = useState(false);
  const [bsToken, setBsToken] = useState('');
  const [bsEnableMfa, setBsEnableMfa] = useState(false);
  const [totpSetupInfo, setTotpSetupInfo] = useState<{
    secret: string;
    otpauthUrl: string;
    recoveryCodes?: string[];
  } | null>(null);
  const [qrCodeDataUrl, setQrCodeDataUrl] = useState<string | null>(null);
  const [copiedRecovery, setCopiedRecovery] = useState(false);

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
  const [loginMethod, setLoginMethod] = useState<LoginAuthMethod>('PASSWORD');
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginPin, setLoginPin] = useState('');
  const [showLoginPassword, setShowLoginPassword] = useState(false);
  const [trustDevice, setTrustDevice] = useState(true);

  // Streamlined Register (Cadastro) + Method Selector (Senha, PIN 6-8, Win Hello)
  const [regMethod, setRegMethod] = useState<RegisterAuthMethod>('PASSWORD');
  const [regName, setRegName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regPin, setRegPin] = useState('');
  const [showRegPassword, setShowRegPassword] = useState(false);
  const [showAdvancedRegister, setShowAdvancedRegister] = useState(false);
  const [regRole, setRegRole] = useState<'SECURITY_LEAD' | 'QA_ENGINEER' | 'AUDITOR'>(
    'SECURITY_LEAD'
  );
  const [regEnableMfa, setRegEnableMfa] = useState(false);

  // MFA verification state & two-step preAuth challenge
  const [mfaCode, setMfaCode] = useState('');
  const [preAuthToken, setPreAuthToken] = useState<string | null>(null);
  const [serverTimeIso, setServerTimeIso] = useState<string | null>(null);
  const [useRecoveryMode, setUseRecoveryMode] = useState(false);
  const [recoveryBackupCode, setRecoveryBackupCode] = useState('');

  // Recovery fields
  const [recEmail, setRecEmail] = useState('');
  const [recToken, setRecToken] = useState('');
  const [recNewPassword, setRecNewPassword] = useState('');
  const [showRecPassword, setShowRecPassword] = useState(false);
  const [recStepRequested, setRecStepRequested] = useState(false);
  const [recHintPath, setRecHintPath] = useState<string | null>(null);

  const regStrength = useMemo(() => evaluatePasswordStrength(regPassword), [regPassword]);
  const regPinStatus = useMemo(() => evaluatePinClientStatus(regPin), [regPin]);

  const clockDriftSeconds = useMemo(() => {
    if (!serverTimeIso) return 0;
    const parsed = Date.parse(serverTimeIso);
    if (!Number.isFinite(parsed)) return 0;
    return Math.round(Math.abs(Date.now() - parsed) / 1000);
  }, [serverTimeIso]);

  React.useEffect(() => {
    if (mfaRequired && mode !== 'MFA') {
      setMode('MFA');
    } else if (!bootstrapRequired && !mfaRequired && mode === 'BOOTSTRAP') {
      setMode('LOGIN');
    }
  }, [bootstrapRequired, mfaRequired, mode]);

  const handleBootstrapSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setInfoMsg(null);
    setWebAuthnIframeFallback(null);
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
      if (data.sessionId) {
        setGlobalSessionToken(data.sessionId, trustDevice);
      }
      if (data.csrfToken) {
        setGlobalCsrfToken(data.csrfToken, trustDevice);
      }
      if (data.totpSetup) {
        setTotpSetupInfo({
          secret: data.totpSetup.secret || data.totpSetup.secretBase32,
          otpauthUrl: data.totpSetup.otpauthUrl || data.totpSetup.otpauthUri,
          recoveryCodes: data.totpSetup.recoveryCodes || [],
        });
        setPreAuthToken(null);
        setMode('MFA');
        setInfoMsg(
          'Administrador criado! Escaneie o QR Code, salve os códigos de recuperação e informe o token de 6 dígitos.'
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

  const tryNativeWindowsHelloRegister = async (): Promise<
    { ok: true } | { ok: false; osUnsupported: boolean; errorMessage: string }
  > => {
    try {
      const nativeRes = await fetch('/api/auth/windows-hello/native-register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: regName.trim(),
          email: regEmail.trim(),
          role: regRole,
          trustDevice,
        }),
      });
      const nativeData = await nativeRes.json();
      if (!nativeRes.ok) {
        return {
          ok: false,
          osUnsupported:
            nativeRes.status === 501 || nativeData?.code === 'WINDOWS_HELLO_OS_UNSUPPORTED',
          errorMessage: nativeData?.error || 'Falha na verificação nativa do Windows Hello.',
        };
      }
      if (nativeData.sessionId) {
        setGlobalSessionToken(nativeData.sessionId, trustDevice);
      }
      if (nativeData.csrfToken) {
        setGlobalCsrfToken(nativeData.csrfToken, trustDevice);
      }
      if (nativeData.user) {
        onAuthenticated(nativeData.user);
      } else {
        await onRefreshSession();
      }
      return { ok: true };
    } catch {
      return {
        ok: false,
        osUnsupported: false,
        errorMessage: 'Erro de comunicação ao acionar o Windows Hello nativo no servidor local.',
      };
    }
  };

  const tryNativeWindowsHelloLogin = async (): Promise<
    { ok: true } | { ok: false; osUnsupported: boolean; errorMessage: string }
  > => {
    try {
      const nativeRes = await fetch('/api/auth/windows-hello/native-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: loginEmail.trim() || undefined,
          trustDevice,
        }),
      });
      const nativeData = await nativeRes.json();
      if (!nativeRes.ok) {
        return {
          ok: false,
          osUnsupported:
            nativeRes.status === 501 || nativeData?.code === 'WINDOWS_HELLO_OS_UNSUPPORTED',
          errorMessage: nativeData?.error || 'Falha na autenticação nativa do Windows Hello.',
        };
      }
      if (nativeData.sessionId) {
        setGlobalSessionToken(nativeData.sessionId, trustDevice);
      }
      if (nativeData.csrfToken) {
        setGlobalCsrfToken(nativeData.csrfToken, trustDevice);
      }
      if (nativeData.requiresTotp || nativeData.mfaRequired) {
        setPreAuthToken(nativeData.preAuthToken || null);
        setServerTimeIso(nativeData.serverTimeIso || null);
        setMfaCode('');
        setRecoveryBackupCode('');
        setUseRecoveryMode(false);
        setMode('MFA');
        setInfoMsg('Informe o código TOTP de 6 dígitos do seu aplicativo autenticador.');
        return { ok: true };
      }
      if (nativeData.user) {
        onAuthenticated(nativeData.user);
      } else {
        await onRefreshSession();
      }
      return { ok: true };
    } catch {
      return {
        ok: false,
        osUnsupported: false,
        errorMessage: 'Erro de comunicação ao autenticar com Windows Hello nativo.',
      };
    }
  };

  const handleWebAuthnRegister = async () => {
    setErrorMsg(null);
    setInfoMsg(null);
    setWebAuthnIframeFallback(null);

    if (regName.trim().length < 2) {
      setErrorMsg('Informe seu nome de exibição (mínimo 2 caracteres).');
      return;
    }
    if (!regEmail.trim()) {
      setErrorMsg('Informe um endereço de e-mail válido.');
      return;
    }
    if (!ensureWebAuthnEnvironmentReady()) {
      return;
    }

    setSubmitting(true);
    try {
      if (!window.PublicKeyCredential || !navigator.credentials) {
        const nativeFallback = await tryNativeWindowsHelloRegister();
        if (nativeFallback.ok) return;
        if (nativeFallback.osUnsupported && isRunningInIframe()) {
          setWebAuthnIframeFallback('register');
        }
        setErrorMsg(
          nativeFallback.osUnsupported
            ? 'O preview do navegador bloqueia biometria em iframe sem allow="publickey-credentials-create" e este servidor remoto executa em container Linux.'
            : nativeFallback.errorMessage
        );
        return;
      }

      const optRes = await fetch('/api/auth/webauthn/register-account/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: regName.trim(),
          email: regEmail.trim(),
          role: regRole,
          rpId: window.location.hostname,
        }),
      });
      const optData = await optRes.json();
      if (!optRes.ok) {
        setErrorMsg(optData.error || 'Falha ao iniciar registro com Windows Hello.');
        return;
      }

      const publicKeyOptions: PublicKeyCredentialCreationOptions = {
        rp: {
          name: optData.rp?.name || 'WinHood Benchmark Analyzer',
          id: optData.rp?.id || window.location.hostname,
        },
        user: {
          id: base64UrlToUint8Array(optData.user.id),
          name: optData.user.name,
          displayName: optData.user.displayName,
        },
        challenge: base64UrlToUint8Array(optData.challenge),
        pubKeyCredParams: optData.pubKeyCredParams,
        timeout: optData.timeout || 60000,
        attestation: optData.attestation || 'none',
        authenticatorSelection: optData.authenticatorSelection,
      };

      const cred = (await navigator.credentials.create({
        publicKey: publicKeyOptions,
      })) as PublicKeyCredential | null;

      if (!cred) {
        setErrorMsg('Operação Windows Hello cancelada pelo usuário.');
        return;
      }

      const attResp = cred.response as AuthenticatorAttestationResponse & {
        getAuthenticatorData?: () => ArrayBuffer;
        getPublicKey?: () => ArrayBuffer | null;
        getPublicKeyAlgorithm?: () => number;
        getTransports?: () => string[];
      };

      const pubKeyDer =
        typeof attResp.getPublicKey === 'function' ? attResp.getPublicKey() : null;
      const authDataBuf =
        typeof attResp.getAuthenticatorData === 'function'
          ? attResp.getAuthenticatorData()
          : null;

      const verifyRes = await fetch('/api/auth/webauthn/register-account/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: optData.challengeId,
          credentialId: arrayBufferToBase64Url(cred.rawId),
          clientDataJSON: arrayBufferToBase64Url(attResp.clientDataJSON),
          attestationObject: arrayBufferToBase64Url(attResp.attestationObject),
          authenticatorData: authDataBuf ? arrayBufferToBase64Url(authDataBuf) : undefined,
          publicKeySpkiBase64: pubKeyDer ? arrayBufferToBase64Url(pubKeyDer) : undefined,
          coseAlgorithm:
            typeof attResp.getPublicKeyAlgorithm === 'function'
              ? attResp.getPublicKeyAlgorithm()
              : -7,
          transports:
            typeof attResp.getTransports === 'function' ? attResp.getTransports() : ['internal'],
          trustDevice,
        }),
      });
      const verifyData = await verifyRes.json();
      if (!verifyRes.ok) {
        setErrorMsg(verifyData.error || 'Falha ao validar credencial Windows Hello.');
        return;
      }
      if (verifyData.sessionId) {
        setGlobalSessionToken(verifyData.sessionId, trustDevice);
      }
      if (verifyData.csrfToken) {
        setGlobalCsrfToken(verifyData.csrfToken, trustDevice);
      }
      if (verifyData.user) {
        onAuthenticated(verifyData.user);
      } else {
        await onRefreshSession();
      }
    } catch (err: any) {
      if (err?.name === 'NotAllowedError' || err?.name === 'SecurityError') {
        const nativeFallback = await tryNativeWindowsHelloRegister();
        if (nativeFallback.ok) {
          return;
        }
        if (nativeFallback.osUnsupported && isRunningInIframe()) {
          setWebAuthnIframeFallback('register');
          setErrorMsg(
            'O preview do navegador bloqueia biometria (WebAuthn) dentro de iframe sem allow="publickey-credentials-create". Use o botão abaixo para concluir com PIN Rápido em 1 clique ou execute localmente em http://localhost:3000 / aplicativo .exe.'
          );
          return;
        }
        if (!nativeFallback.osUnsupported) {
          setErrorMsg(nativeFallback.errorMessage);
          return;
        }
      }
      if (err?.name === 'NotAllowedError') {
        setErrorMsg(
          'Operação do Windows Hello cancelada na janela do Windows ou tempo esgotado.'
        );
      } else {
        setErrorMsg(err?.message || 'Não foi possível concluir o cadastro com Windows Hello.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleWebAuthnLogin = async () => {
    setErrorMsg(null);
    setInfoMsg(null);
    setWebAuthnIframeFallback(null);

    if (!ensureWebAuthnEnvironmentReady()) {
      return;
    }

    setSubmitting(true);
    try {
      if (!window.PublicKeyCredential || !navigator.credentials) {
        const nativeFallback = await tryNativeWindowsHelloLogin();
        if (nativeFallback.ok) return;
        if (nativeFallback.osUnsupported && isRunningInIframe()) {
          setWebAuthnIframeFallback('login');
        }
        setErrorMsg(
          nativeFallback.osUnsupported
            ? 'O preview do navegador bloqueia biometria em iframe sem allow="publickey-credentials-get" e este servidor remoto executa em container Linux.'
            : nativeFallback.errorMessage
        );
        return;
      }

      const optRes = await fetch('/api/auth/webauthn/login/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: loginEmail.trim() || undefined,
          rpId: window.location.hostname,
        }),
      });
      const optData = await optRes.json();
      if (!optRes.ok) {
        setErrorMsg(optData.error || 'Falha ao iniciar autenticação com Windows Hello.');
        return;
      }

      const allowCredentials: PublicKeyCredentialDescriptor[] = Array.isArray(
        optData.allowCredentials
      )
        ? optData.allowCredentials.map((c: { id: string; transports?: AuthenticatorTransport[] }) => ({
            type: 'public-key' as const,
            id: base64UrlToUint8Array(c.id),
            transports: c.transports,
          }))
        : [];

      const assertion = (await navigator.credentials.get({
        publicKey: {
          challenge: base64UrlToUint8Array(optData.challenge),
          rpId: optData.rpId || window.location.hostname,
          timeout: optData.timeout || 60000,
          userVerification: 'required',
          ...(allowCredentials.length > 0 ? { allowCredentials } : {}),
        },
      })) as PublicKeyCredential | null;

      if (!assertion) {
        setErrorMsg('Autenticação Windows Hello cancelada.');
        return;
      }

      const assertResp = assertion.response as AuthenticatorAssertionResponse;
      const verifyRes = await fetch('/api/auth/webauthn/login/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: optData.challengeId,
          credentialId: arrayBufferToBase64Url(assertion.rawId),
          clientDataJSON: arrayBufferToBase64Url(assertResp.clientDataJSON),
          authenticatorData: arrayBufferToBase64Url(assertResp.authenticatorData),
          signature: arrayBufferToBase64Url(assertResp.signature),
          email: loginEmail.trim() || undefined,
          trustDevice,
        }),
      });
      const data = await verifyRes.json();
      if (!verifyRes.ok) {
        setErrorMsg(data.error || 'Falha na verificação do Windows Hello.');
        return;
      }
      if (data.sessionId) {
        setGlobalSessionToken(data.sessionId, trustDevice);
      }
      if (data.csrfToken) {
        setGlobalCsrfToken(data.csrfToken, trustDevice);
      }
      if (data.requiresTotp || data.mfaRequired) {
        setPreAuthToken(data.preAuthToken || null);
        setServerTimeIso(data.serverTimeIso || null);
        setMfaCode('');
        setRecoveryBackupCode('');
        setUseRecoveryMode(false);
        setMode('MFA');
        setInfoMsg('Informe o código TOTP de 6 dígitos do seu aplicativo autenticador.');
        return;
      }
      if (data.user) {
        onAuthenticated(data.user);
      } else {
        await onRefreshSession();
      }
    } catch (err: any) {
      if (err?.name === 'NotAllowedError' || err?.name === 'SecurityError') {
        const nativeFallback = await tryNativeWindowsHelloLogin();
        if (nativeFallback.ok) {
          return;
        }
        if (nativeFallback.osUnsupported && isRunningInIframe()) {
          setWebAuthnIframeFallback('login');
          setErrorMsg(
            'O preview do navegador bloqueia biometria (WebAuthn) dentro de iframe sem allow="publickey-credentials-get". Use o botão abaixo para entrar com PIN Rápido em 1 clique ou execute localmente em http://localhost:3000 / aplicativo .exe.'
          );
          return;
        }
        if (!nativeFallback.osUnsupported) {
          setErrorMsg(nativeFallback.errorMessage);
          return;
        }
      }
      if (err?.name === 'NotAllowedError') {
        setErrorMsg(
          'Operação do Windows Hello cancelada na janela do Windows ou tempo esgotado.'
        );
      } else {
        setErrorMsg(err?.message || 'Erro ao autenticar com Windows Hello.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setInfoMsg(null);

    if (regMethod === 'WEBAUTHN') {
      await handleWebAuthnRegister();
      return;
    }

    if (regName.trim().length < 2) {
      setErrorMsg('Informe seu nome de exibição (mínimo 2 caracteres).');
      return;
    }

    if (regMethod === 'PIN') {
      if (!regPinStatus.valid) {
        setErrorMsg(regPinStatus.reason);
        return;
      }
    } else if (regPassword.length < 10) {
      setErrorMsg('A senha deve possuir no mínimo 10 caracteres.');
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
          password: regMethod === 'PASSWORD' ? regPassword : '',
          pin: regMethod === 'PIN' ? regPin.trim() : undefined,
          enableMfa: regEnableMfa,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || 'Não foi possível concluir o cadastro.');
        return;
      }
      if (data.sessionId) {
        setGlobalSessionToken(data.sessionId, trustDevice);
      }
      if (data.csrfToken) {
        setGlobalCsrfToken(data.csrfToken, trustDevice);
      }
      if (data.totpSetup) {
        setTotpSetupInfo({
          secret: data.totpSetup.secret || data.totpSetup.secretBase32,
          otpauthUrl: data.totpSetup.otpauthUrl || data.totpSetup.otpauthUri,
          recoveryCodes: data.totpSetup.recoveryCodes || [],
        });
        setPreAuthToken(null);
        setMode('MFA');
        setInfoMsg(
          'Conta criada! Escaneie o QR Code abaixo no seu autenticador, guarde os códigos de backup e digite os 6 dígitos.'
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
      const endpoint = loginMethod === 'PIN' ? '/api/auth/login-pin' : '/api/auth/login';
      const payload =
        loginMethod === 'PIN'
          ? {
              email: loginEmail.trim(),
              pin: loginPin.trim(),
              trustDevice,
            }
          : {
              email: loginEmail.trim(),
              password: loginPassword,
              trustDevice,
            };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || 'Credenciais inválidas ou conta bloqueada.');
        return;
      }
      if (data.sessionId) {
        setGlobalSessionToken(data.sessionId, trustDevice);
      }
      if (data.csrfToken) {
        setGlobalCsrfToken(data.csrfToken, trustDevice);
      }
      if (data.requiresTotp || data.mfaRequired) {
        setPreAuthToken(data.preAuthToken || null);
        setServerTimeIso(data.serverTimeIso || null);
        setMfaCode('');
        setRecoveryBackupCode('');
        setUseRecoveryMode(false);
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

  const submitMfaChallenge = async (overrideCode?: string) => {
    if (submittingRef.current) return;
    const totpClean = (overrideCode ?? mfaCode).replace(/\D/g, '').slice(0, 6);
    const recoveryClean = recoveryBackupCode.trim();

    if (!useRecoveryMode && totpClean.length !== 6) {
      setErrorMsg('Informe os 6 dígitos numéricos do aplicativo autenticador.');
      return;
    }
    if (useRecoveryMode && recoveryClean.replace(/[\s-]/g, '').length < 8) {
      setErrorMsg('Informe o código de recuperação no formato XXXX-XXXX.');
      return;
    }

    submittingRef.current = true;
    setErrorMsg(null);
    setSubmitting(true);
    try {
      const endpoint =
        preAuthToken && !totpSetupInfo
          ? '/api/auth/totp/authenticate'
          : '/api/auth/mfa/verify';

      const payload =
        preAuthToken && !totpSetupInfo
          ? {
              preAuthToken,
              totpCode: useRecoveryMode ? undefined : totpClean,
              recoveryCode: useRecoveryMode ? recoveryClean : undefined,
              trustDevice,
            }
          : {
              totpCode: useRecoveryMode ? '' : totpClean,
              recoveryCode: useRecoveryMode ? recoveryClean : undefined,
              trustDevice,
            };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || 'Código TOTP inválido ou expirado.');
        return;
      }
      if (data.sessionId) {
        setGlobalSessionToken(data.sessionId, trustDevice);
      }
      if (data.csrfToken) {
        setGlobalCsrfToken(data.csrfToken, trustDevice);
      }
      if (data.user) {
        onAuthenticated(data.user);
      } else {
        await onRefreshSession();
      }
    } catch {
      setErrorMsg('Erro ao verificar token MFA.');
    } finally {
      submittingRef.current = false;
      setSubmitting(false);
    }
  };

  const handleVerifyMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await submitMfaChallenge();
  };

  const handleMfaCodeChange = (rawVal: string) => {
    const clean = rawVal.replace(/\D/g, '').slice(0, 6);
    setMfaCode(clean);
    if (clean.length === 6 && !useRecoveryMode) {
      void submitMfaChallenge(clean);
    }
  };

  const handleMfaPaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    const pasted = e.clipboardData.getData('text');
    const digits = pasted.replace(/[\s-]/g, '').replace(/\D/g, '').slice(0, 6);
    if (digits.length > 0) {
      e.preventDefault();
      setMfaCode(digits);
      if (digits.length === 6 && !useRecoveryMode) {
        void submitMfaChallenge(digits);
      }
    }
  };

  const handleCopyRecoveryCodes = async (codes: string[]) => {
    try {
      await navigator.clipboard.writeText(codes.join('\n'));
      setCopiedRecovery(true);
      setTimeout(() => setCopiedRecovery(false), 2500);
    } catch {
      // Clipboard fallback ignored
    }
  };

  const handleDownloadRecoveryCodes = (codes: string[]) => {
    const content = [
      '# WinHood Security Benchmark — Códigos de Recuperação TOTP (Uso Único)',
      `# Gerado em: ${new Date().toISOString()}`,
      '',
      ...codes,
      '',
    ].join('\n');
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'winhood-recovery-codes.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCancelMfaLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    clearClientAuthTokens();
    setTotpSetupInfo(null);
    setPreAuthToken(null);
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
    setWebAuthnIframeFallback(null);
    setMode(nextMode);
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="winhood-auth-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/92 p-4 overflow-y-auto"
    >
      <div className="w-full max-w-lg rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0c1017] shadow-2xl overflow-hidden my-auto">
        {/* Header + 3D Isometric Padlock Showcase */}
        <div className="px-6 pt-5 pb-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
          <div className="flex flex-col items-center justify-center mb-3.5">
            <HairlineAnimatedFigure
              type="padlock"
              variant="hero"
              width={184}
              height={142}
              active={true}
              unlocked={Boolean(infoMsg)}
              typingProgress={Math.min(
                1,
                ((mode === 'REGISTER'
                  ? regPassword.length + regEmail.length + regName.length
                  : mode === 'BOOTSTRAP'
                    ? bsPassword.length + bsEmail.length
                    : loginPassword.length + loginEmail.length) || 0) / 18
              )}
              accentColor={mode === 'REGISTER' ? '#10b981' : '#31d6c4'}
              subtitle={
                infoMsg
                  ? 'COFRE KMS DESBLOQUEADO'
                  : mode === 'REGISTER'
                    ? 'SCRYPT · COFRE AES-256-GCM'
                    : 'KMS · SESSÃO HTTPONLY'
              }
            />
          </div>
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <WinHoodLogo size={36} className="shrink-0" />
              <div>
                <h2
                  id="winhood-auth-title"
                  className="text-base font-bold text-slate-900 dark:text-slate-100"
                >
                  {mode === 'BOOTSTRAP' && 'Provisionamento Inicial do Administrador'}
                  {mode === 'LOGIN' && 'Autenticação WinHood Platform'}
                  {mode === 'REGISTER' && 'Criar Nova Conta WinHood'}
                  {mode === 'MFA' && 'Verificação em Duas Etapas (TOTP MFA)'}
                  {mode === 'RECOVERY' && 'Recuperação Segura de Senha'}
                </h2>
                <p className="text-[11px] font-mono text-[#0e9f8e] dark:text-[#31d6c4]">
                  Sessão HttpOnly · Cofre AES-256-GCM · Scrypt + TOTP RFC 6238
                </p>
              </div>
            </div>
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-[#31d6c4]/30 bg-[#31d6c4]/10 text-[10px] font-mono font-semibold text-[#0e9f8e] dark:text-[#31d6c4] shrink-0">
              <Lock className="w-3.5 h-3.5" />
              <span>whdb:enc:v2</span>
            </div>
          </div>
        </div>

        {/* Mode Switcher Tabs (Entrar vs Criar Conta) */}
        {mode !== 'MFA' && (
          <div
            role="tablist"
            aria-label="Opções de acesso"
            className="grid grid-cols-2 border-b border-slate-200 dark:border-slate-800 bg-slate-100/70 dark:bg-[#080b10]/60 text-xs font-bold"
          >
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'LOGIN' || mode === 'RECOVERY'}
              onClick={() => switchModeClean('LOGIN')}
              className={`py-2.5 px-4 flex items-center justify-center gap-1.5 border-b-2 transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                mode === 'LOGIN' || mode === 'RECOVERY'
                  ? 'border-[#31d6c4] text-[#0e9f8e] dark:text-[#31d6c4] bg-white dark:bg-[#0c1017]'
                  : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Entrar</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={mode === 'REGISTER'}
              onClick={() => switchModeClean('REGISTER')}
              className={`py-2.5 px-4 flex items-center justify-center gap-1.5 border-b-2 transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                mode === 'REGISTER'
                  ? 'border-[#31d6c4] text-[#0e9f8e] dark:text-[#31d6c4] bg-white dark:bg-[#0c1017]'
                  : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <UserPlus className="w-3.5 h-3.5" />
              <span>Criar Conta</span>
            </button>
          </div>
        )}

        {/* Body */}
        <div className="p-6 space-y-4">
          {errorMsg && (
            <div
              role="alert"
              className="p-3 rounded-lg border border-rose-500/40 bg-rose-500/10 text-xs text-rose-600 dark:text-rose-300 space-y-2"
            >
              <div className="flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{errorMsg}</span>
              </div>

              {webAuthnIframeFallback && (
                <div className="pl-6 pt-1 space-y-2">
                  <button
                    type="button"
                    onClick={() => {
                      const flow = webAuthnIframeFallback;
                      setErrorMsg(null);
                      setWebAuthnIframeFallback(null);
                      if (flow === 'register') {
                        setMode('REGISTER');
                        setRegMethod('PIN');
                        setInfoMsg(
                          'Modo PIN Rápido ativado: digite um PIN de 6 a 8 dígitos para concluir o cadastro agora.'
                        );
                      } else {
                        setMode('LOGIN');
                        setLoginMethod('PIN');
                        setInfoMsg(
                          'Modo PIN Rápido ativado: digite seu PIN de 6 a 8 dígitos para entrar.'
                        );
                      }
                    }}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
                  >
                    <Hash className="w-3.5 h-3.5" />
                    <span>
                      {webAuthnIframeFallback === 'register'
                        ? 'Concluir Cadastro com PIN Rápido (1 clique)'
                        : 'Entrar com PIN Rápido (1 clique)'}
                    </span>
                  </button>
                  <p className="text-[11px] text-slate-600 dark:text-slate-300">
                    Para usar a biometria/PIN nativa do Windows Hello sem restrição de iframe, abra localmente em{' '}
                    <code className="font-mono font-semibold">http://localhost:3000</code> ou execute o instalador Desktop (<code className="font-mono font-semibold">.exe</code>).
                  </p>
                </div>
              )}
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
              <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="font-bold flex items-center gap-1.5">
                    <KeyRound className="w-3.5 h-3.5" />
                    <span>Provisionamento Admin via Token CLI</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => switchModeClean('REGISTER')}
                    className="text-[11px] font-semibold underline hover:text-amber-900 dark:hover:text-amber-100 cursor-pointer whitespace-nowrap shrink-0"
                  >
                    Voltar ao Cadastro Direto
                  </button>
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
                  name="name"
                  type="text"
                  autoComplete="name"
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
                  name="email"
                  type="email"
                  autoComplete="email"
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
                <div className="relative">
                  <input
                    id="bs-password-input"
                    name="new-password"
                    type={showBsPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                    required
                    minLength={10}
                    value={bsPassword}
                    onChange={(e) => setBsPassword(e.target.value)}
                    placeholder="Mínimo 10 caracteres"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] pl-3 pr-10 py-2 text-slate-900 dark:text-slate-100"
                  />
                  <button
                    type="button"
                    aria-label={showBsPassword ? 'Ocultar senha' : 'Visualizar senha'}
                    onClick={() => setShowBsPassword((v) => !v)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 cursor-pointer"
                  >
                    {showBsPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
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
                  name="bootstrap-token"
                  type="text"
                  autoComplete="off"
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
              <button
                type="button"
                disabled={submitting}
                onClick={handleWebAuthnLogin}
                className="w-full py-2.5 px-4 rounded-lg font-bold border border-[#31d6c4]/50 bg-[#31d6c4]/10 text-[#0e9f8e] dark:text-[#31d6c4] hover:bg-[#31d6c4]/20 transition-colors flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 whitespace-nowrap shrink-0"
              >
                <Fingerprint className="w-4 h-4 shrink-0" />
                <span>Entrar com Windows Hello</span>
              </button>

              <div className="grid grid-cols-2 gap-1 p-1 rounded-lg bg-slate-100 dark:bg-[#080b10] border border-slate-200 dark:border-slate-800">
                <button
                  type="button"
                  onClick={() => {
                    setErrorMsg(null);
                    setLoginMethod('PASSWORD');
                  }}
                  className={`py-1.5 px-3 rounded-md font-semibold transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                    loginMethod === 'PASSWORD'
                      ? 'bg-white dark:bg-[#131924] text-slate-900 dark:text-slate-100 shadow-xs'
                      : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                  }`}
                >
                  E-mail e Senha
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setErrorMsg(null);
                    setLoginMethod('PIN');
                  }}
                  className={`py-1.5 px-3 rounded-md font-semibold transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                    loginMethod === 'PIN'
                      ? 'bg-white dark:bg-[#131924] text-slate-900 dark:text-slate-100 shadow-xs'
                      : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                  }`}
                >
                  PIN Rápido
                </button>
              </div>

              <div>
                <label
                  htmlFor="login-email-input"
                  className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  E-mail
                </label>
                <input
                  id="login-email-input"
                  name="email"
                  type="email"
                  autoComplete="username"
                  required={loginMethod === 'PASSWORD'}
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  placeholder="usuario@organizacao.com"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                />
              </div>

              {loginMethod === 'PASSWORD' ? (
                <div>
                  <label
                    htmlFor="login-password-input"
                    className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                  >
                    Senha
                  </label>
                  <div className="relative">
                    <input
                      id="login-password-input"
                      name="password"
                      type={showLoginPassword ? 'text' : 'password'}
                      autoComplete="current-password"
                      required
                      value={loginPassword}
                      onChange={(e) => setLoginPassword(e.target.value)}
                      placeholder="••••••••••"
                      className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] pl-3 pr-10 py-2 text-slate-900 dark:text-slate-100"
                    />
                    <button
                      type="button"
                      aria-label={showLoginPassword ? 'Ocultar senha' : 'Visualizar senha'}
                      onClick={() => setShowLoginPassword((v) => !v)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 cursor-pointer"
                    >
                      {showLoginPassword ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>
              ) : (
                <div>
                  <label
                    htmlFor="login-pin-input"
                    className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                  >
                    PIN Rápido (6 a 8 dígitos)
                  </label>
                  <input
                    id="login-pin-input"
                    name="pin"
                    type="password"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    autoComplete="off"
                    required
                    minLength={6}
                    maxLength={8}
                    value={loginPin}
                    onChange={(e) => setLoginPin(e.target.value.replace(/\D/g, '').slice(0, 8))}
                    placeholder="••••••"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 font-mono text-base tracking-[0.3em] text-center text-slate-900 dark:text-slate-100 tabular-nums"
                  />
                </div>
              )}

              <label
                htmlFor="login-trust-device"
                className="flex items-center gap-2 text-slate-700 dark:text-slate-300 cursor-pointer"
              >
                <input
                  id="login-trust-device"
                  type="checkbox"
                  checked={trustDevice}
                  onChange={(e) => setTrustDevice(e.target.checked)}
                  className="rounded border-slate-400"
                />
                <span>Manter sessão ativa neste computador por 30 dias (cookie HttpOnly)</span>
              </label>

              <button
                type="submit"
                disabled={submitting}
                className="w-full py-2.5 rounded-lg font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-50"
              >
                {submitting
                  ? 'Autenticando...'
                  : loginMethod === 'PIN'
                    ? 'Entrar com PIN Rápido'
                    : 'Entrar no WinHood'}
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
            <form onSubmit={handleRegisterSubmit} className="space-y-3.5 text-xs">
              <div className="p-2.5 rounded-lg border border-[#31d6c4]/30 bg-[#31d6c4]/10 text-[11px] text-slate-700 dark:text-slate-200 flex items-center justify-between gap-2">
                <span>
                  {bootstrapRequired
                    ? 'Primeiro acesso local: a 1ª conta cadastrada recebe perfil ADMIN automaticamente.'
                    : 'Cadastro autenticado com derivação Scrypt e sessão persistente de 30 dias.'}
                </span>
                {bootstrapRequired && (
                  <button
                    type="button"
                    onClick={() => switchModeClean('BOOTSTRAP')}
                    className="text-[11px] font-mono font-semibold text-[#0e9f8e] dark:text-[#31d6c4] hover:underline whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    Usar Token
                  </button>
                )}
              </div>

              {/* Method Selector: Senha | PIN (6-8) | Win Hello */}
              <div
                role="group"
                aria-label="Método de credencial para cadastro"
                className="grid grid-cols-3 gap-1 p-1 rounded-lg bg-slate-100 dark:bg-[#080b10] border border-slate-200 dark:border-slate-800"
              >
                <button
                  type="button"
                  onClick={() => {
                    setErrorMsg(null);
                    setRegMethod('PASSWORD');
                  }}
                  className={`py-1.5 px-2.5 rounded-md font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                    regMethod === 'PASSWORD'
                      ? 'bg-white dark:bg-[#131924] text-slate-900 dark:text-slate-100 shadow-xs'
                      : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                  }`}
                >
                  <Lock className="w-3.5 h-3.5 shrink-0" />
                  <span>Senha</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setErrorMsg(null);
                    setRegMethod('PIN');
                  }}
                  className={`py-1.5 px-2.5 rounded-md font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                    regMethod === 'PIN'
                      ? 'bg-white dark:bg-[#131924] text-slate-900 dark:text-slate-100 shadow-xs'
                      : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                  }`}
                >
                  <Hash className="w-3.5 h-3.5 shrink-0" />
                  <span>PIN (6-8)</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setErrorMsg(null);
                    setRegMethod('WEBAUTHN');
                  }}
                  className={`py-1.5 px-2.5 rounded-md font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                    regMethod === 'WEBAUTHN'
                      ? 'bg-white dark:bg-[#131924] text-slate-900 dark:text-slate-100 shadow-xs'
                      : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                  }`}
                >
                  <Fingerprint className="w-3.5 h-3.5 shrink-0" />
                  <span>Win Hello</span>
                </button>
              </div>

              <div>
                <label
                  htmlFor="reg-name-input"
                  className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Nome de Exibição
                </label>
                <input
                  id="reg-name-input"
                  name="name"
                  type="text"
                  autoComplete="name"
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
                  E-mail
                </label>
                <input
                  id="reg-email-input"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                  placeholder="ana.costa@organizacao.com"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-slate-900 dark:text-slate-100"
                />
              </div>

              {regMethod === 'PASSWORD' && (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label
                      htmlFor="reg-password-input"
                      className="font-semibold text-slate-700 dark:text-slate-300"
                    >
                      Senha
                    </label>
                    <span className={`text-[11px] font-mono font-semibold ${regStrength.textColor}`}>
                      {regStrength.label}
                    </span>
                  </div>
                  <div className="relative">
                    <input
                      id="reg-password-input"
                      name="new-password"
                      type={showRegPassword ? 'text' : 'password'}
                      autoComplete="new-password"
                      required
                      minLength={10}
                      value={regPassword}
                      onChange={(e) => setRegPassword(e.target.value)}
                      placeholder="Mínimo 10 caracteres (use o ícone para conferir)"
                      className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] pl-3 pr-10 py-2 text-slate-900 dark:text-slate-100"
                    />
                    <button
                      type="button"
                      aria-label={showRegPassword ? 'Ocultar senha' : 'Visualizar senha'}
                      onClick={() => setShowRegPassword((v) => !v)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 cursor-pointer"
                    >
                      {showRegPassword ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>

                  {/* 4-Level Entropy Meter */}
                  <div className="grid grid-cols-4 gap-1.5 mt-2" aria-label="Medidor de força da senha">
                    {[1, 2, 3, 4].map((step) => (
                      <div
                        key={step}
                        className={`h-1.5 rounded-full transition-colors ${
                          regStrength.level >= step
                            ? regStrength.barColor
                            : 'bg-slate-200 dark:bg-slate-800'
                        }`}
                      />
                    ))}
                  </div>

                  {/* Criteria Checklist */}
                  <div className="grid grid-cols-2 gap-1.5 mt-2 text-[11px] text-slate-500 dark:text-slate-400">
                    <span className={regStrength.checks.minLength ? 'text-emerald-500 font-medium' : ''}>
                      {regStrength.checks.minLength ? '✓' : '○'} Mínimo 10 caracteres
                    </span>
                    <span className={regStrength.checks.mixedCase ? 'text-emerald-500 font-medium' : ''}>
                      {regStrength.checks.mixedCase ? '✓' : '○'} Maiúsculas &amp; minúsculas
                    </span>
                    <span className={regStrength.checks.hasDigit ? 'text-emerald-500 font-medium' : ''}>
                      {regStrength.checks.hasDigit ? '✓' : '○'} Ao menos 1 número
                    </span>
                    <span className={regStrength.checks.hasSymbol ? 'text-emerald-500 font-medium' : ''}>
                      {regStrength.checks.hasSymbol ? '✓' : '○'} Símbolo especial (!@#$)
                    </span>
                  </div>
                </div>
              )}

              {regMethod === 'PIN' && (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label
                      htmlFor="reg-pin-input"
                      className="font-semibold text-slate-700 dark:text-slate-300"
                    >
                      PIN Rápido (6 a 8 dígitos)
                    </label>
                    <span
                      className={`text-[11px] font-mono font-semibold ${
                        regPinStatus.valid ? 'text-emerald-500' : 'text-amber-500'
                      }`}
                    >
                      {regPinStatus.reason}
                    </span>
                  </div>
                  <input
                    id="reg-pin-input"
                    name="pin"
                    type="password"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    autoComplete="off"
                    required
                    minLength={6}
                    maxLength={8}
                    value={regPin}
                    onChange={(e) => setRegPin(e.target.value.replace(/\D/g, '').slice(0, 8))}
                    placeholder="Ex.: 482917"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 font-mono text-base tracking-[0.3em] text-center text-slate-900 dark:text-slate-100 tabular-nums"
                  />
                  <p className="mt-1.5 text-[11px] text-slate-500 dark:text-slate-400">
                    Armazenado com Scrypt (N=16384, r=8, p=1) e bloqueio automático contra força bruta após 5 tentativas.
                  </p>
                </div>
              )}

              {regMethod === 'WEBAUTHN' && (
                <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-1.5">
                  <div className="font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                    <Fingerprint className="w-4 h-4 text-[#0e9f8e] dark:text-[#31d6c4]" />
                    <span>Credencial FIDO2 / Windows Hello (TPM Plataforma)</span>
                  </div>
                  <p className="text-[11px] text-slate-600 dark:text-slate-400">
                    Utiliza biometria, reconhecimento facial ou PIN do sistema operacional Windows com chave criptográfica assimétrica ES256/RS256 sem envio de senha pela rede.
                  </p>
                </div>
              )}

              {/* Progressive Profiling Toggle */}
              {regMethod !== 'WEBAUTHN' && (
                <div className="border-t border-slate-200 dark:border-slate-800 pt-2.5">
                  <button
                    type="button"
                    onClick={() => setShowAdvancedRegister((v) => !v)}
                    className="w-full flex items-center justify-between text-[11px] font-semibold text-slate-600 dark:text-slate-400 hover:text-[#31d6c4] cursor-pointer"
                  >
                    <span>Configurações opcionais de perfil (RBAC &amp; 2FA)</span>
                    {showAdvancedRegister ? (
                      <ChevronUp className="w-3.5 h-3.5" />
                    ) : (
                      <ChevronDown className="w-3.5 h-3.5" />
                    )}
                  </button>

                  {showAdvancedRegister && (
                    <div className="mt-2.5 space-y-2.5 p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
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
                          className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0c1017] px-2.5 py-1.5 text-slate-900 dark:text-slate-100"
                        >
                          <option value="SECURITY_LEAD">
                            SECURITY_LEAD — AppSec, SAST, MqrBridge &amp; Benchmarks
                          </option>
                          <option value="QA_ENGINEER">
                            QA_ENGINEER — Qualidade, Testes &amp; Performance
                          </option>
                          <option value="AUDITOR">
                            AUDITOR — Auditoria de Evidências &amp; Relatórios
                          </option>
                        </select>
                      </div>

                      <label className="flex items-center gap-2 text-slate-700 dark:text-slate-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={regEnableMfa}
                          onChange={(e) => setRegEnableMfa(e.target.checked)}
                          className="rounded border-slate-400"
                        />
                        <span>Ativar autenticação 2FA (TOTP) já na criação da conta</span>
                      </label>
                    </div>
                  )}
                </div>
              )}

              <button
                type="submit"
                disabled={submitting}
                className="w-full py-2.5 rounded-lg font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {regMethod === 'WEBAUTHN' ? (
                  <Fingerprint className="w-4 h-4" />
                ) : (
                  <UserPlus className="w-4 h-4" />
                )}
                <span>
                  {submitting
                    ? 'Cadastrando conta...'
                    : regMethod === 'WEBAUTHN'
                      ? 'Registrar com Windows Hello'
                      : regMethod === 'PIN'
                        ? 'Criar Conta com PIN & Acessar'
                        : 'Criar Conta & Acessar WinHood'}
                </span>
              </button>

              <div className="flex items-center justify-between pt-2 border-t border-slate-200 dark:border-slate-800/80">
                {bootstrapRequired ? (
                  <button
                    type="button"
                    onClick={() => switchModeClean('BOOTSTRAP')}
                    className="text-[11px] font-semibold text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 hover:underline cursor-pointer"
                  >
                    Usar Token de Bootstrap (CLI)
                  </button>
                ) : (
                  <span />
                )}
                <button
                  type="button"
                  onClick={() => switchModeClean('LOGIN')}
                  className="text-[11px] font-bold text-[#0e9f8e] dark:text-[#31d6c4] hover:underline cursor-pointer"
                >
                  Já possui uma conta? Fazer login
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

              {clockDriftSeconds > 25 && (
                <div className="p-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 text-[11px] text-amber-600 dark:text-amber-300 flex items-start gap-2">
                  <Clock className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>
                    Dessincronização de relógio detectada ({clockDriftSeconds}s de diferença em relação ao servidor). Se o código falhar, sincronize a hora automática do seu dispositivo.
                  </span>
                </div>
              )}

              {totpSetupInfo && (
                <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-2.5 text-[11px] text-center">
                  <div className="font-bold text-slate-800 dark:text-slate-200">
                    Escaneie o QR Code no Google Authenticator, Authy ou 1Password:
                  </div>
                  {qrCodeDataUrl ? (
                    <div className="flex justify-center p-2 bg-white rounded shadow-inner">
                      <img src={qrCodeDataUrl} alt="QR Code TOTP MFA" className="w-36 h-36 object-contain" />
                    </div>
                  ) : (
                    <div className="text-slate-400">Gerando QR Code criptográfico offline...</div>
                  )}
                  <div className="text-left space-y-1 pt-1">
                    <div className="text-slate-500 font-semibold">Chave Base32 (Configuração Manual):</div>
                    <div className="font-mono text-[#0e9f8e] dark:text-[#31d6c4] break-all select-all p-1.5 bg-slate-100 dark:bg-slate-900 rounded">
                      {totpSetupInfo.secret}
                    </div>
                  </div>

                  {totpSetupInfo.recoveryCodes && totpSetupInfo.recoveryCodes.length > 0 && (
                    <div className="text-left space-y-1.5 pt-2 border-t border-slate-200 dark:border-slate-800">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-amber-600 dark:text-amber-400">
                          8 Códigos de Recuperação de Uso Único (Salve em local seguro):
                        </span>
                        <div className="flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() =>
                              void handleCopyRecoveryCodes(totpSetupInfo.recoveryCodes!)
                            }
                            className="px-2 py-0.5 rounded border border-slate-300 dark:border-slate-700 hover:border-[#31d6c4] inline-flex items-center gap-1 cursor-pointer"
                          >
                            {copiedRecovery ? (
                              <Check className="w-3 h-3 text-emerald-500" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                            <span>{copiedRecovery ? 'Copiado' : 'Copiar'}</span>
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              handleDownloadRecoveryCodes(totpSetupInfo.recoveryCodes!)
                            }
                            className="px-2 py-0.5 rounded border border-slate-300 dark:border-slate-700 hover:border-[#31d6c4] inline-flex items-center gap-1 cursor-pointer"
                          >
                            <Download className="w-3 h-3" />
                            <span>.TXT</span>
                          </button>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 font-mono text-[11px]">
                        {totpSetupInfo.recoveryCodes.map((code) => (
                          <div
                            key={code}
                            className="px-2 py-1 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center select-all"
                          >
                            {code}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {!useRecoveryMode ? (
                <div>
                  <label
                    htmlFor="mfa-code-input"
                    className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                  >
                    Código TOTP (6 dígitos — validação automática ao preencher)
                  </label>
                  <input
                    id="mfa-code-input"
                    name="one-time-code"
                    type="text"
                    required
                    inputMode="numeric"
                    pattern="[0-9]*"
                    autoComplete="one-time-code"
                    autoFocus
                    maxLength={6}
                    value={mfaCode}
                    onChange={(e) => handleMfaCodeChange(e.target.value)}
                    onPaste={handleMfaPaste}
                    placeholder="000000"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2.5 font-mono text-lg tracking-[0.35em] text-center text-slate-900 dark:text-slate-100 tabular-nums"
                  />
                </div>
              ) : (
                <div>
                  <label
                    htmlFor="mfa-recovery-input"
                    className="block font-semibold text-slate-700 dark:text-slate-300 mb-1"
                  >
                    Código de Recuperação de Uso Único (XXXX-XXXX)
                  </label>
                  <input
                    id="mfa-recovery-input"
                    name="recovery-code"
                    type="text"
                    required
                    autoFocus
                    maxLength={12}
                    value={recoveryBackupCode}
                    onChange={(e) => setRecoveryBackupCode(e.target.value.toUpperCase())}
                    placeholder="A1B2-C3D4"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 font-mono text-base tracking-widest text-center text-slate-900 dark:text-slate-100 uppercase"
                  />
                </div>
              )}

              <div className="flex items-center justify-between gap-2">
                <label
                  htmlFor="mfa-trust-device"
                  className="flex items-center gap-2 text-slate-600 dark:text-slate-400 cursor-pointer"
                >
                  <input
                    id="mfa-trust-device"
                    type="checkbox"
                    checked={trustDevice}
                    onChange={(e) => setTrustDevice(e.target.checked)}
                    className="rounded border-slate-400"
                  />
                  <span>Lembrar este computador (30d)</span>
                </label>

                <button
                  type="button"
                  onClick={() => {
                    setErrorMsg(null);
                    setUseRecoveryMode((v) => !v);
                  }}
                  className="text-[11px] font-semibold text-[#0e9f8e] dark:text-[#31d6c4] hover:underline cursor-pointer"
                >
                  {useRecoveryMode
                    ? 'Voltar para código TOTP (6 dígitos)'
                    : 'Usar código de recuperação de uso único'}
                </button>
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
                    id="rec-email-input"
                    name="email"
                    type="email"
                    autoComplete="email"
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
                    id="rec-token-input"
                    name="recovery-token"
                    type="text"
                    autoComplete="one-time-code"
                    required
                    value={recToken}
                    onChange={(e) => setRecToken(e.target.value)}
                    placeholder="Token de recuperação de uso único"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 font-mono text-slate-900 dark:text-slate-100"
                  />
                  <div className="relative">
                    <input
                      id="rec-new-password-input"
                      name="new-password"
                      type={showRecPassword ? 'text' : 'password'}
                      autoComplete="new-password"
                      required
                      minLength={10}
                      value={recNewPassword}
                      onChange={(e) => setRecNewPassword(e.target.value)}
                      placeholder="Nova senha forte (mín. 10 caracteres)"
                      className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] pl-3 pr-10 py-2 text-slate-900 dark:text-slate-100"
                    />
                    <button
                      type="button"
                      aria-label={showRecPassword ? 'Ocultar senha' : 'Visualizar senha'}
                      onClick={() => setShowRecPassword((v) => !v)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 cursor-pointer"
                    >
                      {showRecPassword ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
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

          {/* Discrete Footer Link: Privacidade & Termos (Microsoft Store Section 10.5) */}
          <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
            <span className="font-mono">100% Local · MIT Open Source</span>
            <button
              type="button"
              onClick={() => setIsPrivacyModalOpen(true)}
              className="font-semibold text-slate-600 dark:text-slate-300 hover:text-[#31d6c4] underline underline-offset-2 cursor-pointer"
            >
              Privacidade &amp; Termos
            </button>
          </div>
        </div>
      </div>

      <PrivacyAndTermsModal
        isOpen={isPrivacyModalOpen}
        onClose={() => setIsPrivacyModalOpen(false)}
      />
    </div>
  );
};
