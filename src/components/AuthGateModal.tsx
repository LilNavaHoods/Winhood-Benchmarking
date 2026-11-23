import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  Check,
  ChevronRight,
  Copy,
  ExternalLink,
  Eye,
  EyeOff,
  Fingerprint,
  Github,
  Hash,
  KeyRound,
  Laptop,
  Lock,
  LogOut,
  ShieldCheck,
} from 'lucide-react';
import { WinHoodLogo } from './WinHoodLogo';
import { PrivacyAndTermsModal } from './PrivacyAndTermsModal';
import {
  clearClientAuthTokens,
  csrfFetch as fetch,
  setGlobalCsrfToken,
  setGlobalSessionToken,
} from '../utils/csrfFetch';
import {
  extractGitHubOAuthErrorFromSearch,
  GITHUB_OAUTH_ERROR_MESSAGES,
  GITHUB_OAUTH_START_URL,
  GITHUB_OAUTH_UNAVAILABLE_NOTICE,
  resolveGitHubOAuthCtaLabel,
  type GitHubOAuthAvailabilityState,
  type WinHoodAccessMode,
} from '../shared/authTypes';

export interface AuthUserView {
  id: string;
  name: string;
  email: string;
  role: 'ADMIN' | 'SECURITY_LEAD' | 'AUDITOR' | 'QA_ENGINEER';
  mfaEnabled: boolean;
  mfaVerified: boolean;
  pinEnabled?: boolean;
  webauthnEnabled?: boolean;
  githubLinked?: boolean;
  githubLogin?: string | null;
  githubAvatarUrl?: string | null;
  authProviders?: Array<'password' | 'pin' | 'github' | 'webauthn' | 'windows-hello-native'>;
}

interface WinHoodDesktopBridge {
  isElectronDesktop?: boolean;
  openExternalUrl?: (url: string) => Promise<unknown>;
}

interface AuthGateModalProps {
  bootstrapRequired: boolean;
  bootstrapTokenFileHint?: string | null;
  mfaRequired: boolean;
  pendingUser: AuthUserView | null;
  onAuthenticated: (user: AuthUserView) => void;
  onRefreshSession: () => Promise<void>;
}

interface AccessModeStatus {
  mode: WinHoodAccessMode;
  soloLocalAllowed: boolean;
  reason: string;
  vaultLockEnabled: boolean;
  teamServerMode: boolean;
  githubDeviceFlowConfigured: boolean;
  githubOAuthDirectConfigured?: boolean;
  githubOAuthStatus?: 'CONFIGURED' | 'NOT_CONFIGURED';
  githubSignupAllowed?: boolean;
  githubPatSupported?: boolean;
  windowsHelloNativeSupported?: boolean;
  hasRegisteredWebAuthnCredentials?: boolean;
  runtimeEnv: string;
}

interface GitHubDeviceSessionState {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  expiresAtMs: number;
  intervalSec: number;
}

type TeamCredentialTab = 'PASSWORD' | 'PIN';
type TeamActionTab = 'LOGIN' | 'REGISTER';
type WindowsHelloTab = 'LOGIN' | 'REGISTER';

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

function isRunningInIframe(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    return window.self !== window.top;
  } catch {
    return true;
  }
}

const FOCUS_RING =
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#14b8a6] dark:focus-visible:ring-[#31d6c4] focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:focus-visible:ring-offset-[#0c1017]';

export const AuthGateModal: React.FC<AuthGateModalProps> = ({
  bootstrapRequired,
  mfaRequired,
  pendingUser,
  onAuthenticated,
  onRefreshSession,
}) => {
  const [accessPolicy, setAccessPolicy] = useState<AccessModeStatus | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [infoMsg, setInfoMsg] = useState<string | null>(null);
  const [isPrivacyModalOpen, setIsPrivacyModalOpen] = useState(false);

  // GitHub Social Login (OAuth 2.0 PKCE) + Legacy Admin Compatibility (PAT / Device Flow)
  const [githubOAuthStatus, setGithubOAuthStatus] =
    useState<GitHubOAuthAvailabilityState>('LOADING');
  const [ghDevice, setGhDevice] = useState<GitHubDeviceSessionState | null>(null);
  const [copiedDeviceCode, setCopiedDeviceCode] = useState(false);
  const [showGitHubUnavailableNotice, setShowGitHubUnavailableNotice] = useState(false);
  const [showTechnicalGitHubCompat, setShowTechnicalGitHubCompat] = useState(false);
  const [redirectingToGitHub, setRedirectingToGitHub] = useState(false);
  const [githubPatInput, setGithubPatInput] = useState('');
  const [githubClientIdInput, setGithubClientIdInput] = useState('');
  const [oauthPendingState, setOauthPendingState] = useState<{
    state: string;
    authorizeUrl: string;
  } | null>(null);
  const pollTimerRef = useRef<number | null>(null);
  const oauthPollTimerRef = useRef<number | null>(null);
  const oauthMsgListenerRef = useRef<((ev: MessageEvent) => void) | null>(null);
  const oauthInFlightRef = useRef(false);

  // Windows Hello / Passkey tabbed panel (Login vs Register)
  const [showWindowsHelloPanel, setShowWindowsHelloPanel] = useState(false);
  const [helloMode, setHelloMode] = useState<WindowsHelloTab>('REGISTER');
  const [helloNameInput, setHelloNameInput] = useState('');
  const [helloEmailInput, setHelloEmailInput] = useState('');

  // Team Server progressive disclosure (<details>)
  const [teamAction, setTeamAction] = useState<TeamActionTab>(
    bootstrapRequired ? 'REGISTER' : 'LOGIN'
  );
  const [teamMethod, setTeamMethod] = useState<TeamCredentialTab>('PASSWORD');
  const [nameInput, setNameInput] = useState('');
  const [emailInput, setEmailInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [pinInput, setPinInput] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [trustDevice, setTrustDevice] = useState(true);

  // Pending TOTP challenge (only if account already has MFA enabled post-login)
  const [showMfaChallenge, setShowMfaChallenge] = useState(mfaRequired);
  const [preAuthToken, setPreAuthToken] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState('');
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const [recoveryBackupCode, setRecoveryBackupCode] = useState('');
  const mfaSubmittingRef = useRef(false);

  useEffect(() => {
    setShowMfaChallenge(mfaRequired);
  }, [mfaRequired]);

  useEffect(() => {
    let returnedNotConfigured = false;
    if (typeof window !== 'undefined') {
      const parsedError = extractGitHubOAuthErrorFromSearch(window.location.search);
      if (parsedError.errorCode) {
        if (parsedError.isNotConfigured) {
          returnedNotConfigured = true;
          setGithubOAuthStatus('NOT_CONFIGURED');
          setShowGitHubUnavailableNotice(true);
        } else if (parsedError.message) {
          setErrorMsg(parsedError.message);
        }
        const nextUrl = `${window.location.pathname}${parsedError.cleanedSearch}${window.location.hash}`;
        window.history.replaceState({}, document.title, nextUrl);
      }
    }

    let active = true;
    fetch('/api/auth/access-mode', { cache: 'no-store' })
      .then((res) => (res.ok ? res.json() : null))
      .then((data: AccessModeStatus | null) => {
        if (!active) return;
        if (data) {
          setAccessPolicy(data);
          const isConfigured =
            data.githubOAuthStatus === 'CONFIGURED' || Boolean(data.githubOAuthDirectConfigured);
          setGithubOAuthStatus(isConfigured ? 'CONFIGURED' : 'NOT_CONFIGURED');
          if (isConfigured) {
            setShowGitHubUnavailableNotice(false);
          }
          if (typeof data.hasRegisteredWebAuthnCredentials === 'boolean') {
            setHelloMode(data.hasRegisteredWebAuthnCredentials ? 'LOGIN' : 'REGISTER');
          }
        } else if (!returnedNotConfigured) {
          setGithubOAuthStatus('ERROR');
        }
      })
      .catch(() => {
        if (active && !returnedNotConfigured) {
          setGithubOAuthStatus('ERROR');
        }
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    const handlePageShow = (event: PageTransitionEvent) => {
      if (event.persisted) {
        oauthInFlightRef.current = false;
        setRedirectingToGitHub(false);
        setSubmitting(false);
        setInfoMsg(null);
      }
    };
    window.addEventListener('pageshow', handlePageShow);
    return () => {
      window.removeEventListener('pageshow', handlePageShow);
      if (pollTimerRef.current !== null) {
        window.clearTimeout(pollTimerRef.current);
      }
      if (oauthPollTimerRef.current !== null) {
        window.clearTimeout(oauthPollTimerRef.current);
      }
      if (oauthMsgListenerRef.current) {
        window.removeEventListener('message', oauthMsgListenerRef.current);
      }
    };
  }, []);

  const persistTokensAndComplete = async (data: {
    user?: AuthUserView;
    sessionId?: string;
    csrfToken?: string;
  }) => {
    // Sessão em ambiente padrão/Desktop usa cookie HttpOnly; header/storage fallback apenas em iframe cross-site.
    if (data.sessionId && isRunningInIframe()) {
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
  };

  const handleSoloLocalWorkspace = async () => {
    setErrorMsg(null);
    setInfoMsg(null);
    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/solo-local', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(
          data?.error ||
            'Sessão Solo Local indisponível neste modo de servidor. Utilize GitHub, Windows Hello ou Acesso Avançado.'
        );
        return;
      }
      await persistTokensAndComplete(data);
    } catch {
      setErrorMsg('Erro de comunicação ao inicializar o Workspace Local.');
    } finally {
      setSubmitting(false);
    }
  };

  const stopGitHubPolling = () => {
    if (pollTimerRef.current !== null) {
      window.clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
    setGhDevice(null);
  };

  const scheduleGitHubPoll = (session: GitHubDeviceSessionState, explicitClientId?: string) => {
    if (Date.now() >= session.expiresAtMs) {
      stopGitHubPolling();
      setErrorMsg('Código de autorização do GitHub expirou. Solicite um novo código.');
      return;
    }

    pollTimerRef.current = window.setTimeout(async () => {
      try {
        const res = await fetch('/api/auth/github/device/poll', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deviceCode: session.deviceCode,
            clientId: explicitClientId || undefined,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          stopGitHubPolling();
          setErrorMsg(data?.error || 'Falha ao verificar autorização no GitHub.');
          return;
        }
        if (data.authorized) {
          stopGitHubPolling();
          setInfoMsg('Autorização GitHub confirmada. Abrindo workspace...');
          await persistTokensAndComplete(data);
          return;
        }
        if (data.status === 'EXPIRED' || data.status === 'ACCESS_DENIED' || data.status === 'ERROR') {
          stopGitHubPolling();
          setErrorMsg(data.errorDescription || 'Autorização GitHub cancelada ou expirada.');
          return;
        }
        const nextInterval = data.status === 'SLOW_DOWN' ? session.intervalSec + 5 : session.intervalSec;
        scheduleGitHubPoll({ ...session, intervalSec: nextInterval }, explicitClientId);
      } catch {
        stopGitHubPolling();
        setErrorMsg('Erro de rede ao consultar status do GitHub OAuth Device Flow.');
      }
    }, Math.max(session.intervalSec, 5) * 1000);
  };

  const handleStartGitHubDeviceFlow = async (explicitClientId?: string) => {
    setErrorMsg(null);
    setInfoMsg(null);
    stopGitHubPolling();

    const candidateClientId = (explicitClientId ?? githubClientIdInput).trim();
    if (!accessPolicy?.githubDeviceFlowConfigured && candidateClientId.length < 8) {
      setErrorMsg('Informe um Client ID de OAuth App válido para usar o Device Flow.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/github/device/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(candidateClientId ? { clientId: candidateClientId } : {}),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(
          data?.error ||
            'Não foi possível iniciar o GitHub Device Flow. Verifique o Client ID informado.'
        );
        return;
      }
      const nextSession: GitHubDeviceSessionState = {
        deviceCode: String(data.device_code),
        userCode: String(data.user_code),
        verificationUri: String(data.verification_uri || 'https://github.com/login/device'),
        expiresAtMs: Date.now() + Number(data.expires_in || 900) * 1000,
        intervalSec: Number(data.interval || 5),
      };
      setGhDevice(nextSession);
      setInfoMsg('Insira o código abaixo na página oficial do GitHub para concluir o acesso.');
      scheduleGitHubPoll(nextSession, candidateClientId || undefined);
    } catch {
      setErrorMsg('Não foi possível conectar ao endpoint de GitHub OAuth Device Flow.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleGitHubPatLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setInfoMsg(null);

    const cleanToken = githubPatInput.trim();
    if (cleanToken.length < 10) {
      setErrorMsg(
        'Informe um GitHub Personal Access Token válido (ghp_... ou github_pat_...) com escopo read:user.'
      );
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/github/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: cleanToken, trustDevice }),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data?.error || 'Token GitHub recusado pela API oficial.');
        return;
      }
      setGithubPatInput('');
      setInfoMsg('Conta GitHub validada na API oficial. Abrindo workspace...');
      await persistTokensAndComplete(data);
    } catch {
      setErrorMsg('Erro de rede ao validar token na API oficial do GitHub.');
    } finally {
      setSubmitting(false);
    }
  };

  const stopGitHubOAuthPolling = () => {
    if (oauthPollTimerRef.current !== null) {
      window.clearTimeout(oauthPollTimerRef.current);
      oauthPollTimerRef.current = null;
    }
    if (oauthMsgListenerRef.current) {
      window.removeEventListener('message', oauthMsgListenerRef.current);
      oauthMsgListenerRef.current = null;
    }
    setOauthPendingState(null);
  };

  const scheduleGitHubOAuthStatusPoll = (state: string, attemptsLeft = 90) => {
    if (attemptsLeft <= 0) {
      stopGitHubOAuthPolling();
      setErrorMsg('Tempo limite para autorização no GitHub excedido. Tente novamente.');
      return;
    }
    oauthPollTimerRef.current = window.setTimeout(async () => {
      try {
        const res = await fetch(
          `/api/auth/github/oauth/status?state=${encodeURIComponent(state)}`
        );
        const data = await res.json();
        if (res.ok && data.authorized) {
          stopGitHubOAuthPolling();
          setShowGitHubUnavailableNotice(false);
          setInfoMsg(
            data.isNewAccount
              ? 'Conta criada e autenticada via GitHub. Abrindo workspace...'
              : 'Login GitHub confirmado. Abrindo workspace...'
          );
          await persistTokensAndComplete(data);
          return;
        }
        if (res.status === 429) {
          stopGitHubOAuthPolling();
          setErrorMsg(GITHUB_OAUTH_ERROR_MESSAGES.rate_limited);
          return;
        }
        if (res.status >= 400) {
          stopGitHubOAuthPolling();
          setErrorMsg(data?.error || 'Autorização GitHub expirada ou recusada.');
          return;
        }
        scheduleGitHubOAuthStatusPoll(state, attemptsLeft - 1);
      } catch {
        scheduleGitHubOAuthStatusPoll(state, attemptsLeft - 1);
      }
    }, 2000);
  };

  const handleGitHubDirectAuth = async () => {
    if (oauthInFlightRef.current || submitting) return;
    setErrorMsg(null);
    setInfoMsg(null);
    setShowWindowsHelloPanel(false);
    stopGitHubPolling();
    stopGitHubOAuthPolling();

    // Somente bloquear localmente quando o backend já confirmou explicitamente NOT_CONFIGURED.
    // Nunca bloquear quando o estado ainda estiver em LOADING ou ERROR — o backend é a fonte definitiva.
    if (githubOAuthStatus === 'NOT_CONFIGURED') {
      setShowGitHubUnavailableNotice(true);
      return;
    }

    setShowGitHubUnavailableNotice(false);
    oauthInFlightRef.current = true;

    const desktopBridge = (window as unknown as { winhoodDesktop?: WinHoodDesktopBridge })
      .winhoodDesktop;
    const isElectron = Boolean(
      desktopBridge?.isElectronDesktop && typeof desktopBridge.openExternalUrl === 'function'
    );
    const inIframe = isRunningInIframe();

    // Em navegador padrão (aba top-level fora de iframe/Electron): redirecionamento direto OAuth 2.0 PKCE.
    if (!isElectron && !inIframe) {
      setRedirectingToGitHub(true);
      setSubmitting(true);
      setInfoMsg('Redirecionando com segurança para autenticação no GitHub...');
      window.location.assign(GITHUB_OAUTH_START_URL);
      return;
    }

    setSubmitting(true);
    try {
      const mode = isElectron ? 'desktop' : 'popup';
      const res = await fetch(`/api/auth/github/oauth/start?mode=${mode}`, { cache: 'no-store' });
      const data = (await res.json()) as {
        authorizeUrl?: string;
        state?: string;
        error?: string;
        code?: string;
      };
      if (res.status === 429) {
        setErrorMsg(GITHUB_OAUTH_ERROR_MESSAGES.rate_limited);
        return;
      }
      if (!res.ok || !data.authorizeUrl || !data.state) {
        if (data?.code === 'GITHUB_OAUTH_NOT_CONFIGURED') {
          setGithubOAuthStatus('NOT_CONFIGURED');
          setShowGitHubUnavailableNotice(true);
        } else {
          setGithubOAuthStatus('ERROR');
          setErrorMsg(
            data?.error ||
              'Não foi possível iniciar o login com o GitHub no momento. Tente novamente.'
          );
        }
        return;
      }
      setGithubOAuthStatus('CONFIGURED');

      const oauthState = data.state;
      const authorizeUrl = data.authorizeUrl;
      setOauthPendingState({ state: oauthState, authorizeUrl });

      if (isElectron && desktopBridge?.openExternalUrl) {
        await desktopBridge.openExternalUrl(authorizeUrl);
        setInfoMsg(
          'Conclua o login no GitHub pelo navegador externo aberto. O WinHood continuará automaticamente.'
        );
        scheduleGitHubOAuthStatusPoll(oauthState);
        return;
      }

      const onMessage = async (event: MessageEvent) => {
        if (event.origin !== window.location.origin) return;
        const payload = event.data as {
          type?: string;
          ok?: boolean;
          state?: string;
          error?: string;
          user?: AuthUserView;
          csrfToken?: string;
          isNewAccount?: boolean;
        } | null;
        if (!payload || payload.type !== 'winhood-github-oauth-result') return;

        if (!payload.ok) {
          stopGitHubOAuthPolling();
          setErrorMsg(payload.error || 'Autorização GitHub cancelada ou recusada.');
          return;
        }

        try {
          const statusRes = await fetch(
            `/api/auth/github/oauth/status?state=${encodeURIComponent(payload.state || oauthState)}`
          );
          const statusData = await statusRes.json();
          stopGitHubOAuthPolling();
          if (statusRes.ok && statusData.authorized) {
            setInfoMsg(
              statusData.isNewAccount
                ? 'Conta criada e conectada com GitHub. Abrindo workspace...'
                : 'Conta GitHub autenticada. Abrindo workspace...'
            );
            await persistTokensAndComplete(statusData);
          } else {
            await persistTokensAndComplete({
              user: payload.user,
              csrfToken: payload.csrfToken,
            });
          }
        } catch {
          stopGitHubOAuthPolling();
          await onRefreshSession();
        }
      };

      oauthMsgListenerRef.current = onMessage;
      window.addEventListener('message', onMessage);

      setInfoMsg(
        'Clique em "Continuar autorização no GitHub" abaixo para concluir a autenticação em nova aba e retornar automaticamente ao WinHood.'
      );
      scheduleGitHubOAuthStatusPoll(oauthState);
    } catch {
      setErrorMsg('Erro de comunicação ao iniciar o login com o GitHub.');
    } finally {
      oauthInFlightRef.current = false;
      setSubmitting(false);
    }
  };

  const handleCopyDeviceCode = async () => {
    if (!ghDevice) return;
    try {
      await navigator.clipboard.writeText(ghDevice.userCode);
      setCopiedDeviceCode(true);
      window.setTimeout(() => setCopiedDeviceCode(false), 2000);
    } catch {
      // Clipboard API unavailable
    }
  };

  const handleWindowsHelloLogin = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setErrorMsg(null);
    setInfoMsg(null);
    setSubmitting(true);

    const inIframe = isRunningInIframe();
    const targetEmail = helloEmailInput.trim();
    let webAuthnBlockedInIframe = false;

    try {
      if (window.PublicKeyCredential && navigator.credentials) {
        const optRes = await fetch('/api/auth/webauthn/login/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: targetEmail || undefined,
            rpId: window.location.hostname,
          }),
        });

        if (optRes.ok) {
          const optData = await optRes.json();
          const allowCredentials: PublicKeyCredentialDescriptor[] = Array.isArray(
            optData.allowCredentials
          )
            ? optData.allowCredentials.map(
                (c: { id: string; transports?: AuthenticatorTransport[] }) => ({
                  type: 'public-key' as const,
                  id: base64UrlToUint8Array(c.id),
                  transports: c.transports,
                })
              )
            : [];

          if (allowCredentials.length > 0) {
            try {
              const assertion = (await navigator.credentials.get({
                publicKey: {
                  challenge: base64UrlToUint8Array(optData.challenge),
                  rpId: optData.rpId || window.location.hostname,
                  timeout: optData.timeout || 60000,
                  userVerification: 'required',
                  allowCredentials,
                },
              })) as PublicKeyCredential | null;

              if (assertion) {
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
                    email: targetEmail || undefined,
                    trustDevice,
                  }),
                });
                const data = await verifyRes.json();
                if (!verifyRes.ok) {
                  setErrorMsg(
                    data?.error || 'Falha na validação da credencial Passkey/Windows Hello.'
                  );
                  return;
                }
                if (data.requiresTotp || data.mfaRequired) {
                  setPreAuthToken(data.preAuthToken || null);
                  setShowMfaChallenge(true);
                  setInfoMsg('Informe o código TOTP de 6 dígitos do seu aplicativo autenticador.');
                  return;
                }
                await persistTokensAndComplete(data);
                return;
              }
            } catch (webAuthnErr: unknown) {
              const errName = webAuthnErr instanceof Error ? webAuthnErr.name : '';
              if (errName === 'NotAllowedError' && !inIframe) {
                setErrorMsg('Verificação Windows Hello / Passkey cancelada ou tempo esgotado.');
                return;
              }
              if (inIframe && (errName === 'SecurityError' || errName === 'NotAllowedError')) {
                webAuthnBlockedInIframe = true;
              }
            }
          } else if (!accessPolicy?.windowsHelloNativeSupported) {
            setHelloMode('REGISTER');
            setShowWindowsHelloPanel(true);
            setInfoMsg(
              targetEmail
                ? `Nenhuma Passkey vinculada a "${targetEmail}". Preencha seu nome e e-mail para criar sua conta com Windows Hello.`
                : 'Nenhuma Passkey Windows Hello cadastrada ainda. Crie sua conta com Windows Hello abaixo.'
            );
            return;
          }
        }
      }

      if (accessPolicy?.windowsHelloNativeSupported) {
        const nativeRes = await fetch('/api/auth/windows-hello/native-login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: targetEmail || undefined,
            trustDevice,
          }),
        });
        const nativeData = await nativeRes.json();
        if (nativeRes.status === 404 && nativeData?.code === 'WEBAUTHN_CREDENTIAL_NOT_FOUND') {
          setHelloMode('REGISTER');
          setShowWindowsHelloPanel(true);
          setInfoMsg(
            'Nenhuma credencial Windows Hello cadastrada para este e-mail. Crie sua conta na aba "Criar Conta com Windows Hello".'
          );
          return;
        }
        if (!nativeRes.ok) {
          setErrorMsg(
            nativeData?.error || 'Falha ao autenticar via Windows Hello nativo do Windows.'
          );
          return;
        }
        if (nativeData.requiresTotp || nativeData.mfaRequired) {
          setPreAuthToken(nativeData.preAuthToken || null);
          setShowMfaChallenge(true);
          setInfoMsg('Informe o código TOTP de 6 dígitos do seu aplicativo autenticador.');
          return;
        }
        await persistTokensAndComplete(nativeData);
        return;
      }

      if (inIframe || webAuthnBlockedInIframe) {
        setErrorMsg(
          'Navegadores bloqueiam WebAuthn/Passkey dentro de iframes de preview. Utilize "Continuar no Workspace Local (1 clique)", "Entrar ou Cadastrar com GitHub" ou abra em aba própria.'
        );
        return;
      }

      setErrorMsg(
        'Nenhum autenticador Passkey/Windows Hello disponível neste navegador. Use "Continuar no Workspace Local (1 clique)" ou "Entrar ou Cadastrar com GitHub".'
      );
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error
          ? err.message
          : 'Não foi possível autenticar via Windows Hello / Passkey.'
      );
    } finally {
      setSubmitting(false);
    }
  };

  const handleWindowsHelloRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setInfoMsg(null);

    const cleanName = helloNameInput.trim();
    const cleanEmail = helloEmailInput.trim().toLowerCase();
    if (cleanName.length < 2) {
      setErrorMsg('Informe seu nome completo (mínimo 2 caracteres) para cadastrar com Windows Hello.');
      return;
    }
    if (!cleanEmail.includes('@') || !cleanEmail.includes('.')) {
      setErrorMsg('Informe um endereço de e-mail válido para associar à sua Passkey.');
      return;
    }

    const inIframe = isRunningInIframe();
    let webAuthnFailedOrBlocked = false;
    setSubmitting(true);

    try {
      if (window.PublicKeyCredential && navigator.credentials && !inIframe) {
        const regOptRes = await fetch('/api/auth/webauthn/register-account/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: cleanName,
            email: cleanEmail,
            rpId: window.location.hostname,
          }),
        });
        const regOptData = await regOptRes.json();
        if (!regOptRes.ok) {
          if (regOptRes.status === 409) {
            setHelloMode('LOGIN');
          }
          setErrorMsg(regOptData?.error || 'Não foi possível iniciar o cadastro com Windows Hello.');
          return;
        }

        const pk = regOptData.publicKey || regOptData;
        try {
          const created = (await navigator.credentials.create({
            publicKey: {
              challenge: base64UrlToUint8Array(pk.challenge),
              rp: {
                name: pk.rp?.name || 'WinHood Benchmark Analyzer',
                id: pk.rp?.id || window.location.hostname,
              },
              user: {
                id: base64UrlToUint8Array(pk.user?.id),
                name: pk.user?.name || cleanEmail,
                displayName: pk.user?.displayName || cleanName,
              },
              pubKeyCredParams: Array.isArray(pk.pubKeyCredParams)
                ? pk.pubKeyCredParams
                : [
                    { type: 'public-key', alg: -7 },
                    { type: 'public-key', alg: -257 },
                  ],
              authenticatorSelection: pk.authenticatorSelection || {
                authenticatorAttachment: 'platform',
                userVerification: 'required',
                residentKey: 'required',
                requireResidentKey: true,
              },
              timeout: pk.timeout || 60000,
              attestation: 'none',
            },
          })) as PublicKeyCredential | null;

          if (created) {
            const attResp = created.response as AuthenticatorAttestationResponse & {
              getAuthenticatorData?: () => ArrayBuffer;
              getPublicKey?: () => ArrayBuffer | null;
              getPublicKeyAlgorithm?: () => number;
              getTransports?: () => string[];
            };
            const authDataBuf =
              typeof attResp.getAuthenticatorData === 'function'
                ? attResp.getAuthenticatorData()
                : undefined;
            const pubKeyBuf =
              typeof attResp.getPublicKey === 'function' ? attResp.getPublicKey() : null;
            const regVerifyRes = await fetch('/api/auth/webauthn/register-account/verify', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                challengeId: regOptData.challengeId,
                credentialId: arrayBufferToBase64Url(created.rawId),
                clientDataJSON: arrayBufferToBase64Url(attResp.clientDataJSON),
                attestationObject: arrayBufferToBase64Url(attResp.attestationObject),
                authenticatorData: authDataBuf
                  ? arrayBufferToBase64Url(authDataBuf)
                  : undefined,
                publicKeySpkiBase64: pubKeyBuf ? arrayBufferToBase64Url(pubKeyBuf) : undefined,
                coseAlgorithm:
                  typeof attResp.getPublicKeyAlgorithm === 'function'
                    ? attResp.getPublicKeyAlgorithm()
                    : -7,
                transports:
                  typeof attResp.getTransports === 'function'
                    ? attResp.getTransports()
                    : ['internal'],
                trustDevice,
              }),
            });
            const regVerifyData = await regVerifyRes.json();
            if (!regVerifyRes.ok) {
              setErrorMsg(
                regVerifyData?.error || 'Falha ao concluir o cadastro da Passkey/Windows Hello.'
              );
              return;
            }
            setInfoMsg('Conta e Passkey Windows Hello criadas com sucesso. Abrindo workspace...');
            await persistTokensAndComplete(regVerifyData);
            return;
          }
        } catch (regErr: unknown) {
          const errName = regErr instanceof Error ? regErr.name : '';
          if (errName === 'NotAllowedError' && !accessPolicy?.windowsHelloNativeSupported) {
            setErrorMsg(
              'Cadastro de Passkey / Windows Hello cancelado ou nenhum autenticador biométrico configurado neste dispositivo.'
            );
            return;
          }
          webAuthnFailedOrBlocked = true;
        }
      } else {
        webAuthnFailedOrBlocked = true;
      }

      if (webAuthnFailedOrBlocked && accessPolicy?.windowsHelloNativeSupported) {
        const nativeRegRes = await fetch('/api/auth/windows-hello/native-register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: cleanName,
            email: cleanEmail,
            trustDevice,
          }),
        });
        const nativeRegData = await nativeRegRes.json();
        if (!nativeRegRes.ok) {
          if (nativeRegRes.status === 409) {
            setHelloMode('LOGIN');
          }
          setErrorMsg(
            nativeRegData?.error ||
              'Não foi possível cadastrar o Windows Hello nativo neste dispositivo.'
          );
          return;
        }
        setInfoMsg('Conta cadastrada via Windows Hello nativo. Abrindo workspace...');
        await persistTokensAndComplete(nativeRegData);
        return;
      }

      if (inIframe) {
        setErrorMsg(
          'Navegadores bloqueiam criação de Passkey WebAuthn dentro de iframes de preview. Abra o WinHood em aba dedicada ou use "Continuar no Workspace Local (1 clique)" / "Entrar ou Cadastrar com GitHub".'
        );
        return;
      }

      setErrorMsg(
        'Nenhum autenticador biométrico WebAuthn/Windows Hello disponível neste dispositivo.'
      );
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error
          ? err.message
          : 'Erro ao cadastrar conta com Windows Hello / Passkey.'
      );
    } finally {
      setSubmitting(false);
    }
  };

  const handleTeamAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setInfoMsg(null);

    const cleanEmail = emailInput.trim();
    if (!cleanEmail) {
      setErrorMsg('Informe um endereço de e-mail válido.');
      return;
    }

    if (teamAction === 'REGISTER') {
      if (nameInput.trim().length < 2) {
        setErrorMsg('Informe seu nome de exibição (mínimo 2 caracteres).');
        return;
      }
      if (passwordInput.length < 10) {
        setErrorMsg('A senha deve possuir no mínimo 10 caracteres.');
        return;
      }
    } else if (teamMethod === 'PIN') {
      if (!/^\d{6,8}$/.test(pinInput.trim())) {
        setErrorMsg('Informe um PIN numérico válido de 6 a 8 dígitos.');
        return;
      }
    } else if (!passwordInput) {
      setErrorMsg('Informe sua senha de acesso.');
      return;
    }

    setSubmitting(true);
    try {
      const endpoint =
        teamAction === 'REGISTER'
          ? '/api/auth/register'
          : teamMethod === 'PIN'
            ? '/api/auth/login-pin'
            : '/api/auth/login';

      const payload =
        teamAction === 'REGISTER'
          ? {
              name: nameInput.trim(),
              email: cleanEmail,
              password: passwordInput,
              enableMfa: false,
            }
          : teamMethod === 'PIN'
            ? {
                email: cleanEmail,
                pin: pinInput.trim(),
                trustDevice,
              }
            : {
                email: cleanEmail,
                password: passwordInput,
                trustDevice,
              };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data?.error || 'Credenciais inválidas ou operação não autorizada.');
        return;
      }
      if (data.requiresTotp || data.mfaRequired) {
        setPreAuthToken(data.preAuthToken || null);
        setMfaCode('');
        setRecoveryBackupCode('');
        setUseRecoveryCode(false);
        setShowMfaChallenge(true);
        setInfoMsg('Informe o código TOTP de 6 dígitos do seu aplicativo autenticador.');
        return;
      }
      await persistTokensAndComplete(data);
    } catch {
      setErrorMsg('Erro de comunicação com o servidor de autenticação.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleVerifyMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (mfaSubmittingRef.current) return;

    const cleanTotp = mfaCode.replace(/\D/g, '').slice(0, 6);
    const cleanRecovery = recoveryBackupCode.trim();

    if (!useRecoveryCode && cleanTotp.length !== 6) {
      setErrorMsg('Informe os 6 dígitos numéricos do seu aplicativo autenticador.');
      return;
    }
    if (useRecoveryCode && cleanRecovery.replace(/[\s-]/g, '').length < 8) {
      setErrorMsg('Informe um código de recuperação válido (XXXX-XXXX).');
      return;
    }

    mfaSubmittingRef.current = true;
    setErrorMsg(null);
    setSubmitting(true);
    try {
      const endpoint = preAuthToken ? '/api/auth/totp/authenticate' : '/api/auth/mfa/verify';
      const payload = preAuthToken
        ? {
            preAuthToken,
            totpCode: useRecoveryCode ? undefined : cleanTotp,
            recoveryCode: useRecoveryCode ? cleanRecovery : undefined,
            trustDevice,
          }
        : {
            totpCode: useRecoveryCode ? '' : cleanTotp,
            recoveryCode: useRecoveryCode ? cleanRecovery : undefined,
            trustDevice,
          };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data?.error || 'Código TOTP inválido ou expirado.');
        return;
      }
      await persistTokensAndComplete(data);
    } catch {
      setErrorMsg('Erro de comunicação ao verificar código MFA.');
    } finally {
      mfaSubmittingRef.current = false;
      setSubmitting(false);
    }
  };

  const handleCancelMfa = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    clearClientAuthTokens();
    setPreAuthToken(null);
    setShowMfaChallenge(false);
    setErrorMsg(null);
    setInfoMsg(null);
    await onRefreshSession();
  };

  const vaultLocked = Boolean(accessPolicy?.vaultLockEnabled);
  const soloLocalAvailable = Boolean(accessPolicy?.soloLocalAllowed);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="winhood-auth-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/92 p-4 overflow-y-auto"
    >
      <div className="w-full max-w-[460px] rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0c1017] shadow-2xl overflow-hidden my-auto">
        {/* Clean Single-Elevation Header */}
        <header className="px-6 pt-6 pb-5 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
          <div className="flex items-center gap-3.5">
            <WinHoodLogo size={38} className="shrink-0" />
            <div className="min-w-0">
              <h1
                id="winhood-auth-title"
                className="text-lg font-bold tracking-tight text-slate-950 dark:text-slate-50"
              >
                {showMfaChallenge
                  ? 'Verificação em Duas Etapas'
                  : 'Acessar WinHood Platform'}
              </h1>
              <p className="mt-0.5 text-xs leading-snug text-slate-700 dark:text-slate-300">
                Autenticação segura para análise e benchmarking de software
              </p>
            </div>
          </div>
        </header>

        {/* Progressive Single-Card Body */}
        <div className="p-5 space-y-4">
          {/* Accessible Live Status / Error Region */}
          <div aria-live="polite" className="space-y-2.5 empty:hidden">
            {errorMsg && (
              <div
                role="alert"
                className="p-3.5 rounded-lg border border-rose-600/50 dark:border-rose-400/50 bg-rose-50 dark:bg-rose-950/50 text-xs leading-relaxed text-rose-950 dark:text-rose-100 flex items-start gap-2.5"
              >
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-700 dark:text-rose-300" aria-hidden="true" />
                <span>{errorMsg}</span>
              </div>
            )}

            {infoMsg && (
              <div
                role="status"
                className="p-3.5 rounded-lg border border-teal-700/40 dark:border-teal-400/40 bg-teal-50 dark:bg-teal-950/40 text-xs leading-relaxed text-teal-950 dark:text-teal-100 flex items-start gap-2.5"
              >
                <ShieldCheck className="w-4 h-4 shrink-0 mt-0.5 text-teal-700 dark:text-teal-300" aria-hidden="true" />
                <span>{infoMsg}</span>
              </div>
            )}
          </div>

          {showMfaChallenge ? (
            <form onSubmit={handleVerifyMfaSubmit} className="space-y-4">
              {pendingUser && (
                <p className="text-xs text-slate-800 dark:text-slate-200">
                  Confirmando identidade para{' '}
                  <strong className="font-semibold text-slate-950 dark:text-white">
                    {pendingUser.email}
                  </strong>
                </p>
              )}

              {!useRecoveryCode ? (
                <div className="space-y-1.5">
                  <label
                    htmlFor="winhood-mfa-code"
                    className="block text-xs font-semibold text-slate-900 dark:text-slate-100"
                  >
                    Código TOTP de 6 dígitos
                  </label>
                  <input
                    id="winhood-mfa-code"
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    placeholder="000000"
                    className={`w-full px-3.5 py-2.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] text-slate-950 dark:text-slate-50 font-mono text-base tracking-[0.35em] text-center tabular-nums ${FOCUS_RING}`}
                    required
                  />
                </div>
              ) : (
                <div className="space-y-1.5">
                  <label
                    htmlFor="winhood-recovery-code"
                    className="block text-xs font-semibold text-slate-900 dark:text-slate-100"
                  >
                    Código de recuperação de uso único
                  </label>
                  <input
                    id="winhood-recovery-code"
                    type="text"
                    value={recoveryBackupCode}
                    onChange={(e) => setRecoveryBackupCode(e.target.value.toUpperCase())}
                    placeholder="XXXX-XXXX"
                    className={`w-full px-3.5 py-2.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] text-slate-950 dark:text-slate-50 font-mono text-sm tracking-widest text-center ${FOCUS_RING}`}
                    required
                  />
                </div>
              )}

              <button
                type="submit"
                disabled={submitting}
                className={`w-full min-h-[44px] px-4 py-2.5 rounded-lg text-sm font-bold bg-[#14b8a6] hover:bg-[#0d9488] dark:bg-[#31d6c4] dark:hover:bg-[#22c4b2] text-slate-950 transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
              >
                {submitting ? 'Verificando...' : 'Confirmar código'}
              </button>

              <div className="flex items-center justify-between pt-1 text-xs">
                <button
                  type="button"
                  onClick={() => {
                    setUseRecoveryCode((v) => !v);
                    setErrorMsg(null);
                  }}
                  className={`font-medium text-teal-800 dark:text-teal-300 hover:underline cursor-pointer ${FOCUS_RING} rounded`}
                >
                  {useRecoveryCode ? 'Usar código TOTP de 6 dígitos' : 'Usar código de recuperação'}
                </button>
                <button
                  type="button"
                  onClick={handleCancelMfa}
                  className={`inline-flex items-center gap-1 font-medium text-slate-700 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white cursor-pointer ${FOCUS_RING} rounded`}
                >
                  <LogOut className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Voltar</span>
                </button>
              </div>
            </form>
          ) : (
            <>
              {/* Primary Zero-Friction Actions (single clear primary CTA matching real access mode) */}
              <div className="space-y-3">
                {soloLocalAvailable ? (
                  <button
                    type="button"
                    disabled={submitting}
                    onClick={handleSoloLocalWorkspace}
                    aria-label="Continuar no Workspace Local em 1 clique"
                    className={`w-full min-h-[44px] px-4 py-2.5 rounded-lg text-sm font-bold bg-[#14b8a6] hover:bg-[#0d9488] dark:bg-[#31d6c4] dark:hover:bg-[#22c4b2] text-slate-950 flex items-center justify-center gap-2 transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
                  >
                    <Laptop className="w-4 h-4 shrink-0" aria-hidden="true" />
                    <span>Continuar no Workspace Local (1 clique)</span>
                  </button>
                ) : vaultLocked ? (
                  <button
                    type="button"
                    disabled={submitting}
                    onClick={() => {
                      setShowWindowsHelloPanel((prev) => {
                        const next = !prev;
                        if (next) {
                          setShowGitHubUnavailableNotice(false);
                          setGhDevice(null);
                          setOauthPendingState(null);
                          setInfoMsg(null);
                        }
                        return next;
                      });
                      setErrorMsg(null);
                    }}
                    aria-label="Entrar ou cadastrar com Windows Hello Passkey"
                    aria-expanded={showWindowsHelloPanel}
                    className={`w-full min-h-[44px] px-4 py-2.5 rounded-lg text-sm font-bold bg-[#14b8a6] hover:bg-[#0d9488] dark:bg-[#31d6c4] dark:hover:bg-[#22c4b2] text-slate-950 flex items-center justify-center gap-2 transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
                  >
                    <Fingerprint className="w-4 h-4 shrink-0" aria-hidden="true" />
                    <span>Entrar ou Cadastrar com Windows Hello</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    data-testid="github-oauth-login-btn"
                    disabled={submitting}
                    onClick={handleGitHubDirectAuth}
                    aria-label={resolveGitHubOAuthCtaLabel({
                      redirecting: false,
                      signupAllowed: accessPolicy?.githubSignupAllowed,
                    })}
                    aria-expanded={
                      showGitHubUnavailableNotice || Boolean(oauthPendingState)
                    }
                    className={`w-full min-h-[44px] px-4 py-2.5 rounded-lg text-sm font-bold bg-[#14b8a6] hover:bg-[#0d9488] dark:bg-[#31d6c4] dark:hover:bg-[#22c4b2] text-slate-950 flex items-center justify-center gap-2 transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
                  >
                    <Github className="w-4 h-4 shrink-0" aria-hidden="true" />
                    <span>
                      {resolveGitHubOAuthCtaLabel({
                        redirecting: redirectingToGitHub,
                        signupAllowed: accessPolicy?.githubSignupAllowed,
                      })}
                    </span>
                  </button>
                )}

                {(soloLocalAvailable || vaultLocked) && (
                  <button
                    type="button"
                    data-testid="github-oauth-login-btn"
                    disabled={submitting}
                    onClick={handleGitHubDirectAuth}
                    aria-label={resolveGitHubOAuthCtaLabel({
                      redirecting: false,
                      signupAllowed: accessPolicy?.githubSignupAllowed,
                    })}
                    aria-expanded={
                      showGitHubUnavailableNotice || Boolean(oauthPendingState)
                    }
                    className={`w-full min-h-[44px] px-4 py-2.5 rounded-lg text-sm font-semibold border border-slate-300 dark:border-slate-700 bg-slate-50 hover:bg-slate-100 dark:bg-[#111827] dark:hover:bg-[#1a2234] text-slate-950 dark:text-slate-50 flex items-center justify-center gap-2 transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
                  >
                    <Github className="w-4 h-4 shrink-0" aria-hidden="true" />
                    <span>
                      {resolveGitHubOAuthCtaLabel({
                        redirecting: redirectingToGitHub,
                        signupAllowed: accessPolicy?.githubSignupAllowed,
                      })}
                    </span>
                  </button>
                )}

                {/* Pending GitHub OAuth 2.0 PKCE Browser Authorization Card */}
                {oauthPendingState && (
                  <section
                    aria-label="Autorização GitHub OAuth em andamento"
                    className="p-3.5 rounded-lg border border-teal-700/40 dark:border-teal-400/40 bg-slate-50 dark:bg-[#080b10] space-y-2.5"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold text-slate-950 dark:text-slate-50">
                        Aguardando confirmação no GitHub...
                      </span>
                      <button
                        type="button"
                        onClick={stopGitHubOAuthPolling}
                        className={`text-xs font-medium text-slate-700 dark:text-slate-300 hover:underline cursor-pointer rounded ${FOCUS_RING}`}
                      >
                        Cancelar
                      </button>
                    </div>
                    <a
                      href={oauthPendingState.authorizeUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className={`w-full min-h-[40px] px-3 py-2 rounded-lg text-xs font-bold bg-slate-900 hover:bg-slate-800 dark:bg-slate-100 dark:hover:bg-white text-white dark:text-slate-950 flex items-center justify-center gap-1.5 transition-colors ${FOCUS_RING}`}
                    >
                      <span>Continuar autorização no GitHub</span>
                      <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
                    </a>
                  </section>
                )}

                {/* Friendly Notice when Admin has not configured GitHub OAuth (No PAT/Client ID fields for end users) */}
                {showGitHubUnavailableNotice && githubOAuthStatus === 'NOT_CONFIGURED' && (
                  <section
                    role="status"
                    aria-label="Login com GitHub indisponível"
                    className="p-3.5 rounded-lg border border-amber-500/40 bg-amber-50 dark:bg-amber-950/30 space-y-2"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-start gap-2 text-xs text-amber-950 dark:text-amber-100">
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" aria-hidden="true" />
                        <div className="space-y-1">
                          <div className="font-bold">{GITHUB_OAUTH_UNAVAILABLE_NOTICE.title}</div>
                          <p className="leading-relaxed text-amber-900/90 dark:text-amber-200/90">
                            {GITHUB_OAUTH_UNAVAILABLE_NOTICE.description}{' '}
                            {GITHUB_OAUTH_UNAVAILABLE_NOTICE.guidance}
                          </p>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => setShowGitHubUnavailableNotice(false)}
                        className={`text-xs font-medium text-amber-900 dark:text-amber-200 hover:underline cursor-pointer rounded shrink-0 ${FOCUS_RING}`}
                      >
                        Fechar
                      </button>
                    </div>
                  </section>
                )}

                {!vaultLocked && (
                  <button
                    type="button"
                    disabled={submitting}
                    onClick={() => {
                      setShowWindowsHelloPanel((prev) => {
                        const next = !prev;
                        if (next) {
                          setShowGitHubUnavailableNotice(false);
                          setGhDevice(null);
                          setOauthPendingState(null);
                          setInfoMsg(null);
                        }
                        return next;
                      });
                      setErrorMsg(null);
                    }}
                    aria-label="Entrar ou cadastrar com Windows Hello Passkey"
                    aria-expanded={showWindowsHelloPanel}
                    className={`w-full min-h-[44px] px-4 py-2.5 rounded-lg text-sm font-semibold border border-slate-300 dark:border-slate-700 bg-white hover:bg-slate-50 dark:bg-[#111827] dark:hover:bg-[#1a2234] text-slate-900 dark:text-slate-100 flex items-center justify-center gap-2 transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
                  >
                    <Fingerprint className="w-4 h-4 shrink-0" aria-hidden="true" />
                    <span>Entrar ou Cadastrar com Windows Hello</span>
                  </button>
                )}

                {/* Accessible Tabbed Windows Hello / Passkey Panel (Login & Register) */}
                {showWindowsHelloPanel && (
                  <section
                    aria-label="Entrar ou criar conta com Windows Hello ou Passkey"
                    className="p-3.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] space-y-3"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold text-slate-950 dark:text-slate-50">
                        Windows Hello / Passkey FIDO2
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          setShowWindowsHelloPanel(false);
                          setErrorMsg(null);
                          setInfoMsg(null);
                        }}
                        className={`text-xs font-medium text-slate-700 dark:text-slate-300 hover:underline cursor-pointer rounded ${FOCUS_RING}`}
                      >
                        Fechar
                      </button>
                    </div>

                    <div
                      role="tablist"
                      aria-label="Modo de acesso Windows Hello"
                      className="grid grid-cols-2 gap-1 p-1 rounded-lg bg-slate-200/80 dark:bg-[#0c1017] border border-slate-300 dark:border-slate-800"
                    >
                      <button
                        type="button"
                        role="tab"
                        aria-selected={helloMode === 'LOGIN'}
                        onClick={() => {
                          setHelloMode('LOGIN');
                          setErrorMsg(null);
                        }}
                        className={`py-1.5 px-2.5 rounded-md text-xs font-semibold transition-colors cursor-pointer ${FOCUS_RING} ${
                          helloMode === 'LOGIN'
                            ? 'bg-white dark:bg-slate-800 text-slate-950 dark:text-white shadow-xs'
                            : 'text-slate-700 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white'
                        }`}
                      >
                        Entrar
                      </button>
                      <button
                        type="button"
                        role="tab"
                        aria-selected={helloMode === 'REGISTER'}
                        aria-label="Criar Conta com Windows Hello"
                        onClick={() => {
                          setHelloMode('REGISTER');
                          setErrorMsg(null);
                        }}
                        className={`py-1.5 px-2.5 rounded-md text-xs font-semibold whitespace-nowrap transition-colors cursor-pointer ${FOCUS_RING} ${
                          helloMode === 'REGISTER'
                            ? 'bg-white dark:bg-slate-800 text-slate-950 dark:text-white shadow-xs'
                            : 'text-slate-700 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white'
                        }`}
                      >
                        Criar Conta
                      </button>
                    </div>

                    {helloMode === 'LOGIN' ? (
                      <form onSubmit={handleWindowsHelloLogin} className="space-y-2.5">
                        <div className="space-y-1">
                          <label
                            htmlFor="winhood-hello-login-email"
                            className="block text-xs font-semibold text-slate-900 dark:text-slate-100"
                          >
                            E-mail da conta (opcional para Passkey residente)
                          </label>
                          <input
                            id="winhood-hello-login-email"
                            type="email"
                            autoComplete="username webauthn"
                            value={helloEmailInput}
                            onChange={(e) => setHelloEmailInput(e.target.value)}
                            placeholder="operador@empresa.com"
                            className={`w-full min-h-[42px] px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0c1017] text-sm text-slate-950 dark:text-slate-50 placeholder:text-slate-500 dark:placeholder:text-slate-400 ${FOCUS_RING}`}
                          />
                        </div>
                        <button
                          type="submit"
                          disabled={submitting}
                          className={`w-full min-h-[44px] px-4 py-2 rounded-lg text-xs font-bold bg-slate-900 hover:bg-slate-800 dark:bg-slate-100 dark:hover:bg-white text-white dark:text-slate-950 transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
                        >
                          {submitting
                            ? 'Aguardando Windows Hello...'
                            : 'Desbloquear com Windows Hello'}
                        </button>
                      </form>
                    ) : (
                      <form onSubmit={handleWindowsHelloRegister} className="space-y-2.5">
                        <div className="space-y-1">
                          <label
                            htmlFor="winhood-hello-reg-name"
                            className="block text-xs font-semibold text-slate-900 dark:text-slate-100"
                          >
                            Nome completo
                          </label>
                          <input
                            id="winhood-hello-reg-name"
                            type="text"
                            autoComplete="name"
                            value={helloNameInput}
                            onChange={(e) => setHelloNameInput(e.target.value)}
                            placeholder="Engenheiro(a) de Segurança"
                            className={`w-full min-h-[42px] px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0c1017] text-sm text-slate-950 dark:text-slate-50 placeholder:text-slate-500 dark:placeholder:text-slate-400 ${FOCUS_RING}`}
                            required
                          />
                        </div>
                        <div className="space-y-1">
                          <label
                            htmlFor="winhood-hello-reg-email"
                            className="block text-xs font-semibold text-slate-900 dark:text-slate-100"
                          >
                            E-mail da conta
                          </label>
                          <input
                            id="winhood-hello-reg-email"
                            type="email"
                            autoComplete="email"
                            value={helloEmailInput}
                            onChange={(e) => setHelloEmailInput(e.target.value)}
                            placeholder="operador@empresa.com"
                            className={`w-full min-h-[42px] px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0c1017] text-sm text-slate-950 dark:text-slate-50 placeholder:text-slate-500 dark:placeholder:text-slate-400 ${FOCUS_RING}`}
                            required
                          />
                        </div>
                        <button
                          type="submit"
                          disabled={submitting}
                          className={`w-full min-h-[44px] px-4 py-2 rounded-lg text-xs font-bold bg-slate-900 hover:bg-slate-800 dark:bg-slate-100 dark:hover:bg-white text-white dark:text-slate-950 transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
                        >
                          {submitting
                            ? 'Registrando Passkey...'
                            : 'Criar Conta e Registrar Windows Hello'}
                        </button>
                      </form>
                    )}
                  </section>
                )}

                {!soloLocalAvailable && !vaultLocked && (
                  <button
                    type="button"
                    disabled={submitting}
                    onClick={handleSoloLocalWorkspace}
                    aria-label="Continuar no Workspace Local Desktop"
                    className={`w-full min-h-[40px] px-4 py-2 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-800 bg-transparent hover:bg-slate-50 dark:hover:bg-slate-900/60 text-slate-700 dark:text-slate-300 flex items-center justify-center gap-2 transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
                  >
                    <Laptop className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                    <span>Continuar no Workspace Local (Desktop Electron)</span>
                  </button>
                )}

                {accessPolicy && !soloLocalAvailable && !vaultLocked && (
                  <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                    Modo atual: <span className="font-mono font-semibold">{accessPolicy.mode}</span> —{' '}
                    {accessPolicy.reason}
                  </p>
                )}
              </div>

              {/* Active GitHub OAuth Device Flow Verification Panel */}
              {ghDevice && (
                <section
                  aria-label="Código de verificação GitHub Device Flow"
                  className="p-4 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] space-y-3"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                      Código de Dispositivo GitHub
                    </span>
                    <button
                      type="button"
                      onClick={stopGitHubPolling}
                      className={`text-xs font-medium text-slate-700 dark:text-slate-300 hover:underline cursor-pointer rounded ${FOCUS_RING}`}
                    >
                      Cancelar
                    </button>
                  </div>

                  <div className="flex items-center justify-between gap-2 px-3.5 py-2.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0c1017]">
                    <code className="text-lg font-mono font-bold tracking-[0.2em] text-slate-950 dark:text-slate-50 tabular-nums">
                      {ghDevice.userCode}
                    </code>
                    <button
                      type="button"
                      onClick={handleCopyDeviceCode}
                      aria-label="Copiar código de verificação GitHub"
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer ${FOCUS_RING}`}
                    >
                      {copiedDeviceCode ? (
                        <>
                          <Check className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Copiado</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Copiar</span>
                        </>
                      )}
                    </button>
                  </div>

                  <a
                    href={ghDevice.verificationUri}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={`w-full min-h-[40px] px-3 py-2 rounded-lg text-xs font-bold bg-slate-900 hover:bg-slate-800 dark:bg-slate-100 dark:hover:bg-white text-white dark:text-slate-950 flex items-center justify-center gap-1.5 transition-colors ${FOCUS_RING}`}
                  >
                    <span>Abrir {ghDevice.verificationUri}</span>
                    <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
                  </a>
                </section>
              )}

              {/* Progressive Disclosure for Team Server Credentials */}
              <details
                className="group border-t border-slate-200 dark:border-slate-800 pt-4"
                open={Boolean(accessPolicy?.teamServerMode && !accessPolicy?.githubDeviceFlowConfigured)}
              >
                <summary
                  className={`flex items-center justify-between cursor-pointer select-none text-xs font-semibold text-slate-800 dark:text-slate-200 py-1.5 rounded list-none ${FOCUS_RING}`}
                >
                  <span className="inline-flex items-center gap-2">
                    <KeyRound className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                    <span>Acesso avançado (Servidor de Equipe)</span>
                  </span>
                  <ChevronRight
                    className="w-4 h-4 shrink-0 transition-transform duration-150 group-open:rotate-90"
                    aria-hidden="true"
                  />
                </summary>

                <div className="pt-4 space-y-4">
                  {/* Segmented Action Control: Entrar / Criar Conta */}
                  <div
                    role="group"
                    aria-label="Modo de credencial de equipe"
                    className="grid grid-cols-2 gap-1 p-1 rounded-lg bg-slate-100 dark:bg-[#080b10] border border-slate-200 dark:border-slate-800"
                  >
                    <button
                      type="button"
                      onClick={() => {
                        setTeamAction('LOGIN');
                        setErrorMsg(null);
                      }}
                      className={`py-2 px-3 rounded-md text-xs font-semibold transition-colors cursor-pointer ${FOCUS_RING} ${
                        teamAction === 'LOGIN'
                          ? 'bg-white dark:bg-slate-800 text-slate-950 dark:text-white shadow-xs'
                          : 'text-slate-700 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white'
                      }`}
                    >
                      Entrar com credencial
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setTeamAction('REGISTER');
                        setTeamMethod('PASSWORD');
                        setErrorMsg(null);
                      }}
                      className={`py-2 px-3 rounded-md text-xs font-semibold transition-colors cursor-pointer ${FOCUS_RING} ${
                        teamAction === 'REGISTER'
                          ? 'bg-white dark:bg-slate-800 text-slate-950 dark:text-white shadow-xs'
                          : 'text-slate-700 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white'
                      }`}
                    >
                      Criar conta local
                    </button>
                  </div>

                  {teamAction === 'LOGIN' && (
                    <div
                      role="group"
                      aria-label="Método de autenticação"
                      className="flex items-center gap-2 text-xs"
                    >
                      <button
                        type="button"
                        onClick={() => {
                          setTeamMethod('PASSWORD');
                          setErrorMsg(null);
                        }}
                        className={`flex-1 py-1.5 px-3 rounded-md border font-medium flex items-center justify-center gap-1.5 cursor-pointer transition-colors ${FOCUS_RING} ${
                          teamMethod === 'PASSWORD'
                            ? 'border-teal-700 dark:border-teal-400 bg-teal-50 dark:bg-teal-950/40 text-teal-950 dark:text-teal-100'
                            : 'border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300'
                        }`}
                      >
                        <Lock className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>E-mail + Senha</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setTeamMethod('PIN');
                          setErrorMsg(null);
                        }}
                        className={`flex-1 py-1.5 px-3 rounded-md border font-medium flex items-center justify-center gap-1.5 cursor-pointer transition-colors ${FOCUS_RING} ${
                          teamMethod === 'PIN'
                            ? 'border-teal-700 dark:border-teal-400 bg-teal-50 dark:bg-teal-950/40 text-teal-950 dark:text-teal-100'
                            : 'border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300'
                        }`}
                      >
                        <Hash className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>PIN (6–8 dígitos)</span>
                      </button>
                    </div>
                  )}

                  <form onSubmit={handleTeamAuthSubmit} className="space-y-3.5">
                    {teamAction === 'REGISTER' && (
                      <div className="space-y-1">
                        <label
                          htmlFor="winhood-team-name"
                          className="block text-xs font-semibold text-slate-900 dark:text-slate-100"
                        >
                          Nome completo
                        </label>
                        <input
                          id="winhood-team-name"
                          type="text"
                          autoComplete="name"
                          value={nameInput}
                          onChange={(e) => setNameInput(e.target.value)}
                          placeholder="Engenheiro(a) de Segurança"
                          className={`w-full min-h-[42px] px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] text-sm text-slate-950 dark:text-slate-50 placeholder:text-slate-500 dark:placeholder:text-slate-400 ${FOCUS_RING}`}
                          required
                        />
                      </div>
                    )}

                    <div className="space-y-1">
                      <label
                        htmlFor="winhood-team-email"
                        className="block text-xs font-semibold text-slate-900 dark:text-slate-100"
                      >
                        E-mail corporativo
                      </label>
                      <input
                        id="winhood-team-email"
                        type="email"
                        autoComplete="email"
                        value={emailInput}
                        onChange={(e) => setEmailInput(e.target.value)}
                        placeholder="operador@empresa.com"
                        className={`w-full min-h-[42px] px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] text-sm text-slate-950 dark:text-slate-50 placeholder:text-slate-500 dark:placeholder:text-slate-400 ${FOCUS_RING}`}
                        required
                      />
                    </div>

                    {teamAction === 'LOGIN' && teamMethod === 'PIN' ? (
                      <div className="space-y-1">
                        <label
                          htmlFor="winhood-team-pin"
                          className="block text-xs font-semibold text-slate-900 dark:text-slate-100"
                        >
                          PIN numérico (6 a 8 dígitos)
                        </label>
                        <input
                          id="winhood-team-pin"
                          type="password"
                          inputMode="numeric"
                          autoComplete="current-password"
                          maxLength={8}
                          value={pinInput}
                          onChange={(e) => setPinInput(e.target.value.replace(/\D/g, '').slice(0, 8))}
                          placeholder="••••••"
                          className={`w-full min-h-[42px] px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] text-sm font-mono tracking-widest text-slate-950 dark:text-slate-50 placeholder:text-slate-500 dark:placeholder:text-slate-400 tabular-nums ${FOCUS_RING}`}
                          required
                        />
                      </div>
                    ) : (
                      <div className="space-y-1">
                        <label
                          htmlFor="winhood-team-password"
                          className="block text-xs font-semibold text-slate-900 dark:text-slate-100"
                        >
                          Senha {teamAction === 'REGISTER' ? '(mínimo 10 caracteres)' : ''}
                        </label>
                        <div className="relative">
                          <input
                            id="winhood-team-password"
                            type={showPassword ? 'text' : 'password'}
                            autoComplete={
                              teamAction === 'REGISTER' ? 'new-password' : 'current-password'
                            }
                            value={passwordInput}
                            onChange={(e) => setPasswordInput(e.target.value)}
                            placeholder="Digite sua senha"
                            className={`w-full min-h-[42px] pl-3 pr-10 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] text-sm text-slate-950 dark:text-slate-50 placeholder:text-slate-500 dark:placeholder:text-slate-400 ${FOCUS_RING}`}
                            required
                          />
                          <button
                            type="button"
                            onClick={() => setShowPassword((v) => !v)}
                            aria-label={showPassword ? 'Ocultar senha' : 'Mostrar senha'}
                            className={`absolute right-2 top-1/2 -translate-y-1/2 p-1.5 rounded text-slate-700 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white cursor-pointer ${FOCUS_RING}`}
                          >
                            {showPassword ? (
                              <EyeOff className="w-4 h-4" aria-hidden="true" />
                            ) : (
                              <Eye className="w-4 h-4" aria-hidden="true" />
                            )}
                          </button>
                        </div>
                      </div>
                    )}

                    <label className="flex items-center gap-2 text-xs text-slate-800 dark:text-slate-200 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={trustDevice}
                        onChange={(e) => setTrustDevice(e.target.checked)}
                        className={`w-4 h-4 rounded border-slate-400 dark:border-slate-600 accent-[#0d9488] ${FOCUS_RING}`}
                      />
                      <span>Manter dispositivo confiável (sessão HttpOnly de 30 dias)</span>
                    </label>

                    <button
                      type="submit"
                      disabled={submitting}
                      className={`w-full min-h-[44px] px-4 py-2.5 rounded-lg text-sm font-bold bg-slate-900 hover:bg-slate-800 dark:bg-slate-100 dark:hover:bg-white text-white dark:text-slate-950 transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
                    >
                      {submitting
                        ? 'Processando...'
                        : teamAction === 'REGISTER'
                          ? 'Criar conta e entrar'
                          : 'Entrar no Servidor de Equipe'}
                    </button>
                  </form>

                  <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                    MFA (TOTP), cadastro de PIN e permissões RBAC podem ser configurados em{' '}
                    <strong className="font-semibold text-slate-900 dark:text-slate-100">
                      Configurações da Conta
                    </strong>{' '}
                    após o acesso.
                  </p>

                  {/* Legacy / Technical Integration Compatibility (PAT / Device Flow) mounted only on explicit click */}
                  <div className="border-t border-slate-200 dark:border-slate-800 pt-3">
                    <button
                      type="button"
                      aria-expanded={showTechnicalGitHubCompat}
                      onClick={() => setShowTechnicalGitHubCompat((prev) => !prev)}
                      className={`w-full flex items-center justify-between cursor-pointer select-none text-[11px] font-semibold text-slate-600 dark:text-slate-400 py-1 rounded ${FOCUS_RING}`}
                    >
                      <span className="inline-flex items-center gap-1.5">
                        <Github className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                        <span>Compatibilidade técnica / CI (token ou Device Flow)</span>
                      </span>
                      <ChevronRight
                        className={`w-3.5 h-3.5 shrink-0 transition-transform duration-150 ${showTechnicalGitHubCompat ? 'rotate-90' : ''}`}
                        aria-hidden="true"
                      />
                    </button>

                    {showTechnicalGitHubCompat && (
                      <div className="pt-3 space-y-3">
                        <form onSubmit={handleGitHubPatLogin} className="space-y-2">
                          <label
                            htmlFor="winhood-github-pat"
                            className="block text-[11px] font-semibold text-slate-800 dark:text-slate-200"
                          >
                            Token de integração GitHub (uso técnico/CI)
                          </label>
                          <input
                            id="winhood-github-pat"
                            type="password"
                            autoComplete="off"
                            value={githubPatInput}
                            onChange={(e) => setGithubPatInput(e.target.value)}
                            placeholder="ghp_... ou github_pat_..."
                            className={`w-full min-h-[38px] px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0c1017] text-xs font-mono text-slate-950 dark:text-slate-50 ${FOCUS_RING}`}
                            required
                          />
                          <button
                            type="submit"
                            disabled={submitting}
                            className={`w-full min-h-[38px] px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 dark:bg-slate-100 dark:hover:bg-white text-white dark:text-slate-950 transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
                          >
                            {submitting ? 'Validando...' : 'Autenticar com token'}
                          </button>
                        </form>

                        <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-slate-800">
                          <label
                            htmlFor="winhood-github-client-id"
                            className="block text-[11px] font-semibold text-slate-800 dark:text-slate-200"
                          >
                            GitHub Device Flow (RFC 8628 — identificador opcional)
                          </label>
                          <input
                            id="winhood-github-client-id"
                            type="text"
                            autoComplete="off"
                            value={githubClientIdInput}
                            onChange={(e) => setGithubClientIdInput(e.target.value)}
                            placeholder="Ov23li..."
                            className={`w-full min-h-[38px] px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0c1017] text-xs font-mono text-slate-950 dark:text-slate-50 ${FOCUS_RING}`}
                          />
                          <button
                            type="button"
                            disabled={
                              submitting ||
                              (!accessPolicy?.githubDeviceFlowConfigured &&
                                githubClientIdInput.trim().length < 8)
                            }
                            onClick={() =>
                              handleStartGitHubDeviceFlow(githubClientIdInput.trim() || undefined)
                            }
                            className={`w-full min-h-[38px] px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 bg-white hover:bg-slate-100 dark:bg-[#111827] dark:hover:bg-[#1a2234] text-slate-900 dark:text-slate-100 transition-colors cursor-pointer disabled:opacity-50 ${FOCUS_RING}`}
                          >
                            Iniciar Device Flow (RFC 8628)
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </details>
            </>
          )}
        </div>

        {/* Quiet Accessible Footer */}
        <footer className="px-6 py-3.5 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] flex items-center justify-between text-xs text-slate-700 dark:text-slate-300">
          <span>WinHood Benchmarking v4.4.0</span>
          <button
            type="button"
            onClick={() => setIsPrivacyModalOpen(true)}
            className={`font-medium text-teal-800 dark:text-teal-300 hover:underline cursor-pointer rounded ${FOCUS_RING}`}
          >
            Privacidade e Segurança
          </button>
        </footer>
      </div>

      <PrivacyAndTermsModal
        isOpen={isPrivacyModalOpen}
        onClose={() => setIsPrivacyModalOpen(false)}
        initialTab="PRIVACY"
      />
    </div>
  );
};
