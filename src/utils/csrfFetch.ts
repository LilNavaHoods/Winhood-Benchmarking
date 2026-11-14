/**
 * Centralizador de origem HTTP, sessão híbrida (Cookie HttpOnly + Bearer Token fallback para iframes)
 * e interceptor CSRF para todas as chamadas à API do WinHood.
 */

declare global {
  interface Window {
    __WINHOOD_CSRF_TOKEN__?: string;
    __WINHOOD_SESSION_TOKEN__?: string;
    __WINHOOD_BACKEND_ORIGIN__?: string;
    winhoodDesktop?: {
      isElectron: boolean;
      platform: string;
      getBackendOrigin?: () => string;
      getRuntimeStatus?: () => Promise<any>;
    };
  }
}

const SESSION_STORAGE_KEY = 'winhood.auth.session_token';
const CSRF_STORAGE_KEY = 'winhood.auth.csrf_token';

function safeStorageGet(key: string): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.sessionStorage?.getItem(key) || window.localStorage?.getItem(key) || null;
  } catch {
    return null;
  }
}

function safeStorageSet(key: string, value: string | null | undefined, persist = true): void {
  if (typeof window === 'undefined') return;
  try {
    if (!value) {
      window.localStorage?.removeItem(key);
      window.sessionStorage?.removeItem(key);
      return;
    }
    window.sessionStorage?.setItem(key, value);
    if (persist) {
      window.localStorage?.setItem(key, value);
    } else {
      window.localStorage?.removeItem(key);
    }
  } catch {
    // Ignore storage quota/sandbox errors in restricted iframes
  }
}

export function setGlobalSessionToken(
  sessionToken: string | null | undefined,
  persist = true
): void {
  if (typeof window !== 'undefined') {
    window.__WINHOOD_SESSION_TOKEN__ = sessionToken || undefined;
    safeStorageSet(SESSION_STORAGE_KEY, sessionToken, persist);
  }
}

export function getGlobalSessionToken(): string | null {
  if (typeof window === 'undefined') return null;
  if (window.__WINHOOD_SESSION_TOKEN__) {
    return window.__WINHOOD_SESSION_TOKEN__;
  }
  const stored = safeStorageGet(SESSION_STORAGE_KEY);
  if (stored) {
    window.__WINHOOD_SESSION_TOKEN__ = stored;
    return stored;
  }
  return null;
}

export function setGlobalCsrfToken(token: string | null | undefined, persist = true): void {
  if (typeof window !== 'undefined') {
    window.__WINHOOD_CSRF_TOKEN__ = token || undefined;
    safeStorageSet(CSRF_STORAGE_KEY, token, persist);
  }
}

export function getGlobalCsrfToken(): string | undefined {
  if (typeof window === 'undefined') return undefined;
  if (window.__WINHOOD_CSRF_TOKEN__) {
    return window.__WINHOOD_CSRF_TOKEN__;
  }
  const stored = safeStorageGet(CSRF_STORAGE_KEY);
  if (stored) {
    window.__WINHOOD_CSRF_TOKEN__ = stored;
    return stored;
  }
  return undefined;
}

export function clearClientAuthTokens(): void {
  setGlobalSessionToken(null);
  setGlobalCsrfToken(null);
}

export function getCsrfTokenFromCookie(): string | null {
  const globalTok = getGlobalCsrfToken();
  if (globalTok) return globalTok;
  if (typeof document === 'undefined' || !document.cookie) return null;
  const match = document.cookie.match(/(?:^|;\s*)(?:winhood_csrf|csrf_token)=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

export function resolveApiBaseOrigin(): string {
  if (typeof window === 'undefined') return '';
  if (window.__WINHOOD_BACKEND_ORIGIN__) {
    let u = window.__WINHOOD_BACKEND_ORIGIN__;
    while (u.endsWith('/')) u = u.slice(0, -1);
    return u;
  }
  if (typeof window.winhoodDesktop?.getBackendOrigin === 'function') {
    const origin = window.winhoodDesktop.getBackendOrigin();
    if (origin && origin.startsWith('http')) {
      let u = origin;
      while (u.endsWith('/')) u = u.slice(0, -1);
      return u;
    }
  }
  return '';
}

const initialNativeFetch: typeof globalThis.fetch | null =
  typeof window !== 'undefined' && typeof window.fetch === 'function'
    ? window.fetch.bind(window)
    : typeof globalThis.fetch === 'function'
      ? globalThis.fetch.bind(globalThis)
      : null;

export async function csrfFetch(
  input: RequestInfo | URL,
  init?: RequestInit
): Promise<Response> {
  const currentWinFetch =
    typeof window !== 'undefined' &&
    typeof window.fetch === 'function' &&
    window.fetch !== csrfFetch
      ? window.fetch.bind(window)
      : initialNativeFetch || globalThis.fetch.bind(globalThis);

  let urlStr =
    typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.toString()
        : input.url;

  const baseOrigin = resolveApiBaseOrigin();
  if (baseOrigin && urlStr.startsWith('/api/')) {
    urlStr = `${baseOrigin}${urlStr}`;
    input = urlStr;
  }

  const isApiCall = urlStr.startsWith('/api/') || urlStr.includes('/api/');

  if (isApiCall) {
    const nextInit: RequestInit = { ...(init || {}) };
    if (!nextInit.credentials) {
      nextInit.credentials = 'include';
    }
    const headers = new Headers(nextInit.headers || {});

    // Injeta token de sessão via header para funcionar mesmo quando o navegador bloqueia cookies em iframe
    const sessionTok = getGlobalSessionToken();
    if (sessionTok) {
      if (!headers.has('Authorization') && !headers.has('authorization')) {
        headers.set('Authorization', `Bearer ${sessionTok}`);
      }
      if (!headers.has('X-WinHood-Session') && !headers.has('x-winhood-session')) {
        headers.set('X-WinHood-Session', sessionTok);
      }
    }

    const method = (nextInit.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      const csrf = getCsrfTokenFromCookie();
      if (csrf && !headers.has('X-CSRF-Token') && !headers.has('x-csrf-token')) {
        headers.set('X-CSRF-Token', csrf);
      }
    }

    nextInit.headers = headers;
    const response = await currentWinFetch(input, nextInit);

    // Captura automática de novos tokens caso venham nos headers de resposta
    const respSession = response.headers.get('x-winhood-session-token');
    const respCsrf = response.headers.get('x-winhood-csrf-token');
    if (respSession) setGlobalSessionToken(respSession);
    if (respCsrf) setGlobalCsrfToken(respCsrf);

    return response;
  }

  return currentWinFetch(input, init);
}

export function installGlobalCsrfFetchInterceptor(): void {
  if (typeof window === 'undefined' || (window as any).__WINHOOD_FETCH_PATCHED__) {
    return;
  }
  (window as any).__WINHOOD_FETCH_PATCHED__ = true;

  try {
    const ownDesc = Object.getOwnPropertyDescriptor(window, 'fetch');
    if (ownDesc && ownDesc.writable === true && !ownDesc.get) {
      Object.defineProperty(window, 'fetch', {
        value: csrfFetch,
        configurable: ownDesc.configurable ?? true,
        writable: true,
      });
    }
  } catch {
    // Ignorar silenciosamente em ambientes onde window.fetch é protegido por getter.
  }
}

installGlobalCsrfFetchInterceptor();
