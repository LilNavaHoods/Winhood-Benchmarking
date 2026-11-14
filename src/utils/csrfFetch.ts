/**
 * Centralizador de origem HTTP e interceptor CSRF para todas as chamadas à API do WinHood (Seção 4.3).
 * - Preserva `credentials: 'same-origin'` e cabeçalho `X-CSRF-Token` em todas as mutações.
 * - Suporta resolução automática de origem dinâmica quando executado dentro do Electron Desktop
 *   sem fixar portas ou endereços hardcoded nos componentes React.
 * - Compatível com ambientes de iframe/preview onde `window.fetch` possui apenas getter (sem atribuir `window.fetch = ...`).
 */

declare global {
  interface Window {
    __WINHOOD_CSRF_TOKEN__?: string;
    __WINHOOD_BACKEND_ORIGIN__?: string;
    winhoodDesktop?: {
      isElectron: boolean;
      platform: string;
      getBackendOrigin?: () => string;
      getRuntimeStatus?: () => Promise<any>;
    };
  }
}

export function setGlobalCsrfToken(token: string | null | undefined): void {
  if (typeof window !== 'undefined') {
    window.__WINHOOD_CSRF_TOKEN__ = token || undefined;
  }
}

export function getGlobalCsrfToken(): string | undefined {
  if (typeof window !== 'undefined') {
    return window.__WINHOOD_CSRF_TOKEN__;
  }
  return undefined;
}

export function getCsrfTokenFromCookie(): string | null {
  const globalTok = getGlobalCsrfToken();
  if (globalTok) return globalTok;
  if (typeof document === 'undefined' || !document.cookie) return null;
  const match = document.cookie.match(/(?:^|;\s*)(?:winhood_csrf|csrf_token)=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

/**
 * Resolve a origem da API de forma centralizada:
 * - No navegador / AI Studio Preview / servidor local Express: string vazia `''` (same-origin).
 * - No Electron caso a janela seja carregada de protocolo diferente de http(s), utiliza a origem
 *   exposta pelo preload (`winhoodDesktop.getBackendOrigin()`).
 */
export function resolveApiBaseOrigin(): string {
  if (typeof window === 'undefined') return '';
  if (window.__WINHOOD_BACKEND_ORIGIN__) {
    return window.__WINHOOD_BACKEND_ORIGIN__.replace(/\/+$/, '');
  }
  if (typeof window.winhoodDesktop?.getBackendOrigin === 'function') {
    const origin = window.winhoodDesktop.getBackendOrigin();
    if (origin && origin.startsWith('http')) {
      return origin.replace(/\/+$/, '');
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
    const method = (nextInit.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      const csrf = getCsrfTokenFromCookie();
      if (csrf) {
        const headers = new Headers(nextInit.headers || {});
        if (!headers.has('X-CSRF-Token') && !headers.has('x-csrf-token')) {
          headers.set('X-CSRF-Token', csrf);
        }
        nextInit.headers = headers;
      }
    }
    return currentWinFetch(input, nextInit);
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
    // Somente substitui se for uma propriedade de dados gravável (sem getter somente-leitura)
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
