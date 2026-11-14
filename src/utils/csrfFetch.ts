/**
 * Global same-origin fetch wrapper for WinHood:
 * - Always sends HttpOnly session cookies (`credentials: 'same-origin'`) for `/api/*`.
 * - Reads `winhood_csrf` cookie and attaches `x-csrf-token` on mutating requests.
 * - Emits `winhood:auth-required` on 401 responses from protected endpoints so the UI shows AuthGateModal.
 */

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const AUTH_EXEMPT_401_PATHS = [
  '/api/auth/login',
  '/api/auth/bootstrap-admin',
  '/api/auth/bootstrap-status',
  '/api/auth/session',
  '/api/auth/recovery/request',
  '/api/auth/recovery/confirm',
];

export function getCsrfTokenFromCookie(): string {
  if (typeof document === 'undefined') return '';
  const pairs = document.cookie ? document.cookie.split(';') : [];
  for (const part of pairs) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    if (key === 'winhood_csrf') {
      return decodeURIComponent(part.slice(idx + 1).trim());
    }
  }
  return '';
}

function isSameOriginApiRequest(input: RequestInfo | URL): { isApi: boolean; pathname: string } {
  try {
    const rawUrl =
      typeof input === 'string'
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    if (rawUrl.startsWith('/api/')) {
      return { isApi: true, pathname: rawUrl.split('?')[0] };
    }
    if (typeof window !== 'undefined') {
      const parsed = new URL(rawUrl, window.location.origin);
      if (parsed.origin === window.location.origin && parsed.pathname.startsWith('/api/')) {
        return { isApi: true, pathname: parsed.pathname };
      }
    }
  } catch {
    // Ignore malformed URLs
  }
  return { isApi: false, pathname: '' };
}

export function installCsrfFetchInterceptor(): void {
  const g = globalThis as typeof globalThis & { __winhoodCsrfFetchInstalled?: boolean };
  if (g.__winhoodCsrfFetchInstalled || typeof g.fetch !== 'function') return;

  const originalFetch = g.fetch.bind(g);
  g.__winhoodCsrfFetchInstalled = true;

  g.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const { isApi, pathname } = isSameOriginApiRequest(input);
    if (!isApi) {
      return originalFetch(input, init);
    }

    const method = (
      init?.method ||
      (typeof input !== 'string' && !(input instanceof URL) ? input.method : 'GET') ||
      'GET'
    ).toUpperCase();

    const headers = new Headers(
      init?.headers ||
        (typeof input !== 'string' && !(input instanceof URL) ? input.headers : undefined)
    );

    if (MUTATING_METHODS.has(method) && !headers.has('x-csrf-token')) {
      const csrf = getCsrfTokenFromCookie();
      if (csrf) {
        headers.set('x-csrf-token', csrf);
      }
    }

    const response = await originalFetch(input, {
      ...init,
      credentials: init?.credentials ?? 'same-origin',
      headers,
    });

    if (
      response.status === 401 &&
      typeof window !== 'undefined' &&
      !AUTH_EXEMPT_401_PATHS.some((exempt) => pathname.startsWith(exempt))
    ) {
      window.dispatchEvent(
        new CustomEvent('winhood:auth-required', { detail: { pathname, status: 401 } })
      );
    }

    return response;
  };
}

installCsrfFetchInterceptor();
