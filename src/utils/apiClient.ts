import { getCsrfTokenFromCookie } from './csrfFetch';

export interface ApiFetchOptions extends RequestInit {
  timeoutMs?: number;
}

export class ApiHttpError extends Error {
  public readonly status: number;
  public readonly url: string;
  public readonly details?: unknown;

  constructor(message: string, status: number, url: string, details?: unknown) {
    super(message);
    this.name = 'ApiHttpError';
    this.status = status;
    this.url = url;
    this.details = details;
  }
}

export function enforceStrictHttpsUrl(rawUrl: string): string {
  const trimmed = rawUrl.trim();
  if (trimmed.startsWith('/') || trimmed.startsWith('./')) {
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed);
    const isLocalhost =
      parsed.hostname === 'localhost' ||
      parsed.hostname === '127.0.0.1' ||
      parsed.hostname === '0.0.0.0';
    if (!isLocalhost && parsed.protocol === 'http:') {
      parsed.protocol = 'https:';
      return parsed.toString();
    }
    return parsed.toString();
  } catch {
    return trimmed;
  }
}

/**
 * Helper centralizado de requisição HTTP com AbortController, credenciais HttpOnly e CSRF.
 */
export async function apiFetchJson<T>(
  url: string,
  options?: ApiFetchOptions,
  timeoutMs: number = 15000
): Promise<T> {
  const secureUrl = enforceStrictHttpsUrl(url);
  const effectiveTimeout = options?.timeoutMs ?? timeoutMs;
  const controller = new AbortController();
  const timerId = globalThis.setTimeout(() => controller.abort(), effectiveTimeout);

  const method = (options?.method || 'GET').toUpperCase();
  const csrf = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)
    ? getCsrfTokenFromCookie()
    : '';

  try {
    const response = await fetch(secureUrl, {
      ...options,
      credentials: options?.credentials ?? 'same-origin',
      signal: options?.signal ?? controller.signal,
      headers: {
        Accept: 'application/json',
        ...(options?.body ? { 'Content-Type': 'application/json' } : {}),
        ...(csrf ? { 'x-csrf-token': csrf } : {}),
        ...(options?.headers ?? {}),
      },
    });

    if (response.status === 401 && typeof window !== 'undefined' && !secureUrl.includes('/api/auth/')) {
      window.dispatchEvent(
        new CustomEvent('winhood:auth-required', { detail: { pathname: secureUrl, status: 401 } })
      );
    }

    if (!response.ok) {
      let errorDetails: unknown = undefined;
      let serverMessage = `HTTP ${response.status} (${response.statusText || 'Erro na requisição'})`;
      try {
        const parsed = (await response.json()) as { error?: string; message?: string };
        errorDetails = parsed;
        if (parsed?.error) {
          serverMessage = parsed.error;
        } else if (parsed?.message) {
          serverMessage = parsed.message;
        }
      } catch {
        // Ignore JSON parse fallback errors
      }
      throw new ApiHttpError(serverMessage, response.status, url, errorDetails);
    }

    return (await response.json()) as T;
  } catch (err) {
    if (err instanceof ApiHttpError) {
      throw err;
    }
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new Error(`Tempo limite de ${Math.round(effectiveTimeout / 1000)}s excedido ao conectar com ${url}`);
    }
    throw err instanceof Error ? err : new Error(String(err));
  } finally {
    globalThis.clearTimeout(timerId);
  }
}
