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

/**
 * Helper centralizado de requisição HTTP com AbortController e tratamento determinístico de erros.
 */
export async function apiFetchJson<T>(
  url: string,
  options?: ApiFetchOptions,
  timeoutMs: number = 15000
): Promise<T> {
  const effectiveTimeout = options?.timeoutMs ?? timeoutMs;
  const controller = new AbortController();
  const timerId = globalThis.setTimeout(() => controller.abort(), effectiveTimeout);

  try {
    const response = await fetch(url, {
      ...options,
      signal: options?.signal ?? controller.signal,
      headers: {
        Accept: 'application/json',
        ...(options?.body ? { 'Content-Type': 'application/json' } : {}),
        ...(options?.headers ?? {}),
      },
    });

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
