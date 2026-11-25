import type http from 'node:http';

export interface GracefulShutdownOptions {
  server: http.Server;
  onBeforeClose?: () => void | Promise<void>;
  onAfterClose?: () => void | Promise<void>;
  forceTimeoutMs?: number;
  signals?: NodeJS.Signals[];
  exitProcess?: boolean;
}

export interface GracefulShutdownController {
  shutdown: (reason: string) => Promise<{ closed: boolean; reason: string; flushed: boolean }>;
  unregister: () => void;
}

/**
 * Gerenciador de encerramento limpo do servidor HTTP WinHood.
 * Garante flush de persistência pendente, encerramento de timers e fechamento do socket
 * sem corrupção de estado em SIGINT / SIGTERM.
 */
export function registerGracefulShutdown(
  options: GracefulShutdownOptions
): GracefulShutdownController {
  const forceTimeoutMs = options.forceTimeoutMs ?? 5000;
  const signals: NodeJS.Signals[] = options.signals ?? ['SIGINT', 'SIGTERM'];
  const exitProcess = options.exitProcess ?? false;

  let activePromise: Promise<{ closed: boolean; reason: string; flushed: boolean }> | null = null;

  const shutdown = (
    reason: string
  ): Promise<{ closed: boolean; reason: string; flushed: boolean }> => {
    if (activePromise) {
      return activePromise;
    }

    activePromise = (async () => {
      let flushed = false;
      try {
        if (options.onBeforeClose) {
          await options.onBeforeClose();
          flushed = true;
        }
      } catch (err) {
        console.error('[WinHood GracefulShutdown] Erro ao executar flush pré-fechamento:', err);
      }

      const closed = await new Promise<boolean>((resolve) => {
        if (!options.server.listening) {
          resolve(true);
          return;
        }
        let settled = false;
        const timer = setTimeout(() => {
          if (!settled) {
            settled = true;
            resolve(false);
          }
        }, forceTimeoutMs);
        timer.unref();

        options.server.close((err) => {
          clearTimeout(timer);
          if (!settled) {
            settled = true;
            if (err) {
              console.error('[WinHood GracefulShutdown] Erro ao fechar servidor HTTP:', err);
              resolve(false);
            } else {
              resolve(true);
            }
          }
        });
      });

      try {
        if (options.onAfterClose) {
          await options.onAfterClose();
        }
      } catch (err) {
        console.error('[WinHood GracefulShutdown] Erro no cleanup pós-fechamento:', err);
      }

      return { closed, reason, flushed };
    })();

    return activePromise;
  };

  const listeners = new Map<NodeJS.Signals, () => void>();
  for (const sig of signals) {
    const handler = () => {
      void shutdown(sig).finally(() => {
        if (exitProcess) {
          process.exit(0);
        }
      });
    };
    listeners.set(sig, handler);
    process.once(sig, handler);
  }

  const unregister = (): void => {
    for (const [sig, handler] of listeners.entries()) {
      process.removeListener(sig, handler);
    }
    listeners.clear();
  };

  return { shutdown, unregister };
}
