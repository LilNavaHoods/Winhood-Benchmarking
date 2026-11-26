import type { ChildProcess } from 'node:child_process';
import type http from 'node:http';
import type { Socket } from 'node:net';

export const WINHOOD_IPC_SHUTDOWN_MESSAGE = 'WINHOOD_GRACEFUL_SHUTDOWN' as const;
export const WINHOOD_IPC_SHUTDOWN_ACK = 'WINHOOD_SHUTDOWN_ACK' as const;

export interface GracefulShutdownResult {
  closed: boolean;
  reason: string;
  flushed: boolean;
  timedOut: boolean;
  exitCode: number;
  signal: NodeJS.Signals | null;
  destroyedSockets: number;
  terminatedChildren: number;
}

export interface GracefulShutdownOptions {
  server: http.Server;
  onBeforeClose?: () => void | Promise<void>;
  onAfterClose?: () => void | Promise<void>;
  forceTimeoutMs?: number;
  signals?: NodeJS.Signals[];
  exitProcess?: boolean;
  enableIpcShutdown?: boolean;
  trackedChildren?: Set<ChildProcess>;
}

export interface GracefulShutdownController {
  shutdown: (reason: string, signal?: NodeJS.Signals | null) => Promise<GracefulShutdownResult>;
  trackChildProcess: (child: ChildProcess) => void;
  unregister: () => void;
}

/**
 * Multiplatform graceful shutdown controller for the WinHood HTTP server.
 *
 * Cross-platform guarantees (Linux, macOS, Windows):
 * - Handles POSIX signals (`SIGINT`, `SIGTERM`) and controlled IPC messages
 *   (`WINHOOD_GRACEFUL_SHUTDOWN`) so Windows parent/orchestrator processes can trigger
 *   deterministic exit code `0` instead of abrupt `TerminateProcess` (`code === null`).
 * - Tracks open HTTP sockets to close idle connections immediately and prevent hangs
 *   caused by HTTP keep-alive connections.
 * - Terminates any tracked child processes to avoid orphan processes.
 * - Flushes persistent state before closing and cleans up ephemeral resources after closing.
 * - Distinguishes clean exit (`exitCode: 0`, `timedOut: false`) from forced timeout (`exitCode: 1`, `timedOut: true`).
 */
export function registerGracefulShutdown(
  options: GracefulShutdownOptions
): GracefulShutdownController {
  const forceTimeoutMs = Math.max(250, options.forceTimeoutMs ?? 5000);
  const signals: NodeJS.Signals[] = options.signals ?? ['SIGINT', 'SIGTERM'];
  const exitProcess = options.exitProcess ?? false;
  const enableIpcShutdown = options.enableIpcShutdown ?? exitProcess;
  const trackedChildren = options.trackedChildren ?? new Set<ChildProcess>();
  const activeSockets = new Set<Socket>();

  const onConnection = (socket: Socket): void => {
    activeSockets.add(socket);
    socket.once('close', () => {
      activeSockets.delete(socket);
    });
  };
  options.server.on('connection', onConnection);

  const trackChildProcess = (child: ChildProcess): void => {
    if (!child || child.exitCode !== null) return;
    trackedChildren.add(child);
    child.once('exit', () => {
      trackedChildren.delete(child);
    });
  };

  let activePromise: Promise<GracefulShutdownResult> | null = null;

  const terminateTrackedChildren = async (): Promise<number> => {
    let terminated = 0;
    const exits: Promise<void>[] = [];
    for (const child of Array.from(trackedChildren)) {
      if (child.exitCode !== null || child.killed) {
        trackedChildren.delete(child);
        continue;
      }
      terminated += 1;
      const waitExit = new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          if (child.exitCode === null) {
            try {
              child.kill('SIGKILL');
            } catch {
              // Ignore already-exited child
            }
          }
          resolve();
        }, Math.min(2000, Math.floor(forceTimeoutMs / 2)));
        timer.unref();
        child.once('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });
      try {
        if (typeof child.send === 'function' && child.connected) {
          child.send({ type: WINHOOD_IPC_SHUTDOWN_MESSAGE, reason: 'PARENT_SHUTDOWN' });
        } else {
          child.kill('SIGTERM');
        }
      } catch {
        try {
          child.kill('SIGTERM');
        } catch {
          // Ignore already-exited child
        }
      }
      exits.push(waitExit);
    }
    if (exits.length > 0) {
      await Promise.all(exits);
    }
    trackedChildren.clear();
    return terminated;
  };

  const shutdown = (
    reason: string,
    signal: NodeJS.Signals | null = null
  ): Promise<GracefulShutdownResult> => {
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

      const terminatedChildren = await terminateTrackedChildren();

      let timedOut = false;
      let destroyedSockets = 0;

      const closed = await new Promise<boolean>((resolve) => {
        if (!options.server.listening) {
          resolve(true);
          return;
        }

        let settled = false;
        const timer = setTimeout(() => {
          if (!settled) {
            settled = true;
            timedOut = true;
            destroyedSockets = activeSockets.size;
            if (typeof options.server.closeAllConnections === 'function') {
              options.server.closeAllConnections();
            }
            for (const sock of activeSockets) {
              sock.destroy();
            }
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

        // Immediately release idle keep-alive sockets so server.close() finishes deterministically
        if (typeof options.server.closeIdleConnections === 'function') {
          options.server.closeIdleConnections();
        }
        for (const sock of activeSockets) {
          if (!sock.destroyed && sock.writableLength === 0) {
            sock.end();
          }
        }
      });

      try {
        if (options.onAfterClose) {
          await options.onAfterClose();
        }
      } catch (err) {
        console.error('[WinHood GracefulShutdown] Erro no cleanup pós-fechamento:', err);
      }

      const exitCode = closed && !timedOut ? 0 : 1;
      return {
        closed,
        reason,
        flushed,
        timedOut,
        exitCode,
        signal,
        destroyedSockets,
        terminatedChildren,
      };
    })();

    return activePromise;
  };

  const listeners = new Map<NodeJS.Signals, () => void>();
  for (const sig of signals) {
    const handler = () => {
      void shutdown(sig, sig).then((result) => {
        if (exitProcess) {
          process.exit(result.exitCode);
        }
      });
    };
    listeners.set(sig, handler);
    process.once(sig, handler);
  }

  const onIpcMessage = (message: unknown): void => {
    if (
      message &&
      typeof message === 'object' &&
      (message as { type?: unknown }).type === WINHOOD_IPC_SHUTDOWN_MESSAGE
    ) {
      const msgReason =
        typeof (message as { reason?: unknown }).reason === 'string'
          ? (message as { reason: string }).reason
          : 'IPC_GRACEFUL_SHUTDOWN';
      void shutdown(msgReason, null).then((result) => {
        if (typeof process.send === 'function' && process.connected) {
          try {
            process.send({
              type: WINHOOD_IPC_SHUTDOWN_ACK,
              ...result,
            });
          } catch {
            // Parent IPC channel already closed
          }
        }
        if (exitProcess) {
          process.exit(result.exitCode);
        }
      });
    }
  };

  if (enableIpcShutdown) {
    process.on('message', onIpcMessage);
  }

  const unregister = (): void => {
    options.server.removeListener('connection', onConnection);
    for (const [sig, handler] of listeners.entries()) {
      process.removeListener(sig, handler);
    }
    listeners.clear();
    if (enableIpcShutdown) {
      process.removeListener('message', onIpcMessage);
    }
  };

  return { shutdown, trackChildProcess, unregister };
}
