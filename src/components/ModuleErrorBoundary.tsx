import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface ModuleErrorBoundaryProps {
  children: React.ReactNode;
  moduleName?: string;
  resetKey?: string | number;
  isGlobal?: boolean;
}

interface ModuleErrorBoundaryState {
  hasError: boolean;
  errorMessage: string | null;
  isChunkLoadError: boolean;
  retryCount: number;
}

/**
 * ModuleErrorBoundary (Seção 4.2 — Estabilidade de Visualização e Lazy Loading)
 * Isola falhas de renderização ou de importação dinâmica (React.lazy / chunk load)
 * sem desmontar a aplicação inteira, oferecendo recuperação controlada.
 */
export class ModuleErrorBoundary extends React.Component<
  ModuleErrorBoundaryProps,
  ModuleErrorBoundaryState
> {
  public state: ModuleErrorBoundaryState = {
    hasError: false,
    errorMessage: null,
    isChunkLoadError: false,
    retryCount: 0,
  };

  public static getDerivedStateFromError(error: Error): Partial<ModuleErrorBoundaryState> {
    const msg = error?.message || String(error);
    const isChunk =
      msg.includes('Failed to fetch dynamically imported module') ||
      msg.includes('Loading chunk') ||
      msg.includes('Importing a module script failed');
    return {
      hasError: true,
      errorMessage: msg,
      isChunkLoadError: isChunk,
    };
  }

  public componentDidUpdate(prevProps: ModuleErrorBoundaryProps): void {
    if (this.state.hasError && prevProps.resetKey !== this.props.resetKey) {
      this.setState({
        hasError: false,
        errorMessage: null,
        isChunkLoadError: false,
      });
    }
  }

  public componentDidCatch(error: Error, errorInfo: React.ErrorInfo): void {
    console.error(
      `[WinHood ErrorBoundary] Falha capturada no módulo "${this.props.moduleName || 'Global'}":`,
      error,
      errorInfo.componentStack
    );
  }

  private handleRetry = (): void => {
    this.setState((prev) => ({
      hasError: false,
      errorMessage: null,
      isChunkLoadError: false,
      retryCount: prev.retryCount + 1,
    }));
  };

  public render(): React.ReactNode {
    if (this.state.hasError) {
      return (
        <div
          role="alert"
          className="rounded-xl border border-rose-500/40 bg-white dark:bg-[#0f141c] p-6 my-4 shadow-lg space-y-4"
        >
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-lg bg-rose-500/10 text-rose-500 shrink-0">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <div className="space-y-1">
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                {this.state.isChunkLoadError
                  ? 'Falha ao carregar módulo sob demanda (Chunk Load Error)'
                  : `Erro isolado no módulo ${this.props.moduleName || 'da interface'}`}
              </h2>
              <p className="text-xs text-slate-600 dark:text-slate-400">
                {this.state.isChunkLoadError
                  ? 'O pacote JavaScript deste módulo não pôde ser transferido do servidor local. Verifique se o backend está online e tente recarregar o módulo.'
                  : 'Ocorreu uma exceção durante a renderização deste painel. O restante da plataforma permanece protegido e operacional.'}
              </p>
            </div>
          </div>

          {this.state.errorMessage && (
            <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] font-mono text-xs text-rose-600 dark:text-rose-400 break-all">
              Detalhe técnico: {this.state.errorMessage}
            </div>
          )}

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={this.handleRetry}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Tentar Recarregar Módulo</span>
            </button>
            {this.props.isGlobal && (
              <button
                type="button"
                onClick={() => window.location.reload()}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-[#31d6c4] transition-colors cursor-pointer"
              >
                <span>Recarregar Aplicação Completa</span>
              </button>
            )}
          </div>
        </div>
      );
    }

    return (
      <React.Fragment key={this.state.retryCount}>
        {this.props.children}
      </React.Fragment>
    );
  }
}

export default ModuleErrorBoundary;
