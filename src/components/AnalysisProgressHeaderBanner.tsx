import React, { useEffect, useState } from 'react';
import {
  Activity,
  Clock,
  Cpu,
  Layers,
  StopCircle,
} from 'lucide-react';
import type { BenchmarkRun, BenchmarkRunProgress } from '../types/benchmark';

interface AnalysisProgressHeaderBannerProps {
  activeRun: BenchmarkRun | null;
  onCancelRun?: (runId: string) => Promise<void>;
  onRefresh?: () => Promise<void>;
}

export const AnalysisProgressHeaderBanner: React.FC<AnalysisProgressHeaderBannerProps> = ({
  activeRun,
  onCancelRun,
  onRefresh,
}) => {
  const [canceling, setCanceling] = useState(false);
  const [localProgress, setLocalProgress] = useState<BenchmarkRunProgress | null>(
    activeRun?.progress || null
  );

  useEffect(() => {
    if (activeRun?.progress) {
      setLocalProgress(activeRun.progress);
    }
  }, [activeRun?.progress]);

  // Polling em tempo real se a corrida estiver com status RUNNING
  useEffect(() => {
    if (!activeRun || activeRun.status !== 'RUNNING') return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/benchmark-runs/${activeRun.id}/progress`);
        if (res.ok) {
          const data = await res.json();
          if (data.progress) {
            setLocalProgress(data.progress);
          }
          if (data.status && data.status !== 'RUNNING') {
            onRefresh?.();
          }
        }
      } catch {
        // Ignora erros de polling momentâneos
      }
    }, 700);

    return () => clearInterval(interval);
  }, [activeRun?.id, activeRun?.status, onRefresh]);

  if (!activeRun || activeRun.status !== 'RUNNING') {
    return null;
  }

  const percent = Math.min(100, Math.max(0, localProgress?.percent ?? 15));
  const etaSeconds = localProgress?.estimatedRemainingSeconds ?? 12;
  const stageLabel =
    localProgress?.stageLabel ||
    'Executando avaliação determinística e análise estática de código...';
  const currentTool = localProgress?.currentTool || 'WinHood Security & Quality Engine';
  const processedFiles = localProgress?.processedFiles ?? 0;
  const totalFiles = localProgress?.totalFiles ?? 1;

  const handleEmergencyStop = async () => {
    if (!onCancelRun) return;
    setCanceling(true);
    try {
      await onCancelRun(activeRun.id);
    } finally {
      setCanceling(false);
    }
  };

  const formatEta = (seconds: number) => {
    if (seconds <= 0) return 'Concluindo...';
    if (seconds < 60) return `~${seconds}s restantes`;
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `~${mins}m ${secs}s restantes`;
  };

  return (
    <div
      role="status"
      aria-live="polite"
      className="w-full bg-[#0c1420] text-slate-100 border-b border-[#31d6c4]/40 shadow-sm relative overflow-hidden"
    >
      {/* Barra de progresso animada contínua no topo */}
      <div className="w-full h-1 bg-slate-800/80 overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-[#0e9f8e] via-[#31d6c4] to-emerald-400 transition-all duration-500 ease-out"
          style={{ width: `${percent}%` }}
        />
      </div>

      <div className="px-6 py-2.5 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
        {/* Identificação da análise e percentual */}
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex items-center gap-1.5 shrink-0 text-[#31d6c4] font-semibold">
            <Activity className="w-4 h-4 animate-spin text-[#31d6c4]" />
            <span className="uppercase font-mono tracking-wider text-[11px]">
              Análise em Andamento
            </span>
          </div>

          <div className="h-3.5 w-px bg-slate-700/80 hidden sm:block shrink-0" />

          <div className="font-mono tabular-nums text-sm font-bold text-[#31d6c4] shrink-0">
            {percent}%
          </div>

          <div className="h-3.5 w-px bg-slate-700/80 hidden sm:block shrink-0" />

          {/* Estágio técnico e ferramenta ativa */}
          <div className="truncate text-slate-300">
            <span className="font-semibold text-slate-100">{activeRun.projectName}</span>
            <span className="text-slate-500 mx-1.5">·</span>
            <span className="text-slate-300 truncate">{stageLabel}</span>
          </div>
        </div>

        {/* Métricas de progresso: arquivos, ferramenta e ETA */}
        <div className="flex items-center gap-4 shrink-0 font-mono text-[11px] text-slate-300">
          <div className="hidden lg:flex items-center gap-1.5 text-slate-400">
            <Cpu className="w-3.5 h-3.5 text-[#31d6c4]" />
            <span>{currentTool}</span>
          </div>

          {totalFiles > 0 && (
            <div className="hidden sm:flex items-center gap-1.5 text-slate-300 tabular-nums">
              <Layers className="w-3.5 h-3.5 text-slate-400" />
              <span>
                {processedFiles}/{totalFiles} arqs
              </span>
            </div>
          )}

          {/* Tempo Estimado de Conclusão (ETA) */}
          <div className="flex items-center gap-1.5 text-[#31d6c4] font-semibold bg-[#31d6c4]/10 border border-[#31d6c4]/30 px-2 py-1 rounded">
            <Clock className="w-3.5 h-3.5 text-[#31d6c4]" />
            <span className="tabular-nums font-bold">ETA: {formatEta(etaSeconds)}</span>
          </div>

          {/* Botão de cancelamento emergencial */}
          {onCancelRun && (
            <button
              type="button"
              disabled={canceling}
              onClick={handleEmergencyStop}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-sans font-medium text-rose-300 hover:text-white bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/60 transition-colors disabled:opacity-50 cursor-pointer"
              title="Cancelar execução e restaurar snapshot"
            >
              <StopCircle className="w-3 h-3 text-rose-400" />
              <span>{canceling ? 'Parando...' : 'Interromper'}</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
