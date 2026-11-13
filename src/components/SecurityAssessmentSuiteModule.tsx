import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Crosshair,
  GitBranch,
  Lock,
  Network,
  OctagonX,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type {
  BenchmarkRun,
  SecurityAssessmentSuiteBundle,
  VulnerabilityValidationState,
} from '../types/benchmark';

interface SecurityAssessmentSuiteModuleProps {
  latestRun: BenchmarkRun | null;
  onRefresh: () => Promise<void>;
  onNotify: (msg: string, type?: 'success' | 'error') => void;
}

const VALIDATION_STATES: Array<{
  value: VulnerabilityValidationState;
  label: string;
}> = [
  { value: 'CONFIRMADA', label: 'Confirmada (Evidência Reproduzida)' },
  { value: 'PROVAVEL', label: 'Provável (Alta Confiança Estática)' },
  { value: 'FALSO_POSITIVO', label: 'Falso Positivo (Descartada com Justificativa)' },
  { value: 'NAO_REPRODUZIVEL', label: 'Não Reproduzível no Ambiente' },
  { value: 'INCONCLUSIVA', label: 'Inconclusiva (Reduz Confiança)' },
  { value: 'NAO_TESTADA', label: 'Não Testada' },
];

export const SecurityAssessmentSuiteModule: React.FC<
  SecurityAssessmentSuiteModuleProps
> = ({ latestRun, onRefresh, onNotify }) => {
  const [suite, setSuite] = useState<SecurityAssessmentSuiteBundle | null>(null);
  const [loading, setLoading] = useState(false);
  const [emergencyStopped, setEmergencyStopped] = useState(false);
  const [validationMap, setValidationMap] = useState<
    Record<string, VulnerabilityValidationState>
  >({});

  const fetchSuite = useCallback(async () => {
    if (!latestRun) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/security-suite?runId=${latestRun.id}`);
      if (res.ok) {
        const data = await res.json();
        setSuite(data.suite);
      }
    } catch {
      onNotify('Falha ao carregar a suíte de segurança.', 'error');
    } finally {
      setLoading(false);
    }
  }, [latestRun, onNotify]);

  useEffect(() => {
    fetchSuite();
  }, [fetchSuite]);

  const handleValidateFinding = async (
    findingId: string,
    newState: VulnerabilityValidationState
  ) => {
    try {
      const res = await fetch(`/api/findings/${findingId}/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          validationState: newState,
          verificationNote: `Classificação atualizada via Matriz de Validação para ${newState}.`,
        }),
      });
      const payload = await res.json();
      if (!res.ok) {
        onNotify(payload.message || payload.error || 'Erro ao validar achado.', 'error');
        return;
      }
      setValidationMap((prev) => ({ ...prev, [findingId]: newState }));
      onNotify(
        `Status de validação atualizado para ${newState} (SHA-256: ${payload.evidenceHash.slice(0, 12)}...).`,
        'success'
      );
      await fetchSuite();
      await onRefresh();
    } catch {
      onNotify('Erro de comunicação ao registrar validação.', 'error');
    }
  };

  const handleEmergencyStop = async () => {
    if (!latestRun) return;
    try {
      const res = await fetch(`/api/benchmark-runs/${latestRun.id}/emergency-stop`, {
        method: 'POST',
      });
      const payload = await res.json();
      if (!res.ok) {
        onNotify(payload.message || payload.error || 'Falha ao acionar parada.', 'error');
        return;
      }
      setEmergencyStopped(true);
      onNotify(payload.message, 'success');
      await onRefresh();
    } catch {
      onNotify('Erro ao executar cancelamento emergencial.', 'error');
    }
  };

  if (!latestRun) {
    return (
      <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-8 text-center">
        <p className="text-sm text-slate-500">
          Execute um benchmark para carregar os 15 módulos de Avaliação Comparativa de Segurança (A vs. B).
        </p>
      </div>
    );
  }

  if (loading && !suite) {
    return (
      <div className="p-8 text-center text-xs font-mono text-slate-400">
        Sincronizando telemetria dos 15 módulos de segurança e superfície de ataque...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header + Controle de Escopo e Botão de Cancelamento Emergencial */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
            Suíte de Avaliação de Segurança, Superfície &amp; Attack Path Analysis (A vs. B)
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            Comparação determinística sob os mesmos parâmetros com validação em 6 estados, isolamento por MicroVM e trilha SHA-256.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={fetchSuite}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Recalcular Matriz
          </button>
          <button
            type="button"
            onClick={handleEmergencyStop}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold bg-rose-600 text-white hover:bg-rose-500 transition-colors cursor-pointer"
          >
            <OctagonX className="w-4 h-4" />
            {emergencyStopped
              ? 'Snapshot T0 Restaurado (Sandbox Encerrado)'
              : 'Cancelamento Emergencial (Kill Switch Sandbox)'}
          </button>
        </div>
      </div>

      {/* Barra de Governança do Ambiente Isolado */}
      {suite && (
        <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs font-mono tabular-nums">
          <div>
            <div className="text-slate-400 font-sans text-[11px]">Isolamento</div>
            <div className="font-bold text-[#31d6c4] mt-0.5">
              {suite.sandboxControl.isolationMode}
            </div>
          </div>
          <div>
            <div className="text-slate-400 font-sans text-[11px]">Escopo Autorizado</div>
            <div className="font-bold text-slate-900 dark:text-slate-100 mt-0.5 truncate">
              {suite.sandboxControl.scopeAllowlist[0]}
            </div>
          </div>
          <div>
            <div className="text-slate-400 font-sans text-[11px]">Política de Rede</div>
            <div className="font-bold text-slate-900 dark:text-slate-100 mt-0.5">
              {suite.sandboxControl.networkPolicy}
            </div>
          </div>
          <div>
            <div className="text-slate-400 font-sans text-[11px]">Limites de Recursos</div>
            <div className="font-bold text-slate-900 dark:text-slate-100 mt-0.5">
              {suite.sandboxControl.cpuLimitCores} vCPU / {suite.sandboxControl.memoryLimitMb} MB
            </div>
          </div>
          <div>
            <div className="text-slate-400 font-sans text-[11px]">Snapshot Baseline</div>
            <div className="font-bold text-slate-900 dark:text-slate-100 mt-0.5">
              {suite.sandboxControl.snapshotBaselineId}
            </div>
          </div>
          <div>
            <div className="text-slate-400 font-sans text-[11px]">Timeout &amp; Recuperação</div>
            <div className="font-bold text-emerald-500 mt-0.5">
              {suite.sandboxControl.timeoutSeconds}s / Verificada
            </div>
          </div>
        </div>
      )}

      {/* 1. Comparação Direta A versus B */}
      {suite && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {suite.comparisonMetrics.map((m) => (
            <div
              key={m.softwareId}
              className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4"
            >
              <div className="flex items-start justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
                <div>
                  <span className="text-xs font-mono text-slate-400">
                    Versão {m.softwareVersion}
                  </span>
                  <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">
                    {m.softwareName}
                  </h2>
                </div>
                <div className="text-right font-mono tabular-nums">
                  <div className="text-2xl font-bold text-[#31d6c4]">
                    {m.overallSecurityMaturityScore.toFixed(2)} / 5.00
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Confiança da Comparação: {m.comparisonConfidencePercent}%
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono tabular-nums">
                <div className="p-2.5 rounded bg-slate-50 dark:bg-[#080b10] border border-slate-200 dark:border-slate-800">
                  <div className="text-[10px] font-sans text-slate-400">Encontradas / Confirmadas</div>
                  <div className="font-bold text-sm text-rose-500 mt-0.5">
                    {m.vulnerabilitiesFound} / {m.vulnerabilitiesConfirmed}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-slate-50 dark:bg-[#080b10] border border-slate-200 dark:border-slate-800">
                  <div className="text-[10px] font-sans text-slate-400">Falsos Positivos</div>
                  <div className="font-bold text-sm text-slate-900 dark:text-slate-100 mt-0.5">
                    {m.falsePositivesCount}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-slate-50 dark:bg-[#080b10] border border-slate-200 dark:border-slate-800">
                  <div className="text-[10px] font-sans text-slate-400">Cobertura de Testes</div>
                  <div className="font-bold text-sm text-emerald-500 mt-0.5">
                    {m.testCoveragePercent}% ({m.totalExecutionTimeMs}ms)
                  </div>
                </div>
                <div className="p-2.5 rounded bg-slate-50 dark:bg-[#080b10] border border-slate-200 dark:border-slate-800">
                  <div className="text-[10px] font-sans text-slate-400">Recuperação / Resiliência</div>
                  <div className="font-bold text-sm text-[#31d6c4] mt-0.5">
                    {m.recoveryCapabilityScore.toFixed(1)} / {m.performanceUnderStressScore.toFixed(1)}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* 2. Mapa de Superfície de Ataque & Attack Path Analysis */}
      {suite && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Mapa de Superfície de Ataque */}
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Network className="w-4 h-4 text-[#31d6c4]" />
              <span>Mapa Comparativo de Superfície de Ataque</span>
            </h3>
            <div className="space-y-4">
              {suite.attackSurfaces.map((surf) => (
                <div
                  key={surf.softwareId}
                  className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-2 text-xs"
                >
                  <div className="flex items-center justify-between font-bold">
                    <span>{surf.softwareName}</span>
                    <span className="font-mono text-amber-500">
                      Índice de Exposição: {surf.surfaceRiskIndex.toFixed(1)} / 10.0
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                    <div>Pontos de Entrada: {surf.exposedEntryPoints.length}</div>
                    <div>Conectores SQL/DB: {surf.databaseConnectors.length}</div>
                    <div>Chamadas de Processo/SO: {surf.externalProcessInvocations.length}</div>
                    <div>Operações Privilegiadas: {surf.privilegedOperations.length}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Attack Path Analysis */}
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-rose-500" />
              <span>Attack Path Analysis (Caminhos Críticos no Grafo de Código)</span>
            </h3>
            {suite.attackPaths.length === 0 ? (
              <p className="text-xs text-slate-500">
                Nenhum caminho de ataque encadeado identificado nos softwares analisados.
              </p>
            ) : (
              <div className="space-y-3 max-h-80 df-hover-scroll">
                {suite.attackPaths.map((pathChain) => (
                  <div
                    key={pathChain.id}
                    className="p-3.5 rounded-lg border border-rose-500/30 bg-rose-500/5 space-y-2 text-xs"
                  >
                    <div className="flex items-center justify-between font-bold text-rose-600 dark:text-rose-400">
                      <span>
                        [{pathChain.softwareName}] {pathChain.title}
                      </span>
                      <span className="font-mono">{pathChain.validationState}</span>
                    </div>
                    <div className="space-y-1 font-mono text-[11px]">
                      {pathChain.nodes.map((n) => (
                        <div key={n.stepOrder} className="text-slate-700 dark:text-slate-300">
                          {n.stepOrder}. [{n.layer}] {n.filePath}:{n.lineNumber} ({n.weaknessCwe})
                        </div>
                      ))}
                    </div>
                    <div className="text-[11px] text-emerald-700 dark:text-[#31d6c4]">
                      <strong>Controle de Mitigação:</strong> {pathChain.mitigationControl}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* 3. Matriz de Validação de Vulnerabilidades em 6 Estados */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
        <div>
          <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-[#31d6c4]" />
            <span>
              Matriz de Validação de Vulnerabilidades (6 Estados Não-Destrutivos &amp; Rastreabilidade SHA-256)
            </span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Resultados de scanners não são aceitos cegamente: classifique e valide cada evidência técnica abaixo.
          </p>
        </div>

        <div className="overflow-x-auto df-hover-scroll">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                <th className="py-2.5 pr-3">Software</th>
                <th className="py-2.5 px-3">Ferramenta &amp; Cenário</th>
                <th className="py-2.5 px-3">Severidade</th>
                <th className="py-2.5 px-3">Evidência Técnica (SHA-256)</th>
                <th className="py-2.5 pl-3">Estado de Validação (6 Estados)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {latestRun.findings.map((f) => {
                const currentVal =
                  validationMap[f.id] ||
                  (f.validationStatus === 'FALSE_POSITIVE_REVIEWED' || f.validationStatus === 'FALSE_POSITIVE'
                    ? 'FALSO_POSITIVO'
                    : f.validationStatus === 'INCONCLUSIVE'
                      ? 'INCONCLUSIVA'
                      : f.validationStatus === 'NOT_REPRODUCIBLE'
                        ? 'NAO_REPRODUZIVEL'
                        : 'PROVAVEL');
                return (
                  <tr key={f.id}>
                    <td className="py-3 pr-3 font-semibold text-slate-900 dark:text-slate-100 whitespace-nowrap">
                      {f.softwareName} (v{f.softwareVersion})
                    </td>
                    <td className="py-3 px-3">
                      <div className="font-semibold text-slate-800 dark:text-slate-200">
                        {f.title}
                      </div>
                      <div className="text-[11px] font-mono text-slate-500">
                        {f.toolName} v{f.toolVersion} · {f.originalRuleId}
                      </div>
                    </td>
                    <td className="py-3 px-3 font-mono font-bold text-rose-500">
                      {f.severity}
                    </td>
                    <td className="py-3 px-3 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                      <div>
                        {f.filePath}:{f.lineNumber}
                      </div>
                      <div className="text-slate-400">
                        SHA-256: {f.evidenceSha256.slice(0, 16)}...
                      </div>
                    </td>
                    <td className="py-3 pl-3">
                      <select
                        aria-label={`Estado de validação para ${f.title}`}
                        value={currentVal}
                        onChange={(e) =>
                          handleValidateFinding(
                            f.id,
                            e.target.value as VulnerabilityValidationState
                          )
                        }
                        className="rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100"
                      >
                        {VALIDATION_STATES.map((st) => (
                          <option key={st.value} value={st.value}>
                            {st.label}
                          </option>
                        ))}
                      </select>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
