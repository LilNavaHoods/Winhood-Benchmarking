import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Database,
  GitBranch,
  HardDrive,
  Monitor,
  XCircle,
} from 'lucide-react';
import type { BenchmarkRun } from '../types/benchmark';

interface ArchitectureQaPerfOsModuleProps {
  latestRun: BenchmarkRun | null;
}

export const ArchitectureQaPerfOsModule: React.FC<ArchitectureQaPerfOsModuleProps> = ({
  latestRun,
}) => {
  const [subTab, setSubTab] = useState<'architecture' | 'qa' | 'perf_db' | 'os_sandbox'>(
    'architecture'
  );

  if (!latestRun) {
    return (
      <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-8 text-center">
        <p className="text-sm text-slate-500">
          Execute um benchmark para visualizar as análises de Arquitetura, QA, Desempenho, Banco de Dados e Instalação Windows Sandbox.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header & Tabs */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
            Arquitetura, QA Funcional, Desempenho, Banco &amp; Sistema Operacional
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            Inspeção estrutural de acoplamento/ciclos, matriz de equivalência funcional, latência sob carga equivalente e snapshots Windows T0/T1/T2.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1 p-1 rounded-lg bg-slate-200/70 dark:bg-[#0f141c] border border-slate-300/60 dark:border-slate-800">
          {[
            { id: 'architecture', label: 'Arquitetura & Ciclos' },
            { id: 'qa', label: 'QA & Equivalência Funcional' },
            { id: 'perf_db', label: 'Desempenho & Banco SQL' },
            { id: 'os_sandbox', label: 'Instalação Windows (T0/T1/T2)' },
          ].map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setSubTab(t.id as typeof subTab)}
              className={`px-3.5 py-1.5 rounded-md text-xs font-semibold transition-colors whitespace-nowrap cursor-pointer ${
                subTab === t.id
                  ? 'bg-[#31d6c4] text-slate-950'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Sub-Tab 1: Architecture */}
      {subTab === 'architecture' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {latestRun.architectureGraphs.map((arch) => (
            <div
              key={arch.softwareId}
              className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4"
            >
              <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
                <div>
                  <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                    <GitBranch className="w-4 h-4 text-[#31d6c4]" />
                    <span>{arch.softwareName}</span>
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Módulos: {arch.modules.length} · Arestas de dependência: {arch.edges.length}
                  </p>
                </div>
                <div className="text-right font-mono tabular-nums text-xs">
                  <div
                    className={
                      arch.circularChains.length === 0
                        ? 'text-emerald-600 dark:text-[#31d6c4] font-bold'
                        : 'text-rose-500 font-bold'
                    }
                  >
                    Ciclos: {arch.circularChains.length}
                  </div>
                  <div className="text-slate-400">
                    Violações de Camada: {arch.layerViolations.length}
                  </div>
                </div>
              </div>

              {/* Modules Coupling Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                      <th className="py-2 pr-2">Módulo</th>
                      <th className="py-2 px-2">Camada</th>
                      <th className="py-2 px-2 text-right">Ca / Ce</th>
                      <th className="py-2 pl-2 text-right">Instabilidade (I)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                    {arch.modules.map((m) => (
                      <tr key={m.id}>
                        <td className="py-2 pr-2 font-semibold text-slate-900 dark:text-slate-100">
                          {m.name}
                        </td>
                        <td className="py-2 px-2 text-slate-500">{m.layer}</td>
                        <td className="py-2 px-2 text-right">
                          {m.afferentCoupling} / {m.efferentCoupling}
                        </td>
                        <td className="py-2 pl-2 text-right font-bold">
                          {m.instability.toFixed(2)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Circular Chains & Layer Violations */}
              <div className="pt-3 border-t border-slate-200 dark:border-slate-800 space-y-2 text-xs">
                {arch.circularChains.length === 0 && arch.layerViolations.length === 0 ? (
                  <div className="text-emerald-600 dark:text-[#31d6c4] flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Grafo acíclico direcionado (DAG) íntegro e isolamento de camadas respeitado.</span>
                  </div>
                ) : (
                  <>
                    {arch.circularChains.map((chain, i) => (
                      <div key={i} className="text-rose-500 flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                        <span>
                          <strong>Dependência Circular:</strong>{' '}
                          <code className="font-mono">{chain.join(' → ')}</code>
                        </span>
                      </div>
                    ))}
                    {arch.layerViolations.map((v, i) => (
                      <div key={i} className="text-amber-500 flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                        <span>{v}</span>
                      </div>
                    ))}
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Sub-Tab 2: QA & Functional Equivalence Matrix */}
      {subTab === 'qa' && (
        <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
              Matriz de Equivalência Funcional &amp; Auditoria de Comportamento Real
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Uma funcionalidade só é considerada aprovada (PASSED_VALIDATED) após verificação de efeito real no backend e persistência. Componentes apenas visuais recebem classificação VISUAL_ONLY.
            </p>
          </div>

          <div className="overflow-x-auto df-hover-scroll">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                  <th className="py-2.5 pr-3">ID</th>
                  <th className="py-2.5 px-3">Requisito Funcional</th>
                  <th className="py-2.5 px-3">Criticidade</th>
                  {latestRun.scoreCards.map((sc) => (
                    <th key={sc.softwareId} className="py-2.5 px-3">
                      {sc.softwareName}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {latestRun.functionalMatrix.map((row) => (
                  <tr key={row.featureId}>
                    <td className="py-3 pr-3 font-mono font-bold text-slate-700 dark:text-slate-300">
                      {row.featureId}
                    </td>
                    <td className="py-3 px-3">
                      <div className="font-semibold text-slate-900 dark:text-slate-100">
                        {row.featureName}
                      </div>
                      <div className="text-[11px] text-slate-500">{row.domainCategory}</div>
                    </td>
                    <td className="py-3 px-3 font-mono">
                      {row.essential ? (
                        <span className="text-rose-500 font-semibold">ESSENCIAL</span>
                      ) : (
                        <span className="text-slate-400">COMPLEMENTAR</span>
                      )}
                    </td>
                    {latestRun.scoreCards.map((sc) => {
                      const res = row.resultsBySoftware[sc.softwareId];
                      return (
                        <td key={sc.softwareId} className="py-3 px-3">
                          {res ? (
                            <div className="space-y-1">
                              <div className="font-mono font-bold flex items-center gap-1.5">
                                {res.status === 'PASSED_VALIDATED' ? (
                                  <span className="text-emerald-600 dark:text-[#31d6c4] inline-flex items-center gap-1">
                                    <CheckCircle2 className="w-3.5 h-3.5" />
                                    PASSED_VALIDATED
                                  </span>
                                ) : res.status === 'VISUAL_ONLY' ? (
                                  <span className="text-amber-500 inline-flex items-center gap-1">
                                    <AlertTriangle className="w-3.5 h-3.5" />
                                    VISUAL_ONLY
                                  </span>
                                ) : (
                                  <span className="text-rose-500 inline-flex items-center gap-1">
                                    <XCircle className="w-3.5 h-3.5" />
                                    {res.status}
                                  </span>
                                )}
                              </div>
                              <div className="text-[11px] text-slate-500">
                                {res.evidenceLog} ({res.executionTimeMs}ms)
                              </div>
                            </div>
                          ) : (
                            '—'
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Sub-Tab 3: Performance & Database */}
      {subTab === 'perf_db' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {latestRun.scoreCards.map((sc) => (
            <div
              key={sc.softwareId}
              className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4"
            >
              <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
                <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-[#31d6c4]" />
                  <span>{sc.softwareName} (v{sc.softwareVersion})</span>
                </h2>
                <span className="text-xs font-mono tabular-nums font-bold text-[#31d6c4]">
                  Desempenho: {sc.groupedScores.performanceScore.toFixed(2)} / 5.00
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono tabular-nums">
                <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                  <div className="text-slate-400 font-sans text-[11px]">Latência P50</div>
                  <div className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                    {sc.metricsSummary.p50LatencyMs} ms
                  </div>
                </div>
                <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                  <div className="text-slate-400 font-sans text-[11px]">Latência P95</div>
                  <div className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                    {sc.metricsSummary.p95LatencyMs} ms
                  </div>
                </div>
                <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                  <div className="text-slate-400 font-sans text-[11px]">Latência P99</div>
                  <div className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                    {sc.metricsSummary.p99LatencyMs} ms
                  </div>
                </div>
                <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                  <div className="text-slate-400 font-sans text-[11px]">Throughput</div>
                  <div className="text-sm font-bold text-[#31d6c4] mt-0.5">
                    {sc.metricsSummary.throughputRps} req/s
                  </div>
                </div>
                <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                  <div className="text-slate-400 font-sans text-[11px]">Consumo RAM</div>
                  <div className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                    {sc.metricsSummary.memoryMb} MB
                  </div>
                </div>
                <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                  <div className="text-slate-400 font-sans text-[11px]">Uso de CPU</div>
                  <div className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                    {sc.metricsSummary.cpuPercent}%
                  </div>
                </div>
                <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                  <div className="text-slate-400 font-sans text-[11px]">Inicialização</div>
                  <div className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                    {sc.metricsSummary.startupTimeMs} ms
                  </div>
                </div>
                <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                  <div className="text-slate-400 font-sans text-[11px]">Alertas SQLFluff</div>
                  <div
                    className={`text-sm font-bold mt-0.5 ${
                      sc.metricsSummary.dbSchemaIssues === 0
                        ? 'text-emerald-500'
                        : 'text-rose-500'
                    }`}
                  >
                    {sc.metricsSummary.dbSchemaIssues} problemas
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Sub-Tab 4: Windows Sandbox Snapshots T0 / T1 / T2 */}
      {subTab === 'os_sandbox' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {latestRun.sandboxDiffs.map((diff) => (
            <div
              key={diff.softwareId}
              className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4"
            >
              <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
                <div>
                  <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                    <Monitor className="w-4 h-4 text-[#31d6c4]" />
                    <span>{diff.softwareName}</span>
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">{diff.sandboxEnvironment}</p>
                </div>
                <div className="text-xs font-mono font-bold">
                  {diff.cleanUninstall ? (
                    <span className="text-emerald-600 dark:text-[#31d6c4] inline-flex items-center gap-1">
                      <CheckCircle2 className="w-4 h-4" />
                      T2 == T0 (Sem Resíduos)
                    </span>
                  ) : (
                    <span className="text-rose-500 inline-flex items-center gap-1">
                      <AlertTriangle className="w-4 h-4" />
                      T2 != T0 (Resíduos Detectados)
                    </span>
                  )}
                </div>
              </div>

              <div className="space-y-2 text-xs font-mono tabular-nums p-3 rounded bg-slate-100 dark:bg-[#080b10]">
                <div className="truncate">
                  <strong>T0 (Estado Anterior):</strong> {diff.t0BaselineHash.slice(0, 28)}...
                </div>
                <div className="truncate">
                  <strong>T1 (Pós-Instalação):</strong> {diff.t1PostInstallHash.slice(0, 28)}...
                </div>
                <div className="truncate">
                  <strong>T2 (Pós-Desinstalação):</strong> {diff.t2PostUninstallHash.slice(0, 28)}...
                </div>
              </div>

              <div className="space-y-2 text-xs">
                <div>
                  <strong className="text-slate-700 dark:text-slate-300">
                    Comunicação de Rede Observada:
                  </strong>{' '}
                  <span className="font-mono text-slate-600 dark:text-slate-400">
                    {diff.networkEndpointsContacted.join(', ')}
                  </span>
                </div>
                <div>
                  <strong className="text-slate-700 dark:text-slate-300">
                    Resíduos de Arquivos Pós-Desinstalação (T2):
                  </strong>{' '}
                  <span className="font-mono text-slate-600 dark:text-slate-400">
                    {diff.residualFilesT2.length === 0
                      ? 'Nenhum arquivo órfão'
                      : diff.residualFilesT2.join(', ')}
                  </span>
                </div>
                <div>
                  <strong className="text-slate-700 dark:text-slate-300">
                    Resíduos de Registro Windows (T2):
                  </strong>{' '}
                  <span className="font-mono text-slate-600 dark:text-slate-400">
                    {diff.residualRegistryKeysT2.length === 0
                      ? 'Nenhuma chave residual'
                      : diff.residualRegistryKeysT2.join(', ')}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
