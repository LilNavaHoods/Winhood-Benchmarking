import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Download,
  FileSpreadsheet,
  FileText,
  Hash,
  Lock,
  Printer,
  Server,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import type {
  AuditLogEntry,
  BenchmarkRun,
  ToolAdapterInfo,
} from '../types/benchmark';

interface VeracityAdaptersReportsModuleProps {
  latestRun: BenchmarkRun | null;
  adapters: ToolAdapterInfo[];
  auditLogs: AuditLogEntry[];
  initialTab?: 'veracity' | 'adapters' | 'reports';
}

const REPORT_TYPES = [
  { id: 'EXECUTIVE', label: '01. Relatório Executivo Consolidado' },
  { id: 'TECHNICAL', label: '02. Relatório Técnico de Engenharia' },
  { id: 'CODE_QUALITY', label: '03. Relatório de Qualidade de Código' },
  { id: 'SECURITY', label: '04. Relatório de Segurança & DevSecOps' },
  { id: 'FUNCTIONAL', label: '05. Relatório de Equivalência Funcional (QA)' },
  { id: 'PERFORMANCE', label: '06. Relatório de Desempenho sob Equivalência' },
  { id: 'ARCHITECTURAL', label: '07. Relatório Arquitetural & Acoplamento' },
  { id: 'DATABASE', label: '08. Relatório de Banco de Dados & SQL' },
  { id: 'COMPATIBILITY', label: '09. Relatório de Instalação & Compatibilidade' },
  { id: 'COMPARATIVE_FULL', label: '10. Relatório Comparativo Completo (Mestre)' },
];

export const VeracityAdaptersReportsModule: React.FC<
  VeracityAdaptersReportsModuleProps
> = ({ latestRun, adapters, auditLogs, initialTab = 'veracity' }) => {
  const [subTab, setSubTab] = useState<'veracity' | 'adapters' | 'reports'>(initialTab);
  const [selectedReportType, setSelectedReportType] = useState('COMPARATIVE_FULL');

  const handleDownloadReport = (format: 'json' | 'csv' | 'md' | 'sarif' | 'html') => {
    if (!latestRun) return;
    const url = `/api/reports/${latestRun.id}/export?format=${format}&type=${selectedReportType}`;
    const link = document.createElement('a');
    link.href = url;
    link.download = `winhood_${latestRun.id}_${selectedReportType.toLowerCase()}.${format === 'sarif' ? 'sarif' : format}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handlePrintPdfReport = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
            Motor de Veracidade, Adaptadores, Evidências &amp; Relatórios
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            Auditoria criptográfica de cobertura, status de ferramentas integradas (Ports &amp; Adapters) e geração de relatórios oficiais.
          </p>
        </div>

        <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-200/70 dark:bg-[#0f141c] border border-slate-300/60 dark:border-slate-800 shrink-0">
          {[
            { id: 'veracity', label: 'Veracidade & Evidências' },
            { id: 'adapters', label: 'Adaptadores & OTel' },
            { id: 'reports', label: 'Relatórios & Auditoria' },
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

      {/* Sub-Tab 1: Veracity Engine & Append-Only Evidence Chain */}
      {subTab === 'veracity' && (
        <div className="space-y-6">
          {!latestRun ? (
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-8 text-center text-sm text-slate-500">
              Execute um benchmark para visualizar o atestado do Motor de Veracidade e a cadeia de evidências SHA-256.
            </div>
          ) : (
            <>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {latestRun.veracityResults.map((v) => (
                  <div
                    key={v.softwareId}
                    className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4"
                  >
                    <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
                      <div>
                        <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                          <ShieldCheck className="w-4 h-4 text-[#31d6c4]" />
                          <span>{v.softwareName}</span>
                        </h2>
                        <p className="text-xs text-slate-500 mt-0.5">
                          Cobertura Efetiva de Análise: {v.overallCoveragePercent.toFixed(1)}%
                        </p>
                      </div>
                      <div className="text-xs font-mono font-bold text-emerald-600 dark:text-[#31d6c4]">
                        {v.overallClassification}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-xs">
                      {[
                        { label: '1. Ferramenta Executada', ok: v.checks.toolExecuted },
                        { label: '2. Versão Identificada', ok: v.checks.versionIdentified },
                        { label: '3. Artefatos Recebidos', ok: v.checks.artifactsReceived },
                        { label: '4. Elegíveis Identificados', ok: v.checks.eligibleFilesIdentified },
                        { label: '5. Arquivos Analisados', ok: v.checks.filesEffectivelyAnalyzed },
                        { label: '6. Cobertura Calculada', ok: v.checks.coverageCalculated },
                        { label: '7. Erros de Parsing (0)', ok: v.checks.parsingErrorsChecked },
                        { label: '8. Relatório Gerado', ok: v.checks.reportGenerated },
                        { label: '9. Schema Validado', ok: v.checks.schemaValidated },
                        { label: '10. Evidências Salvas', ok: v.checks.evidenceStored },
                        { label: '11. Persistência Confirmada', ok: v.checks.persistenceConfirmed },
                        { label: '12. Integridade SHA-256', ok: v.checks.integrityVerified },
                      ].map((chk) => (
                        <div
                          key={chk.label}
                          className="flex items-center justify-between p-2 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]"
                        >
                          <span className="text-slate-700 dark:text-slate-300">{chk.label}</span>
                          {chk.ok ? (
                            <CheckCircle2 className="w-3.5 h-3.5 text-[#31d6c4] shrink-0" />
                          ) : (
                            <AlertTriangle className="w-3.5 h-3.5 text-rose-500 shrink-0" />
                          )}
                        </div>
                      ))}
                    </div>

                    {v.warnings.length > 0 && (
                      <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] text-[11px] text-slate-600 dark:text-slate-400">
                        {v.warnings.join(' ')}
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {/* Append-Only Evidence Chain Table */}
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                      <Lock className="w-4 h-4 text-[#31d6c4]" />
                      <span>
                        Trilha de Auditoria de Evidências Append-Only ({latestRun.evidenceChain.length} registros encadeados)
                      </span>
                    </h3>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Cada registro referencia criptograficamente o hash SHA-256 do registro anterior, impedindo adulteração retroativa silenciosa.
                    </p>
                  </div>
                </div>

                <div className="overflow-x-auto max-h-96 df-hover-scroll">
                  <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                        <th className="py-2 pr-3">#</th>
                        <th className="py-2 px-3">Software</th>
                        <th className="py-2 px-3">Ferramenta</th>
                        <th className="py-2 px-3">Resumo da Evidência</th>
                        <th className="py-2 px-3">Hash Anterior</th>
                        <th className="py-2 pl-3">Hash Atual (SHA-256)</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                      {latestRun.evidenceChain.map((ev) => (
                        <tr key={ev.id}>
                          <td className="py-2.5 pr-3 font-bold text-[#31d6c4]">
                            #{ev.immutableIndex}
                          </td>
                          <td className="py-2.5 px-3 font-sans font-medium text-slate-800 dark:text-slate-200 whitespace-nowrap">
                            {ev.softwareName} (v{ev.version})
                          </td>
                          <td className="py-2.5 px-3 text-slate-500 whitespace-nowrap">
                            {ev.toolName} v{ev.toolVersion}
                          </td>
                          <td className="py-2.5 px-3 font-sans text-slate-700 dark:text-slate-300">
                            {ev.resultSummary}
                          </td>
                          <td className="py-2.5 px-3 text-slate-400">
                            {ev.previousRecordSha256.slice(0, 12)}...
                          </td>
                          <td className="py-2.5 pl-3 text-slate-700 dark:text-slate-200 font-semibold">
                            {ev.sha256.slice(0, 16)}...
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* Sub-Tab 2: Adapters & OpenTelemetry Observability */}
      {subTab === 'adapters' && (
        <div className="space-y-6">
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Server className="w-4 h-4 text-[#31d6c4]" />
                <span>Catálogo Administrativo de Adaptadores (Ports &amp; Adapters)</span>
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Exibe o status real de cada ferramenta integrada: OPERATIONAL, FERRAMENTA NÃO INSTALADA ou INTEGRAÇÃO NÃO CONFIGURADA.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {adapters.map((ad) => (
                <div
                  key={ad.id}
                  className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-[#080b10] space-y-2"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-xs font-bold text-slate-900 dark:text-slate-100">
                        {ad.name} (v{ad.version})
                      </div>
                      <div className="text-[11px] text-slate-500">
                        {ad.vendor} · Formato Canônico: <code className="font-mono">{ad.canonicalFormat}</code>
                      </div>
                    </div>
                    <div className="text-xs font-mono font-bold shrink-0">
                      {ad.status === 'OPERATIONAL' ? (
                        <span className="text-emerald-600 dark:text-[#31d6c4] inline-flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          OPERATIONAL
                        </span>
                      ) : (
                        <span className="text-amber-500 inline-flex items-center gap-1">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          {ad.status}
                        </span>
                      )}
                    </div>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-300">{ad.description}</p>

                  <div className="pt-2 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-500">
                    <span>Método: {ad.executionMethod}</span>
                    <span>Assinatura: {ad.signatureHash.slice(0, 14)}...</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {latestRun && (
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
              <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-[#31d6c4]" />
                <span>Histórico de Execução dos Workers &amp; Logs Estruturados</span>
              </h3>
              <div className="space-y-3 max-h-96 df-hover-scroll">
                {latestRun.toolExecutions.map((ex) => (
                  <div
                    key={ex.id}
                    className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] text-xs font-mono space-y-1.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 font-sans font-semibold text-slate-900 dark:text-slate-100">
                      <span>
                        {ex.toolName} v{ex.toolVersion} — {ex.canonicalFormat}
                      </span>
                      <span className="font-mono text-[#31d6c4]">
                        Exit Code: {ex.exitCode} · Duração: {ex.durationMs}ms · {ex.veracityStatus}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 space-y-0.5">
                      {ex.logs.map((line, i) => (
                        <div key={i}>{line}</div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Sub-Tab 3: Reports & RBAC Audit Logs */}
      {subTab === 'reports' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Report Generator Card */}
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4 h-fit">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
              <FileText className="w-4 h-4 text-[#31d6c4]" />
              <span>Exportação Oficial de Relatórios</span>
            </h2>

            <div>
              <label
                htmlFor="rep-type"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5"
              >
                Selecione a Modalidade do Relatório (10 Tipos)
              </label>
              <select
                id="rep-type"
                value={selectedReportType}
                onChange={(e) => setSelectedReportType(e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
              >
                {REPORT_TYPES.map((rt) => (
                  <option key={rt.id} value={rt.id}>
                    {rt.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-2.5 pt-2">
              <button
                type="button"
                disabled={!latestRun}
                onClick={() => handleDownloadReport('sarif')}
                className="w-full inline-flex items-center justify-between px-4 py-2.5 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] disabled:opacity-50 cursor-pointer"
                title="Exportar no formato canônico oficial SARIF 2.1.0 (SonarQube e GitHub Code Scanning)"
              >
                <span>Exportar SARIF 2.1.0 (SonarQube &amp; GitHub)</span>
                <Download className="w-4 h-4" />
              </button>

              <button
                type="button"
                disabled={!latestRun}
                onClick={() => handleDownloadReport('html')}
                className="w-full inline-flex items-center justify-between px-4 py-2.5 rounded-lg text-xs font-semibold border border-[#31d6c4]/40 bg-[#31d6c4]/10 text-[#0e9f8e] dark:text-[#31d6c4] hover:bg-[#31d6c4]/20 disabled:opacity-50 cursor-pointer"
                title="Exportar Dossiê HTML Interativo com Gráficos e Estilos Autônomos"
              >
                <span>Exportar Dossiê Interativo (HTML)</span>
                <FileText className="w-4 h-4 text-[#31d6c4]" />
              </button>

              <button
                type="button"
                disabled={!latestRun}
                onClick={() => handleDownloadReport('json')}
                className="w-full inline-flex items-center justify-between px-4 py-2.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
              >
                <span>Exportar Pacote Estruturado (JSON)</span>
                <Download className="w-4 h-4" />
              </button>

              <button
                type="button"
                disabled={!latestRun}
                onClick={() => handleDownloadReport('csv')}
                className="w-full inline-flex items-center justify-between px-4 py-2.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
              >
                <span>Exportar Planilha Técnica (CSV / Excel)</span>
                <FileSpreadsheet className="w-4 h-4 text-[#31d6c4]" />
              </button>

              <button
                type="button"
                disabled={!latestRun}
                onClick={() => handleDownloadReport('md')}
                className="w-full inline-flex items-center justify-between px-4 py-2.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
              >
                <span>Exportar Dossiê Técnico (Markdown)</span>
                <FileText className="w-4 h-4 text-[#31d6c4]" />
              </button>

              <button
                type="button"
                disabled={!latestRun}
                onClick={handlePrintPdfReport}
                className="w-full inline-flex items-center justify-between px-4 py-2.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
              >
                <span>Imprimir / Salvar Relatório Executivo (PDF)</span>
                <Printer className="w-4 h-4 text-[#31d6c4]" />
              </button>
            </div>
          </div>

          {/* Live Report Preview + Audit Trail */}
          <div className="lg:col-span-2 space-y-6">
            {latestRun && (
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
                <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
                  <div className="text-xs font-mono text-slate-500">
                    PRÉ-VISUALIZAÇÃO DO RELATÓRIO: {selectedReportType} · EXECUÇÃO {latestRun.id}
                  </div>
                  <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100 mt-1">
                    {latestRun.projectName}
                  </h3>
                  <p className="text-xs text-slate-600 dark:text-slate-300 mt-1">
                    {latestRun.executiveSummary}
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  {latestRun.scoreCards.map((sc) => (
                    <div
                      key={sc.softwareId}
                      className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-2.5"
                    >
                      <div className="font-bold text-slate-900 dark:text-slate-100 flex items-center justify-between">
                        <span>
                          {sc.softwareName} (v{sc.softwareVersion})
                        </span>
                        <span className="font-mono text-[#31d6c4]">
                          {sc.groupedScores.overallScore.toFixed(2)} / 5.00 ({sc.classificationLabel})
                        </span>
                      </div>

                      {/* SonarQube Quality Gate & Ratings Banner */}
                      <div className="p-2.5 rounded bg-white dark:bg-[#0c1017] border border-slate-200 dark:border-slate-800 font-mono text-[11px] space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-slate-500">Quality Gate:</span>
                          <span
                            className={`font-bold ${
                              sc.qualityGate?.status === 'PASSED'
                                ? 'text-emerald-500'
                                : sc.qualityGate?.status === 'WARN'
                                  ? 'text-amber-500'
                                  : 'text-rose-500'
                            }`}
                          >
                            {sc.qualityGate?.status || 'NÃO AVALIADO'}
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-slate-400">
                          <span>Ratings (A-E):</span>
                          <span className="text-slate-200">
                            Segurança: <strong>{sc.ratings?.security || 'A'}</strong> · Confiabilidade: <strong>{sc.ratings?.reliability || 'A'}</strong> · Manutenibilidade: <strong>{sc.ratings?.maintainability || 'A'}</strong>
                          </span>
                        </div>
                      </div>

                      <div>
                        <strong className="text-emerald-600 dark:text-[#31d6c4]">Vantagens:</strong>
                        <ul className="list-disc list-inside text-slate-600 dark:text-slate-300 mt-0.5 space-y-0.5">
                          {sc.advantages.map((a, i) => (
                            <li key={i}>{a}</li>
                          ))}
                        </ul>
                      </div>
                      {sc.deficiencies.length > 0 && (
                        <div>
                          <strong className="text-rose-500">Deficiências &amp; Riscos:</strong>
                          <ul className="list-disc list-inside text-slate-600 dark:text-slate-300 mt-0.5 space-y-0.5">
                            {sc.deficiencies.map((d, i) => (
                              <li key={i}>{d}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Platform Audit Log */}
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-3">
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#31d6c4]" />
                <span>Logs de Auditoria de Segurança e Operações da Plataforma ({auditLogs.length})</span>
              </h3>
              <div className="overflow-x-auto max-h-64 df-hover-scroll">
                <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                      <th className="py-2 pr-3">Timestamp</th>
                      <th className="py-2 px-3">Ator (RBAC)</th>
                      <th className="py-2 px-3">Ação</th>
                      <th className="py-2 px-3">Detalhes</th>
                      <th className="py-2 pl-3">Integridade</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                    {auditLogs.map((log) => (
                      <tr key={log.id}>
                        <td className="py-2 pr-3 text-slate-500 whitespace-nowrap">
                          {new Date(log.timestamp).toLocaleTimeString('pt-BR')}
                        </td>
                        <td className="py-2 px-3 font-sans text-slate-800 dark:text-slate-200 whitespace-nowrap">
                          {log.actor}
                        </td>
                        <td className="py-2 px-3 font-semibold text-[#31d6c4] whitespace-nowrap">
                          {log.action}
                        </td>
                        <td className="py-2 px-3 font-sans text-slate-600 dark:text-slate-300">
                          {log.details}
                        </td>
                        <td className="py-2 pl-3 text-slate-400">
                          <Hash className="w-3 h-3 inline mr-0.5" />
                          {log.integrityHash.slice(0, 10)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
