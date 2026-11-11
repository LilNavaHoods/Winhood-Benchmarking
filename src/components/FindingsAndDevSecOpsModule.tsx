import React, { useMemo, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Code2,
  FileCode,
  GitCommit,
  Hash,
  Info,
  KeyRound,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { BenchmarkRun, NormalizedFinding, SeverityLevel } from '../types/benchmark';
import { CATEGORY_LABELS } from './DashboardModule';

interface FindingsAndDevSecOpsModuleProps {
  latestRun: BenchmarkRun | null;
  onRunUpdated?: (updatedRun: BenchmarkRun) => void;
  onNotify?: (msg: string, type?: 'success' | 'error') => void;
}

export const FindingsAndDevSecOpsModule: React.FC<FindingsAndDevSecOpsModuleProps> = ({
  latestRun,
  onRunUpdated,
  onNotify,
}) => {
  const [selectedSoftwareId, setSelectedSoftwareId] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedToolId, setSelectedToolId] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [triageLoadingId, setTriageLoadingId] = useState<string | null>(null);

  const findings = latestRun?.findings || [];

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (selectedSoftwareId !== 'ALL' && f.softwareId !== selectedSoftwareId) return false;
      if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) return false;
      if (selectedCategory !== 'ALL' && f.category !== selectedCategory) return false;
      if (selectedToolId !== 'ALL' && f.toolId !== selectedToolId) return false;
      if (searchQuery.trim().length > 0) {
        const q = searchQuery.toLowerCase();
        const match =
          f.title.toLowerCase().includes(q) ||
          f.filePath.toLowerCase().includes(q) ||
          f.originalRuleId.toLowerCase().includes(q) ||
          (f.whyItIsAnIssue && f.whyItIsAnIssue.toLowerCase().includes(q)) ||
          (f.cwe && f.cwe.toLowerCase().includes(q)) ||
          (f.cve && f.cve.toLowerCase().includes(q));
        if (!match) return false;
      }
      return true;
    });
  }, [findings, selectedSoftwareId, selectedSeverity, selectedCategory, selectedToolId, searchQuery]);

  const activeFinding = useMemo(() => {
    if (selectedFindingId) {
      const found = findings.find((f) => f.id === selectedFindingId);
      if (found) return found;
    }
    return filteredFindings[0] || null;
  }, [findings, filteredFindings, selectedFindingId]);

  const handleUpdateFindingStatus = async (
    finding: NormalizedFinding,
    newStatus:
      | 'VALIDATED'
      | 'ACCEPTED'
      | 'FALSE_POSITIVE_REVIEWED'
      | 'CONFIRMED'
      | 'PROBABLE'
      | 'FALSE_POSITIVE'
      | 'INCONCLUSIVE'
      | 'NOT_REPRODUCIBLE'
      | 'NOT_TESTED'
      | 'ACCEPTED_RISK'
      | 'FIXED_PENDING_RETEST'
      | 'VERIFIED_RESOLVED'
  ) => {
    if (!latestRun) return;
    setTriageLoadingId(finding.id);
    try {
      const res = await fetch(`/api/findings/${finding.id}/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          runId: latestRun.id,
          validationStatus: newStatus,
          lifecycleState: [
            'CONFIRMED',
            'PROBABLE',
            'FALSE_POSITIVE',
            'INCONCLUSIVE',
            'NOT_REPRODUCIBLE',
            'NOT_TESTED',
            'ACCEPTED_RISK',
            'FIXED_PENDING_RETEST',
            'VERIFIED_RESOLVED',
          ].includes(newStatus)
            ? newStatus
            : undefined,
          verificationNote: `Status alterado na Central DevSecOps para ${newStatus} com recálculo em tempo real do ScoreCard, Ratings A-E, Quality Gate e re-assinatura HMAC-SHA256.`,
        }),
      });
      const data = await res.json();
      if (res.ok && data.run) {
        if (onRunUpdated) {
          onRunUpdated(data.run);
        }
        if (onNotify) {
          onNotify(
            `Status do apontamento [${finding.originalRuleId}] atualizado para ${newStatus}. Notas, Ratings A–E e Quality Gate recalculados em tempo real!`,
            'success'
          );
        }
      } else if (onNotify) {
        onNotify(data.error || 'Falha ao atualizar status do apontamento.', 'error');
      }
    } catch {
      if (onNotify) {
        onNotify('Erro de conexão ao atualizar triagem DevSecOps.', 'error');
      }
    } finally {
      setTriageLoadingId(null);
    }
  };

  const renderSeverityLabel = (sev: SeverityLevel) => {
    switch (sev) {
      case 'BLOCKER':
        return (
          <span className="inline-flex items-center gap-1 font-bold text-rose-700 dark:text-rose-300 bg-rose-500/15 px-1.5 py-0.5 rounded border border-rose-500/30">
            <AlertOctagon className="w-3.5 h-3.5 shrink-0" />
            BLOCKER
          </span>
        );
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1 font-bold text-rose-600 dark:text-rose-400">
            <AlertOctagon className="w-3.5 h-3.5 shrink-0" />
            CRÍTICO
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1 font-bold text-orange-600 dark:text-orange-400">
            <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
            ALTO
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1 font-semibold text-amber-600 dark:text-amber-400">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            MÉDIO
          </span>
        );
      case 'LOW':
        return (
          <span className="inline-flex items-center gap-1 font-medium text-sky-600 dark:text-sky-400">
            <Info className="w-3.5 h-3.5 shrink-0" />
            BAIXO
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 text-slate-500 dark:text-slate-400">
            <Info className="w-3.5 h-3.5 shrink-0" />
            INFO
          </span>
        );
    }
  };

  if (!latestRun) {
    return (
      <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-8 text-center">
        <p className="text-sm text-slate-500">
          Nenhuma execução de benchmark disponível. Execute um benchmark no Wizard para inspecionar os achados de Qualidade e DevSecOps.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
          Central de Qualidade de Código, Taint Analysis &amp; Triagem DevSecOps (MQR)
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
          Rastreabilidade total no código-fonte (linha/coluna, contexto ±2 linhas, fluxo Source-to-Sink, impactos MQR nas 12 categorias e recálculo em tempo real ao aceitar ou revisar falsos positivos).
        </p>
      </div>

      {/* Comparative Quality & Security Summary Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {latestRun.scoreCards.map((sc) => (
          <div
            key={sc.softwareId}
            className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5"
          >
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  {sc.softwareName} (v{sc.softwareVersion})
                </h2>
                <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-mono">
                  <span>Nota Geral: <strong>{sc.groupedScores.overallScore.toFixed(2)}/5.00</strong></span>
                  <span className="mx-1.5">·</span>
                  <span>Segurança: {sc.groupedScores.securityScore.toFixed(2)} (Rating {sc.ratings?.security || 'A'})</span>
                  <span className="mx-1.5">·</span>
                  <span>Qualidade: {sc.groupedScores.qualityScore.toFixed(2)} (Rating {sc.ratings?.maintainability || 'A'})</span>
                  <span className="mx-1.5">·</span>
                  <span>Confiabilidade: Rating {sc.ratings?.reliability || 'A'}</span>
                </div>
              </div>
              <button
                type="button"
                onClick={() =>
                  setSelectedSoftwareId((prev) =>
                    prev === sc.softwareId ? 'ALL' : sc.softwareId
                  )
                }
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors cursor-pointer ${
                  selectedSoftwareId === sc.softwareId
                    ? 'bg-[#31d6c4] text-slate-950'
                    : 'border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300'
                }`}
              >
                {selectedSoftwareId === sc.softwareId ? 'Mostrando Apenas Este' : 'Filtrar Software'}
              </button>
            </div>

            <div className="grid grid-cols-3 sm:grid-cols-6 gap-2.5 mt-4 text-xs font-mono tabular-nums">
              <div>
                <div className="text-slate-400 font-sans text-[11px]">Críticas</div>
                <div className="font-bold text-rose-500 text-sm">{sc.metricsSummary.criticalVulns}</div>
              </div>
              <div>
                <div className="text-slate-400 font-sans text-[11px]">Segredos</div>
                <div className="font-bold text-rose-500 text-sm">{sc.metricsSummary.secretsExposed}</div>
              </div>
              <div>
                <div className="text-slate-400 font-sans text-[11px]">Bugs</div>
                <div className="font-bold text-amber-500 text-sm">{sc.metricsSummary.bugs}</div>
              </div>
              <div>
                <div className="text-slate-400 font-sans text-[11px]">Code Smells</div>
                <div className="font-bold text-slate-900 dark:text-slate-100 text-sm">
                  {sc.metricsSummary.codeSmells}
                </div>
              </div>
              <div>
                <div className="text-slate-400 font-sans text-[11px]">Quality Gate</div>
                <div
                  className={`font-bold text-sm ${
                    sc.qualityGate?.status === 'PASSED'
                      ? 'text-emerald-500'
                      : sc.qualityGate?.status === 'WARN'
                        ? 'text-amber-500'
                        : 'text-rose-500'
                  }`}
                >
                  {sc.qualityGate?.status || 'N/A'}
                </div>
              </div>
              <div>
                <div className="text-slate-400 font-sans text-[11px]">Dívida Técnica</div>
                <div className="font-bold text-slate-900 dark:text-slate-100 text-sm">
                  {sc.metricsSummary.technicalDebtMinutes}m
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Filters Toolbar */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <div>
            <label
              htmlFor="flt-search"
              className="block text-[11px] font-semibold text-slate-500 mb-1"
            >
              Buscar por Regra, Arquivo, CWE ou Motivo
            </label>
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                id="flt-search"
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Ex: CWE-89, sql, masterKey..."
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] pl-8 pr-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="flt-software"
              className="block text-[11px] font-semibold text-slate-500 mb-1"
            >
              Software Analisado
            </label>
            <select
              id="flt-software"
              value={selectedSoftwareId}
              onChange={(e) => setSelectedSoftwareId(e.target.value)}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
            >
              <option value="ALL">Todos os Softwares</option>
              {latestRun.scoreCards.map((sc) => (
                <option key={sc.softwareId} value={sc.softwareId}>
                  {sc.softwareName}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label
              htmlFor="flt-sev"
              className="block text-[11px] font-semibold text-slate-500 mb-1"
            >
              Severidade
            </label>
            <select
              id="flt-sev"
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
            >
              <option value="ALL">Todas as Severidades</option>
              <option value="BLOCKER">BLOCKER (Bloqueador)</option>
              <option value="CRITICAL">CRITICAL (Crítico)</option>
              <option value="HIGH">HIGH (Alto)</option>
              <option value="MEDIUM">MEDIUM (Médio)</option>
              <option value="LOW">LOW (Baixo)</option>
              <option value="INFO">INFO (Informativo)</option>
            </select>
          </div>

          <div>
            <label
              htmlFor="flt-cat"
              className="block text-[11px] font-semibold text-slate-500 mb-1"
            >
              Categoria de Análise
            </label>
            <select
              id="flt-cat"
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
            >
              <option value="ALL">Todas as Categorias</option>
              <option value="SAST">SAST (Segurança Estática)</option>
              <option value="SECRETS">SECRETS (Segredos Expostos)</option>
              <option value="SCA">SCA (Dependências Vulneráveis)</option>
              <option value="CODE_QUALITY">CODE_QUALITY (Qualidade)</option>
              <option value="ARCHITECTURE">ARCHITECTURE (Arquitetura)</option>
              <option value="DATABASE">DATABASE (Banco de Dados SQL)</option>
            </select>
          </div>

          <div>
            <label
              htmlFor="flt-tool"
              className="block text-[11px] font-semibold text-slate-500 mb-1"
            >
              Ferramenta de Origem
            </label>
            <select
              id="flt-tool"
              value={selectedToolId}
              onChange={(e) => setSelectedToolId(e.target.value)}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
            >
              <option value="ALL">Todas as Ferramentas</option>
              <option value="opengrep-sast">Opengrep SAST Engine</option>
              <option value="gitleaks-secrets">Gitleaks Secret Scanner</option>
              <option value="sonarqube-quality">SonarQube Static Analyzer</option>
              <option value="syft-grype-sca">Syft SBOM &amp; Grype SCA</option>
              <option value="archunit-cruiser">Dependency Cruiser &amp; ArchUnit</option>
              <option value="sqlfluff-db">SQLFluff &amp; Schema Auditor</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table + Evidence Detail Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] overflow-hidden h-fit">
          <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
            <span className="text-xs font-bold text-slate-800 dark:text-slate-200">
              Achados Normalizados e Rastreáveis ({filteredFindings.length})
            </span>
            <span className="text-[11px] text-slate-500">
              Clique em um apontamento para inspecionar código, fluxo Taint e triagem MQR
            </span>
          </div>

          <div className="overflow-x-auto max-h-[680px] df-hover-scroll">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50 dark:bg-[#080b10] text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800">
                  <th className="py-2.5 px-4">Severidade / Status</th>
                  <th className="py-2.5 px-3">Software</th>
                  <th className="py-2.5 px-3">Apontamento, Regra &amp; Impactos MQR</th>
                  <th className="py-2.5 px-3">Arquivo : Linha</th>
                  <th className="py-2.5 px-3 text-right">CWE / CVSS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {filteredFindings.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500">
                      Nenhum achado encontrado para os filtros selecionados dentro do escopo analisado.
                    </td>
                  </tr>
                ) : (
                  filteredFindings.map((f) => {
                    const isSelected = activeFinding?.id === f.id;
                    const isExempt =
                      [
                        'ACCEPTED',
                        'ACCEPTED_RISK',
                        'FALSE_POSITIVE_REVIEWED',
                        'FALSE_POSITIVE',
                        'NOT_REPRODUCIBLE',
                        'INCONCLUSIVE',
                        'VERIFIED_RESOLVED',
                      ].includes(f.validationStatus) ||
                      (f.lifecycleState &&
                        [
                          'ACCEPTED_RISK',
                          'FALSE_POSITIVE',
                          'NOT_REPRODUCIBLE',
                          'INCONCLUSIVE',
                          'VERIFIED_RESOLVED',
                        ].includes(f.lifecycleState));
                    return (
                      <tr
                        key={f.id}
                        onClick={() => setSelectedFindingId(f.id)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-[#31d6c4]/10'
                            : isExempt
                              ? 'opacity-60 bg-slate-50/40 dark:bg-slate-900/30 hover:opacity-90'
                              : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                        }`}
                      >
                        <td className="py-3 px-4 font-mono whitespace-nowrap space-y-1">
                          <div>{renderSeverityLabel(f.severity)}</div>
                          <div
                            className={`text-[10px] font-bold px-1.5 py-0.5 rounded inline-block ${
                              f.validationStatus === 'ACCEPTED'
                                ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                                : f.validationStatus === 'FALSE_POSITIVE_REVIEWED'
                                  ? 'bg-slate-500/20 text-slate-300 border border-slate-500/30'
                                  : 'bg-emerald-500/15 text-[#31d6c4] border border-[#31d6c4]/30'
                            }`}
                          >
                            {f.validationStatus}
                          </div>
                        </td>
                        <td className="py-3 px-3 font-medium text-slate-800 dark:text-slate-200 whitespace-nowrap">
                          {f.softwareName}
                        </td>
                        <td className="py-3 px-3">
                          <div className="font-semibold text-slate-900 dark:text-slate-100">
                            {f.title}
                          </div>
                          <div className="text-[11px] font-mono text-slate-500 mt-0.5">
                            <span>{f.category}</span>
                            <span className="mx-1.5">·</span>
                            <span>{f.originalRuleId}</span>
                            <span className="mx-1.5">·</span>
                            <span>{f.toolName}</span>
                          </div>
                          {f.mqrImpacts && f.mqrImpacts.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1.5">
                              {f.mqrImpacts.map((imp, idx) => (
                                <span
                                  key={`${imp.benchmarkCategory}-${idx}`}
                                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                                    isExempt
                                      ? 'border-slate-600 text-slate-400 line-through'
                                      : 'border-rose-500/30 bg-rose-500/10 text-rose-400 font-bold'
                                  }`}
                                >
                                  {CATEGORY_LABELS[imp.benchmarkCategory] || imp.benchmarkCategory}:{' '}
                                  {imp.scoreDeduction.toFixed(2)} pts ({imp.softwareQuality})
                                </span>
                              ))}
                            </div>
                          )}
                        </td>
                        <td className="py-3 px-3 font-mono tabular-nums text-slate-600 dark:text-slate-300 whitespace-nowrap">
                          <div>
                            {f.filePath}:{f.lineNumber}
                            {f.endLineNumber && f.endLineNumber > f.lineNumber ? `-${f.endLineNumber}` : ''}
                          </div>
                          {f.columnStart && (
                            <div className="text-[10px] text-slate-400">
                              Col {f.columnStart}–{f.columnEnd || f.columnStart + 20}
                            </div>
                          )}
                        </td>
                        <td className="py-3 px-3 text-right font-mono tabular-nums whitespace-nowrap">
                          <div>{f.cwe || f.cve || '—'}</div>
                          {f.cvss && (
                            <div className="text-[11px] text-rose-500 font-bold">
                              CVSS {f.cvss.toFixed(1)}
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Evidence Inspector & DevSecOps Triage Panel */}
        <div className="lg:col-span-5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 h-fit space-y-4">
          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
            <FileCode className="w-4 h-4 text-[#31d6c4]" />
            <span>Inspetor MQR: Onde no Código, Por Quê &amp; Impacto na Nota</span>
          </h3>

          {!activeFinding ? (
            <p className="text-xs text-slate-500">
              Selecione qualquer linha na tabela ao lado para inspecionar o código-fonte com contexto, o fluxo Source-to-Sink e realizar a triagem DevSecOps.
            </p>
          ) : (
            (() => {
              const item = activeFinding;
              const isTriageLoading = triageLoadingId === item.id;
              return (
                <div className="space-y-4 text-xs">
                  {/* DevSecOps Real-Time Triage Action Bar (9 Lifecycle States + Quick Buttons) */}
                  <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                        Triagem DevSecOps (9 Estados + Recálculo MQR em Tempo Real)
                      </span>
                      <span className="font-mono text-[11px] font-bold text-[#31d6c4]">
                        {item.lifecycleState || item.validationStatus}
                      </span>
                    </div>
                    <div className="grid grid-cols-3 gap-2">
                      <button
                        type="button"
                        disabled={isTriageLoading}
                        onClick={() => handleUpdateFindingStatus(item, 'VALIDATED')}
                        className={`px-2.5 py-1.5 rounded text-[11px] font-bold border transition-colors cursor-pointer ${
                          item.validationStatus === 'VALIDATED' || item.lifecycleState === 'CONFIRMED'
                            ? 'bg-rose-500 text-white border-rose-500'
                            : 'border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-rose-500'
                        }`}
                      >
                        VALIDATED (Ativo)
                      </button>
                      <button
                        type="button"
                        disabled={isTriageLoading}
                        onClick={() => handleUpdateFindingStatus(item, 'ACCEPTED')}
                        className={`px-2.5 py-1.5 rounded text-[11px] font-bold border transition-colors cursor-pointer ${
                          item.validationStatus === 'ACCEPTED' || item.lifecycleState === 'ACCEPTED_RISK'
                            ? 'bg-amber-500 text-slate-950 border-amber-500'
                            : 'border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-amber-400'
                        }`}
                      >
                        ACCEPTED (Isentar)
                      </button>
                      <button
                        type="button"
                        disabled={isTriageLoading}
                        onClick={() => handleUpdateFindingStatus(item, 'FALSE_POSITIVE_REVIEWED')}
                        className={`px-2.5 py-1.5 rounded text-[11px] font-bold border transition-colors cursor-pointer ${
                          item.validationStatus === 'FALSE_POSITIVE_REVIEWED' ||
                          item.lifecycleState === 'FALSE_POSITIVE'
                            ? 'bg-[#31d6c4] text-slate-950 border-[#31d6c4]'
                            : 'border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-[#31d6c4]'
                        }`}
                      >
                        FALSE_POSITIVE
                      </button>
                    </div>

                    <div className="flex items-center justify-between gap-2 pt-1 border-t border-slate-200 dark:border-slate-800/80">
                      <label
                        htmlFor="lifecycle-select"
                        className="text-[10px] font-mono text-slate-400 shrink-0"
                      >
                        Ciclo Completo (9 Estados):
                      </label>
                      <select
                        id="lifecycle-select"
                        disabled={isTriageLoading}
                        value={item.lifecycleState || 'CONFIRMED'}
                        onChange={(e) => handleUpdateFindingStatus(item, e.target.value as any)}
                        className="rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-2 py-1 text-[11px] font-mono text-slate-900 dark:text-slate-100"
                      >
                        <option value="CONFIRMED">1. CONFIRMED (Confirmada)</option>
                        <option value="PROBABLE">2. PROBABLE (Provável)</option>
                        <option value="FALSE_POSITIVE">3. FALSE_POSITIVE (Falso Positivo — Isenta)</option>
                        <option value="INCONCLUSIVE">4. INCONCLUSIVE (Inconclusiva — Isenta)</option>
                        <option value="NOT_REPRODUCIBLE">5. NOT_REPRODUCIBLE (Não Reproduzível — Isenta)</option>
                        <option value="NOT_TESTED">6. NOT_TESTED (Não Testada)</option>
                        <option value="ACCEPTED_RISK">7. ACCEPTED_RISK (Risco Aceito — Isenta)</option>
                        <option value="FIXED_PENDING_RETEST">8. FIXED_PENDING_RETEST (Aguardando Reteste)</option>
                        <option value="VERIFIED_RESOLVED">9. VERIFIED_RESOLVED (Resolvida — Isenta)</option>
                      </select>
                    </div>
                  </div>

                  {/* Header & Metadata */}
                  <div>
                    <div className="flex items-center justify-between">
                      {renderSeverityLabel(item.severity)}
                      <span className="font-mono text-[11px] text-slate-400 flex items-center gap-1">
                        <Clock className="w-3 h-3 text-[#31d6c4]" />
                        Esforço: {item.remediationEffortMinutes || 20} min · Clean Code:{' '}
                        <strong>{item.cleanCodeAttribute || 'TRUSTWORTHY'}</strong>
                      </span>
                    </div>
                    <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-2">
                      {item.title}
                    </h4>
                  </div>

                  {/* Location Box */}
                  <div className="p-3 rounded bg-slate-100 dark:bg-[#080b10] font-mono tabular-nums space-y-1 text-[11px] border border-slate-200 dark:border-slate-800">
                    <div>
                      <strong>Software:</strong> {item.softwareName} (v{item.softwareVersion})
                    </div>
                    <div>
                      <strong>Arquivo &amp; Coordenadas:</strong>{' '}
                      <span className="text-[#31d6c4]">
                        {item.filePath}:{item.lineNumber}
                        {item.endLineNumber && item.endLineNumber > item.lineNumber
                          ? `-${item.endLineNumber}`
                          : ''}
                      </span>{' '}
                      (Colunas {item.columnStart || 1}–{item.columnEnd || 80})
                    </div>
                    <div>
                      <strong>Regra &amp; Motor:</strong> {item.originalRuleId} ({item.toolName} v{item.toolVersion})
                    </div>
                    {(item.cwe || item.cve || item.cvss) && (
                      <div>
                        <strong>Classificação Oficial:</strong>{' '}
                        {[item.cwe, item.cve, item.cvss ? `CVSS ${item.cvss.toFixed(1)}` : null]
                          .filter(Boolean)
                          .join(' · ')}
                      </div>
                    )}
                  </div>

                  {/* Why It Is An Issue & MQR Impacts */}
                  <div className="p-3.5 rounded-lg border border-rose-500/30 bg-rose-500/5 space-y-2">
                    <div className="font-bold text-rose-600 dark:text-rose-400 flex items-center gap-1.5">
                      <ShieldAlert className="w-4 h-4 shrink-0" />
                      <span>Por Que Este Trecho é um Problema e Como Descontou Pontos</span>
                    </div>
                    <p className="text-slate-700 dark:text-slate-200 leading-relaxed">
                      {item.whyItIsAnIssue || item.description}
                    </p>
                    {item.evaluationImpactSummary && (
                      <div className="text-[11px] font-mono text-rose-500 dark:text-rose-300 pt-1 border-t border-rose-500/20">
                        <strong>Resumo de Impacto:</strong> {item.evaluationImpactSummary}
                      </div>
                    )}
                    {item.mqrImpacts && item.mqrImpacts.length > 0 && (
                      <div className="space-y-1 pt-1">
                        {item.mqrImpacts.map((imp, idx) => (
                          <div
                            key={`${imp.benchmarkCategory}-${idx}`}
                            className="p-2 rounded bg-white/80 dark:bg-[#080b10] border border-rose-500/20 font-mono text-[11px]"
                          >
                            <div className="flex items-center justify-between font-bold text-rose-500">
                              <span>
                                [{imp.softwareQuality}] Categoria:{' '}
                                {CATEGORY_LABELS[imp.benchmarkCategory] || imp.benchmarkCategory}
                              </span>
                              <span>{imp.scoreDeduction.toFixed(2)} pts ({imp.severity})</span>
                            </div>
                            <div className="font-sans text-slate-600 dark:text-slate-400 mt-0.5">
                              {imp.rationale}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Code Snippet with +-2 Context Lines */}
                  <div>
                    <div className="font-semibold text-slate-700 dark:text-slate-300 mb-1 flex items-center justify-between">
                      <span>Trecho Exato no Código-Fonte (com Contexto Anterior/Posterior)</span>
                      <KeyRound className="w-3.5 h-3.5 text-[#31d6c4]" />
                    </div>
                    <div className="rounded-lg bg-slate-950 border border-slate-800 p-3 font-mono text-[11px] overflow-x-auto space-y-0.5">
                      {(item.contextBefore || []).map((ctxLine, i) => {
                        const lineNum = Math.max(1, item.lineNumber - (item.contextBefore?.length || 0) + i);
                        return (
                          <div key={`before-${i}`} className="text-slate-500 flex gap-3">
                            <span className="w-8 text-right select-none opacity-60">{lineNum}</span>
                            <span className="whitespace-pre">{ctxLine}</span>
                          </div>
                        );
                      })}
                      <div className="bg-rose-500/20 border-l-2 border-rose-500 text-rose-200 font-bold flex gap-3 py-0.5 px-1 -mx-1 rounded-r">
                        <span className="w-8 text-right select-none text-rose-400">{item.lineNumber}</span>
                        <span className="whitespace-pre">{item.snippet}</span>
                      </div>
                      {(item.contextAfter || []).map((ctxLine, i) => {
                        const lineNum = (item.endLineNumber || item.lineNumber) + i + 1;
                        return (
                          <div key={`after-${i}`} className="text-slate-500 flex gap-3">
                            <span className="w-8 text-right select-none opacity-60">{lineNum}</span>
                            <span className="whitespace-pre">{ctxLine}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Taint Analysis / Execution Flow (SOURCE -> PROPAGATOR -> SANITIZER_MISSING -> SINK) */}
                  {item.executionFlows && item.executionFlows.length > 0 && (
                    <div className="p-3.5 rounded-lg border border-amber-500/30 bg-amber-500/5 space-y-2.5">
                      <div className="font-bold text-amber-600 dark:text-amber-400 flex items-center gap-1.5">
                        <GitCommit className="w-4 h-4 shrink-0" />
                        <span>Rastreamento de Fluxo no Código (Taint Analysis: Source → Sink)</span>
                      </div>
                      <div className="space-y-2">
                        {item.executionFlows.map((flowStep, idx) => (
                          <div
                            key={`${flowStep.stepIndex}-${idx}`}
                            className="p-2.5 rounded bg-white dark:bg-[#080b10] border border-amber-500/20 space-y-1"
                          >
                            <div className="flex items-center justify-between font-mono text-[10px]">
                              <span
                                className={`px-1.5 py-0.5 rounded font-bold ${
                                  flowStep.nodeType === 'SOURCE'
                                    ? 'bg-sky-500/20 text-sky-400'
                                    : flowStep.nodeType === 'SINK'
                                      ? 'bg-rose-500/20 text-rose-400'
                                      : flowStep.nodeType === 'SANITIZER_MISSING'
                                        ? 'bg-amber-500/20 text-amber-400'
                                        : 'bg-indigo-500/20 text-indigo-400'
                                }`}
                              >
                                PASSO {flowStep.stepIndex}: {flowStep.nodeType}
                              </span>
                              <span className="text-slate-400">
                                {flowStep.filePath}:{flowStep.lineNumber}
                              </span>
                            </div>
                            <pre className="text-[11px] font-mono text-[#31d6c4] overflow-x-auto">
                              {flowStep.codeSnippet}
                            </pre>
                            <p className="text-[11px] text-slate-600 dark:text-slate-400">
                              {flowStep.explanation}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Remediation & Compliant Code Example */}
                  <div className="space-y-2">
                    <div className="font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                      <ShieldCheck className="w-4 h-4 text-emerald-500" />
                      <span>Recomendação Técnica de Correção &amp; Exemplo Seguro (Compliant Code)</span>
                    </div>
                    <p className="p-3 rounded border border-emerald-500/30 bg-emerald-500/5 text-slate-700 dark:text-slate-200 leading-relaxed">
                      {item.remediation}
                    </p>
                    {item.compliantCodeExample && (
                      <div>
                        <div className="text-[10px] font-mono uppercase text-emerald-500 font-bold mb-1">
                          Exemplo de Implementação Segura (Compliant Solution):
                        </div>
                        <pre className="p-3 rounded bg-slate-950 border border-emerald-500/30 text-emerald-300 font-mono text-[11px] overflow-x-auto">
                          {item.compliantCodeExample}
                        </pre>
                      </div>
                    )}
                  </div>

                  <div className="pt-2 border-t border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-500 break-all">
                    <Hash className="w-3 h-3 inline mr-1 text-[#31d6c4]" />
                    <strong>Evidence SHA-256:</strong> {item.evidenceSha256}
                  </div>
                </div>
              );
            })()
          )}
        </div>
      </div>
    </div>
  );
};

