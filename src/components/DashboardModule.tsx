import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Award,
  CheckCircle2,
  Code2,
  Cpu,
  FileCheck2,
  FolderGit2,
  GitCommit,
  Layers,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Download,
} from 'lucide-react';
import type { BenchmarkCategoryKey, BenchmarkRun, VisualReportCategoryKey } from '../types/benchmark';
import { WinHoodLogo } from './WinHoodLogo';
import { HairlineAnimatedFigure } from './HairlineAnimatedFigure';

export const CATEGORY_LABELS: Record<BenchmarkCategoryKey, string> = {
  functionality: 'Funcionalidades',
  code_quality: 'Qualidade de Código',
  security: 'Segurança & Criptografia',
  performance: 'Desempenho',
  architecture: 'Arquitetura',
  database: 'Banco de Dados',
  reliability: 'Confiabilidade',
  compatibility: 'Compatibilidade',
  usability: 'Usabilidade',
  installation: 'Instalação (T0/T1/T2)',
  privacy: 'Privacidade',
  documentation: 'Documentação',
};

interface DashboardData {
  hasEvaluations: boolean;
  kpis: {
    totalProjects: number;
    totalSoftwares: number;
    totalRuns: number;
    runningAnalyses: number;
    completedAnalyses: number;
    failedAnalyses: number;
    vulnerabilitiesCount: number;
    codeQualityIssuesCount: number;
    avgPerformance: number | null;
    avgQuality: number | null;
  };
  latestRun: BenchmarkRun | null;
  historicalRuns: Array<{
    id: string;
    projectName: string;
    profileName: string;
    completedAt: string;
    status: string;
    scores: Array<{
      softwareId: string;
      softwareName: string;
      overallScore: number;
      securityScore: number;
      qualityScore: number;
    }>;
  }>;
}

interface DashboardModuleProps {
  data: DashboardData | null;
  loading: boolean;
  onNavigate: (tab: string) => void;
  onSeedRealWorkspace: () => Promise<void>;
  onResetEmptyWorkspace: () => Promise<void>;
}

export const DashboardModule: React.FC<DashboardModuleProps> = ({
  data,
  loading,
  onNavigate,
  onSeedRealWorkspace,
  onResetEmptyWorkspace,
}) => {
  const [selectedDrillCategory, setSelectedDrillCategory] =
    useState<BenchmarkCategoryKey>('security');

  if (loading && !data) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {Array.from({ length: 10 }).map((_, idx) => (
            <div
              key={idx}
              className="h-24 rounded-lg border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-4 animate-pulse"
            />
          ))}
        </div>
      </div>
    );
  }

  const kpis = data?.kpis || {
    totalProjects: 0,
    totalSoftwares: 0,
    totalRuns: 0,
    runningAnalyses: 0,
    completedAnalyses: 0,
    failedAnalyses: 0,
    vulnerabilitiesCount: 0,
    codeQualityIssuesCount: 0,
    avgPerformance: null,
    avgQuality: null,
  };

  const latestRun = data?.latestRun || null;

  return (
    <div className="space-y-8">
      {/* Header Toolbar */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800/80 pb-5">
        <div className="flex items-start gap-3.5">
          <WinHoodLogo size={48} className="shrink-0" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
              Dashboard Central de Benchmarking &amp; Qualidade
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
              Métricas consolidadas exclusivamente a partir das execuções reais persistidas no backend e validadas pelo Motor de Veracidade.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={() => onNavigate('sonar_hub')}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border border-[#31d6c4]/40 text-[#31d6c4] hover:bg-[#31d6c4]/10 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Exportar Relatório SonarCloud JSON
          </button>
          <button
            type="button"
            onClick={() => onNavigate('market_discovery')}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800/60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Award className="w-3.5 h-3.5 text-[#31d6c4]" />
            Pesquisa de Mercado
          </button>
          {data?.hasEvaluations ? (
            <>
              <button
                type="button"
                onClick={() => onNavigate('wizard')}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5" />
                Nova Execução de Benchmark
              </button>
              <button
                type="button"
                onClick={onResetEmptyWorkspace}
                className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800/60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                Simular Estado Inicial Vazio
              </button>
            </>
          ) : (
            <button
              type="button"
              onClick={onSeedRealWorkspace}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Executar Ingestão Real: Comparativo de Cofres de Senhas
            </button>
          )}
        </div>
      </div>

      {/* 10 Real Backend KPIs Grid (Frente 2.4: p-5 + tabular-nums + xl:grid-cols-5) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-4">
        <div className="rounded-lg border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Total de Projetos</span>
            <FolderGit2 className="w-4 h-4 text-[#31d6c4]" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {kpis.totalProjects}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Identificados por UUID v4
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Softwares Cadastrados</span>
            <Layers className="w-4 h-4 text-[#31d6c4]" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {kpis.totalSoftwares}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Artefatos com hash SHA-256
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Benchmarks Executados</span>
            <Activity className="w-4 h-4 text-[#31d6c4]" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {kpis.totalRuns}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            <span>Concluídos: {kpis.completedAnalyses}</span>
            <span className="mx-1.5">·</span>
            <span>Em curso: {kpis.runningAnalyses}</span>
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Vulnerabilidades</span>
            <ShieldAlert className="w-4 h-4 text-rose-500" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-rose-600 dark:text-rose-400">
            {kpis.vulnerabilitiesCount}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            SAST · SCA · Segredos · SQL
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Problemas de Qualidade</span>
            <Code2 className="w-4 h-4 text-amber-500" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-amber-600 dark:text-amber-400">
            {kpis.codeQualityIssuesCount}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Bugs · Code Smells · Ciclos
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Média de Qualidade</span>
            <FileCheck2 className="w-4 h-4 text-[#31d6c4]" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {kpis.avgQuality !== null ? `${kpis.avgQuality.toFixed(2)} / 5.00` : 'N/A'}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Escala determinística 0–5
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Média de Desempenho</span>
            <Cpu className="w-4 h-4 text-[#31d6c4]" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {kpis.avgPerformance !== null ? `${kpis.avgPerformance.toFixed(2)} / 5.00` : 'N/A'}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Ambiente equivalente validado
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Análises Concluídas</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-emerald-600 dark:text-emerald-400">
            {kpis.completedAnalyses}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Veracidade SUCCESS_VALIDATED
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Análises com Falha</span>
            <AlertTriangle className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {kpis.failedAnalyses}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Erros de parser ou timeout
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Evidências SHA-256</span>
            <ShieldCheck className="w-4 h-4 text-[#31d6c4]" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {latestRun ? latestRun.evidenceChain.length : 0}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Trilha append-only imutável
          </div>
        </div>
      </div>

      {/* Empty State when no evaluations exist (Requirement Section 6) */}
      {!data?.hasEvaluations || !latestRun ? (
        <div
          data-testid="empty-evaluations-state"
          className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-10 text-center max-w-3xl mx-auto my-8"
        >
          <ShieldCheck className="w-12 h-12 text-[#31d6c4] mx-auto mb-4" />
          <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">
            Ainda não existem avaliações ou benchmarks executados neste ambiente
          </h2>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-2 max-w-xl mx-auto">
            Em conformidade com a política de veracidade estrita da plataforma, nenhuma métrica fictícia ou demonstrativa é exibida sem execução real. Cadastre um projeto e importe o código-fonte dos softwares ou carregue os repositórios reais de referência para iniciar.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-4">
            <button
              type="button"
              onClick={onSeedRealWorkspace}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
            >
              <Play className="w-4 h-4" />
              Carregar e Analisar Repositórios Reais (VaultCore vs KeeSafe Open)
            </button>
            <button
              type="button"
              onClick={() => onNavigate('projects')}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-medium border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
            >
              Criar Projeto do Zero
            </button>
            <button
              type="button"
              onClick={() => onNavigate('user_guide')}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-semibold border border-[#31d6c4]/50 text-[#0e9f8e] dark:text-[#31d6c4] hover:bg-[#31d6c4]/10 transition-colors cursor-pointer"
            >
              Ler Guia Completo Passo a Passo
            </button>
          </div>
        </div>
      ) : (
        <>
          {/* Executive Verdict Banner */}
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-6">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
                  <span>Execução: {latestRun.id}</span>
                  <span>·</span>
                  <span>Algoritmo: {latestRun.algorithmVersion}</span>
                  <span>·</span>
                  <span>Status: {latestRun.status}</span>
                </div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <Award className="w-5 h-5 text-[#31d6c4] shrink-0" />
                  <span>{latestRun.projectName} — {latestRun.profileName}</span>
                </h2>
                <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed max-w-4xl">
                  {latestRun.executiveSummary}
                </p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <button
                  type="button"
                  onClick={() => onNavigate('findings')}
                  className="px-3.5 py-2 rounded-lg text-xs font-medium border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap cursor-pointer"
                >
                  Inspecionar Evidências ({latestRun.findings.length})
                </button>
                <button
                  type="button"
                  onClick={() => onNavigate('reports')}
                  className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors whitespace-nowrap cursor-pointer"
                >
                  Exportar Relatório Técnico
                </button>
              </div>
            </div>
          </div>

          {/* Comparability & Impartiality Status Banner (Seção 6) */}
          {latestRun.comparabilityReport && latestRun.scoreCards.length > 1 && (
            <div
              className={`rounded-lg border p-4 text-xs ${
                latestRun.comparabilityReport.canDeclareOfficialWinner
                  ? 'border-emerald-500/30 bg-emerald-500/5 text-slate-700 dark:text-slate-200'
                  : 'border-amber-500/40 bg-amber-500/10 text-amber-200'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                <span className="font-sans font-bold text-slate-900 dark:text-slate-100">
                  Motor de Comparabilidade &amp; Imparcialidade: {latestRun.comparabilityReport.overallStatus}
                </span>
                <span
                  className={`px-2 py-0.5 rounded font-bold ${
                    latestRun.comparabilityReport.canDeclareOfficialWinner
                      ? 'bg-emerald-500/20 text-[#31d6c4]'
                      : 'bg-rose-500/20 text-rose-400'
                  }`}
                >
                  {latestRun.comparabilityReport.canDeclareOfficialWinner
                    ? 'PARIDADE VALIDADA — VENCEDOR OFICIAL HABILITADO'
                    : 'ASSIMETRIA DETECTADA — VENCEDOR OFICIAL BLOQUEADO'}
                </span>
              </div>
              {latestRun.comparabilityReport.blockingReasons.length > 0 && (
                <div className="mt-1.5 text-rose-400">
                  {latestRun.comparabilityReport.blockingReasons.join(' · ')}
                </div>
              )}
            </div>
          )}

          {/* 1. Comparação Direta de Pontuação Entre Softwares, 5 Indicadores Separados & Travas Matemáticas */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {latestRun.scoreCards.map((sc) => {
              const isWinner = sc.softwareId === latestRun.winnerSoftwareId;
              const sep = sc.separatedIndicators;

              // Calcular Delta Histórico Run-over-Run (Frente 3.3)
              const priorRunEntry = (data?.historicalRuns || []).find(
                (hr) =>
                  hr.id !== latestRun.id &&
                  hr.scores.some((s) => s.softwareId === sc.softwareId)
              );
              const priorSwScore = priorRunEntry?.scores.find(
                (s) => s.softwareId === sc.softwareId
              );
              const overallDelta = priorSwScore
                ? Number((sc.groupedScores.overallScore - priorSwScore.overallScore).toFixed(2))
                : null;
              const securityDelta = priorSwScore
                ? Number((sc.groupedScores.securityScore - priorSwScore.securityScore).toFixed(2))
                : null;
              const qualityDelta = priorSwScore
                ? Number((sc.groupedScores.qualityScore - priorSwScore.qualityScore).toFixed(2))
                : null;

              const formatDeltaBadge = (label: string, delta: number | null) => {
                if (delta === null) return null;
                const sign = delta > 0 ? '+' : '';
                const colorClass =
                  delta > 0
                    ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
                    : delta < 0
                      ? 'text-rose-400 bg-rose-500/10 border-rose-500/30'
                      : 'text-slate-400 bg-slate-800 border-slate-700';
                return (
                  <span
                    key={label}
                    className={`px-1.5 py-0.5 rounded text-[11px] font-mono border tabular-nums ${colorClass}`}
                    title={`Evolução histórica (${label}) vs execução anterior`}
                  >
                    {label}: {sign}
                    {delta.toFixed(2)}
                  </span>
                );
              };

              return (
                <div
                  key={sc.softwareId}
                  className={`rounded-lg border p-6 bg-white dark:bg-[#0f141c] ${
                    isWinner
                      ? 'border-[#31d6c4]/60'
                      : 'border-slate-200 dark:border-slate-800/80'
                  }`}
                >
                  <div className="flex items-start justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
                    <div>
                      <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                        <span>Versão {sc.softwareVersion}</span>
                        <span>·</span>
                        <span>
                          {isWinner
                            ? 'Vencedor Técnico Validado'
                            : latestRun.winnerSoftwareId === null && latestRun.scoreCards.length > 1
                              ? 'Sem Vencedor Oficial (Comparação Assimétrica)'
                              : 'Avaliado'}
                        </span>
                      </div>
                      <h3 className="text-xl font-bold text-slate-900 dark:text-slate-100 mt-1">
                        {sc.softwareName}
                      </h3>
                      {priorSwScore && (
                        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                          {formatDeltaBadge('Δ Geral', overallDelta)}
                          {formatDeltaBadge('Δ Seg', securityDelta)}
                          {formatDeltaBadge('Δ Qual', qualityDelta)}
                        </div>
                      )}
                    </div>
                    <div className="text-right font-mono tabular-nums">
                      <div
                        className={`text-3xl font-bold ${
                          sep && sep.technicalScore === null
                            ? 'text-slate-400'
                            : sc.groupedScores.overallScore >= 4.0
                              ? 'text-emerald-600 dark:text-[#31d6c4]'
                              : sc.groupedScores.overallScore >= 3.0
                                ? 'text-amber-500'
                                : 'text-rose-500'
                        }`}
                      >
                        {sep && sep.technicalScore === null
                          ? 'N/A'
                          : sc.groupedScores.overallScore.toFixed(2)}{' '}
                        <span className="text-sm font-normal text-slate-400">/ 5.00</span>
                      </div>
                      <div className="text-xs font-semibold text-slate-600 dark:text-slate-300 mt-0.5">
                        Classificação: {sc.classificationLabel}
                      </div>
                    </div>
                  </div>

                  {/* 5 Indicadores Separados Obrigatórios (Seção 8.3) */}
                  {sep && (
                    <div className="mt-4 grid grid-cols-2 sm:grid-cols-5 gap-2 text-[11px] font-mono">
                      <div className="p-2 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                        <div className="text-[10px] text-slate-400 font-sans">1. Nota Técnica</div>
                        <div className="font-bold text-slate-900 dark:text-slate-100">
                          {sep.technicalScore !== null ? `${sep.technicalScore.toFixed(2)}/5.00` : 'N/A'}
                        </div>
                      </div>
                      <div className="p-2 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                        <div className="text-[10px] text-slate-400 font-sans">2. Cobertura Escopo</div>
                        <div className="font-bold text-[#31d6c4]">{sep.scopeCoveragePercent}%</div>
                      </div>
                      <div className="p-2 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                        <div className="text-[10px] text-slate-400 font-sans">3. Confiança Evid.</div>
                        <div className="font-bold text-slate-900 dark:text-slate-100">
                          {sep.evidenceConfidence}
                        </div>
                      </div>
                      <div className="p-2 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                        <div className="text-[10px] text-slate-400 font-sans">4. Quality Gate</div>
                        <div
                          className={`font-bold ${
                            sep.qualityGateDecision === 'APPROVED'
                              ? 'text-emerald-500'
                              : sep.qualityGateDecision === 'REJECTED'
                                ? 'text-rose-500'
                                : 'text-amber-500'
                          }`}
                        >
                          {sep.qualityGateDecision}
                        </div>
                      </div>
                      <div className="p-2 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                        <div className="text-[10px] text-slate-400 font-sans">5. Veracidade</div>
                        <div className="font-bold text-emerald-500 truncate" title={sep.veracityState}>
                          {sep.veracityState}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Grouped Dimension Bars */}
                  <div className="mt-5 space-y-3">
                    {[
                      { label: 'Nota de Segurança & DevSecOps', val: sc.groupedScores.securityScore },
                      { label: 'Nota de Qualidade de Código', val: sc.groupedScores.qualityScore },
                      { label: 'Nota de Arquitetura & Modularidade', val: sc.groupedScores.architectureScore },
                      { label: 'Nota Funcional (Equivalência)', val: sc.groupedScores.functionalScore },
                      { label: 'Nota de Desempenho (P95 / RPS)', val: sc.groupedScores.performanceScore },
                      { label: 'Nota Técnica Consolidada', val: sc.groupedScores.technicalScore },
                    ].map((row) => {
                      const pct = Math.max(2, Math.min(100, (row.val / 5) * 100));
                      return (
                        <div key={row.label}>
                          <div className="flex items-center justify-between text-xs mb-1">
                            <span className="text-slate-700 dark:text-slate-300 font-medium">
                              {row.label}
                            </span>
                            <span className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
                              {row.val.toFixed(2)} / 5.00
                            </span>
                          </div>
                          <div className="h-2 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                row.val >= 4.0
                                  ? 'bg-[#31d6c4]'
                                  : row.val >= 3.0
                                    ? 'bg-amber-500'
                                    : 'bg-rose-500'
                              }`}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Penalty Caps Triggered */}
                  <div className="mt-5 pt-4 border-t border-slate-200 dark:border-slate-800">
                    <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">
                      Travas Matemáticas (Penalty Caps / Kill Switches):{' '}
                      <span className="font-mono tabular-nums">
                        {sc.penaltyCapsTriggered.length}
                      </span>
                    </div>
                    {sc.penaltyCapsTriggered.length === 0 ? (
                      <div className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                        <span>Nenhuma trava de penalidade acionada. Todas as categorias cumpriram os requisitos mínimos.</span>
                      </div>
                    ) : (
                      <ul className="space-y-1.5 text-xs text-rose-600 dark:text-rose-400">
                        {sc.penaltyCapsTriggered.map((cap, idx) => (
                          <li key={`${cap.ruleId}-${idx}`} className="flex items-start gap-2">
                            <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                            <span>
                              <strong className="font-mono">{cap.ruleId}</strong> ({cap.category}):{' '}
                              {cap.reason} [Teto aplicado: {cap.maxAllowedScore.toFixed(2)}]
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* 2. Comparação nas 12 Categorias & Distribuição de Vulnerabilidades */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* 12-Category Matrix Table */}
            <div className="lg:col-span-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                    Comparação Detalhada por Categoria (12 Dimensões)
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Escala 0.00 (Inexistente) a 5.00 (Excelente) ponderada pelos pesos matemáticos do perfil.
                  </p>
                </div>
              </div>
              <div className="overflow-x-auto df-hover-scroll">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                      <th className="py-2.5 pr-4 font-semibold">Categoria</th>
                      <th className="py-2.5 px-3 font-semibold text-right">Peso (%)</th>
                      {latestRun.scoreCards.map((sc) => (
                        <th key={sc.softwareId} className="py-2.5 px-3 font-semibold text-right">
                          {sc.softwareName}
                        </th>
                      ))}
                      <th className="py-2.5 pl-3 font-semibold text-right">Diferencial</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60 font-mono tabular-nums">
                    {(Object.keys(CATEGORY_LABELS) as BenchmarkCategoryKey[]).map((catKey) => {
                      const weight = latestRun.weightsUsed[catKey] ?? 0;
                      const s0 = latestRun.scoreCards[0]?.categoryScores[catKey] ?? 0;
                      const s1 = latestRun.scoreCards[1]?.categoryScores[catKey] ?? 0;
                      const delta = s1 - s0;
                      const isSelectedCat = selectedDrillCategory === catKey;
                      return (
                        <tr
                          key={catKey}
                          onClick={() => setSelectedDrillCategory(catKey)}
                          className={`cursor-pointer transition-colors ${
                            isSelectedCat
                              ? 'bg-[#31d6c4]/10'
                              : 'hover:bg-slate-50 dark:hover:bg-slate-800/30'
                          }`}
                        >
                          <td className="py-2.5 pr-4 font-sans font-medium text-slate-800 dark:text-slate-200 flex items-center gap-2">
                            <span>{CATEGORY_LABELS[catKey]}</span>
                            {isSelectedCat && (
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#31d6c4] text-slate-950 font-bold">
                                Inspecionando
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-3 text-right text-slate-500 dark:text-slate-400">
                            {weight}%
                          </td>
                          {latestRun.scoreCards.map((sc) => {
                            const val = sc.categoryScores[catKey];
                            const reasonsCount =
                              sc.categoryDetails?.[catKey]?.evaluationReasons?.length || 0;
                            return (
                              <td
                                key={sc.softwareId}
                                className={`py-2.5 px-3 text-right font-semibold ${
                                  val === null
                                    ? 'text-slate-400'
                                    : val >= 4.0
                                      ? 'text-emerald-600 dark:text-[#31d6c4]'
                                      : val >= 3.0
                                        ? 'text-amber-500'
                                        : 'text-rose-500'
                                }`}
                              >
                                {val !== null ? val.toFixed(2) : 'Não Avaliado'}
                                {reasonsCount > 0 && (
                                  <span className="ml-1 text-[10px] text-slate-400">
                                    ({reasonsCount})
                                  </span>
                                )}
                              </td>
                            );
                          })}
                          <td className="py-2.5 pl-3 text-right text-slate-600 dark:text-slate-300">
                            {delta === 0
                              ? '0.00'
                              : delta > 0
                                ? `+${delta.toFixed(2)} (${latestRun.scoreCards[1]?.softwareName.split(' ')[0]})`
                                : `+${Math.abs(delta).toFixed(2)} (${latestRun.scoreCards[0]?.softwareName.split(' ')[0]})`}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Drill-down de Motivos de Avaliação e Evidências no Código para a Categoria Selecionada */}
              <div className="mt-5 pt-4 border-t border-slate-200 dark:border-slate-800 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-xs font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                    <Code2 className="w-4 h-4 text-[#31d6c4]" />
                    <span>
                      Auditoria MQR de Motivos de Avaliação &amp; Código-Fonte:{' '}
                      <span className="text-[#31d6c4]">
                        {CATEGORY_LABELS[selectedDrillCategory]}
                      </span>
                    </span>
                  </div>
                  <span className="text-[11px] text-slate-500">
                    Clique em qualquer categoria na tabela acima para inspecionar os descontos e trechos exatos
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {latestRun.scoreCards.map((sc) => {
                    const catDetail = sc.categoryDetails?.[selectedDrillCategory];
                    const reasons = [...(catDetail?.evaluationReasons || [])].sort(
                      (a, b) => a.scoreDelta - b.scoreDelta
                    );
                    const sumDelta = reasons.reduce((acc, r) => acc + r.scoreDelta, 0);
                    return (
                      <div
                        key={`${sc.softwareId}-${selectedDrillCategory}`}
                        className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#080b10] space-y-2.5 text-xs"
                      >
                        <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2 font-mono">
                          <span className="font-sans font-bold text-slate-900 dark:text-slate-100">
                            {sc.softwareName}
                          </span>
                          <span className="text-[11px] text-[#31d6c4] font-bold">
                            clamp[0,5](5.00 {sumDelta >= 0 ? `+ ${sumDelta.toFixed(2)}` : `- ${Math.abs(sumDelta).toFixed(2)}`}) ={' '}
                            {catDetail?.finalScore !== null && catDetail?.finalScore !== undefined
                              ? `${catDetail.finalScore.toFixed(2)} / 5.00`
                              : 'N/A'}
                          </span>
                        </div>

                        {reasons.length === 0 ? (
                          <div className="text-emerald-600 dark:text-emerald-400 text-[11px] flex items-center gap-1.5">
                            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                            <span>
                              Nenhuma dedução de código ou limite estático excedido nesta categoria (5.00/5.00).
                            </span>
                          </div>
                        ) : (
                          <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                            {reasons.map((r) => (
                              <div
                                key={r.id}
                                className="p-2.5 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] space-y-1.5"
                              >
                                <div className="flex items-center justify-between font-mono text-[11px]">
                                  <span
                                    className={`font-bold ${
                                      r.scoreDelta < 0 ? 'text-rose-500' : 'text-emerald-400'
                                    }`}
                                  >
                                    {r.scoreDelta >= 0
                                      ? `+${r.scoreDelta.toFixed(2)}`
                                      : r.scoreDelta.toFixed(2)}{' '}
                                    pts · [{r.severity}] {r.originType}
                                  </span>
                                  <span className="text-[#31d6c4] truncate max-w-[180px]">
                                    {r.filePath}:{r.lineNumber}
                                  </span>
                                </div>
                                <div className="font-semibold text-slate-900 dark:text-slate-100 text-[11px]">
                                  {r.title}
                                </div>
                                <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                                  {r.whyExplanation}
                                </p>
                                <pre className="p-2 rounded bg-slate-950 text-rose-200 border-l-2 border-rose-500 font-mono text-[10px] overflow-x-auto">
                                  {r.codeSnippet}
                                </pre>
                                {r.executionFlow && r.executionFlow.length > 0 && (
                                  <div className="text-[10px] font-mono text-amber-400 flex items-center gap-1">
                                    <GitCommit className="w-3 h-3 shrink-0" />
                                    <span className="truncate">
                                      Taint: {r.executionFlow.map((s) => s.nodeType).join(' → ')}
                                    </span>
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Distribuição de Vulnerabilidades & Qualidade + Desempenho */}
            <div className="space-y-6">
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5">
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Distribuição de Vulnerabilidades por Severidade
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 mb-4">
                  Comparativo de achados SAST, SCA, Segredos e SQL validados.
                </p>
                <div className="space-y-4">
                  {latestRun.scoreCards.map((sc) => (
                    <div
                      key={sc.softwareId}
                      className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-[#080b10]"
                    >
                      <div className="flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200 mb-2">
                        <span>{sc.softwareName}</span>
                        <span className="font-mono tabular-nums">
                          Total: {sc.metricsSummary.vulnerabilities}
                        </span>
                      </div>
                      <div className="grid grid-cols-4 gap-2 text-center font-mono tabular-nums text-xs">
                        <div className="p-2 rounded bg-rose-500/10 text-rose-600 dark:text-rose-400">
                          <div className="font-bold text-sm">{sc.metricsSummary.criticalVulns}</div>
                          <div className="text-[10px] font-sans">Críticas</div>
                        </div>
                        <div className="p-2 rounded bg-orange-500/10 text-orange-600 dark:text-orange-400">
                          <div className="font-bold text-sm">{sc.metricsSummary.highVulns}</div>
                          <div className="text-[10px] font-sans">Altas</div>
                        </div>
                        <div className="p-2 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400">
                          <div className="font-bold text-sm">{sc.metricsSummary.mediumVulns}</div>
                          <div className="text-[10px] font-sans">Médias</div>
                        </div>
                        <div className="p-2 rounded bg-sky-500/10 text-sky-600 dark:text-sky-400">
                          <div className="font-bold text-sm">{sc.metricsSummary.lowVulns}</div>
                          <div className="text-[10px] font-sans">Baixas</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5">
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Métricas de Desempenho &amp; Qualidade
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 mb-3">
                  Sob carga controlada ({latestRun.equivalenceEnvironment.cpuCoresLimit} vCPUs /{' '}
                  {latestRun.equivalenceEnvironment.memoryMbLimit} MB RAM).
                </p>
                <div className="space-y-2.5 text-xs font-mono tabular-nums">
                  {latestRun.scoreCards.map((sc) => (
                    <div
                      key={sc.softwareId}
                      className="p-3 rounded-lg border border-slate-200 dark:border-slate-800/80 space-y-1"
                    >
                      <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                        {sc.softwareName}
                      </div>
                      {sc.runtimeMetrics?.status === 'MEASURED' || (sc.metricsSummary.p95LatencyMs > 0 || sc.metricsSummary.throughputRps > 0) ? (
                        <div className="text-slate-600 dark:text-slate-400">
                          <span>P50: {sc.metricsSummary.p50LatencyMs}ms</span>
                          <span className="mx-1.5">·</span>
                          <span>P95: {sc.metricsSummary.p95LatencyMs}ms</span>
                          <span className="mx-1.5">·</span>
                          <span>RPS: {sc.metricsSummary.throughputRps}</span>
                        </div>
                      ) : (
                        <div className="text-amber-600 dark:text-amber-400 font-sans text-[11px] font-medium">
                          ⚡ Desempenho de Runtime: <strong>NÃO MEDIDO</strong> (Requer execução de worker de carga)
                        </div>
                      )}
                      <div className="text-slate-600 dark:text-slate-400">
                        <span>Cobertura Testes: {sc.metricsSummary.testCoveragePercent}%</span>
                        <span className="mx-1.5">·</span>
                        <span>Dívida: {sc.metricsSummary.technicalDebtMinutes} min</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
