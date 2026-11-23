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

export const SemicircularHealthGaugeSvg: React.FC<{
  score: number | null;
  softwareName: string;
  qualityGateStatus?: string;
  classificationLabel?: string;
}> = ({ score, softwareName, qualityGateStatus = 'NOT_MEASURED', classificationLabel = 'Não Avaliado' }) => {
  const clamped = score === null ? 0 : Math.max(0, Math.min(5, score));
  const ratio = clamped / 5;
  const radius = 72;
  const circumference = Math.PI * radius;
  const strokeDashoffset = circumference * (1 - ratio);
  const strokeColor =
    score === null
      ? '#64748b'
      : clamped >= 4.0
        ? '#10b981'
        : clamped >= 3.0
          ? '#f59e0b'
          : '#f43f5e';

  return (
    <div className="flex flex-col items-center justify-between p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#080b10]">
      <div className="w-full flex items-center justify-between text-xs mb-1">
        <span className="font-bold text-slate-900 dark:text-slate-100 truncate">{softwareName}</span>
        <span
          className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${
            qualityGateStatus === 'PASSED' || qualityGateStatus === 'APPROVED' || qualityGateStatus === 'APROVADO'
              ? 'bg-emerald-500/15 text-emerald-500 border border-emerald-500/30'
              : qualityGateStatus === 'WARN' || qualityGateStatus === 'APPROVED_WITH_RESERVATIONS' || qualityGateStatus === 'PARTIAL'
                ? 'bg-amber-500/15 text-amber-500 border border-amber-500/30'
                : qualityGateStatus === 'NOT_MEASURED' || qualityGateStatus === 'INCONCLUSIVE'
                  ? 'bg-slate-500/15 text-slate-400 border border-slate-500/30'
                  : 'bg-rose-500/15 text-rose-500 border border-rose-500/30'
          }`}
        >
          QG: {qualityGateStatus}
        </span>
      </div>

      <svg viewBox="0 0 200 118" className="w-48 h-28 overflow-visible" aria-label={`Índice Global ${softwareName}`}>
        {/* Track Background */}
        <path
          d="M 28 96 A 72 72 0 0 1 172 96"
          fill="none"
          stroke="currentColor"
          className="text-slate-200 dark:text-slate-800"
          strokeWidth="14"
          strokeLinecap="round"
        />
        {/* Zonas de Referência sutis (0-3.0 Rose, 3.0-4.0 Amber, 4.0-5.0 Emerald) */}
        <path
          d="M 28 96 A 72 72 0 0 1 172 96"
          fill="none"
          stroke={strokeColor}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
        />
        <text
          x="100"
          y="80"
          textAnchor="middle"
          className="fill-slate-900 dark:fill-slate-100 font-mono text-2xl font-bold"
        >
          {score !== null ? clamped.toFixed(2) : 'N/A'}
        </text>
        <text
          x="100"
          y="98"
          textAnchor="middle"
          className="fill-slate-500 dark:fill-slate-400 font-mono text-[10px]"
        >
          escala 0.00 – 5.00
        </text>
        <text x="24" y="113" textAnchor="middle" className="fill-rose-500 font-mono text-[9px]">
          0.0
        </text>
        <text x="100" y="16" textAnchor="middle" className="fill-amber-500 font-mono text-[9px]">
          3.0
        </text>
        <text x="176" y="113" textAnchor="middle" className="fill-emerald-500 font-mono text-[9px]">
          5.0
        </text>
      </svg>

      <div className="text-[11px] font-medium text-slate-600 dark:text-slate-300 mt-1">
        Classificação: <strong style={{ color: strokeColor }}>{classificationLabel}</strong>
      </div>
    </div>
  );
};

export const TwelvePillarRadarSvg: React.FC<{ run: BenchmarkRun }> = ({ run }) => {
  const categories = Object.keys(CATEGORY_LABELS) as BenchmarkCategoryKey[];
  const cx = 160;
  const cy = 150;
  const maxR = 102;
  const levels = [1, 2, 3, 4, 5];

  const pointFor = (idx: number, val: number) => {
    const angle = (Math.PI * 2 * idx) / categories.length - Math.PI / 2;
    const r = (Math.max(0, Math.min(5, val)) / 5) * maxR;
    return {
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
      labelX: cx + (maxR + 24) * Math.cos(angle),
      labelY: cy + (maxR + 18) * Math.sin(angle),
    };
  };

  const buildPolygonPoints = (scIndex: number) => {
    const sc = run.scoreCards[scIndex];
    if (!sc) return '';
    return categories
      .map((cat, idx) => {
        const raw = sc.categoryScores[cat];
        const val = raw === null || raw === undefined ? 0 : raw;
        const pt = pointFor(idx, val);
        return `${pt.x.toFixed(1)},${pt.y.toFixed(1)}`;
      })
      .join(' ');
  };

  const sw0 = run.scoreCards[0];
  const sw1 = run.scoreCards[1];

  return (
    <div className="flex flex-col items-center">
      <svg
        viewBox="0 0 320 300"
        className="w-full max-w-[340px] h-auto overflow-visible"
        aria-label="Radar Comparativo dos 12 Pilares"
      >
        {/* Polígonos concêntricos de nível 1..5 */}
        {levels.map((lvl) => {
          const pts = categories
            .map((_, idx) => {
              const pt = pointFor(idx, lvl);
              return `${pt.x.toFixed(1)},${pt.y.toFixed(1)}`;
            })
            .join(' ');
          return (
            <polygon
              key={lvl}
              points={pts}
              fill="none"
              stroke="currentColor"
              className="text-slate-200 dark:text-slate-800"
              strokeWidth="1"
            />
          );
        })}

        {/* Eixos radiais */}
        {categories.map((cat, idx) => {
          const outer = pointFor(idx, 5);
          const shortLabel = CATEGORY_LABELS[cat].split(' ')[0];
          return (
            <g key={cat}>
              <line
                x1={cx}
                y1={cy}
                x2={outer.x}
                y2={outer.y}
                stroke="currentColor"
                className="text-slate-200 dark:text-slate-800"
                strokeWidth="1"
              />
              <text
                x={outer.labelX}
                y={outer.labelY}
                textAnchor="middle"
                dominantBaseline="middle"
                className="fill-slate-600 dark:fill-slate-400 font-mono text-[8.5px]"
              >
                {shortLabel}
              </text>
            </g>
          );
        })}

        {/* Polígono Software B (secundário #a855f7) */}
        {sw1 && (
          <polygon
            points={buildPolygonPoints(1)}
            fill="rgba(168, 85, 247, 0.18)"
            stroke="#a855f7"
            strokeWidth="2"
          />
        )}

        {/* Polígono Software A (primário #31d6c4) */}
        {sw0 && (
          <polygon
            points={buildPolygonPoints(0)}
            fill="rgba(49, 214, 196, 0.22)"
            stroke="#31d6c4"
            strokeWidth="2.2"
          />
        )}
      </svg>

      <div className="flex flex-wrap items-center justify-center gap-4 text-xs font-mono mt-1">
        {sw0 && (
          <span className="inline-flex items-center gap-1.5 text-slate-800 dark:text-slate-200">
            <span className="w-3 h-3 rounded-sm bg-[#31d6c4] inline-block" />
            <span>
              {sw0.softwareName} ({sw0.groupedScores.overallScore.toFixed(2)})
            </span>
          </span>
        )}
        {sw1 && (
          <span className="inline-flex items-center gap-1.5 text-slate-800 dark:text-slate-200">
            <span className="w-3 h-3 rounded-sm bg-[#a855f7] inline-block" />
            <span>
              {sw1.softwareName} ({sw1.groupedScores.overallScore.toFixed(2)})
            </span>
          </span>
        )}
      </div>
    </div>
  );
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

  const handleExportMqrCloudJson = async () => {
    const filename = `winhood-mqr-report-${latestRun?.id || 'workspace'}.json`;
    if (latestRun) {
      try {
        const res = await window.fetch(
          `/api/reports/${encodeURIComponent(latestRun.id)}/export?format=json&type=COMPARATIVE_FULL`,
          { credentials: 'include' }
        );
        if (res.ok) {
          const text = await res.text();
          if (text.trim().startsWith('{')) {
            const blob = new Blob([text], { type: 'application/json;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 4000);
            return;
          }
        }
      } catch {
        // Fallback para serialização determinística local
      }
    }
    const payload = {
      schemaVersion: 'WINHOOD-MQR-CLOUD-REPORT-v2.0',
      exportedAt: new Date().toISOString(),
      hasEvaluations: Boolean(data?.hasEvaluations),
      kpis,
      latestRun,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  };

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
            onClick={() => void handleExportMqrCloudJson()}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border border-[#31d6c4]/40 text-[#31d6c4] hover:bg-[#31d6c4]/10 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Exportar Relatório Nuvem MQR JSON
          </button>
          <button
            type="button"
            onClick={() => onNavigate('sonar_hub')}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800/60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Code2 className="w-3.5 h-3.5 text-[#31d6c4]" />
            Configurar Hub MQR
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

      {/* Domínios da Plataforma & Atalhos Operacionais — Estado Real do Backend */}
      <div
        data-testid="dashboard-hairline-telemetry-bar"
        className="rounded-xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-4 space-y-3"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-bold text-slate-900 dark:text-slate-100">
            Domínios da Plataforma &amp; Atalhos Operacionais
          </div>
          <div className="text-[11px] font-mono tabular-nums text-slate-500 dark:text-slate-400">
            Fonte: /api/dashboard ·{' '}
            {latestRun?.completedAt
              ? `Última execução: ${new Date(latestRun.completedAt).toLocaleString('pt-BR')}`
              : 'Nenhuma execução registrada'}
          </div>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3">
          {[
            {
              label: 'Segurança & SAST',
              sub: `${kpis.vulnerabilitiesCount} vulnerabilidade(s) · ${kpis.completedAnalyses} run(s)`,
              type: 'vault' as const,
              color: '#f43f5e',
              target: 'security_suite',
            },
            {
              label: 'Dados & Cofre AES-256-GCM',
              sub: `${kpis.totalProjects} projeto(s) · ${kpis.totalSoftwares} software(s)`,
              type: 'lockers' as const,
              color: '#38bdf8',
              target: 'projects',
            },
            {
              label: 'Criptografia & IAM',
              sub: latestRun
                ? latestRun.scoreCards[0]?.categoryScores?.security === null ||
                  latestRun.scoreCards[0]?.groupedScores?.securityScore === undefined
                  ? 'Seg.: NÃO MEDIDO'
                  : `Score Seg.: ${latestRun.scoreCards[0].groupedScores.securityScore.toFixed(2)}/5.00`
                : 'Aguardando auditoria IAM',
              type: 'padlock' as const,
              color: '#a855f7',
              target: 'reference_intelligence',
            },
            {
              label: 'Rede, Cloud & MQR',
              sub: `${kpis.codeQualityIssuesCount} achado(s) MQR · ${latestRun?.status || 'IDLE'}`,
              type: 'router' as const,
              color: '#10b981',
              target: 'sonar_hub',
            },
            {
              label: 'Arquitetura & Clean Code',
              sub:
                kpis.avgQuality !== null
                  ? `Qualidade média: ${kpis.avgQuality.toFixed(2)}/5.00`
                  : 'Sem média calculada',
              type: 'exploded' as const,
              color: '#f59e0b',
              target: 'arch_qa_perf',
            },
            {
              label: 'Performance & Hardware',
              sub:
                kpis.avgPerformance !== null
                  ? `Desempenho médio: ${kpis.avgPerformance.toFixed(2)}/5.00`
                  : 'Benchmark sob demanda',
              type: 'turntable' as const,
              color: '#06b6d4',
              target: 'hardware_benchmark',
            },
          ].map((dom) => (
            <button
              key={dom.type}
              type="button"
              onClick={() => onNavigate(dom.target)}
              className="flex items-center gap-3 p-2.5 rounded-lg border border-slate-200/80 dark:border-slate-800/90 bg-slate-50/70 dark:bg-[#090d14] hover:border-[#31d6c4]/60 transition-colors text-left cursor-pointer"
            >
              <HairlineAnimatedFigure
                type={dom.type}
                size={56}
                active={Boolean(data?.hasEvaluations)}
                accentColor={dom.color}
              />
              <div className="min-w-0">
                <div className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate">
                  {dom.label}
                </div>
                <div className="text-[10px] font-mono tabular-nums text-slate-500 dark:text-slate-400 truncate mt-0.5">
                  {dom.sub}
                </div>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* 10 Real Backend KPIs Grid (Part 6.2: grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 2xl:grid-cols-5 gap-4) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 2xl:grid-cols-5 gap-4">
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
            {kpis.avgPerformance !== null
              ? 'Ambiente equivalente validado'
              : 'Não medido (análise estática)'}
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

      {/* Glossário Rápido Amigável de Siglas Técnicas (Part 6.3) */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-3.5 text-xs">
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-slate-600 dark:text-slate-400">
          <span className="font-bold text-slate-900 dark:text-slate-100">Legenda Rápida:</span>
          <span>
            <strong className="font-mono text-[#31d6c4]">MQR</strong>: Multi-Quality Rule (avalia Segurança, Confiabilidade e Manutenibilidade simultaneamente)
          </span>
          <span>
            <strong className="font-mono text-[#31d6c4]">Taint Analysis</strong>: Rastreamento do dado não confiável da entrada (Source) até o comando crítico (Sink)
          </span>
          <span>
            <strong className="font-mono text-[#31d6c4]">CV ≤ 5%</strong>: Coeficiente de Variação máximo para estabilidade estatística de benchmark
          </span>
          <span>
            <strong className="font-mono text-[#31d6c4]">EPSS / KEV</strong>: Probabilidade de exploração real em 30 dias (FIRST.org) e catálogo de falhas exploradas (CISA)
          </span>
        </div>
      </div>

      {/* Empty State when no evaluations exist (Requirement Section 6) */}
      {!data?.hasEvaluations || !latestRun ? (
        <div
          data-testid="empty-evaluations-state"
          className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-8 max-w-4xl mx-auto my-8 space-y-6"
        >
          <div className="flex flex-col md:flex-row items-center gap-6 text-center md:text-left">
            <HairlineAnimatedFigure
              type="phosphor"
              variant="hero"
              width={176}
              height={138}
              active={true}
              accentColor="#10b981"
              subtitle="TELEMETRY READY"
            />
            <div className="flex-1 space-y-2">
              <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">
                Ainda não existem avaliações ou benchmarks executados neste ambiente
              </h2>
              <p className="text-sm text-slate-600 dark:text-slate-400">
                Em conformidade com a política de veracidade estrita da plataforma, nenhuma métrica fictícia ou demonstrativa é exibida sem execução real. Cadastre um projeto e importe o código-fonte dos softwares ou carregue os repositórios reais de referência para iniciar.
              </p>
              <div className="pt-3 flex flex-wrap items-center justify-center md:justify-start gap-3">
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
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-medium border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
                >
                  Criar Projeto do Zero
                </button>
                <button
                  type="button"
                  onClick={() => onNavigate('user_guide')}
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-semibold border border-[#31d6c4]/50 text-[#0e9f8e] dark:text-[#31d6c4] hover:bg-[#31d6c4]/10 transition-colors cursor-pointer"
                >
                  Ler Guia Completo Passo a Passo
                </button>
              </div>
            </div>
          </div>

          {/* Prévia visual das 6 categorias 3D */}
          <div className="pt-4 border-t border-slate-200 dark:border-slate-800/80 grid grid-cols-3 sm:grid-cols-6 gap-3">
            {[
              { type: 'vault' as const, label: 'Segurança', color: '#f43f5e' },
              { type: 'lockers' as const, label: 'Cofre & DB', color: '#38bdf8' },
              { type: 'padlock' as const, label: 'Cripto & IAM', color: '#a855f7' },
              { type: 'router' as const, label: 'Rede & Cloud', color: '#10b981' },
              { type: 'exploded' as const, label: 'Arquitetura', color: '#f59e0b' },
              { type: 'turntable' as const, label: 'Hardware', color: '#06b6d4' },
            ].map((item) => (
              <div
                key={item.type}
                className="flex flex-col items-center gap-1.5 p-2 rounded-lg bg-slate-50 dark:bg-[#090d14] border border-slate-200/60 dark:border-slate-800/70"
              >
                <HairlineAnimatedFigure
                  type={item.type}
                  size={52}
                  active={true}
                  accentColor={item.color}
                />
                <span className="text-[11px] font-mono font-semibold text-slate-600 dark:text-slate-300">
                  {item.label}
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <>
          {/* Executive Verdict Banner */}
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-6">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-5">
              <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
                <HairlineAnimatedFigure
                  type="phosphor"
                  variant="hero"
                  width={164}
                  height={128}
                  active={true}
                  accentColor="#10b981"
                />
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

          {/* Avaliação Parcial Banner (Contrato P0/P4 — Sem Fabricação de Métricas Não Medidas) */}
          {(latestRun.isPartialEvaluation ||
            latestRun.scoreCards.some(
              (sc) => sc.isPartialEvaluation || (sc.unmeasuredCategories && sc.unmeasuredCategories.length > 0)
            )) && (
            <div
              data-testid="partial-evaluation-banner"
              className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-xs space-y-1.5"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-bold text-amber-600 dark:text-amber-300 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>
                    Avaliação Parcial — Categorias sem execução dinâmica/medição real permanecem explícitas como NOT_MEASURED
                  </span>
                </span>
                <button
                  type="button"
                  onClick={() => onNavigate('reference_intelligence')}
                  className="px-2.5 py-1 rounded border border-amber-500/40 text-amber-700 dark:text-amber-200 font-semibold hover:bg-amber-500/20 transition-colors cursor-pointer"
                >
                  Executar Medição Controlada →
                </button>
              </div>
              <div className="text-slate-700 dark:text-slate-300 flex flex-wrap gap-2">
                {latestRun.scoreCards.map((sc) =>
                  sc.unmeasuredCategories && sc.unmeasuredCategories.length > 0 ? (
                    <span key={sc.softwareId} className="font-mono text-[11px]">
                      <strong>{sc.softwareName}:</strong>{' '}
                      {sc.unmeasuredCategories.map((c) => CATEGORY_LABELS[c] || c).join(', ')}
                    </span>
                  ) : null
                )}
              </div>
            </div>
          )}

          {/* Gráficos Executivos SVG Nativos (Part 6.4: Semicircular Health Gauge + Radar 12 Pilares) */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-7 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Índice Global de Qualidade &amp; Segurança (Gauge 0.00 – 5.00)
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Zonas de decisão técnica: Crítico (&lt; 3.00), Atenção (3.00–3.99) e Excelente (≥ 4.00) com status do Quality Gate.
                </p>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {latestRun.scoreCards.map((sc) => (
                  <SemicircularHealthGaugeSvg
                    key={sc.softwareId}
                    score={
                      sc.separatedIndicators && sc.separatedIndicators.technicalScore === null
                        ? null
                        : sc.groupedScores.overallScore
                    }
                    softwareName={`${sc.softwareName} (v${sc.softwareVersion})`}
                    qualityGateStatus={
                      sc.qualityGate?.status ||
                      sc.separatedIndicators?.qualityGateDecision ||
                      'INCONCLUSIVE'
                    }
                    classificationLabel={sc.classificationLabel}
                  />
                ))}
              </div>
            </div>

            <div className="lg:col-span-5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 flex flex-col justify-between">
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Radar Comparativo dos 12 Pilares (MQR)
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Sobreposição direta entre os softwares avaliados nas 12 dimensões técnicas.
                </p>
              </div>
              <TwelvePillarRadarSvg run={latestRun} />
            </div>
          </div>

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
                        <div className="text-[10px] text-slate-400 font-sans">2. Cobertura Medição</div>
                        <div className="font-bold text-[#31d6c4]">
                          {sc.measuredCoveragePercent ?? sep.measuredCoveragePercent ?? sep.scopeCoveragePercent}%
                        </div>
                        <div className="text-[9px] text-slate-500">
                          Escopo arq.: {sep.scopeCoveragePercent}%
                        </div>
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
                            sep.qualityGateDecision === 'APPROVED' || sep.qualityGateDecision === 'APROVADO'
                              ? 'text-emerald-500'
                              : sep.qualityGateDecision === 'REJECTED' ||
                                  sep.qualityGateDecision === 'REPROVADO' ||
                                  sep.qualityGateDecision === 'BLOCKED'
                                ? 'text-rose-500'
                                : 'text-amber-500'
                          }`}
                        >
                          {sep.qualityGateDecision}
                        </div>
                      </div>
                      <div className="p-2 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                        <div className="text-[10px] text-slate-400 font-sans">5. Veracidade</div>
                        <div
                          className={`font-bold truncate ${
                            sep.veracityState === 'SUCCESS_VALIDATED'
                              ? 'text-emerald-500'
                              : sep.veracityState === 'PARTIAL' ||
                                  sep.veracityState === 'SUCCESS_WITH_WARNINGS' ||
                                  sep.veracityState === 'INCOMPLETE_COVERAGE'
                                ? 'text-amber-500'
                                : 'text-rose-500'
                          }`}
                          title={sep.veracityState}
                        >
                          {sep.veracityState}
                        </div>
                      </div>
                    </div>
                  )}
                  {sc.weightRenormalization?.applied && (
                    <div className="mt-2 px-2.5 py-1.5 rounded border border-amber-500/30 bg-amber-500/5 text-[11px] text-amber-700 dark:text-amber-300">
                      <strong>Renormalização de Pesos ({sc.measuredCoveragePercent ?? 0}% medido):</strong>{' '}
                      {sc.weightRenormalization.explanation}
                    </div>
                  )}

                  {/* Separação Estrita: MqrBridge Nativo vs WinHood Composto (Regra 9) */}
                  {(sc.sonarNativeResults || sc.winhoodCalculatedResults) && (
                    <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-[11px]">
                      <div className="p-2.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#080b10] space-y-1">
                        <div className="flex items-center justify-between font-bold text-slate-800 dark:text-slate-200">
                          <span>MqrBridge Nativo</span>
                          <span
                            className={`font-mono text-[10px] px-1.5 py-0.5 rounded ${
                              sc.sonarNativeResults?.available
                                ? 'bg-emerald-500/15 text-emerald-500'
                                : 'bg-slate-200 dark:bg-slate-800 text-slate-500'
                            }`}
                          >
                            {sc.sonarNativeResults?.available ? 'CONECTADO' : 'NOT_MEASURED'}
                          </span>
                        </div>
                        {sc.sonarNativeResults?.available ? (
                          <div className="font-mono text-slate-600 dark:text-slate-300 space-y-0.5">
                            <div>
                              Nota Nativa: {sc.sonarNativeResults.nativeScore?.toFixed(2) ?? 'N/A'} · QG:{' '}
                              {sc.sonarNativeResults.qualityGateStatus || 'N/A'}
                            </div>
                            <div className="text-[10px] text-slate-400">
                              Ratings S/R/M: {sc.sonarNativeResults.securityRating || '-'}/
                              {sc.sonarNativeResults.reliabilityRating || '-'}/
                              {sc.sonarNativeResults.maintainabilityRating || '-'} · v
                              {sc.sonarNativeResults.sonarVersion || '-'}
                            </div>
                          </div>
                        ) : (
                          <div className="text-slate-500 leading-snug">
                            {sc.sonarNativeResults?.note ||
                              'Sem instância MqrBridge real conectada — nunca substituído por mock.'}
                          </div>
                        )}
                      </div>

                      <div className="p-2.5 rounded border border-[#31d6c4]/30 bg-[#31d6c4]/5 space-y-1">
                        <div className="flex items-center justify-between font-bold text-slate-900 dark:text-slate-100">
                          <span>WinHood Composto</span>
                          <span className="font-mono text-[10px] text-[#31d6c4]">
                            {sc.winhoodCalculatedResults?.assessedCategoriesCount ??
                              Object.values(sc.categoryScores).filter((v) => v !== null).length}
                            /
                            {sc.winhoodCalculatedResults?.totalCategoriesCount ?? 12} dims
                          </span>
                        </div>
                        <div className="font-mono text-slate-700 dark:text-slate-200">
                          Nota: {(sc.winhoodCalculatedResults?.compositeScore ?? sc.groupedScores.overallScore).toFixed(2)} / 5.00
                        </div>
                        <div className="font-mono text-[10px] text-slate-500 truncate">
                          {sc.winhoodCalculatedResults?.algorithmVersion || latestRun.algorithmVersion}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Grouped Dimension Bars */}
                  <div className="mt-5 space-y-3">
                    {[
                      {
                        label: 'Nota de Segurança & DevSecOps',
                        val: sc.groupedScores.securityScore,
                        isNotMeasured: sc.categoryScores.security === null,
                      },
                      {
                        label: 'Nota de Qualidade de Código',
                        val: sc.groupedScores.qualityScore,
                        isNotMeasured: sc.categoryScores.code_quality === null,
                      },
                      {
                        label: 'Nota de Arquitetura & Modularidade',
                        val: sc.groupedScores.architectureScore,
                        isNotMeasured: sc.categoryScores.architecture === null,
                      },
                      {
                        label: 'Nota Funcional (Equivalência)',
                        val: sc.groupedScores.functionalScore,
                        isNotMeasured: sc.categoryScores.functionality === null,
                      },
                      {
                        label: 'Nota de Desempenho (P95 / RPS)',
                        val: sc.groupedScores.performanceScore,
                        isNotMeasured: sc.categoryScores.performance === null,
                      },
                      {
                        label: 'Nota Técnica Consolidada',
                        val: sc.groupedScores.technicalScore,
                        isNotMeasured: false,
                      },
                    ].map((row) => {
                      const isMissing =
                        row.isNotMeasured || typeof row.val !== 'number' || !Number.isFinite(row.val);
                      const numericVal = !isMissing ? (row.val as number) : 0;
                      const pct = isMissing
                        ? 0
                        : Math.max(2, Math.min(100, (numericVal / 5) * 100));
                      return (
                        <div key={row.label}>
                          <div className="flex items-center justify-between text-xs mb-1">
                            <span className="text-slate-700 dark:text-slate-300 font-medium">
                              {row.label}
                            </span>
                            {isMissing ? (
                              <span className="font-mono text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                                NOT_MEASURED (N/A)
                              </span>
                            ) : (
                              <span className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
                                {numericVal.toFixed(2)} / 5.00
                              </span>
                            )}
                          </div>
                          <div className="h-2 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                isMissing
                                  ? 'bg-slate-400/30'
                                  : numericVal >= 4.0
                                    ? 'bg-[#31d6c4]'
                                    : numericVal >= 3.0
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
                  {(() => {
                    const capsTriggered = Array.isArray(sc.penaltyCapsTriggered)
                      ? sc.penaltyCapsTriggered
                      : [];
                    return (
                      <div className="mt-5 pt-4 border-t border-slate-200 dark:border-slate-800">
                        <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">
                          Travas Matemáticas (Penalty Caps / Kill Switches):{' '}
                          <span className="font-mono tabular-nums">
                            {capsTriggered.length}
                          </span>
                        </div>
                        {capsTriggered.length === 0 ? (
                          <div className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
                            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                            <span>Nenhuma trava de penalidade acionada. Todas as categorias cumpriram os requisitos mínimos.</span>
                          </div>
                        ) : (
                          <ul className="space-y-1.5 text-xs text-rose-600 dark:text-rose-400">
                            {capsTriggered.map((cap, idx) => (
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
                    );
                  })()}
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
                      const rawS0 = latestRun.scoreCards[0]?.categoryScores?.[catKey];
                      const rawS1 = latestRun.scoreCards[1]?.categoryScores?.[catKey];
                      const s0 = typeof rawS0 === 'number' && Number.isFinite(rawS0) ? rawS0 : null;
                      const s1 = typeof rawS1 === 'number' && Number.isFinite(rawS1) ? rawS1 : null;
                      const delta = s0 !== null && s1 !== null ? s1 - s0 : null;
                      const isSelectedCat = selectedDrillCategory === catKey;
                      return (
                        <tr
                          key={catKey}
                          tabIndex={0}
                          aria-selected={isSelectedCat}
                          onClick={() => setSelectedDrillCategory(catKey)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                              e.preventDefault();
                              setSelectedDrillCategory(catKey);
                            }
                          }}
                          className={`cursor-pointer transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#31d6c4] ${
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
                            const rawVal = sc.categoryScores?.[catKey];
                            const val = typeof rawVal === 'number' && Number.isFinite(rawVal) ? rawVal : null;
                            const reasonsCount =
                              sc.categoryDetails?.[catKey]?.evaluationReasons?.length || 0;
                            const mState = sc.categoryDetails?.[catKey]?.measurementState;
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
                                <div>
                                  {val !== null ? val.toFixed(2) : 'Não Medido'}
                                  {reasonsCount > 0 && (
                                    <span className="ml-1 text-[10px] text-slate-400">
                                      ({reasonsCount})
                                    </span>
                                  )}
                                </div>
                                {mState && (
                                  <div className="text-[9px] font-mono text-slate-400 font-normal">
                                    {mState}
                                  </div>
                                )}
                              </td>
                            );
                          })}
                          <td className="py-2.5 pl-3 text-right text-slate-600 dark:text-slate-300">
                            {delta === null
                              ? 'N/A (Não Medido)'
                              : delta === 0
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
                        {sc.veracity?.coverageBreakdown?.test?.state === 'MEASURED' &&
                        sc.veracity.coverageBreakdown.test.percent !== null ? (
                          <span>
                            Cobertura Testes ({sc.veracity.coverageBreakdown.test.sourceFormat || 'LCOV'}):{' '}
                            <strong className="text-emerald-500">
                              {sc.veracity.coverageBreakdown.test.percent}%
                            </strong>
                          </span>
                        ) : (
                          <span className="text-amber-600 dark:text-amber-400 font-sans">
                            Cobertura Testes: <strong>NÃO MEDIDO</strong> (Ingestão/Análise:{' '}
                            {sc.veracity?.coverageBreakdown?.analysis?.percent !== null &&
                            sc.veracity?.coverageBreakdown?.analysis?.percent !== undefined
                              ? `${sc.veracity.coverageBreakdown.analysis.percent}%`
                              : 'NOT_MEASURED'}
                            )
                          </span>
                        )}
                        <span className="mx-1.5">·</span>
                        <span>
                          Dívida:{' '}
                          {sc.metricsSummary.technicalDebtMinutes !== null &&
                          sc.metricsSummary.technicalDebtMinutes !== undefined
                            ? `${sc.metricsSummary.technicalDebtMinutes} min`
                            : 'NOT_MEASURED'}
                        </span>
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
