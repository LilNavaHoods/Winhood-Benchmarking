import React, { useMemo, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Calculator,
  CheckCircle2,
  Clock,
  Code2,
  FileCode,
  GitCommit,
  Hash,
  Info,
  KeyRound,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { BenchmarkRun, NormalizedFinding, SeverityLevel, VisualReportCategoryKey } from '../types/benchmark';
import { CATEGORY_LABELS } from './DashboardModule';
import { HairlineAnimatedFigure } from './HairlineAnimatedFigure';
import { csrfFetch as fetch } from '../utils/csrfFetch';

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
  const [selectedVisualCat, setSelectedVisualCat] = useState<VisualReportCategoryKey>('all');
  const [selectedToolId, setSelectedToolId] = useState<string>('ALL');
  const [selectedValidationStatus, setSelectedValidationStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [triageLoadingId, setTriageLoadingId] = useState<string | null>(null);
  const [simulatedFixedIds, setSimulatedFixedIds] = useState<Set<string>>(() => new Set());

  const findings = latestRun?.findings || [];

  const statusCounters = useMemo(() => {
    const activeOpen = findings.filter(
      (f) =>
        f.validationStatus !== 'ACCEPTED' &&
        f.validationStatus !== 'FALSE_POSITIVE_REVIEWED'
    ).length;
    const accepted = findings.filter((f) => f.validationStatus === 'ACCEPTED').length;
    const falsePositives = findings.filter(
      (f) => f.validationStatus === 'FALSE_POSITIVE_REVIEWED'
    ).length;
    return {
      total: findings.length,
      activeOpen,
      accepted,
      falsePositives,
    };
  }, [findings]);

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (selectedSoftwareId !== 'ALL' && f.softwareId !== selectedSoftwareId) return false;
      if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) return false;
      if (selectedCategory !== 'ALL' && f.category !== selectedCategory) return false;

      // Filtro visual dedicado por categoria (Seção 8 e 10)
      if (selectedVisualCat === 'database') {
        const isDb =
          f.category === 'DATABASE' ||
          f.filePath.toLowerCase().includes('sql') ||
          (f.originalRuleId || '').toLowerCase().includes('sql');
        if (!isDb) return false;
      } else if (selectedVisualCat === 'security') {
        const isSec =
          f.category === 'SAST' ||
          f.category === 'SECRETS' ||
          f.category === 'SCA' ||
          f.category === 'DAST';
        if (!isSec) return false;
      } else if (selectedVisualCat === 'auth_passwords') {
        const isAuth =
          f.category === 'SECRETS' ||
          f.title.toLowerCase().includes('password') ||
          f.title.toLowerCase().includes('token') ||
          f.title.toLowerCase().includes('auth') ||
          f.title.toLowerCase().includes('secret');
        if (!isAuth) return false;
      } else if (selectedVisualCat === 'web_network') {
        const isNet =
          f.filePath.toLowerCase().includes('http') ||
          f.filePath.toLowerCase().includes('api') ||
          f.title.toLowerCase().includes('cors') ||
          f.title.toLowerCase().includes('tls') ||
          f.title.toLowerCase().includes('network');
        if (!isNet) return false;
      } else if (selectedVisualCat === 'code_quality') {
        if (f.category !== 'CODE_QUALITY' && f.category !== 'ARCHITECTURE') return false;
      } else if (selectedVisualCat === 'performance') {
        const isPerf =
          f.title.toLowerCase().includes('perf') ||
          f.title.toLowerCase().includes('memory') ||
          f.title.toLowerCase().includes('cpu') ||
          f.description.toLowerCase().includes('performance') ||
          f.category === 'ARCHITECTURE';
        if (!isPerf) return false;
      }
      if (selectedToolId !== 'ALL' && f.toolId !== selectedToolId) return false;
      if (selectedValidationStatus === 'OPEN_ACTIVE') {
        if (
          f.validationStatus === 'ACCEPTED' ||
          f.validationStatus === 'FALSE_POSITIVE_REVIEWED'
        ) {
          return false;
        }
      } else if (
        selectedValidationStatus !== 'ALL' &&
        f.validationStatus !== selectedValidationStatus
      ) {
        return false;
      }
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
  }, [
    findings,
    selectedSoftwareId,
    selectedSeverity,
    selectedCategory,
    selectedVisualCat,
    selectedToolId,
    selectedValidationStatus,
    searchQuery,
  ]);

  const whatIfProjections = useMemo(() => {
    if (!latestRun || simulatedFixedIds.size === 0) return null;

    const toScoreRating = (score: number): 'A' | 'B' | 'C' | 'D' | 'E' => {
      if (score >= 4.4) return 'A';
      if (score >= 3.6) return 'B';
      if (score >= 2.7) return 'C';
      if (score >= 1.8) return 'D';
      return 'E';
    };

    const simulatedFindings = findings.filter((f) => simulatedFixedIds.has(f.id));
    const totalEffortMinutes = simulatedFindings.reduce(
      (acc, f) => acc + (f.remediationEffortMinutes || 15),
      0
    );

    const perSoftware = latestRun.scoreCards.map((sc) => {
      const swSimFindings = simulatedFindings.filter((f) => f.softwareId === sc.softwareId);
      const swEffortMin = swSimFindings.reduce(
        (acc, f) => acc + (f.remediationEffortMinutes || 15),
        0
      );

      let secRestore = 0;
      let qualRestore = 0;
      let relRestore = 0;
      let critFixed = 0;
      let secretsFixed = 0;
      let bugsFixed = 0;

      for (const f of swSimFindings) {
        const basePenalty =
          f.severity === 'BLOCKER'
            ? 0.55
            : f.severity === 'CRITICAL'
              ? 0.4
              : f.severity === 'HIGH'
                ? 0.25
                : f.severity === 'MEDIUM'
                  ? 0.12
                  : 0.05;

        if (f.mqrImpacts && f.mqrImpacts.length > 0) {
          for (const imp of f.mqrImpacts) {
            const delta = Math.abs(imp.scoreDeduction);
            if (imp.softwareQuality === 'SECURITY') secRestore += delta;
            else if (imp.softwareQuality === 'RELIABILITY') relRestore += delta;
            else qualRestore += delta;
          }
        } else if (f.category === 'SAST' || f.category === 'SECRETS' || f.category === 'SCA' || f.category === 'DAST') {
          secRestore += basePenalty;
        } else {
          qualRestore += basePenalty;
        }

        if (f.severity === 'BLOCKER' || f.severity === 'CRITICAL') critFixed += 1;
        if (f.category === 'SECRETS') secretsFixed += 1;
        if (f.originalRuleId?.toLowerCase().includes('bug') || f.mqrImpacts?.some((i) => i.softwareQuality === 'RELIABILITY')) {
          bugsFixed += 1;
        }
      }

      const projSec = Math.min(5, Number((sc.groupedScores.securityScore + secRestore).toFixed(2)));
      const projQual = Math.min(5, Number((sc.groupedScores.qualityScore + qualRestore).toFixed(2)));
      const relBase = sc.categoryScores?.reliability ?? sc.groupedScores.qualityScore;
      const projRel = Math.min(5, Number((relBase + relRestore).toFixed(2)));
      const secGain = projSec - sc.groupedScores.securityScore;
      const qualGain = projQual - sc.groupedScores.qualityScore;
      const projOverall = Math.min(
        5,
        Number((sc.groupedScores.overallScore + secGain * 0.45 + qualGain * 0.4 + Math.min(0.4, relRestore * 0.15)).toFixed(2))
      );

      const remCrit = Math.max(0, sc.metricsSummary.criticalVulns - critFixed);
      const remSecrets = Math.max(0, sc.metricsSummary.secretsExposed - secretsFixed);
      const projSecRating = remCrit === 0 && remSecrets === 0 && projSec >= 4.4 ? 'A' : toScoreRating(projSec);
      const projMaintRating = toScoreRating(projQual);
      const projRelRating = bugsFixed > 0 && projRel >= 4.4 ? 'A' : toScoreRating(projRel);
      const projQualityGate: 'PASSED' | 'WARN' | 'FAILED' =
        remCrit === 0 && remSecrets === 0 && projSec >= 3.8 && projQual >= 3.5
          ? 'PASSED'
          : remCrit <= 1 && remSecrets === 0
            ? 'WARN'
            : 'FAILED';

      return {
        softwareId: sc.softwareId,
        softwareName: sc.softwareName,
        simulatedCount: swSimFindings.length,
        effortHours: Number((swEffortMin / 60).toFixed(1)),
        currentOverall: sc.groupedScores.overallScore,
        projectedOverall: projOverall,
        projectedSecurity: projSec,
        projectedQuality: projQual,
        projectedRatings: {
          security: projSecRating,
          maintainability: projMaintRating,
          reliability: projRelRating,
        },
        currentQualityGate: sc.qualityGate?.status || 'N/A',
        projectedQualityGate: projQualityGate,
        remainingCritical: remCrit,
        remainingSecrets: remSecrets,
      };
    });

    return {
      totalSimulatedCount: simulatedFindings.length,
      totalEffortHours: Number((totalEffortMinutes / 60).toFixed(1)),
      perSoftware,
    };
  }, [latestRun, findings, simulatedFixedIds]);

  const toggleSimulatedFinding = (id: string) => {
    setSimulatedFixedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

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

      {/* Seletor Visual de Categorias com Figuras Hairline (Seção 8) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
        <button
          type="button"
          onClick={() => setSelectedVisualCat('all')}
          className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer flex items-center gap-2 ${
            selectedVisualCat === 'all'
              ? 'bg-white dark:bg-[#131a24] border-[#10b981] shadow-sm'
              : 'border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-[#090d13] hover:border-slate-300'
          }`}
        >
          <HairlineAnimatedFigure type="vault" size={30} color="#10b981" />
          <div className="min-w-0">
            <div className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate">Todos</div>
            <div className="text-[10px] text-slate-500 font-mono">Consolidado</div>
          </div>
        </button>

        <button
          type="button"
          onClick={() => setSelectedVisualCat('database')}
          className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer flex items-center gap-2 ${
            selectedVisualCat === 'database'
              ? 'bg-white dark:bg-[#131a24] border-[#3b82f6] shadow-sm'
              : 'border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-[#090d13] hover:border-slate-300'
          }`}
        >
          <HairlineAnimatedFigure type="lockers" size={30} color="#3b82f6" />
          <div className="min-w-0">
            <div className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate">Banco / DB</div>
            <div className="text-[10px] text-slate-500 font-mono">Storage & SQL</div>
          </div>
        </button>

        <button
          type="button"
          onClick={() => setSelectedVisualCat('security')}
          className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer flex items-center gap-2 ${
            selectedVisualCat === 'security'
              ? 'bg-white dark:bg-[#131a24] border-[#10b981] shadow-sm'
              : 'border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-[#090d13] hover:border-slate-300'
          }`}
        >
          <HairlineAnimatedFigure type="vault" size={30} color="#10b981" />
          <div className="min-w-0">
            <div className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate">Segurança</div>
            <div className="text-[10px] text-slate-500 font-mono">DevSecOps</div>
          </div>
        </button>

        <button
          type="button"
          onClick={() => setSelectedVisualCat('auth_passwords')}
          className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer flex items-center gap-2 ${
            selectedVisualCat === 'auth_passwords'
              ? 'bg-white dark:bg-[#131a24] border-[#f59e0b] shadow-sm'
              : 'border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-[#090d13] hover:border-slate-300'
          }`}
        >
          <HairlineAnimatedFigure type="padlock" size={30} color="#f59e0b" />
          <div className="min-w-0">
            <div className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate">Senhas & IAM</div>
            <div className="text-[10px] text-slate-500 font-mono">Segredos</div>
          </div>
        </button>

        <button
          type="button"
          onClick={() => setSelectedVisualCat('web_network')}
          className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer flex items-center gap-2 ${
            selectedVisualCat === 'web_network'
              ? 'bg-white dark:bg-[#131a24] border-[#06b6d4] shadow-sm'
              : 'border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-[#090d13] hover:border-slate-300'
          }`}
        >
          <HairlineAnimatedFigure type="router" size={30} color="#06b6d4" />
          <div className="min-w-0">
            <div className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate">Web & APIs</div>
            <div className="text-[10px] text-slate-500 font-mono">TLS / Rede</div>
          </div>
        </button>

        <button
          type="button"
          onClick={() => setSelectedVisualCat('code_quality')}
          className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer flex items-center gap-2 ${
            selectedVisualCat === 'code_quality'
              ? 'bg-white dark:bg-[#131a24] border-[#8b5cf6] shadow-sm'
              : 'border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-[#090d13] hover:border-slate-300'
          }`}
        >
          <HairlineAnimatedFigure type="layers" size={30} color="#8b5cf6" />
          <div className="min-w-0">
            <div className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate">Qualidade</div>
            <div className="text-[10px] text-slate-500 font-mono">SAST / Smells</div>
          </div>
        </button>
      </div>

      {/* Filters Toolbar (Frente 3.4: Combinable Filters + Validation Status + Dynamic Counters) */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-4 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3">
          <div>
            <label
              htmlFor="flt-search"
              className="block text-xs font-semibold text-slate-500 mb-1"
            >
              Buscar (Regra, Arquivo, CWE)
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
              className="block text-xs font-semibold text-slate-500 mb-1"
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
              className="block text-xs font-semibold text-slate-500 mb-1"
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
              className="block text-xs font-semibold text-slate-500 mb-1"
            >
              Categoria MQR / SAST
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
              htmlFor="flt-status"
              className="block text-xs font-semibold text-slate-500 mb-1"
            >
              Status de Triagem DevSecOps
            </label>
            <select
              id="flt-status"
              value={selectedValidationStatus}
              onChange={(e) => setSelectedValidationStatus(e.target.value)}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100 font-mono"
            >
              <option value="ALL">Todos ({statusCounters.total})</option>
              <option value="OPEN_ACTIVE">Ativos na Nota ({statusCounters.activeOpen})</option>
              <option value="VALIDATED">VALIDATED</option>
              <option value="ACCEPTED">ACCEPTED ({statusCounters.accepted})</option>
              <option value="FALSE_POSITIVE_REVIEWED">
                FALSE_POSITIVE ({statusCounters.falsePositives})
              </option>
            </select>
          </div>

          <div>
            <label
              htmlFor="flt-tool"
              className="block text-xs font-semibold text-slate-500 mb-1"
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
              <option value="gitleaks-secrets">Detector de Segredos SARIF Secret Scanner</option>
              <option value="mqr-bridge-quality">MqrBridge Static Analyzer</option>
              <option value="syft-grype-sca">Syft SBOM &amp; Grype SCA</option>
              <option value="archunit-cruiser">Dependency Cruiser &amp; ArchUnit</option>
              <option value="sqlfluff-db">SQLFluff &amp; Schema Auditor</option>
            </select>
          </div>
        </div>
      </div>

      {/* Interactive What-If Remediation & Technical ROI Simulator (Non-destructive) */}
      <div className="rounded-lg border border-[#31d6c4]/30 bg-white dark:bg-[#0f141c] p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Calculator className="w-4 h-4 text-[#31d6c4]" />
            <div>
              <h3 className="text-xs font-bold text-slate-900 dark:text-slate-100">
                Simulador What-If de Remediação &amp; ROI Técnico (Não-Destrutivo)
              </h3>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Marque achados na lista abaixo ou use um preset para simular o ganho na nota MQR, Ratings A–E, Quality Gate e esforço estimado sem alterar o banco oficial.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
            <button
              type="button"
              onClick={() => {
                const critIds = findings
                  .filter((f) => f.severity === 'BLOCKER' || f.severity === 'CRITICAL')
                  .map((f) => f.id);
                setSimulatedFixedIds(new Set(critIds));
              }}
              className="px-2.5 py-1 rounded border border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-300 font-semibold hover:bg-rose-500/20 cursor-pointer"
            >
              Simular BLOCKER / CRITICAL
            </button>
            <button
              type="button"
              onClick={() => {
                const secIds = findings
                  .filter((f) => f.category === 'SECRETS')
                  .map((f) => f.id);
                setSimulatedFixedIds(new Set(secIds));
              }}
              className="px-2.5 py-1 rounded border border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-300 font-semibold hover:bg-amber-500/20 cursor-pointer"
            >
              Simular SECRETS
            </button>
            <button
              type="button"
              onClick={() => {
                setSimulatedFixedIds(new Set(filteredFindings.map((f) => f.id)));
              }}
              className="px-2.5 py-1 rounded border border-[#31d6c4]/40 bg-[#31d6c4]/10 text-[#0e9f8e] dark:text-[#31d6c4] font-semibold hover:bg-[#31d6c4]/20 cursor-pointer"
            >
              Simular Todos Filtrados ({filteredFindings.length})
            </button>
            {simulatedFixedIds.size > 0 && (
              <button
                type="button"
                onClick={() => setSimulatedFixedIds(new Set())}
                className="px-2.5 py-1 rounded border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 font-semibold inline-flex items-center gap-1 cursor-pointer"
              >
                <RotateCcw className="w-3 h-3" />
                <span>Limpar ({simulatedFixedIds.size})</span>
              </button>
            )}
          </div>
        </div>

        {whatIfProjections && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-slate-200 dark:border-slate-800">
            {whatIfProjections.perSoftware.map((proj) => {
              const deltaOverall = Number((proj.projectedOverall - proj.currentOverall).toFixed(2));
              return (
                <div
                  key={proj.softwareId}
                  className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-2 text-xs font-mono tabular-nums"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-sans font-bold text-slate-900 dark:text-slate-100">
                      {proj.softwareName}
                    </span>
                    <span className="text-[#0e9f8e] dark:text-[#31d6c4] font-bold">
                      {proj.simulatedCount} correções · {proj.effortHours}h estimadas
                    </span>
                  </div>
                  <div className="grid grid-cols-4 gap-2 text-[11px]">
                    <div>
                      <div className="text-slate-400">Nota Projetada</div>
                      <div className="font-bold text-slate-900 dark:text-slate-100">
                        {proj.projectedOverall.toFixed(2)}{' '}
                        <span className="text-emerald-500">
                          (+{deltaOverall.toFixed(2)})
                        </span>
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-400">Segurança</div>
                      <div className="font-bold text-[#31d6c4]">
                        {proj.projectedSecurity.toFixed(2)} ({proj.projectedRatings.security})
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-400">Qualidade</div>
                      <div className="font-bold text-slate-200">
                        {proj.projectedQuality.toFixed(2)} ({proj.projectedRatings.maintainability})
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-400">Quality Gate</div>
                      <div
                        className={`font-bold ${
                          proj.projectedQualityGate === 'PASSED'
                            ? 'text-emerald-400'
                            : proj.projectedQualityGate === 'WARN'
                              ? 'text-amber-400'
                              : 'text-rose-400'
                        }`}
                      >
                        {proj.currentQualityGate} → {proj.projectedQualityGate}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
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
                          <div className="flex items-center gap-2">
                            <input
                              type="checkbox"
                              aria-label={`Simular correção de ${f.title}`}
                              checked={simulatedFixedIds.has(f.id)}
                              onClick={(e) => e.stopPropagation()}
                              onChange={() => toggleSimulatedFinding(f.id)}
                              title="Simular correção no What-If ROI"
                              className="rounded border-slate-400 cursor-pointer"
                            />
                            {renderSeverityLabel(f.severity)}
                          </div>
                          <div
                            className={`text-[10px] font-bold px-1.5 py-0.5 rounded inline-block ${
                              simulatedFixedIds.has(f.id)
                                ? 'bg-[#31d6c4]/20 text-[#31d6c4] border border-[#31d6c4]/40'
                                : f.validationStatus === 'ACCEPTED'
                                  ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                                  : f.validationStatus === 'FALSE_POSITIVE_REVIEWED'
                                    ? 'bg-slate-500/20 text-slate-300 border border-slate-500/30'
                                    : 'bg-emerald-500/15 text-[#31d6c4] border border-[#31d6c4]/30'
                            }`}
                          >
                            {simulatedFixedIds.has(f.id) ? 'SIMULADO_CORRIGIDO' : f.validationStatus}
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

