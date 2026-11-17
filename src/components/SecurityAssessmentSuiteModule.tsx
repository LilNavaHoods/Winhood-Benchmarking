import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Crosshair,
  Filter,
  GitBranch,
  Info,
  Network,
  OctagonX,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type {
  BenchmarkRun,
  FindingValidationLifecycleState,
  Project,
  SecurityAssessmentSuiteBundle,
  SeverityLevel,
  Software,
  VulnerabilityValidationState,
} from '../types/benchmark';
import { HairlineAnimatedFigure } from './HairlineAnimatedFigure';
import { csrfFetch as fetch } from '../utils/csrfFetch';
import {
  computeSecurityFindingsFilterMetrics,
  DEFAULT_SECURITY_SUITE_FILTERS,
  filterSecuritySuiteFindings,
  normalizeFindingSeverityBucket,
  resolveFindingRemediationInfo,
  type CoreSeverityFilter,
  type RemediationStatusBucket,
  type SecuritySuiteFilterState,
} from '../utils/securityFindingsFilter';

interface SecurityAssessmentSuiteModuleProps {
  latestRun: BenchmarkRun | null;
  softwares?: Software[];
  projects?: Project[];
  securitySuiteFilters?: SecuritySuiteFilterState;
  onSecuritySuiteFiltersChange?: React.Dispatch<React.SetStateAction<SecuritySuiteFilterState>>;
  onRunUpdated?: (updatedRun: BenchmarkRun) => void;
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

const REMEDIATION_LIFECYCLE_OPTIONS: Array<{
  value: FindingValidationLifecycleState;
  label: string;
}> = [
  { value: 'CONFIRMED', label: 'Pendente de Remediação (Confirmada)' },
  { value: 'PROBABLE', label: 'Pendente de Remediação (Provável)' },
  { value: 'FIXED_PENDING_RETEST', label: 'Em Remediação (Aguardando Reteste)' },
  { value: 'VERIFIED_RESOLVED', label: 'Remediado & Verificado (Resolvido)' },
  { value: 'ACCEPTED_RISK', label: 'Risco Aceito (Exceção Governança)' },
  { value: 'FALSE_POSITIVE', label: 'Descartado (Falso Positivo)' },
  { value: 'NOT_REPRODUCIBLE', label: 'Descartado (Não Reproduzível)' },
  { value: 'INCONCLUSIVE', label: 'Inconclusivo (Sob Análise)' },
  { value: 'NOT_TESTED', label: 'Não Testado' },
];

const SEVERITY_FILTER_ITEMS: Array<{
  key: CoreSeverityFilter;
  label: string;
  shortLabel: string;
  activeClass: string;
  textClass: string;
}> = [
  {
    key: 'CRITICAL',
    label: 'Critical',
    shortLabel: 'Crítico / Blocker',
    activeClass: 'bg-rose-600 text-white border-rose-600',
    textClass: 'text-rose-600 dark:text-rose-400',
  },
  {
    key: 'HIGH',
    label: 'High',
    shortLabel: 'Alto',
    activeClass: 'bg-orange-500 text-slate-950 border-orange-500',
    textClass: 'text-orange-600 dark:text-orange-400',
  },
  {
    key: 'MEDIUM',
    label: 'Medium',
    shortLabel: 'Médio',
    activeClass: 'bg-amber-500 text-slate-950 border-amber-500',
    textClass: 'text-amber-600 dark:text-amber-400',
  },
  {
    key: 'LOW',
    label: 'Low',
    shortLabel: 'Baixo / Info',
    activeClass: 'bg-sky-500 text-slate-950 border-sky-500',
    textClass: 'text-sky-600 dark:text-sky-400',
  },
];

export const SecurityAssessmentSuiteModule: React.FC<
  SecurityAssessmentSuiteModuleProps
> = ({
  latestRun,
  softwares = [],
  projects = [],
  securitySuiteFilters,
  onSecuritySuiteFiltersChange,
  onRunUpdated,
  onRefresh,
  onNotify,
}) => {
  const [suite, setSuite] = useState<SecurityAssessmentSuiteBundle | null>(null);
  const [loading, setLoading] = useState(false);
  const [emergencyStopped, setEmergencyStopped] = useState(false);
  const [validationMap, setValidationMap] = useState<
    Record<string, VulnerabilityValidationState>
  >({});
  const [lifecycleMap, setLifecycleMap] = useState<
    Record<string, FindingValidationLifecycleState>
  >({});
  const [updatingFindingId, setUpdatingFindingId] = useState<string | null>(null);

  // Fallback local filter state only if global state is not provided via App.tsx props
  const [localFilters, setLocalFilters] = useState<SecuritySuiteFilterState>(
    DEFAULT_SECURITY_SUITE_FILTERS
  );

  const activeFilters = securitySuiteFilters ?? localFilters;
  const setFilters: React.Dispatch<React.SetStateAction<SecuritySuiteFilterState>> =
    onSecuritySuiteFiltersChange ?? setLocalFilters;

  const updateFilterField = useCallback(
    <K extends keyof SecuritySuiteFilterState>(
      field: K,
      value: SecuritySuiteFilterState[K]
    ) => {
      setFilters((prev) => ({
        ...prev,
        [field]: value,
      }));
    },
    [setFilters]
  );

  const toggleSeverityFilter = useCallback(
    (severity: CoreSeverityFilter) => {
      setFilters((prev) => {
        const exists = prev.severities.includes(severity);
        const nextSeverities = exists
          ? prev.severities.filter((s) => s !== severity)
          : [...prev.severities, severity];
        return {
          ...prev,
          severities: nextSeverities,
        };
      });
    },
    [setFilters]
  );

  const resetAllFilters = useCallback(() => {
    setFilters(DEFAULT_SECURITY_SUITE_FILTERS);
  }, [setFilters]);

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

  const allFindings = useMemo(() => latestRun?.findings || [], [latestRun]);

  const availableSoftwares = useMemo(() => {
    if (latestRun?.scoreCards && latestRun.scoreCards.length > 0) {
      return latestRun.scoreCards.map((sc) => ({
        id: sc.softwareId,
        name: sc.softwareName,
        version: sc.softwareVersion,
      }));
    }
    return softwares.map((sw) => ({
      id: sw.id,
      name: sw.name,
      version: sw.version,
    }));
  }, [latestRun, softwares]);

  const activeProjectName = useMemo(() => {
    if (!latestRun) return null;
    const matched = projects.find((p) => p.id === latestRun.projectId);
    return matched?.name || latestRun.projectName;
  }, [latestRun, projects]);

  const filteredFindings = useMemo(
    () =>
      filterSecuritySuiteFindings(allFindings, activeFilters, {
        validationMap,
        lifecycleMap,
      }),
    [allFindings, activeFilters, validationMap, lifecycleMap]
  );

  const filterMetrics = useMemo(
    () =>
      computeSecurityFindingsFilterMetrics(
        allFindings,
        filteredFindings,
        activeFilters,
        { validationMap, lifecycleMap }
      ),
    [allFindings, filteredFindings, activeFilters, validationMap, lifecycleMap]
  );

  const handleValidateFinding = async (
    findingId: string,
    newState: VulnerabilityValidationState
  ) => {
    if (!latestRun) return;
    setUpdatingFindingId(findingId);
    try {
      const res = await fetch(`/api/findings/${findingId}/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          runId: latestRun.id,
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
      if (payload.finding?.lifecycleState) {
        setLifecycleMap((prev) => ({
          ...prev,
          [findingId]: payload.finding.lifecycleState,
        }));
      }
      if (payload.run && onRunUpdated) {
        onRunUpdated(payload.run);
      }
      onNotify(
        `Status de validação atualizado para ${newState} (SHA-256: ${payload.evidenceHash.slice(0, 12)}...).`,
        'success'
      );
      await fetchSuite();
      await onRefresh();
    } catch {
      onNotify('Erro de comunicação ao registrar validação.', 'error');
    } finally {
      setUpdatingFindingId(null);
    }
  };

  const handleUpdateRemediationStatus = async (
    findingId: string,
    newLifecycleState: FindingValidationLifecycleState
  ) => {
    if (!latestRun) return;
    setUpdatingFindingId(findingId);
    try {
      const res = await fetch(`/api/findings/${findingId}/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          runId: latestRun.id,
          lifecycleState: newLifecycleState,
          validationStatus: newLifecycleState,
          verificationNote: `Status de remediação atualizado na Suíte de Segurança para ${newLifecycleState}.`,
        }),
      });
      const payload = await res.json();
      if (!res.ok) {
        onNotify(
          payload.message || payload.error || 'Erro ao atualizar status de remediação.',
          'error'
        );
        return;
      }
      setLifecycleMap((prev) => ({ ...prev, [findingId]: newLifecycleState }));
      const resolved = resolveFindingRemediationInfo(
        { validationStatus: newLifecycleState, lifecycleState: newLifecycleState },
        undefined,
        newLifecycleState
      );
      setValidationMap((prev) => ({ ...prev, [findingId]: resolved.validationState6 }));
      if (payload.run && onRunUpdated) {
        onRunUpdated(payload.run);
      }
      onNotify(
        `Status de remediação atualizado para ${newLifecycleState} (SHA-256: ${payload.evidenceHash.slice(0, 12)}...).`,
        'success'
      );
      await fetchSuite();
      await onRefresh();
    } catch {
      onNotify('Erro de comunicação ao atualizar status de remediação.', 'error');
    } finally {
      setUpdatingFindingId(null);
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

  const renderSeverityIndicator = (severity: SeverityLevel) => {
    const bucket = normalizeFindingSeverityBucket(severity);
    switch (bucket) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1.5 font-mono font-bold text-rose-600 dark:text-rose-400">
            <AlertOctagon className="w-3.5 h-3.5 shrink-0" />
            <span>Critical ({severity})</span>
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1.5 font-mono font-bold text-orange-600 dark:text-orange-400">
            <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
            <span>High</span>
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1.5 font-mono font-semibold text-amber-600 dark:text-amber-400">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            <span>Medium</span>
          </span>
        );
      case 'LOW':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 font-mono font-medium text-sky-600 dark:text-sky-400">
            <Info className="w-3.5 h-3.5 shrink-0" />
            <span>Low ({severity})</span>
          </span>
        );
    }
  };

  if (!latestRun) {
    return (
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
          <HairlineAnimatedFigure
            type="vault"
            variant="hero"
            width={160}
            height={126}
            active={true}
            accentColor="#f43f5e"
          />
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
              Suíte de Avaliação de Segurança, Superfície &amp; Attack Path Analysis (A vs. B)
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
              Comparação determinística sob os mesmos parâmetros com validação em 6 estados, isolamento por MicroVM e trilha SHA-256.
            </p>
          </div>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-8 text-center">
          <p className="text-sm text-slate-500">
            Execute um benchmark para carregar os 15 módulos de Avaliação Comparativa de Segurança (A vs. B).
          </p>
        </div>
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

  const singleSeveritySelectValue =
    activeFilters.severities.length === 1
      ? activeFilters.severities[0]!
      : activeFilters.severities.length === 0
        ? 'ALL'
        : 'MULTI';

  return (
    <div className="space-y-6">
      {/* Header + Controle de Escopo e Botão de Cancelamento Emergencial */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div className="flex flex-col sm:flex-row sm:items-center gap-4">
          <HairlineAnimatedFigure
            type="vault"
            variant="hero"
            width={160}
            height={126}
            active={true}
            accentColor="#f43f5e"
          />
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
              Suíte de Avaliação de Segurança, Superfície &amp; Attack Path Analysis (A vs. B)
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
              Comparação determinística sob os mesmos parâmetros com validação em 6 estados, isolamento por MicroVM e trilha SHA-256
              {activeProjectName ? ` · Projeto: ${activeProjectName}` : ''}.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={fetchSuite}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer whitespace-nowrap shrink-0"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Recalcular Matriz
          </button>
          <button
            type="button"
            onClick={handleEmergencyStop}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold bg-rose-600 text-white hover:bg-rose-500 transition-colors cursor-pointer whitespace-nowrap shrink-0"
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
        <div className="space-y-3">
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs font-mono tabular-nums">
            <div>
              <div className="text-slate-400 font-sans text-[11px]">Isolamento Real</div>
              <div className="font-bold text-[#31d6c4] mt-0.5">
                {suite.sandboxControl.isolationMode} ({suite.sandboxControl.isolationState || 'N/A'})
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
              <div
                className={`font-bold mt-0.5 ${
                  suite.sandboxControl.recoveryVerified ? 'text-emerald-500' : 'text-amber-500'
                }`}
              >
                {suite.sandboxControl.timeoutSeconds}s /{' '}
                {suite.sandboxControl.recoveryVerified ? 'Verificada' : 'Não Exercitada'}
              </div>
            </div>
          </div>

          {suite.modules && suite.modules.length > 0 && (
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-4 flex flex-wrap items-center justify-between gap-3 text-xs">
              <div>
                <span className="font-bold text-slate-900 dark:text-slate-100">
                  Módulos da Suíte (Implementados vs Ativos em Execução Real):
                </span>{' '}
                <span className="font-mono text-slate-500 tabular-nums">
                  {suite.modules.filter((m) => m.implementationState === 'IMPLEMENTED').length} implementados ·{' '}
                  {suite.modules.filter((m) => m.status === 'ACTIVE').length} ativos ·{' '}
                  {suite.modules.filter((m) => m.status === 'NOT_CONFIGURED').length} não configurados ·{' '}
                  {suite.modules.filter((m) => m.status === 'BLOCKED').length} bloqueados
                </span>
              </div>
              <div className="flex flex-wrap gap-1.5 font-mono text-[10px]">
                {suite.modules.map((mod) => (
                  <span
                    key={mod.moduleId}
                    title={mod.reason || mod.label}
                    className={`px-2 py-0.5 rounded border ${
                      mod.status === 'ACTIVE'
                        ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-500'
                        : mod.status === 'BLOCKED'
                          ? 'border-rose-500/30 bg-rose-500/10 text-rose-500'
                          : 'border-amber-500/30 bg-amber-500/10 text-amber-500'
                    }`}
                  >
                    {mod.moduleId}: {mod.status}
                  </span>
                ))}
              </div>
            </div>
          )}
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
                  {m.testCoverageState === 'MEASURED' || (m.testCoveragePercent !== null && m.testCoveragePercent > 0) ? (
                    <div className="font-bold text-sm text-emerald-500 mt-0.5">
                      {m.testCoveragePercent}% ({m.totalExecutionTimeMs}ms)
                    </div>
                  ) : (
                    <div className="font-bold text-xs text-amber-500 mt-1">
                      NÃO MEDIDO ({m.testCoverageState || 'NOT_MEASURED'})
                    </div>
                  )}
                </div>
                <div className="p-2.5 rounded bg-slate-50 dark:bg-[#080b10] border border-slate-200 dark:border-slate-800">
                  <div className="text-[10px] font-sans text-slate-400">Recuperação / Resiliência</div>
                  <div className="font-bold text-sm text-[#31d6c4] mt-0.5">
                    {m.recoveryCapabilityScore !== null ? m.recoveryCapabilityScore.toFixed(1) : 'N/A'} /{' '}
                    {m.performanceUnderStressScore !== null ? m.performanceUnderStressScore.toFixed(1) : 'N/A'}
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
                    <span className="font-mono text-amber-500 tabular-nums">
                      Índice de Exposição: {surf.surfaceRiskIndex.toFixed(1)} / 10.0
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 font-mono text-[11px] text-slate-600 dark:text-slate-400 tabular-nums">
                    <div>Pontos de Entrada: {surf.exposedEntryPoints.length}</div>
                    <div>Conectores SQL/DB: {surf.databaseConnectors.length}</div>
                    <div>Chamadas de Processo/SO: {surf.externalProcessInvocations.length}</div>
                    <div>Operações Privilegiadas: {surf.privilegedOperations.length}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Attack Path & Taint Analysis */}
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <GitBranch className="w-4 h-4 text-rose-500" />
                <span>Attack Path &amp; Taint Analysis (Caminhos Críticos no Grafo de Código)</span>
              </h3>
              <HairlineAnimatedFigure
                type="sieve"
                size={56}
                active={true}
                accentColor="#f59e0b"
                title="Funil SAST & Taint Analysis (15 Sinks CWE)"
              />
            </div>
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
                    <div className="space-y-1 font-mono text-[11px] tabular-nums">
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

      {/* 3. Sistema de Filtros Avançados & Matriz de Validação / Remediação de Vulnerabilidades */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-4">
          <div>
            <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-[#31d6c4]" />
              <span>
                Matriz de Validação de Vulnerabilidades, Gravidade &amp; Status de Remediação (Rastreabilidade SHA-256)
              </span>
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Filtre achados por gravidade (Critical, High, Medium, Low), status de remediação e validação técnica, com persistência global na sessão.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 text-xs font-mono tabular-nums">
            <span className="text-slate-600 dark:text-slate-300">
              Exibindo <strong>{filterMetrics.filteredCount}</strong> de{' '}
              <strong>{filterMetrics.totalFindings}</strong> achados
              <span className="mx-1.5">·</span>
              Esforço estimado: <strong>{filterMetrics.filteredEffortMinutes} min</strong>
            </span>

            {filterMetrics.hasActiveFilters && (
              <button
                type="button"
                onClick={resetAllFilters}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:border-[#31d6c4] hover:text-[#31d6c4] transition-colors cursor-pointer whitespace-nowrap shrink-0"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Limpar Filtros</span>
              </button>
            )}
          </div>
        </div>

        {/* Painel de Filtros Avançados (Gravidade + Status de Remediação + Software + Busca) */}
        <div
          role="region"
          aria-label="Filtros avançados de achados de segurança"
          className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#080b10] space-y-4"
        >
          {/* Linha 1: Botões Rápidos de Gravidade (Critical, High, Medium, Low) + Seletores de Status de Remediação */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {/* Filtro Interativo por Gravidade (Critical, High, Medium, Low) */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                  <Filter className="w-3.5 h-3.5 text-[#31d6c4]" />
                  <span>Gravidade do Achado (Critical, High, Medium, Low)</span>
                </span>
                <span className="text-[11px] font-mono text-slate-500">
                  {activeFilters.severities.length === 0
                    ? 'Todas selecionadas'
                    : `${activeFilters.severities.length} selecionada(s)`}
                </span>
              </div>

              <div
                role="group"
                aria-label="Filtro por gravidade"
                className="flex flex-wrap items-center gap-1.5"
              >
                <button
                  type="button"
                  aria-pressed={activeFilters.severities.length === 0}
                  onClick={() => updateFilterField('severities', [])}
                  className={`px-3 py-1.5 rounded-md text-xs font-semibold border transition-colors cursor-pointer whitespace-nowrap shrink-0 font-mono tabular-nums ${
                    activeFilters.severities.length === 0
                      ? 'bg-[#31d6c4] text-slate-950 border-[#31d6c4] font-bold'
                      : 'bg-white dark:bg-[#0f141c] border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:border-[#31d6c4]'
                  }`}
                >
                  Todas ({filterMetrics.totalFindings})
                </button>

                {SEVERITY_FILTER_ITEMS.map((item) => {
                  const isSelected = activeFilters.severities.includes(item.key);
                  const count = filterMetrics.bySeverity[item.key];
                  return (
                    <button
                      key={item.key}
                      type="button"
                      aria-pressed={isSelected}
                      onClick={() => toggleSeverityFilter(item.key)}
                      className={`px-3 py-1.5 rounded-md text-xs font-semibold border transition-colors cursor-pointer whitespace-nowrap shrink-0 font-mono tabular-nums ${
                        isSelected
                          ? item.activeClass
                          : `bg-white dark:bg-[#0f141c] border-slate-300 dark:border-slate-700 ${item.textClass} hover:border-slate-400`
                      }`}
                    >
                      {item.label} ({count})
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Filtro Interativo por Status de Remediação */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-[#31d6c4]" />
                  <span>Status de Remediação (Ciclo DevSecOps)</span>
                </span>
                <span className="text-[11px] font-mono text-slate-500">
                  {activeFilters.remediationStatus === 'ALL'
                    ? 'Todos os status'
                    : activeFilters.remediationStatus}
                </span>
              </div>

              <div
                role="group"
                aria-label="Filtro rápido por status de remediação"
                className="flex flex-wrap items-center gap-1.5"
              >
                <button
                  type="button"
                  aria-pressed={activeFilters.remediationStatus === 'ALL'}
                  onClick={() => updateFilterField('remediationStatus', 'ALL')}
                  className={`px-2.5 py-1.5 rounded-md text-xs font-semibold border transition-colors cursor-pointer whitespace-nowrap shrink-0 font-mono tabular-nums ${
                    activeFilters.remediationStatus === 'ALL'
                      ? 'bg-[#31d6c4] text-slate-950 border-[#31d6c4] font-bold'
                      : 'bg-white dark:bg-[#0f141c] border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:border-[#31d6c4]'
                  }`}
                >
                  Todos ({filterMetrics.totalFindings})
                </button>

                <button
                  type="button"
                  aria-pressed={activeFilters.remediationStatus === 'OPEN_PENDING'}
                  onClick={() => updateFilterField('remediationStatus', 'OPEN_PENDING')}
                  className={`px-2.5 py-1.5 rounded-md text-xs font-semibold border transition-colors cursor-pointer whitespace-nowrap shrink-0 font-mono tabular-nums ${
                    activeFilters.remediationStatus === 'OPEN_PENDING'
                      ? 'bg-rose-600 text-white border-rose-600 font-bold'
                      : 'bg-white dark:bg-[#0f141c] border-slate-300 dark:border-slate-700 text-rose-600 dark:text-rose-400 hover:border-rose-400'
                  }`}
                >
                  Pendente ({filterMetrics.byRemediationBucket.OPEN_PENDING})
                </button>

                <button
                  type="button"
                  aria-pressed={activeFilters.remediationStatus === 'IN_REMEDIATION'}
                  onClick={() => updateFilterField('remediationStatus', 'IN_REMEDIATION')}
                  className={`px-2.5 py-1.5 rounded-md text-xs font-semibold border transition-colors cursor-pointer whitespace-nowrap shrink-0 font-mono tabular-nums ${
                    activeFilters.remediationStatus === 'IN_REMEDIATION'
                      ? 'bg-amber-500 text-slate-950 border-amber-500 font-bold'
                      : 'bg-white dark:bg-[#0f141c] border-slate-300 dark:border-slate-700 text-amber-600 dark:text-amber-400 hover:border-amber-400'
                  }`}
                >
                  Em Remediação ({filterMetrics.byRemediationBucket.IN_REMEDIATION})
                </button>

                <button
                  type="button"
                  aria-pressed={activeFilters.remediationStatus === 'REMEDIATED'}
                  onClick={() => updateFilterField('remediationStatus', 'REMEDIATED')}
                  className={`px-2.5 py-1.5 rounded-md text-xs font-semibold border transition-colors cursor-pointer whitespace-nowrap shrink-0 font-mono tabular-nums ${
                    activeFilters.remediationStatus === 'REMEDIATED'
                      ? 'bg-emerald-500 text-slate-950 border-emerald-500 font-bold'
                      : 'bg-white dark:bg-[#0f141c] border-slate-300 dark:border-slate-700 text-emerald-600 dark:text-emerald-400 hover:border-emerald-400'
                  }`}
                >
                  Remediado ({filterMetrics.byRemediationBucket.REMEDIATED})
                </button>

                <button
                  type="button"
                  aria-pressed={activeFilters.remediationStatus === 'RISK_ACCEPTED'}
                  onClick={() => updateFilterField('remediationStatus', 'RISK_ACCEPTED')}
                  className={`px-2.5 py-1.5 rounded-md text-xs font-semibold border transition-colors cursor-pointer whitespace-nowrap shrink-0 font-mono tabular-nums ${
                    activeFilters.remediationStatus === 'RISK_ACCEPTED'
                      ? 'bg-indigo-500 text-white border-indigo-500 font-bold'
                      : 'bg-white dark:bg-[#0f141c] border-slate-300 dark:border-slate-700 text-indigo-600 dark:text-indigo-400 hover:border-indigo-400'
                  }`}
                >
                  Risco Aceito ({filterMetrics.byRemediationBucket.RISK_ACCEPTED})
                </button>

                <button
                  type="button"
                  aria-pressed={activeFilters.remediationStatus === 'DISMISSED_FP'}
                  onClick={() => updateFilterField('remediationStatus', 'DISMISSED_FP')}
                  className={`px-2.5 py-1.5 rounded-md text-xs font-semibold border transition-colors cursor-pointer whitespace-nowrap shrink-0 font-mono tabular-nums ${
                    activeFilters.remediationStatus === 'DISMISSED_FP'
                      ? 'bg-slate-600 text-white border-slate-600 font-bold'
                      : 'bg-white dark:bg-[#0f141c] border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:border-slate-400'
                  }`}
                >
                  Falso Positivo / Descartado ({filterMetrics.byRemediationBucket.DISMISSED_FP})
                </button>
              </div>
            </div>
          </div>

          {/* Linha 2: Controles Combináveis Detalhados (Busca, Gravidade Select, Status de Remediação Select, Software, Categoria, Validação 6 Estados) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3 pt-2 border-t border-slate-200 dark:border-slate-800">
            <div>
              <label
                htmlFor="sec-suite-search"
                className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1"
              >
                Buscar Achado (Regra, CWE, Arquivo)
              </label>
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                <input
                  id="sec-suite-search"
                  type="text"
                  value={activeFilters.searchQuery}
                  onChange={(e) => updateFilterField('searchQuery', e.target.value)}
                  placeholder="Ex.: CWE-89, sql, token..."
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] pl-8 pr-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="sec-suite-severity-select"
                className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1"
              >
                Filtro de Gravidade
              </label>
              <select
                id="sec-suite-severity-select"
                value={singleSeveritySelectValue}
                onChange={(e) => {
                  const val = e.target.value;
                  if (val === 'ALL' || val === 'MULTI') {
                    updateFilterField('severities', []);
                  } else {
                    updateFilterField('severities', [val as CoreSeverityFilter]);
                  }
                }}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-2.5 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100"
              >
                <option value="ALL">Todas as Gravidades</option>
                {singleSeveritySelectValue === 'MULTI' && (
                  <option value="MULTI">
                    Múltiplas ({activeFilters.severities.join(', ')})
                  </option>
                )}
                <option value="CRITICAL">Critical (Crítico / Blocker)</option>
                <option value="HIGH">High (Alto)</option>
                <option value="MEDIUM">Medium (Médio)</option>
                <option value="LOW">Low (Baixo / Info)</option>
              </select>
            </div>

            <div>
              <label
                htmlFor="sec-suite-remediation-select"
                className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1"
              >
                Status de Remediação
              </label>
              <select
                id="sec-suite-remediation-select"
                value={activeFilters.remediationStatus}
                onChange={(e) =>
                  updateFilterField(
                    'remediationStatus',
                    e.target.value as RemediationStatusBucket
                  )
                }
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-2.5 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100"
              >
                <option value="ALL">Todos os Status ({filterMetrics.totalFindings})</option>
                <optgroup label="Agrupamentos de Remediação">
                  <option value="OPEN_PENDING">
                    Pendente de Remediação ({filterMetrics.byRemediationBucket.OPEN_PENDING})
                  </option>
                  <option value="IN_REMEDIATION">
                    Em Remediação / Reteste ({filterMetrics.byRemediationBucket.IN_REMEDIATION})
                  </option>
                  <option value="REMEDIATED">
                    Remediado &amp; Verificado ({filterMetrics.byRemediationBucket.REMEDIATED})
                  </option>
                  <option value="RISK_ACCEPTED">
                    Risco Aceito ({filterMetrics.byRemediationBucket.RISK_ACCEPTED})
                  </option>
                  <option value="DISMISSED_FP">
                    Descartado / Falso Positivo ({filterMetrics.byRemediationBucket.DISMISSED_FP})
                  </option>
                </optgroup>
                <optgroup label="Estados Específicos do Ciclo (9 Estados)">
                  <option value="CONFIRMED">CONFIRMED (Confirmada)</option>
                  <option value="PROBABLE">PROBABLE (Provável)</option>
                  <option value="FIXED_PENDING_RETEST">
                    FIXED_PENDING_RETEST (Aguardando Reteste)
                  </option>
                  <option value="VERIFIED_RESOLVED">
                    VERIFIED_RESOLVED (Resolvida &amp; Verificada)
                  </option>
                  <option value="ACCEPTED_RISK">ACCEPTED_RISK (Risco Aceito)</option>
                  <option value="FALSE_POSITIVE">FALSE_POSITIVE (Falso Positivo)</option>
                  <option value="NOT_REPRODUCIBLE">NOT_REPRODUCIBLE (Não Reproduzível)</option>
                  <option value="INCONCLUSIVE">INCONCLUSIVE (Inconclusiva)</option>
                  <option value="NOT_TESTED">NOT_TESTED (Não Testada)</option>
                </optgroup>
              </select>
            </div>

            <div>
              <label
                htmlFor="sec-suite-software-select"
                className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1"
              >
                Software Avaliado
              </label>
              <select
                id="sec-suite-software-select"
                value={activeFilters.softwareId}
                onChange={(e) => updateFilterField('softwareId', e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-2.5 py-1.5 text-xs text-slate-900 dark:text-slate-100"
              >
                <option value="ALL">Todos os Softwares</option>
                {availableSoftwares.map((sw) => (
                  <option key={sw.id} value={sw.id}>
                    {sw.name} (v{sw.version})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                htmlFor="sec-suite-category-select"
                className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1"
              >
                Categoria Técnica
              </label>
              <select
                id="sec-suite-category-select"
                value={activeFilters.category}
                onChange={(e) => updateFilterField('category', e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-2.5 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100"
              >
                <option value="ALL">Todas as Categorias</option>
                <option value="SAST">SAST (Análise Estática)</option>
                <option value="SECRETS">SECRETS (Segredos Expostos)</option>
                <option value="SCA">SCA (Dependências)</option>
                <option value="DATABASE">DATABASE (Banco de Dados SQL)</option>
                <option value="DAST">DAST (Superfície Dinâmica)</option>
                <option value="CODE_QUALITY">CODE_QUALITY (Qualidade)</option>
                <option value="ARCHITECTURE">ARCHITECTURE (Arquitetura)</option>
              </select>
            </div>

            <div>
              <label
                htmlFor="sec-suite-validation-select"
                className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1"
              >
                Validação Técnica (6 Estados)
              </label>
              <select
                id="sec-suite-validation-select"
                value={activeFilters.validationState}
                onChange={(e) =>
                  updateFilterField(
                    'validationState',
                    e.target.value as 'ALL' | VulnerabilityValidationState
                  )
                }
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-2.5 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100"
              >
                <option value="ALL">Todos os Estados (6)</option>
                {VALIDATION_STATES.map((st) => (
                  <option key={st.value} value={st.value}>
                    {st.value}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Tabela de Achados Filtrados */}
        <div className="overflow-x-auto df-hover-scroll">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                <th className="py-2.5 pr-3">Software</th>
                <th className="py-2.5 px-3">Ferramenta, Cenário &amp; Remediação Recomendada</th>
                <th className="py-2.5 px-3">Gravidade</th>
                <th className="py-2.5 px-3">Evidência Técnica (SHA-256)</th>
                <th className="py-2.5 px-3">Status de Remediação</th>
                <th className="py-2.5 pl-3">Estado de Validação (6 Estados)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center space-y-3">
                    <div className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                      Nenhum achado corresponde aos filtros de gravidade e remediação selecionados.
                    </div>
                    <p className="text-xs text-slate-500">
                      Ajuste os critérios de gravidade (Critical, High, Medium, Low) ou status de remediação acima.
                    </p>
                    {filterMetrics.hasActiveFilters && (
                      <div>
                        <button
                          type="button"
                          onClick={resetAllFilters}
                          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
                        >
                          <RotateCcw className="w-3.5 h-3.5" />
                          <span>Limpar Filtros Ativos</span>
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ) : (
                filteredFindings.map((f) => {
                  const remInfo = resolveFindingRemediationInfo(
                    f,
                    validationMap[f.id],
                    lifecycleMap[f.id]
                  );
                  const isUpdating = updatingFindingId === f.id;

                  return (
                    <tr
                      key={f.id}
                      className={`transition-colors ${
                        remInfo.isExempt
                          ? 'bg-slate-50/50 dark:bg-slate-900/25 opacity-80'
                          : 'hover:bg-slate-50 dark:hover:bg-slate-800/30'
                      }`}
                    >
                      <td className="py-3 pr-3 font-semibold text-slate-900 dark:text-slate-100 whitespace-nowrap align-top">
                        <div>
                          {f.softwareName} (v{f.softwareVersion})
                        </div>
                        <div className="text-[11px] font-mono font-normal text-slate-500 mt-0.5">
                          {f.category}
                          {f.cwe ? ` · ${f.cwe}` : ''}
                        </div>
                      </td>

                      <td className="py-3 px-3 align-top max-w-md">
                        <div className="font-semibold text-slate-800 dark:text-slate-200">
                          {f.title}
                        </div>
                        <div className="text-[11px] font-mono text-slate-500 mt-0.5">
                          {f.toolName} v{f.toolVersion} · {f.originalRuleId}
                        </div>
                        {f.remediation && (
                          <div className="text-[11px] text-slate-600 dark:text-slate-400 mt-1">
                            <span className="font-semibold text-emerald-700 dark:text-[#31d6c4]">
                              Remediação:
                            </span>{' '}
                            {f.remediation}
                          </div>
                        )}
                      </td>

                      <td className="py-3 px-3 whitespace-nowrap align-top">
                        <div>{renderSeverityIndicator(f.severity)}</div>
                        <div className="text-[11px] font-mono text-slate-400 mt-0.5 flex items-center gap-1 tabular-nums">
                          <Clock className="w-3 h-3 text-[#31d6c4]" />
                          <span>{f.remediationEffortMinutes || 15} min</span>
                        </div>
                      </td>

                      <td className="py-3 px-3 font-mono text-[11px] text-slate-600 dark:text-slate-300 whitespace-nowrap align-top tabular-nums">
                        <div>
                          {f.filePath}:{f.lineNumber}
                        </div>
                        <div className="text-slate-400">
                          SHA-256: {f.evidenceSha256.slice(0, 16)}...
                        </div>
                      </td>

                      <td className="py-3 px-3 align-top">
                        <select
                          aria-label={`Status de remediação para ${f.title}`}
                          disabled={isUpdating}
                          value={remInfo.lifecycleState}
                          onChange={(e) =>
                            handleUpdateRemediationStatus(
                              f.id,
                              e.target.value as FindingValidationLifecycleState
                            )
                          }
                          className="rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100 disabled:opacity-50"
                        >
                          {REMEDIATION_LIFECYCLE_OPTIONS.map((opt) => (
                            <option key={opt.value} value={opt.value}>
                              {opt.label}
                            </option>
                          ))}
                        </select>
                        <div className="mt-1 text-[11px] font-mono text-slate-500 flex items-center gap-1">
                          {remInfo.remediationBucket === 'REMEDIATED' ? (
                            <CheckCircle2 className="w-3 h-3 text-emerald-500 shrink-0" />
                          ) : null}
                          <span>{remInfo.remediationLabel}</span>
                        </div>
                      </td>

                      <td className="py-3 pl-3 align-top">
                        <select
                          aria-label={`Estado de validação para ${f.title}`}
                          disabled={isUpdating}
                          value={remInfo.validationState6}
                          onChange={(e) =>
                            handleValidateFinding(
                              f.id,
                              e.target.value as VulnerabilityValidationState
                            )
                          }
                          className="rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100 disabled:opacity-50"
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
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
