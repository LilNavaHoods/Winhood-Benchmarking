import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Award,
  CheckCircle2,
  Cpu,
  FileCheck2,
  GitCompare,
  Globe2,
  Layers,
  Lock,
  Play,
  Scale,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Sparkles,
  UserCheck,
} from 'lucide-react';
import type {
  AssessmentMode,
  BenchmarkCategoryKey,
  BenchmarkProfileConfig,
  MarketCompetitorCandidate,
  Project,
  Software,
} from '../types/benchmark';
import { CATEGORY_LABELS } from './DashboardModule';
import {
  ALL_BENCHMARK_CATEGORIES,
  DEFAULT_CATEGORY_WEIGHTS,
  normalizeEnabledCategoryWeights,
  validateCategoryWeights,
  validateEquivalenceConditions,
} from '../engine/scoringEngine';
import {
  DOMAIN_SPECIALIZED_PROFILES,
  buildPreAnalysisSummary,
  evaluateSoftwareComparability,
} from '../engine/methodologyCatalogEngine';

interface BenchmarkWizardModuleProps {
  projects: Project[];
  softwares: Software[];
  profiles: BenchmarkProfileConfig[];
  onRunCompleted: () => Promise<void>;
  onNotify: (msg: string, type?: 'success' | 'error') => void;
  onRequestUpload?: () => void;
}

export const BenchmarkWizardModule: React.FC<BenchmarkWizardModuleProps> = ({
  projects,
  softwares,
  profiles,
  onRunCompleted,
  onNotify,
  onRequestUpload,
}) => {
  // Wizard Steps: 1 = Mode, 2 = Project & Primary Software, 3 = Compare Target / Competitor Discovery, 4 = Weights & Profile, 5 = Equivalence & Review
  const [step, setStep] = useState<1 | 2 | 3 | 4 | 5>(1);
  const [wizardMode, setWizardMode] = useState<'QUICK' | 'CUSTOM' | 'ADVANCED'>('CUSTOM');
  const [crossProjectSelection, setCrossProjectSelection] = useState<boolean>(true);

  // Mode Selection (Seção 1: Três Modalidades Independentes)
  const [assessmentMode, setAssessmentMode] = useState<AssessmentMode>('INDIVIDUAL');

  // Primary Selection (Project is optional / cross-project enabled by default)
  const [selectedProjectId, setSelectedProjectId] = useState<string>(projects[0]?.id || '');
  const [primarySoftwareId, setPrimarySoftwareId] = useState<string>(softwares[0]?.id || '');
  const [comparisonSoftwareIds, setComparisonSoftwareIds] = useState<string[]>([]);

  // Market Competitor Discovery State (Modalidade C)
  const [discovering, setDiscovering] = useState<boolean>(false);
  const [marketCandidates, setMarketCandidates] = useState<MarketCompetitorCandidate[]>([]);
  const [selectedCandidate, setSelectedCandidate] = useState<MarketCompetitorCandidate | null>(null);
  const [candidateApproved, setCandidateApproved] = useState<boolean>(false);
  const [approvedCompetitorSoftwareId, setApprovedCompetitorSoftwareId] = useState<string>('');

  // Profile, Enabled Categories, Not Applicable Categories, Quality Gate & Weights
  const [selectedProfileId, setSelectedProfileId] = useState<string>(
    profiles[0]?.id || 'prof-complete-enterprise'
  );
  const [enabledCategories, setEnabledCategories] = useState<BenchmarkCategoryKey[]>([
    ...ALL_BENCHMARK_CATEGORIES,
  ]);
  const [notApplicableCategories, setNotApplicableCategories] = useState<BenchmarkCategoryKey[]>([]);
  const [qualityGateId, setQualityGateId] = useState<string>('qg-sonar-way-mqr');
  const [weights, setWeights] = useState<Record<BenchmarkCategoryKey, number>>({
    ...(profiles[0]?.weights || DEFAULT_CATEGORY_WEIGHTS),
  });
  const [enablePenaltyCaps, setEnablePenaltyCaps] = useState<boolean>(true);

  // Experimental Equivalence (Seção 22)
  const [cpuCoresLimit, setCpuCoresLimit] = useState<number>(4);
  const [memoryMbLimit, setMemoryMbLimit] = useState<number>(4096);
  const [osTarget, setOsTarget] = useState<string>(
    'Windows 11 Enterprise Sandbox / Linux Worker 6.8'
  );
  const [workloadConcurrency, setWorkloadConcurrency] = useState<number>(100);
  const [dastFormalAuth, setDastFormalAuth] = useState<boolean>(true);
  const [authorizedByOwner, setAuthorizedByOwner] = useState<string>(
    'CISO & Architecture Board (Auth #WH-2026-884)'
  );

  const [executing, setExecuting] = useState<boolean>(false);

  // Update primary software when project changes (or allow all softwares in cross-project mode)
  const projectSoftwares = crossProjectSelection
    ? softwares
    : softwares.filter((s) => !selectedProjectId || s.projectId === selectedProjectId);

  useEffect(() => {
    if (projectSoftwares.length > 0 && !projectSoftwares.some((s) => s.id === primarySoftwareId)) {
      setPrimarySoftwareId(projectSoftwares[0].id);
    }
  }, [selectedProjectId, projectSoftwares, primarySoftwareId]);

  const activePrimarySoftware = softwares.find((s) => s.id === primarySoftwareId);

  // Trigger Competitor Discovery when entering step 3 in Mode C
  useEffect(() => {
    if (step === 3 && assessmentMode === 'MARKET_COMPETITOR' && activePrimarySoftware) {
      handleDiscoverCompetitors();
    }
  }, [step, assessmentMode, activePrimarySoftware?.id]);

  const handleDiscoverCompetitors = async () => {
    setDiscovering(true);
    try {
      const res = await fetch('/api/market/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          softwareId: activePrimarySoftware?.id,
          category: activePrimarySoftware?.inventory?.category,
          purpose: activePrimarySoftware?.name,
          targetFeatures: activePrimarySoftware?.inventory?.frameworks || [],
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setMarketCandidates(data.candidates || []);
        if (data.candidates && data.candidates.length > 0) {
          setSelectedCandidate(data.candidates[0]);
        }
      } else {
        onNotify('Falha ao consultar catálogo de inteligência de mercado.', 'error');
      }
    } catch {
      onNotify('Erro de conexão com o motor de pesquisa de mercado.', 'error');
    } finally {
      setDiscovering(false);
    }
  };

  const handleApproveCompetitor = async (candidate: MarketCompetitorCandidate) => {
    if (!selectedProjectId || !activePrimarySoftware) {
      onNotify('Selecione o projeto e o software principal primeiro.', 'error');
      return;
    }

    try {
      const res = await fetch('/api/market/approve-and-compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: selectedProjectId,
          mainSoftwareId: activePrimarySoftware.id,
          competitorCandidate: candidate,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || 'Falha ao homologar concorrente.', 'error');
        return;
      }

      setCandidateApproved(true);
      setApprovedCompetitorSoftwareId(data.competitorSoftwareId);
      onNotify(
        `Concorrente "${candidate.name}" aprovado formalmente para a comparação mercadológica!`,
        'success'
      );
    } catch {
      onNotify('Erro ao registrar aprovação do concorrente.', 'error');
    }
  };

  const weightValidation = validateCategoryWeights(weights, enabledCategories);
  const eqValidation = validateEquivalenceConditions({
    cpuCoresLimit,
    memoryMbLimit,
    osTarget,
    workloadConcurrency,
    dastFormalAuthorization: dastFormalAuth,
    authorizedByOwner,
  });

  const handleSelectProfile = (profId: string) => {
    setSelectedProfileId(profId);
    const foundStandard = profiles.find((p) => p.id === profId);
    if (foundStandard) {
      const cats =
        foundStandard.enabledCategories && foundStandard.enabledCategories.length > 0
          ? [...foundStandard.enabledCategories]
          : [...ALL_BENCHMARK_CATEGORIES];
      setEnabledCategories(cats);
      setNotApplicableCategories(foundStandard.notApplicableCategories || []);
      setQualityGateId(foundStandard.qualityGateId || 'qg-sonar-way-mqr');
      setWeights(normalizeEnabledCategoryWeights(foundStandard.weights, cats));
      setEnablePenaltyCaps(foundStandard.enablePenaltyCaps);
      setCpuCoresLimit(foundStandard.equivalenceEnvironment.cpuCoresLimit);
      setMemoryMbLimit(foundStandard.equivalenceEnvironment.memoryMbLimit);
      setOsTarget(foundStandard.equivalenceEnvironment.osTarget);
      setWorkloadConcurrency(foundStandard.equivalenceEnvironment.workloadConcurrency);
      return;
    }

    const foundSpecialized = DOMAIN_SPECIALIZED_PROFILES.find((p) => p.id === profId);
    if (foundSpecialized) {
      const cats = [...foundSpecialized.enabledCategories];
      setEnabledCategories(cats);
      setNotApplicableCategories([...foundSpecialized.notApplicableCategories]);
      setWeights(normalizeEnabledCategoryWeights(foundSpecialized.weights, cats));
    }
  };

  const handleToggleCategoryScope = (cat: BenchmarkCategoryKey) => {
    setEnabledCategories((prev) => {
      const exists = prev.includes(cat);
      if (exists && prev.length <= 1) {
        onNotify('Mantenha pelo menos 1 categoria habilitada para o cálculo.', 'error');
        return prev;
      }
      const next = exists ? prev.filter((c) => c !== cat) : [...prev, cat];
      setWeights((curWeights) => normalizeEnabledCategoryWeights(curWeights, next));
      return next;
    });
  };

  const handleEnableAll12Categories = () => {
    const all12 = [...ALL_BENCHMARK_CATEGORIES];
    setEnabledCategories(all12);
    setWeights({ ...DEFAULT_CATEGORY_WEIGHTS });
  };

  const handleNormalizeWeightsTo100 = () => {
    setWeights((cur) => normalizeEnabledCategoryWeights(cur, enabledCategories));
  };

  const handleExecute = async () => {
    // Resolve final softwareIds list based on assessmentMode
    let finalSoftwareIds: string[] = [];

    if (assessmentMode === 'INDIVIDUAL') {
      if (!primarySoftwareId) {
        onNotify('Selecione o software a ser avaliado.', 'error');
        return;
      }
      finalSoftwareIds = [primarySoftwareId];
    } else if (assessmentMode === 'AB_COMPARE') {
      if (!primarySoftwareId) {
        onNotify('Selecione o primeiro software.', 'error');
        return;
      }
      if (comparisonSoftwareIds.length === 0) {
        onNotify('Selecione ao menos um segundo software para comparação.', 'error');
        return;
      }
      finalSoftwareIds = [primarySoftwareId, ...comparisonSoftwareIds.filter((id) => id !== primarySoftwareId)];
    } else if (assessmentMode === 'MARKET_COMPETITOR') {
      if (!primarySoftwareId) {
        onNotify('Selecione o software principal.', 'error');
        return;
      }
      if (!candidateApproved || !approvedCompetitorSoftwareId) {
        onNotify(
          'Homologue e aprove um concorrente de mercado antes de iniciar o benchmark.',
          'error'
        );
        return;
      }
      finalSoftwareIds = [primarySoftwareId, approvedCompetitorSoftwareId];
    }

    if (!weightValidation.valid) {
      onNotify(weightValidation.errors.join(' '), 'error');
      return;
    }
    if (!eqValidation.equivalent) {
      onNotify(eqValidation.reasons.join(' '), 'error');
      return;
    }

    setExecuting(true);
    try {
      const activeProf =
        profiles.find((p) => p.id === selectedProfileId) ||
        DOMAIN_SPECIALIZED_PROFILES.find((p) => p.id === selectedProfileId);
      const res = await fetch('/api/benchmark-runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: selectedProjectId || projects[0]?.id,
          softwareIds: finalSoftwareIds,
          profileId: selectedProfileId,
          profileName:
            assessmentMode === 'INDIVIDUAL'
              ? `Avaliação Individual - ${activePrimarySoftware?.name} (${activeProf?.name || 'MQR'})`
              : assessmentMode === 'MARKET_COMPETITOR'
                ? `Benchmark de Mercado: ${activePrimarySoftware?.name} vs ${selectedCandidate?.name}`
                : activeProf?.name || 'Benchmark Comparativo A/B WinHood',
          wizardMode,
          weights,
          enabledCategories,
          notApplicableCategories,
          qualityGateId,
          enablePenaltyCaps,
          equivalenceEnvironment: {
            cpuCoresLimit,
            memoryMbLimit,
            osTarget,
            workloadConcurrency,
            dastFormalAuthorization: dastFormalAuth,
            authorizedByOwner,
          },
          assessmentMode,
        }),
      });

      const payload = await res.json();
      if (!res.ok) {
        onNotify(payload.error || payload.message || 'Falha ao executar avaliação.', 'error');
        setExecuting(false);
        return;
      }

      onNotify(
        `Avaliação iniciada com sucesso [ID: ${payload.run.id}]. Acompanhe o progresso em tempo real!`,
        'success'
      );
      await onRunCompleted();
    } catch {
      onNotify('Erro de comunicação ao orquestrar avaliação.', 'error');
    } finally {
      setExecuting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-3">
            <Scale className="w-7 h-7 text-[#31d6c4]" />
            <span>Assistente de Avaliação &amp; Benchmark de Softwares</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mt-1">
            Plataforma independente de Software Quality Assessment, Security Assessment e Benchmark
            Intelligence. Três modalidades com auditoria, pré-análise e veracidade absoluta.
          </p>
        </div>

        {/* 3 Wizard Modes Selector (Seção 10.2: Rápido, Personalizado, Avançado) */}
        <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-200/70 dark:bg-[#0f141c] border border-slate-300/60 dark:border-slate-800 shrink-0">
          {[
            { id: 'QUICK', label: 'Modo Rápido' },
            { id: 'CUSTOM', label: 'Modo Personalizado' },
            { id: 'ADVANCED', label: 'Modo Avançado' },
          ].map((m) => (
            <button
              key={m.id}
              type="button"
              onClick={() => setWizardMode(m.id as 'QUICK' | 'CUSTOM' | 'ADVANCED')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors cursor-pointer ${
                wizardMode === m.id
                  ? 'bg-[#31d6c4] text-slate-950'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>
      </div>

      {/* Step Indicator Bar */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2.5">
        {[
          { num: 1, title: '01. Modalidade', sub: 'Individual, A/B ou Mercado' },
          { num: 2, title: '02. Software Principal', sub: 'Origem e integridade SHA-256' },
          {
            num: 3,
            title: assessmentMode === 'INDIVIDUAL' ? '03. Escopo Individual' : assessmentMode === 'MARKET_COMPETITOR' ? '03. Concorrente de Mercado' : '03. Segundo Software',
            sub: assessmentMode === 'INDIVIDUAL' ? 'Diagnóstico & conformidade' : assessmentMode === 'MARKET_COMPETITOR' ? 'Descoberta com aprovação' : 'Seleção de concorrentes',
          },
          { num: 4, title: '04. Perfis & Pesos', sub: '12 categorias matemáticas' },
          { num: 5, title: '05. Execução & Contrato', sub: 'Equivalência e veracidade' },
        ].map((item) => {
          const active = step === item.num;
          const done = step > item.num;
          return (
            <button
              key={item.num}
              type="button"
              onClick={() => setStep(item.num as any)}
              className={`text-left p-3.5 rounded-lg border transition-colors cursor-pointer ${
                active
                  ? 'border-[#31d6c4] bg-[#31d6c4]/10'
                  : done
                    ? 'border-emerald-500/40 bg-white dark:bg-[#0f141c]'
                    : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c]'
              }`}
            >
              <div className="text-xs font-bold text-slate-900 dark:text-slate-100 flex items-center justify-between">
                <span>{item.title}</span>
                {done && <CheckCircle2 className="w-4 h-4 text-[#31d6c4]" />}
              </div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 truncate">
                {item.sub}
              </div>
            </button>
          );
        })}
      </div>

      {/* Step Content */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-6 space-y-6">
        {/* STEP 1: MODALIDADE DE AVALIAÇÃO (Seção 1 da Especificação) */}
        {step === 1 && (
          <div className="space-y-6">
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                Como você deseja avaliar o software?
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                Selecione uma das três modalidades independentes de auditoria técnica.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Opção A: Avaliação Individual */}
              <div
                onClick={() => setAssessmentMode('INDIVIDUAL')}
                className={`p-5 rounded-xl border-2 transition-all cursor-pointer flex flex-col justify-between ${
                  assessmentMode === 'INDIVIDUAL'
                    ? 'border-[#31d6c4] bg-[#31d6c4]/5 shadow-sm'
                    : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className="w-10 h-10 rounded-lg bg-[#31d6c4]/10 flex items-center justify-center text-[#31d6c4]">
                      <ShieldCheck className="w-6 h-6" />
                    </div>
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-bold">
                      Modalidade A
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                    Avaliar um Único Software
                  </h3>
                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-2 leading-relaxed">
                    Auditoria aprofundada de qualidade de código, segurança, arquitetura, QA e
                    conformidade de um único projeto.
                  </p>
                  <ul className="text-[11px] text-slate-500 space-y-1.5 mt-3">
                    <li className="flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-[#31d6c4]" />
                      Nota de qualidade consolidada (0 a 100)
                    </li>
                    <li className="flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-[#31d6c4]" />
                      Atestado de Veracidade de 19 pontos
                    </li>
                    <li className="flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-[#31d6c4]" />
                      Plano prioritário de remediação
                    </li>
                  </ul>
                </div>
                <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80 text-[11px] font-bold text-[#31d6c4]">
                  {assessmentMode === 'INDIVIDUAL' ? '✓ Modalidade Selecionada' : 'Selecionar Modalidade A'}
                </div>
              </div>

              {/* Opção B: Comparação A/B */}
              <div
                onClick={() => setAssessmentMode('AB_COMPARE')}
                className={`p-5 rounded-xl border-2 transition-all cursor-pointer flex flex-col justify-between ${
                  assessmentMode === 'AB_COMPARE'
                    ? 'border-[#31d6c4] bg-[#31d6c4]/5 shadow-sm'
                    : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className="w-10 h-10 rounded-lg bg-indigo-500/10 flex items-center justify-center text-indigo-400">
                      <GitCompare className="w-6 h-6" />
                    </div>
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-bold">
                      Modalidade B
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                    Comparar Dois ou Mais Softwares
                  </h3>
                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-2 leading-relaxed">
                    Benchmark técnico lado a lado entre dois ou mais softwares fornecidos pela sua
                    equipe sob condições experimentais idênticas.
                  </p>
                  <ul className="text-[11px] text-slate-500 space-y-1.5 mt-3">
                    <li className="flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" />
                      Matriz comparativa de 12 categorias
                    </li>
                    <li className="flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" />
                      Garantia de equivalência experimental
                    </li>
                    <li className="flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" />
                      Vencedor fundamentado e gaps técnicos
                    </li>
                  </ul>
                </div>
                <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80 text-[11px] font-bold text-indigo-400">
                  {assessmentMode === 'AB_COMPARE' ? '✓ Modalidade Selecionada' : 'Selecionar Modalidade B'}
                </div>
              </div>

              {/* Opção C: Descoberta de Concorrente */}
              <div
                onClick={() => setAssessmentMode('MARKET_COMPETITOR')}
                className={`p-5 rounded-xl border-2 transition-all cursor-pointer flex flex-col justify-between ${
                  assessmentMode === 'MARKET_COMPETITOR'
                    ? 'border-[#31d6c4] bg-[#31d6c4]/5 shadow-sm'
                    : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className="w-10 h-10 rounded-lg bg-amber-500/10 flex items-center justify-center text-amber-400">
                      <Sparkles className="w-6 h-6" />
                    </div>
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-bold">
                      Modalidade C
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                    Descobrir Concorrente de Mercado
                  </h3>
                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-2 leading-relaxed">
                    Identifica automaticamente o concorrente de mercado mais próximo e exige
                    aprovação humana explícita antes do benchmark.
                  </p>
                  <ul className="text-[11px] text-slate-500 space-y-1.5 mt-3">
                    <li className="flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-amber-400" />
                      Motor de Similaridade Ponderada (6 eixos)
                    </li>
                    <li className="flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-amber-400" />
                      Aprovação humana obrigatória (HITL)
                    </li>
                    <li className="flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-amber-400" />
                      Diferenciação clara Open vs Closed Source
                    </li>
                  </ul>
                </div>
                <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80 text-[11px] font-bold text-amber-400">
                  {assessmentMode === 'MARKET_COMPETITOR' ? '✓ Modalidade Selecionada' : 'Selecionar Modalidade C'}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* STEP 2: PROJETO (OPCIONAL) & SOFTWARE PRINCIPAL */}
        {step === 2 && (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-lg bg-slate-50 dark:bg-[#080b10] border border-slate-200 dark:border-slate-800 text-xs">
              <span className="text-slate-600 dark:text-slate-300">
                <strong>Desacoplamento de Projetos (Seção 10.1):</strong> Softwares podem ser avaliados avulsos ou comparados entre projetos diferentes.
              </span>
              <label className="flex items-center gap-2 font-bold text-[#31d6c4] cursor-pointer">
                <input
                  type="checkbox"
                  checked={crossProjectSelection}
                  onChange={(e) => setCrossProjectSelection(e.target.checked)}
                  className="rounded accent-[#31d6c4]"
                />
                <span>Listar softwares de todos os projetos / avulsos</span>
              </label>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-bold text-slate-700 dark:text-slate-300 mb-2">
                  1. Contexto / Projeto (Opcional)
                </label>
                <select
                  value={selectedProjectId}
                  onChange={(e) => setSelectedProjectId(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3.5 py-2.5 text-xs text-slate-900 dark:text-slate-100"
                >
                  <option value="">Portfólio Global / Avaliação Independente</option>
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.enabledCategories?.length || 12}/12 Categorias)
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 dark:text-slate-300 mb-2">
                  2. Software Principal a ser Avaliado
                </label>
                <select
                  value={primarySoftwareId}
                  onChange={(e) => setPrimarySoftwareId(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3.5 py-2.5 text-xs text-slate-900 dark:text-slate-100"
                >
                  {projectSoftwares.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name} (v{s.version}) - {s.inventory?.primaryLanguage || s.languages?.[0] || 'Multi-Language'}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Validation & Manifest Check */}
            {activePrimarySoftware ? (
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 p-4 bg-slate-50 dark:bg-[#080b10] space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <FileCheck2 className="w-4 h-4 text-[#31d6c4]" />
                    <span className="text-xs font-bold text-slate-900 dark:text-slate-100">
                      Manifesto de Origem &amp; Integridade Criptográfica
                    </span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                    Origem: {activePrimarySoftware.dataOrigin || 'USER_SOURCE'}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                  <div className="p-2.5 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                    <div className="text-[10px] text-slate-400 font-sans">Arquivos Ingeridos</div>
                    <div className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                      {activePrimarySoftware.sourceManifest?.ingestedFilesCount ||
                        activePrimarySoftware.sourceCodeFiles?.length ||
                        activePrimarySoftware.inventory?.totalFiles ||
                        0}
                    </div>
                  </div>
                  <div className="p-2.5 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                    <div className="text-[10px] text-slate-400 font-sans">Linhas de Código (LOC)</div>
                    <div className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                      {(activePrimarySoftware.inventory?.totalLinesOfCode || 0).toLocaleString()}
                    </div>
                  </div>
                  <div className="p-2.5 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                    <div className="text-[10px] text-slate-400 font-sans">Linguagem Principal</div>
                    <div className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                      {activePrimarySoftware.inventory?.primaryLanguage || 'N/A'}
                    </div>
                  </div>
                  <div className="p-2.5 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                    <div className="text-[10px] text-slate-400 font-sans">Status de Veracidade</div>
                    <div className="text-sm font-bold text-emerald-500 mt-0.5">
                      {activePrimarySoftware.dataOrigin === 'DEMO_FIXTURE' ? 'DEMO FIXTURE' : 'FONTE REAL'}
                    </div>
                  </div>
                </div>

                <div className="p-2 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-500 truncate">
                  SHA-256:{' '}
                  <span className="text-[#31d6c4]">
                    {activePrimarySoftware.verifiedSha256 || activePrimarySoftware.sourceHash || 'Não calculado'}
                  </span>
                </div>

                {(!activePrimarySoftware.sourceCodeFiles || activePrimarySoftware.sourceCodeFiles.length === 0) &&
                  (!activePrimarySoftware.sourceManifest || activePrimarySoftware.sourceManifest.discoveredFilesCount === 0) && (
                    <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-500/10 text-xs text-amber-200 flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <strong>Aviso de Veracidade (Seção 2):</strong> Este software não possui
                        arquivos de código fonte ingeridos. Para executar uma avaliação oficial, faça
                        o upload de uma pasta/ZIP ou importe o repositório.
                        {onRequestUpload && (
                          <button
                            type="button"
                            onClick={onRequestUpload}
                            className="mt-2 block underline font-bold text-[#31d6c4] cursor-pointer"
                          >
                            Realizar Upload de Arquivos de Código Agora
                          </button>
                        )}
                      </div>
                    </div>
                  )}
              </div>
            ) : (
              <div className="p-6 rounded-lg border border-dashed border-slate-300 dark:border-slate-700 text-center">
                <p className="text-xs text-slate-500">Nenhum software cadastrado neste projeto.</p>
                {onRequestUpload && (
                  <button
                    type="button"
                    onClick={onRequestUpload}
                    className="mt-3 px-4 py-2 rounded-lg bg-[#31d6c4] text-slate-950 text-xs font-bold"
                  >
                    Fazer Upload do Primeiro Software
                  </button>
                )}
              </div>
            )}
          </div>
        )}

        {/* STEP 3: SCOPE ESPECÍFICO POR MODALIDADE */}
        {step === 3 && (
          <div className="space-y-6">
            {/* MODALIDADE A: ESCOPO INDIVIDUAL */}
            {assessmentMode === 'INDIVIDUAL' && (
              <div className="space-y-4">
                <div className="flex items-center gap-2">
                  <Shield className="w-5 h-5 text-[#31d6c4]" />
                  <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                    Definição de Escopo da Avaliação Individual
                  </h3>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  A avaliação individual de <strong>{activePrimarySoftware?.name}</strong> executará os
                  motores estáticos, SAST (Opengrep), segredos (Gitleaks), dependências (Syft/Grype)
                  e SonarQube, gerando uma nota consolidada independente de 0 a 100.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                    <div className="font-bold text-slate-900 dark:text-slate-100">Segurança &amp; SAST</div>
                    <p className="text-slate-500 text-[11px] mt-1">
                      Varredura de vulnerabilidades OWASP Top 10, CWE e segredos expostos.
                    </p>
                  </div>
                  <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                    <div className="font-bold text-slate-900 dark:text-slate-100">Arquitetura &amp; QA</div>
                    <p className="text-slate-500 text-[11px] mt-1">
                      Acoplamento, complexidade ciclomática, dívida técnica e cobertura de testes.
                    </p>
                  </div>
                  <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                    <div className="font-bold text-slate-900 dark:text-slate-100">Atestado de Veracidade</div>
                    <p className="text-slate-500 text-[11px] mt-1">
                      Checklist formal de 19 pontos com cadeia de custódia e evidências de execução.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* MODALIDADE B: COMPARAÇÃO A/B ENTRE SOFTWARES DO USUÁRIO */}
            {assessmentMode === 'AB_COMPARE' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                      Selecione o(s) Software(s) para Comparar com {activePrimarySoftware?.name}
                    </h3>
                    <p className="text-xs text-slate-500 mt-0.5">
                      O benchmark comparativo exige ao menos 2 softwares equivalentes para análise paritária.
                    </p>
                  </div>
                  <span className="text-xs font-mono text-[#31d6c4]">
                    Total Selecionados: {1 + comparisonSoftwareIds.length}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {softwares
                    .filter((s) => s.id !== primarySoftwareId)
                    .map((s) => {
                      const isSelected = comparisonSoftwareIds.includes(s.id);
                      return (
                        <div
                          key={s.id}
                          onClick={() => {
                            setComparisonSoftwareIds((prev) =>
                              prev.includes(s.id) ? prev.filter((id) => id !== s.id) : [...prev, s.id]
                            );
                          }}
                          className={`p-4 rounded-lg border cursor-pointer transition-colors ${
                            isSelected
                              ? 'border-[#31d6c4] bg-[#31d6c4]/10'
                              : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-bold text-slate-900 dark:text-slate-100">
                              {s.name} (v{s.version})
                            </span>
                            <span className="text-[10px] font-mono text-slate-500">
                              {s.vendor || 'Interno'}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-500 mt-1">
                            {s.inventory?.primaryLanguage || 'Linguagem N/A'} · {(s.inventory?.totalLinesOfCode || 0).toLocaleString()} LOC
                          </div>
                          <div className="mt-2 text-[10px] font-bold text-[#31d6c4]">
                            {isSelected ? '✓ Selecionado para Benchmark' : '+ Clique para Adicionar'}
                          </div>
                        </div>
                      );
                    })}
                </div>
              </div>
            )}

            {/* MODALIDADE C: DESCOBERTA E APROVAÇÃO DE CONCORRENTE DE MERCADO (Seção 1.3 e 14) */}
            {assessmentMode === 'MARKET_COMPETITOR' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                      <Search className="w-4 h-4 text-amber-400" />
                      <span>Descoberta de Concorrente de Mercado Inteligente</span>
                    </h3>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Calculado com base em 6 eixos de similaridade ponderada. Requer aprovação humana explícita.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={handleDiscoverCompetitors}
                    disabled={discovering}
                    className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-xs font-bold text-slate-700 dark:text-slate-300 hover:border-amber-400"
                  >
                    {discovering ? 'Pesquisando...' : 'Re-analisar Similaridade'}
                  </button>
                </div>

                {discovering ? (
                  <div className="p-8 text-center text-xs text-slate-500">
                    Consultando catálogo de inteligência de mercado e calculando similaridade ponderada...
                  </div>
                ) : marketCandidates.length === 0 ? (
                  <div className="p-6 rounded-lg border border-slate-200 dark:border-slate-800 text-center text-xs text-slate-500">
                    Nenhum concorrente catalogado diretamente para esta categoria técnica.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {marketCandidates.map((cand) => {
                      const isSelected = selectedCandidate?.id === cand.id;
                      const isApproved = candidateApproved && isSelected;
                      return (
                        <div
                          key={cand.id}
                          className={`p-4 rounded-xl border-2 transition-all ${
                            isSelected
                              ? 'border-amber-400 bg-amber-500/5'
                              : 'border-slate-200 dark:border-slate-800'
                          }`}
                        >
                          <div className="flex items-start justify-between">
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-bold text-slate-900 dark:text-slate-100">
                                  {cand.name}
                                </span>
                                <span
                                  className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold ${
                                    cand.openSource
                                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                                      : 'bg-purple-500/10 text-purple-400 border border-purple-500/30'
                                  }`}
                                >
                                  {cand.openSource ? 'OPEN-SOURCE' : 'CLOSED-SOURCE'}
                                </span>
                              </div>
                              <div className="text-[11px] text-slate-500">{cand.vendor} · Categoria: {cand.category}</div>
                            </div>
                            <div className="text-right">
                              <div className="text-base font-bold font-mono text-amber-400">
                                {cand.similarityScore}%
                              </div>
                              <div className="text-[9px] text-slate-400 uppercase font-sans">Match</div>
                            </div>
                          </div>

                          {/* Similarity Breakdown (Seção 14.2) */}
                          <div className="mt-3 grid grid-cols-3 gap-1.5 text-[10px] font-mono bg-white dark:bg-[#080b10] p-2 rounded-lg border border-slate-200 dark:border-slate-800">
                            <div>Propósito (30%): <strong className="text-slate-700 dark:text-slate-200">{cand.similarityBreakdown.purposeMatch}%</strong></div>
                            <div>Funcionalidades (25%): <strong className="text-slate-700 dark:text-slate-200">{cand.similarityBreakdown.featuresMatch}%</strong></div>
                            <div>Público (15%): <strong className="text-slate-700 dark:text-slate-200">{cand.similarityBreakdown.audienceMatch}%</strong></div>
                            <div>Plataforma (10%): <strong className="text-slate-700 dark:text-slate-200">{cand.similarityBreakdown.platformMatch}%</strong></div>
                            <div>Distribuição (10%): <strong className="text-slate-700 dark:text-slate-200">{cand.similarityBreakdown.distributionMatch}%</strong></div>
                            <div>Integrações (10%): <strong className="text-slate-700 dark:text-slate-200">{cand.similarityBreakdown.integrationsMatch}%</strong></div>
                          </div>

                          <p className="text-[11px] text-slate-600 dark:text-slate-400 mt-2.5">
                            {cand.description}
                          </p>

                          <div className="mt-3 pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
                            <span className="text-[10px] text-slate-500">
                              {cand.analysisScope === 'FULL_SOURCE'
                                ? 'Varredura completa de código fonte'
                                : 'Análise de manifesto, API e specs públicas'}
                            </span>
                            {isApproved ? (
                              <span className="inline-flex items-center gap-1 text-xs font-bold text-emerald-400">
                                <CheckCircle2 className="w-3.5 h-3.5" />
                                Homologado pelo Usuário
                              </span>
                            ) : (
                              <button
                                type="button"
                                onClick={() => {
                                  setSelectedCandidate(cand);
                                  handleApproveCompetitor(cand);
                                }}
                                className="px-3 py-1.5 rounded-lg bg-amber-400 text-slate-950 text-xs font-bold hover:bg-amber-300 cursor-pointer"
                              >
                                Homologar e Aprovar Concorrente
                              </button>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* STEP 4: PERFIS DE AVALIAÇÃO, QUALITY GATE & PESOS POR CATEGORIA (Seção 20 — MQR) */}
        {step === 4 && (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-[#31d6c4]" />
                  <span>
                    Escopo Multi-Categoria ({enabledCategories.length}/12 ativas) &amp; Pesos Matemáticos (Total = 100%)
                  </span>
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Qualquer projeto pode ser avaliado simultaneamente nas 12 categorias ou em um subconjunto customizável com normalização automática para 100%.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleEnableAll12Categories}
                  className="px-3 py-1.5 rounded-lg bg-[#31d6c4]/15 text-[#0e9f8e] dark:text-[#31d6c4] border border-[#31d6c4]/40 text-xs font-bold hover:bg-[#31d6c4]/25 cursor-pointer"
                >
                  Avaliar Todas as 12 Categorias
                </button>
                <button
                  type="button"
                  onClick={handleNormalizeWeightsTo100}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-xs font-bold text-slate-700 dark:text-slate-300 hover:border-[#31d6c4] cursor-pointer"
                >
                  Normalizar Pesos Ativos (100%)
                </button>
              </div>
            </div>

            {/* Profile & Quality Gate Selector (Standard + 27 Specialized Profiles) */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
              <div>
                <label className="block text-[11px] font-bold text-slate-600 dark:text-slate-400 mb-1">
                  Perfil de Avaliação &amp; Especialização por Domínio (27 Perfis Oficiais)
                </label>
                <select
                  value={selectedProfileId}
                  onChange={(e) => handleSelectProfile(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
                >
                  <optgroup label="Perfis Corporativos Padrão">
                    {profiles.map((prof) => (
                      <option key={prof.id} value={prof.id}>
                        {prof.name}
                      </option>
                    ))}
                  </optgroup>
                  <optgroup label="15 Perfis Especializados por Domínio Funcional">
                    {DOMAIN_SPECIALIZED_PROFILES.filter((p) => p.profileType === 'DOMAIN_SPECIALIZED').map(
                      (prof) => (
                        <option key={prof.id} value={prof.id}>
                          {prof.name} ({prof.enabledCategories.length}/12 Dimensões Ativas)
                        </option>
                      )
                    )}
                  </optgroup>
                  <optgroup label="12 Perfis Gerais Focados por Dimensão">
                    {DOMAIN_SPECIALIZED_PROFILES.filter((p) => p.profileType === 'GENERAL_DIMENSION').map(
                      (prof) => (
                        <option key={prof.id} value={prof.id}>
                          {prof.name}
                        </option>
                      )
                    )}
                  </optgroup>
                </select>
              </div>

              <div>
                <label className="block text-[11px] font-bold text-slate-600 dark:text-slate-400 mb-1">
                  Quality Gate Transversal (SonarQube MQR)
                </label>
                <select
                  value={qualityGateId}
                  onChange={(e) => setQualityGateId(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
                >
                  <option value="qg-sonar-way-mqr">Sonar way (MQR — Clean as You Code + Fudge Factor &lt; 20 linhas)</option>
                  <option value="qg-zero-trust-strict">WinHood Zero-Trust Strict (Zero Bugs + Bloqueio CVSS &gt;= 7.0)</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {ALL_BENCHMARK_CATEGORIES.map((cat) => {
                const isEnabled = enabledCategories.includes(cat);
                const val = isEnabled ? weights[cat] || 0 : 0;
                return (
                  <div
                    key={cat}
                    className={`p-3 rounded-lg border transition-colors ${
                      isEnabled
                        ? 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]'
                        : 'border-slate-200/50 dark:border-slate-800/40 bg-slate-100/50 dark:bg-[#080b10]/40 opacity-60'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs font-bold text-slate-800 dark:text-slate-200">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={isEnabled}
                          onChange={() => handleToggleCategoryScope(cat)}
                          className="rounded accent-[#31d6c4]"
                        />
                        <span>{CATEGORY_LABELS[cat] || cat}</span>
                      </label>
                      <span className="font-mono text-[#31d6c4]">{val}%</span>
                    </div>
                    <input
                      type="range"
                      min={0}
                      max={50}
                      disabled={!isEnabled}
                      value={val}
                      onChange={(e) => {
                        const newWeight = parseInt(e.target.value, 10);
                        setWeights((prev) => ({ ...prev, [cat]: newWeight }));
                      }}
                      className="w-full mt-2 accent-[#31d6c4]"
                    />
                  </div>
                );
              })}
            </div>

            <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] flex flex-wrap items-center justify-between gap-3">
              <div className="text-xs">
                <span className="text-slate-500">Soma Total dos Pesos ({enabledCategories.length} categorias): </span>
                <span
                  className={`font-mono font-bold ${
                    weightValidation.valid ? 'text-emerald-500' : 'text-rose-500'
                  }`}
                >
                  {weightValidation.totalWeight}% {weightValidation.valid ? '(VÁLIDO)' : '(CLIQUE EM NORMALIZAR PESOS ATIVOS PARA 100%)'}
                </span>
              </div>

              <label className="flex items-center gap-2 text-xs font-bold text-slate-700 dark:text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={enablePenaltyCaps}
                  onChange={(e) => setEnablePenaltyCaps(e.target.checked)}
                  className="rounded accent-[#31d6c4]"
                />
                <span>Habilitar Travas de Segurança (Penalty Caps Auditados com CAP_APPLIED)</span>
              </label>
            </div>
          </div>
        )}

        {/* STEP 5: PRÉ-ANÁLISE, COMPARABILIDADE, EQUIVALÊNCIA EXPERIMENTAL & REVISÃO FINAL (Seções 6, 10.3, 13, 22) */}
        {step === 5 && (() => {
          const selectedSwList =
            assessmentMode === 'INDIVIDUAL'
              ? activePrimarySoftware
                ? [activePrimarySoftware]
                : []
              : assessmentMode === 'AB_COMPARE'
                ? softwares.filter(
                    (s) => s.id === primarySoftwareId || comparisonSoftwareIds.includes(s.id)
                  )
                : activePrimarySoftware
                  ? [
                      activePrimarySoftware,
                      ...softwares.filter((s) => s.id === approvedCompetitorSoftwareId),
                    ]
                  : [];

          const preAnalyses = selectedSwList.map((sw) =>
            buildPreAnalysisSummary(sw, enabledCategories, weights, selectedProfileId)
          );
          const compPreview = evaluateSoftwareComparability({
            softwares: selectedSwList,
            enabledCategories,
            environmentEquivalent: eqValidation.equivalent,
          });

          return (
            <div className="space-y-6">
              <div className="flex items-center gap-2 text-base font-bold text-slate-900 dark:text-slate-100">
                <ShieldCheck className="w-5 h-5 text-[#31d6c4]" />
                <span>Pré-Análise Técnica, Comparabilidade &amp; Contrato de Veracidade</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
                <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                  <div className="text-slate-400 font-sans">Modalidade &amp; Modo do Wizard</div>
                  <div className="text-base font-bold text-slate-900 dark:text-slate-100 mt-1">
                    {assessmentMode === 'INDIVIDUAL'
                      ? 'Opção A: Individual'
                      : assessmentMode === 'AB_COMPARE'
                        ? 'Opção B: Comparação A/B'
                        : 'Opção C: Concorrente Mercado'}{' '}
                    ({wizardMode})
                  </div>
                  <div className="text-slate-500 mt-1 font-sans">
                    Software Principal: {activePrimarySoftware?.name}
                  </div>
                </div>

                <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                  <div className="text-slate-400 font-sans">Validação Matemática</div>
                  <div className="text-base font-bold text-emerald-500 mt-1">
                    {weightValidation.totalWeight}% ({enabledCategories.length}/12 Dimensões)
                  </div>
                  <div className="text-slate-500 mt-1 font-sans">
                    Travas Penalty Caps: {enablePenaltyCaps ? 'ATIVAS' : 'DESLIGADAS'}
                  </div>
                </div>

                <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                  <div className="text-slate-400 font-sans">Imparcialidade &amp; Comparabilidade</div>
                  <div
                    className={`text-base font-bold mt-1 ${
                      compPreview.canDeclareOfficialWinner ? 'text-[#31d6c4]' : 'text-amber-500'
                    }`}
                  >
                    {compPreview.overallStatus}
                  </div>
                  <div className="text-slate-500 mt-1 font-sans">
                    Vencedor Oficial: {compPreview.canDeclareOfficialWinner ? 'PERMITIDO' : 'BLOQUEADO'}
                  </div>
                </div>
              </div>

              {/* Pre-Analysis Summary Cards (Seção 10.3) */}
              {preAnalyses.length > 0 && (
                <div className="space-y-3">
                  <div className="text-xs font-bold text-slate-800 dark:text-slate-200">
                    Resumo de Pré-Análise dos Artefatos Selecionados ({preAnalyses.length})
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    {preAnalyses.map((pa) => (
                      <div
                        key={pa.softwareId}
                        className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#080b10] space-y-1.5"
                      >
                        <div className="flex items-center justify-between font-bold text-slate-900 dark:text-slate-100">
                          <span>{pa.softwareName}</span>
                          <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-[#31d6c4]/15 text-[#31d6c4]">
                            {pa.ingestionState} · {pa.sourceAvailability}
                          </span>
                        </div>
                        <div className="font-mono text-[11px] text-slate-500">
                          Elegíveis: <strong>{pa.eligibleFiles}</strong>/{pa.totalFiles} arqs ·{' '}
                          <strong>{pa.totalLinesOfCode.toLocaleString()}</strong> LOC · Domínio:{' '}
                          <strong>{pa.inferredDomain}</strong>
                        </div>
                        <div className="text-[11px] text-slate-600 dark:text-slate-400">
                          Critérios Verificáveis: <strong>{pa.verifiableCriteriaCount}</strong> · Não Aplicáveis:{' '}
                          <strong>{pa.notApplicableCategories.length}</strong> · Perfil Sugerido:{' '}
                          <span className="font-semibold text-[#31d6c4]">{pa.recommendedProfileName}</span>
                        </div>
                        {pa.warnings.length > 0 && (
                          <div className="text-[11px] text-amber-500 pt-1">
                            ⚠️ {pa.warnings.join(' ')}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Comparability Warnings / Blocking Reasons */}
              {(compPreview.blockingReasons.length > 0 || compPreview.warnings.length > 0) && (
                <div className="p-3.5 rounded-lg border border-amber-500/30 bg-amber-500/10 text-xs space-y-1">
                  <div className="font-bold text-amber-500 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>Diagnóstico do Motor de Comparabilidade &amp; Imparcialidade (Seção 6):</span>
                  </div>
                  {compPreview.blockingReasons.map((b, i) => (
                    <div key={`b-${i}`} className="text-rose-400 font-medium">
                      • [BLOQUEIO DE VENCEDOR] {b}
                    </div>
                  ))}
                  {compPreview.warnings.map((w, i) => (
                    <div key={`w-${i}`} className="text-amber-300">
                      • [AVISO] {w}
                    </div>
                  ))}
                </div>
              )}

              <div className="pt-2">
                <button
                  type="button"
                  disabled={
                    executing ||
                    !activePrimarySoftware ||
                    !weightValidation.valid ||
                    !eqValidation.equivalent ||
                    (assessmentMode === 'MARKET_COMPETITOR' && !candidateApproved)
                  }
                  onClick={handleExecute}
                  className="inline-flex items-center gap-2 px-6 py-3 rounded-lg text-sm font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] disabled:opacity-50 transition-colors cursor-pointer"
                >
                  <Play className="w-4 h-4" />
                  {executing
                    ? 'Executando Adaptadores & Validando Evidências...'
                    : assessmentMode === 'INDIVIDUAL'
                      ? `Iniciar Avaliação Individual de ${activePrimarySoftware?.name}`
                      : assessmentMode === 'MARKET_COMPETITOR'
                        ? `Iniciar Benchmark de Mercado (${activePrimarySoftware?.name} vs ${selectedCandidate?.name})`
                        : 'Iniciar Benchmark Comparativo Real'}
                </button>
              </div>
            </div>
          );
        })()}

        {/* Wizard Footer Navigation */}
        <div className="flex items-center justify-between pt-4 border-t border-slate-200 dark:border-slate-800">
          <button
            type="button"
            disabled={step === 1}
            onClick={() => setStep((s) => Math.max(1, s - 1) as any)}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 disabled:opacity-40 cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Etapa Anterior
          </button>

          {step < 5 && (
            <button
              type="button"
              onClick={() => setStep((s) => Math.min(5, s + 1) as any)}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] cursor-pointer"
            >
              Próxima Etapa
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
