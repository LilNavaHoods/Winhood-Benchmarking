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
  DEFAULT_CATEGORY_WEIGHTS,
  validateCategoryWeights,
  validateEquivalenceConditions,
} from '../engine/scoringEngine';

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

  // Mode Selection (Seção 1: Três Modalidades Independentes)
  const [assessmentMode, setAssessmentMode] = useState<AssessmentMode>('INDIVIDUAL');

  // Primary Selection
  const [selectedProjectId, setSelectedProjectId] = useState<string>(projects[0]?.id || '');
  const [primarySoftwareId, setPrimarySoftwareId] = useState<string>(softwares[0]?.id || '');
  const [comparisonSoftwareIds, setComparisonSoftwareIds] = useState<string[]>([]);

  // Market Competitor Discovery State (Modalidade C)
  const [discovering, setDiscovering] = useState<boolean>(false);
  const [marketCandidates, setMarketCandidates] = useState<MarketCompetitorCandidate[]>([]);
  const [selectedCandidate, setSelectedCandidate] = useState<MarketCompetitorCandidate | null>(null);
  const [candidateApproved, setCandidateApproved] = useState<boolean>(false);
  const [approvedCompetitorSoftwareId, setApprovedCompetitorSoftwareId] = useState<string>('');

  // Profile & Weights
  const [selectedProfileId, setSelectedProfileId] = useState<string>(
    profiles[0]?.id || 'prof-complete-enterprise'
  );
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

  // Update primary software when project changes
  const projectSoftwares = softwares.filter(
    (s) => !selectedProjectId || s.projectId === selectedProjectId
  );

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

  const weightValidation = validateCategoryWeights(weights);
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
    const found = profiles.find((p) => p.id === profId);
    if (found) {
      setWeights({ ...found.weights });
      setEnablePenaltyCaps(found.enablePenaltyCaps);
      setCpuCoresLimit(found.equivalenceEnvironment.cpuCoresLimit);
      setMemoryMbLimit(found.equivalenceEnvironment.memoryMbLimit);
      setOsTarget(found.equivalenceEnvironment.osTarget);
      setWorkloadConcurrency(found.equivalenceEnvironment.workloadConcurrency);
    }
  };

  const handleNormalizeWeightsTo100 = () => {
    setWeights({ ...DEFAULT_CATEGORY_WEIGHTS });
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
      const activeProf = profiles.find((p) => p.id === selectedProfileId);
      const res = await fetch('/api/benchmark-runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: selectedProjectId || projects[0]?.id,
          softwareIds: finalSoftwareIds,
          profileName:
            assessmentMode === 'INDIVIDUAL'
              ? `Avaliação Individual - ${activePrimarySoftware?.name}`
              : assessmentMode === 'MARKET_COMPETITOR'
                ? `Benchmark de Mercado: ${activePrimarySoftware?.name} vs ${selectedCandidate?.name}`
                : activeProf?.name || 'Benchmark Comparativo A/B WinHood',
          weights,
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
      <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-3">
          <Scale className="w-7 h-7 text-[#31d6c4]" />
          <span>Assistente de Avaliação &amp; Benchmark de Softwares</span>
        </h1>
        <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mt-1">
          Plataforma independente de Software Quality Assessment, Security Assessment e Benchmark
          Intelligence. Três modalidades com auditoria e veracidade absoluta.
        </p>
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

        {/* STEP 2: PROJETO & SOFTWARE PRINCIPAL */}
        {step === 2 && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-bold text-slate-700 dark:text-slate-300 mb-2">
                  1. Projeto Vinculado
                </label>
                <select
                  value={selectedProjectId}
                  onChange={(e) => setSelectedProjectId(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3.5 py-2.5 text-xs text-slate-900 dark:text-slate-100"
                >
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.category})
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
                      {s.name} (v{s.version}) - {s.inventory?.primaryLanguage || 'Sem linguagem'}
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

        {/* STEP 4: PERFIS DE AVALIAÇÃO & PESOS POR CATEGORIA (Seção 20) */}
        {step === 4 && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-[#31d6c4]" />
                  <span>Configuração de Pesos Matemáticos (Total = 100%)</span>
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  A pontuação oficial utiliza a média ponderada das 12 categorias. Performance sem runtime workers é sinalizada como NÃO MEDIDA.
                </p>
              </div>

              <button
                type="button"
                onClick={handleNormalizeWeightsTo100}
                className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-xs font-bold text-slate-700 dark:text-slate-300 hover:border-[#31d6c4]"
              >
                Restaurar Padrão WinHood (100%)
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {(Object.keys(weights) as BenchmarkCategoryKey[]).map((cat) => {
                const val = weights[cat];
                return (
                  <div
                    key={cat}
                    className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]"
                  >
                    <div className="flex items-center justify-between text-xs font-bold text-slate-800 dark:text-slate-200">
                      <span>{CATEGORY_LABELS[cat] || cat}</span>
                      <span className="font-mono text-[#31d6c4]">{val}%</span>
                    </div>
                    <input
                      type="range"
                      min={0}
                      max={40}
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

            <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] flex items-center justify-between">
              <div className="text-xs">
                <span className="text-slate-500">Soma Total dos Pesos: </span>
                <span
                  className={`font-mono font-bold ${
                    weightValidation.valid ? 'text-emerald-500' : 'text-rose-500'
                  }`}
                >
                  {weightValidation.totalWeight}% {weightValidation.valid ? '(VÁLIDO)' : '(DEVE SER EXATAMENTE 100%)'}
                </span>
              </div>

              <label className="flex items-center gap-2 text-xs font-bold text-slate-700 dark:text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={enablePenaltyCaps}
                  onChange={(e) => setEnablePenaltyCaps(e.target.checked)}
                  className="rounded accent-[#31d6c4]"
                />
                <span>Habilitar Travas de Segurança (Penalty Caps para CVEs Críticas)</span>
              </label>
            </div>
          </div>
        )}

        {/* STEP 5: EQUIVALÊNCIA EXPERIMENTAL & REVISÃO FINAL (Seção 22 e Seção 13) */}
        {step === 5 && (
          <div className="space-y-6">
            <div className="flex items-center gap-2 text-base font-bold text-slate-900 dark:text-slate-100">
              <ShieldCheck className="w-5 h-5 text-[#31d6c4]" />
              <span>Contrato de Execução, Equivalência &amp; Veracidade</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
              <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                <div className="text-slate-400 font-sans">Modalidade de Avaliação</div>
                <div className="text-base font-bold text-slate-900 dark:text-slate-100 mt-1">
                  {assessmentMode === 'INDIVIDUAL'
                    ? 'Opção A: Individual'
                    : assessmentMode === 'AB_COMPARE'
                      ? 'Opção B: Comparação A/B'
                      : 'Opção C: Concorrente Mercado'}
                </div>
                <div className="text-slate-500 mt-1 font-sans">
                  Software Principal: {activePrimarySoftware?.name}
                </div>
              </div>

              <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                <div className="text-slate-400 font-sans">Validação Matemática</div>
                <div className="text-base font-bold text-emerald-500 mt-1">
                  {weightValidation.totalWeight}% (100% OK)
                </div>
                <div className="text-slate-500 mt-1 font-sans">
                  Travas Penalty Caps: {enablePenaltyCaps ? 'ATIVAS' : 'DESLIGADAS'}
                </div>
              </div>

              <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                <div className="text-slate-400 font-sans">Equivalência Experimental</div>
                <div className="text-base font-bold text-slate-900 dark:text-slate-100 mt-1">
                  {cpuCoresLimit} vCPUs · {memoryMbLimit} MB RAM
                </div>
                <div className="text-slate-500 mt-1 font-sans">
                  Status: {eqValidation.equivalent ? 'HOMOLOGADO' : 'BLOQUEADO'}
                </div>
              </div>
            </div>

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
        )}

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
